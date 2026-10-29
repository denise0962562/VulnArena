import asyncio
import hashlib
import json
import logging
from contextlib import suppress

from pydantic import ValidationError
from redis.exceptions import RedisError
from sqlalchemy import select

from vulnarena.config import Settings
from vulnarena.db import Database, Revision
from vulnarena.nvd import NVDClient, NVDError
from vulnarena.schemas import Severity, SyncRequest, SyncTask, TaskStatus, VulnerabilityList
from vulnarena.state import TaskStore
from vulnarena.study import StudyCollector

logger = logging.getLogger(__name__)


class SyncService:
    def __init__(self, db: Database, store: TaskStore, nvd: NVDClient, settings: Settings):
        self.db, self.store, self.nvd, self.settings = db, store, nvd, settings
        self.collector = StudyCollector(
            db,
            translation_model=settings.translation_model,
            online_translation=settings.online_translation,
        )

    async def run(self, task: SyncTask, query: SyncRequest) -> None:
        async def synchronize() -> None:
            records = await self.nvd.fetch(query)
            await self.store.save(task)
            task.changed = await self.db.upsert(records)
            task.processed = len(records)
            if query.enrich:
                for record in records:
                    await self.collector.collect(record)
                    await self.store.save(task)

        await self._run(task, synchronize)

    async def enrich_record(self, task: SyncTask, cve_id: str) -> None:
        async def enrich() -> None:
            record = await self.db.get(cve_id)
            if record is None:
                raise ValueError("CVE not found")
            await self.collector.collect(record, force=True)
            task.processed = task.changed = 1

        await self._run(task, enrich)

    async def _run(self, task: SyncTask, operation) -> None:
        heartbeat = None
        work = None
        try:
            task.status = TaskStatus.RUNNING
            await self.store.save(task)
            heartbeat = asyncio.create_task(self.store.heartbeat(task))

            work = asyncio.create_task(operation())
            async with asyncio.timeout(self.settings.task_timeout):
                done, _ = await asyncio.wait({heartbeat, work}, return_when=asyncio.FIRST_COMPLETED)
                for finished in done:
                    finished.result()  # Heartbeat failures cancel work and surface as FAILED.
            task.status = TaskStatus.SUCCESS
            await self.store.save(task)
        except asyncio.CancelledError:
            task.status, task.error = TaskStatus.FAILED, "application shutdown interrupted sync"
            with suppress(Exception):
                await self.store.save(task)
            raise
        except Exception as exc:
            task.status = TaskStatus.FAILED
            # Only expose class name, never DB SQL, filesystem credentials, or HTTP headers.
            detail = str(exc) if isinstance(exc, NVDError) else "retry synchronization"
            task.error = f"{type(exc).__name__}: {detail}"
            logger.warning("sync %s failed (%s)", task.id, task.error)
            with suppress(Exception):
                await self.store.save(task)
        finally:
            for child in (work, heartbeat):
                if child is not None:
                    child.cancel()
                    with suppress(asyncio.CancelledError, Exception):
                        await child
            with suppress(Exception):
                await self.store.release(task.id)


async def cached_list(
    db: Database,
    store: TaskStore,
    settings: Settings,
    page: int,
    page_size: int,
    severity: Severity | None,
    keyword: str | None,
    status: str | None,
    topic: str | None = None,
    sort: str = "modified",
    year_from: int | None = None,
    year_to: int | None = None,
) -> VulnerabilityList:
    query = json.dumps(
        [page, page_size, severity, keyword, status, topic, sort, year_from, year_to],
        ensure_ascii=True,
    )
    digest = hashlib.sha256(query.encode()).hexdigest()
    async with db.read_sessions() as session:
        epoch, revision = (
            await session.execute(
                select(Revision.cache_epoch, Revision.value).where(Revision.id == 1)
            )
        ).one()
        key = f"vulnarena:list:{epoch}:{revision}:{digest}"
        try:
            cached = await store.redis.get(key)
            if cached:
                return VulnerabilityList.model_validate_json(cached)
        except (RedisError, ValidationError):
            logger.warning("cache unavailable or invalid; reading PostgreSQL")
        result = await db.list_from_session(
            session, page, page_size, severity, keyword, status, topic, sort, year_from, year_to
        )
        try:
            await store.redis.set(key, result.model_dump_json(), ex=settings.cache_ttl)
        except RedisError:
            logger.warning("cache write unavailable; PostgreSQL result returned")
        return result

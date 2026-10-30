import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query, Request
from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.staticfiles import StaticFiles

from vulnarena.arena import (
    ArenaRuntime,
    InMemoryEventBus,
    InMemoryPolicyStore,
    RedisEventBus,
    RedisPolicyStore,
    WafMiddleware,
)
from vulnarena.arena.context import ArenaContext
from vulnarena.arena.contracts import ArenaSession, ArenaStatus, GuideStep
from vulnarena.arena.deepseek import DeepSeekClient
from vulnarena.arena.events import ArenaEvent
from vulnarena.arena.guide import build_guide
from vulnarena.arena.levels import BY_ID as LEVELS_BY_ID
from vulnarena.arena.levels import progress as level_progress
from vulnarena.arena.levels import rank as level_rank
from vulnarena.arena.levels import total_score as level_total
from vulnarena.arena.pipeline import run_pipeline
from vulnarena.arena.registry import SessionRegistry
from vulnarena.arena.restore import apply_patch, restore_vulnerable
from vulnarena.arena.review import build_review
from vulnarena.arena.stream import event_stream
from vulnarena.arena.targets import TargetRegistry
from vulnarena.bench.corpus import load_corpus
from vulnarena.bench.selfplay import run_selfplay
from vulnarena.config import Settings
from vulnarena.console import render as render_lab
from vulnarena.db import Database
from vulnarena.descriptions import DescriptionTranslator
from vulnarena.intelligence.router import router as intelligence_router
from vulnarena.intelligence.service import IntelligenceService
from vulnarena.intelligence.sources import source_signature
from vulnarena.nvd import NVDClient
from vulnarena.procure import ProcureState, build_procure_app
from vulnarena.procure.models import DefectFlag
from vulnarena.schemas import (
    Severity,
    SyncRequest,
    SyncTask,
    VulnerabilityList,
    VulnerabilityView,
    utcnow,
)
from vulnarena.service import SyncService, cached_list
from vulnarena.state import TaskBusy, TaskStore
from vulnarena.study import cpe_products, study_bundle, weakness_ids
from vulnarena.study_contract import merge_description
from vulnarena.topics import TOPICS, classify

WEB_DIR = Path(__file__).resolve().parent / "web"
ARENA_PAGE = Path(__file__).resolve().parent / "arena" / "static" / "arena.html"

logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    *,
    redis: Redis | None = None,
    nvd: NVDClient | None = None,
    portal: FastAPI | None = None,
) -> FastAPI:
    settings = settings or Settings()
    runtime = ArenaRuntime()
    llm = DeepSeekClient(settings)
    portal_state = ProcureState() if portal is None else None
    portal_app = portal if portal is not None else build_procure_app(state=portal_state)
    portal_app.add_middleware(WafMiddleware, runtime=runtime)
    if portal_state is None:
        portal_state = getattr(portal_app.state, "procure", None)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = Database(settings.database_url.get_secret_value(), schema=settings.database_schema)
        redis_client = (
            redis
            if redis is not None
            else Redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_timeout=3,
                socket_connect_timeout=3,
                retry=Retry(NoBackoff(), 0),
            )
        )
        nvd_client = nvd if nvd is not None else NVDClient(settings)
        try:
            await db.initialize()
            # Redis is required for tasks; reads can fall back to PostgreSQL.
            store = TaskStore(redis_client, settings)
            app.state.db, app.state.store = db, store
            app.state.sync = SyncService(db, store, nvd_client, settings)
            app.state.descriptions = DescriptionTranslator(db, settings.translation_model)
            app.state.intelligence = IntelligenceService(db, settings)
            await app.state.intelligence.startup()
            # The arena shares Redis with tasks but never with the task lease keys.
            runtime.policy_store = RedisPolicyStore(redis_client)
            runtime.events = RedisEventBus(redis_client)
            try:
                await redis_client.ping()
            except RedisError:
                # The drill must stay runnable on a laptop without Redis.
                runtime.policy_store = InMemoryPolicyStore()
                runtime.events = InMemoryEventBus()
                logger.warning("Redis unavailable: arena falls back to in-memory policy/events")
            yield
        finally:
            await llm.aclose()
            if portal_state is not None:
                await portal_state.aclose()
            await nvd_client.aclose()
            if hasattr(app.state, "sync"):
                await app.state.sync.collector.aclose()
            if hasattr(app.state, "descriptions"):
                await app.state.descriptions.close()
            if hasattr(app.state, "intelligence"):
                await app.state.intelligence.close()
            await redis_client.aclose()
            await db.aclose()

    app = FastAPI(title="VulnArena", version="0.1.0", lifespan=lifespan)
    app.include_router(intelligence_router)
    app.state.runtime = runtime
    app.state.portal_state = portal_state
    app.state.sessions = SessionRegistry()
    app.state.targets = TargetRegistry()
    app.state.llm = llm

    @app.exception_handler(RedisError)
    async def redis_unavailable(request, exc) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "Redis unavailable; retry later"})

    @app.exception_handler(SQLAlchemyError)
    async def database_unavailable(request, exc) -> JSONResponse:
        return JSONResponse(
            status_code=503, content={"detail": "PostgreSQL unavailable; retry later"}
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        async with app.state.db.sessions() as session:
            await session.execute(text("SELECT 1"))
        await app.state.store.redis.ping()
        return {"status": "ok"}

    @app.post("/api/sync", response_model=SyncTask, status_code=202)
    async def start_sync(query: SyncRequest, background: BackgroundTasks) -> SyncTask:
        try:
            task = await app.state.store.create()
        except TaskBusy as exc:
            raise HTTPException(409, str(exc)) from exc
        background.add_task(app.state.sync.run, task.model_copy(deep=True), query)
        return task

    @app.get("/api/tasks/{task_id}", response_model=SyncTask)
    async def get_task(task_id: str) -> SyncTask:
        task = await app.state.store.get(task_id)
        if task is None:
            raise HTTPException(404, "task not found or expired")
        return task

    @app.get("/api/topics")
    async def topics() -> list[str]:
        return list(TOPICS)

    @app.get("/api/library/stats")
    async def library_stats() -> dict[str, int]:
        return await app.state.db.library_stats()

    @app.get("/api/library/years")
    async def year_coverage(
        year_from: Annotated[int, Query(ge=1999, le=2100)] = 2020,
        year_to: Annotated[int, Query(ge=1999, le=2100)] = 2026,
    ) -> list[dict]:
        if year_from > year_to:
            raise HTTPException(422, "year_from must not exceed year_to")
        return await app.state.db.year_coverage(year_from, year_to)

    @app.get(
        "/api/vulnerabilities",
        response_model=VulnerabilityList,
        response_model_exclude={"items": {"__all__": {"raw", "metrics", "references"}}},
    )
    async def list_vulnerabilities(
        page: Annotated[int, Query(ge=1, le=100000)] = 1,
        page_size: Annotated[int, Query(ge=1, le=100)] = 20,
        severity: Severity | None = None,
        keyword: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
        status: Annotated[str | None, Query(min_length=1, max_length=100)] = None,
        topic: str | None = None,
        sort: Literal["modified", "published"] = "modified",
        year_from: Annotated[int | None, Query(ge=1999, le=2100)] = None,
        year_to: Annotated[int | None, Query(ge=1999, le=2100)] = None,
    ) -> VulnerabilityList:
        if topic is not None and topic not in TOPICS:
            raise HTTPException(422, "unknown topic")
        if year_from and year_to and year_from > year_to:
            raise HTTPException(422, "year_from must not exceed year_to")
        return await cached_list(
            app.state.db,
            app.state.store,
            settings,
            page,
            page_size,
            severity,
            keyword,
            status,
            topic,
            sort,
            year_from,
            year_to,
        )

    @app.get("/api/vulnerabilities/{cve_id}", response_model=VulnerabilityView)
    async def get_vulnerability(cve_id: str) -> VulnerabilityView:
        record = await app.state.db.get(cve_id)
        if record is None:
            raise HTTPException(404, "CVE not found")
        study = await app.state.db.get_study(cve_id)
        ai_source_signature = source_signature(record, study)
        study = merge_description(
            record,
            study
            or {
                "topics": classify(record.description),
                "status": "pending",
                "affected": cpe_products(record.raw),
                "weaknesses": weakness_ids(record.raw),
            },
            await app.state.db.get_chinese(cve_id),
        )
        study["ai_source_signature"] = ai_source_signature
        return VulnerabilityView(
            **record.model_dump(),
            study=study,
        )

    @app.post("/api/vulnerabilities/{cve_id}/translate", status_code=202)
    async def translate_description(cve_id: str) -> dict:
        result = await app.state.descriptions.request(cve_id)
        if result["status"] == "not_found":
            raise HTTPException(404, "CVE not found")
        if result["status"] == "busy":
            raise HTTPException(429, "translation queue full; retry later")
        return result

    @app.get("/api/vulnerabilities/{cve_id}/translation")
    async def translation_status(cve_id: str) -> dict:
        result = await app.state.descriptions.status(cve_id)
        if result["status"] == "not_found":
            raise HTTPException(404, "CVE not found")
        return result

    @app.post("/api/vulnerabilities/{cve_id}/enrich", response_model=SyncTask, status_code=202)
    async def enrich_vulnerability(cve_id: str, background: BackgroundTasks) -> SyncTask:
        if await app.state.db.get(cve_id) is None:
            raise HTTPException(404, "CVE not found")
        try:
            task = await app.state.store.create()
        except TaskBusy as exc:
            raise HTTPException(409, str(exc)) from exc
        background.add_task(app.state.sync.enrich_record, task.model_copy(deep=True), cve_id)
        return task

    @app.get("/api/vulnerabilities/{cve_id}/download")
    async def download_vulnerability(cve_id: str) -> Response:
        record = await app.state.db.get(cve_id)
        if record is None:
            raise HTTPException(404, "CVE not found")
        study = await app.state.db.get_study(cve_id)
        signature = source_signature(record, study)
        study = merge_description(record, study, await app.state.db.get_chinese(cve_id))
        card = await app.state.intelligence.get_card(cve_id)
        if not card or card["status"] != "complete" or card.get("signature") != signature:
            card = None
        return Response(
            study_bundle(record, study, ai_card=card),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{record.cve_id}-study.zip"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def run_session(session_id: str, level_id: str = "", defects=None) -> None:
        """Drive one drill. TODO(phase 2): move behind /api/red with an admin token."""
        if app.state.portal_state is None:
            await app.state.runtime.emit(
                ArenaEvent(
                    session_id=session_id,
                    stage="DONE",
                    kind="error",
                    message="portal sandbox is not mounted",
                )
            )
            return
        transport = httpx.ASGITransport(app=app)
        try:
            async with httpx.AsyncClient(
                transport=transport, base_url="http://arena.local", timeout=30
            ) as client:
                ctx = ArenaContext(
                    client=client,
                    state=app.state.portal_state,
                    runtime=app.state.runtime,
                    session_id=session_id,
                    base="/api/procure",
                    llm=llm,
                )
                session = (
                    await run_pipeline(ctx, defects=defects) if defects else await run_pipeline(ctx)
                )
                session.level_id = level_id
        except Exception as exc:  # a failed drill must surface, never hang the page
            logger.warning("arena session %s failed: %s", session_id, exc)
            placeholder = app.state.sessions.get(session_id)
            if placeholder is not None:
                placeholder.status = ArenaStatus.BREACH_FAILED
                placeholder.finished_at = utcnow()
            await app.state.runtime.emit(
                ArenaEvent(
                    session_id=session_id,
                    stage="DONE",
                    kind="error",
                    message=f"{type(exc).__name__}: {exc}",
                )
            )
            return
        app.state.sessions.put(session)

    @app.post("/api/arena/start", status_code=202)
    async def arena_start(background: BackgroundTasks, level: str | None = None) -> dict[str, str]:
        defects = None
        level_id = ""
        if level:
            chosen = LEVELS_BY_ID.get(level)
            if chosen is None:
                raise HTTPException(404, "level not found")
            entry = next(
                (item for item in level_progress(app.state.sessions.all()) if item.id == level),
                None,
            )
            if entry is None or not entry.unlocked:
                raise HTTPException(409, f"level locked: pass {chosen.unlock_after} first")
            defects = tuple(DefectFlag(value) for value in chosen.defects)
            level_id = chosen.id
        session_id = uuid4().hex[:8]
        placeholder = ArenaSession(session_id=session_id, status=ArenaStatus.CREATED)
        placeholder.level_id = level_id
        app.state.sessions.put(placeholder)
        background.add_task(run_session, session_id, level_id, defects)
        return {"session_id": session_id, "level": level_id}

    @app.post("/api/arena/sessions/{session_id}/hint")
    async def arena_hint(session_id: str) -> dict[str, int]:
        session = app.state.sessions.get(session_id)
        if session is None:
            raise HTTPException(404, "session not found")
        session.hint_uses += 1
        return {"hint_uses": session.hint_uses}

    @app.get("/api/arena/sessions")
    async def arena_sessions() -> list[dict[str, object]]:
        return app.state.sessions.recent()

    @app.post("/api/bench/selfplay")
    async def bench_selfplay(rounds: int = 3, category: str = "sqli", red_limit: int = 20) -> dict:
        """跑一轮离线自博弈（确定性红队，不需要模型）。"""
        from vulnarena.bench.mutate import mutate

        def red(current, target):
            known = set(current.attacks.get(target, []))
            fresh: list[str] = []
            for sample in current.attacks.get(target, []):
                for variant in mutate(sample):
                    if variant not in known and variant not in fresh:
                        fresh.append(variant)
                if len(fresh) >= red_limit:
                    return fresh
            return fresh

        results = await run_selfplay(
            load_corpus(), rounds=max(1, min(rounds, 10)), category=category, red=red
        )
        payload = [item.to_dict() for item in results]
        app.state.selfplay = {"category": category, "rounds": payload}
        return app.state.selfplay

    @app.get("/api/bench/selfplay")
    async def bench_selfplay_latest() -> dict:
        return getattr(app.state, "selfplay", {"category": "sqli", "rounds": []})

    @app.get("/api/arena/levels")
    async def arena_levels() -> list[dict]:
        items = level_progress(app.state.sessions.all())
        return [item.model_dump() for item in items]

    @app.get("/api/arena/targets")
    async def arena_targets() -> list[dict[str, object]]:
        return [target.model_dump(mode="json") for target in app.state.targets.all()]

    @app.get("/api/arena/sessions/{session_id}", response_model=ArenaSession)
    async def arena_session(session_id: str) -> ArenaSession:
        session = app.state.sessions.get(session_id)
        if session is None:
            raise HTTPException(404, "session not found")
        return session

    @app.get("/api/arena/sessions/{session_id}/guide", response_model=list[GuideStep])
    async def arena_guide(session_id: str, request: Request) -> list[GuideStep]:
        session = app.state.sessions.get(session_id)
        if session is None:
            raise HTTPException(404, "session not found")
        host = str(request.base_url).rstrip("/")
        return build_guide(session, base="/api/procure", host=host)

    @app.post("/api/arena/sessions/{session_id}/restore", response_model=ArenaSession)
    async def arena_restore(session_id: str) -> ArenaSession:
        session = app.state.sessions.get(session_id)
        if session is None:
            raise HTTPException(404, "session not found")
        if app.state.portal_state is None:
            raise HTTPException(503, "portal sandbox is not mounted")
        try:
            return await restore_vulnerable(app.state.portal_state, app.state.runtime, session)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/arena/sessions/{session_id}/apply-patch", response_model=ArenaSession)
    async def arena_apply_patch(session_id: str) -> ArenaSession:
        session = app.state.sessions.get(session_id)
        if session is None:
            raise HTTPException(404, "session not found")
        if app.state.portal_state is None:
            raise HTTPException(503, "portal sandbox is not mounted")
        try:
            return await apply_patch(app.state.portal_state, app.state.runtime, session)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/arena/sessions/{session_id}/review")
    async def arena_review(session_id: str) -> dict:
        session = app.state.sessions.get(session_id)
        if session is None:
            raise HTTPException(404, "session not found")
        return build_review(session).model_dump()

    def lab_response(*, error: str = "", status_code: int = 200) -> HTMLResponse:
        targets = [target.model_dump(mode="json") for target in app.state.targets.all()]
        levels = [item.model_dump() for item in level_progress(app.state.sessions.all())]
        app.state.last_score = level_total(level_progress(app.state.sessions.all()))
        score = level_total(level_progress(app.state.sessions.all()))
        return HTMLResponse(
            render_lab(
                targets,
                app.state.sessions.recent(),
                levels,
                score,
                level_rank(score),
                selfplay=getattr(app.state, "selfplay", {}),
                selfplay_error=error,
            ),
            status_code=status_code,
            headers={"Cache-Control": "no-store, must-revalidate"},
        )

    @app.get("/lab", include_in_schema=False)
    async def lab_console() -> HTMLResponse:
        return lab_response()

    @app.post("/lab/selfplay", include_in_schema=False)
    async def lab_selfplay() -> Response:
        try:
            await bench_selfplay(rounds=3, category="sqli", red_limit=20)
        except Exception:
            logger.exception("Lab selfplay failed")
            return lab_response(
                error="自博弈运行失败，请稍后重试；下方保留上次结果。", status_code=503
            )
        return RedirectResponse(
            "/lab", status_code=303, headers={"Cache-Control": "no-store, must-revalidate"}
        )

    @app.get("/arena", include_in_schema=False)
    async def arena_page() -> HTMLResponse:
        if not ARENA_PAGE.is_file():
            raise HTTPException(503, "arena page is missing on disk")
        return HTMLResponse(ARENA_PAGE.read_text(encoding="utf-8"))

    @app.get("/api/arena/stream/{session_id}")
    async def arena_stream(
        request: Request,
        session_id: str,
        last_event_id: Annotated[str | None, Header()] = None,
    ) -> StreamingResponse:
        """Read-only relay of arena events. It never interprets what it forwards."""
        bus = app.state.runtime.events
        if bus is None:
            raise HTTPException(503, "arena event bus unavailable")
        offset = int(last_event_id) if last_event_id and last_event_id.isdigit() else 0
        return StreamingResponse(
            event_stream(bus, session_id, offset=offset, is_disconnected=request.is_disconnected),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # API routes are registered first, so static files never shadow the API.
    app.mount("/api/procure", portal_app)
    if (WEB_DIR / "index.html").is_file():
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="frontend")
    else:

        @app.get("/", include_in_schema=False, status_code=503)
        async def frontend_unavailable() -> dict[str, str]:
            return {"detail": "Frontend not built. Run npm ci and npm run build in frontend/."}

    return app


app = create_app()

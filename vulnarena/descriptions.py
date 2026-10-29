"""Freshness-aware Chinese summaries, without downloading or modifying source CVEs."""

import asyncio
import hashlib
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from vulnarena.db import Database, Translation
from vulnarena.offline_translation import load_translator
from vulnarena.study_contract import description_fingerprint, usable_chinese

PROVIDER = "Argos en-zh 1.9 / CTranslate2 (offline; batch-v2)"
LEGACY_PROVIDERS = ["Argos en-zh 1.9 / CTranslate2 (offline)", "Google Translate (gtx)"]


def cache_key(text: str, provider: str = PROVIDER) -> str:
    return hashlib.sha256((provider + ":en:zh-CN:v1:" + text).encode()).hexdigest()


class DescriptionTranslator:
    def __init__(self, db: Database, model_path: str):
        self.db, self.model_path = db, model_path
        self.lock = asyncio.Lock()
        self.pending = {}
        self.errors = {}

    async def translate_rows(self, records: list[dict]) -> dict:
        if not records:
            return {"saved": 0, "errors": []}
        texts = list(
            dict.fromkeys(
                record["description"] for record in records if record["description"].strip()
            )
        )
        keys = {
            text: [cache_key(text), *(cache_key(text, p) for p in LEGACY_PROVIDERS)]
            for text in texts
        }
        async with self.db.read_sessions() as session:
            cached = dict(
                (
                    await session.execute(
                        select(Translation.digest, Translation.text).where(
                            Translation.digest.in_(
                                [key for values in keys.values() for key in values]
                            )
                        )
                    )
                ).all()
            )
        translated = {}
        providers = {}
        for source in texts:
            for index, key in enumerate(keys[source]):
                candidate = cached.get(key, "").replace("▁", " ").strip()
                if usable_chinese(source, candidate):
                    translated[source] = candidate
                    providers[source] = [PROVIDER, *LEGACY_PROVIDERS][index]
                    break
        missing = [source for source in texts if source not in translated]
        failed = []
        if missing:
            async with self.lock:
                model = await asyncio.to_thread(load_translator, self.model_path)
                try:
                    outputs = await asyncio.to_thread(
                        model.translate_many,
                        missing,
                        beam_size=1,
                        max_batch_size=256,
                        allow_partial=True,
                    )
                except ValueError:
                    # Isolate pathological documents; one failure must not discard a batch.
                    outputs = []
                    for source in missing:
                        try:
                            outputs.append(await asyncio.to_thread(model.translate, source))
                        except (ValueError, RuntimeError):
                            outputs.append("")
            cache_rows = []
            for source, output in zip(missing, outputs, strict=True):
                if not usable_chinese(source, output):
                    try:
                        async with self.lock:
                            output = await asyncio.to_thread(model.translate, source)
                    except (ValueError, RuntimeError):
                        output = ""
                if usable_chinese(source, output):
                    translated[source] = output
                    providers[source] = PROVIDER
                    cache_rows.append({"digest": cache_key(source), "text": output})
                else:
                    failed.append(description_fingerprint(source))
            if cache_rows:
                async with self.db.sessions.begin() as session:
                    for offset in range(0, len(cache_rows), 100):
                        await session.execute(
                            insert(Translation)
                            .values(cache_rows[offset : offset + 100])
                            .on_conflict_do_nothing()
                        )
        now = datetime.now(UTC)
        values = [
            {
                "cve_id": record["cve_id"],
                "source_sha256": description_fingerprint(record["description"]),
                "text_zh": translated[record["description"]],
                "provider": providers[record["description"]],
                "translated_at": now,
            }
            for record in records
            if record["description"] in translated
        ]
        saved = await self.db.save_chinese(values)
        return {
            "saved": saved,
            "errors": [
                record["cve_id"]
                for record in records
                if record["description"].strip()
                and description_fingerprint(record["description"]) in failed
            ],
            "source_missing": [
                record["cve_id"] for record in records if not record["description"].strip()
            ],
        }

    async def request(self, cve_id: str) -> dict:
        record = await self.db.get(cve_id)
        if record is None:
            return {"status": "not_found"}
        current = await self.db.get_chinese(cve_id)
        digest = description_fingerprint(record.description)
        if current and current["source_sha256"] == digest:
            return {"status": "complete"}
        if not record.description.strip():
            return {"status": "source_missing"}
        key = (cve_id, digest)
        if key not in self.pending:
            if len(self.pending) >= 32:
                return {"status": "busy"}
            self.errors.pop(cve_id, None)

            async def work():
                try:
                    result = await self.translate_rows(
                        [{"cve_id": cve_id, "description": record.description}]
                    )
                    if result["errors"]:
                        self.errors[cve_id] = "translation failed"
                except Exception:
                    self.errors[cve_id] = "translation unavailable"
                finally:
                    self.pending.pop(key, None)
                    if len(self.errors) > 32:
                        self.errors.pop(next(iter(self.errors)))

            self.pending[key] = asyncio.create_task(work())
        return {"status": "pending"}

    async def status(self, cve_id: str) -> dict:
        record = await self.db.get(cve_id)
        if record is None:
            return {"status": "not_found"}
        current = await self.db.get_chinese(cve_id)
        if current and current["source_sha256"] == description_fingerprint(record.description):
            return {"status": "complete"}
        if cve_id in self.errors:
            return {"status": "failed"}
        return {"status": "pending" if any(key[0] == cve_id for key in self.pending) else "missing"}

    async def close(self):
        tasks = list(self.pending.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

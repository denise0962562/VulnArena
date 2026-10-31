import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import delete, func, literal_column, or_, select, update
from sqlalchemy.dialects.postgresql import insert

from vulnarena.db import (
    CVE,
    ChineseDescription,
    Database,
    Revision,
    Study,
    current_chinese_join,
    year_filters,
)
from vulnarena.intelligence.benchmarks import cases
from vulnarena.intelligence.models import (
    AITrace,
    AnswerCache,
    EvidenceChunk,
    IndexedRecord,
    IntelligenceJob,
    StudyCard,
)
from vulnarena.intelligence.query import expanded_query, query_anchors, tokens
from vulnarena.intelligence.schemas import Filters
from vulnarena.intelligence.sources import SOURCE_VERSION, digest, make_sources, source_signature
from vulnarena.schemas import Vulnerability

SEED_IDS = [
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2024-3094",
    "CVE-2024-4577",
    "CVE-2021-34527",
    "CVE-2020-1472",
    "CVE-2021-4034",
    "CVE-2022-0847",
    "CVE-2023-4863",
    "CVE-2023-38545",
    "CVE-2023-44487",
    "CVE-2024-34359",
    "CVE-2024-27980",
    "CVE-2024-24576",
    "CVE-2023-29406",
    "CVE-2024-24790",
    "CVE-2023-43622",
    "CVE-2024-6387",
    "CVE-2021-3156",
    "CVE-2022-3602",
]


HOLDOUT_IDS = list(
    dict.fromkeys(
        identifier
        for case in [*cases("regression"), *cases("holdout")]
        for identifier in case["expected_cves"]
    )
)


def now():
    return datetime.now(UTC)


def as_job(row, *, include_rows=True):
    result = dict(row.result)
    if result.get("dataset_version") == "nvd-holdout-25-v1":
        result["classification"] = "regression"
        result["classification_note"] = "此题集已用于领域判断缺陷诊断；不得继续解释成盲测。"
    if "generation" in result:
        samples = []
        for sample in result["generation"]:
            sample = dict(sample)
            reviews = [
                review
                for review in result.get("human_reviews", [])
                if review["trace_id"] == sample["trace_id"]
            ]
            if reviews:
                sample["human_entailment_review"] = "reviewed"
                sample["latest_human_review"] = reviews[-1]
            answer = sample.get("answer")
            if answer is not None and not any(
                claim.get("references") for claim in answer.get("claims", [])
            ):
                sample["quote_validation_passed"] = False
                sample["quote_validation_status"] = "no_citations"
            elif not answer:
                sample["quote_validation_status"] = "legacy_unverified"
            samples.append(sample)
        result["generation"] = samples
    if not include_rows:
        result.pop("rows", None)
        if "generation" in result:
            result["generation"] = [
                {key: value for key, value in case.items() if key != "answer"}
                for case in result["generation"]
            ]
    return {
        "id": row.id,
        "kind": row.kind,
        "status": row.status,
        "progress": row.progress,
        "total": row.total,
        "result": result,
        "parameters": getattr(row, "parameters", {}),
        "error": row.error,
        "created_at": row.created_at.isoformat(),
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }


class BudgetExceeded(ValueError):
    pass


class Repository:
    def __init__(self, db: Database):
        self.db = db
        self.snapshot_slots = asyncio.Semaphore(2)

    async def recover(self):
        async with self.db.sessions.begin() as session:
            recoverable = or_(
                IntelligenceJob.status.in_(["pending", "running"]),
                IntelligenceJob.error == "service_shutdown",
            )
            previous = [
                as_job(job)
                for job in await session.scalars(
                    select(IntelligenceJob)
                    .where(recoverable)
                    .order_by(IntelligenceJob.created_at.desc())
                )
            ]
            await session.execute(
                update(IntelligenceJob)
                .where(recoverable)
                .values(
                    status="interrupted",
                    error="服务重启，已保存的索引仍可复用。",
                    finished_at=now(),
                )
            )
            await session.execute(
                update(AITrace).where(AITrace.status == "running").values(status="interrupted")
            )
        return previous

    async def snapshots(self, identifiers: list[str]) -> dict[str, dict]:
        if not identifiers:
            return {}
        async with self.db.read_sessions() as session:
            rows = await session.execute(
                select(CVE, Study.content, ChineseDescription)
                .outerjoin(Study, Study.cve_id == CVE.cve_id)
                .outerjoin(ChineseDescription, current_chinese_join())
                .where(CVE.cve_id.in_(identifiers))
            )
            output = {}
            for row, study, chinese in rows:
                record = Vulnerability.model_validate(row)
                translated = (
                    {
                        "source_sha256": chinese.source_sha256,
                        "text_zh": chinese.text_zh,
                        "provider": chinese.provider,
                        "translated_at": chinese.translated_at.isoformat(),
                    }
                    if chinese
                    else None
                )
                async with self.snapshot_slots:
                    snapshot = await asyncio.to_thread(
                        make_sources, record, study or {}, translated
                    )
                snapshot["rejected"] = record.vuln_status == "Rejected"
                output[record.cve_id] = snapshot
            return output

    async def candidates(self, limit: int) -> list[str]:
        async with self.db.read_sessions() as session:
            chosen = list(
                await session.scalars(
                    select(CVE.cve_id).where(
                        CVE.cve_id.in_([*SEED_IDS, *HOLDOUT_IDS]), CVE.vuln_status != "Rejected"
                    )
                )
            )
            studied = await session.scalars(
                select(CVE.cve_id)
                .join(Study, Study.cve_id == CVE.cve_id)
                .where(*year_filters(2020, 2026), CVE.vuln_status != "Rejected")
                .order_by(CVE.cve_id)
                .limit(min(limit // 2, 1600))
            )
            chosen = list(dict.fromkeys([*chosen, *studied]))[:limit]
            quota = max(1, (limit - len(chosen) + 6) // 7)
            for year in range(2020, 2027):
                identifiers = await session.scalars(
                    select(CVE.cve_id)
                    .where(
                        *year_filters(year, year),
                        CVE.vuln_status != "Rejected",
                        CVE.description != "",
                        CVE.cve_id.not_in(chosen),
                    )
                    .order_by(CVE.cve_id)
                    .limit(quota)
                )
                chosen.extend(identifiers)
            if len(chosen) < limit:
                chosen.extend(
                    await session.scalars(
                        select(CVE.cve_id)
                        .where(
                            *year_filters(2020, 2026),
                            CVE.vuln_status != "Rejected",
                            CVE.description != "",
                            CVE.cve_id.not_in(chosen),
                        )
                        .order_by(CVE.last_modified_at.desc())
                        .limit(limit - len(chosen))
                    )
                )
            return chosen[:limit]

    async def index_signature(self, identifier: str, model: str) -> str | None:
        async with self.db.read_sessions() as session:
            return await session.scalar(
                select(IndexedRecord.signature).where(
                    IndexedRecord.cve_id == identifier,
                    IndexedRecord.embedding_model == model,
                    IndexedRecord.source_version == SOURCE_VERSION,
                )
            )

    async def save_index(self, snapshot: dict, vectors: list[list[float]], model: str) -> bool:
        async with self.db.sessions.begin() as session:
            record = await session.scalar(
                select(CVE).where(CVE.cve_id == snapshot["cve_id"]).with_for_update()
            )
            study = await session.get(Study, snapshot["cve_id"])
            if (
                record is None
                or source_signature(
                    Vulnerability.model_validate(record), study.content if study else {}
                )
                != snapshot["signature"]
            ):
                return False
            values = {
                key: snapshot[key] for key in ["cve_id", "signature", "year", "severity", "topics"]
            }
            values.update(embedding_model=model, indexed_at=now(), source_version=SOURCE_VERSION)
            statement = insert(IndexedRecord).values(**values)
            await session.execute(
                statement.on_conflict_do_update(index_elements=[IndexedRecord.cve_id], set_=values)
            )
            await session.execute(
                delete(EvidenceChunk).where(EvidenceChunk.cve_id == snapshot["cve_id"])
            )
            for chunk, vector in zip(snapshot["chunks"], vectors, strict=True):
                searchable = " ".join(
                    tokens(
                        chunk["cve_id"]
                        + " "
                        + chunk["title"]
                        + " "
                        + chunk["text"]
                        + " "
                        + chunk.get("text_zh", "")[:2500]
                    )
                )
                await session.execute(
                    insert(EvidenceChunk).values(
                        id=chunk["id"],
                        cve_id=chunk["cve_id"],
                        content=chunk,
                        embedding=vector,
                        search_vector=func.to_tsvector(
                            literal_column("'simple'::regconfig"), searchable
                        ),
                    )
                )
            return True

    @staticmethod
    def filter_clauses(filters: Filters):
        clauses = [IndexedRecord.source_version == SOURCE_VERSION]
        if filters.year_from:
            clauses.append(IndexedRecord.year >= filters.year_from)
        if filters.year_to:
            clauses.append(IndexedRecord.year <= filters.year_to)
        if filters.topic:
            clauses.append(IndexedRecord.topics.contains([filters.topic]))
        if filters.severity:
            clauses.append(IndexedRecord.severity == filters.severity)
        return clauses

    async def lexical(self, question: str, filters: Filters, limit=60):
        words = tokens(expanded_query(question))
        if not words:
            return []
        expression = " | ".join(words[:60])
        tsquery = func.to_tsquery(literal_column("'simple'::regconfig"), expression)
        anchors = query_anchors(question)
        anchor_query = (
            func.to_tsquery(literal_column("'simple'::regconfig"), " | ".join(anchors))
            if anchors
            else None
        )
        async with self.db.read_sessions() as session:
            return list(
                await session.scalars(
                    select(EvidenceChunk.id)
                    .join(IndexedRecord)
                    .where(
                        EvidenceChunk.search_vector.op("@@")(tsquery),
                        *self.filter_clauses(filters),
                        *([EvidenceChunk.search_vector.op("@@")(anchor_query)] if anchors else []),
                    )
                    .order_by(
                        func.ts_rank_cd(EvidenceChunk.search_vector, tsquery).desc(),
                        EvidenceChunk.id,
                    )
                    .limit(limit)
                )
            )

    async def chunks(self, identifiers):
        if not identifiers:
            return {}
        async with self.db.read_sessions() as session:
            return dict(
                (
                    await session.execute(
                        select(EvidenceChunk.id, EvidenceChunk.content).where(
                            EvidenceChunk.id.in_(identifiers)
                        )
                    )
                ).all()
            )

    async def matrix_version(self, model: str):
        async with self.db.read_sessions() as session:
            row = (
                await session.execute(
                    select(func.count(), func.max(IndexedRecord.indexed_at)).where(
                        IndexedRecord.embedding_model == model,
                        IndexedRecord.source_version == SOURCE_VERSION,
                    )
                )
            ).one()
            return (row[0], row[1].isoformat() if row[1] else "")

    async def matrix_rows(self, model: str):
        async with self.db.read_sessions() as session:
            stream = await session.stream(
                select(
                    EvidenceChunk.id,
                    EvidenceChunk.embedding,
                    IndexedRecord.year,
                    IndexedRecord.severity,
                    IndexedRecord.topics,
                )
                .join(IndexedRecord)
                .where(
                    IndexedRecord.embedding_model == model,
                    IndexedRecord.source_version == SOURCE_VERSION,
                )
                .order_by(EvidenceChunk.id)
                .execution_options(yield_per=256)
            )
            async for row in stream:
                yield row

    async def index_stats(self, model=None):
        async with self.db.read_sessions() as session:
            records = await session.scalar(select(func.count()).select_from(IndexedRecord))
            current_records = await session.scalar(
                select(func.count())
                .select_from(IndexedRecord)
                .where(
                    IndexedRecord.source_version == SOURCE_VERSION,
                    *([IndexedRecord.embedding_model == model] if model else []),
                )
            )
            chunks = await session.scalar(select(func.count()).select_from(EvidenceChunk))
            years = (
                await session.execute(
                    select(IndexedRecord.year, func.count())
                    .group_by(IndexedRecord.year)
                    .order_by(IndexedRecord.year)
                )
            ).all()
            return {
                "records": records,
                "current_records": current_records,
                "outdated_records": records - current_records,
                "source_version": SOURCE_VERSION,
                "chunks": chunks,
                "years": [{"year": year, "records": count} for year, count in years],
            }

    async def corpus_snapshot(self):
        async with self.db.read_sessions() as session:
            rows = (
                await session.execute(
                    select(
                        IndexedRecord.cve_id, IndexedRecord.signature, IndexedRecord.embedding_model
                    ).order_by(IndexedRecord.cve_id)
                )
            ).all()
            revision = await session.scalar(select(Revision.value).where(Revision.id == 1))
            return {
                "records": len(rows),
                "index_fingerprint": digest([list(row) for row in rows]),
                "data_revision": revision,
                "captured_at": now().isoformat(),
            }

    async def new_job(self, kind, total, parameters=None):
        identity = uuid4().hex
        async with self.db.sessions.begin() as session:
            session.add(
                IntelligenceJob(
                    id=identity,
                    kind=kind,
                    status="pending",
                    progress=0,
                    total=total,
                    result={},
                    parameters=parameters or {},
                    error=None,
                    created_at=now(),
                    finished_at=None,
                )
            )
        return await self.job(identity)

    async def update_job(self, identity, **changes):
        async with self.db.sessions.begin() as session:
            await session.execute(
                update(IntelligenceJob).where(IntelligenceJob.id == identity).values(**changes)
            )

    async def job(self, identity):
        async with self.db.read_sessions() as session:
            row = await session.get(IntelligenceJob, identity)
            return as_job(row) if row else None

    async def recent_jobs(self, limit=10):
        async with self.db.read_sessions() as session:
            return [
                as_job(row, include_rows=False)
                for row in await session.scalars(
                    select(IntelligenceJob).order_by(IntelligenceJob.created_at.desc()).limit(limit)
                )
            ]

    async def save_reviews(self, identity, batch):
        async with self.db.sessions.begin() as session:
            row = await session.get(IntelligenceJob, identity, with_for_update=True)
            if row is None or row.kind != "evaluation" or row.status != "complete":
                raise ValueError("只能评审已完成的评测报告。")
            samples = {sample["trace_id"]: sample for sample in row.result.get("generation", [])}
            previous = list(row.result.get("human_reviews", []))
            if len(previous) + len(batch.reviews) > 200:
                raise ValueError("此报告已达到 200 条评审记录上限。")
            for review in batch.reviews:
                sample = samples.get(review.trace_id)
                if not sample or not sample.get("answer"):
                    raise ValueError("评审引用的回答不存在或未保存全文。")
                available = {source["source_id"] for source in sample["answer"].get("sources", [])}
                if not set(review.source_ids).issubset(available):
                    raise ValueError("评审中的来源编号不属于该回答。")
                if review.verdict in {"supported", "partially_supported"} and not review.source_ids:
                    raise ValueError("支持性判定必须指出核对的原文来源。")
                previous.append(
                    {
                        **review.model_dump(),
                        "reviewed_at": now().isoformat(),
                        "method": "human_self_reported",
                    }
                )
            row.result = {**row.result, "human_reviews": previous}
            return as_job(row)

    async def card(self, identifier):
        async with self.db.read_sessions() as session:
            row = await session.get(StudyCard, identifier)
            return (
                {
                    **row.content,
                    "signature": row.signature,
                    "model": row.model,
                    "prompt_version": row.prompt_version,
                    "created_at": row.created_at.isoformat(),
                }
                if row
                else None
            )

    async def save_card(self, identifier, signature, model, prompt_version, content):
        values = dict(
            cve_id=identifier,
            signature=signature,
            model=model,
            prompt_version=prompt_version,
            content=content,
            created_at=now(),
        )
        async with self.db.sessions.begin() as session:
            statement = insert(StudyCard).values(**values)
            await session.execute(
                statement.on_conflict_do_update(index_elements=[StudyCard.cve_id], set_=values)
            )

    async def cached_answer(self, key, ttl):
        async with self.db.read_sessions() as session:
            row = await session.get(AnswerCache, key)
            return row.content if row and (now() - row.created_at).total_seconds() < ttl else None

    async def cache_answer(self, key, content):
        async with self.db.sessions.begin() as session:
            statement = insert(AnswerCache).values(digest=key, content=content, created_at=now())
            await session.execute(
                statement.on_conflict_do_update(
                    index_elements=[AnswerCache.digest],
                    set_={"content": content, "created_at": now()},
                )
            )

    async def trace(self, kind, question, model):
        identity = uuid4().hex
        async with self.db.sessions.begin() as session:
            session.add(
                AITrace(
                    id=identity,
                    kind=kind,
                    status="running",
                    question=question,
                    model=model,
                    model_called=False,
                    payload={},
                    created_at=now(),
                )
            )
        return identity

    async def reserve_model_call(self, identity, daily_limit):
        async with self.db.sessions.begin() as session:
            await session.execute(select(func.pg_advisory_xact_lock(1448438878)))
            start = now().replace(hour=0, minute=0, second=0, microsecond=0)
            count = await session.scalar(
                select(func.count())
                .select_from(AITrace)
                .where(AITrace.created_at >= start, AITrace.model_called.is_(True))
            )
            if count >= daily_limit:
                raise BudgetExceeded("今日模型请求额度已用完。")
            await session.execute(
                update(AITrace).where(AITrace.id == identity).values(model_called=True)
            )

    async def finish_trace(self, identity, status, payload):
        async with self.db.sessions.begin() as session:
            await session.execute(
                update(AITrace).where(AITrace.id == identity).values(status=status, payload=payload)
            )

    async def traces(self, limit=30):
        async with self.db.read_sessions() as session:
            return [
                {
                    "id": row.id,
                    "kind": row.kind,
                    "status": row.status,
                    "question": row.question,
                    "model": row.model,
                    "model_called": row.model_called,
                    "created_at": row.created_at.isoformat(),
                    **row.payload,
                }
                for row in await session.scalars(
                    select(AITrace).order_by(AITrace.created_at.desc()).limit(limit)
                )
            ]

    async def daily_calls(self):
        start = now().replace(hour=0, minute=0, second=0, microsecond=0)
        async with self.db.read_sessions() as session:
            return await session.scalar(
                select(func.count())
                .select_from(AITrace)
                .where(AITrace.created_at >= start, AITrace.model_called.is_(True))
            )

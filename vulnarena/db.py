import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    and_,
    cast,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB, insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from vulnarena.schemas import Severity, Vulnerability, VulnerabilityList, VulnerabilityView
from vulnarena.study_contract import merge_description
from vulnarena.topics import TOPICS, classify


class UTCDateTime(TypeDecorator[datetime]):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("timezone required")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        return value.astimezone(UTC) if value is not None else None


class Base(DeclarativeBase):
    pass


class CVE(Base):
    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    description: Mapped[str]
    description_lang: Mapped[str | None]
    published_at: Mapped[datetime] = mapped_column(UTCDateTime())
    last_modified_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    vuln_status: Mapped[str] = mapped_column(index=True)
    cvss_score: Mapped[float | None]
    severity: Mapped[str] = mapped_column(String(10), index=True)
    cvss_version: Mapped[str | None]
    cvss_vector: Mapped[str | None]
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB)
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB)
    parse_warnings: Mapped[list[str]] = mapped_column(JSONB)


class Revision(Base):
    __tablename__ = "data_revision"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[int]
    cache_epoch: Mapped[str]


class Study(Base):
    __tablename__ = "vulnerability_studies"

    cve_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    content: Mapped[dict[str, Any]] = mapped_column(JSONB)


class Translation(Base):
    __tablename__ = "study_translations"

    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    text: Mapped[str]


class FeedState(Base):
    __tablename__ = "nvd_feed_checkpoints"

    year: Mapped[int] = mapped_column(Integer, primary_key=True)
    content: Mapped[dict[str, Any]] = mapped_column(JSONB)


class ChineseDescription(Base):
    __tablename__ = "chinese_descriptions"

    cve_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("vulnerabilities.cve_id"), primary_key=True
    )
    source_sha256: Mapped[str] = mapped_column(String(64))
    text_zh: Mapped[str]
    provider: Mapped[str] = mapped_column(String(160))
    translated_at: Mapped[datetime] = mapped_column(UTCDateTime())


def current_description_hash():
    return func.encode(func.sha256(func.convert_to(CVE.description, "UTF8")), "hex")


def current_chinese_join():
    return and_(
        ChineseDescription.cve_id == CVE.cve_id,
        ChineseDescription.source_sha256 == current_description_hash(),
    )


def year_filters(year_from: int | None, year_to: int | None):
    filters = []
    if year_from is not None:
        filters.append(CVE.cve_id >= f"CVE-{year_from:04d}-")
    if year_to is not None:
        filters.append(CVE.cve_id < f"CVE-{year_to + 1:04d}-")
    return filters


class Database:
    def __init__(self, url: str, *, schema: str | None = None):
        connect_args: dict[str, Any] = {"timeout": 5}
        if schema is not None:
            connect_args["server_settings"] = {"search_path": schema}
        self.engine = create_async_engine(
            url, pool_pre_ping=True, hide_parameters=True, connect_args=connect_args
        )
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        self.read_sessions = async_sessionmaker(
            self.engine.execution_options(
                isolation_level="REPEATABLE READ", postgresql_readonly=True
            ),
            expire_on_commit=False,
        )
        self.init_lock = asyncio.Lock()
        self.initialized = False

    async def initialize(self) -> None:
        async with self.init_lock:
            if self.initialized:
                return
            async with self.engine.begin() as connection:
                # PostgreSQL transaction lock also serializes separate app instances.
                await connection.exec_driver_sql("SELECT pg_advisory_xact_lock(1448438862)")
                await connection.run_sync(Base.metadata.create_all)
                await connection.execute(
                    insert(Revision)
                    .values(id=1, value=0, cache_epoch=str(uuid4()))
                    .on_conflict_do_nothing()
                )
            self.initialized = True

    async def upsert(self, records: list[Vulnerability]) -> int:
        changed = 0
        async with self.sessions.begin() as session:
            for record in sorted(records, key=lambda item: item.cve_id):
                values = record.model_dump(mode="python")
                values["severity"] = record.severity.value
                statement = insert(CVE).values(**values)
                statement = statement.on_conflict_do_update(
                    index_elements=[CVE.cve_id],
                    set_={
                        key: getattr(statement.excluded, key) for key in values if key != "cve_id"
                    },
                    where=statement.excluded.last_modified_at >= CVE.last_modified_at,
                ).returning(CVE.cve_id)
                result = await session.execute(statement)
                changed += result.scalar_one_or_none() is not None
            if changed:
                # The cache generation changes in the SAME commit as the data.
                await session.execute(
                    update(Revision).where(Revision.id == 1).values(value=Revision.value + 1)
                )
        # sessions.begin commits on success, rolls back on error, always closes.
        return changed

    async def get(self, cve_id: str) -> Vulnerability | None:
        async with self.read_sessions() as session:
            row = await session.get(CVE, cve_id)
            return Vulnerability.model_validate(row) if row else None

    async def get_feed_state(self, year: int) -> dict[str, Any]:
        async with self.read_sessions() as session:
            row = await session.get(FeedState, year)
            return row.content if row else {}

    async def upsert_many(
        self,
        records: list[Vulnerability],
        *,
        feed_state: tuple[int, dict[str, Any]] | None = None,
    ) -> int:
        """Bounded multi-row writes; feed cursor commits atomically with its records.

        Unlike upsert(), this returns a count of unique IDs written. Within a batch
        the newest record wins; an equal timestamp uses the last input occurrence.
        """
        unique = {}
        for record in records:
            previous = unique.get(record.cve_id)
            if previous is None or record.last_modified_at >= previous.last_modified_at:
                unique[record.cve_id] = record
        ordered = sorted(unique.values(), key=lambda record: record.cve_id)
        changed = 0
        async with self.sessions.begin() as session:
            for start in range(0, len(ordered), 100):
                values = [
                    record.model_dump(mode="python") for record in ordered[start : start + 100]
                ]
                for value in values:
                    value["severity"] = value["severity"].value
                statement = insert(CVE).values(values)
                statement = statement.on_conflict_do_update(
                    index_elements=[CVE.cve_id],
                    set_={
                        key: getattr(statement.excluded, key)
                        for key in values[0]
                        if key != "cve_id"
                    },
                    where=statement.excluded.last_modified_at >= CVE.last_modified_at,
                ).returning(CVE.cve_id)
                changed += len((await session.scalars(statement)).all())
            if changed:
                await session.execute(
                    update(Revision).where(Revision.id == 1).values(value=Revision.value + 1)
                )
            if feed_state is not None:
                year, content = feed_state
                statement = insert(FeedState).values(year=year, content=content)
                await session.execute(
                    statement.on_conflict_do_update(
                        index_elements=[FeedState.year],
                        set_={"content": statement.excluded.content},
                    )
                )
        return changed

    async def get_study(self, cve_id: str) -> dict[str, Any]:
        async with self.read_sessions() as session:
            row = await session.get(Study, cve_id)
            return row.content if row else {}

    async def get_chinese(self, cve_id: str) -> dict | None:
        async with self.read_sessions() as session:
            row = await session.get(ChineseDescription, cve_id)
            return (
                {
                    "source_sha256": row.source_sha256,
                    "text_zh": row.text_zh,
                    "provider": row.provider,
                    "translated_at": row.translated_at.isoformat(),
                }
                if row
                else None
            )

    async def save_chinese(self, rows: list[dict]) -> int:
        if not rows:
            return 0
        by_id = {row["cve_id"]: row for row in rows}
        if any(not row["text_zh"].strip() for row in rows):
            raise ValueError("empty translations cannot be marked complete")
        async with self.sessions.begin() as session:
            current = dict(
                (
                    await session.execute(
                        select(CVE.cve_id, current_description_hash())
                        .where(CVE.cve_id.in_(by_id))
                        .order_by(CVE.cve_id)
                        .with_for_update(of=CVE)
                    )
                ).all()
            )
            values = [
                by_id[key]
                for key in sorted(by_id)
                if current.get(key) == by_id[key]["source_sha256"]
            ]
            for offset in range(0, len(values), 100):
                statement = insert(ChineseDescription).values(values[offset : offset + 100])
                await session.execute(
                    statement.on_conflict_do_update(
                        index_elements=[ChineseDescription.cve_id],
                        set_={
                            key: getattr(statement.excluded, key)
                            for key in values[0]
                            if key != "cve_id"
                        },
                    )
                )
            if values:
                await session.execute(
                    update(Revision).where(Revision.id == 1).values(value=Revision.value + 1)
                )
        return len(values)

    async def save_study(self, cve_id: str, content: dict[str, Any]) -> None:
        async with self.sessions.begin() as session:
            statement = insert(Study).values(cve_id=cve_id, content=content)
            await session.execute(
                statement.on_conflict_do_update(
                    index_elements=[Study.cve_id], set_={"content": statement.excluded.content}
                )
            )
            await session.execute(
                update(Revision).where(Revision.id == 1).values(value=Revision.value + 1)
            )

    async def get_translation(self, digest: str) -> str | None:
        async with self.read_sessions() as session:
            return await session.scalar(
                select(Translation.text).where(Translation.digest == digest)
            )

    async def save_translation(self, digest: str, text: str) -> None:
        async with self.sessions.begin() as session:
            await session.execute(
                insert(Translation).values(digest=digest, text=text).on_conflict_do_nothing()
            )

    async def library_stats(self) -> dict[str, int]:
        async with self.read_sessions() as session:
            total = await session.scalar(select(func.count()).select_from(CVE))
            studied = await session.scalar(select(func.count()).select_from(Study))
            translated = await session.scalar(
                select(func.count())
                .select_from(CVE)
                .join(ChineseDescription, current_chinese_join())
            )
            documents = await session.scalar(
                select(func.sum(cast(Study.content["document_count"].astext, Integer)))
            )
            return {
                "total": total or 0,
                "studied": studied or 0,
                "translated": translated or 0,
                "documents": documents or 0,
            }

    async def year_coverage(self, year_from: int = 2020, year_to: int = 2026) -> list[dict]:
        async with self.read_sessions() as session:
            year = cast(func.substr(CVE.cve_id, 5, 4), Integer)
            rows = await session.execute(
                select(year, func.count(), func.count(ChineseDescription.cve_id))
                .select_from(CVE)
                .outerjoin(ChineseDescription, current_chinese_join())
                .where(*year_filters(year_from, year_to))
                .group_by(year)
                .order_by(year)
            )
            return [
                {"year": y, "total": total, "translated": translated, "pending": total - translated}
                for y, total, translated in rows
            ]

    @staticmethod
    async def list_from_session(
        session: AsyncSession,
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
        filters = year_filters(year_from, year_to)
        if severity:
            filters.append(CVE.severity == severity.value)
        if keyword:
            filters.append(
                or_(
                    CVE.description.icontains(keyword, autoescape=True),
                    CVE.cve_id.icontains(keyword, autoescape=True),
                    cast(Study.content["description_zh"], Text).icontains(keyword, autoescape=True),
                    cast(Study.content["title"], Text).icontains(keyword, autoescape=True),
                    ChineseDescription.text_zh.icontains(keyword, autoescape=True),
                )
            )
        if status:
            filters.append(CVE.vuln_status == status)
        if topic:
            filters.append(Study.content["topics"].contains([topic]))
        base = select(CVE, Study.content, ChineseDescription).outerjoin(
            Study, Study.cve_id == CVE.cve_id
        )
        base = base.outerjoin(ChineseDescription, current_chinese_join())
        if topic and topic != "其他":
            # Regex fallback also covers records not enriched yet. PostgreSQL uses POSIX boundaries.
            pattern = TOPICS[topic].replace(r"\b", r"\y")
            filters[-1] = or_(filters[-1], CVE.description.op("~*")(pattern))
        total = await session.scalar(
            select(func.count()).select_from(base.where(*filters).subquery())
        )
        order = CVE.published_at if sort == "published" else CVE.last_modified_at
        rows = await session.execute(
            base.where(*filters)
            .order_by(order.desc(), CVE.cve_id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return VulnerabilityList(
            total=total,
            page=page,
            page_size=page_size,
            items=[
                VulnerabilityView(
                    **Vulnerability.model_validate(row).model_dump(),
                    study={
                        "topics": (content or {}).get("topics", classify(row.description)),
                        **{
                            key: value
                            for key, value in merge_description(
                                Vulnerability.model_validate(row),
                                content or {},
                                {
                                    "source_sha256": chinese.source_sha256,
                                    "text_zh": chinese.text_zh,
                                    "provider": chinese.provider,
                                    "translated_at": chinese.translated_at.isoformat(),
                                }
                                if chinese
                                else None,
                            ).items()
                            if key
                            in {
                                "stale",
                                "description_stale",
                                "description_zh",
                                "translation_status",
                                "translation_provider",
                                "description_translated_at",
                            }
                        },
                        **{
                            key: value
                            for key, value in (content or {}).items()
                            if key
                            in {
                                "title",
                                "fetched_at",
                                "document_count",
                                "weaknesses",
                                "status",
                            }
                        },
                    },
                )
                for row, content, chinese in rows
            ],
        )

    async def aclose(self) -> None:
        await self.engine.dispose()

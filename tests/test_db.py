import asyncio
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from vulnarena.db import CVE, Database, Revision, UTCDateTime
from vulnarena.nvd import parse_cve


async def test_unique_upsert_revision_and_timezone(db, raw_cve):
    await asyncio.gather(db.initialize(), db.initialize())
    item = parse_cve(raw_cve)
    assert await db.upsert([item, item]) == 2
    stored = await db.get(item.cve_id)
    assert stored == item
    newer = item.model_copy(
        update={
            "description": "Revised",
            "cvss_score": None,
            "last_modified_at": datetime(2025, 1, 1, tzinfo=UTC),
        }
    )
    assert await db.upsert([newer]) == 1
    assert await db.upsert([item]) == 0
    assert (await db.get(item.cve_id)).description == "Revised"
    async with db.sessions() as session:
        assert await session.scalar(select(Revision.value)) == 2
        rows = (await session.scalars(select(CVE))).all()
        assert len(rows) == 1 and rows[0].cvss_score is None
    assert await db.get("CVE-1999-9999") is None


async def test_transaction_rollback_and_unique_constraint(db, raw_cve):
    item = parse_cve(raw_cve)
    broken = item.model_copy(update={"cve_id": "CVE-2024-9999", "description": None})
    with pytest.raises(IntegrityError):
        await db.upsert([item, broken])
    assert await db.get(item.cve_id) is None
    async with db.sessions() as session:
        assert await session.scalar(select(Revision.value)) == 0
    await db.upsert([item])
    with pytest.raises(IntegrityError):
        async with db.sessions.begin() as session:
            session.add(CVE(**item.model_dump()))
    assert await db.get(item.cve_id) == item


def test_utc_storage_type():
    column = UTCDateTime()
    assert column.process_bind_param(None, None) is None
    assert column.process_result_value(None, None) is None
    with pytest.raises(ValueError, match="timezone required"):
        column.process_bind_param(datetime(2024, 1, 1), None)


async def test_postgresql_native_types_and_consistent_read_snapshot(db, raw_cve):
    item = parse_cve(raw_cve)
    await db.upsert([item])
    async with db.read_sessions() as session:
        assert await session.scalar(text("SHOW transaction_isolation")) == "repeatable read"
        assert await session.scalar(text("SHOW transaction_read_only")) == "on"
        first_revision = await session.scalar(select(Revision.value))
        types = (
            await session.execute(
                text(
                    "SELECT pg_typeof(raw)::text, pg_typeof(published_at)::text "
                    "FROM vulnerabilities LIMIT 1"
                )
            )
        ).one()
        assert types == ("jsonb", "timestamp with time zone")
        updated = item.model_copy(update={"description": "Revised concurrently"})
        await db.upsert([updated])
        assert await session.scalar(select(Revision.value)) == first_revision
        assert await session.scalar(select(CVE.description)) == item.description
    assert (await db.get(item.cve_id)).description == "Revised concurrently"


async def test_independent_initializers_and_case_insensitive_search(database_settings, raw_cve):
    # Start with an empty schema and two independent initialization locks/connection pools.
    url = database_settings.database_url.get_secret_value()
    db = Database(url, schema=database_settings.database_schema)
    other = Database(url, schema=database_settings.database_schema)
    try:
        await asyncio.gather(db.initialize(), other.initialize(), other.initialize())
        await db.upsert([parse_cve(raw_cve)])
        async with other.read_sessions() as session:
            result = await other.list_from_session(session, 1, 10, None, "example", None)
            assert result.total == 1
        async with other.read_sessions() as session:
            result = await other.list_from_session(session, 1, 10, None, "%", None)
            assert result.total == 0
    finally:
        await other.aclose()
        await db.aclose()

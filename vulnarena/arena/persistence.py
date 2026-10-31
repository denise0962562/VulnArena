"""Persist reports, never live sandbox connections, tokens or model keys."""

import json

from sqlalchemy import text


async def load_reports(db):
    async with db.read_sessions() as session:
        return dict((await session.execute(text("SELECT key,payload FROM arena_reports"))).all())


async def save_report(db, key, payload):
    async with db.sessions.begin() as session:
        await session.execute(
            text(
                "INSERT INTO arena_reports(key,payload) VALUES (:key,CAST(:payload AS JSONB)) "
                "ON CONFLICT(key) DO UPDATE SET payload=EXCLUDED.payload,"
                "updated_at=CURRENT_TIMESTAMP"
            ),
            {"key": key, "payload": json.dumps(payload, ensure_ascii=False)},
        )

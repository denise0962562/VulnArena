"""Forward-only, transactional PostgreSQL upgrades with immutable checksums.

The pre-existing schema is adopted as the baseline. New upgrades are numbered SQL
files; editing an already-applied file is rejected instead of silently drifting.
"""

import hashlib
from pathlib import Path

from sqlalchemy import text


async def upgrade(connection):
    await connection.exec_driver_sql(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(version VARCHAR(100) PRIMARY KEY, checksum VARCHAR(64) NOT NULL, "
        "applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    applied = dict(
        (await connection.exec_driver_sql("SELECT version, checksum FROM schema_migrations")).all()
    )
    migrations = sorted(Path(__file__).parent.glob("[0-9]*.sql"))
    known = {p.name for p in migrations}
    if set(applied) - known:
        raise RuntimeError(
            "Database schema is newer than this application; do not downgrade binaries."
        )
    for path in migrations:
        source = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        checksum = hashlib.sha256(source.encode()).hexdigest()
        if path.name in applied:
            if applied[path.name] != checksum:
                raise RuntimeError(f"Applied migration changed: {path.name}")
            continue
        await connection.exec_driver_sql(source)
        await connection.execute(
            text("INSERT INTO schema_migrations(version,checksum) VALUES (:version,:checksum)"),
            {"version": path.name, "checksum": checksum},
        )


async def status(connection):
    return [
        dict(row)
        for row in (
            await connection.exec_driver_sql(
                "SELECT version,checksum,applied_at FROM schema_migrations ORDER BY version"
            )
        ).mappings()
    ]

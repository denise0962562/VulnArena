"""One-time, idempotent import from legacy SQLite into configured PostgreSQL."""

import argparse
import asyncio
import json
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from vulnarena.config import Settings
from vulnarena.db import Database
from vulnarena.schemas import Vulnerability

ROOT = Path(__file__).resolve().parents[1]


def read_legacy(path: Path, batch_size: int = 200) -> Iterator[list[Vulnerability]]:
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        cursor = connection.execute("SELECT * FROM vulnerabilities ORDER BY cve_id")
        while rows := cursor.fetchmany(batch_size):
            batch = []
            for row in rows:
                values = dict(row)
                for field in ("metrics", "references", "raw", "parse_warnings"):
                    values[field] = json.loads(values[field])
                for field in ("published_at", "last_modified_at"):
                    timestamp = datetime.fromisoformat(values[field])
                    # The legacy storage type explicitly wrote naive UTC values.
                    values[field] = (
                        timestamp.replace(tzinfo=UTC) if timestamp.tzinfo is None else timestamp
                    )
                batch.append(Vulnerability.model_validate(values))
            yield batch
    finally:
        connection.close()


def backup_legacy(source: Path, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError("Backup already exists; refusing to overwrite")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True) as original:
        with sqlite3.connect(destination) as backup:
            original.backup(backup)


async def migrate(source: Path, database: Database, batch_size: int = 200) -> dict[str, int]:
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    await database.initialize()
    processed = changed = 0
    for batch in read_legacy(source, batch_size):
        changed += await database.upsert(batch)
        for record in batch:
            stored = await database.get(record.cve_id)
            if stored is None or stored.last_modified_at < record.last_modified_at:
                raise RuntimeError(f"Migration verification failed: {record.cve_id}")
            if stored.last_modified_at == record.last_modified_at and stored != record:
                raise RuntimeError(f"Migration field mismatch: {record.cve_id}")
        processed += len(batch)
    return {"processed": processed, "writes": changed}


async def main(source: Path) -> None:
    backup = (
        ROOT
        / "data/backups"
        / ("sqlite-before-postgresql-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + ".db")
    )
    await asyncio.to_thread(backup_legacy, source, backup)
    settings = Settings()
    database = Database(settings.database_url.get_secret_value())
    try:
        result = await migrate(backup, database)
    finally:
        await database.aclose()
    report = {"source": str(source), "backup": str(backup), **result}
    report_path = ROOT / "verification/postgresql-migration.json"
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("data/vulnarena.db"))
    args = parser.parse_args()
    asyncio.run(main(args.source))

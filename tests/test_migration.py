import hashlib
import json
import sqlite3

import pytest

from scripts.migrate_sqlite import backup_legacy, migrate, read_legacy
from vulnarena.nvd import parse_cve


def legacy_file(path, records):
    with sqlite3.connect(path) as connection:
        columns = list(type(records[0]).model_fields)
        connection.execute(
            "CREATE TABLE vulnerabilities (" + ",".join(f'"{key}" TEXT' for key in columns) + ")"
        )
        for record in records:
            values = record.model_dump(mode="python")
            for key in ("metrics", "references", "raw", "parse_warnings"):
                values[key] = json.dumps(values[key], ensure_ascii=False)
            for key in ("published_at", "last_modified_at"):
                values[key] = values[key].replace(tzinfo=None).isoformat(sep=" ")
            values["severity"] = record.severity.value
            connection.execute(
                "INSERT INTO vulnerabilities VALUES (" + ",".join("?" for _ in columns) + ")",
                [values[key] for key in columns],
            )


async def test_sqlite_to_postgresql_preserves_fields_and_is_idempotent(db, raw_cve, tmp_path):
    source = tmp_path / "legacy.db"
    item = parse_cve(raw_cve).model_copy(update={"description": "中文描述", "cvss_score": None})
    legacy_file(source, [item])
    original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    backup = tmp_path / "backups/legacy.db"
    backup_legacy(source, backup)
    with pytest.raises(FileExistsError):
        backup_legacy(source, backup)
    assert await migrate(backup, db, batch_size=1) == {"processed": 1, "writes": 1}
    assert await db.get(item.cve_id) == item
    assert await migrate(backup, db) == {"processed": 1, "writes": 1}
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original_hash
    with pytest.raises(ValueError, match="positive"):
        await migrate(backup, db, batch_size=0)


async def test_migration_rejects_bad_json_without_writing(db, raw_cve, tmp_path):
    source = tmp_path / "broken.db"
    item = parse_cve(raw_cve)
    legacy_file(source, [item])
    with sqlite3.connect(source) as connection:
        connection.execute("UPDATE vulnerabilities SET raw='broken'")
    with pytest.raises(json.JSONDecodeError):
        await migrate(source, db)
    assert await db.get(item.cve_id) is None
    with pytest.raises(sqlite3.OperationalError):
        list(read_legacy(tmp_path / "missing.db"))
    assert not (tmp_path / "missing.db").exists()

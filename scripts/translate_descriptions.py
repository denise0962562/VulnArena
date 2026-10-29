"""Resume local Chinese summary translation for the selected CVE ID years."""

import argparse
import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select, text

from scripts.import_nvd_feeds import lower_priority, save_report
from vulnarena.config import Settings
from vulnarena.db import CVE, ChineseDescription, Database, current_chinese_join, year_filters
from vulnarena.descriptions import DescriptionTranslator


async def main(args):
    lower_priority()
    settings = Settings()
    db = Database(settings.database_url.get_secret_value(), schema=settings.database_schema)
    translator = DescriptionTranslator(db, settings.translation_model)
    report_path = Path(args.report)
    report = {
        "status": "running",
        "started_at": datetime.now(UTC).isoformat(),
        "year_from": args.year_from,
        "year_to": args.year_to,
        "saved": 0,
        "errors": [],
        "source_missing": [],
        "pause_seconds": args.pause,
    }
    started = time.monotonic()
    locked = False
    try:
        await db.initialize()
        async with db.engine.connect() as connection:
            connection = await connection.execution_options(isolation_level="AUTOCOMMIT")
            locked = await connection.scalar(text("SELECT pg_try_advisory_lock(1448438864)"))
            if not locked:
                raise RuntimeError("another summary translation is already running")
            report["initial_coverage"] = await db.year_coverage(args.year_from, args.year_to)
            await asyncio.to_thread(save_report, report_path, report)
            for year in range(args.year_to, args.year_from - 1, -1):
                cursor = ""
                while True:
                    async with db.read_sessions() as session:
                        rows = (
                            await session.execute(
                                select(CVE.cve_id, CVE.description)
                                .outerjoin(ChineseDescription, current_chinese_join())
                                .where(
                                    *year_filters(year, year),
                                    CVE.cve_id > cursor,
                                    ChineseDescription.cve_id.is_(None),
                                )
                                .order_by(CVE.cve_id)
                                .limit(args.batch_size)
                            )
                        ).all()
                    if not rows:
                        break
                    result = await translator.translate_rows(
                        [
                            {"cve_id": identifier, "description": description}
                            for identifier, description in rows
                        ]
                    )
                    cursor = rows[-1][0]
                    report["saved"] += result["saved"]
                    report["errors"].extend(result["errors"])
                    report["source_missing"].extend(result.get("source_missing", []))
                    report.update(
                        current_year=year,
                        cursor=cursor,
                        elapsed_seconds=round(time.monotonic() - started, 1),
                    )
                    await asyncio.to_thread(save_report, report_path, report)
                    if report["saved"] % (args.batch_size * 5) < args.batch_size:
                        print(
                            f"Chinese {year}: saved {report['saved']}; cursor {cursor}", flush=True
                        )
                    pause = args.pause
                    control = Path("data/translation-control.json")
                    if await asyncio.to_thread(control.exists):
                        try:
                            config = json.loads(
                                await asyncio.to_thread(control.read_text, encoding="utf-8")
                            )
                            pause = max(0.0, min(30.0, float(config.get("pause_seconds", pause))))
                        except (ValueError, OSError, TypeError):
                            pass
                    report["pause_seconds"] = pause
                    await asyncio.sleep(pause)
                report["coverage"] = await db.year_coverage(args.year_from, args.year_to)
                await asyncio.to_thread(save_report, report_path, report)
                print(f"Chinese {year}: year completed", flush=True)
            report["coverage"] = await db.year_coverage(args.year_from, args.year_to)
            report["status"] = (
                "complete" if all(row["pending"] == 0 for row in report["coverage"]) else "partial"
            )
            report["finished_at"] = datetime.now(UTC).isoformat()
            await connection.execute(text("SELECT pg_advisory_unlock(1448438864)"))
    except BaseException as exc:
        report.update(
            status="interrupted"
            if isinstance(exc, (KeyboardInterrupt, asyncio.CancelledError))
            else "failed",
            error=type(exc).__name__,
        )
        raise
    finally:
        if locked:
            await asyncio.to_thread(save_report, report_path, report)
        await translator.close()
        await db.aclose()
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--year-from", type=int, default=2020)
    parser.add_argument("--year-to", type=int, default=2026)
    parser.add_argument(
        "--batch-size", type=int, default=256, choices=range(1, 513), metavar="1..512"
    )
    parser.add_argument("--pause", type=float, default=1.0)
    parser.add_argument("--report", default="verification/chinese-descriptions.json")
    args = parser.parse_args()
    if not 1999 <= args.year_from <= args.year_to <= 2100 or not 0 <= args.pause <= 30:
        parser.error("invalid year range or pause")
    asyncio.run(main(args))

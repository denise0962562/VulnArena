"""Import the official NVD annual corpus with verified downloads and atomic resume.

python scripts/import_nvd_feeds.py --start-year 2002 --end-year 2026
Repeating this command skips unchanged completed feeds and resumes partial feeds.
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select, text

from vulnarena.bulk import FeedDownloader, feed_batches, feed_header, next_batch
from vulnarena.config import Settings
from vulnarena.db import CVE, Database
from vulnarena.nvd import NVDClient, parse_cve

ROOT = Path(__file__).resolve().parents[1]
LOCK_ID = 1448438863


def lower_priority():
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.SetPriorityClass(kernel.GetCurrentProcess(), 0x00004000)  # BELOW_NORMAL


def save_report(path: Path, report: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


async def count_records(db):
    async with db.read_sessions() as session:
        return await session.scalar(select(func.count()).select_from(CVE))


async def import_feeds(args):
    lower_priority()
    settings = Settings()
    db = Database(settings.database_url.get_secret_value(), schema=settings.database_schema)
    downloader = FeedDownloader(ROOT / "data/nvd-feeds")
    api = NVDClient(settings)
    report_path = ROOT / args.report
    report = {
        "started_at": datetime.now(UTC).isoformat(),
        "status": "running",
        "source": "Official NVD JSON 2.0 annual feeds + recent API changes",
        "feeds": {},
        "errors": [],
        "translation": "not started",
        "batch_size": args.batch_size,
        "pause_seconds": args.pause,
    }
    owns_lock = False
    try:
        await db.initialize()
        async with db.engine.connect() as connection:
            connection = await connection.execution_options(isolation_level="AUTOCOMMIT")
            locked = await connection.scalar(
                text("SELECT pg_try_advisory_lock(:key)"), {"key": LOCK_ID}
            )
            if not locked:
                raise RuntimeError("another NVD bulk import is already running")
            owns_lock = True
            try:
                report["initial_total"] = await count_records(db)
                await asyncio.to_thread(save_report, report_path, report)
                for year in range(args.end_year, args.start_year - 1, -1):
                    entry = {"status": "downloading"}
                    report["feeds"][str(year)] = entry
                    await asyncio.to_thread(save_report, report_path, report)
                    print(f"Feed {year}: checking official metadata", flush=True)
                    try:
                        meta = await asyncio.to_thread(downloader.metadata, year)
                        entry.update(
                            gzip_bytes=meta.gz_size, json_bytes=meta.size, sha256=meta.sha256
                        )
                        await asyncio.to_thread(save_report, report_path, report)
                        saved = await db.get_feed_state(year)
                        if saved.get("sha256") == meta.sha256 and saved.get("status") == "complete":
                            entry.update(saved, status="unchanged")
                            print(
                                f"Feed {year}: unchanged, {saved['processed']} records", flush=True
                            )
                            continue
                        path = await asyncio.to_thread(downloader.obtain, year, meta)
                        header = await asyncio.to_thread(feed_header, path)
                        total = header["totalResults"]
                        start = (
                            saved.get("processed", 0) if saved.get("sha256") == meta.sha256 else 0
                        )
                        if not isinstance(start, int) or not 0 <= start <= total:
                            raise ValueError("invalid saved feed cursor")
                        cursor = {
                            "sha256": meta.sha256,
                            "processed": start,
                            "total": total,
                            "status": "running",
                            "source_modified": meta.modified,
                            "url": f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz",
                        }
                        entry.update(cursor, gzip_bytes=meta.gz_size, written=0)
                        print(f"Feed {year}: SHA-256 verified; resume {start}/{total}", flush=True)
                        batches = feed_batches(path, args.batch_size, skip=start)
                        while item := await asyncio.to_thread(next_batch, batches):
                            processed, records = item
                            if processed > total:
                                raise ValueError("feed count exceeds official envelope")
                            cursor.update(
                                processed=processed, updated_at=datetime.now(UTC).isoformat()
                            )
                            written = await db.upsert_many(records, feed_state=(year, dict(cursor)))
                            entry.update(cursor, written=entry["written"] + written)
                            report["current_year"] = year
                            await asyncio.to_thread(save_report, report_path, report)
                            if processed % 5000 == 0 or processed == total:
                                print(f"Feed {year}: {processed}/{total}", flush=True)
                            await asyncio.sleep(args.pause)
                        if cursor["processed"] != total:
                            raise ValueError("feed count does not match official envelope")
                        cursor.update(status="complete", completed_at=datetime.now(UTC).isoformat())
                        await db.upsert_many([], feed_state=(year, cursor))
                        entry.update(cursor)
                        report["current_total"] = await count_records(db)
                        print(
                            f"Feed {year}: complete; library {report['current_total']}", flush=True
                        )
                    except Exception as exc:
                        entry.update(status="failed", error=type(exc).__name__)
                        report["errors"].append({"year": year, "type": type(exc).__name__})
                        print(
                            f"Feed {year}: FAILED ({type(exc).__name__}); cursor retained",
                            flush=True,
                        )
                    finally:
                        await asyncio.to_thread(save_report, report_path, report)
                    await asyncio.sleep(1)

                if args.recent_days:
                    end = datetime.now(UTC)
                    params = {
                        "lastModStartDate": (end - timedelta(days=args.recent_days)).isoformat(),
                        "lastModEndDate": end.isoformat(),
                        "resultsPerPage": 2000,
                    }
                    start = 0
                    report["recent"] = {"processed": 0, **params}
                    while True:
                        payload = await api.request({**params, "startIndex": start})
                        total = payload.get("totalResults")
                        if (
                            not isinstance(total, int)
                            or isinstance(total, bool)
                            or total < 0
                            or payload.get("startIndex") != start
                        ):
                            raise ValueError("invalid recent API pagination")
                        items = payload["vulnerabilities"]
                        if not items and start < total:
                            raise ValueError("unexpected empty recent API page")
                        records = [parse_cve(item["cve"]) for item in items]
                        for offset in range(0, len(records), args.batch_size):
                            await db.upsert_many(records[offset : offset + args.batch_size])
                            await asyncio.sleep(args.pause)
                        start += len(items)
                        report["recent"].update(processed=start, total=total)
                        await asyncio.to_thread(save_report, report_path, report)
                        print(f"Recent changes: {start}/{total}", flush=True)
                        if start >= total:
                            break
                probe = await api.request({"resultsPerPage": 1})
                report["upstream_api_total"] = probe.get("totalResults")
                report["final_total"] = await count_records(db)
                report["added"] = report["final_total"] - report["initial_total"]
                report["status"] = "complete" if not report["errors"] else "partial"
                report["finished_at"] = datetime.now(UTC).isoformat()
            finally:
                await connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": LOCK_ID})
    except BaseException as exc:
        report.update(
            status="interrupted"
            if isinstance(exc, (KeyboardInterrupt, asyncio.CancelledError))
            else "failed",
            error=type(exc).__name__,
        )
        raise
    finally:
        if owns_lock:
            await asyncio.to_thread(save_report, report_path, report)
        downloader.close()
        await api.aclose()
        await db.aclose()
    print(
        json.dumps(
            {key: value for key, value in report.items() if key != "feeds"},
            ensure_ascii=False,
            indent=2,
        ),
        flush=True,
    )
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start-year", type=int, default=2002)
    parser.add_argument("--end-year", type=int, default=datetime.now(UTC).year)
    parser.add_argument(
        "--batch-size", type=int, default=500, choices=range(1, 1001), metavar="1..1000"
    )
    parser.add_argument("--pause", type=float, default=0.2)
    parser.add_argument(
        "--recent-days", type=int, default=8, choices=range(0, 121), metavar="0..120"
    )
    parser.add_argument("--report", default="verification/nvd-bulk-import.json")
    args = parser.parse_args()
    if not 2002 <= args.start_year <= args.end_year <= datetime.now(UTC).year:
        parser.error("require 2002 <= start-year <= end-year <= current year")
    if not 0 <= args.pause <= 10:
        parser.error("pause must be between 0 and 10 seconds")
    raise SystemExit(asyncio.run(import_feeds(args)))

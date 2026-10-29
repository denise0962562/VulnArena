"""Resumable, bounded multi-ecosystem collection. Run from the project root.

Examples:
  python scripts/refresh_library.py --per-topic 100 --advisories 50 --enrich-limit 500
  python scripts/refresh_library.py --skip-fetch --enrich-limit 500 --references 2
"""

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import Integer, case, cast, func, literal, or_, select
from sqlalchemy.dialects.postgresql import JSONPATH

from vulnarena.config import Settings
from vulnarena.db import CVE, Database, Study
from vulnarena.nvd import NVDClient, severity_for
from vulnarena.schemas import SyncRequest, Vulnerability
from vulnarena.study import StudyCollector

TOPIC_QUERIES = [
    "Linux",
    "Windows",
    "Java",
    "golang",
    "Python",
    "PHP",
    "C++",
    ".NET",
    "Rust",
    "JavaScript",
    "OpenSSL",
    "FastAPI",
    "Django",
    "Spring",
]
ECOSYSTEMS = ["pip", "maven", "go", "composer", "nuget", "rust", "npm"]
CURATED = [
    "CVE-2021-44228",
    "CVE-2022-22965",
    "CVE-2024-3094",
    "CVE-2024-4577",
    "CVE-2021-34527",
    "CVE-2020-1472",
    "CVE-2019-0708",
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
]


def candidate_query(limit, *, only_missing=False, only_curated=False, advisory_ids=()):
    """Choose a bounded work set in SQL; never load the entire raw CVE corpus."""
    query = select(CVE).outerjoin(Study, Study.cve_id == CVE.cve_id)
    if only_curated:
        query = query.where(CVE.cve_id.in_(CURATED))
    if only_missing:
        incomplete_document = func.jsonb_path_exists(
            Study.content,
            cast(
                literal(
                    "$.documents[*] ? (!exists(@.translation_status) "
                    '|| @.translation_status != "complete")'
                ),
                JSONPATH,
            ),
        )
        query = query.where(
            or_(
                Study.cve_id.is_(None),
                func.coalesce(Study.content["translation_status"].astext, "") != "complete",
                func.coalesce(cast(Study.content["document_count"].astext, Integer), 0) <= 0,
                incomplete_document,
            )
        )
    return query.order_by(
        case((CVE.cve_id.in_(CURATED), 0), else_=1),
        case((CVE.cve_id.in_(list(advisory_ids)), 0), else_=1),
        case((Study.content["fetched_at"].astext.is_not(None), 1), else_=0),
        CVE.published_at.desc(),
        CVE.cve_id,
    ).limit(max(0, limit))


def github_record(advisory):
    cvss = advisory.get("cvss") or {}
    score = cvss.get("score")
    vector = cvss.get("vector_string") or ""
    version = (
        "3.1" if vector.startswith("CVSS:3.1") else "3.0" if vector.startswith("CVSS:3.0") else None
    )
    return Vulnerability(
        cve_id=advisory["cve_id"],
        description=advisory.get("summary") or "",
        description_lang="en",
        published_at=advisory["published_at"],
        last_modified_at=advisory["updated_at"],
        vuln_status="GitHub Reviewed" if not advisory.get("withdrawn_at") else "Withdrawn",
        cvss_score=score,
        cvss_version=version,
        cvss_vector=vector or None,
        severity=severity_for(score, version or "3.1") if score is not None else "UNKNOWN",
        references=[{"url": u} for u in advisory.get("references", [])],
        raw={"source": "GitHub Advisory", "advisory": advisory},
    )


async def main(args):
    settings = Settings()
    db = Database(settings.database_url.get_secret_value(), schema=settings.database_schema)
    nvd = NVDClient(settings)
    collector = StudyCollector(
        db,
        translate=not args.no_translate,
        translation_model=settings.translation_model,
        online_translation=settings.online_translation,
    )
    report_path = Path(args.report)
    report_path.parent.mkdir(exist_ok=True)
    cached = Path("data/advisory-cache.json")

    def read_cache():
        return json.loads(cached.read_text(encoding="utf-8")) if cached.exists() else {}

    by_cve = await asyncio.to_thread(read_cache)
    report = {
        "started_at": datetime.now(UTC).isoformat(),
        "queries": [],
        "errors": [],
        "enriched": 0,
        "translated": 0,
        "documents": 0,
    }

    def save():
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    try:
        await db.initialize()
        async with db.read_sessions() as session:
            report["initial_total"] = await session.scalar(select(func.count()).select_from(CVE))
        if not args.skip_fetch:
            for ecosystem in ECOSYSTEMS:
                if not args.advisories:
                    break
                url = (
                    "https://api.github.com/advisories?type=reviewed&ecosystem="
                    + ecosystem
                    + f"&per_page={args.advisories}&sort=published&direction=desc"
                )
                try:
                    _, body = await collector.download(url)
                    advisories = json.loads(body)
                    if not isinstance(advisories, list):
                        raise ValueError("expected advisories array")
                    added = 0
                    for advisory in advisories:
                        cve_id = advisory.get("cve_id")
                        if not cve_id or advisory.get("withdrawn_at"):
                            continue
                        by_cve[cve_id] = [advisory]
                        if await db.get(cve_id) is None:
                            await db.upsert([github_record(advisory)])
                            added += 1
                    cached.parent.mkdir(exist_ok=True)
                    await asyncio.to_thread(
                        cached.write_text, json.dumps(by_cve, ensure_ascii=False), encoding="utf-8"
                    )
                    report["queries"].append(
                        {"ecosystem": ecosystem, "received": len(advisories), "added": added}
                    )
                    print(
                        f"GitHub {ecosystem}: {len(advisories)} advisories, {added} new CVEs",
                        flush=True,
                    )
                except Exception as exc:
                    report["errors"].append({"ecosystem": ecosystem, "type": type(exc).__name__})
                save()
            for term in TOPIC_QUERIES if args.per_topic else []:
                try:
                    records = await nvd.fetch(
                        SyncRequest(keyword=term, max_records=args.per_topic, latest=True)
                    )
                    changed = await db.upsert(records)
                    report["queries"].append(
                        {"keyword": term, "received": len(records), "changed": changed}
                    )
                    print(f"NVD {term}: {len(records)} records", flush=True)
                except Exception as exc:
                    report["errors"].append({"keyword": term, "type": type(exc).__name__})
                    print(f"NVD {term}: {type(exc).__name__}", flush=True)
                save()
            for cve_id in CURATED if args.curated else []:
                try:
                    records = await nvd.fetch(SyncRequest(cve_id=cve_id))
                    await db.upsert(records)
                    print(f"Curated {cve_id}", flush=True)
                except Exception as exc:
                    report["errors"].append({"cve_id": cve_id, "type": type(exc).__name__})
                save()
        async with db.read_sessions() as session:
            rows = await session.scalars(
                candidate_query(
                    args.enrich_limit,
                    only_missing=args.only_missing,
                    only_curated=args.only_curated,
                    advisory_ids=by_cve,
                )
            )
            pending_records = [Vulnerability.model_validate(row) for row in rows]

        semaphore = asyncio.Semaphore(args.workers)

        async def enrich_one(record):
            async with semaphore:
                await enrich_record(record)

        async def enrich_record(record):
            try:
                advisories = by_cve.get(record.cve_id, [])
                if args.only_curated and not advisories:
                    try:
                        _, body = await collector.download(
                            "https://api.github.com/advisories?cve_id=" + record.cve_id
                        )
                        payload = json.loads(body)
                        if isinstance(payload, list):
                            advisories = payload
                    except Exception:
                        pass  # CNA and vendor sources still proceed if GitHub is unavailable.
                study = await collector.collect(
                    record,
                    advisories=advisories,
                    references=args.references,
                    force=args.force,
                )
                report["enriched"] += 1
                report["translated"] += study.get("translation_status") == "complete"
                report["documents"] += study.get("document_count", 0)
                print(
                    f"Study {report['enriched']}: {record.cve_id} {study['document_count']} docs; "
                    f"zh={study['translation_status']}",
                    flush=True,
                )
            except Exception as exc:
                report["errors"].append({"cve_id": record.cve_id, "type": type(exc).__name__})
                print(f"Study {record.cve_id}: {type(exc).__name__}", flush=True)
            save()

        await asyncio.gather(*(enrich_one(record) for record in pending_records))
        async with db.read_sessions() as session:
            report["final_total"] = await session.scalar(select(func.count()).select_from(CVE))
            report["study_total"] = await session.scalar(select(func.count()).select_from(Study))
        report["finished_at"] = datetime.now(UTC).isoformat()
        save()
        print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    finally:
        await collector.aclose()
        await nvd.aclose()
        await db.aclose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--per-topic", type=int, default=100, choices=range(0, 1001), metavar="0..1000"
    )
    parser.add_argument(
        "--advisories", type=int, default=50, choices=range(0, 101), metavar="0..100"
    )
    parser.add_argument("--enrich-limit", type=int, default=500)
    parser.add_argument("--references", type=int, default=1, choices=range(0, 4))
    parser.add_argument("--skip-fetch", action="store_true")
    parser.add_argument("--curated", action="store_true")
    parser.add_argument("--no-translate", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--only-missing", action="store_true")
    parser.add_argument("--only-curated", action="store_true")
    parser.add_argument("--report", default="verification/library-refresh.json")
    parser.add_argument("--workers", type=int, default=3, choices=range(1, 5))
    asyncio.run(main(parser.parse_args()))

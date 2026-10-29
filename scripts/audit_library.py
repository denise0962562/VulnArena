"""Write a factual coverage report for the current local learning library."""

import asyncio
import json
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from vulnarena.config import Settings
from vulnarena.db import CVE, Database, Study
from vulnarena.schemas import Vulnerability
from vulnarena.study_contract import study_matches
from vulnarena.topics import classify


async def main():
    settings = Settings()
    db = Database(settings.database_url.get_secret_value(), schema=settings.database_schema)
    try:
        counts = Counter()
        topics = Counter()
        sources = Counter()
        languages = Counter()
        incomplete = []
        async with db.read_sessions() as session:
            rows = await session.stream(
                select(CVE, Study.content)
                .outerjoin(Study, Study.cve_id == CVE.cve_id)
                .execution_options(yield_per=200)
            )
            async for row, study in rows:
                record = Vulnerability.model_validate(row)
                counts["total"] += 1
                languages[record.description_lang or "unknown"] += 1
                study = study or {}
                topics.update(study.get("topics") or classify(record.description) or ["其他"])
                counts["studied"] += bool(study)
                counts["translated_summaries"] += study.get("translation_status") == "complete"
                counts["stale_studies"] += not study_matches(record, study)
                docs = study.get("documents", [])
                counts["with_documents"] += bool(docs)
                counts["documents"] += len(docs)
                counts["translated_documents"] += sum(
                    d.get("translation_status") == "complete" for d in docs
                )
                sources.update(d.get("source", "unknown") for d in docs)
                if (
                    not study
                    or study.get("translation_status") != "complete"
                    or not docs
                    or any(d.get("translation_status") != "complete" for d in docs)
                ):
                    incomplete.append(record.cve_id)
        report = {
            "checked_at": datetime.now(UTC).isoformat(),
            "counts": dict(counts),
            "topics": dict(topics),
            "document_sources": dict(sources),
            "description_languages": dict(languages),
            "incomplete": sorted(incomplete),
        }
        path = Path("verification/library-audit.json")
        await asyncio.to_thread(
            path.write_text, json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(
            json.dumps(
                {key: value for key, value in report.items() if key != "incomplete"},
                ensure_ascii=False,
                indent=2,
            )
        )
        print("Incomplete records:", len(incomplete))
    finally:
        await db.aclose()


if __name__ == "__main__":
    asyncio.run(main())

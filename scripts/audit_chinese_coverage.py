"""Audit current Chinese summaries and locally collected bilingual documents."""

import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from vulnarena.config import Settings
from vulnarena.db import (
    CVE,
    ChineseDescription,
    Database,
    Study,
    current_chinese_join,
    year_filters,
)
from vulnarena.study_contract import usable_chinese


async def main():
    settings = Settings()
    db = Database(settings.database_url.get_secret_value(), schema=settings.database_schema)
    try:
        report = {
            "checked_at": datetime.now(UTC).isoformat(),
            "period": "CVE ID years 2020–2026",
            "years": await db.year_coverage(),
            "library": await db.library_stats(),
            "documents": 0,
            "documents_missing_chinese": [],
            "documents_incomplete": [],
            "summaries_invalid_chinese": [],
        }
        # Stream summary text only, never materialize full raw CVEs for the corpus.
        async with db.read_sessions() as session:
            stream = await session.stream(
                select(CVE.cve_id, CVE.description, ChineseDescription.text_zh)
                .join(ChineseDescription, current_chinese_join())
                .where(*year_filters(2020, 2026))
                .execution_options(yield_per=1000)
            )
            async for identifier, source, translated in stream:
                if not usable_chinese(source, translated):
                    report["summaries_invalid_chinese"].append(identifier)
        async with db.read_sessions() as session:
            stream = await session.stream(
                select(Study.cve_id, Study.content)
                .where(*[Study.cve_id >= "CVE-2020-", Study.cve_id < "CVE-2027-"])
                .execution_options(yield_per=50)
            )
            async for identifier, study in stream:
                for index, document in enumerate(study.get("documents", []), 1):
                    report["documents"] += 1
                    if (
                        document.get("text_en", "").strip()
                        and document.get("translation_status") != "complete"
                    ):
                        report["documents_incomplete"].append(
                            {"cve_id": identifier, "document": index}
                        )
                    if not usable_chinese(document.get("text_en", ""), document.get("text_zh", "")):
                        report["documents_missing_chinese"].append(
                            {"cve_id": identifier, "document": index, "url": document.get("url")}
                        )
        report["total"] = sum(row["total"] for row in report["years"])
        report["translated"] = sum(row["translated"] for row in report["years"])
        report["pending"] = sum(row["pending"] for row in report["years"])
        path = Path("verification/chinese-coverage-audit.json")
        await asyncio.to_thread(
            path.write_text, json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
    finally:
        await db.aclose()


if __name__ == "__main__":
    asyncio.run(main())

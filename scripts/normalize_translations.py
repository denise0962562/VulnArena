"""Remove leaked SentencePiece whitespace markers from stored Chinese text only."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import func, select, update

from vulnarena.config import Settings
from vulnarena.db import Database, Study, Translation


async def main():
    settings = Settings()
    db = Database(settings.database_url.get_secret_value(), schema=settings.database_schema)
    count = 0
    try:
        await db.initialize()
        async with db.read_sessions() as session:
            studies = (await session.execute(select(Study.cve_id, Study.content))).all()
        for cve_id, content in studies:
            changed = False
            if "▁" in content.get("description_zh", ""):
                content["description_zh"] = content["description_zh"].replace("▁", " ").strip()
                changed = True
            for doc in content.get("documents", []):
                if "▁" in doc.get("text_zh", ""):
                    doc["text_zh"] = doc["text_zh"].replace("▁", " ").strip()
                    changed = True
            if changed:
                await db.save_study(cve_id, content)
                count += 1
        async with db.sessions.begin() as session:
            await session.execute(
                update(Translation)
                .where(Translation.text.contains("▁"))
                .values(text=func.replace(Translation.text, "▁", " "))
            )
        print(f"Normalized {count} study records; English originals remain untouched.")
    finally:
        await db.aclose()


if __name__ == "__main__":
    asyncio.run(main())

"""Inspect or apply checked, forward-only PostgreSQL migrations. Back up first."""

import argparse
import asyncio
import json

from vulnarena.config import Settings
from vulnarena.db import Database
from vulnarena.intelligence import models  # noqa: F401
from vulnarena.migrations import status


async def run(apply):
    db = Database(Settings().database_url.get_secret_value())
    try:
        if apply:
            await db.initialize()
        async with db.engine.connect() as connection:
            versions = await status(connection)
        print(json.dumps(versions, default=str, indent=2))
    finally:
        await db.aclose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Apply pending upgrades after backup")
    asyncio.run(run(parser.parse_args().apply))

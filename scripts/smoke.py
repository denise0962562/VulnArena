"""Manual live smoke check. NOT collected by pytest or run in CI."""

import argparse
import asyncio
import json
import time

import httpx


async def smoke(base_url: str, cve_id: str) -> None:
    async with httpx.AsyncClient(base_url=base_url, timeout=10, trust_env=False) as client:
        health = await client.get("/health")
        health.raise_for_status()
        response = await client.post("/api/sync", json={"cve_id": cve_id})
        response.raise_for_status()
        task_id = response.json()["id"]
        deadline = time.monotonic() + 330
        while time.monotonic() < deadline:
            task = await client.get(f"/api/tasks/{task_id}")
            task.raise_for_status()
            if task.json()["status"] in ("SUCCESS", "FAILED"):
                break
            await asyncio.sleep(1)
        else:
            raise RuntimeError("synchronization did not finish within 330 seconds")
        if task.json()["status"] != "SUCCESS":
            raise RuntimeError(task.json()["error"])
        record = await client.get(f"/api/vulnerabilities/{cve_id}")
        record.raise_for_status()
        result = {
            "health": health.json(),
            "task": task.json(),
            "record": {
                key: record.json()[key]
                for key in (
                    "cve_id",
                    "vuln_status",
                    "cvss_score",
                    "cvss_version",
                    "published_at",
                    "last_modified_at",
                    "severity",
                )
            },
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--cve-id", default="CVE-2021-44228")
    args = parser.parse_args()
    asyncio.run(smoke(args.base_url, args.cve_id))

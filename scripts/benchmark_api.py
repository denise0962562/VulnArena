"""Serial local HTTP timings; no generation, training, or model API calls."""

import argparse
import json
import math
import os
import platform
import statistics
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from vulnarena.config import Settings


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--out", type=Path, default=Path("verification/api-benchmark.json"))
    args = parser.parse_args()
    if not 5 <= args.samples <= 200 or not 0 <= args.interval <= 10:
        parser.error("samples must be 5..200; interval must be 0..10 seconds")
    if urlsplit(args.base_url).hostname not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("This benchmark only sends credentials to loopback addresses.")
    key = Settings().admin_token.get_secret_value()
    headers = {"x-vulnarena-admin": key} if key else {}
    with httpx.Client(
        base_url=args.base_url, headers=headers, trust_env=False, timeout=60
    ) as client:
        system = client.get("/api/system/status")
        system.raise_for_status()
        ai = client.get("/api/ai/status")
        ai.raise_for_status()
        if any(job["status"] in {"pending", "running"} for job in ai.json()["jobs"]):
            raise SystemExit(
                "Wait for background indexing/evaluation to finish for comparable timings."
            )
        endpoints = [
            ("health", "GET", "/health", None),
            (
                "library-page",
                "GET",
                "/api/vulnerabilities?page=1&page_size=20&year_from=2020&year_to=2026",
                None,
            ),
            ("library-stats", "GET", "/api/library/stats", None),
            ("cve-detail", "GET", "/api/vulnerabilities/CVE-2021-44228", None),
            (
                "hybrid-search",
                "POST",
                "/api/ai/search",
                {
                    "question": "Log4j 日志中的 JNDI LDAP 查找为何会导致远程代码执行",
                    "mode": "hybrid",
                },
            ),
        ]
        results = []
        for name, method, path, body in endpoints:
            observations = []
            request_ids = []
            for i in range(args.samples + 2):
                started = time.perf_counter()
                response = client.request(method, path, json=body)
                response.raise_for_status()
                elapsed = (time.perf_counter() - started) * 1000
                if i >= 2:
                    observations.append(round(elapsed, 3))
                    request_ids.append(response.headers.get("x-request-id"))
                time.sleep(args.interval)
            results.append(
                {
                    "endpoint": name,
                    "samples": len(observations),
                    "p50_ms": percentile(observations, 0.5),
                    "p95_ms": percentile(observations, 0.95),
                    "mean_ms": round(statistics.mean(observations), 3),
                    "min_ms": min(observations),
                    "max_ms": max(observations),
                    "observations_ms": observations,
                    "request_ids": request_ids,
                }
            )
            print(name, "p50/p95 ms:", results[-1]["p50_ms"], results[-1]["p95_ms"])
        report = {
            "method": (
                "serial, two warmups per endpoint excluded; "
                "nearest-rank quantiles; no model generation"
            ),
            "environment": {
                "platform": platform.platform(),
                "python": platform.python_version(),
                "logical_cpus": os.cpu_count(),
            },
            "system": system.json(),
            "index": ai.json()["index"],
            "results": results,
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()

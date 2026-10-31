"""Ablate explicit technical-name constraints on one frozen local index. No LLM calls."""

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

from vulnarena.config import Settings
from vulnarena.db import Database
from vulnarena.intelligence.benchmarks import VERSION, cases
from vulnarena.intelligence.evaluation import summarize
from vulnarena.intelligence.schemas import SearchRequest
from vulnarena.intelligence.service import IntelligenceService


async def main():
    settings = Settings()
    db = Database(settings.database_url.get_secret_value())
    service = IntelligenceService(db, settings)
    try:
        running = [
            job
            for job in await service.repository.recent_jobs()
            if job["status"] in {"pending", "running"}
        ]
        if running:
            raise SystemExit("Wait for indexing/evaluation to finish before the ablation.")
        before = await service.repository.corpus_snapshot()
        rows = []
        for enabled in [False, True]:
            # This experiment is an isolated process; it never patches the web service.
            if enabled:
                from vulnarena.intelligence.query import query_anchors

                replacement = query_anchors
            else:

                def replacement(_):
                    return []

            with (
                patch("vulnarena.intelligence.retrieval.query_anchors", replacement),
                patch("vulnarena.intelligence.repository.query_anchors", replacement),
            ):
                for case in cases():
                    result = await service.search(
                        SearchRequest(question=case["question"], mode="hybrid", top_k=10)
                    )
                    if result["diagnostics"]["mode"] == "keyword_fallback":
                        raise RuntimeError(
                            "Semantic encoder unavailable: do not label this a hybrid experiment."
                        )
                    retrieved = list(
                        dict.fromkeys(source["cve_id"] for source in result["sources"])
                    )[:5]
                    expected = case["expected_cves"]
                    ranks = [
                        retrieved.index(identifier) + 1
                        for identifier in expected
                        if identifier in retrieved
                    ]
                    rows.append(
                        {
                            **case,
                            "mode": "with_constraints" if enabled else "without_constraints",
                            "retrieved_cves": retrieved,
                            "recall_at_5": len(set(retrieved).intersection(expected))
                            / len(expected)
                            if expected
                            else 0,
                            "reciprocal_rank": 1 / min(ranks) if ranks else 0,
                            "retrieval_ms": result["retrieval_ms"],
                            "skipped": False,
                        }
                    )
                    await asyncio.sleep(0.05)
        after = await service.repository.corpus_snapshot()
        if (
            before["index_fingerprint"] != after["index_fingerprint"]
            or before["data_revision"] != after["data_revision"]
        ):
            raise RuntimeError("Corpus changed; rerun instead of comparing mismatched snapshots.")
        report = {
            "dataset_version": VERSION,
            "index_snapshot": before,
            "experiment": (
                "same index and hybrid ranking, explicit technical-name "
                "constraints off/on; no generation"
            ),
            "natural_language": {
                mode: summarize(
                    [
                        row
                        for row in rows
                        if row["mode"] == mode
                        and row["category"] in {"english", "cross_language", "paraphrase"}
                    ]
                )
                for mode in ["without_constraints", "with_constraints"]
            },
            "rows": rows,
        }
        output = Path("verification/retrieval-ablation.json")
        output.parent.mkdir(exist_ok=True)
        await asyncio.to_thread(
            output.write_text, json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(json.dumps(report["natural_language"]))
    finally:
        await service.close()
        await db.aclose()


if __name__ == "__main__":
    asyncio.run(main())

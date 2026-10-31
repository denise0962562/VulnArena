import asyncio
import time

from vulnarena.intelligence.benchmarks import VERSION, cases, dataset_info
from vulnarena.intelligence.retrieval import RETRIEVAL_VERSION
from vulnarena.intelligence.schemas import SearchRequest
from vulnarena.intelligence.sources import PROMPT_VERSION, SOURCE_VERSION


def summarize(rows):
    positive = [row for row in rows if row["expected_cves"] and not row.get("skipped")]
    negatives = [row for row in rows if row["expected_abstain"] and not row.get("skipped")]
    return {
        "cases": len(rows),
        "evaluated": sum(not row.get("skipped") for row in rows),
        "skipped": sum(bool(row.get("skipped")) for row in rows),
        "recall_at_5": round(sum(row["recall_at_5"] for row in positive) / len(positive), 4)
        if positive
        else None,
        "mrr": round(sum(row["reciprocal_rank"] for row in positive) / len(positive), 4)
        if positive
        else None,
        "no_evidence_accuracy": round(
            sum(not row["retrieved_cves"] for row in negatives) / len(negatives), 4
        )
        if negatives
        else None,
        "mean_retrieval_ms": round(
            sum(row["retrieval_ms"] for row in rows if not row.get("skipped"))
            / max(1, sum(not row.get("skipped") for row in rows))
        ),
    }


async def start_evaluation(service, request):
    selected = cases(request.dataset)[: request.limit]

    async def run(identity):
        corpus_before = await service.repository.corpus_snapshot()
        rows = []
        seed_ids = list({identifier for case in selected for identifier in case["expected_cves"]})
        indexed = {}
        present = await service.repository.snapshots(seed_ids)
        for identifier in seed_ids:
            indexed[identifier] = bool(
                await service.repository.index_signature(identifier, service.encoder.model_name)
            )
        total = len(selected) * 3 + (request.generation_limit if request.include_generation else 0)
        await service.repository.update_job(identity, total=total)
        for mode in ["keyword", "semantic", "hybrid"]:
            for case in selected:
                skipped = any(
                    identifier not in present for identifier in case["expected_cves"]
                ) or (
                    mode != "keyword"
                    and case["category"] != "exact_cve"
                    and any(not indexed[identifier] for identifier in case["expected_cves"])
                )
                started = time.monotonic()
                result = (
                    await service.search(
                        SearchRequest(question=case["question"], mode=mode, top_k=10)
                    )
                    if not skipped
                    else {"sources": [], "diagnostics": {"mode": "skipped"}}
                )
                if result["diagnostics"]["mode"] == "keyword_fallback" and mode != "keyword":
                    skipped = True
                retrieved = list(dict.fromkeys(source["cve_id"] for source in result["sources"]))[
                    :5
                ]
                expected = set(case["expected_cves"])
                ranks = [
                    retrieved.index(identifier) + 1
                    for identifier in expected
                    if identifier in retrieved
                ]
                rows.append(
                    {
                        **case,
                        "mode": mode,
                        "effective_mode": result["diagnostics"]["mode"],
                        "retrieved_cves": retrieved,
                        "skipped": skipped,
                        "recall_at_5": len(expected.intersection(retrieved)) / len(expected)
                        if expected
                        else 0,
                        "reciprocal_rank": 1 / min(ranks) if ranks else 0,
                        "retrieval_ms": round((time.monotonic() - started) * 1000),
                    }
                )
                if len(rows) % 5 == 0:
                    await service.repository.update_job(
                        identity,
                        progress=len(rows),
                        result={"stage": "retrieval", "mode": mode, "completed_cases": len(rows)},
                    )
                await asyncio.sleep(0.05)
        generations = []
        if request.include_generation:
            # Human-readable, supported source questions; each call follows the same budget.
            samples = [case for case in selected if case["category"] == "cross_language"][
                : request.generation_limit
            ]
            for case in samples:
                answer = await service.ask(
                    SearchRequest(question=case["question"]),
                    trace_kind="evaluation",
                    use_cache=False,
                    wait_for_model=True,
                )
                generations.append(
                    {
                        "case_id": case["id"],
                        "question": case["question"],
                        "status": answer["status"],
                        "trace_id": answer["trace_id"],
                        "quote_validation_passed": answer["telemetry"].get("citation_check")
                        == "passed",
                        "quote_validation_status": answer["telemetry"].get(
                            "citation_check", "not_checked"
                        ),
                        "cited_cves": list(
                            dict.fromkeys(
                                source["cve_id"]
                                for source in answer.get("sources", [])
                                if source["source_id"]
                                in {
                                    reference["source_id"]
                                    for claim in answer.get("claims", [])
                                    for reference in claim["references"]
                                }
                            )
                        ),
                        "human_entailment_review": "pending",
                        "answer": answer,
                    }
                )
                await service.repository.update_job(identity, progress=len(rows) + len(generations))
        results = {
            "dataset_version": dataset_info(request.dataset)["version"]
            if request.dataset != "development"
            else VERSION,
            "dataset": request.dataset,
            "dataset_cases": len(selected),
            "index_snapshot": corpus_before,
            "configuration": {
                "build_id": getattr(service, "build_id", "standalone"),
                "prompt_version": PROMPT_VERSION,
                "source_version": SOURCE_VERSION,
                "retrieval_version": RETRIEVAL_VERSION,
                "embedding_model": service.encoder.model_name,
                "generation_model": service.model.model,
                "minimum_cosine_similarity": service.settings.ai_min_similarity,
                "fusion": "RRF k=60; at most two chunks per CVE",
            },
            "dataset_note": dataset_info(request.dataset)["note"]
            if request.dataset != "development"
            else (
                "20 条核验 NVD 种子 × 4 种问法 + 20 条负例；包含模板扩展。"
                "此集用于开发基线，不代替独立留出集。"
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
                for mode in ["keyword", "semantic", "hybrid"]
            },
            "modes": {
                mode: summarize([row for row in rows if row["mode"] == mode])
                for mode in ["keyword", "semantic", "hybrid"]
            },
            "categories": {
                mode: {
                    category: summarize(
                        [row for row in rows if row["mode"] == mode and row["category"] == category]
                    )
                    for category in sorted({row["category"] for row in rows})
                }
                for mode in ["keyword", "semantic", "hybrid"]
            },
            "generation": generations,
            "generation_note": (
                "原文引用位置可程序校验；是否充分支持结论尚需人工复核，未将其标成事实正确率。"
            ),
            "rows": rows,
        }
        await service.repository.update_job(
            identity, progress=len(rows) + len(generations), total=len(rows) + len(generations)
        )
        return results

    return await service.start_job("evaluation", len(selected) * 3, run)

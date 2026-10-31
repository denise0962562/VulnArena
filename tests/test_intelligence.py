import asyncio
import io
import json
import os
import subprocess
import sys
import zipfile

import httpx
import pytest
from pydantic import SecretStr

from vulnarena.intelligence.llm import ModelClient
from vulnarena.intelligence.query import CVE_PATTERN, reciprocal_rank_fusion
from vulnarena.intelligence.schemas import IndexRequest, SearchRequest
from vulnarena.intelligence.service import IntelligenceService
from vulnarena.intelligence.sources import digest, make_sources, source_signature
from vulnarena.nvd import parse_cve


class FakeEncoder:
    model_name = "fixture-encoder-v1"
    available = True
    loaded = False

    async def encode(self, texts, *, query=False):
        return [[1.0, 0.0, 0.0] for _ in texts]

    async def close(self):
        pass


def model_transport(calls, *, bad_quote=False, card=False, empty_answer=False):
    async def respond(request):
        body = json.loads(request.content)
        calls.append(body)
        prompt = json.loads(body["messages"][1]["content"])
        assert "待分析数据" in body["messages"][0]["content"]
        source = prompt["sources"][0]
        reference = {"source_id": source["source_id"], "quote": source["text"][:80]}
        if bad_quote:
            reference["quote"] = "This sentence does not exist in any provided source."
        if card:
            content = {
                "sections": [
                    {
                        "key": key,
                        "status": "supported" if key == "overview" else "missing",
                        "text": "有原文依据的中文解释"
                        if key == "overview"
                        else "invented fix version 99",
                        "references": [reference] if key == "overview" else [],
                    }
                    for key in ["overview", "trigger", "impact", "remediation", "learning"]
                ]
            }
        else:
            content = {
                "insufficient": empty_answer,
                "claims": []
                if empty_answer
                else [{"text": "根据保存的原文解释这个漏洞。", "references": [reference]}],
                "missing_information": ["当前资料不足以回答。"] if empty_answer else [],
            }
        return httpx.Response(
            200,
            json={
                "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(content)}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 60},
            },
        )

    return httpx.MockTransport(respond)


async def install_model(app, calls, **options):
    service = app.state.intelligence
    await service.model.close()
    settings = service.settings.model_copy(
        update={
            "ai_api_key": SecretStr("fixture-secret-do-not-expose"),
            "ai_base_url": "https://model.example/v1",
            "ai_input_price_per_million": 1.0,
            "ai_output_price_per_million": 2.0,
        }
    )
    service.settings = settings
    service.model = ModelClient(settings, transport=model_transport(calls, **options))
    return service


async def wait_for_job(service, identity):
    for _ in range(200):
        job = await service.repository.job(identity)
        if job["status"] not in {"pending", "running"}:
            return job
        await asyncio.sleep(0.01)
    pytest.fail("bounded background job did not finish")


def test_query_ids_and_fusion_are_deterministic():
    assert CVE_PATTERN.findall("解释CVE-2021-44228的原因") == ["CVE-2021-44228"]
    fused = reciprocal_rank_fusion([["a", "b"], ["b", "c"]])
    assert fused[0][0] == "b"
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


def test_github_advisory_keeps_primary_authority(raw_cve):
    record = parse_cve(raw_cve)
    raw = {
        **record.raw,
        "source": "GitHub Advisory",
        "advisory": {"html_url": "https://github.com/advisories/GHSA-example"},
    }
    github = record.model_copy(update={"raw": raw})
    snapshot = make_sources(github, {})
    assert snapshot["facts"]["origin"] == raw["advisory"]["html_url"]
    assert snapshot["chunks"][0]["source"] == "GitHub Advisory"
    assert snapshot["chunks"][0]["url"] == raw["advisory"]["html_url"]
    assert source_signature(record, {}) != source_signature(github, {})


async def test_grounded_answer_cache_usage_and_statistics(api, raw_cve):
    client, app = api
    record = parse_cve(raw_cve)
    await app.state.db.upsert([record])
    calls = []
    service = await install_model(app, calls)
    question = {"question": "解释CVE-2024-1234的原因"}
    first = (await client.post("/api/ai/ask", json=question)).json()
    assert first["status"] == "complete"
    assert first["claims"][0]["references"][0]["quote"] == record.description
    assert first["telemetry"]["input_tokens"] == 120
    assert first["telemetry"]["estimated_cost"] == pytest.approx(0.00024)
    second = (await client.post("/api/ai/ask", json=question)).json()
    assert second["telemetry"]["cached"]
    assert second["telemetry"]["citation_check"] == "passed"
    assert len(calls) == 1
    stats = (await client.post("/api/ai/ask", json={"question": "2024年有多少严重漏洞"})).json()
    assert stats["status"] == "statistics" and stats["statistics"]["count"] == 1
    assert len(calls) == 1
    dashboard = await service.dashboard()
    assert dashboard["model_calls"] == 1 and dashboard["cache_hits"] == 1
    assert "fixture-secret" not in json.dumps(dashboard)
    # Metadata changes invalidate answers too, even with unchanged English.
    revised = record.model_copy(update={"cvss_score": 9.7})
    assert source_signature(record, {}) != source_signature(revised, {})
    await app.state.db.upsert([revised])
    third = (await client.post("/api/ai/ask", json=question)).json()
    assert not third["telemetry"]["cached"] and len(calls) == 2


async def test_invalid_citation_is_rejected_and_no_evidence_does_not_call_model(api, raw_cve):
    client, app = api
    await app.state.db.upsert([parse_cve(raw_cve)])
    calls = []
    await install_model(app, calls, bad_quote=True)
    bad = (await client.post("/api/ai/ask", json={"question": "解释 CVE-2024-1234"})).json()
    assert bad["status"] == "validation_failed" and not bad["claims"]
    assert bad["telemetry"]["citation_check"] == "rejected"
    unknown = (await client.post("/api/ai/ask", json={"question": "解释CVE-2099-999999"})).json()
    assert unknown["status"] == "insufficient" and unknown["sources"] == []
    assert len(calls) == 1
    outside = (await client.post("/api/ai/ask", json={"question": "写一首春天的诗"})).json()
    assert outside["status"] == "insufficient" and len(calls) == 1
    unrelated_count = (
        await client.post("/api/ai/ask", json={"question": "巴黎有多少个景点"})
    ).json()
    assert unrelated_count["status"] == "insufficient" and len(calls) == 1


async def test_card_missing_information_cache_and_staleness(api, raw_cve):
    client, app = api
    record = parse_cve(raw_cve)
    await app.state.db.upsert([record])
    calls = []
    await install_model(app, calls, card=True)
    first = (await client.post("/api/ai/cards/CVE-2024-1234")).json()
    assert first["status"] == "complete"
    assert first["sections"][3]["text"] == "当前本地资料未提供足够依据。"
    assert "invented" not in json.dumps(first)
    cached = (await client.post("/api/ai/cards/CVE-2024-1234")).json()
    assert cached["cached"] and len(calls) == 1
    for field in ["signature", "model", "prompt_version", "created_at", "evidence_scope"]:
        assert first[field] == cached[field]
    exported = await client.get("/api/ai/cards/CVE-2024-1234/download")
    assert exported.status_code == 200 and "AI 学习卡片" in exported.text
    bundle = await client.get("/api/vulnerabilities/CVE-2024-1234/download")
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as archive:
        assert "ai-study-card.md" in archive.namelist()
        assert json.loads(archive.read("ai-study-card.json"))["sections"][0]["text"]
    assert len(calls) == 1
    await app.state.db.upsert(
        [record.model_copy(update={"description": "Corrected original description"})]
    )
    stale = (await client.get("/api/ai/cards/CVE-2024-1234")).json()
    assert stale["status"] == "stale" and "sections" not in stale
    assert (await client.get("/api/ai/cards/CVE-2024-1234/download")).status_code == 409
    bundle = await client.get("/api/vulnerabilities/CVE-2024-1234/download")
    with zipfile.ZipFile(io.BytesIO(bundle.content)) as archive:
        assert "ai-study-card.md" not in archive.namelist()


async def test_index_retrieval_excludes_stale_sources_and_resumes(db, raw_cve, settings):
    service = IntelligenceService(
        db, settings.model_copy(update={"ai_index_pause": 0}), encoder=FakeEncoder()
    )
    record = parse_cve(raw_cve)
    await db.upsert([record])
    try:
        job = await service.start_index(IndexRequest(limit=20))
        finished = await wait_for_job(service, job["id"])
        assert finished["status"] == "complete" and finished["result"]["saved"] == 1
        result = await service.search(
            SearchRequest(question="Example vulnerability", mode="keyword")
        )
        assert result["sources"][0]["cve_id"] == record.cve_id
        await db.upsert(
            [record.model_copy(update={"description": "Updated vulnerability original"})]
        )
        result = await service.search(
            SearchRequest(question="Example vulnerability", mode="keyword")
        )
        assert not result["sources"] and result["diagnostics"]["stale_excluded"] == 1
        job = await service.start_index(IndexRequest(limit=20))
        finished = await wait_for_job(service, job["id"])
        assert finished["result"]["saved"] == 1
        job = await service.start_index(IndexRequest(limit=20))
        finished = await wait_for_job(service, job["id"])
        assert finished["result"]["reused"] == 1
    finally:
        await service.close()


async def test_daily_budget_and_sse_contract(api, raw_cve):
    client, app = api
    await app.state.db.upsert([parse_cve(raw_cve)])
    calls = []
    service = await install_model(app, calls)
    service.settings = service.settings.model_copy(update={"ai_daily_calls": 1})
    response = await client.post("/api/ai/ask/stream", json={"question": "解释 CVE-2024-1234"})
    assert response.status_code == 200
    assert "event: phase" in response.text and "event: answer" in response.text
    assert "event: done" in response.text
    second = (
        await client.post("/api/ai/ask", json={"question": "解释 CVE-2024-1234 的影响"})
    ).json()
    assert second["status"] == "unavailable"
    assert "额度" in second["message"] and len(calls) == 1
    assert (
        await client.post(
            "/api/ai/search",
            json={"question": "Linux漏洞", "filters": {"year_from": 2026, "year_to": 2020}},
        )
    ).status_code == 422


async def test_evaluation_persists_retrieval_and_reviewable_generation(db, raw_cve, settings):
    from vulnarena.intelligence.evaluation import start_evaluation
    from vulnarena.intelligence.schemas import EvaluationRequest

    raw_cve["id"] = "CVE-2021-44228"
    raw_cve["descriptions"] = [
        {
            "lang": "en",
            "value": "Apache Log4j JNDI LDAP message lookup allows remote code execution.",
        }
    ]
    await db.upsert([parse_cve(raw_cve)])
    configured = settings.model_copy(
        update={"ai_api_key": SecretStr("fixture-key"), "ai_index_pause": 0}
    )
    calls = []
    service = IntelligenceService(
        db,
        configured,
        encoder=FakeEncoder(),
        model=ModelClient(configured, transport=model_transport(calls)),
    )
    try:
        indexed = await service.start_index(IndexRequest(limit=20))
        assert (await wait_for_job(service, indexed["id"]))["status"] == "complete"
        evaluation = await start_evaluation(
            service, EvaluationRequest(limit=5, include_generation=True, generation_limit=1)
        )
        report = await wait_for_job(service, evaluation["id"])
        assert report["status"] == "complete", report["error"]
        assert report["result"]["index_snapshot"]["records"] == 1
        assert report["result"]["index_snapshot"]["index_fingerprint"]
        assert len(report["result"]["rows"]) == 15
        assert report["result"]["modes"]["hybrid"]["skipped"] == 1
        assert report["result"]["generation"][0]["quote_validation_passed"]
        assert report["result"]["generation"][0]["answer"]["claims"]
        assert len(calls) == 1
        recent = await service.repository.recent_jobs()
        assert "rows" not in recent[0]["result"]
        assert "answer" not in recent[0]["result"]["generation"][0]
    finally:
        await service.close()


async def test_native_worker_failure_is_contained(settings, monkeypatch):
    from vulnarena.intelligence.embeddings import CPUEncoder, EmbeddingUnavailable

    encoder = CPUEncoder(settings)

    async def start_fixture_worker():
        encoder.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import sys; sys.stdin.readline(); sys.exit(7)",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

    monkeypatch.setattr(encoder, "_start", start_fixture_worker)
    try:
        with pytest.raises(EmbeddingUnavailable):
            await encoder.encode(["fixture text"], query=True)
        assert not encoder.loaded
        assert not encoder.query_cache
    finally:
        await encoder.close()


async def test_background_generation_waits_for_foreground_request(api, raw_cve):
    client, app = api
    await app.state.db.upsert([parse_cve(raw_cve)])
    calls = []
    service = await install_model(app, calls)
    retrieved = asyncio.Event()

    async def phase(event):
        if event["phase"] == "sources":
            retrieved.set()

    async with service.generation_lock:
        task = asyncio.create_task(
            service.ask(
                SearchRequest(question="解释CVE-2024-1234的原因"),
                phase=phase,
                trace_kind="evaluation",
                use_cache=False,
                wait_for_model=True,
            )
        )
        await asyncio.wait_for(retrieved.wait(), 5)
        await asyncio.sleep(0)
        assert not task.done() and not calls
    result = await asyncio.wait_for(task, 5)
    assert result["status"] == "complete" and len(calls) == 1


async def test_empty_abstention_does_not_claim_citation_pass(api, raw_cve):
    from types import SimpleNamespace

    from vulnarena.intelligence.repository import as_job, now

    client, app = api
    await app.state.db.upsert([parse_cve(raw_cve)])
    calls = []
    await install_model(app, calls, empty_answer=True)
    for _ in range(2):
        answer = (await client.post("/api/ai/ask", json={"question": "解释CVE-2024-1234"})).json()
        assert answer["status"] == "partial" and answer["claims"] == []
        assert answer["telemetry"]["citation_check"] == "no_citations"
    assert len(calls) == 1
    old_sample = {"quote_validation_passed": True, "answer": {"claims": []}}
    row = SimpleNamespace(
        id="old-report",
        kind="evaluation",
        status="complete",
        progress=1,
        total=1,
        result={"generation": [old_sample]},
        error=None,
        created_at=now(),
        finished_at=now(),
    )
    saved = as_job(row, include_rows=False)["result"]["generation"][0]
    assert not saved["quote_validation_passed"]
    assert saved["quote_validation_status"] == "no_citations"
    assert old_sample["quote_validation_passed"]


async def test_background_work_is_serial_and_cancellable(db, settings):
    from vulnarena.intelligence.service import WorkBusy

    service = IntelligenceService(db, settings, encoder=FakeEncoder())
    ready = asyncio.Event()

    async def work(identity):
        await service.repository.update_job(identity, progress=1)
        ready.set()
        await asyncio.Event().wait()

    try:
        job = await service.start_job("index", 2, work)
        await ready.wait()
        with pytest.raises(WorkBusy):
            await service.start_job("evaluation", 2, work)
        cancelled = await service.cancel_job(job["id"])
        assert cancelled["status"] == "interrupted" and cancelled["progress"] == 1
    finally:
        await service.close()


async def test_interrupted_index_resumes_without_repeating_unchanged_embeddings(
    db, raw_cve, settings
):
    await db.upsert([parse_cve(raw_cve)])
    service = IntelligenceService(
        db, settings.model_copy(update={"ai_index_pause": 0}), encoder=FakeEncoder()
    )
    try:
        first = await service.start_index(IndexRequest(limit=20))
        assert (await wait_for_job(service, first["id"]))["status"] == "complete"
        lost = await service.repository.new_job(
            "index", 20, {"limit": 20, "force": True, "identifiers": [raw_cve["id"]]}
        )
        await service.repository.update_job(lost["id"], status="running")
        await service.startup()
        latest = (await service.repository.recent_jobs())[0]
        resumed = await wait_for_job(service, latest["id"])
        assert resumed["status"] == "complete" and resumed["result"]["reused"] == 1
        assert resumed["parameters"]["resumes"] == lost["id"]
        assert (await service.repository.job(lost["id"]))["status"] == "interrupted"
    finally:
        await service.close()

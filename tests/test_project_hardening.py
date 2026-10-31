import asyncio
import time

import httpx
import pytest

from vulnarena.arena import InMemoryEventBus, InMemoryPolicyStore
from vulnarena.arena.agents import AttackPlan
from vulnarena.arena.contracts import ArenaSession, ArenaStatus
from vulnarena.arena.deepseek import DeepSeekClient
from vulnarena.arena.registry import SessionRegistry
from vulnarena.arena.safe_regex import BoundedPattern
from vulnarena.config import Settings
from vulnarena.main import create_app


async def test_local_default_denies_remote_and_cross_origin_writes():
    app = create_app(Settings(_env_file=None))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/api/system/status")).status_code == 200
        denied = await c.post("/lab/selfplay", headers={"Origin": "https://attacker.example"})
        assert denied.status_code == 403
        assert "x-request-id" in denied.headers
        assert (await c.get("/lab", headers={"Host": "attacker.example"})).status_code == 403
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("203.0.113.1", 1)), base_url="http://test"
    ) as c:
        assert (await c.get("/api/system/status")).status_code == 403


async def test_admin_login_cookie_header_and_forgery():
    settings = Settings(_env_file=None, admin_token="fixture-admin-key")
    app = create_app(settings)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        assert (await c.get("/api/system/status")).status_code == 401
        assert (await c.get("/lab", headers={"Accept": "text/html"})).headers[
            "location"
        ] == "/login"
        assert (await c.post("/login", data={"token": "中文错误口令"})).status_code == 401
        login = await c.post("/login", data={"token": "fixture-admin-key"})
        assert login.status_code == 303 and "httponly" in login.headers["set-cookie"].lower()
        assert (await c.get("/api/system/status")).status_code == 200
        c.cookies.clear()
        assert (
            await c.get("/api/system/status", headers={"Cookie": "vulnarena_admin=0.fake.bad"})
        ).status_code == 401
        assert (
            await c.get("/api/system/status", headers={"x-vulnarena-admin": "fixture-admin-key"})
        ).status_code == 200


def test_pathological_regex_is_killed_and_next_operation_works():
    pattern = BoundedPattern(r"(a+)+$")
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        pattern.search("a" * 30000 + "!")
    assert time.monotonic() - started < 3
    assert BoundedPattern("hello").search_many(["hello world", "other"]) == [True, False]


async def test_model_retry_budget_is_strict_under_concurrency():
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(429, json={"error": "fixture-rate-limit"})

    async def no_sleep(_):
        await asyncio.sleep(0)

    model = DeepSeekClient(
        Settings(_env_file=None, deepseek_api_key="fixture", arena_max_llm_calls=2),
        transport=httpx.MockTransport(respond),
        sleep=no_sleep,
    )
    try:
        await asyncio.gather(*(model.json_chat("s", "u", AttackPlan) for _ in range(5)))
        assert len(calls) == model.calls == 2
        assert model.last_failure == "budget_exhausted"
    finally:
        await model.aclose()


async def test_shared_sandbox_rejects_overlapping_runs_and_restore(monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()

    async def slow_pipeline(ctx, **kwargs):
        entered.set()
        await release.wait()
        return ArenaSession(session_id=ctx.session_id, status=ArenaStatus.VERIFIED)

    monkeypatch.setattr("vulnarena.main.run_pipeline", slow_pipeline)
    app = create_app(Settings(_env_file=None))
    app.state.runtime.events = InMemoryEventBus()
    app.state.runtime.policy_store = InMemoryPolicyStore()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        first = asyncio.create_task(c.post("/api/arena/start"))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            assert (await c.post("/api/arena/start")).status_code == 409
            identity = app.state.sessions.all()[0].session_id
            assert (await c.post(f"/api/arena/sessions/{identity}/restore")).status_code == 409
        finally:
            release.set()
            assert (await first).status_code == 202
        assert not app.state.arena_busy


async def test_durable_reports_survive_registry_restart(db):
    first = SessionRegistry()
    await first.attach(db)
    finished = ArenaSession(session_id="finished", status=ArenaStatus.VERIFIED)
    from vulnarena.schemas import utcnow

    finished.finished_at = utcnow()
    await first.save(finished)
    await first.save(ArenaSession(session_id="unfinished"))
    second = SessionRegistry()
    await second.attach(db)
    assert second.get("finished").status == ArenaStatus.VERIFIED
    assert second.get("unfinished").status == ArenaStatus.INTERRUPTED
    assert second.get("unfinished").finished_at is not None


async def test_migrations_are_idempotent_and_checksum_protected(db):
    from sqlalchemy import text

    from vulnarena.migrations import upgrade

    async with db.engine.begin() as connection:
        await upgrade(connection)
        count = await connection.scalar(text("SELECT count(*) FROM schema_migrations"))
        assert count == 3
        await connection.execute(
            text(
                "UPDATE schema_migrations SET checksum='fixture-corruption' "
                "WHERE version='001_arena_reports.sql'"
            )
        )
        with pytest.raises(RuntimeError, match="Applied migration changed"):
            await upgrade(connection)


def test_full_advisory_chunks_include_late_remediation(raw_cve):
    from vulnarena.intelligence.sources import make_sources
    from vulnarena.nvd import parse_cve
    from vulnarena.study_contract import record_fingerprint

    record = parse_cve(raw_cve)
    study = {
        "fingerprint": record_fingerprint(record),
        "documents": [
            {
                "title": "Vendor advisory",
                "text_en": "Background details. " * 400
                + "Upgrade to the patched release: fixture-fix-9.8.",
                "url": "https://vendor.example/advisory",
            }
        ],
    }
    sources = make_sources(record, study)
    assert any("fixture-fix-9.8" in chunk["text"] for chunk in sources["chunks"])
    assert any(chunk["offset"] > 6000 for chunk in sources["chunks"])


async def test_human_review_workflow_preserves_answers_and_rejects_fake_sources(api):
    client, app = api
    repository = app.state.intelligence.repository
    job = await repository.new_job("evaluation", 1)
    answer = {
        "claims": [
            {
                "text": "fixture claim",
                "references": [{"source_id": "S1", "quote": "fixture evidence"}],
            }
        ],
        "sources": [{"source_id": "S1", "text": "fixture evidence", "cve_id": "CVE-2024-1234"}],
    }
    await repository.update_job(
        job["id"],
        status="complete",
        result={
            "generation": [
                {
                    "trace_id": "fixture-trace",
                    "answer": answer,
                    "human_entailment_review": "pending",
                }
            ]
        },
    )
    template = (await client.get(f"/api/ai/evaluations/{job['id']}/review-template")).json()
    assert template["reviews"][0]["evidence_reviewed"] is False
    body = {
        "reviews": [
            {
                "trace_id": "fixture-trace",
                "reviewer": "fixture-reviewer",
                "evidence_reviewed": True,
                "verdict": "unsupported",
                "source_ids": ["forged-source"],
                "explanation": "Fixture: quoted text does not support the stated conclusion.",
            }
        ]
    }
    assert (
        await client.post(f"/api/ai/evaluations/{job['id']}/reviews", json=body)
    ).status_code == 409
    body["reviews"][0]["source_ids"] = ["S1"]
    saved = await client.post(f"/api/ai/evaluations/{job['id']}/reviews", json=body)
    assert saved.status_code == 200
    sample = saved.json()["result"]["generation"][0]
    assert sample["answer"] == answer and sample["human_entailment_review"] == "reviewed"
    assert sample["latest_human_review"]["verdict"] == "unsupported"
    assert sample["latest_human_review"]["method"] == "human_self_reported"
    body["reviews"][0]["evidence_reviewed"] = False
    assert (
        await client.post(f"/api/ai/evaluations/{job['id']}/reviews", json=body)
    ).status_code == 422


def test_holdout_cves_are_disjoint_from_development():
    from vulnarena.intelligence.benchmarks import SEEDS, cases

    development = {row[0] for row in SEEDS}
    holdout = {cve for case in cases("holdout") for cve in case["expected_cves"]}
    assert not development.intersection(holdout) and len(holdout) == 10
    assert len(cases("holdout")) == 25
    assert all(
        case.get("label_review") == "human_pending"
        for case in cases("holdout")
        if case["expected_cves"]
    )


def test_card_prompt_is_bounded_but_can_include_late_fix(raw_cve):
    from vulnarena.intelligence.sources import card_evidence, make_sources
    from vulnarena.nvd import parse_cve

    record = parse_cve(raw_cve)
    study = {
        "documents": [
            {
                "text_en": "\n".join(
                    f"Background section {i}: details of the affected component. " * 10
                    for i in range(80)
                )
                + "\nUpgrade to patched release fixture-fix-9.8; "
                "workaround mitigation is available.",
                "url": "https://vendor.example/advisory",
                "title": "Vendor advisory",
            }
        ]
    }
    snapshot = make_sources(record, study)
    selected = card_evidence(snapshot["chunks"])
    assert len(selected) <= 8 < len(snapshot["chunks"])
    assert any("fixture-fix-9.8" in source["text"] for source in selected)


def test_security_domain_terms_and_alias_constraints():
    from vulnarena.intelligence.query import has_query_anchor, in_domain, query_anchors

    assert in_domain("Certificate validation and code-signing spoofing")
    assert in_domain("某网关身份认证绕过和敏感信息泄露")
    assert not in_domain("写一首生日祝福诗")
    anchors = query_anchors("Log4Shell 的触发条件是什么")
    assert "log4j" in anchors and "log4shell" not in anchors
    assert has_query_anchor("Apache Log4j JNDI features allow remote code execution", anchors)


def test_targeted_index_identifiers_are_bounded_and_canonical():
    from pydantic import ValidationError

    from vulnarena.intelligence.schemas import IndexRequest

    assert IndexRequest(identifiers=[" cve-2021-44228 ", "CVE-2021-44228"]).identifiers == [
        "CVE-2021-44228"
    ]
    with pytest.raises(ValidationError):
        IndexRequest(identifiers=["not-a-cve"])
    with pytest.raises(ValidationError):
        IndexRequest(identifiers=["CVE-2024-" + "9" * 100])

"""P3 复盘 + P4 AI 选序：模型可用则用，不可用就退回确定性链。"""

import json

import httpx
import pytest
import pytest_asyncio

from vulnarena.arena import ArenaRuntime, InMemoryEventBus, InMemoryPolicyStore, WafMiddleware
from vulnarena.arena.agents import plan_attack
from vulnarena.arena.attacker import CHAIN
from vulnarena.arena.context import ArenaContext
from vulnarena.arena.deepseek import DeepSeekClient
from vulnarena.arena.pipeline import run_pipeline
from vulnarena.arena.review import build_review
from vulnarena.config import Settings
from vulnarena.procure import ProcureState, build_procure_app

LABELS = [item.label for item in CHAIN]


async def _no_sleep(_seconds: float) -> None:
    return None


def settings_with_key() -> Settings:
    return Settings(_env_file=None, deepseek_api_key="sk-test-0000000000000000000000000000")


def llm_reply(payload: dict) -> httpx.MockTransport:
    body = json.dumps(payload, ensure_ascii=False)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": body}}]})

    return httpx.MockTransport(handler)


# --- P4：客户端与规划器 -------------------------------------------------------


async def test_plan_attack_keeps_only_known_labels():
    transport = llm_reply({"steps": [LABELS[3], "编造的步骤", LABELS[0]], "rationale": "先取数据"})
    llm = DeepSeekClient(settings_with_key(), transport=transport, sleep=_no_sleep)
    plan = await plan_attack(llm, LABELS)
    await llm.aclose()

    assert plan is not None
    assert plan.steps == [LABELS[3], LABELS[0]]
    assert plan.rationale == "先取数据"


async def test_plan_attack_falls_back_on_broken_json():
    transport = httpx.MockTransport(
        lambda _r: httpx.Response(200, json={"choices": [{"message": {"content": "{oops"}}]})
    )
    llm = DeepSeekClient(settings_with_key(), transport=transport, sleep=_no_sleep)
    assert await plan_attack(llm, LABELS) is None
    await llm.aclose()


async def test_plan_attack_retries_on_429_then_succeeds():
    calls = {"n": 0}
    body = json.dumps({"steps": [LABELS[1]], "rationale": "ok"}, ensure_ascii=False)

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, json={"error": "rate"})
        return httpx.Response(200, json={"choices": [{"message": {"content": body}}]})

    llm = DeepSeekClient(
        settings_with_key(), transport=httpx.MockTransport(handler), sleep=_no_sleep
    )
    plan = await plan_attack(llm, LABELS)
    await llm.aclose()
    assert plan is not None and plan.steps == [LABELS[1]]
    assert calls["n"] == 2


async def test_no_key_means_no_calls():
    llm = DeepSeekClient(Settings(_env_file=None), transport=llm_reply({"steps": []}))
    assert llm.available is False
    assert await plan_attack(llm, LABELS) is None
    await llm.aclose()


# --- 编排：AI 选序 + 确定性降级 ------------------------------------------------


@pytest_asyncio.fixture
async def arena():
    state = ProcureState(canary="CANARY-AI-0001")
    app = build_procure_app(state=state)
    runtime = ArenaRuntime(cache_ttl=0.0)
    runtime.policy_store = InMemoryPolicyStore()
    runtime.events = InMemoryEventBus()
    app.add_middleware(WafMiddleware, runtime=runtime)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://arena") as client:
        yield client, state, runtime
    await state.aclose()


async def test_pipeline_uses_the_model_plan(arena):
    client, state, runtime = arena
    plan = [LABELS[3], LABELS[7]]  # UNION ALL 泄露 + SSRF
    llm = DeepSeekClient(
        settings_with_key(), transport=llm_reply({"steps": plan, "rationale": "挑最省事的"})
    )
    ctx = ArenaContext(client=client, state=state, runtime=runtime, session_id="s1", llm=llm)
    session = await run_pipeline(ctx)
    await llm.aclose()

    assert session.agent_mode == "llm"
    assert session.plan_rationale == "挑最省事的"
    assert [trace.label for trace in session.traces] == plan
    assert session.status.value == "VERIFIED"


async def test_pipeline_stays_deterministic_without_a_key(arena):
    client, state, runtime = arena
    ctx = ArenaContext(client=client, state=state, runtime=runtime, session_id="s2")
    session = await run_pipeline(ctx)

    assert session.agent_mode == "deterministic"
    assert len(session.traces) == len(LABELS)
    assert session.plan_rationale == ""


# --- P3：复盘 ----------------------------------------------------------------


async def test_review_summarises_the_drill(arena):
    client, state, runtime = arena
    ctx = ArenaContext(client=client, state=state, runtime=runtime, session_id="s3")
    session = await run_pipeline(ctx)
    review = build_review(session)

    assert review.session_id == "s3"
    assert review.verdict == "VERIFIED"
    assert len(review.steps) == len(session.traces)
    assert len(review.rules) == 2  # sqli（回合中）+ ssrf（收尾）
    assert review.flags_off
    assert "击穿" in review.headline
    assert review.entry_point and review.steps[0].lesson and review.steps[0].defense
    assert review.regression["passed"] is True


@pytest.mark.parametrize("label", LABELS)
def test_every_step_has_a_lesson(label):
    assert label

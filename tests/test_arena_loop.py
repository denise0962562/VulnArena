"""End-to-end arena loop: scenario, attack chain, patch, regression."""

import httpx
import pytest_asyncio

from vulnarena.arena import ArenaRuntime, InMemoryEventBus, InMemoryPolicyStore, WafMiddleware
from vulnarena.arena.context import ArenaContext
from vulnarena.arena.contracts import ArenaStatus, DefensePatch
from vulnarena.arena.corpus import Category
from vulnarena.arena.defender import TemplateDefender
from vulnarena.arena.pipeline import run_pipeline
from vulnarena.arena.policy import WafPolicy, WafRule
from vulnarena.arena.templates import SQLI_RULE_REGEX
from vulnarena.procure import DefectFlag, ProcureState, build_procure_app

CANARY = "CANARY-LOOP-0001"


@pytest_asyncio.fixture
async def arena():
    state = ProcureState(canary=CANARY)
    app = build_procure_app(state=state)
    runtime = ArenaRuntime(cache_ttl=0.0)
    runtime.policy_store = InMemoryPolicyStore()
    runtime.events = InMemoryEventBus()
    app.add_middleware(WafMiddleware, runtime=runtime)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://arena") as client:
        ctx = ArenaContext(client=client, state=state, runtime=runtime, session_id="s1")
        yield ctx, state, runtime
    await state.aclose()


async def test_full_loop_reaches_verified(arena):
    ctx, state, _runtime = arena
    session = await run_pipeline(ctx)

    assert session.status is ArenaStatus.VERIFIED
    assert [trace.step for trace in session.traces] == [1, 2, 3, 4, 5, 6, 7, 8]
    baseline, login_bypass, naive, mutated, idor, asset_idor, traversal, ssrf = session.traces

    assert baseline.status == 200 and not baseline.breached
    assert login_bypass.status == 200 and login_bypass.breached
    assert not login_bypass.canary_hit  # success signal here is the escalated role
    assert naive.status == 403 and naive.blocked_by == "waf"
    # 蓝队在上一回合补了 SQLi 规则，等价变体也被拦了
    assert mutated.status == 403 and mutated.blocked_by == "waf"
    assert idor.status == 200 and idor.canary_hit
    assert asset_idor.status == 200 and asset_idor.canary_hit
    assert traversal.status == 200 and traversal.canary_hit
    assert ssrf.status == 200 and ssrf.canary_hit
    assert {login_bypass.category, naive.category, mutated.category} == {"sqli"}
    assert {idor.category, asset_idor.category} == {"idor", "logic"}
    assert {traversal.category, ssrf.category} == {"path_traversal", "ssrf"}
    # 回合制：红队每走一步，蓝队都可能响应
    assert len(session.rounds) == 8
    reacted = [item for item in session.rounds if item.blue is not None]
    assert reacted
    assert any(item.blue.accepted for item in reacted)  # SQLi 那类有规则可上
    assert any(not item.blue.accepted for item in reacted)  # IDOR/逻辑类只能改代码
    assert all(item.blue.reason for item in reacted)

    assert session.patch is not None and session.patch.rule is not None
    assert session.patch.rules  # sqli 在回合中就上线了，收尾补上 ssrf
    assert all(gate.passed for gate in session.patch.gates)
    assert session.patch.gates[0].recall == 1.0
    assert session.patch.gates[0].false_positive == 0.0
    assert set(session.patch.switched_flags) == {
        "sqli_search",
        "sqli_login_bypass",
        "idor_po_detail",
        "mass_assignment",
        "state_skip",
        "path_traversal",
        "ssrf_supplier",
    }
    assert "--- a/vulnarena/procure/app.py" in session.patch.diff
    assert "--- a/vulnarena/procure/app.py" in session.patch.diff

    # 蓝队只关掉这轮打过的类别；支付/改密三类没被覆盖，仍开着
    still_open = {flag.value for flag, enabled in state.flags.items() if enabled}
    assert still_open == {
        "payment_amount_tamper",
        "payment_replay",
        "password_reset_idor",
    }
    regression = session.regression
    assert regression is not None and regression.passed
    assert regression.attack_blocked == regression.attack_total == 7
    assert regression.benign_allowed == regression.benign_total == 8


async def test_loop_reports_breach_failed_when_gateway_is_already_strong(arena):
    ctx, _state, runtime = arena
    strong = WafRule(category=Category.SQLI, regex=SQLI_RULE_REGEX)
    policy = WafPolicy(session_id="s1", blocked_patterns=[strong])
    await runtime.policy_store.save(policy)

    session = await run_pipeline(ctx, defects=(DefectFlag.SQLI_SEARCH,))

    assert session.status is ArenaStatus.BREACH_FAILED
    assert session.patch is None and session.regression is None
    assert not any(trace.canary_hit for trace in session.traces)


async def test_loop_reports_regression_failure_when_patch_does_nothing(arena, monkeypatch):
    ctx, _state, _runtime = arena

    async def noop_patch(self, traces):
        return DefensePatch(rationale="no-op")

    monkeypatch.setattr(TemplateDefender, "patch", noop_patch)
    session = await run_pipeline(ctx)

    assert session.status is ArenaStatus.REGRESSION_FAILED
    assert session.regression is not None and not session.regression.passed
    assert "idor: read a foreign purchase order" in session.regression.missed


async def test_loop_emits_events_for_every_stage(arena):
    ctx, _state, runtime = arena
    await run_pipeline(ctx)
    events = await runtime.events.since("s1", 0)
    kinds = [event.kind for event in events]
    assert kinds[0] == "blueprint"
    assert kinds.count("trace") == 8
    assert "blue_action" in kinds
    assert "breach" in kinds and "patch" in kinds
    assert kinds[-1] == "verified"
    trace_event = next(event for event in events if event.kind == "trace")
    assert trace_event.data["call"]["path"] == "/pos"

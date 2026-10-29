"""The four-stage closed loop: scenario, attack, patch, regression.

Everything here is deterministic. A model-driven agent can later replace the
attacker or the defender, but the loop must stay reproducible without one.
"""

from vulnarena.arena.agents import plan_attack
from vulnarena.arena.attacker import CHAIN, DeterministicAttacker
from vulnarena.arena.context import ArenaContext
from vulnarena.arena.contracts import (
    ArenaSession,
    ArenaSnapshot,
    ArenaStatus,
    ProbeTrace,
    Round,
)
from vulnarena.arena.corpus import Category
from vulnarena.arena.defender import TemplateDefender
from vulnarena.arena.events import ArenaEvent
from vulnarena.arena.policy import WafRule
from vulnarena.arena.replay import replay
from vulnarena.arena.templates import WEAK_RULE_REGEX
from vulnarena.procure.models import DefectFlag
from vulnarena.schemas import utcnow

DEFAULT_DEFECTS = tuple(DefectFlag)


async def _emit(ctx: ArenaContext, stage: str, kind: str, message: str, data=None) -> None:
    await ctx.runtime.emit(
        ArenaEvent(
            session_id=ctx.session_id,
            stage=stage,
            kind=kind,
            message=message,
            data=data or {},
        )
    )


async def seed_weak_gateway(ctx: ArenaContext) -> bool:
    """Stand in for an unmaintained gateway: one case-sensitive literal rule."""
    store = ctx.runtime.policy_store
    if store is None:
        return False
    policy = await store.load(ctx.session_id)
    if any(rule.regex == WEAK_RULE_REGEX for rule in policy.blocked_patterns):
        return False
    weak = WafRule(
        category=Category.SQLI,
        regex=WEAK_RULE_REGEX,
        source="template",
        rationale="初始薄弱基线：只做大小写敏感的字面匹配",
    )
    updated = policy.model_copy(update={"blocked_patterns": [*policy.blocked_patterns, weak]})
    await store.save(updated)
    ctx.runtime.forget(ctx.session_id)
    return True


async def run_pipeline(ctx: ArenaContext, *, defects=DEFAULT_DEFECTS) -> ArenaSession:
    session = ArenaSession(session_id=ctx.session_id)
    session.defects = [flag.value for flag in defects]

    for flag in defects:
        ctx.state.set_flag(flag, True)
    seeded = await seed_weak_gateway(ctx)
    if ctx.runtime.policy_store is not None:
        session.snapshot = ArenaSnapshot(
            defects=session.defects,
            policy=await ctx.runtime.policy_store.load(ctx.session_id),
        )
    session.status = ArenaStatus.BLUEPRINT_READY
    await _emit(
        ctx,
        "SCENARIO",
        "blueprint",
        "蓝队布防完成，靶场进入脆弱态",
        {"defects": session.defects, "weak_rule_seeded": seeded, "agent_mode": "pending"},
    )

    session.status = ArenaStatus.PROBING

    async def record(trace: ProbeTrace) -> None:
        await _emit(
            ctx,
            "PROBING",
            "trace",
            f"step {trace.step}: {trace.label} -> {trace.status}",
            trace.model_dump(mode="json"),
        )

    plan = await plan_attack(getattr(ctx, "llm", None), [item.label for item in CHAIN])
    session.agent_mode = "llm" if plan is not None else "deterministic"
    session.plan_rationale = plan.rationale if plan is not None else ""
    order = plan.steps if plan is not None else None
    attacker = DeterministicAttacker(ctx, on_trace=record)
    defender = TemplateDefender(ctx)
    by_label = {item.label: item for item in CHAIN}
    sequence = [by_label[label] for label in (order or []) if label in by_label] or list(CHAIN)

    rounds: list[Round] = []
    blue_budget = 3
    for position, item in enumerate(sequence, start=1):
        trace = await attacker.run_one(item, position)
        session.traces.append(trace)
        outcome = "breach" if trace.breached else ("blocked" if trace.status >= 400 else "ok")

        blue = None
        # 只有击穿了才值得回应；蓝队一场最多反应 3 次
        if trace.breached and blue_budget > 0 and ctx.runtime.policy_store is not None:
            blue_budget -= 1
            blue = await defender.react(trace)
            await _emit(
                ctx,
                "DEFENSE",
                "blue_action",
                f"蓝队响应（第 {position} 回合）：{blue.reason}",
                blue.model_dump(),
            )

        rounds.append(
            Round(index=position, step=trace.step, label=trace.label, result=outcome, blue=blue)
        )
    session.rounds = rounds

    if not any(trace.breached for trace in session.traces):
        session.status = ArenaStatus.BREACH_FAILED
        session.finished_at = utcnow()
        await _emit(ctx, "DONE", "breach_failed", "红队未能击穿，演练终止")
        return session

    session.status = ArenaStatus.BREACH_CONFIRMED
    await _emit(ctx, "PROBING", "breach", "canary 泄露，红队击穿成功")

    session.status = ArenaStatus.PATCHING
    session.patch = await TemplateDefender(ctx).patch(session.traces)
    await _emit(
        ctx,
        "PATCHING",
        "patch",
        "网关规则与代码修复已下发",
        session.patch.model_dump(mode="json"),
    )

    session.status = ArenaStatus.VERIFYING
    session.regression = await replay(ctx, session.traces)
    session.status = (
        ArenaStatus.VERIFIED if session.regression.passed else ArenaStatus.REGRESSION_FAILED
    )
    session.finished_at = utcnow()
    await _emit(
        ctx,
        "DONE",
        session.status.value.lower(),
        "演练结束",
        session.regression.model_dump(mode="json"),
    )
    return session

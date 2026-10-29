"""Run the arena closed loop offline and print the timeline.

No Redis, no PostgreSQL, no network: the portal app is driven through an in-process
ASGI transport. Run it from the repository root:

    .\\.venv\\Scripts\\python scripts/arena_demo.py
"""

import asyncio

import httpx

from vulnarena.arena import ArenaRuntime, InMemoryPolicyStore, WafMiddleware
from vulnarena.arena.context import ArenaContext
from vulnarena.arena.pipeline import run_pipeline
from vulnarena.procure import ProcureState, build_procure_app

RULE = "-" * 78


def describe(trace) -> str:
    if trace.canary_hit:
        verdict = "BREACH  canary leaked"
    elif trace.breached:
        verdict = "BREACH  role escalated"
    elif trace.status == 403:
        verdict = f"BLOCKED by {trace.blocked_by}"
    elif trace.status == 200:
        verdict = "OK"
    else:
        verdict = f"HTTP {trace.status}"
    return f"  [{trace.step}] {trace.label:<48} {verdict:<26} {trace.elapsed_ms:>3}ms"


async def main() -> int:
    state = ProcureState(canary="CANARY-DEMO-0001")
    app = build_procure_app(state=state)
    runtime = ArenaRuntime(cache_ttl=0.0)
    runtime.policy_store = InMemoryPolicyStore()
    app.add_middleware(WafMiddleware, runtime=runtime)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://arena") as client:
        ctx = ArenaContext(client=client, state=state, runtime=runtime, session_id="demo")
        session = await run_pipeline(ctx)

    print(RULE)
    print(f"session {session.session_id}   status {session.status}   defects {session.defects}")
    print(RULE)

    print("\n[stage 1] 蓝队布防：开启组合缺陷，只需一条年久失修的字面规则")
    print(f"  defects     : {', '.join(session.defects)}")

    print(f"\n[stage 2] 红队 {len(session.traces)} 步链")
    for trace in session.traces:
        print(describe(trace))
        print(f"        {trace.reasoning}")

    if session.patch is not None:
        patch = session.patch
        print("\n[stage 3] 蓝队修复")
        if patch.rule is not None:
            print(f"  waf rule    : {patch.rule.id}  {patch.rule.regex}")
            if patch.gate is not None:
                print(
                    f"  gate        : passed  recall={patch.gate.recall:.0%}"
                    f"  false_positive={patch.gate.false_positive:.0%}"
                )
        else:
            print("  waf rule    : none (gate rejected every candidate)")
        print(f"  flags off   : {', '.join(patch.switched_flags) or 'none'}")
        print("  code fix    :")
        for line in patch.diff.splitlines()[:18]:
            print(f"    {line}")

    if session.regression is not None:
        result = session.regression
        print("\n[stage 4] 回归验证")
        print(f"  attack      : {result.attack_blocked}/{result.attack_total} blocked")
        print(f"  benign      : {result.benign_allowed}/{result.benign_total} allowed")
        if result.missed:
            print(f"  missed      : {result.missed}")
        if result.false_positives:
            print(f"  false pos.  : {result.false_positives}")

    print("\n" + RULE)
    print(f"RESULT: {session.status}")
    print(RULE)
    return 0 if session.status == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

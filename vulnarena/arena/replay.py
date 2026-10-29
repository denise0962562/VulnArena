"""Stage 4: replay the chain, then prove normal traffic still works.

Two assertions, both mandatory: every vector that ever broke in must now be
blocked, and every legitimate request must still succeed with intact data.
"""

from vulnarena.arena.context import ArenaContext
from vulnarena.arena.contracts import HttpCall, ProbeTrace, RegressionResult

BENIGN: list[tuple[str, HttpCall]] = [
    (
        "login",
        HttpCall(
            method="POST",
            path="/login",
            json_body={"username": "alice", "password": "alice-pw"},
            actor="anonymous",
        ),
    ),
    ("search chinese keyword", HttpCall(method="GET", path="/pos", params={"q": "设备"})),
    ("apostrophe in keyword", HttpCall(method="GET", path="/pos", params={"q": "O'Brien"})),
    ("open own purchase order", HttpCall(method="GET", path="/pos/2")),
    ("supplier detail", HttpCall(method="GET", path="/suppliers/1")),
    (
        "download readme attachment",
        HttpCall(method="GET", path="/attachments", params={"name": "README.txt"}),
    ),
    ("mission status", HttpCall(method="GET", path="/mission")),
]


async def replay(ctx: ArenaContext, traces: list[ProbeTrace]) -> RegressionResult:
    result = RegressionResult()

    expected: list[tuple[str, HttpCall, bool]] = []
    for trace in traces:
        must_block = trace.status >= 400 or trace.breached
        expected.append((trace.label, trace.call, must_block))
    expected.extend((label, call, False) for label, call in BENIGN)

    for label, call, must_block in expected:
        outcome = await ctx.send(call)
        if must_block:
            result.attack_total += 1
            if outcome.status >= 400:
                result.attack_blocked += 1
            else:
                result.missed.append(label)
        else:
            result.benign_total += 1
            clean = ctx.canary not in outcome.text
            if outcome.status == 200 and clean:
                result.benign_allowed += 1
            else:
                result.false_positives.append(label)

    result.passed = not result.missed and not result.false_positives
    return result

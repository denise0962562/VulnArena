"""Rule admission gate: propose, verify, activate.

A model or a template may propose a regex. Nothing reaches the gateway until it
survives deterministic checks, because a rule that kills a legitimate request is
worse than no rule at all.
"""

import asyncio
import re

from pydantic import BaseModel, Field

from vulnarena.arena.corpus import ATTACK, BENIGN, CODE_ONLY, normalise
from vulnarena.arena.policy import WafRule

MAX_REGEX_LENGTH = 300
MAX_SCAN_SECONDS = 0.05
PROBE = "a'" * 2048

NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*]")


class GateResult(BaseModel):
    passed: bool
    failures: list[str] = Field(default_factory=list)
    recall: float = 0.0
    false_positive: float = 0.0


def hits(pattern: re.Pattern[str], sample: str) -> bool:
    """Match both the raw line and its normalised form, exactly like the gateway."""
    return bool(pattern.search(sample) or pattern.search(normalise(sample)))


async def _scan_too_slow(pattern: re.Pattern[str]) -> bool:
    def scan() -> None:
        pattern.search(PROBE)

    try:
        # The worker thread may outlive the timeout; the result only decides admission.
        await asyncio.wait_for(asyncio.to_thread(scan), MAX_SCAN_SECONDS)
    except TimeoutError:
        return True
    return False


async def verify_rule(rule: WafRule) -> GateResult:
    if rule.category in CODE_ONLY:
        return GateResult(passed=False, failures=[f"{rule.category}: {CODE_ONLY[rule.category]}"])
    try:
        pattern = re.compile(rule.regex)
    except re.error as exc:
        return GateResult(passed=False, failures=[f"invalid regex: {exc.msg}"])

    failures: list[str] = []
    if len(rule.regex) > MAX_REGEX_LENGTH:
        failures.append(f"regex longer than {MAX_REGEX_LENGTH} characters")
    if NESTED_QUANTIFIER.search(rule.regex):
        failures.append("nested quantifier risks catastrophic backtracking")
    elif await _scan_too_slow(pattern):
        failures.append(f"scan exceeded {MAX_SCAN_SECONDS}s on a 4KB probe")

    attack = ATTACK[rule.category]
    caught = sum(hits(pattern, sample) for sample in attack)
    recall = caught / len(attack)
    if not caught == len(attack):
        failures.append(f"recall {recall:.0%} misses {len(attack) - caught} attack sample(s)")

    false_hits = [sample for sample in BENIGN if hits(pattern, sample)]
    false_positive = len(false_hits) / len(BENIGN)
    if false_hits:
        failures.append(f"false positive on {len(false_hits)} benign sample(s)")

    return GateResult(
        passed=not failures, failures=failures, recall=recall, false_positive=false_positive
    )

"""跑评测：一条规则 × 一套语料 → 一组指标。

五项检查与上线闸门一致（可编译、长度、ReDoS 探测、召回、误杀），
区别是这里**不抛异常也不拒绝**，而是把每一项都记录成可比较的数字。
"""

import re
import time

from vulnarena.arena.policy import WafRule
from vulnarena.bench.corpus import Corpus
from vulnarena.bench.metrics import RuleMetrics

MAX_REGEX_LENGTH = 300
MAX_SCAN_SECONDS = 0.05
PROBE = "a" * 4096


def _compile(regex: str) -> tuple[re.Pattern[str] | None, str]:
    try:
        return re.compile(regex), ""
    except re.error as exc:
        return None, f"regex does not compile: {exc}"


def evaluate(
    rule: WafRule,
    corpus: Corpus,
    *,
    name: str = "",
    category: str | None = None,
    benign_limit: int | None = None,
) -> RuleMetrics:
    label = name or rule.id
    target = category if category is not None else str(rule.category)
    result = RuleMetrics(
        name=label,
        category=target,
        regex=rule.regex,
        benign_total=len(corpus.benign) if benign_limit is None else benign_limit,
    )

    pattern, error = _compile(rule.regex)
    if pattern is None:
        result.reasons.append(error)
        return result
    if len(rule.regex) > MAX_REGEX_LENGTH:
        result.reasons.append(f"regex longer than {MAX_REGEX_LENGTH} characters")

    started = time.perf_counter()
    pattern.search(PROBE)
    result.elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    if result.elapsed_ms / 1000 > MAX_SCAN_SECONDS:
        result.reasons.append(f"scan exceeded {MAX_SCAN_SECONDS}s on a 4KB probe")

    attacks = corpus.attacks.get(target, [])
    result.attack_total = len(attacks)
    if not attacks:
        result.reasons.append(f"no attack samples for category {target!r}")
    caught: list[str] = []
    for sample in attacks:
        if pattern.search(sample):
            caught.append(sample)
        else:
            result.missed.append(sample)
    result.attack_caught = len(caught)
    result.recall = round(len(caught) / len(attacks), 4) if attacks else 0.0
    if attacks and result.recall < 1.0:
        result.reasons.append(f"recall {result.recall:.0%} misses {len(result.missed)} sample(s)")

    benign = corpus.benign if benign_limit is None else corpus.benign[:benign_limit]
    for sample in benign:
        if pattern.search(sample):
            result.false_positives.append(sample)
    result.benign_hit = len(result.false_positives)
    result.false_positive = round(len(result.false_positives) / len(benign), 4) if benign else 0.0
    if result.false_positives:
        result.reasons.append(f"false positive on {len(result.false_positives)} benign sample(s)")

    result.passed = not result.reasons
    return result


def evaluate_all(rules: list[WafRule], corpus: Corpus) -> list[RuleMetrics]:
    return [evaluate(rule, corpus) for rule in rules]

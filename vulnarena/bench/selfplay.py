"""离线回合制自博弈：红队造变体 → 语料变强 → 蓝队规则被重新打分。

一轮就是四步（全部离线、可复现）：

1. 红队：从现有攻击样本派生等价变体，并入语料（`mutate`，或模型生成）
2. 蓝队：给出当前规则（模板 / 模型提议）
3. 评测：跑一遍全量语料，得到召回与误杀
4. 记录：这一轮的指标落进 `RoundResult`

跑多轮就能看到"红队一变招，蓝队召回就掉"的曲线——这就是"进化"的可量化形态。
"""

from dataclasses import asdict, dataclass, field

from vulnarena.arena.policy import WafRule
from vulnarena.arena.templates import RULE_TEMPLATES
from vulnarena.bench.corpus import Corpus
from vulnarena.bench.mutate import mutate_all
from vulnarena.bench.runner import evaluate


@dataclass(slots=True)
class RoundResult:
    round_no: int
    corpus_attacks: int
    red_added: int
    rule_name: str
    rule_category: str
    recall: float
    false_positive: float
    passed: bool
    note: str = ""
    new_samples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _fallback_rule(category: str) -> WafRule | None:
    template = RULE_TEMPLATES.get(category)
    if template is None:
        return None
    regex, enum_category = template
    return WafRule(category=enum_category, regex=regex, source="template")


def _merge(corpus: Corpus, added: dict[str, list[str]]) -> Corpus:
    attacks = {category: list(samples) for category, samples in corpus.attacks.items()}
    for category, samples in added.items():
        attacks.setdefault(category, [])
        for sample in samples:
            if sample not in attacks[category]:
                attacks[category].append(sample)
    return Corpus(attacks=attacks, benign=list(corpus.benign))


async def run_selfplay(
    corpus: Corpus,
    *,
    rounds: int = 3,
    category: str = "sqli",
    blue=None,
    red=None,
) -> list[RoundResult]:
    """blue(corpus) -> WafRule|None；red(corpus, category) -> list[str]。

    两者都是可替换的：默认蓝队用模板规则、红队用确定性变形，
    传进来就能换成模型版本（P4 的可选增强）。
    """
    results: list[RoundResult] = []
    current = corpus

    for index in range(1, rounds + 1):
        new_samples: list[str] = []
        if red is not None:
            new_samples = list(red(current, category))
        else:
            added = mutate_all({category: current.attacks.get(category, [])})
            new_samples = added.get(category, [])

        current = _merge(current, {category: new_samples} if new_samples else {})

        rule = await blue(current) if blue is not None else _fallback_rule(category)
        if rule is None:
            results.append(
                RoundResult(
                    round_no=index,
                    corpus_attacks=len(current.attacks.get(category, [])),
                    red_added=len(new_samples),
                    rule_name="none",
                    rule_category=category,
                    recall=0.0,
                    false_positive=0.0,
                    passed=False,
                    note="蓝队没给出规则",
                    new_samples=new_samples[:5],
                )
            )
            continue

        metrics = evaluate(rule, current, name=f"round-{index}", category=category)
        results.append(
            RoundResult(
                round_no=index,
                corpus_attacks=metrics.attack_total,
                red_added=len(new_samples),
                rule_name=rule.source,
                rule_category=category,
                recall=metrics.recall,
                false_positive=metrics.false_positive,
                passed=metrics.passed,
                note="；".join(metrics.reasons),
                new_samples=new_samples[:5],
            )
        )
    return results

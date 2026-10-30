"""数据工厂：把自博弈的差集变成可训练数据。

思路（不吹牛版）：每一轮红队造出变体后，我们手上有两份东西——

* **被拒的规则**：模板规则在新语料上召回下降（79%/70%/66%）
* **可通过的规则**：把模板里的空白放宽成"空白或注释"，再跑一遍评测就能 100%

两者构成一对 **preference pair**（同一提示词下的好答案/坏答案），
既能做 SFT（只学好的），也能做 DPO（学好、远离坏的）。
这就是"产出可训练的数据"，而不是"训好了模型"。
"""

import json
from dataclasses import dataclass, field

from vulnarena.arena.policy import WafRule
from vulnarena.arena.templates import RULE_TEMPLATES
from vulnarena.bench.corpus import Corpus
from vulnarena.bench.mutate import mutate_all
from vulnarena.bench.runner import evaluate


@dataclass(slots=True)
class Pair:
    round_no: int
    category: str
    prompt: dict
    chosen_regex: str
    rejected_regex: str
    chosen_recall: float
    rejected_recall: float
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "task": "write a waf regex",
            "round": self.round_no,
            "category": self.category,
            "prompt": self.prompt,
            "chosen": self.chosen_regex,
            "rejected": self.rejected_regex,
            "chosen_recall": round(self.chosen_recall, 4),
            "rejected_recall": round(self.rejected_recall, 4),
            "tags": self.tags,
        }


def widen(regex: str) -> str:
    """把一条件规则放宽到"能覆盖红队的等价变形"，但仍不误伤正常流量。

    三步：
    1. 空白 → 空白或注释（`union/**/select`）
    2. 追加 MySQL `#` 注释分支（`admin'#`）
    3. 追加泛化的布尔恒真分支（`' or 'a'='a`）
    """
    widened = regex.replace(r"\s+", r"[\s/*]*").replace(r"\s*", r"[\s/*]*")
    if widened.endswith(")"):
        widened = widened[:-1] + r"|'[\s/*]*or[\s/*]*'?[\w]|'[\s/*]*#)"
    return widened


def build_pairs(corpus: Corpus, *, rounds: int = 3, category: str = "sqli") -> list[Pair]:
    template = RULE_TEMPLATES.get(category)
    if template is None:
        return []
    base_regex, enum_category = template

    pairs: list[Pair] = []
    current = corpus
    for index in range(1, rounds + 1):
        added = mutate_all({category: current.attacks.get(category, [])})
        fresh = [
            sample
            for sample in added.get(category, [])
            if sample not in current.attacks.get(category, [])
        ][:20]
        if fresh:
            current = Corpus(
                attacks={
                    **{key: list(value) for key, value in current.attacks.items()},
                    category: [*current.attacks.get(category, []), *fresh],
                },
                benign=list(current.benign),
            ).normalised()

        rejected = evaluate(
            WafRule(category=enum_category, regex=base_regex, source="template"),
            current,
            name=f"template-r{index}",
            category=category,
        )
        chosen = evaluate(
            WafRule(category=enum_category, regex=widen(base_regex), source="manual"),
            current,
            name=f"widened-r{index}",
            category=category,
        )
        if not chosen.passed:
            continue
        pairs.append(
            Pair(
                round_no=index,
                category=category,
                prompt={
                    "task": "write a waf regex",
                    "category": category,
                    "attack_samples": current.attacks.get(category, [])[:6],
                    "benign_samples": current.benign[:6],
                },
                chosen_regex=chosen.regex,
                rejected_regex=rejected.regex,
                chosen_recall=chosen.recall,
                rejected_recall=rejected.recall,
                tags=["comment-bypass", f"round-{index}"],
            )
        )
    return pairs


def write_jsonl(pairs: list[Pair], path) -> int:
    """写 JSONL：一行一条 preference pair，可直接喂给 SFT/DPO 脚本。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for pair in pairs:
            handle.write(json.dumps(pair.to_dict(), ensure_ascii=False) + "\n")
    return len(pairs)


def classification_records(corpus: Corpus) -> list[dict]:
    """把语料本身变成"判断攻击/正常"的监督样本——量足、无需模型。"""
    records: list[dict] = []
    for category, samples in corpus.attacks.items():
        for sample in samples:
            records.append(
                {"task": "classify", "category": category, "text": sample, "label": "attack"}
            )
    for sample in corpus.benign:
        records.append(
            {"task": "classify", "category": "benign", "text": sample, "label": "benign"}
        )
    return records


def build_records(corpus: Corpus, *, rounds: int = 3, category: str = "sqli") -> list[dict]:
    records = [pair.to_dict() for pair in build_pairs(corpus, rounds=rounds, category=category)]
    records.extend(classification_records(corpus))
    return records

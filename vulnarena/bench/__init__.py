"""评测台：给一条 WAF 规则打分。

与 `arena.gate` 的区别：gate 是"上线前的自动闸门"，只回答通过/拒绝；
bench 是"评测台"，输出完整指标（召回、误杀、命中明细、耗时），可出报告、
可做多规则/多模型横向对比。两者共用同一套语料。
"""

from vulnarena.bench.corpus import Corpus, load_corpus
from vulnarena.bench.metrics import RuleMetrics
from vulnarena.bench.report import to_json, to_markdown
from vulnarena.bench.runner import evaluate, evaluate_all

__all__ = [
    "Corpus",
    "RuleMetrics",
    "evaluate",
    "evaluate_all",
    "load_corpus",
    "to_json",
    "to_markdown",
]

"""评测语料：攻击样本按类别分组，正常流量单独一组。

默认直接复用 `arena.corpus`（同一套样本，避免两处漂移）；
也支持从 JSON 文件加载，便于以后扩充到几百条：

    {"attacks": {"sqli": ["GET /pos?q=..."], "ssrf": [...]},
     "benign": ["GET /pos?q=设备"]}
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from vulnarena.arena.corpus import ATTACK, BENIGN

WHITESPACE = re.compile(r"\s+")


def normalise(raw: str) -> str:
    """与中间件同构，但保留注释——注释往往正是攻击特征本身。"""
    text = unquote(unquote(raw)).replace("+", " ")
    return WHITESPACE.sub(" ", text).strip().lower()


@dataclass(slots=True)
class Corpus:
    attacks: dict[str, list[str]] = field(default_factory=dict)
    benign: list[str] = field(default_factory=list)

    @property
    def attack_total(self) -> int:
        return sum(len(samples) for samples in self.attacks.values())

    def normalised(self) -> "Corpus":
        """统一做一遍归一化，避免"规则没命中"其实是被编码差异影响。"""
        return Corpus(
            attacks={
                str(category): [normalise(sample) for sample in samples]
                for category, samples in self.attacks.items()
            },
            benign=[normalise(sample) for sample in self.benign],
        )


def load_corpus(path: Path | None = None) -> Corpus:
    """默认用内置语料；给了 path 就从 JSON 读。"""
    if path is None:
        corpus = Corpus(
            attacks={str(category): list(samples) for category, samples in ATTACK.items()},
            benign=list(BENIGN),
        )
        return corpus.normalised()

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    attacks = payload.get("attacks") or {}
    benign = payload.get("benign") or []
    if not isinstance(attacks, dict) or not isinstance(benign, list):
        raise ValueError("corpus json must be {attacks: {category: [..]}, benign: [..]}")
    return Corpus(
        attacks={str(key): [str(item) for item in value] for key, value in attacks.items()},
        benign=[str(item) for item in benign],
    ).normalised()

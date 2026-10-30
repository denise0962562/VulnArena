"""一条规则的评测结果。"""

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class RuleMetrics:
    name: str
    category: str
    regex: str
    passed: bool = False
    recall: float = 0.0
    false_positive: float = 0.0
    attack_total: int = 0
    attack_caught: int = 0
    benign_total: int = 0
    benign_hit: int = 0
    elapsed_ms: float = 0.0
    reasons: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

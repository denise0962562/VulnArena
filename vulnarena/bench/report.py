"""把评测结果变成人能看的表格与机器能读的 JSON。"""

import json

from vulnarena.bench.metrics import RuleMetrics


def _judgement(result: RuleMetrics) -> str:
    return "OK" if result.passed else "REJECT"


def to_markdown(results: list[RuleMetrics], *, title: str = "WAF 规则评测") -> str:
    lines = [
        f"# {title}",
        "",
        f"语料：{results[0].benign_total if results else 0} 条正常流量，攻击样本按类别统计见下表。",
        "",
        "| 规则 | 类别 | 召回 | 误杀 | 耗时ms | 判定 |",
        "|---|---|---|---|---|---|",
    ]
    for item in results:
        lines.append(
            f"| `{item.name}` | {item.category} | {item.recall:.0%} | "
            f"{item.false_positive:.1%} | {item.elapsed_ms} | {_judgement(item)} |"
        )
    failed = [item for item in results if not item.passed]
    if failed:
        lines += ["", "## 未通过的规则", ""]
        for item in failed:
            lines.append(f"### `{item.name}`")
            for reason in item.reasons:
                lines.append(f"- {reason}")
            for sample in item.missed[:3]:
                lines.append(f"- 漏掉：`{sample[:90]}`")
            for sample in item.false_positives[:3]:
                lines.append(f"- 误杀：`{sample[:90]}`")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_json(results: list[RuleMetrics]) -> str:
    payload = {
        "summary": {
            "rules": len(results),
            "passed": sum(1 for item in results if item.passed),
            "failed": sum(1 for item in results if not item.passed),
        },
        "results": [item.to_dict() for item in results],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)

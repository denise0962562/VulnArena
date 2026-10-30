"""命令行入口：

    python -m vulnarena.bench run
    python -m vulnarena.bench run --json reports/latest.json --markdown reports/latest.md

退出码即门禁：有规则没通过就返回 1，可以直接挂进 CI。
"""

import argparse
import sys
from pathlib import Path

from vulnarena.arena.policy import WafRule
from vulnarena.arena.templates import RULE_TEMPLATES
from vulnarena.bench.corpus import load_corpus
from vulnarena.bench.report import to_json, to_markdown
from vulnarena.bench.runner import (
    MAX_REGEX_LENGTH,  # noqa: F401  (供外部检查)
    evaluate_all,
)


def template_rules() -> list[WafRule]:
    rules: list[WafRule] = []
    for name, (regex, category) in RULE_TEMPLATES.items():
        rules.append(WafRule(category=category, regex=regex, source="template", rationale=name))
    return rules


def _cmd_run(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.corpus)
    results = evaluate_all(template_rules(), corpus)

    for item in results:
        mark = "OK " if item.passed else "REJ"
        print(
            f"[{mark}] {item.name:<8} {item.category:<15} "
            f"recall={item.recall:.0%} fp={item.false_positive:.1%} {item.elapsed_ms}ms"
        )
        for reason in item.reasons:
            print(f"      - {reason}")

    failed = [item for item in results if not item.passed]
    print(
        f"\n{len(results)} 条规则：{len(results) - len(failed)} 通过，{len(failed)} 被拒"
        f"（攻击样本 {sum(item.attack_total for item in results)} 条，"
        f"正常流量 {results[0].benign_total if results else 0} 条）"
    )

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(to_json(results), encoding="utf-8")
        print(f"JSON  -> {args.json}")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(to_markdown(results), encoding="utf-8")
        print(f"报告 -> {args.markdown}")

    return 0 if not failed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m vulnarena.bench", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="对内置模板规则打分")
    run.add_argument("--corpus", type=Path, default=None, help="自定义语料 JSON")
    run.add_argument("--json", type=Path, default=None, help="把结果写成 JSON")
    run.add_argument("--markdown", type=Path, default=None, help="把结果写成 markdown 报告")
    run.set_defaults(func=_cmd_run)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())

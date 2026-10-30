"""命令行入口：

    python -m vulnarena.bench run
    python -m vulnarena.bench generate --category sqli

run：给内置模板规则打分，退出码即门禁（有规则被拒 → 1）。
generate：让模型写一条规则，再用同一套指标给它打分。
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from vulnarena.arena.policy import WafRule
from vulnarena.arena.templates import RULE_TEMPLATES
from vulnarena.bench.corpus import Corpus, load_corpus
from vulnarena.bench.generate import generate_rule
from vulnarena.bench.report import to_json, to_markdown
from vulnarena.bench.runner import evaluate, evaluate_all
from vulnarena.bench.selfplay import RoundResult, run_selfplay


def template_rules() -> list[WafRule]:
    rules: list[WafRule] = []
    for name, (regex, category) in RULE_TEMPLATES.items():
        rules.append(WafRule(category=category, regex=regex, source="template", rationale=name))
    return rules


def _print(results) -> None:
    for item in results:
        mark = "OK " if item.passed else "REJ"
        print(
            f"[{mark}] {item.name:<18} {item.category:<15} "
            f"recall={item.recall:.0%} fp={item.false_positive:.1%} {item.elapsed_ms}ms"
        )
        for reason in item.reasons:
            print(f"      - {reason}")


def _write_reports(results, *, args: argparse.Namespace, title: str) -> None:
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(to_json(results), encoding="utf-8")
        print(f"JSON  -> {args.json}")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(to_markdown(results, title=title), encoding="utf-8")
        print(f"报告 -> {args.markdown}")


def _cmd_run(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.corpus)
    results = evaluate_all(template_rules(), corpus)
    _print(results)

    failed = [item for item in results if not item.passed]
    print(
        f"\n{len(results)} 条规则：{len(results) - len(failed)} 通过，{len(failed)} 被拒"
        f"（攻击样本 {sum(item.attack_total for item in results)} 条，"
        f"正常流量 {results[0].benign_total if results else 0} 条）"
    )
    _write_reports(results, args=args, title="WAF 规则评测")
    return 0 if not failed else 1


async def _ask_model(category: str, corpus: Corpus, model: str | None) -> WafRule | None:
    from vulnarena.arena.deepseek import DeepSeekClient
    from vulnarena.config import Settings

    settings = Settings()
    if model:
        settings = settings.model_copy(update={"deepseek_model": model})
    client = DeepSeekClient(settings)
    try:
        return await generate_rule(client, category, corpus)
    finally:
        await client.aclose()


def _cmd_generate(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.corpus)
    rule = asyncio.run(_ask_model(args.category, corpus, args.model))
    if rule is None:
        print("模型没有给出可用的规则（无 key / 调用失败 / 输出不合法）")
        return 0

    results = [evaluate(rule, corpus, name="llm-proposal")]
    template = RULE_TEMPLATES.get(args.category)
    if template is not None:
        baseline = WafRule(category=rule.category, regex=template[0], source="template")
        results.append(evaluate(baseline, corpus, name="template-baseline"))

    _print(results)
    print(f"\n模型给的理由：{rule.rationale}")
    _write_reports(results, args=args, title=f"模型生成规则 · {args.category}")
    return 0


def _rounds_markdown(results: list[RoundResult], category: str) -> str:
    lines = [
        f"# 自博弈 · {category}",
        "",
        "| 轮次 | 语料 | 红队新增 | 蓝队规则 | 召回 | 误杀 | 判定 |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in results:
        lines.append(
            f"| {item.round_no} | {item.corpus_attacks} | {item.red_added} | "
            f"{item.rule_name} | {item.recall:.0%} | {item.false_positive:.1%} | "
            f"{'OK' if item.passed else 'REJECT'} |"
        )
    failed = [item for item in results if not item.passed]
    if failed:
        lines += ["", "## 蓝队漏掉的", ""]
        for item in failed:
            lines.append(f"### 第 {item.round_no} 轮：{item.note}")
            for sample in item.new_samples:
                lines.append(f"- `{sample[:100]}`")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _cmd_selfplay(args: argparse.Namespace) -> int:
    corpus = load_corpus(args.corpus)

    async def play():
        from vulnarena.bench.mutate import mutate

        client = None
        if args.llm:
            from vulnarena.arena.deepseek import DeepSeekClient
            from vulnarena.config import Settings

            client = DeepSeekClient(Settings())

        async def blue(current):
            if client is None:
                return None
            return await generate_rule(client, args.category, current)

        def red(current, category):
            known = set(current.attacks.get(category, []))
            fresh: list[str] = []
            for sample in current.attacks.get(category, []):
                for variant in mutate(sample):
                    if variant not in known and variant not in fresh:
                        fresh.append(variant)
                if len(fresh) >= args.red_limit:
                    return fresh
            return fresh

        try:
            return await run_selfplay(
                corpus,
                rounds=args.rounds,
                category=args.category,
                blue=blue if client is not None else None,
                red=red,
            )
        finally:
            if client is not None:
                await client.aclose()

    results = asyncio.run(play())

    for item in results:
        mark = "OK " if item.passed else "REJ"
        print(
            f"[{mark}] round {item.round_no}  corpus={item.corpus_attacks} "
            f"red+{item.red_added}  rule={item.rule_name}  "
            f"recall={item.recall:.0%} fp={item.false_positive:.1%}"
        )
        if not item.passed:
            print(f"      - {item.note}")

    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(_rounds_markdown(results, args.category), encoding="utf-8")
        print(f"报告 -> {args.markdown}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps([item.to_dict() for item in results], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"JSON  -> {args.json}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m vulnarena.bench", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="对内置模板规则打分")
    run.add_argument("--corpus", type=Path, default=None, help="自定义语料 JSON")
    run.add_argument("--json", type=Path, default=None, help="把结果写成 JSON")
    run.add_argument("--markdown", type=Path, default=None, help="把结果写成 markdown 报告")
    run.set_defaults(func=_cmd_run)

    gen = sub.add_parser("generate", help="让模型写一条规则并打分")
    gen.add_argument("--category", required=True, help="sqli / ssrf / idor / path_traversal")
    gen.add_argument("--model", default=None, help="覆盖默认模型名")
    gen.add_argument("--corpus", type=Path, default=None)
    gen.add_argument("--json", type=Path, default=None)
    gen.add_argument("--markdown", type=Path, default=None)
    gen.set_defaults(func=_cmd_generate)

    play = sub.add_parser("selfplay", help="离线回合制：红队造变体，蓝队规则被重新打分")
    play.add_argument("--rounds", type=int, default=3)
    play.add_argument("--red-limit", type=int, default=20, help="红队每轮最多新增多少条")
    play.add_argument("--category", default="sqli")
    play.add_argument("--llm", action="store_true", help="让模型当蓝队（规则提议）")
    play.add_argument("--corpus", type=Path, default=None)
    play.add_argument("--json", type=Path, default=None)
    play.add_argument("--markdown", type=Path, default=None)
    play.set_defaults(func=_cmd_selfplay)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())

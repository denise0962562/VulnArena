"""把自博弈结果画成 SVG（不依赖浏览器，可在 CI 里重生成）。

用法：
    python scripts/plot_selfplay.py --json reports/selfplay.json --out docs/figures/selfplay.svg
不给 --json 时现场运行三回合确定性基线；不读取写死的数字。
"""

import argparse
import asyncio
import html
import json
from pathlib import Path

WIDTH, HEIGHT = 720, 320
PAD_L, PAD_R, PAD_T, PAD_B = 64, 24, 28, 48


def render(rounds: list[dict], *, title: str = "自博弈：固定规则与唯一语料召回率") -> str:
    plot_w = WIDTH - PAD_L - PAD_R
    plot_h = HEIGHT - PAD_T - PAD_B
    count = len(rounds)

    def x_at(index: int) -> float:
        return PAD_L + (plot_w * index / (count - 1) if count > 1 else plot_w / 2)

    def y_at(value: float) -> float:
        return PAD_T + plot_h * (1 - value)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" '
        f'font-family="Segoe UI, Microsoft YaHei, sans-serif">',
        f'<rect width="{WIDTH}" height="{HEIGHT}" fill="#0d1117"/>',
        f'<text x="{PAD_L}" y="20" fill="#c9d4e5" font-size="13">{html.escape(title)}</text>',
    ]

    # 网格 + y 轴刻度（0/25/50/75/100%）
    for step in range(5):
        value = step / 4
        y = y_at(value)
        parts.append(
            f'<line x1="{PAD_L}" y1="{y:.1f}" x2="{WIDTH - PAD_R}" y2="{y:.1f}" '
            f'stroke="#232c3a" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{PAD_L - 10}" y="{y + 4:.1f}" fill="#7c8aa5" font-size="11" '
            f'text-anchor="end">{int(value * 100)}%</text>'
        )

    points = " ".join(f"{x_at(i):.1f},{y_at(row['recall']):.1f}" for i, row in enumerate(rounds))
    parts.append(f'<polyline points="{points}" fill="none" stroke="#4f8cff" stroke-width="2.5"/>')

    for index, row in enumerate(rounds):
        x, y = x_at(index), y_at(row["recall"])
        color = "#35d07f" if row.get("false_positive", 0) == 0 else "#ff5d6c"
        parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{color}"/>')
        parts.append(
            f'<text x="{x:.1f}" y="{y - 10:.1f}" fill="#c9d4e5" font-size="11" '
            f'text-anchor="middle">{row["recall"]:.0%}</text>'
        )
        parts.append(
            f'<text x="{x:.1f}" y="{HEIGHT - PAD_B + 18}" fill="#7c8aa5" font-size="11" '
            f'text-anchor="middle">R{row["round_no"]} · {row["corpus_attacks"]} 条</text>'
        )

    parts.append(
        f'<text x="{PAD_L}" y="{HEIGHT - 8}" fill="#55617a" font-size="10">'
        f"蓝队规则固定为模板；红队每轮上限 20 条变体</text>"
    )
    parts.append("</svg>")
    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=Path("docs/figures/selfplay.svg"))
    args = parser.parse_args()

    if args.json and args.json.exists():
        payload = json.loads(args.json.read_text(encoding="utf-8"))
        rounds = payload.get("rounds", payload) if isinstance(payload, dict) else payload
    else:
        if args.json:
            raise SystemExit("Specified report file does not exist.")
        from vulnarena.bench.corpus import load_corpus
        from vulnarena.bench.mutate import limited_variants
        from vulnarena.bench.selfplay import run_selfplay

        results = asyncio.run(
            run_selfplay(
                load_corpus(),
                rounds=3,
                red=lambda corpus, category: limited_variants(corpus, category, 20),
            )
        )
        rounds = [item.to_dict() for item in results]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(rounds), encoding="utf-8")
    print(f"wrote {args.out} ({len(rounds)} rounds)")


if __name__ == "__main__":
    main()

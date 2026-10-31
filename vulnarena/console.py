"""靶场管理台：挂在 VulnArena 主站上的服务端渲染页面。

从 VulnArena 侧边栏点进来，能看见：靶标、关卡进度与段位、跑过哪些演练、一键开始。
观战台（/arena）和靶场前台（/api/procure/ui/login）都从这里进。
"""

import html
from pathlib import Path
from string import Template

LAB_TEMPLATE = Template(
    Path(__file__).with_name("templates").joinpath("lab.html").read_text(encoding="utf-8")
)

STYLE = """
:root{--bg:#0d1117;--panel:#151b24;--line:#232c3a;--text:#c9d4e5;--muted:#7c8aa5;
--blue:#4f8cff;--green:#35d07f;--red:#ff5d6c;--amber:#f5b942}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.65 "Segoe UI","Microsoft YaHei",system-ui,sans-serif}
a{color:var(--blue);text-decoration:none}
header{display:flex;justify-content:space-between;align-items:center;
padding:12px 22px;border-bottom:1px solid var(--line);background:#10161f}
.brand{font-weight:700}.brand span{color:var(--blue)}
main{max-width:1180px;margin:0 auto;padding:22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}
h1{font-size:20px;margin:0 0 6px}
h3{margin:0 0 12px;font-size:15px}
.muted{color:var(--muted);font-size:12.5px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);font-size:13.5px}
th{color:var(--muted);font-size:12px;letter-spacing:.6px;text-transform:uppercase}
tr:last-child td{border-bottom:0}
.tag{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.tag.on{color:var(--green);border-color:#1c4634}
.tag.ok{color:var(--green);border-color:#1c4634}
.tag.bad{color:var(--red);border-color:#4a1a20}
button{font:inherit;background:var(--blue);color:#06121f;border:0;border-radius:8px;
padding:8px 16px;font-weight:600;cursor:pointer}
button:disabled{background:#24304a;color:#55617a;cursor:not-allowed}
a.btn{display:inline-block;padding:7px 14px;border:1px solid var(--line);border-radius:8px;
color:var(--text);font-weight:500}
a.btn:hover{border-color:var(--blue);color:var(--blue)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.stat{background:#0b1119;border:1px solid var(--line);border-radius:10px;padding:12px}
.stat b{display:block;font-size:22px}
"""


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def selfplay_result(payload: dict) -> tuple[str, str]:
    """Render stored numeric results as HTML/SVG without browser scripting."""
    rows = payload.get("rounds", [])
    if not rows:
        return '<tr><td colspan="7" class="muted">还没跑过</td></tr>', ""
    table = []
    points = []
    marks = []
    for index, row in enumerate(rows):
        recall = float(row["recall"])
        passed = bool(row["passed"])
        x = 320 if len(rows) == 1 else 24 + 592 * index / (len(rows) - 1)
        y = 24 + 152 * (1 - max(0, min(1, recall)))
        points.append(f"{x:.2f},{y:.2f}")
        marks.append(
            f'<circle cx="{x:.2f}" cy="{y:.2f}" r="4" '
            f'fill="{"#35d07f" if passed else "#ff5d6c"}" />'
            f'<text x="{x:.2f}" y="{y - 8:.2f}" fill="#7c8aa5" '
            f'font-size="11" text-anchor="middle">{recall:.0%}</text>'
        )
        table.append(
            f"<tr><td>{esc(row['round_no'])}</td><td>{esc(row['corpus_attacks'])}</td>"
            f"<td>{esc(row.get('red_candidates', '—'))}</td>"
            f"<td>+{esc(row['red_added'])}</td><td>{recall:.0%}</td>"
            f"<td>{float(row['false_positive']):.1%}</td>"
            f'<td><span class="tag {"ok" if passed else "bad"}">'
            f"{'OK' if passed else 'REJECT'}</span></td></tr>"
        )
    curve = (
        f'<polyline points="{" ".join(points)}" fill="none" stroke="#4f8cff" '
        'stroke-width="2" />' + "".join(marks)
    )
    return "".join(table), curve


def render(
    targets: list[dict],
    sessions: list[dict],
    levels: list[dict] | None = None,
    score: int = 0,
    rank: str = "",
    selfplay: dict | None = None,
    selfplay_error: str = "",
) -> str:
    selfplay = selfplay or {}
    rounds_rows, curve = selfplay_result(selfplay)
    play_hint = (
        f"已完成 {len(selfplay['rounds'])} 回合；刷新仅查看结果，不会重跑。"
        if selfplay.get("rounds")
        else "确定性红队，不调用模型；提交后等待结果页，无需 JavaScript。"
    )
    play_error = f'<p role="alert">{esc(selfplay_error)}</p>' if selfplay_error else ""
    enabled = [t for t in targets if t.get("enabled")]
    live = len(sessions)
    verified = sum(1 for s in sessions if s.get("status") == "VERIFIED")
    levels = levels or []
    solved = sum(1 for level in levels if level.get("solved"))
    earned = sum(level.get("score", 0) for level in levels)
    total = score or earned
    defects = sorted({d for t in enabled for d in (t.get("defects") or [])})

    target_rows = "".join(
        "<tr>"
        f"<td><code>{esc(t.get('id'))}</code></td>"
        f"<td>{esc(t.get('language'))}</td>"
        f"<td>{esc(t.get('scenario'))}</td>"
        f"<td><span class='tag {'on' if t.get('enabled') else ''}'>"
        f"{'已启用' if t.get('enabled') else '未启用'}</span></td>"
        f"<td>{esc(t.get('base_path'))}</td>"
        "</tr>"
        for t in targets
    )

    level_rows = (
        "".join(
            "<tr>"
            f"<td>L{esc(level.get('tier'))}</td>"
            f"<td>{esc(level.get('title'))}</td>"
            f"<td>{esc(level.get('goal'))}</td>"
            f"<td>{esc(level.get('teaches'))}</td>"
            f"<td>{esc(level.get('difficulty'))}</td>"
            f"<td>{esc(level.get('points'))}</td>"
            f"<td>{esc(level.get('score'))}</td>"
            f"<td><span class='tag {'ok' if level.get('solved') else ''}'>"
            f"{'已通过' if level.get('solved') else ('可挑战' if level.get('unlocked') else '未解锁')}"
            f"</span></td>"
            "</tr>"
            for level in levels
        )
        or "<tr><td colspan='8' class='muted'>暂无关卡</td></tr>"
    )

    if sessions:
        session_rows = "".join(
            "<tr>"
            f"<td><code>{esc(s.get('session_id'))}</code></td>"
            f"<td><span class='tag {'ok' if s.get('status') == 'VERIFIED' else 'bad'}'>"
            f"{esc(s.get('status'))}</span></td>"
            f"<td>{esc(s.get('agent_mode', 'deterministic'))} · {esc(s.get('model_calls', 0))} 次调用"
            f"<br><span class='muted'>{esc(s.get('fallback_reason', ''))}</span></td>"
            f"<td>{esc(', '.join(s.get('defects') or []) or '—')}</td>"
            f"<td class='muted'>{esc((s.get('started_at') or '')[:19].replace('T', ' '))}</td>"
            "</tr>"
            for s in sessions[:10]
        )
    else:
        session_rows = (
            "<tr><td colspan='5' class='muted'>还没有演练记录，点上面的按钮跑一场。</td></tr>"
        )

    return LAB_TEMPLATE.substitute(
        style=STYLE,
        enabled_count=len(enabled),
        defect_count=len(defects),
        session_count=live,
        verified_count=verified,
        solved_count=solved,
        level_count=len(levels),
        score=total,
        rank=esc(rank or "新人"),
        play_hint=esc(play_hint),
        play_error=play_error,
        metrics_version=esc(selfplay.get("metrics_version", "尚未运行")),
        build_id=esc(selfplay.get("build_id", "—")),
        created_at=esc(selfplay.get("created_at", "—")),
        curve=curve,
        rounds_rows=rounds_rows,
        level_rows=level_rows,
        target_rows=target_rows,
        session_rows=session_rows,
    )

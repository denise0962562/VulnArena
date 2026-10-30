"""靶场管理台：挂在 VulnArena 主站上的服务端渲染页面。

从 VulnArena 侧边栏点进来，能看见：靶标、关卡进度与段位、跑过哪些演练、一键开始。
观战台（/arena）和靶场前台（/api/procure/ui/login）都从这里进。
"""

import html

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


SELFPLAY_SCRIPT = """
<script>
const playBtn = document.getElementById('play');
const roundsBody = document.getElementById('rounds');
const curve = document.getElementById('curve');

function draw(rows) {
  curve.innerHTML = '';
  if (!rows.length) return;
  const pad = 24, w = 640 - pad * 2, h = 200 - pad * 2;
  const points = rows.map((row, i) => {
    const x = pad + (rows.length === 1 ? w / 2 : (w * i) / (rows.length - 1));
    const y = pad + h * (1 - row.recall);
    return `${x},${y}`;
  });
  const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
  line.setAttribute('points', points.join(' '));
  line.setAttribute('fill', 'none');
  line.setAttribute('stroke', '#4f8cff');
  line.setAttribute('stroke-width', '2');
  curve.append(line);
  rows.forEach((row, i) => {
    const [x, y] = points[i].split(',');
    const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    dot.setAttribute('cx', x); dot.setAttribute('cy', y); dot.setAttribute('r', '4');
    dot.setAttribute('fill', row.passed ? '#35d07f' : '#ff5d6c');
    curve.append(dot);
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', x); label.setAttribute('y', Number(y) - 8);
    label.setAttribute('fill', '#7c8aa5'); label.setAttribute('font-size', '11');
    label.setAttribute('text-anchor', 'middle');
    label.textContent = `${Math.round(row.recall * 100)}%`;
    curve.append(label);
  });
}

function render(payload) {
  const rows = payload.rounds || [];
  roundsBody.innerHTML = rows.map((row) => `<tr>
    <td>${row.round_no}</td><td>${row.corpus_attacks}</td><td>+${row.red_added}</td>
    <td>${Math.round(row.recall * 100)}%</td><td>${(row.false_positive * 100).toFixed(1)}%</td>
    <td><span class="tag ${row.passed ? 'ok' : 'bad'}">${row.passed ? 'OK' : 'REJECT'}</span></td>
  </tr>`).join('');
  draw(rows);
}

async function load() {
  const response = await fetch('/api/bench/selfplay');
  render(await response.json());
}

playBtn.addEventListener('click', async () => {
  playBtn.disabled = true;
  document.getElementById('play-hint').textContent = '跑着呢…';
  try {
    const response = await fetch('/api/bench/selfplay?rounds=3', { method: 'POST' });
    render(await response.json());
    document.getElementById('play-hint').textContent = '跑完了';
  } catch (error) {
    document.getElementById('play-hint').textContent = '失败：' + error.message;
  } finally {
    playBtn.disabled = false;
  }
});

window.addEventListener("error", (event) => {`n  const hint = document.getElementById("play-hint");`n  if (hint) hint.textContent = "页面脚本出错：" + event.message;`n});`n`nload().catch((error) => {`n  const hint = document.getElementById("play-hint");`n  if (hint) hint.textContent = "加载历史失败：" + error.message;`n});
</script>
"""


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def render(
    targets: list[dict],
    sessions: list[dict],
    levels: list[dict] | None = None,
    score: int = 0,
    rank: str = "",
) -> str:
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
            f"<td>{esc(', '.join(s.get('defects') or []) or '—')}</td>"
            f"<td class='muted'>{esc((s.get('started_at') or '')[:19].replace('T', ' '))}</td>"
            "</tr>"
            for s in sessions[:10]
        )
    else:
        session_rows = (
            "<tr><td colspan='4' class='muted'>还没有演练记录，点上面的按钮跑一场。</td></tr>"
        )

    return (
        f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>靶场管理 · VulnArena</title><style>{STYLE}</style></head><body>
<header><div class="brand">Vuln<span>Scope</span> · 靶场管理</div>
<div class="row"><a class="btn" href="/">返回情报台</a></div></header>
<main>
  <div class="card">
    <h1>靶场演练台</h1>
    <p class="muted">左边是情报，这里是对抗。所有靶标都是本项目自建的内存沙盒，
    不连接任何外部系统；演练结果可回放、可跟练。</p>
    <div class="grid" style="margin-top:14px">
      <div class="stat"><b>{len(enabled)}</b><span class="muted">已启用靶标</span></div>
      <div class="stat"><b>{len(defects)}</b><span class="muted">可开关的缺陷类型</span></div>
      <div class="stat"><b>{live}</b><span class="muted">本次进程内演练</span></div>
      <div class="stat"><b>{verified}</b><span class="muted">其中 VERIFIED</span></div>
      <div class="stat"><b>{solved}/{len(levels)}</b><span class="muted">关卡通过</span></div>
      <div class="stat"><b>{total}</b><span class="muted">总分 · {esc(rank or "新人")}</span></div>
    </div>
    <div class="row" style="margin-top:16px">
      <button id="start">开始一场演练</button>
      <a class="btn" href="/arena">打开观战台</a>
      <a class="btn" href="/api/procure/ui/login" target="_blank">打开靶场前台（采购系统）</a>
      <span id="hint" class="muted"></span>
    </div>
  </div>

  <div class="card">
    <h3>自博弈曲线（红队造变体 → 蓝队召回下降）</h3>
    <div class="row">
      <button id="play">跑一轮（3 回合）</button>
      <span id="play-hint" class="muted">确定性红队，不调用模型，几秒出结果</span>
    </div>
    <svg id="curve" viewBox="0 0 640 200" style="width:100%;height:200px;margin-top:12px"></svg>
    <table><thead><tr><th>轮次</th><th>语料</th><th>红队新增</th><th>召回</th><th>误杀</th><th>判定</th></tr></thead>
    <tbody id="rounds"><tr><td colspan="6" class="muted">还没跑过</td></tr></tbody></table>
  </div>

  <div class="card">
    <h3>关卡（由浅入深，通过后解锁下一层）</h3>
    <table><thead><tr><th>层</th><th>关卡</th><th>目标</th><th>考什么</th><th>难度</th>
    <th>分值</th><th>得分</th><th>状态</th></tr></thead><tbody>{level_rows}</tbody></table>
    <p class="muted" style="margin-top:10px">判定看攻击的副作用（canary / 数据库状态），不看提交的 flag；
    用提示会扣分（每用一次七折，最低四成）。</p>
  </div>

  <div class="card">
    <h3>靶标清单</h3>
    <table><thead><tr><th>ID</th><th>语言</th><th>业务场景</th><th>状态</th><th>挂载路径</th></tr></thead>
    <tbody>{target_rows}</tbody></table>
    <p class="muted" style="margin-top:10px">新增一门语言 = 加一条 manifest + 一个小服务，
    不改动已有靶标（见 docs/SYSTEM-DESIGN.md）。</p>
  </div>

  <div class="card">
    <h3>最近演练</h3>
    <table><thead><tr><th>会话</th><th>状态</th><th>开启的缺陷</th><th>开始时间</th></tr></thead>
    <tbody>{session_rows}</tbody></table>
  </div>
</main>
<script>
document.getElementById('start').addEventListener('click', async (event) => {{
  const button = event.target; button.disabled = true;
  const hint = document.getElementById('hint');
  hint.textContent = '正在创建演练…';
  try {{
    const response = await fetch('/api/arena/start', {{ method: 'POST' }});
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const body = await response.json();
    hint.textContent = '已创建 ' + body.session_id + '，正在跳转观战台…';
    setTimeout(() => {{ window.location.href = '/arena?session=' + body.session_id; }}, 600);
  }} catch (error) {{
    hint.textContent = '启动失败：' + error.message;
    button.disabled = false;
  }}
}});

{SELFPLAY_SCRIPT}</body></html>"""
    )

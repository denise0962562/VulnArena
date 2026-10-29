"""Turn a finished drill into a hands-on guide.

三级提示：L1 任务（要达成什么）→ L2 思路（往哪看）→ L3 命令（具体怎么打）。
默认只给 L1，学习者自己动手；卡住了再逐级展开，做完再对答案（explanation）。

Deterministic on purpose: the same session always yields the same steps. A model
may later rewrite the prose, but commands and expectations must never depend on it.
"""

import json
import shlex
from urllib.parse import urlencode

from vulnarena.arena.contracts import ArenaSession, GuideStep, HttpCall, ProbeTrace

DEFAULT_HOST = "http://127.0.0.1:8000"
DEFAULT_BASE = "/api/procure"

LOGIN = HttpCall(
    method="POST",
    path="/login",
    json_body={"username": "alice", "password": "alice-pw"},
    actor="anonymous",
)

# L1 任务 / L2 思路，按步骤标题索引；第 3 级（命令）由请求本身渲染。
HINTS: dict[str, tuple[str, str]] = {
    "baseline: list purchase orders": (
        "先摸清正常响应长什么样",
        "不带任何攻击载荷请求一次 /pos，记下条数、字段、状态码。后面每一步都要跟它对比。",
    ),
    "login bypass: become the CFO": (
        "拿到一个高管会话",
        "登录框把用户名直接拼进 SQL。想一想：如果密码那一段被注释掉，校验还在吗？",
    ),
    "naive union on order search": (
        "用搜索框把 secrets 表读出来",
        "搜索参数被拼进 LIKE。先数一下返回几列，再构造同样列数的联合查询。",
    ),
    "mutated union (UNION ALL)": (
        "绕过那条刚拦住你的规则",
        "上一轮被拦，说明规则认的是某个固定写法。SQL 里有没有和它等价、但字面不同的写法？",
    ),
    "idor: read a foreign purchase order": (
        "读到一张不属于你的单据",
        "详情接口只认 id。换一个别人的单号试试——注意响应里有没有审批人、预算科目。",
    ),
    "mass assignment: approve as the CFO": (
        "让一张大额单据一步变 APPROVED",
        "审批接口接收了 approver 字段。服务端是拿会话身份，还是请求体里的身份？状态机校验了吗？",
    ),
    "attachment traversal: read the bank key": (
        "读出付款网关的密钥",
        "附件名被拼进路径。上传目录的上一级是什么？试试用 ../ 往上走。",
    ),
    "ssrf: reach the metadata service": (
        "让服务器替你访问内网",
        "供应商回调地址由请求体决定。服务端校验过目标主机吗？试试常见的云元数据地址。",
    ),
}

DEFENSE_NOTES = {
    "sqli": "两层一起做：SQL 参数化绑定消灭缺陷，网关正则挡住已经在路上的流量。"
    "只做正则会被等价变体绕过（本场演练里 UNION ALL 就是一例）。",
    "idor": "网关拦不住越权。必须由服务端校验资源归属，并且覆盖列表、详情、批量三个入口。",
    "logic": "身份永远从会话取，不能从请求体取；状态机的合法迁移要写成显式表，而不是 if 分支。",
    "path_traversal": "路径必须先归一化再校验前缀，并且只允许白名单目录；不要相信 basename。",
    "ssrf": "目标主机走白名单，或者干脆只允许固定的回调域名；解析后的 IP 也要校验。",
}
DEFAULT_DEFENSE = "先判断这个缺陷属于「代码问题」还是「流量特征」，再决定改代码还是加规则。"


def render_url(call: HttpCall, base: str, host: str) -> str:
    url = f"{host}{base}{call.path}"
    if call.params:
        url = f"{url}?{urlencode(call.params)}"
    return url


def render_curl(call: HttpCall, base: str, host: str) -> str:
    parts = ["curl", "-s", "-X", call.method, shlex.quote(render_url(call, base, host))]
    if call.actor != "anonymous":
        parts += ["-H", shlex.quote("Authorization: Bearer $TOKEN")]
    if call.json_body is not None:
        body = json.dumps(call.json_body, ensure_ascii=False)
        parts += ["-H", shlex.quote("Content-Type: application/json"), "-d", shlex.quote(body)]
    return " ".join(parts)


def render_powershell(call: HttpCall, base: str, host: str) -> str:
    url = render_url(call, base, host)
    parts = [f'Invoke-RestMethod -Uri "{url}"']
    if call.method != "GET":
        parts.append(f"-Method {call.method.title()}")
    if call.actor != "anonymous":
        parts.append('-Headers @{ Authorization = "Bearer $TOKEN" }')
    if call.json_body is not None:
        body = json.dumps(call.json_body, ensure_ascii=False).replace("'", "''")
        parts.append('-ContentType "application/json"')
        parts.append(f"-Body '{body}'")
    return " ".join(parts)


def _marker(trace: ProbeTrace) -> str:
    if trace.canary_hit:
        return "响应里出现 canary 标记（说明缺陷被真实触发）"
    if trace.breached:
        return "HTTP 200，且响应里的 role / approver 变成了别人的身份"
    if trace.status == 403 and trace.blocked_by == "waf":
        return f"HTTP 403，rule_id={trace.rule_id}（被网关规则拦下）"
    if trace.status == 403:
        return "HTTP 403（被业务权限拒绝）"
    return f"HTTP {trace.status}，响应中不含 canary"


def _explanation(trace: ProbeTrace) -> str:
    if trace.canary_hit:
        return (
            f"{trace.reasoning}。判断依据不是状态码，而是 canary 有没有出现在响应里——"
            "这是本演练最直接的击穿信号。"
        )
    if trace.breached:
        return (
            f"{trace.reasoning}。这一步的成功信号不是 canary，而是服务端认可了伪造的身份："
            "身份/状态机校验被绕过。"
        )
    if trace.status == 403 and trace.blocked_by == "waf":
        return (
            f"{trace.reasoning}。注意这里被拦不代表安全：初始规则只覆盖了一种写法，"
            "下一步会给出等价变体。"
        )
    if trace.status == 403:
        return f"{trace.reasoning}。这次是被业务逻辑拒绝，不是网关。"
    return f"{trace.reasoning}。这是一条正常业务请求，用来做基线对比。"


def build_guide(
    session: ArenaSession, *, base: str = DEFAULT_BASE, host: str = DEFAULT_HOST
) -> list[GuideStep]:
    steps: list[GuideStep] = [
        GuideStep(
            index=1,
            title="准备：登录拿 token",
            intent="业务接口都要 Bearer token，先取一个放进 $TOKEN。",
            brief="登录一个普通员工账号",
            hint="用 alice / alice-pw 调 /login，把返回的 token 存进环境变量 $TOKEN。",
            request=LOGIN,
            curl=render_curl(LOGIN, base, host),
            powershell=render_powershell(LOGIN, base, host),
            expected_status=200,
            expected_marker="返回 token、role、tenant、department",
            explanation="登录成功返回 token。这一步没有漏洞，但它决定了你后面以什么身份行动。",
            defense_note="登录本身就是攻击面：用户名拼 SQL 允许跳过密码校验，下一步会演示。",
        )
    ]

    index = 2
    for trace in session.traces:
        brief, hint = HINTS.get(trace.label, ("复现这一类缺陷", trace.reasoning))
        steps.append(
            GuideStep(
                index=index,
                title=trace.label,
                intent=trace.reasoning,
                brief=brief,
                hint=hint,
                request=trace.call,
                curl=render_curl(trace.call, base, host),
                powershell=render_powershell(trace.call, base, host),
                expected_status=trace.status,
                expected_marker=_marker(trace),
                explanation=_explanation(trace),
                defense_note=DEFENSE_NOTES.get(trace.category or "", DEFAULT_DEFENSE),
            )
        )
        index += 1

    breach = next((trace for trace in session.traces if trace.breached), None)
    if breach is not None and session.patch is not None:
        steps.append(
            GuideStep(
                index=index,
                title="验证修复：同一条请求应当被拒绝",
                intent="蓝队已经打上补丁，重放刚才成功的那条请求，对比结果。",
                brief="确认防御真的生效",
                hint="把刚才那条成功的请求原样再发一次；如果还是 200，说明补丁没打到点上。",
                request=breach.call,
                curl=render_curl(breach.call, base, host),
                powershell=render_powershell(breach.call, base, host),
                expected_status=403,
                expected_marker="HTTP 403；响应里不再出现 canary",
                explanation="如果仍然 200 且带 canary，说明补丁无效或规则没生效——"
                "这就是回归验证存在的意义。",
                defense_note="同一个 payload，修复前 200、修复后 403，"
                "这个对比本身就是防御生效的证据。",
            )
        )
    return steps

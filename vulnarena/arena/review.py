"""复盘：把一场演练翻译成"你是怎么打穿的、蓝队怎么补的"。

只做归纳，不产生新事实——所有结论都来自 session 里已有的 trace / patch / regression。
"""

from pydantic import BaseModel, Field

from vulnarena.arena.contracts import ArenaSession, ArenaStatus

LESSONS = {
    "sqli": "SQL 拼接让输入变成了代码：先想清楚这条查询的字符串长什么样，再决定塞什么进去。",
    "idor": "接口只校验「有没有登录」，没校验「是不是你的」。改一个 id 就够了。",
    "logic": "身份与状态机都应该由服务端从会话推导，一旦信任请求体，越权就是一步的事。",
    "path_traversal": "路径拼接后没有归一化，`../` 就能跳出预期目录。",
    "ssrf": "服务端替你发请求时，目标地址必须白名单，否则内网就是它的后花园。",
}

DEFENSES = {
    "sqli": "参数化绑定 + 网关规则双保险；只加规则会被等价变体绕过。",
    "idor": "每个详情/批量接口都要校验资源归属，网关帮不上忙。",
    "logic": "审计日志 + 显式状态机；身份永远从会话取。",
    "path_traversal": "归一化后校验前缀，只允许白名单目录。",
    "ssrf": "目标主机白名单 + 解析后 IP 校验。",
}


class ReviewStep(BaseModel):
    step: int
    label: str
    action: str
    result: str
    lesson: str
    defense: str


class ArenaReview(BaseModel):
    session_id: str
    verdict: str
    headline: str
    entry_point: str
    steps: list[ReviewStep] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)
    flags_off: list[str] = Field(default_factory=list)
    regression: dict[str, object] = Field(default_factory=dict)
    cost_ms: int = 0


def _action(trace) -> str:
    call = trace.call
    query = "&".join(f"{key}={value}" for key, value in (call.params or {}).items())
    target = f"{call.path}?{query}" if query else call.path
    actor = call.actor if call.actor != "anonymous" else "未登录"
    body = ""
    if call.json_body:
        body = " " + str(call.json_body)
    return f"{actor} → {call.method} {target}{body}"


def _result(trace) -> str:
    if trace.canary_hit:
        return f"HTTP {trace.status}，响应里带出 canary（真实数据泄露）"
    if trace.breached:
        return f"HTTP {trace.status}，攻击成功（身份/状态被绕过）"
    if trace.status >= 400:
        by = {"waf": "网关规则", "authorization": "业务校验"}.get(trace.blocked_by, "业务校验")
        return f"HTTP {trace.status}，被{by}拦下"
    return f"HTTP {trace.status}，正常响应"


def build_review(session: ArenaSession) -> ArenaReview:
    breaches = [trace for trace in session.traces if trace.breached]
    categories = {trace.category for trace in breaches if trace.category}
    entry = next((trace for trace in breaches if trace.category == "sqli"), None)

    steps = [
        ReviewStep(
            step=trace.step,
            label=trace.label,
            action=_action(trace),
            result=_result(trace),
            lesson=LESSONS.get(trace.category or "", trace.reasoning),
            defense=DEFENSES.get(trace.category or "", "按缺陷类型分别处理。"),
        )
        for trace in session.traces
    ]

    rules = [rule.regex for rule in (session.patch.rules if session.patch else [])]
    flags_off = list(session.patch.switched_flags) if session.patch else []
    regression = (
        session.regression.model_dump()
        if session.regression is not None
        else {"passed": None, "attack_blocked": 0, "attack_total": 0}
    )

    headline = (
        f"红队 {len(session.traces)} 步、击穿 {len(breaches)} 次，涉及 "
        f"{len(categories)} 类缺陷；蓝队下发 {len(rules)} 条网关规则、关闭 "
        f"{len(flags_off)} 个缺陷，回归 {regression.get('attack_blocked', 0)}/"
        f"{regression.get('attack_total', 0)} 拦截。"
    )
    if session.status is not ArenaStatus.VERIFIED:
        headline = f"演练未通过（{session.status.value}）：" + headline

    return ArenaReview(
        session_id=session.session_id,
        verdict=session.status.value,
        headline=headline,
        entry_point=_action(entry) if entry is not None else "没有找到可用入口",
        steps=steps,
        rules=rules,
        flags_off=flags_off,
        regression=regression,
        cost_ms=sum(trace.elapsed_ms for trace in session.traces),
    )

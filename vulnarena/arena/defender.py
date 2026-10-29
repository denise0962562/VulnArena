"""蓝队：既能在一回合内立刻反应，也能在演练收尾时补齐所有规则。

两条路径共用同一套闸门——**任何规则上线前都要过 5 项检查**，没有例外。
"""

from vulnarena.arena.agents import propose_rule
from vulnarena.arena.context import ArenaContext
from vulnarena.arena.contracts import BlueAction, DefensePatch, ProbeTrace
from vulnarena.arena.gate import GateResult, verify_rule
from vulnarena.arena.policy import WafRule
from vulnarena.arena.templates import RULE_TEMPLATES, render_diff
from vulnarena.procure.models import DefectFlag

FLAG_FOR_CATEGORY: dict[str, tuple[DefectFlag, ...]] = {
    "sqli": (DefectFlag.SQLI_SEARCH, DefectFlag.SQLI_LOGIN_BYPASS),
    "idor": (DefectFlag.IDOR_PO_DETAIL,),
    "logic": (DefectFlag.MASS_ASSIGNMENT, DefectFlag.STATE_SKIP),
    "path_traversal": (DefectFlag.PATH_TRAVERSAL,),
    "ssrf": (DefectFlag.SSRF_SUPPLIER,),
}

RATIONALE = {
    "sqli": "大小写无关并处理注释，覆盖初始规则漏掉的等价变形",
    "ssrf": "同时覆盖点分、十六进制与十进制写法，直接封住元数据地址",
}

NO_RULE_REASON = "这一类没有可用的网关规则（正常流量也长这样），只能改代码"


class TemplateDefender:
    def __init__(self, ctx: ArenaContext):
        self.ctx = ctx

    async def _policy_regexes(self) -> set[str]:
        store = self.ctx.runtime.policy_store
        if store is None:
            return set()
        policy = await store.load(self.ctx.session_id)
        return {rule.regex for rule in policy.blocked_patterns}

    async def _activate(self, rule: WafRule) -> bool:
        store = self.ctx.runtime.policy_store
        if store is None:
            raise RuntimeError("policy store is required to activate a rule")
        policy = await store.load(self.ctx.session_id)
        if any(existing.regex == rule.regex for existing in policy.blocked_patterns):
            return False
        updated = policy.model_copy(update={"blocked_patterns": [*policy.blocked_patterns, rule]})
        await store.save(updated)
        self.ctx.runtime.forget(self.ctx.session_id)
        return True

    async def react(self, trace: ProbeTrace) -> BlueAction:
        """一个回合内立刻响应：给这一类缺陷补一条规则，过了闸门就立刻生效。"""
        category = trace.category or ""
        template = RULE_TEMPLATES.get(category)
        idea = await propose_rule(getattr(self.ctx, "llm", None), trace)

        if idea is not None and template is not None:
            regex, rule_category, source = idea.regex, template[1], "llm"
        elif template is not None:
            regex, rule_category, source = template[0], template[1], "template"
        else:
            return BlueAction(
                after_step=trace.step, accepted=False, reason=NO_RULE_REASON, source="none"
            )

        candidate = WafRule(
            category=rule_category,
            regex=regex,
            source=source,
            rationale=(idea.rationale if idea is not None else RATIONALE.get(category, "")),
        )
        gate = await verify_rule(candidate)
        if not gate.passed:
            return BlueAction(
                after_step=trace.step,
                regex=regex,
                accepted=False,
                reason="闸门否决：" + "；".join(gate.failures[:2]),
                source=source,
            )

        added = await self._activate(candidate)
        return BlueAction(
            after_step=trace.step,
            regex=regex,
            rule_id=candidate.id,
            accepted=True,
            reason="已上线" if added else "同类规则已存在",
            source=source,
        )

    async def patch(self, traces: list[ProbeTrace]) -> DefensePatch:
        """收尾：补齐还没上线的类别，并把能关的代码缺陷全部关掉。"""
        categories = sorted({trace.category for trace in traces if trace.category})
        existing = await self._policy_regexes()
        rules: list[WafRule] = []
        gates: list[GateResult] = []

        for category in categories:
            template = RULE_TEMPLATES.get(category)
            if template is None:
                continue
            regex, rule_category = template
            candidate = WafRule(
                category=rule_category,
                regex=regex,
                source="template",
                rationale=RATIONALE.get(category, ""),
            )
            gate = await verify_rule(candidate)
            gates.append(gate)
            if not gate.passed:
                continue
            rules.append(candidate)  # 回合中上线的也算进最终防线
            if candidate.regex in existing:
                continue  # policy 里已经有了，不重复写
            await self._activate(candidate)

        switched: list[str] = []
        for category in categories:
            for flag in FLAG_FOR_CATEGORY.get(category, ()):
                self.ctx.state.set_flag(flag, False)
                switched.append(flag.value)

        return DefensePatch(
            rule=rules[0] if rules else None,
            rules=rules,
            gate=gates[0] if gates else None,
            gates=gates,
            switched_flags=switched,
            diff="\n".join(render_diff(category) for category in categories),
            rationale="能上网关的补规则，网关拦不住的改代码；两层缺一不可。",
        )

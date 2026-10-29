"""红队 AI：只让它决定「打哪一枪、按什么顺序」，payload 仍然是确定的。

这样既有模型参与（它会挑顺序、给理由），又不会因为模型胡编 payload 而炸场；
模型不可用时原样退回确定性链。
"""

import json

from pydantic import BaseModel, ConfigDict, Field

from vulnarena.arena.deepseek import DeepSeekClient

SYSTEM = (
    "你是红队队长，正在测试自建靶场（一套企业采购审批系统）。"
    "你只能从 catalog 里挑选步骤并排序，不能发明新步骤，也不能改动步骤内容。"
    "目标：用尽量少的步骤拿到真实数据（canary）或提升身份。"
    '只输出 json，形如 {"steps": ["标签1", "标签2"], "rationale": "一句话理由"}'
)


class AttackPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    steps: list[str] = Field(min_length=1, max_length=12)
    rationale: str = Field(default="", max_length=300)


async def plan_attack(llm: DeepSeekClient | None, catalog: list[str]) -> AttackPlan | None:
    if llm is None or not llm.available or llm.budget_left <= 0:
        return None
    user = json.dumps(
        {"catalog": catalog, "hint": "先侦察，再拿身份，再取数据，最后看暴露面"},
        ensure_ascii=False,
    )
    plan = await llm.json_chat(SYSTEM, user, AttackPlan)
    if plan is None:
        return None
    valid = [label for label in plan.steps if label in catalog]
    if not valid:
        return None
    return plan.model_copy(update={"steps": valid})


RULE_SYSTEM = (
    "你是蓝队防守工程师。给你一次刚刚成功的攻击，请给出一条 WAF 正则："
    "既要拦住这类攻击，又不能误伤正常业务（例如带单引号的中文标题、百分比、文件名）。"
    '只输出 json，形如 {"regex": "...", "rationale": "一句话"}'
)


class RuleIdea(BaseModel):
    model_config = ConfigDict(extra="forbid")

    regex: str = Field(min_length=3, max_length=300)
    rationale: str = Field(default="", max_length=200)


async def propose_rule(llm: DeepSeekClient | None, trace) -> RuleIdea | None:
    """让模型提一条规则；它只是提议，能不能上线由闸门决定。"""
    if llm is None or not llm.available or llm.budget_left <= 0:
        return None
    payload = {
        "category": trace.category,
        "label": trace.label,
        "what_happened": trace.reasoning,
        "status": trace.status,
    }
    return await llm.json_chat(RULE_SYSTEM, json.dumps(payload, ensure_ascii=False), RuleIdea)

"""让模型写一条 WAF 规则：给类别 + 少量攻击样本 + 正常样本，要求输出正则。

关键点：**模型只负责提议**。它写的正则不会被信任，一律交给 bench 打分；
过不了闸门就是"模型想得美"，这正是要展示的东西。
"""

import json
import logging

from pydantic import BaseModel, Field

from vulnarena.arena.agents import RuleIdea
from vulnarena.arena.corpus import Category
from vulnarena.arena.deepseek import DeepSeekClient
from vulnarena.arena.policy import WafRule
from vulnarena.bench.corpus import Corpus

logger = logging.getLogger(__name__)

SYSTEM = """你是 Web 应用防火墙（WAF）的规则工程师。
给你一类攻击和少量真实样本，请写**一条**正则，要求：
1. 命中该类攻击的全部形态（大小写、编码、注释拆分、等价语法）；
2. 不误伤正常业务流量（中文、单引号、百分号、正常文件名都可能出现）；
3. 长度不超过 300 字符，不使用嵌套量词（避免灾难性回溯）。
只输出 json：{"regex": "...", "rationale": "一句话说明"}"""

MAX_ATTACK_HINTS = 4
MAX_BENIGN_HINTS = 6


def build_prompt(category: str, corpus: Corpus) -> str:
    attacks = corpus.attacks.get(category, [])[:MAX_ATTACK_HINTS]
    benign = corpus.benign[:MAX_BENIGN_HINTS]
    payload = {
        "category": category,
        "attack_samples": attacks,
        "benign_samples": benign,
        "note": "样本只给了一部分，规则要能覆盖同类攻击的其它变体",
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


async def generate_rule(
    client: DeepSeekClient | None, category: str, corpus: Corpus
) -> WafRule | None:
    """模型不可用、输出不合法、类别未知时一律返回 None。"""
    if client is None or not client.available:
        return None
    try:
        enum_category = Category(category)
    except ValueError:
        logger.warning("unknown category %s", category)
        return None

    idea = await client.json_chat(SYSTEM, build_prompt(category, corpus), RuleIdea)
    if not isinstance(idea, RuleIdea):
        return None
    return WafRule(
        category=enum_category,
        regex=idea.regex.strip(),
        source="llm",
        rationale=idea.rationale or "model proposal",
    )


VARIANT_SYSTEM = """你是红队。给你一条正在生效的 WAF 规则和几条已知攻击样本，
请写出能绕过该规则、但语义等价的攻击载荷。
允许的手法：注释拆分、大小写、等价关键字、空白替换、编码。
只输出 json：{"payloads": ["...", "..."]}，最多 6 条，不要解释。"""


class VariantIdea(BaseModel):
    payloads: list[str] = Field(min_length=1, max_length=8)


async def generate_variants(
    client: DeepSeekClient | None, category: str, corpus: Corpus, *, regex: str = ""
) -> list[str]:
    """模型造绕过样本；不可用时返回空列表（调用方退回确定性变形）。"""
    if client is None or not client.available:
        return []
    samples = corpus.attacks.get(category, [])[:3]
    payload = json.dumps(
        {"rule_regex": regex, "attack_samples": samples, "category": category},
        ensure_ascii=False,
    )
    idea = await client.json_chat(VARIANT_SYSTEM, payload, VariantIdea)
    if not isinstance(idea, VariantIdea):
        return []
    known = set(corpus.attacks.get(category, []))
    return [item.strip() for item in idea.payloads if item.strip() and item.strip() not in known]

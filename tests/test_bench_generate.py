"""模型写规则：输出合法才采纳，任何异常都退回 None。"""

import json

import httpx
import pytest

from vulnarena.arena.deepseek import DeepSeekClient
from vulnarena.bench.corpus import load_corpus
from vulnarena.bench.generate import build_prompt, generate_rule
from vulnarena.config import Settings


def _llm(content: str) -> DeepSeekClient:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, json={"choices": [{"message": {"content": content}}]})
    )
    return DeepSeekClient(
        Settings(_env_file=None, deepseek_api_key="sk-test-key-0000000000000000"),
        transport=transport,
    )


async def test_prompt_shows_attacks_and_benign():
    prompt = build_prompt("sqli", load_corpus())
    payload = json.loads(prompt)
    assert payload["category"] == "sqli"
    assert payload["attack_samples"], "要给出攻击样本"
    assert payload["benign_samples"], "要给出正常样本"


async def test_valid_proposal_becomes_a_rule():
    client = _llm(json.dumps({"regex": r"(?i)union\s+select", "rationale": "test"}))
    rule = await generate_rule(client, "sqli", load_corpus())
    await client.aclose()

    assert rule is not None
    assert rule.source == "llm"
    assert str(rule.category) == "sqli"
    assert "union" in rule.regex


async def test_broken_json_is_rejected():
    client = _llm("{not json")
    assert await generate_rule(client, "sqli", load_corpus()) is None
    await client.aclose()


async def test_unknown_category_is_rejected():
    client = _llm(json.dumps({"regex": "x", "rationale": ""}))
    assert await generate_rule(client, "not-a-category", load_corpus()) is None
    await client.aclose()


async def test_client_without_key_returns_none():
    client = DeepSeekClient(Settings(_env_file=None))
    assert await generate_rule(client, "sqli", load_corpus()) is None
    await client.aclose()


@pytest.mark.parametrize("category", ["sqli", "ssrf"])
async def test_proposal_for_each_regex_category(category):
    client = _llm(json.dumps({"regex": "(?i)select|169\\.254", "rationale": "wide"}))
    rule = await generate_rule(client, category, load_corpus())
    await client.aclose()
    assert rule is not None

"""Arena gateway tests: corpora, rule gate, policy store, event bus, middleware."""

import httpx
import pytest
import pytest_asyncio

from vulnarena.arena import (
    ArenaEvent,
    ArenaRuntime,
    InMemoryEventBus,
    InMemoryPolicyStore,
    RedisEventBus,
    RedisPolicyStore,
    WafMiddleware,
    WafPolicy,
    WafRule,
    verify_rule,
)
from vulnarena.arena.corpus import Category, normalise, observation
from vulnarena.arena.middleware import read_jti
from vulnarena.arena.templates import SQLI_RULE_REGEX as GOOD_SQLI
from vulnarena.procure import ProcureState, build_procure_app

# --- corpora -----------------------------------------------------------------


def test_normalise_unquotes_twice_and_strips_comments():
    assert normalise("name=..%252Fetc") == "name=../etc"
    assert normalise("x' UNION/**/SELECT 1 -- trailing") == "x' union select 1"
    assert normalise("a   b") == "a b"


def test_observation_shape():
    raw, norm = observation("get", "/api/procure/pos", "q=1%3D1", "")
    assert raw == "GET /api/procure/pos?q=1%3D1|"
    assert norm == "get /api/procure/pos?q=1=1|"


# --- rule gate ---------------------------------------------------------------


async def test_gate_accepts_precise_rule():
    result = await verify_rule(WafRule(category=Category.SQLI, regex=GOOD_SQLI))
    assert result.passed, result.failures
    assert result.recall == 1.0 and result.false_positive == 0.0


async def test_gate_rejects_rule_that_kills_apostrophes():
    result = await verify_rule(WafRule(category=Category.SQLI, regex="'"))
    assert not result.passed
    assert any("false positive" in failure for failure in result.failures)
    assert result.false_positive > 0


async def test_gate_rejects_low_recall():
    result = await verify_rule(WafRule(category=Category.SQLI, regex="flag_vault"))
    assert not result.passed
    assert any("recall" in failure for failure in result.failures)


async def test_gate_rejects_nested_quantifier():
    result = await verify_rule(WafRule(category=Category.SQLI, regex=r"(union\s*select)+"))
    assert not result.passed
    assert any("nested quantifier" in failure for failure in result.failures)


async def test_gate_rejects_overlong_and_invalid_patterns():
    long_rule = WafRule(category=Category.SQLI, regex="a" * 301)
    assert any("longer than" in failure for failure in (await verify_rule(long_rule)).failures)

    broken = WafRule(category=Category.SQLI, regex="(unclosed")
    assert any("invalid regex" in failure for failure in (await verify_rule(broken)).failures)


async def test_gate_refuses_regex_for_idor():
    result = await verify_rule(WafRule(category=Category.IDOR, regex="/pos/1[0-9]"))
    assert not result.passed
    assert any("cannot tell" in failure for failure in result.failures)


async def test_gate_refuses_traversal_regex_because_notes_contain_dotdot():
    rule = WafRule(category=Category.PATH_TRAVERSAL, regex=r"\.\./")
    result = await verify_rule(rule)
    assert not result.passed
    assert any("legitimate notes" in failure for failure in result.failures)


async def test_ssrf_rule_passes_gate():
    rule = WafRule(category=Category.SSRF, regex=r"(169\.254\.169\.254|0xa9fea9fe|2852039166)")
    result = await verify_rule(rule)
    assert result.passed, result.failures
    assert result.recall == 1.0 and result.false_positive == 0.0


# --- policy store / runtime --------------------------------------------------


async def test_in_memory_policy_store_versions():
    store = InMemoryPolicyStore()
    empty = await store.load("s1")
    assert empty.version == 0 and not empty.blocked_patterns

    first = await store.save(WafPolicy(session_id="s1", blocked_patterns=[]))
    assert first.version == 1
    second = await store.save(first)
    assert second.version == 2
    assert (await store.load("s1")).version == 2


async def test_redis_policy_store_roundtrip(redis):
    store = RedisPolicyStore(redis)
    rule = WafRule(category=Category.SQLI, regex=GOOD_SQLI)
    saved = await store.save(WafPolicy(session_id="s2", blocked_patterns=[rule]))
    loaded = await store.load("s2")
    assert saved.version == 1
    assert loaded.blocked_patterns[0].regex == GOOD_SQLI
    assert (await store.load("missing")).version == 0


class CountingStore(InMemoryPolicyStore):
    def __init__(self):
        super().__init__()
        self.loads = 0

    async def load(self, session_id: str) -> WafPolicy:
        self.loads += 1
        return await super().load(session_id)


async def test_runtime_caches_policy_between_requests():
    runtime = ArenaRuntime(cache_ttl=60)
    runtime.policy_store = CountingStore()
    await runtime.policy_for("s1")
    await runtime.policy_for("s1")
    assert runtime.policy_store.loads == 1

    runtime.forget("s1")
    await runtime.policy_for("s1")
    assert runtime.policy_store.loads == 2


class BrokenStore:
    async def load(self, session_id: str) -> WafPolicy:
        raise RuntimeError("redis down")

    async def save(self, policy: WafPolicy) -> WafPolicy:
        raise RuntimeError("redis down")


async def test_runtime_degrades_when_store_fails():
    runtime = ArenaRuntime()
    runtime.policy_store = BrokenStore()
    policy, rules = await runtime.policy_for("s1")
    assert runtime.degraded is True
    assert policy.session_id == "s1" and rules == []


# --- event bus ---------------------------------------------------------------


async def test_in_memory_event_bus_offsets_and_trimming():
    bus = InMemoryEventBus(max_events=2)
    for index in range(3):
        await bus.publish(ArenaEvent(session_id="s1", stage="s", kind="k", message=str(index)))
    assert [event.message for event in await bus.since("s1", 0)] == ["1", "2"]
    assert [event.message for event in await bus.since("s1", 1)] == ["2"]
    assert await bus.since("other", 0) == []


async def test_redis_event_bus_roundtrip(redis):
    bus = RedisEventBus(redis)
    await bus.publish(ArenaEvent(session_id="s3", stage="probe", kind="blocked", message="first"))
    await bus.publish(ArenaEvent(session_id="s3", stage="probe", kind="blocked", message="second"))
    events = await bus.since("s3", 1)
    assert [event.message for event in events] == ["second"]


# --- middleware --------------------------------------------------------------


@pytest_asyncio.fixture
async def gateway():
    state = ProcureState(canary="CANARY-WAF-0001")
    app = build_procure_app(state=state)
    runtime = ArenaRuntime(cache_ttl=60)
    runtime.policy_store = InMemoryPolicyStore()
    app.add_middleware(WafMiddleware, runtime=runtime)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://procure") as client:
        yield client, state, runtime
    await state.aclose()


async def test_gateway_allows_benign_traffic_without_rules(gateway):
    client, _state, _runtime = gateway
    response = await client.post("/login", json={"username": "alice", "password": "alice-pw"})
    assert response.status_code == 200
    assert "x-waf-degraded" not in response.headers


async def test_gateway_blocks_when_rule_is_active(gateway):
    client, _state, runtime = gateway
    rule = WafRule(category=Category.SQLI, regex=GOOD_SQLI)
    await runtime.policy_store.save(WafPolicy(session_id="lab-default", blocked_patterns=[rule]))
    runtime.forget("lab-default")

    denied = await client.get("/pos", params={"q": "x' UNION SELECT 1 --"})
    assert denied.status_code == 403
    body = denied.json()
    assert body["rule_id"] == rule.id and body["session_id"] == "lab-default"

    allowed = await client.get("/pos", params={"q": "O'Brien"})
    assert allowed.status_code == 401  # no token, but the gateway let it through


async def test_gateway_isolates_sessions(gateway):
    client, _state, runtime = gateway
    rule = WafRule(category=Category.SQLI, regex=GOOD_SQLI)
    await runtime.policy_store.save(WafPolicy(session_id="session-a", blocked_patterns=[rule]))
    runtime.forget("session-a")

    blocked = await client.get(
        "/pos", params={"q": "x' UNION SELECT 1"}, headers={"x-arena-session": "session-a"}
    )
    clean = await client.get(
        "/pos", params={"q": "x' UNION SELECT 1"}, headers={"x-arena-session": "session-b"}
    )
    assert blocked.status_code == 403
    assert clean.status_code == 401


async def test_gateway_revokes_token_by_jti(gateway):
    client, _state, runtime = gateway
    login = await client.post("/login", json={"username": "alice", "password": "alice-pw"})
    token = login.json()["token"]
    jti = read_jti(f"Bearer {token}")
    assert jti

    await runtime.policy_store.save(WafPolicy(session_id="lab-default", revoked_jti=[jti]))
    runtime.forget("lab-default")

    denied = await client.get("/pos", headers={"Authorization": f"Bearer {token}"})
    assert denied.status_code == 403
    assert denied.json()["rule_id"] == "TOKEN_REVOKED"


async def test_gateway_rejects_oversized_body(gateway):
    client, _state, runtime = gateway
    await runtime.policy_store.save(WafPolicy(session_id="lab-default", max_body_bytes=1024))
    runtime.forget("lab-default")
    payload = {"url": "http://hooks.internal/" + "a" * 1500}
    response = await client.post("/suppliers/1/callback-test", json=payload)
    assert response.status_code == 413


async def test_gateway_records_blocks_on_the_event_bus(gateway):
    client, _state, runtime = gateway
    bus = InMemoryEventBus()
    runtime.events = bus
    rule = WafRule(category=Category.SQLI, regex=GOOD_SQLI)
    await runtime.policy_store.save(WafPolicy(session_id="lab-default", blocked_patterns=[rule]))
    runtime.forget("lab-default")

    await client.get("/pos", params={"q": "x' UNION SELECT 1 --"})
    events = await bus.since("lab-default", 0)
    assert len(events) == 1
    assert events[0].kind == "blocked" and events[0].data["rule_id"] == rule.id


@pytest.mark.parametrize("header_value", [None, "Bearer", "Bearer not-a-token"])
def test_read_jti_ignores_unusable_headers(header_value):
    assert read_jti(header_value) is None

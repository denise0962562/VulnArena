"""WAF policy: what the gateway enforces, and where it lives.

A policy is small, hot-reloadable and versioned. Loading never raises into the
request path: Redis being down degrades the gateway, it does not break the lab.
"""

import re
import secrets
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis

from vulnarena.arena.corpus import Category
from vulnarena.arena.safe_regex import BoundedPattern

POLICY_KEY = "vulnarena:arena:policy:"
POLICY_TTL = 3600


class WafRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=lambda: f"R-{secrets.token_hex(4)}")
    category: Category
    regex: str = Field(min_length=1, max_length=1000)
    rationale: str = ""
    source: Literal["llm", "template", "manual"] = "template"


class WafPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    version: int = 0
    blocked_patterns: list[WafRule] = Field(default_factory=list)
    revoked_jti: list[str] = Field(default_factory=list)
    patch_switches: dict[str, bool] = Field(default_factory=dict)
    max_body_bytes: int = Field(default=65536, ge=1024, le=1048576)

    @classmethod
    def empty(cls, session_id: str) -> "WafPolicy":
        return cls(session_id=session_id)


class CompiledRule(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    rule: WafRule
    pattern: BoundedPattern


def compile_rules(policy: WafPolicy) -> list[CompiledRule]:
    compiled: list[CompiledRule] = []
    for rule in policy.blocked_patterns:
        try:
            compiled.append(CompiledRule(rule=rule, pattern=BoundedPattern(rule.regex)))
        except re.error:
            continue  # a bad rule is skipped, never fatal
    return compiled


class PolicyStore(Protocol):
    async def load(self, session_id: str) -> WafPolicy: ...

    async def save(self, policy: WafPolicy) -> WafPolicy: ...


def policy_key(session_id: str) -> str:
    return f"{POLICY_KEY}{session_id}"


class RedisPolicyStore:
    def __init__(self, redis: Redis, *, ttl: int = POLICY_TTL):
        self.redis = redis
        self.ttl = ttl

    async def load(self, session_id: str) -> WafPolicy:
        raw = await self.redis.get(policy_key(session_id))
        if raw is None:
            return WafPolicy.empty(session_id)
        try:
            return WafPolicy.model_validate_json(raw)
        except ValueError:
            return WafPolicy.empty(session_id)

    async def save(self, policy: WafPolicy) -> WafPolicy:
        current = await self.load(policy.session_id)
        updated = policy.model_copy(update={"version": current.version + 1})
        await self.redis.set(policy_key(updated.session_id), updated.model_dump_json(), ex=self.ttl)
        return updated


class InMemoryPolicyStore:
    def __init__(self) -> None:
        self.policies: dict[str, WafPolicy] = {}

    async def load(self, session_id: str) -> WafPolicy:
        return self.policies.get(session_id) or WafPolicy.empty(session_id)

    async def save(self, policy: WafPolicy) -> WafPolicy:
        current = await self.load(policy.session_id)
        updated = policy.model_copy(update={"version": current.version + 1})
        self.policies[updated.session_id] = updated
        return updated

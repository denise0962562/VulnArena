"""Shared execution context for the arena stages."""

import time
from dataclasses import dataclass, field

import httpx

from vulnarena.arena.contracts import BlockedBy, HttpCall
from vulnarena.arena.runtime import ArenaRuntime
from vulnarena.procure.app import ProcureState

WAF_DETAIL = "blocked by waf"


@dataclass
class CallResult:
    status: int
    text: str
    elapsed_ms: int
    rule_id: str | None = None
    blocked_by: BlockedBy = "none"


@dataclass
class ArenaContext:
    client: httpx.AsyncClient
    state: ProcureState
    runtime: ArenaRuntime
    session_id: str = "demo"
    base: str = ""
    llm: object | None = None
    tokens: dict[str, str] = field(default_factory=dict)

    @property
    def canary(self) -> str:
        return self.state.canary

    async def headers(self, actor: str) -> dict[str, str]:
        if actor == "anonymous":
            return {}
        if actor not in self.tokens:
            response = await self.client.post(
                f"{self.base}/login", json={"username": actor, "password": f"{actor}-pw"}
            )
            response.raise_for_status()
            self.tokens[actor] = response.json()["token"]
        return {"Authorization": f"Bearer {self.tokens[actor]}"}

    async def send(self, call: HttpCall) -> CallResult:
        headers = await self.headers(call.actor)
        # The gateway picks the policy by session; without this every request would
        # fall back to the default lab session and see an empty gateway.
        headers["x-arena-session"] = self.session_id
        url = f"{self.base}{call.path}"
        params = call.params or None
        started = time.perf_counter()
        if call.method == "GET":
            response = await self.client.get(url, params=params, headers=headers)
        else:
            response = await self.client.post(
                url, params=params, headers=headers, json=call.json_body
            )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return self._classify(response, elapsed_ms)

    @staticmethod
    def _classify(response: httpx.Response, elapsed_ms: int) -> CallResult:
        rule_id: str | None = None
        blocked_by: BlockedBy = "none"
        if response.status_code == 403:
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            detail = payload.get("detail", "") if isinstance(payload, dict) else ""
            rule_id = payload.get("rule_id") if isinstance(payload, dict) else None
            blocked_by = "waf" if WAF_DETAIL in str(detail) else "authorization"
        return CallResult(
            status=response.status_code,
            text=response.text,
            elapsed_ms=elapsed_ms,
            rule_id=rule_id if isinstance(rule_id, str) else None,
            blocked_by=blocked_by,
        )

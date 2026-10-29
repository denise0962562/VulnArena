"""Late-bound arena runtime shared by the portal gateway.

Stores are attached during application startup, so the gateway object can be
built before Redis exists and tests can run without it.
"""

import time
from collections.abc import Callable

from vulnarena.arena.events import ArenaEvent, ArenaEventBus
from vulnarena.arena.policy import CompiledRule, PolicyStore, WafPolicy, compile_rules


class ArenaRuntime:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic, cache_ttl: float = 1.0):
        self.policy_store: PolicyStore | None = None
        self.events: ArenaEventBus | None = None
        self.clock = clock
        self.cache_ttl = cache_ttl
        self.degraded = False
        self._cache: dict[str, tuple[WafPolicy, list[CompiledRule], float]] = {}

    async def policy_for(self, session_id: str) -> tuple[WafPolicy, list[CompiledRule]]:
        cached = self._cache.get(session_id)
        if cached is not None and self.clock() - cached[2] < self.cache_ttl:
            return cached[0], cached[1]
        if self.policy_store is None:
            policy = WafPolicy.empty(session_id)
            self.degraded = False
        else:
            try:
                policy = await self.policy_store.load(session_id)
                self.degraded = False
            except Exception:
                # A dead Redis degrades the gateway; it must never break the request path.
                self.degraded = True
                stale = cached[0] if cached is not None else WafPolicy.empty(session_id)
                return stale, compile_rules(stale)
        compiled = compile_rules(policy)
        self._cache[session_id] = (policy, compiled, self.clock())
        return policy, compiled

    def forget(self, session_id: str) -> None:
        """Drop the cached policy so the next request re-reads the store."""
        self._cache.pop(session_id, None)

    async def emit(self, event: ArenaEvent) -> None:
        if self.events is None:
            return
        try:
            await self.events.publish(event)
        except Exception:
            self.degraded = True

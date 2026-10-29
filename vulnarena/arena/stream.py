"""Server-sent events for live arena playback.

Kept out of the route so the relay itself is unit-testable: the HTTP layer only
wires a bus and a disconnect probe into this generator.
"""

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable

from vulnarena.arena.events import ArenaEventBus

POLL_SECONDS = 0.5


async def event_stream(
    bus: ArenaEventBus,
    session_id: str,
    *,
    offset: int = 0,
    is_disconnected: Callable[[], Awaitable[bool]] | None = None,
    poll: float = POLL_SECONDS,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> AsyncIterator[str]:
    while True:
        if is_disconnected is not None and await is_disconnected():
            return
        batch = await bus.since(session_id, offset)
        for event in batch:
            offset += 1
            yield f"id: {offset}\ndata: {event.model_dump_json()}\n\n"
        if not batch:
            yield ": keep-alive\n\n"
        await sleep(poll)

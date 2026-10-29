"""Arena event bus.

The protocol follows Kafka semantics (append-only log, monotonic offset, consumer
position) so the transport can be swapped later. The first implementation is a
Redis list because Redis is already part of the deployment.
"""

from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field
from redis.asyncio import Redis

from vulnarena.schemas import utcnow

PREFIX = "vulnarena:arena:events:"
MAX_EVENTS = 500
MAX_EVENT_BYTES = 8192


class ArenaEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    stage: str
    kind: str
    message: str
    created_at: Any = Field(default_factory=utcnow)
    data: dict[str, Any] = Field(default_factory=dict)


class ArenaEventBus(Protocol):
    async def publish(self, event: ArenaEvent) -> int: ...

    async def since(self, session_id: str, offset: int) -> list[ArenaEvent]: ...


def key(session_id: str) -> str:
    return f"{PREFIX}{session_id}"


def _dumps(event: ArenaEvent) -> str:
    payload = event.model_dump_json()
    if len(payload.encode()) > MAX_EVENT_BYTES:
        event = event.model_copy(update={"data": {"truncated": True}})
        payload = event.model_dump_json()
    return payload


class RedisEventBus:
    """Append-only list; offset is the list index, oldest entry dropped past MAX_EVENTS."""

    def __init__(self, redis: Redis, *, max_events: int = MAX_EVENTS):
        self.redis = redis
        self.max_events = max_events

    async def publish(self, event: ArenaEvent) -> int:
        stream = key(event.session_id)
        await self.redis.rpush(stream, _dumps(event))
        await self.redis.ltrim(stream, -self.max_events, -1)
        return int(await self.redis.llen(stream))

    async def since(self, session_id: str, offset: int) -> list[ArenaEvent]:
        raw = await self.redis.lrange(key(session_id), offset, -1)
        events: list[ArenaEvent] = []
        for item in raw:
            try:
                events.append(ArenaEvent.model_validate_json(item))
            except ValueError:
                continue  # a malformed entry must not stall the live feed
        return events


class InMemoryEventBus:
    def __init__(self, *, max_events: int = MAX_EVENTS):
        self.streams: dict[str, list[ArenaEvent]] = {}
        self.max_events = max_events

    async def publish(self, event: ArenaEvent) -> int:
        stream = self.streams.setdefault(event.session_id, [])
        stream.append(event)
        del stream[: max(0, len(stream) - self.max_events)]
        return len(stream)

    async def since(self, session_id: str, offset: int) -> list[ArenaEvent]:
        return list(self.streams.get(session_id, [])[offset:])

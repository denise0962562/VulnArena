"""SSE relay: the core watches the arena without importing its internals."""

import httpx

from vulnarena.arena import ArenaEvent, InMemoryEventBus
from vulnarena.arena.stream import event_stream
from vulnarena.config import Settings
from vulnarena.main import create_app


async def _no_sleep(_seconds: float) -> None:
    return None


async def _connected() -> bool:
    return False


def relay(bus, session_id, *, offset=0, disconnected=_connected):
    return event_stream(
        bus, session_id, offset=offset, is_disconnected=disconnected, sleep=_no_sleep
    )


async def test_relay_emits_events_with_increasing_ids():
    bus = InMemoryEventBus()
    for index in range(2):
        await bus.publish(
            ArenaEvent(session_id="s1", stage="PROBING", kind="blocked", message=f"e{index}")
        )
    stream = relay(bus, "s1")
    first = await anext(stream)
    second = await anext(stream)
    await stream.aclose()
    assert first.startswith("id: 1\ndata: ") and '"e0"' in first
    assert second.startswith("id: 2\ndata: ") and '"e1"' in second


async def test_relay_keeps_alive_when_idle():
    stream = relay(InMemoryEventBus(), "empty")
    chunk = await anext(stream)
    await stream.aclose()
    assert chunk == ": keep-alive\n\n"


async def test_relay_stops_when_client_disconnects():
    async def gone() -> bool:
        return True

    stream = relay(InMemoryEventBus(), "s1", disconnected=gone)
    assert await anext(stream, None) is None


async def test_relay_resumes_from_offset():
    bus = InMemoryEventBus()
    for index in range(3):
        await bus.publish(
            ArenaEvent(session_id="s2", stage="PATCHING", kind="info", message=f"e{index}")
        )
    stream = relay(bus, "s2", offset=2)
    chunk = await anext(stream)
    await stream.aclose()
    assert chunk.startswith("id: 3\n") and '"e2"' in chunk


async def test_stream_route_reports_503_without_a_bus():
    app = create_app(Settings(_env_file=None))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/arena/stream/s1")
    assert response.status_code == 503

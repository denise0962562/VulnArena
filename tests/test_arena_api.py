"""Arena control API and the drill page."""

import asyncio

import httpx
import pytest_asyncio

from vulnarena.arena import InMemoryEventBus, InMemoryPolicyStore
from vulnarena.arena.contracts import ArenaStatus
from vulnarena.config import Settings
from vulnarena.main import create_app

FINAL = {
    ArenaStatus.VERIFIED.value,
    ArenaStatus.REGRESSION_FAILED.value,
    ArenaStatus.BREACH_FAILED.value,
}


@pytest_asyncio.fixture
async def client():
    app = create_app(Settings(_env_file=None))
    app.state.runtime.policy_store = InMemoryPolicyStore()
    app.state.runtime.events = InMemoryEventBus()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http, app


async def wait_for(client: httpx.AsyncClient, session_id: str, limit_seconds: float = 5.0) -> dict:
    async with asyncio.timeout(limit_seconds):
        while True:
            response = await client.get(f"/api/arena/sessions/{session_id}")
            if response.status_code == 200 and response.json()["status"] in FINAL:
                return response.json()
            await asyncio.sleep(0.05)


async def test_start_runs_the_whole_drill(client):
    http, _app = client
    response = await http.post("/api/arena/start")
    assert response.status_code == 202
    session_id = response.json()["session_id"]
    assert len(session_id) == 8

    session = await wait_for(http, session_id)
    assert session["status"] == "VERIFIED"
    assert [trace["step"] for trace in session["traces"]] == [1, 2, 3, 4, 5, 6, 7, 8]
    assert session["patch"]["rule"] is not None
    assert session["regression"]["passed"] is True


async def test_sessions_are_listed_and_fetchable(client):
    http, _app = client
    session_id = (await http.post("/api/arena/start")).json()["session_id"]
    await wait_for(http, session_id)

    listing = (await http.get("/api/arena/sessions")).json()
    assert [item["session_id"] for item in listing] == [session_id]
    assert listing[0]["status"] == "VERIFIED"

    assert (await http.get("/api/arena/sessions/missing")).status_code == 404


async def test_drill_page_is_served(client):
    http, _app = client
    response = await http.get("/arena")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "AI Cyber Arena" in response.text
    assert "/api/arena/stream/" in response.text


async def test_each_drill_uses_its_own_session(client):
    http, _app = client
    first = (await http.post("/api/arena/start")).json()["session_id"]
    second = (await http.post("/api/arena/start")).json()["session_id"]
    assert first != second

    await wait_for(http, first)
    await wait_for(http, second)
    assert len((await http.get("/api/arena/sessions")).json()) == 2

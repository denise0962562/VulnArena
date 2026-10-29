"""Teaching layer: guide generation plus snapshot restore."""

import asyncio

import httpx
import pytest_asyncio

from vulnarena.arena import InMemoryEventBus, InMemoryPolicyStore
from vulnarena.config import Settings
from vulnarena.main import create_app

UNION = "' UNION ALL SELECT 1, value, 1, 'PAID', 'x' FROM secrets --"
FINAL = {"VERIFIED", "REGRESSION_FAILED", "BREACH_FAILED"}


@pytest_asyncio.fixture
async def api():
    app = create_app(Settings(_env_file=None))
    app.state.runtime.policy_store = InMemoryPolicyStore()
    app.state.runtime.events = InMemoryEventBus()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, app


async def wait_for(client: httpx.AsyncClient, session_id: str, limit: float = 5.0) -> dict:
    async with asyncio.timeout(limit):
        while True:
            response = await client.get(f"/api/arena/sessions/{session_id}")
            if response.status_code == 200 and response.json()["status"] in FINAL:
                return response.json()
            await asyncio.sleep(0.05)


async def drill(client: httpx.AsyncClient) -> str:
    session_id = (await client.post("/api/arena/start")).json()["session_id"]
    await wait_for(client, session_id)
    return session_id


async def portal_token(client: httpx.AsyncClient, session_id: str, user: str = "alice") -> dict:
    response = await client.post(
        "/api/procure/login",
        json={"username": user, "password": f"{user}-pw"},
        headers={"x-arena-session": session_id},
    )
    assert response.status_code == 200, response.text
    return {
        "Authorization": f"Bearer {response.json()['token']}",
        "x-arena-session": session_id,
    }


async def test_guide_contains_copyable_steps(api):
    client, _app = api
    session_id = await drill(client)

    steps = (await client.get(f"/api/arena/sessions/{session_id}/guide")).json()
    assert len(steps) == 10  # login + eight chain steps + verification
    assert steps[0]["title"].startswith("准备")
    assert "/login" in steps[0]["curl"]

    for step in steps:
        assert step["curl"].startswith("curl ")
        assert "/api/procure" in step["curl"]
        assert "Invoke-RestMethod" in step["powershell"]
        assert step["expected_marker"] and step["explanation"] and step["defense_note"]
        # 三级提示：任务和思路必须独立于命令，学习者先自己想
        assert step["brief"] and step["hint"]
        assert step["brief"] != step["curl"]

    breach = next(step for step in steps if "canary" in step["expected_marker"])
    assert breach["expected_status"] == 200
    assert steps[-1]["expected_status"] == 403


async def test_restore_then_patch_flips_the_same_request(api):
    client, _app = api
    session_id = await drill(client)
    headers = await portal_token(client, session_id)

    patched = await client.get(
        "/api/procure/pos", params={"q": UNION, "page_size": 50}, headers=headers
    )
    assert patched.status_code == 403  # after the drill the patch is active

    restored = await client.post(f"/api/arena/sessions/{session_id}/restore")
    assert restored.status_code == 200
    assert restored.json()["status"] == "BREACH_CONFIRMED"

    leaked = await client.get(
        "/api/procure/pos", params={"q": UNION, "page_size": 50}, headers=headers
    )
    assert leaked.status_code == 200 and "CANARY" in leaked.text

    reapplied = await client.post(f"/api/arena/sessions/{session_id}/apply-patch")
    assert reapplied.status_code == 200
    assert reapplied.json()["status"] == "VERIFIED"

    blocked = await client.get(
        "/api/procure/pos", params={"q": UNION, "page_size": 50}, headers=headers
    )
    assert blocked.status_code == 403 and "CANARY" not in blocked.text


async def test_restore_is_idempotent(api):
    client, _app = api
    session_id = await drill(client)
    for _ in range(2):
        assert (await client.post(f"/api/arena/sessions/{session_id}/restore")).status_code == 200
    for _ in range(2):
        response = await client.post(f"/api/arena/sessions/{session_id}/apply-patch")
        assert response.status_code == 200 and response.json()["status"] == "VERIFIED"


async def test_unknown_session_is_404(api):
    client, _app = api
    assert (await client.get("/api/arena/sessions/nope/guide")).status_code == 404
    assert (await client.post("/api/arena/sessions/nope/restore")).status_code == 404
    assert (await client.post("/api/arena/sessions/nope/apply-patch")).status_code == 404

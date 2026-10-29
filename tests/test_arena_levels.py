"""关卡：进度判定与解锁。"""

import httpx
import pytest_asyncio

from vulnarena.arena import ArenaRuntime, InMemoryEventBus, InMemoryPolicyStore, WafMiddleware
from vulnarena.arena.context import ArenaContext
from vulnarena.arena.levels import LEVELS, progress
from vulnarena.arena.pipeline import run_pipeline
from vulnarena.config import Settings
from vulnarena.main import create_app
from vulnarena.procure import ProcureState, build_procure_app


def test_empty_history_unlocks_only_the_first_level():
    items = progress([])
    assert [item.id for item in items] == [level.id for level in LEVELS]
    assert items[0].unlocked is True
    assert all(item.unlocked is False for item in items[1:])
    assert not any(item.solved for item in items)


@pytest_asyncio.fixture
async def arena():
    state = ProcureState(canary="CANARY-LV-0001")
    app = build_procure_app(state=state)
    runtime = ArenaRuntime(cache_ttl=0.0)
    runtime.policy_store = InMemoryPolicyStore()
    runtime.events = InMemoryEventBus()
    app.add_middleware(WafMiddleware, runtime=runtime)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://arena"
    ) as client:
        yield client, state, runtime


async def test_a_drill_advances_the_levels(arena):
    client, state, runtime = arena
    ctx = ArenaContext(client=client, state=state, runtime=runtime, session_id="lv1")
    session = await run_pipeline(ctx)

    items = progress([session])
    solved = [item.id for item in items if item.solved]
    assert "auth-bypass" in solved
    assert "broken-access" in solved
    assert "logic-flaw" in solved
    assert "exposure" in solved

    # 解锁是链式的：前一层通过才解锁下一层
    first_locked = next((item for item in items if not item.solved), None)
    if first_locked is not None:
        assert first_locked.unlocked is True


async def test_levels_endpoint_lists_all_levels():
    app = create_app(Settings(_env_file=None))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as client:
        response = await client.get("/api/arena/levels")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 6  # 5 层 + 神秘关卡
    assert payload[0]["points"] == 10 and payload[4]["points"] == 50
    assert payload[-1]["id"] == "mystery"
    assert all("check" not in item for item in payload)  # 判据说明不外泄给前端


async def test_mystery_needs_a_clean_run(arena):
    """神秘关卡：用过提示就不算通过。"""
    client, state, runtime = arena
    ctx = ArenaContext(client=client, state=state, runtime=runtime, session_id="m1")
    session = await run_pipeline(ctx)
    session.level_id = "mystery"

    session.hint_uses = 0
    assert next(item for item in progress([session]) if item.id == "mystery").solved

    session.hint_uses = 2
    assert not next(item for item in progress([session]) if item.id == "mystery").solved

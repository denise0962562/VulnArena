import os
from uuid import uuid4

import pytest
from redis.asyncio import Redis

from vulnarena.main import create_app
from vulnarena.nvd import NVDClient, RateLimiter
from vulnarena.schemas import TaskStatus
from vulnarena.state import TaskStore


@pytest.mark.redis
async def test_real_redis_atomic_lifecycle(settings, monkeypatch):
    url = os.getenv("TEST_REDIS_URL")
    if not url:
        pytest.skip("TEST_REDIS_URL not set; real Redis integration not executed")
    # Unique namespace; never FLUSHDB or delete another application's data.
    import vulnarena.state as module

    namespace = f"vulnarena:test:{uuid4()}"
    monkeypatch.setattr(module, "LOCK", namespace + ":active")
    monkeypatch.setattr(TaskStore, "key", staticmethod(lambda task_id: namespace + ":" + task_id))
    redis = Redis.from_url(url, decode_responses=True)
    store = TaskStore(redis, settings)
    task_ids = []
    try:
        assert await redis.ping()
        task = await store.create()
        task_ids.append(task.id)
        assert (await store.get(task.id)).status == TaskStatus.PENDING
        task.status = TaskStatus.RUNNING
        await store.save(task)
        assert (await store.get(task.id)).status == TaskStatus.RUNNING
        task.status = TaskStatus.SUCCESS
        await store.save(task)
        await store.release(task.id)
        assert (await store.get(task.id)).status == TaskStatus.SUCCESS
        task = await store.create()
        task_ids.append(task.id)
        await redis.delete(module.LOCK)
        assert (await store.get(task.id)).status == TaskStatus.FAILED
    finally:
        await redis.delete(module.LOCK, *(store.key(task_id) for task_id in task_ids))
        await redis.aclose()


@pytest.mark.redis
async def test_real_redis_api_loop(database_settings, envelope, clock, monkeypatch):
    settings = database_settings
    import httpx

    import vulnarena.state as module

    url = os.getenv("TEST_REDIS_URL")
    if not url:
        pytest.skip("TEST_REDIS_URL not set; real Redis integration not executed")
    namespace = f"vulnarena:test:{uuid4()}"
    monkeypatch.setattr(module, "LOCK", namespace + ":active")
    monkeypatch.setattr(TaskStore, "key", staticmethod(lambda task_id: namespace + ":" + task_id))
    redis = Redis.from_url(url, decode_responses=True)
    nvd = NVDClient(
        settings,
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=envelope)),
        limiter=RateLimiter(6.1, clock=clock.time, sleep=clock.sleep),
    )
    app = create_app(settings, redis=redis, nvd=nvd)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="http://test"
        ) as c:
            response = await c.post("/api/sync", json={"keyword": "example"})
            assert response.status_code == 202
            task_id = response.json()["id"]
            assert (await c.get("/api/tasks/" + task_id)).json()["status"] == "SUCCESS"
            assert (await c.get("/api/vulnerabilities/CVE-2024-1234")).json()["cvss_score"] == 9.8
            await redis.delete(module.LOCK, store_key := TaskStore.key(task_id))
            assert await redis.exists(store_key) == 0

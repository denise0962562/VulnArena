import asyncio

import pytest

from vulnarena.schemas import TaskStatus
from vulnarena.state import LOCK, LeaseLost, TaskBusy, TaskStore


async def test_state_transitions_and_exclusion(redis, settings):
    store = TaskStore(redis, settings)
    task = await store.create()
    assert (await store.get(task.id)).status == TaskStatus.PENDING
    assert 0 < await redis.ttl(store.key(task.id)) <= settings.task_ttl
    with pytest.raises(TaskBusy):
        await store.create()
    task.status = TaskStatus.RUNNING
    await store.save(task)
    assert (await store.get(task.id)).status == TaskStatus.RUNNING
    task.status = TaskStatus.SUCCESS
    await store.save(task)
    await store.release(task.id)
    assert (await store.get(task.id)).status == TaskStatus.SUCCESS
    assert await store.get("missing") is None


@pytest.mark.parametrize("status", [TaskStatus.PENDING, TaskStatus.RUNNING])
async def test_recovery_and_owner_protection(redis, settings, status):
    store = TaskStore(redis, settings)
    old = await store.create()
    old.status = status
    await store.save(old)
    # Simulate lease expiration/process crash without real-time sleeping.
    await redis.delete(LOCK)
    new = await store.create()
    assert (await store.get(old.id)).status == TaskStatus.FAILED
    assert "interrupted" in (await store.get(old.id)).error
    with pytest.raises(LeaseLost):
        await store.save(old)
    await store.release(old.id)
    assert await redis.get(LOCK) == new.id
    await store.release(new.id)


async def test_concurrent_create(redis, settings):
    store = TaskStore(redis, settings)
    results = await asyncio.gather(*(store.create() for _ in range(8)), return_exceptions=True)
    assert sum(isinstance(result, TaskBusy) for result in results) == 7

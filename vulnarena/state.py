"""Redis task leases. Atomic Lua operations never overwrite a different owner's lease."""

import asyncio
from uuid import uuid4

from redis.asyncio import Redis

from vulnarena.config import Settings
from vulnarena.schemas import SyncTask, TaskStatus, utcnow

LOCK = "vulnarena:sync:active"
UPDATE = """
if redis.call('get', KEYS[1]) ~= ARGV[1] then return 0 end
redis.call('set', KEYS[2], ARGV[2], 'EX', ARGV[3])
redis.call('expire', KEYS[1], ARGV[4])
return 1
"""
RELEASE = """
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) end
return 0
"""
RECOVER = """
if redis.call('get', KEYS[1]) == ARGV[1] then return 0 end
if redis.call('get', KEYS[2]) ~= ARGV[2] then return 0 end
redis.call('set', KEYS[2], ARGV[3], 'EX', ARGV[4])
return 1
"""
ACQUIRE = """
if not redis.call('set', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[3]) then return 0 end
redis.call('set', KEYS[2], ARGV[2], 'EX', ARGV[4])
return 1
"""


class TaskBusy(Exception):
    pass


class LeaseLost(Exception):
    pass


class TaskStore:
    def __init__(self, redis: Redis, settings: Settings):
        self.redis, self.settings = redis, settings

    @staticmethod
    def key(task_id: str) -> str:
        return f"vulnarena:task:{task_id}"

    async def create(self) -> SyncTask:
        task = SyncTask(id=str(uuid4()))
        ok = await self.redis.eval(
            ACQUIRE,
            2,
            LOCK,
            self.key(task.id),
            task.id,
            task.model_dump_json(),
            self.settings.lease_seconds,
            self.settings.task_ttl,
        )
        if not ok:
            raise TaskBusy("another synchronization is pending or running")
        return task

    async def save(self, task: SyncTask) -> None:
        task.updated_at = utcnow()
        ok = await self.redis.eval(
            UPDATE,
            2,
            LOCK,
            self.key(task.id),
            task.id,
            task.model_dump_json(),
            self.settings.task_ttl,
            self.settings.lease_seconds,
        )
        if not ok:
            raise LeaseLost("synchronization lease expired or changed owner")

    async def release(self, task_id: str) -> None:
        await self.redis.eval(RELEASE, 1, LOCK, task_id)

    async def get(self, task_id: str) -> SyncTask | None:
        raw = await self.redis.get(self.key(task_id))
        if raw is None:
            return None
        task = SyncTask.model_validate_json(raw)
        if task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
            task.status = TaskStatus.FAILED
            task.error = "process interrupted or lease expired; submit a new idempotent sync"
            task.updated_at = utcnow()
            recovered = await self.redis.eval(
                RECOVER,
                2,
                LOCK,
                self.key(task_id),
                task_id,
                raw,
                task.model_dump_json(),
                self.settings.task_ttl,
            )
            if not recovered:
                current = await self.redis.get(self.key(task_id))
                return SyncTask.model_validate_json(current) if current else None
        return task

    async def heartbeat(self, task: SyncTask) -> None:
        while True:
            await asyncio.sleep(self.settings.lease_seconds / 3)
            await self.save(task)

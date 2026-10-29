import asyncio
from unittest.mock import AsyncMock

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.exc import OperationalError

from vulnarena.nvd import NVDParseError, parse_cve
from vulnarena.schemas import SyncRequest, TaskStatus
from vulnarena.state import LOCK


async def test_complete_loop_persistence_filters_and_cache(api, raw_cve, monkeypatch):
    client, app = api
    assert (await client.get("/health")).json() == {"status": "ok"}
    assert (await client.get("/api/vulnerabilities")).json()["total"] == 0
    response = await client.post("/api/sync", json={"cve_id": raw_cve["id"]})
    assert response.status_code == 202 and response.json()["status"] == "PENDING"
    task = (await client.get("/api/tasks/" + response.json()["id"])).json()
    assert task["status"] == "SUCCESS" and task["processed"] == task["changed"] == 1
    url = "/api/vulnerabilities?severity=CRITICAL&keyword=Example&status=Analyzed&page_size=1"
    result = (await client.get(url)).json()
    assert result["total"] == 1 and result["items"][0]["cvss_score"] == 9.8
    assert result["items"][0]["published_at"].endswith("Z")
    # Prove the second read is served by cache.
    original = app.state.db.list_from_session
    monkeypatch.setattr(app.state.db, "list_from_session", AsyncMock(side_effect=AssertionError))
    assert (await client.get(url)).json() == result
    monkeypatch.setattr(app.state.db, "list_from_session", original)
    assert (await client.get("/api/vulnerabilities")).json()["total"] == 1
    assert (await client.get("/api/vulnerabilities?page=2&page_size=1")).json()["items"] == []
    assert (await client.get("/api/vulnerabilities?severity=LOW")).json()["total"] == 0
    by_id = (await client.get("/api/vulnerabilities?keyword=CVE-2024-1234")).json()
    assert by_id["total"] == 1 and by_id["items"][0]["cve_id"] == raw_cve["id"]
    detail = await client.get("/api/vulnerabilities/" + raw_cve["id"])
    assert detail.json()["raw"]["futureField"]["preserve"] is True


async def test_validation_and_not_found(api):
    client, _ = api
    for url in [
        "/api/vulnerabilities?page_size=101",
        "/api/vulnerabilities?page=0",
        "/api/vulnerabilities?severity=INVALID",
    ]:
        assert (await client.get(url)).status_code == 422
    assert (await client.post("/api/sync", json={})).status_code == 422
    assert (await client.get("/api/tasks/missing")).status_code == 404
    assert (await client.get("/api/vulnerabilities/CVE-1999-9999")).status_code == 404


async def test_duplicate_running_sync(api):
    client, app = api
    pending = await app.state.store.create()
    response = await client.post("/api/sync", json={"keyword": "example"})
    assert response.status_code == 409
    await app.state.store.release(pending.id)


@pytest.mark.parametrize(
    "failure", [NVDParseError("bad response"), OperationalError("sql", {}, Exception("db"))]
)
async def test_task_exception_and_lock_cleanup(api, monkeypatch, failure):
    client, app = api
    target = app.state.db if isinstance(failure, OperationalError) else app.state.sync.nvd
    method = "upsert" if isinstance(failure, OperationalError) else "fetch"
    monkeypatch.setattr(target, method, AsyncMock(side_effect=failure))
    response = await client.post("/api/sync", json={"keyword": "example"})
    task = (await client.get("/api/tasks/" + response.json()["id"])).json()
    assert task["status"] == "FAILED" and type(failure).__name__ in task["error"]
    assert await app.state.store.redis.get(LOCK) is None
    assert (await client.get("/api/vulnerabilities")).json()["total"] == 0


async def test_cache_revision_after_failed_cache_write(api, raw_cve, monkeypatch):
    client, app = api
    assert (await client.get("/api/vulnerabilities")).json()["total"] == 0
    await app.state.db.upsert([parse_cve(raw_cve)])
    monkeypatch.setattr(app.state.store.redis, "set", AsyncMock(side_effect=RedisConnectionError))
    result = await client.get("/api/vulnerabilities")
    assert result.status_code == 200 and result.json()["total"] == 1
    monkeypatch.setattr(app.state.store.redis, "get", AsyncMock(side_effect=RedisConnectionError))
    assert (await client.get("/api/vulnerabilities")).json()["total"] == 1
    assert (await client.get("/api/vulnerabilities/" + raw_cve["id"])).status_code == 200


async def test_invalid_cache_and_service_unavailable(api, monkeypatch):
    client, app = api
    monkeypatch.setattr(app.state.store.redis, "get", AsyncMock(return_value="invalid json"))
    assert (await client.get("/api/vulnerabilities")).json()["total"] == 0
    monkeypatch.setattr(app.state.store.redis, "eval", AsyncMock(side_effect=RedisConnectionError))
    assert (await client.post("/api/sync", json={"keyword": "example"})).status_code == 503
    monkeypatch.setattr(app.state.db, "get", AsyncMock(side_effect=OperationalError("", {}, None)))
    assert (await client.get("/api/vulnerabilities/CVE-2024-1234")).status_code == 503


async def test_timeout_and_heartbeat_failure(api, monkeypatch):
    _, app = api
    service = app.state.sync
    service.settings.task_timeout = 0.01

    async def slow(*args):
        await asyncio.sleep(10)

    monkeypatch.setattr(service.nvd, "fetch", slow)
    task = await app.state.store.create()
    await service.run(task, SyncRequest(keyword="example"))
    assert (await app.state.store.get(task.id)).status == TaskStatus.FAILED
    assert "TimeoutError" in (await app.state.store.get(task.id)).error
    monkeypatch.setattr(app.state.store, "heartbeat", AsyncMock(side_effect=RedisConnectionError))
    task = await app.state.store.create()
    await service.run(task, SyncRequest(keyword="example"))
    assert (await app.state.store.get(task.id)).status == TaskStatus.FAILED
    assert await app.state.db.get("CVE-2024-1234") is None


async def test_cancellation(api, monkeypatch):
    _, app = api
    ready = asyncio.Event()

    async def slow(*args):
        ready.set()
        await asyncio.sleep(10)

    monkeypatch.setattr(app.state.sync.nvd, "fetch", slow)
    task = await app.state.store.create()
    running = asyncio.create_task(app.state.sync.run(task, SyncRequest(keyword="example")))
    await ready.wait()
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert (await app.state.store.get(task.id)).status == TaskStatus.FAILED
    assert await app.state.store.redis.get(LOCK) is None

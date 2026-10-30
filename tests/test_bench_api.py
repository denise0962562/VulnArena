"""P5：自博弈接口与总控台卡片。"""

import httpx
import pytest

from vulnarena.config import Settings
from vulnarena.main import create_app


@pytest.fixture
async def client():
    app = create_app(Settings(_env_file=None))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as http_client:
        yield http_client


async def test_selfplay_endpoint_runs_rounds(client):
    response = await client.post("/api/bench/selfplay?rounds=2")
    assert response.status_code == 200
    payload = response.json()
    assert payload["category"] == "sqli"
    assert len(payload["rounds"]) == 2

    first, second = payload["rounds"]
    assert first["recall"] < 1.0, "红队第一轮就该把模板规则打出缺口"
    assert second["corpus_attacks"] >= first["corpus_attacks"]


async def test_latest_result_is_cached(client):
    empty = await client.get("/api/bench/selfplay")
    assert empty.json()["rounds"] == []

    await client.post("/api/bench/selfplay?rounds=1")
    cached = await client.get("/api/bench/selfplay")
    assert len(cached.json()["rounds"]) == 1


async def test_lab_shows_the_curve_card(client):
    response = await client.get("/lab")
    assert response.status_code == 200
    assert "自博弈曲线" in response.text
    assert "api/bench/selfplay" in response.text

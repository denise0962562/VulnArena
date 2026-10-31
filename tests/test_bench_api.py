"""P5：自博弈接口与总控台卡片。"""

from html.parser import HTMLParser

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
    assert 'method="post" action="/lab/selfplay"' in response.text
    assert 'id="play" type="submit"' in response.text
    assert "还没跑过" in response.text
    assert "api/bench/selfplay" not in response.text
    assert response.headers["cache-control"] == "no-store, must-revalidate"


class LabMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.in_script = False
        self.round_rows = 0
        self.in_rounds = False
        self.points = ""
        self.dots = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self.scripts.append("")
            self.in_script = True
        if tag == "tbody" and attrs.get("id") == "rounds":
            self.in_rounds = True
        if tag == "tr" and self.in_rounds:
            self.round_rows += 1
        if tag == "polyline":
            self.points = attrs["points"]
        if tag == "circle":
            self.dots += 1

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False
        if tag == "tbody":
            self.in_rounds = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts[-1] += data


async def test_lab_form_redirects_and_renders_saved_results_without_js(client):
    response = await client.post("/lab/selfplay", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/lab"
    saved = (await client.get("/api/bench/selfplay")).json()
    assert len(saved["rounds"]) == 3
    for _ in range(2):
        page = await client.get(response.headers["location"])
        parsed = LabMarkup()
        parsed.feed(page.text)
        assert parsed.round_rows == parsed.dots == 3
        assert len(parsed.points.split()) == 3
        assert len(parsed.scripts) == 1 and not parsed.in_script
        assert "<script>" not in parsed.scripts[0]
        assert "getElementById('start')" in parsed.scripts[0]
        assert "getElementById('play')" not in parsed.scripts[0]
        assert "已完成 3 回合" in page.text and "还没跑过" not in page.text
        assert (await client.get("/api/bench/selfplay")).json() == saved
        expected_y = 24 + 152 * (1 - saved["rounds"][0]["recall"])
        assert parsed.points.split()[0] == f"24.00,{expected_y:.2f}"


async def test_api_result_is_also_rendered_on_lab(client):
    await client.post("/api/bench/selfplay?rounds=1")
    parsed = LabMarkup()
    parsed.feed((await client.get("/lab")).text)
    assert parsed.round_rows == parsed.dots == 1
    assert parsed.points.startswith("320.00,")


async def test_lab_form_failure_is_visible_and_keeps_last_result(client, monkeypatch):
    await client.post("/api/bench/selfplay?rounds=1")
    saved = (await client.get("/api/bench/selfplay")).json()

    async def fail(*args, **kwargs):
        raise RuntimeError("fixture internal details")

    monkeypatch.setattr("vulnarena.main.run_selfplay", fail)
    response = await client.post("/lab/selfplay")
    assert response.status_code == 503
    assert 'role="alert"' in response.text and "自博弈运行失败" in response.text
    assert "fixture internal details" not in response.text
    assert (await client.get("/api/bench/selfplay")).json() == saved

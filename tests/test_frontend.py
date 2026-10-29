import httpx

import vulnarena.main as module


async def test_static_frontend_and_api_route_precedence(tmp_path, settings, monkeypatch):
    web = tmp_path / "web"
    (web / "assets").mkdir(parents=True)
    (web / "index.html").write_text("<html><title>VulnArena</title></html>", encoding="utf-8")
    (web / "assets" / "app.js").write_text("console.log('frontend')", encoding="utf-8")
    monkeypatch.setattr(module, "WEB_DIR", web)
    app = module.create_app(settings)
    # These static/validation routes do not access lifespan-managed DB/Redis resources.
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as c:
        page = await c.get("/")
        assert page.status_code == 200 and "text/html" in page.headers["content-type"]
        assert "VulnArena" in page.text
        assert (await c.get("/assets/app.js")).text == "console.log('frontend')"
        assert (await c.post("/api/sync", json={})).status_code == 422
        assert (await c.get("/api/missing")).status_code == 404
        assert (await c.get("/openapi.json")).json()["info"]["title"] == "VulnArena"


async def test_missing_frontend_has_clear_diagnostic(tmp_path, settings, monkeypatch):
    monkeypatch.setattr(module, "WEB_DIR", tmp_path / "not-built")
    app = module.create_app(settings)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as c:
        response = await c.get("/")
        assert response.status_code == 503
        assert "npm run build" in response.json()["detail"]

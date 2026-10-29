"""网页前端（服务端渲染 + Cookie 会话）与告警封禁。"""

import httpx
import pytest_asyncio

from vulnarena.procure import DefectFlag, ProcureState, build_procure_app


@pytest_asyncio.fixture
async def ui():
    state = ProcureState(canary="CANARY-UI-0001")
    app = build_procure_app(state=state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://ui", follow_redirects=False
    ) as client:
        yield client, state
    await state.aclose()


async def login(client, user: str) -> dict[str, str]:
    client.cookies.clear()  # 一个浏览器只能有一个会话
    response = await client.post("/ui/login", data={"username": user, "password": f"{user}-pw"})
    assert response.status_code == 303, response.text
    return {"procure_session": response.cookies["procure_session"]}


async def test_login_page_and_successful_login(ui):
    client, _state = ui
    page = await client.get("/ui/login")
    assert page.status_code == 200 and "员工登录" in page.text

    bad = await client.post("/ui/login", data={"username": "alice", "password": "nope"})
    assert bad.status_code == 200 and "工号或密码错误" in bad.text

    jar = await login(client, "alice")
    orders = await client.get("/ui/pos", cookies=jar)
    assert orders.status_code == 200 and "单号" in orders.text
    assert "设备" in orders.text


async def test_pages_require_a_session(ui):
    client, _state = ui
    response = await client.get("/ui/pos")
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/login"


async def test_detail_page_respects_ownership(ui):
    client, state = ui
    bob = await login(client, "bob")

    denied = await client.get("/ui/pos/4", cookies=bob)
    assert denied.status_code == 403  # 4 号单子是 alice 的

    state.set_flag(DefectFlag.IDOR_PO_DETAIL, True)
    leaked = await client.get("/ui/pos/4", cookies=bob)
    assert leaked.status_code == 200 and "预算科目" in leaked.text


async def test_approval_form_drives_the_state_machine(ui):
    client, _state = ui
    alice = await login(client, "alice")
    mike = await login(client, "mike")

    created = await client.post(
        "/ui/pos", data={"title": "x", "amount": "1000", "supplier_id": "1"}, cookies=alice
    )
    assert created.status_code in (303, 405)  # 页面没有建单表单，接口仍可直连

    submitted = await client.post(
        "/ui/pos/5/approve", data={"decision": "reject", "comment": "预算不足"}, cookies=mike
    )
    assert submitted.status_code == 303
    detail = await client.get("/ui/pos/5", cookies=mike)
    assert "REJECTED" in detail.text and "预算不足" in detail.text


async def test_attachment_page_and_traversal(ui):
    client, state = ui
    alice = await login(client, "alice")

    normal = await client.get("/ui/attachments", params={"name": "README.txt"}, cookies=alice)
    assert normal.status_code == 200 and "uploaded attachments" in normal.text

    escape = await client.get(
        "/ui/attachments", params={"name": "../etc/procure/bank_gateway_key"}, cookies=alice
    )
    assert escape.status_code == 403

    state.set_flag(DefectFlag.PATH_TRAVERSAL, True)
    leaked = await client.get(
        "/ui/attachments", params={"name": "../etc/procure/bank_gateway_key"}, cookies=alice
    )
    assert leaked.status_code == 200 and "CANARY-UI-0001" in leaked.text


async def test_repeated_denials_lead_to_a_ban(ui):
    client, state = ui
    bob = await login(client, "bob")

    codes = []
    for _ in range(6):
        response = await client.get("/ui/pos/4", cookies=bob)
        codes.append(response.status_code)

    assert codes[:5] == [403] * 5
    assert codes[5] == 429
    assert state.alert_snapshot()["active_bans"]

    # 别的账号不受影响
    alice = await login(client, "alice")
    assert (await client.get("/ui/pos/2", cookies=alice)).status_code == 200


async def test_alerts_are_auditor_only(ui):
    client, _state = ui
    guard = await login(client, "guard")
    alice = await login(client, "alice")

    snapshot = await client.get("/alerts", cookies=guard)
    assert snapshot.status_code == 200
    assert snapshot.json()["threshold"] == 5

    assert (await client.get("/alerts", cookies=alice)).status_code == 403


async def test_logout_clears_the_cookie(ui):
    client, _state = ui
    jar = await login(client, "alice")
    response = await client.get("/ui/logout", cookies=jar)
    assert response.status_code == 303 and response.headers["location"] == "/ui/login"

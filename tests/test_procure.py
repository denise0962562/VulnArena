"""采购审批域：状态机、越权、批量赋值、路径穿越、SSRF 与目标判定。"""

import httpx
import pytest_asyncio

from vulnarena.procure import DefectFlag, ProcureState, build_procure_app

CANARY = "CANARY-PROCURE-0001"


@pytest_asyncio.fixture
async def procure():
    state = ProcureState(canary=CANARY)
    app = build_procure_app(state=state)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://procure") as client:
        yield client, state
    await state.aclose()


async def bearer(client, user: str) -> dict[str, str]:
    response = await client.post("/login", json={"username": user, "password": f"{user}-pw"})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def run(**flags: str) -> dict[str, str]:
    return {"x-arena-defect": ",".join(f"{key}={value}" for key, value in flags.items())}


async def test_login_and_list_are_scoped(procure):
    client, _state = procure
    alice = await bearer(client, "alice")
    listing = await client.get("/pos", headers=alice)
    assert listing.status_code == 200
    assert listing.json()["total"] == 8
    assert CANARY not in listing.text

    bad = await client.post("/login", json={"username": "alice", "password": "nope"})
    assert bad.status_code == 401
    assert (await client.get("/pos")).status_code == 401


async def test_login_bypass_flag(procure):
    client, _state = procure
    body = {"username": "admin' --", "password": "whatever"}
    assert (await client.post("/login", json=body)).status_code == 401

    response = await client.post("/login", json=body, headers=run(sqli_login_bypass="on"))
    assert response.status_code == 200
    assert response.json()["role"] == "cfo"


async def test_search_sqli_and_benign_keywords(procure):
    client, _state = procure
    alice = await bearer(client, "alice")
    for keyword in ["设备", "O'Brien", "100%"]:
        assert (await client.get("/pos", params={"q": keyword}, headers=alice)).status_code == 200

    payload = "x%' UNION SELECT 1,value,1,'PAID','a' FROM secrets --"
    clean = await client.get("/pos", params={"q": payload}, headers=alice)
    assert clean.status_code == 200 and CANARY not in clean.text

    leaked = await client.get(
        "/pos", params={"q": payload}, headers={**alice, **run(sqli_search="on")}
    )
    assert leaked.status_code == 200


async def test_idor_detail_flag(procure):
    client, _state = procure
    bob = await bearer(client, "bob")
    assert (await client.get("/pos/1", headers=bob)).status_code == 403

    leaked = await client.get("/pos/1", headers={**bob, **run(idor_po_detail="on")})
    assert leaked.status_code == 200 and leaked.json()["requester"] == "mike"


async def test_approval_state_machine_is_enforced_by_default(procure):
    client, _state = procure
    alice = await bearer(client, "alice")
    mike = await bearer(client, "mike")
    fiona = await bearer(client, "fiona")

    created = await client.post(
        "/pos", json={"title": "测试采购", "amount": 20_000, "supplier_id": 1}, headers=alice
    )
    po = created.json()["id"]
    assert created.json()["status"] == "MANAGER_REVIEW"

    assert (
        await client.post(f"/pos/{po}/approve", json={"decision": "approve"}, headers=fiona)
    ).status_code == 403  # 财务不能替主管审

    approved = await client.post(
        f"/pos/{po}/approve", json={"decision": "approve", "comment": "ok"}, headers=mike
    )
    assert approved.status_code == 200 and approved.json()["status"] == "APPROVED"

    paid = await client.post(f"/pos/{po}/pay", headers=fiona)
    assert paid.status_code == 200 and paid.json()["status"] == "PAID"


async def test_state_skip_and_mass_assignment_together_win_the_mission(procure):
    client, _state = procure
    alice = await bearer(client, "alice")
    fiona = await bearer(client, "fiona")
    admin = await bearer(client, "admin")

    assert (await client.get("/mission", headers=admin)).json()["achieved"] is False

    created = await client.post(
        "/pos", json={"title": "紧急安全采购", "amount": 900_000, "supplier_id": 1}, headers=alice
    )
    po = created.json()["id"]

    flags = run(state_skip="on", mass_assignment="on")
    approved = await client.post(
        f"/pos/{po}/approve",
        json={"decision": "approve", "approver": "admin"},
        headers={**alice, **flags},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "APPROVED"
    assert len(approved.json()["approvals"]) == 1
    assert approved.json()["approvals"][0]["actor"] == "admin"  # 身份由请求体决定

    paid = await client.post(f"/pos/{po}/pay", headers=fiona)
    assert paid.json()["status"] == "PAID"

    mission = (await client.get("/mission", headers=admin)).json()
    assert mission["achieved"] is True and mission["po_id"] == po


async def test_payment_requires_approved_state(procure):
    client, _state = procure
    fiona = await bearer(client, "fiona")
    response = await client.post("/pos/4/pay", headers=fiona)
    assert response.status_code == 409


async def test_attachment_traversal(procure):
    client, state = procure
    alice = await bearer(client, "alice")
    payload = {"name": "note.txt", "content": "hello"}
    assert (await client.post("/attachments", json=payload, headers=alice)).status_code == 200
    assert (
        await client.get("/attachments", params={"name": "note.txt"}, headers=alice)
    ).text == "hello"

    escape = "../etc/procure/bank_gateway_key"
    assert (
        await client.get("/attachments", params={"name": escape}, headers=alice)
    ).status_code == 403
    leaked = await client.get(
        "/attachments", params={"name": escape}, headers={**alice, **run(path_traversal="on")}
    )
    assert leaked.status_code == 200 and CANARY in leaked.text


async def test_supplier_callback_ssrf(procure):
    client, _state = procure
    alice = await bearer(client, "alice")
    payload = {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
    assert (
        await client.post("/suppliers/1/callback-test", json=payload, headers=alice)
    ).status_code == 403

    leaked = await client.post(
        "/suppliers/1/callback-test",
        json=payload,
        headers={**alice, **run(ssrf_supplier="on")},
    )
    assert leaked.status_code == 200 and CANARY in leaked.json()["preview"]


async def test_audit_is_auditor_only(procure):
    client, _state = procure
    guard = await bearer(client, "guard")
    alice = await bearer(client, "alice")
    await client.get("/pos", headers=guard)

    entries = (await client.get("/audit", headers=guard)).json()
    assert entries and any(item["path"] == "/pos" for item in entries)
    assert (await client.get("/audit", headers=alice)).status_code == 403


async def test_every_defect_is_off_by_default(procure):
    _client, state = procure
    assert not any(state.flags.values())
    assert set(state.flags) == set(DefectFlag)

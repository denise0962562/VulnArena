"""支付与改密码：三个新缺陷的正反两面对照。"""

import httpx
import pytest
import pytest_asyncio

from vulnarena.procure import ProcureState, build_procure_app
from vulnarena.procure.models import DefectFlag

CANARY = "CANARY-PAY-0001"


@pytest_asyncio.fixture
async def env():
    state = ProcureState(canary=CANARY)
    app = build_procure_app(state=state)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://procure"
    ) as client:

        async def login(user: str) -> dict[str, str]:
            response = await client.post(
                "/login", json={"username": user, "password": f"{user}-pw"}
            )
            assert response.status_code == 200, response.text
            return {"Authorization": f"Bearer {response.json()['token']}"}

        yield client, state, login
    await state.aclose()


async def _payable_po(client, headers) -> tuple[int, int]:
    """种子里有一张 APPROVED 的单据，直接拿来当支付目标。"""
    listing = await client.get("/pos", headers=headers)
    assert listing.status_code == 200, listing.text
    for item in listing.json()["items"]:
        if item["status"] == "APPROVED":
            return int(item["id"]), int(item["amount"])
    raise AssertionError("seed 里没有 APPROVED 的单据")


# ---------- 金额篡改 ----------


async def test_payment_amount_tamper_allows_underpayment(env):
    client, state, login = env
    finance = await login("fiona")
    po_id, amount = await _payable_po(client, finance)

    state.set_flag(DefectFlag.PAYMENT_AMOUNT_TAMPER, True)
    paid = await client.post("/payments", json={"po_id": po_id, "amount": 1}, headers=finance)
    assert paid.status_code == 201, paid.text
    body = paid.json()
    assert body["amount"] == 1
    assert body["expected_amount"] == amount
    assert body["tampered"] is True


async def test_payment_amount_is_ignored_when_flag_off(env):
    client, state, login = env
    finance = await login("fiona")
    po_id, amount = await _payable_po(client, finance)

    state.set_flag(DefectFlag.PAYMENT_AMOUNT_TAMPER, False)
    state.set_flag(DefectFlag.PAYMENT_REPLAY, False)
    paid = await client.post("/payments", json={"po_id": po_id, "amount": 1}, headers=finance)
    assert paid.status_code == 201, paid.text
    body = paid.json()
    assert body["amount"] == amount
    assert body["tampered"] is False


# ---------- 重复付款 ----------


async def test_replay_defect_allows_paying_twice(env):
    client, state, login = env
    finance = await login("fiona")
    po_id, amount = await _payable_po(client, finance)

    state.set_flag(DefectFlag.PAYMENT_REPLAY, True)
    state.set_flag(DefectFlag.PAYMENT_AMOUNT_TAMPER, False)
    payload = {"po_id": po_id, "amount": amount}
    first = await client.post("/payments", json=payload, headers=finance)
    second = await client.post("/payments", json=payload, headers=finance)
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    listing = await client.get("/payments", headers=finance)
    assert len([row for row in listing.json() if row["po_id"] == po_id]) == 2


async def test_idempotency_key_prevents_double_charge(env):
    client, state, login = env
    finance = await login("fiona")
    po_id, amount = await _payable_po(client, finance)

    state.set_flag(DefectFlag.PAYMENT_REPLAY, False)
    state.set_flag(DefectFlag.PAYMENT_AMOUNT_TAMPER, False)
    payload = {"po_id": po_id, "amount": amount, "idempotency_key": "k-001"}
    first = await client.post("/payments", json=payload, headers=finance)
    second = await client.post("/payments", json=payload, headers=finance)
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert second.json()["duplicate"] is True
    listing = await client.get("/payments", headers=finance)
    assert len([row for row in listing.json() if row["po_id"] == po_id]) == 1


# ---------- 改密码越权 ----------


async def test_password_change_can_take_over_another_account(env):
    client, state, login = env
    alice = await login("alice")
    assert (
        await client.post("/login", json={"username": "bob", "password": "bob-pw"})
    ).status_code == 200

    state.set_flag(DefectFlag.PASSWORD_RESET_IDOR, True)
    changed = await client.post(
        "/account/password",
        json={"old_password": "wrong", "new_password": "hacked-pw", "user_id": 2},
        headers=alice,
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["changed_user"] == "bob"

    stolen = await client.post("/login", json={"username": "bob", "password": "hacked-pw"})
    assert stolen.status_code == 200, "改密之后应该能用新密码登录 bob"


async def test_password_change_requires_the_old_password(env):
    client, state, login = env
    alice = await login("alice")
    state.set_flag(DefectFlag.PASSWORD_RESET_IDOR, False)

    wrong = await client.post(
        "/account/password",
        json={"old_password": "nope", "new_password": "whatever", "user_id": 2},
        headers=alice,
    )
    assert wrong.status_code == 403

    right = await client.post(
        "/account/password",
        json={"old_password": "alice-pw", "new_password": "alice-new", "user_id": 2},
        headers=alice,
    )
    assert right.status_code == 200
    assert right.json()["changed_user"] == "alice"

    again = await client.post("/login", json={"username": "alice", "password": "alice-new"})
    assert again.status_code == 200


@pytest.mark.parametrize("flag", list(DefectFlag))
def test_every_flag_has_a_stable_value(flag):
    assert flag.value and flag.value == flag.value.lower()

"""采购审批域的靶场实现：状态机、金额阈值、审批链，以及七个可开关的缺陷。

安全红线：不 eval/exec、不 subprocess、不出网（SSRF 打的是进程内虚拟网络）、
不读真实文件系统（附件在内存字典里）。
"""

import asyncio
import base64
import hashlib
import hmac
import json
import posixpath
import secrets
import sqlite3
import time
from collections.abc import Callable
from typing import Annotated, Any, TypeVar
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from vulnarena.procure.models import (
    ApprovalOut,
    ApproveIn,
    AttachmentIn,
    AttachmentOut,
    AuditEntry,
    CallbackIn,
    CallbackOut,
    CreatePO,
    DefectFlag,
    LoginIn,
    LoginOut,
    MissionStatus,
    PasswordChangeIn,
    PasswordChangeOut,
    PaymentIn,
    PaymentOut,
    PODetail,
    POList,
    POSummary,
    Role,
    Status,
    SupplierOut,
)
from vulnarena.procure.seed import build as build_seed
from vulnarena.procure.seed import build_files, digest

T = TypeVar("T")
TRUTHY = {"on", "1", "true", "yes"}
DEFECT_HEADER = "x-arena-defect"
MISSION_AMOUNT = 800_000
METADATA_HOST = "169.254.169.254"
HOOKS_HOST = "hooks.internal"


# --- 虚拟网络：主机名映射到进程内 ASGI 应用，永不真实出网 -------------------


def _sandbox(title: str) -> FastAPI:
    return FastAPI(title=title, docs_url=None, openapi_url=None, redoc_url=None)


def build_metadata_app(canary: str) -> FastAPI:
    app = _sandbox("sandbox-metadata")

    @app.get("/latest/meta-data/iam/security-credentials/")
    async def creds() -> dict[str, str]:
        return {"AccessKeyId": "ASIA-SANDBOX", "SecretAccessKey": canary, "Token": "sandbox"}

    @app.get("/latest/meta-data/")
    async def listing() -> dict[str, list[str]]:
        return {"paths": ["iam/", "hostname"]}

    return app


def build_hooks_app() -> FastAPI:
    app = _sandbox("sandbox-hooks")

    @app.get("/ingest")
    @app.post("/ingest")
    async def ingest() -> dict[str, bool]:
        return {"received": True}

    return app


class VirtualNetwork:
    def __init__(self, canary: str):
        self.apps: dict[str, FastAPI] = {
            METADATA_HOST: build_metadata_app(canary),
            HOOKS_HOST: build_hooks_app(),
        }
        self.allowlist: set[str] = {HOOKS_HOST}

    def resolve(self, host: str) -> FastAPI | None:
        return self.apps.get(host)

    async def get(self, host: str, path: str) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.apps[host])
        async with httpx.AsyncClient(transport=transport, base_url=f"http://{host}") as client:
            return await client.get(path)


# --- token -------------------------------------------------------------------


class TokenError(Exception):
    pass


class Tokens:
    def __init__(self, ttl: int = 3600):
        self.secret = secrets.token_urlsafe(32).encode()
        self.ttl = ttl

    def _sign(self, body: str) -> str:
        raw = hmac.new(self.secret, body.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def issue(self, name: str, role: str, tenant: str, department: str) -> str:
        payload = {
            "sub": name,
            "role": role,
            "tenant": tenant,
            "dept": department,
            "jti": secrets.token_hex(6),
            "exp": int(time.time()) + self.ttl,
        }
        body = (
            base64.urlsafe_b64encode(
                json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
            )
            .rstrip(b"=")
            .decode()
        )
        return f"{body}.{self._sign(body)}"

    def verify(self, token: str) -> dict[str, Any]:
        body, _, signature = token.partition(".")
        if not body or not signature or not hmac.compare_digest(self._sign(body), signature):
            raise TokenError("bad signature")
        try:
            payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except ValueError as exc:
            raise TokenError("bad payload") from exc
        if int(payload.get("exp", 0)) < time.time():
            raise TokenError("expired")
        return payload


# --- 状态 --------------------------------------------------------------------


class ProcureState:
    def __init__(
        self,
        *,
        canary: str | None = None,
        flags: dict[DefectFlag, bool] | None = None,
    ):
        self.canary = canary or f"CANARY-{secrets.token_hex(6).upper()}"
        self.pepper = secrets.token_hex(16)
        self.flags: dict[DefectFlag, bool] = {flag: False for flag in DefectFlag}
        if flags:
            self.flags.update({DefectFlag(key): bool(value) for key, value in flags.items()})
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = asyncio.Lock()
        build_seed(self.conn, canary=self.canary, pepper=self.pepper)
        self.files = build_files(self.canary)
        self.network = VirtualNetwork(self.canary)
        self.tokens = Tokens()
        # 告警：同一身份 60 秒内 5 次 401/403 → 封禁 30 秒
        self.failures: dict[str, list[float]] = {}
        self.bans: dict[str, float] = {}
        self.failure_window = 60.0
        self.ban_seconds = 30.0
        self.failure_threshold = 5

    def set_flag(self, flag: DefectFlag, enabled: bool) -> None:
        self.flags[DefectFlag(flag)] = bool(enabled)

    async def run(self, fn: Callable[..., T], *args: Any) -> T:
        async with self.lock:
            return await asyncio.to_thread(fn, *args)

    def ban_remaining(self, key: str) -> float:
        return max(0.0, self.bans.get(key, 0.0) - time.monotonic())

    def register_failure(self, key: str) -> None:
        now = time.monotonic()
        recent = [seen for seen in self.failures.get(key, []) if now - seen < self.failure_window]
        recent.append(now)
        if len(recent) >= self.failure_threshold:
            self.bans[key] = now + self.ban_seconds
            self.failures[key] = []
        else:
            self.failures[key] = recent

    def alert_snapshot(self) -> dict[str, object]:
        now = time.monotonic()
        active = {key: round(until - now, 1) for key, until in self.bans.items() if until > now}
        watching = {key: len(seen) for key, seen in self.failures.items() if seen}
        return {"active_bans": active, "watched": watching, "threshold": self.failure_threshold}

    async def aclose(self) -> None:
        self.conn.close()


def _audit_insert(
    conn: sqlite3.Connection, ts: str, actor: str, role: str, method: str, path: str, status: int
) -> None:
    conn.execute(
        "INSERT INTO audit (ts, actor, role, method, path, status) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, actor, role, method, path, status),
    )
    conn.commit()


def _alert_key(request: Request, state: ProcureState) -> str:
    """优先按账号计数；没有会话时退回请求来源。"""
    cookie = request.cookies.get("procure_session")
    if cookie:
        try:
            return "user:" + str(state.tokens.verify(cookie)["sub"])
        except TokenError:
            pass
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        try:
            claims = state.tokens.verify(header.split(" ", 1)[1].strip())
            return "user:" + str(claims["sub"])
        except TokenError:
            return "token:" + header.split(" ", 1)[1].strip()[:16]
    host = request.client.host if request.client else "local"
    return "host:" + host


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        state = getattr(request.app.state, "procure", None)
        # 演练引擎自己发的包不参与封禁计数，否则一次演练会把自己封掉
        engine = "x-arena-session" in request.headers
        if state is not None and not engine:
            remaining = state.ban_remaining(_alert_key(request, state))
            if remaining > 0:
                return JSONResponse(
                    {
                        "detail": "too many denied requests; temporarily blocked",
                        "retry_after": round(remaining, 1),
                    },
                    status_code=429,
                    headers={"Retry-After": str(int(remaining) + 1)},
                )
        response = await call_next(request)
        state: ProcureState | None = getattr(request.app.state, "procure", None)
        if state is not None:
            actor, role = "anonymous", "anonymous"
            header = request.headers.get("authorization", "")
            if header.lower().startswith("bearer "):
                try:
                    claims = state.tokens.verify(header.split(" ", 1)[1].strip())
                    actor, role = str(claims["sub"]), str(claims["role"])
                except TokenError:
                    actor = "invalid-token"
            try:
                await state.run(
                    _audit_insert,
                    state.conn,
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    actor,
                    role,
                    request.method,
                    request.url.path,
                    response.status_code,
                )
            except Exception:
                pass
        if state is not None and not engine and response.status_code in (401, 403):
            state.register_failure(_alert_key(request, state))
        return response


# --- 路由 --------------------------------------------------------------------

router = APIRouter()


def state_of(request: Request) -> ProcureState:
    state: ProcureState = request.app.state.procure
    return state


def claims_of(
    state: Annotated[ProcureState, Depends(state_of)],
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Bearer 头优先，其次 Cookie——网页和 API 共用同一个会话。"""
    token: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    if token is None:
        token = request.cookies.get("procure_session")
    if not token:
        raise HTTPException(401, "missing bearer token")
    try:
        return state.tokens.verify(token)
    except TokenError:
        raise HTTPException(401, "invalid token") from None


State = Annotated[ProcureState, Depends(state_of)]
Session = Annotated[dict[str, Any], Depends(claims_of)]


def defects_of(request: Request, state: State) -> dict[DefectFlag, bool]:
    resolved = dict(state.flags)
    header = request.headers.get(DEFECT_HEADER)
    if header:
        for item in header.split(","):
            name, _, value = item.partition("=")
            try:
                flag = DefectFlag(name.strip())
            except ValueError:
                continue
            resolved[flag] = value.strip().lower() in TRUTHY
    return resolved


Defects = Annotated[dict[DefectFlag, bool], Depends(defects_of)]


def _search_literal(conn: sqlite3.Connection, keyword: str) -> list[sqlite3.Row]:
    statement = (
        "SELECT id, title, amount, status, requester FROM purchase_orders"
        f" WHERE title LIKE '%{keyword}%' ORDER BY id DESC LIMIT 50"
    )
    return conn.execute(statement).fetchall()


def _search_safe(conn: sqlite3.Connection, keyword: str) -> list[sqlite3.Row]:
    escaped = keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return conn.execute(
        "SELECT id, title, amount, status, requester FROM purchase_orders"
        " WHERE title LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 50",
        (f"%{escaped}%",),
    ).fetchall()


def _po_row(conn: sqlite3.Connection, po_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, tenant, requester, title, amount, supplier_id, status, attachment,"
        " notes FROM purchase_orders WHERE id = ?",
        (po_id,),
    ).fetchone()


def _approvals(conn: sqlite3.Connection, po_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT actor, role, decision, comment FROM approvals WHERE po_id = ? ORDER BY id",
        (po_id,),
    ).fetchall()


def _insert_po(conn: sqlite3.Connection, values: tuple[Any, ...]) -> int:
    cur = conn.execute(
        "INSERT INTO purchase_orders"
        " (tenant, requester, title, amount, supplier_id, status, attachment, notes,"
        " created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        values,
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def _add_approval(
    conn: sqlite3.Connection, po_id: int, actor: str, role: str, decision: str, comment: str
) -> None:
    conn.execute(
        "INSERT INTO approvals (po_id, actor, role, decision, comment, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (po_id, actor, role, decision, comment, time.strftime("%Y-%m-%dT%H:%M:%S")),
    )


def _set_status(conn: sqlite3.Connection, po_id: int, status: str) -> None:
    conn.execute("UPDATE purchase_orders SET status = ? WHERE id = ?", (status, po_id))
    conn.commit()


@router.post("/login", response_model=LoginOut)
async def login(payload: LoginIn, state: State, defects: Defects) -> LoginOut:
    password_hash = digest(payload.password, state.pepper)
    if defects[DefectFlag.SQLI_LOGIN_BYPASS]:
        statement = (
            "SELECT name, role, tenant, department FROM users"
            f" WHERE name = '{payload.username}' AND password_hash = '{password_hash}'"
        )
        row = await state.run(lambda: state.conn.execute(statement).fetchone())
    else:
        row = await state.run(
            lambda: state.conn.execute(
                "SELECT name, role, tenant, department FROM users"
                " WHERE name = ? AND password_hash = ?",
                (payload.username, password_hash),
            ).fetchone()
        )
    if row is None:
        raise HTTPException(401, "invalid credentials")
    token = state.tokens.issue(row["name"], row["role"], row["tenant"], row["department"])
    return LoginOut(
        token=token,
        role=Role(row["role"]),
        tenant=row["tenant"],
        department=row["department"],
    )


@router.get("/pos", response_model=POList)
async def list_pos(
    state: State,
    session: Session,
    defects: Defects,
    q: Annotated[str, Query(max_length=120)] = "",
    page: Annotated[int, Query(ge=1, le=100)] = 1,
    page_size: Annotated[int, Query(ge=1, le=50)] = 10,
) -> POList:
    searcher = _search_literal if defects[DefectFlag.SQLI_SEARCH] else _search_safe
    try:
        rows = await state.run(searcher, state.conn, q)
    except sqlite3.Error:
        raise HTTPException(400, "malformed search expression") from None
    window = rows[(page - 1) * page_size : page * page_size]
    items = [
        POSummary(
            id=row["id"],
            title=row["title"],
            amount=row["amount"],
            status=Status(row["status"]),
            requester=row["requester"],
        )
        for row in window
    ]
    return POList(total=len(rows), page=page, page_size=page_size, items=items)


@router.get("/pos/{po_id}", response_model=PODetail)
async def get_po(po_id: int, state: State, session: Session, defects: Defects) -> PODetail:
    row = await state.run(_po_row, state.conn, po_id)
    if row is None:
        raise HTTPException(404, "purchase order not found")
    if not defects[DefectFlag.IDOR_PO_DETAIL]:
        privileged = session["role"] in (Role.MANAGER, Role.FINANCE, Role.CFO, Role.AUDITOR)
        if not privileged and row["requester"] != session["sub"]:
            raise HTTPException(403, "purchase order belongs to another requester")
    approvals = await state.run(_approvals, state.conn, po_id)
    return PODetail(
        id=row["id"],
        title=row["title"],
        amount=row["amount"],
        status=Status(row["status"]),
        requester=row["requester"],
        supplier_id=row["supplier_id"],
        attachment=row["attachment"],
        notes=row["notes"],
        approvals=[ApprovalOut(**dict(item)) for item in approvals],
    )


@router.post("/pos", response_model=PODetail, status_code=201)
async def create_po(payload: CreatePO, state: State, session: Session) -> PODetail:
    supplier = await state.run(
        lambda: state.conn.execute(
            "SELECT id FROM suppliers WHERE id = ?", (payload.supplier_id,)
        ).fetchone()
    )
    if supplier is None:
        raise HTTPException(404, "supplier not found")
    po_id = await state.run(
        _insert_po,
        state.conn,
        (
            session["tenant"],
            session["sub"],
            payload.title,
            payload.amount,
            payload.supplier_id,
            Status.MANAGER_REVIEW.value,
            f"invoice-{secrets.randbelow(900) + 100}.pdf",
            "新建单据，暂无内部备注",
            time.strftime("%Y-%m-%dT%H:%M:%S"),
        ),
    )
    return await get_po(po_id, state, session, {flag: False for flag in DefectFlag})


@router.post("/pos/{po_id}/approve", response_model=PODetail)
async def approve(
    po_id: int, payload: ApproveIn, state: State, session: Session, defects: Defects
) -> PODetail:
    row = await state.run(_po_row, state.conn, po_id)
    if row is None:
        raise HTTPException(404, "purchase order not found")

    actor = session["sub"]
    role = str(session["role"])
    if defects[DefectFlag.MASS_ASSIGNMENT] and payload.approver:
        actor = payload.approver  # 身份由请求体决定——这就是批量赋值缺陷
        role = Role.CFO.value

    if payload.decision == "reject":
        await state.run(_add_approval, state.conn, po_id, actor, role, "reject", payload.comment)
        await state.run(_set_status, state.conn, po_id, Status.REJECTED.value)
        return await get_po(po_id, state, session, defects)

    if defects[DefectFlag.STATE_SKIP]:
        # 不校验状态机：任何单据一步到 APPROVED
        await state.run(_add_approval, state.conn, po_id, actor, role, "approve", payload.comment)
        await state.run(_set_status, state.conn, po_id, Status.APPROVED.value)
        return await get_po(po_id, state, session, defects)

    status = str(row["status"])
    amount = int(row["amount"])
    stage_role = {
        Status.MANAGER_REVIEW.value: Role.MANAGER,
        Status.FINANCE_REVIEW.value: Role.FINANCE,
        Status.CFO_REVIEW.value: Role.CFO,
    }.get(status)
    if stage_role is None:
        raise HTTPException(409, f"purchase order is {status}, not awaiting approval")
    if role != stage_role.value:
        raise HTTPException(403, f"this stage needs the {stage_role.value} role")

    await state.run(_add_approval, state.conn, po_id, actor, role, "approve", payload.comment)
    if status == Status.MANAGER_REVIEW.value:
        following = Status.FINANCE_REVIEW if amount > 50_000 else Status.APPROVED
    elif status == Status.FINANCE_REVIEW.value:
        following = Status.CFO_REVIEW if amount > 500_000 else Status.APPROVED
    else:
        following = Status.APPROVED
    await state.run(_set_status, state.conn, po_id, following.value)
    return await get_po(po_id, state, session, defects)


@router.post("/pos/{po_id}/pay", response_model=PODetail)
async def pay(po_id: int, state: State, session: Session, defects: Defects) -> PODetail:
    row = await state.run(_po_row, state.conn, po_id)
    if row is None:
        raise HTTPException(404, "purchase order not found")
    if str(row["status"]) != Status.APPROVED.value:
        raise HTTPException(409, f"purchase order is {row['status']}, not APPROVED")
    if session["role"] not in (Role.FINANCE.value, Role.CFO.value):
        raise HTTPException(403, "payment requires the finance or cfo role")
    await state.run(_set_status, state.conn, po_id, Status.PAID.value)
    return await get_po(po_id, state, session, defects)


@router.get("/suppliers/{supplier_id}", response_model=SupplierOut)
async def get_supplier(supplier_id: int, state: State, session: Session) -> SupplierOut:
    row = await state.run(
        lambda: state.conn.execute(
            "SELECT id, name, bank_account, callback_url, level FROM suppliers WHERE id = ?",
            (supplier_id,),
        ).fetchone()
    )
    if row is None:
        raise HTTPException(404, "supplier not found")
    return SupplierOut(**dict(row))


@router.post("/suppliers/{supplier_id}/callback-test", response_model=CallbackOut)
async def callback_test(
    supplier_id: int, payload: CallbackIn, state: State, session: Session, defects: Defects
) -> CallbackOut:
    parsed = urlparse(payload.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, "url must be an http(s) URL with a host")
    host, path = parsed.hostname, parsed.path or "/"
    if not defects[DefectFlag.SSRF_SUPPLIER] and host not in state.network.allowlist:
        raise HTTPException(403, "callback host is not in the supplier allowlist")
    if state.network.resolve(host) is None:
        raise HTTPException(404, "callback host is unreachable")
    response = await state.network.get(host, path)
    return CallbackOut(
        host=host, path=path, status=response.status_code, preview=response.text[:200]
    )


@router.post("/attachments", response_model=AttachmentOut)
async def upload_attachment(
    payload: AttachmentIn, state: State, session: Session, defects: Defects
) -> AttachmentOut:
    key = posixpath.normpath(f"/uploads/{payload.name}")
    if not defects[DefectFlag.PATH_TRAVERSAL] and not key.startswith("/uploads/"):
        raise HTTPException(403, "attachment path outside the upload directory")
    state.files[key] = payload.content
    return AttachmentOut(name=payload.name, stored_at=key, size=len(payload.content))


@router.get("/attachments")
async def download_attachment(
    state: State,
    session: Session,
    defects: Defects,
    name: Annotated[str, Query(min_length=1, max_length=128)],
) -> Response:
    key = posixpath.normpath(f"/uploads/{name}")
    if not defects[DefectFlag.PATH_TRAVERSAL] and not key.startswith("/uploads/"):
        raise HTTPException(403, "attachment path outside the upload directory")
    content = state.files.get(key)
    if content is None:
        raise HTTPException(404, "attachment not found")
    return Response(content=content, media_type="text/plain; charset=utf-8")


@router.get("/audit", response_model=list[AuditEntry])
async def audit_log(
    state: State, session: Session, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[AuditEntry]:
    if session["role"] != Role.AUDITOR.value:
        raise HTTPException(403, "audit log requires the auditor role")
    rows = await state.run(
        lambda: state.conn.execute(
            "SELECT id, ts, actor, role, method, path, status FROM audit ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    )
    return [AuditEntry(**dict(row)) for row in rows]


@router.get("/alerts")
async def alerts(state: State, session: Session) -> dict[str, object]:
    if session["role"] != Role.AUDITOR.value:
        raise HTTPException(403, "alerts require the auditor role")
    return state.alert_snapshot()


@router.get("/mission", response_model=MissionStatus)
async def mission(state: State, session: Session) -> MissionStatus:
    """目标判定只看数据库状态：一笔 ≥80 万的单子只经一人之手就付了款。"""
    rows = await state.run(
        lambda: state.conn.execute(
            "SELECT o.id, o.amount, (SELECT COUNT(*) FROM approvals a WHERE a.po_id = o.id)"
            " FROM purchase_orders o WHERE o.amount >= ? AND o.status = ?",
            (MISSION_AMOUNT, Status.PAID.value),
        ).fetchall()
    )
    for row in rows:
        if int(row[2]) == 1:
            return MissionStatus(
                goal="让一笔 ≥80 万的采购单只经一人之手就变成已付款",
                achieved=True,
                po_id=int(row[0]),
                approvals=1,
                detail="目标达成：金额阈值满足，且审批记录只有一条。",
            )
    return MissionStatus(
        goal="让一笔 ≥80 万的采购单只经一人之手就变成已付款",
        achieved=False,
        detail="还没有满足条件的单据。",
    )


# ---------- 支付：金额与幂等 ----------


def _payment_by_key(conn: sqlite3.Connection, key: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, po_id, amount, receipt_no FROM payments WHERE idempotency_key = ?",
        (key,),
    ).fetchone()


def _insert_payment(
    conn: sqlite3.Connection, po_id: int, amount: int, key: str, receipt: str
) -> int:
    cursor = conn.execute(
        "INSERT INTO payments (po_id, amount, idempotency_key, receipt_no, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (po_id, amount, key, receipt, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
    )
    conn.commit()
    return int(cursor.lastrowid)


def _payments_with_expected(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT p.id, p.po_id, p.amount, p.receipt_no, o.amount AS expected"
        " FROM payments p JOIN purchase_orders o ON o.id = p.po_id ORDER BY p.id"
    ).fetchall()


@router.post("/payments", response_model=PaymentOut, status_code=201)
async def create_payment(
    payload: PaymentIn, state: State, session: Session, defects: Defects
) -> PaymentOut:
    row = await state.run(_po_row, state.conn, payload.po_id)
    if row is None:
        raise HTTPException(404, "purchase order not found")

    expected = int(row["amount"])
    if session["role"] not in (Role.FINANCE.value, Role.CFO.value):
        raise HTTPException(403, "payment requires the finance or cfo role")

    # 幂等先于状态检查：同一个 key 重放要返回原单据，而不是 409
    if payload.idempotency_key and not defects[DefectFlag.PAYMENT_REPLAY]:
        existing = await state.run(_payment_by_key, state.conn, payload.idempotency_key)
        if existing is not None:
            return PaymentOut(
                id=existing["id"],
                po_id=existing["po_id"],
                amount=existing["amount"],
                expected_amount=expected,
                receipt_no=existing["receipt_no"],
                duplicate=True,
                tampered=int(existing["amount"]) != expected,
            )

    payable = {Status.APPROVED.value}
    if defects[DefectFlag.PAYMENT_REPLAY]:
        payable.add(Status.PAID.value)
    if str(row["status"]) not in payable:
        raise HTTPException(409, f"purchase order is {row['status']}, cannot pay")

    amount = int(payload.amount) if defects[DefectFlag.PAYMENT_AMOUNT_TAMPER] else expected
    receipt = f"RCPT-{payload.po_id}-{secrets.token_hex(4)}"
    payment_id = await state.run(
        _insert_payment, state.conn, payload.po_id, amount, payload.idempotency_key, receipt
    )
    await state.run(_set_status, state.conn, payload.po_id, Status.PAID.value)
    return PaymentOut(
        id=payment_id,
        po_id=payload.po_id,
        amount=amount,
        expected_amount=expected,
        receipt_no=receipt,
        duplicate=False,
        tampered=amount != expected,
    )


@router.get("/payments", response_model=list[PaymentOut])
async def list_payments(state: State, session: Session) -> list[PaymentOut]:
    rows = await state.run(_payments_with_expected, state.conn)
    return [
        PaymentOut(
            id=row["id"],
            po_id=row["po_id"],
            amount=row["amount"],
            expected_amount=row["expected"],
            receipt_no=row["receipt_no"],
            tampered=int(row["amount"]) != int(row["expected"]),
        )
        for row in rows
    ]


# ---------- 账号：改密码 ----------


def _user_by_name(conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, name, role, password_hash FROM users WHERE name = ?", (name,)
    ).fetchone()


def _user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, name, role, password_hash FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def _set_password(conn: sqlite3.Connection, user_id: int, password_hash: str) -> None:
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit()


@router.post("/account/password", response_model=PasswordChangeOut)
async def change_password(
    payload: PasswordChangeIn, state: State, session: Session, defects: Defects
) -> PasswordChangeOut:
    me = await state.run(_user_by_name, state.conn, session["sub"])
    if me is None:
        raise HTTPException(401, "session user no longer exists")

    target_id = int(me["id"])
    if defects[DefectFlag.PASSWORD_RESET_IDOR] and payload.user_id is not None:
        target_id = int(payload.user_id)

    target = await state.run(_user_by_id, state.conn, target_id)
    if target is None:
        raise HTTPException(404, "user not found")

    if not defects[DefectFlag.PASSWORD_RESET_IDOR]:
        if digest(payload.old_password, state.pepper) != target["password_hash"]:
            raise HTTPException(403, "old password does not match")

    await state.run(
        _set_password, state.conn, target_id, digest(payload.new_password, state.pepper)
    )
    return PasswordChangeOut(ok=True, changed_user=target["name"])


def build_procure_app(*, state: ProcureState | None = None) -> FastAPI:
    from vulnarena.procure.ui import router as ui_router

    procure = state or ProcureState()
    app = FastAPI(title="VulnArena Procure (sandbox)", version="0.1.0")
    app.state.procure = procure
    app.include_router(router)
    app.include_router(ui_router)
    app.add_middleware(AuditMiddleware)
    return app

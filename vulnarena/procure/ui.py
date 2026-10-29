"""采购系统的网页前端：登录、单据列表、详情、审批、上传。

这不是给学习者看的"演示页"，而是一个能真的点、真的提交、真的被攻击的后台。
页面用服务端渲染 + Cookie 会话，和真实企业内部系统一个形态：

* 表单提交走同一套业务函数，缺陷开关对网页与 API 一视同仁
* 登录成功后把 token 写进 HttpOnly Cookie
* 所有输出都经过 html.escape，避免页面本身自伤
"""

import html
from urllib.parse import parse_qs, quote

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from vulnarena.procure.app import (
    approve,
    change_password,
    create_payment,
    get_po,
    list_pos,
    login,
    pay,
    state_of,
    upload_attachment,
)
from vulnarena.procure.models import (
    ApproveIn,
    AttachmentIn,
    DefectFlag,
    LoginIn,
    PasswordChangeIn,
    PaymentIn,
    PODetail,
    POList,
)

router = APIRouter(prefix="/ui", include_in_schema=False)
COOKIE = "procure_session"

STYLE = """
:root{--bg:#0d1117;--panel:#151b24;--line:#232c3a;--text:#c9d4e5;--muted:#7c8aa5;
--blue:#4f8cff;--green:#35d07f;--red:#ff5d6c;--amber:#f5b942}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.65 "Segoe UI","Microsoft YaHei",system-ui,sans-serif}
a{color:var(--blue);text-decoration:none}
header{display:flex;justify-content:space-between;align-items:center;gap:16px;
padding:12px 22px;border-bottom:1px solid var(--line);background:#10161f}
.brand{font-weight:700;letter-spacing:.3px}
.brand span{color:var(--blue)}
.who{color:var(--muted);font-size:13px}
main{max-width:1080px;margin:0 auto;padding:22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:14px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);font-size:13.5px}
th{color:var(--muted);font-weight:600;font-size:12px;letter-spacing:.6px;text-transform:uppercase}
tr:last-child td{border-bottom:0}
.tag{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.tag.paid{color:var(--green);border-color:#1c4634}
.tag.review{color:var(--amber);border-color:#4a3a12}
input,select,button{font:inherit}
input[type=text],input[type=password],input[type=number],textarea{
width:100%;padding:8px 10px;border-radius:8px;border:1px solid var(--line);
background:#0b1119;color:var(--text);margin:4px 0 12px}
button{background:var(--blue);color:#06121f;border:0;border-radius:8px;padding:8px 16px;
font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:var(--text);border:1px solid var(--line);font-weight:500}
button.danger{background:var(--red);color:#1a0508}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.kv{display:grid;grid-template-columns:110px 1fr;gap:6px 12px;font-size:13.5px}
.kv dt{color:var(--muted)}
.kv dd{margin:0}
.err{color:var(--red);margin:6px 0}
.muted{color:var(--muted);font-size:12.5px}
form.inline{display:inline}
"""


def page(title: str, body: str, who: str = "", status: int = 200) -> HTMLResponse:
    header = (
        '<header><div class="brand">Vuln<span>Procure</span> 采购审批</div>'
        f'<div class="who">{who}</div></header>'
    )
    return HTMLResponse(
        f"<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head>"
        f"<body>{header}<main>{body}</main></body></html>",
        status_code=status,
    )


def escape(value: object) -> str:
    return html.escape("" if value is None else str(value))


async def parse_form(request: Request) -> dict[str, str]:
    """最小表单解析：只处理浏览器默认的 urlencoded，不引入 multipart 依赖。"""
    raw = await request.body()
    pairs = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
    return {key: values[0] for key, values in pairs.items()}


def identity(request: Request) -> dict | None:
    """Cookie 里的 token 解出身份；失败返回 None。"""
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    state = state_of(request)
    try:
        return state.tokens.verify(token)
    except Exception:
        return None


def login_page(error: str = "") -> HTMLResponse:
    body = f"""
<div class="card" style="max-width:420px;margin:40px auto">
  <h3 style="margin-top:0">员工登录</h3>
  <p class="muted">内部采购审批系统 · 请使用工号登录</p>
  {f'<p class="err">{escape(error)}</p>' if error else ""}
  <form method="post" action="/ui/login">
    <label class="muted">工号</label>
    <input type="text" name="username" autocomplete="username" required>
    <label class="muted">密码</label>
    <input type="password" name="password" autocomplete="current-password" required>
    <button type="submit">登录</button>
  </form>
  <p class="muted" style="margin-top:14px">演示账号：alice / mike / fiona / admin / guard（密码为账号名 + -pw）</p>
</div>"""
    return page("登录 · 采购审批", body)


@router.get("/login", response_class=HTMLResponse)
async def ui_login_form(request: Request) -> HTMLResponse:
    if identity(request) is not None:
        return RedirectResponse("/ui/pos", status_code=303)
    return login_page()


@router.post("/login", response_class=HTMLResponse)
async def ui_login(request: Request) -> HTMLResponse:
    form = await parse_form(request)
    username = form.get("username", "")
    password = form.get("password", "")
    state = state_of(request)
    defects = dict(state.flags)
    try:
        result = await login(LoginIn(username=username, password=password), state, defects)
    except Exception:
        return login_page("工号或密码错误")
    response = RedirectResponse("/ui/pos", status_code=303)
    response.set_cookie(COOKIE, result.token, httponly=True, samesite="lax")
    return response


@router.get("/logout")
async def ui_logout() -> RedirectResponse:
    response = RedirectResponse("/ui/login", status_code=303)
    response.delete_cookie(COOKIE)
    return response


def orders_table(payload: POList) -> str:
    if not payload.items:
        return '<p class="muted">没有匹配的单据。</p>'
    rows = "".join(
        f"<tr><td><a href='/ui/pos/{item.id}'>#{item.id}</a></td>"
        f"<td>{escape(item.title)}</td>"
        f"<td>¥{item.amount:,}</td>"
        f"<td>{escape(item.requester)}</td>"
        f"<td><span class='tag'>{escape(item.status)}</span></td></tr>"
        for item in payload.items
    )
    return (
        "<table><thead><tr><th>单号</th><th>标题</th><th>金额</th><th>申请人</th>"
        f"<th>状态</th></tr></thead><tbody>{rows}</tbody></table>"
    )


@router.get("/pos", response_class=HTMLResponse)
async def ui_pos_list(request: Request, q: str = "") -> HTMLResponse:
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    defects = dict(state.flags)
    try:
        payload = await list_pos(state, claims, defects, q=q, page=1, page_size=50)
        table = orders_table(payload)
    except Exception:
        table = '<p class="err">查询失败：搜索表达式不合法。</p>'
    body = f"""
<div class="card">
  <form method="get" action="/ui/pos" class="row">
    <input type="text" name="q" value="{escape(q)}" placeholder="按标题搜索，例如：设备" style="flex:1;margin:0">
    <button type="submit">搜索</button>
  </form>
</div>
<div class="card">{table}</div>"""
    who = f"{escape(claims['sub'])} · {escape(claims['role'])} · <a href='/ui/logout'>退出</a>"
    return page("采购单 · 采购审批", body, who)


def orders_detail(detail: PODetail, claims: dict) -> str:
    approvals = (
        "".join(
            f"<tr><td>{escape(item.actor)}</td><td>{escape(item.role)}</td>"
            f"<td>{escape(item.decision)}</td><td>{escape(item.comment)}</td></tr>"
            for item in detail.approvals
        )
        or '<tr><td colspan="4" class="muted">还没有审批记录</td></tr>'
    )
    actions = ""
    if detail.status in ("MANAGER_REVIEW", "FINANCE_REVIEW", "CFO_REVIEW"):
        actions = f"""
<form method="post" action="/ui/pos/{detail.id}/approve" class="inline">
  <input type="hidden" name="decision" value="approve">
  <input type="text" name="comment" placeholder="审批意见" style="width:220px;margin:0 6px">
  <button type="submit">通过</button>
</form>
<form method="post" action="/ui/pos/{detail.id}/approve" class="inline">
  <input type="hidden" name="decision" value="reject">
  <button type="submit" class="danger">驳回</button>
</form>"""
    if detail.status == "APPROVED":
        actions += f"""
<form method="post" action="/ui/pos/{detail.id}/pay" class="inline" style="margin-left:8px">
  <button type="submit" class="ghost">执行付款</button>
</form>
<a class="btn" href="/ui/pay/{detail.id}" style="margin-left:8px">支付（金额可改）</a>"""
    return f"""
<div class="card">
  <div class="row" style="justify-content:space-between">
    <h3 style="margin:0">#{detail.id} {escape(detail.title)}</h3>
    <span class="tag">{escape(detail.status)}</span>
  </div>
  <dl class="kv" style="margin-top:14px">
    <dt>申请人</dt><dd>{escape(detail.requester)}</dd>
    <dt>金额</dt><dd>¥{detail.amount:,}</dd>
    <dt>供应商</dt><dd><a href="/ui/suppliers/{detail.supplier_id}">#{detail.supplier_id}</a></dd>
    <dt>附件</dt><dd><a href="/ui/attachments?name={escape(detail.attachment)}">{escape(detail.attachment)}</a></dd>
    <dt>内部备注</dt><dd>{escape(detail.notes)}</dd>
  </dl>
  <div class="row" style="margin-top:16px">{actions}</div>
</div>
<div class="card">
  <h4 style="margin-top:0">审批记录</h4>
  <table><thead><tr><th>审批人</th><th>角色</th><th>结论</th><th>意见</th></tr></thead>
  <tbody>{approvals}</tbody></table>
</div>"""


@router.get("/pos/{po_id}", response_class=HTMLResponse)
async def ui_pos_detail(request: Request, po_id: int) -> HTMLResponse:
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    defects = dict(state.flags)
    try:
        detail = await get_po(po_id, state, claims, defects)
    except Exception as exc:
        status = getattr(exc, "status_code", 400)
        message = getattr(exc, "detail", "无法打开该单据")
        body = f"""<div class="card"><p class="err">{escape(message)}</p>
        <p class="muted">HTTP {escape(status)} · 试试直接改地址栏里的单号。</p>
        <p><a href="/ui/pos">返回列表</a></p></div>"""
        who = f"{escape(claims['sub'])} · {escape(claims['role'])}"
        return page(f"单据 #{po_id} · 采购审批", body, who, status=status)
    who = f"{escape(claims['sub'])} · {escape(claims['role'])} · <a href='/ui/pos'>列表</a> · <a href='/ui/account'>账号</a> · <a href='/ui/logout'>退出</a>"
    return page(f"单据 #{po_id} · 采购审批", orders_detail(detail, claims), who)


@router.post("/pos/{po_id}/approve")
async def ui_approve(request: Request, po_id: int) -> RedirectResponse:
    form = await parse_form(request)
    decision = form.get("decision", "approve")
    comment = form.get("comment", "")
    approver = form.get("approver", "")
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    try:
        await approve(
            po_id,
            ApproveIn(decision=decision, comment=comment, approver=approver or None),
            state,
            claims,
            dict(state.flags),
        )
    except Exception:
        pass
    return RedirectResponse(f"/ui/pos/{po_id}", status_code=303)


@router.post("/pos/{po_id}/pay")
async def ui_pay(request: Request, po_id: int) -> RedirectResponse:
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    try:
        await pay(po_id, state, claims, dict(state.flags))
    except Exception:
        pass
    return RedirectResponse(f"/ui/pos/{po_id}", status_code=303)


@router.get("/suppliers/{supplier_id}", response_class=HTMLResponse)
async def ui_supplier(request: Request, supplier_id: int) -> HTMLResponse:
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    row = await state.run(
        lambda: state.conn.execute(
            "SELECT id, name, bank_account, callback_url, level FROM suppliers WHERE id = ?",
            (supplier_id,),
        ).fetchone()
    )
    who = f"{escape(claims['sub'])} · {escape(claims['role'])} · <a href='/ui/pos'>列表</a> · <a href='/ui/account'>账号</a>"
    if row is None:
        return page(
            "供应商 · 采购审批",
            '<div class="card"><p class="err">供应商不存在</p></div>',
            who,
            status=404,
        )
    body = f"""
<div class="card">
  <h3 style="margin-top:0">供应商 #{row["id"]} {escape(row["name"])}</h3>
  <dl class="kv">
    <dt>收款账号</dt><dd>{escape(row["bank_account"])}</dd>
    <dt>回调地址</dt><dd>{escape(row["callback_url"])}</dd>
    <dt>等级</dt><dd>{escape(row["level"])}</dd>
  </dl>
</div>"""
    return page("供应商 · 采购审批", body, who)


@router.get("/attachments", response_class=HTMLResponse)
async def ui_attachment(request: Request, name: str = "") -> HTMLResponse:
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    import posixpath

    key = posixpath.normpath(f"/uploads/{name}")
    defects = dict(state.flags)
    if not defects[DefectFlag.PATH_TRAVERSAL] and not key.startswith("/uploads/"):
        body = '<div class="card"><p class="err">附件路径不在上传目录内</p></div>'
    else:
        content = state.files.get(key)
        body = (
            f"<div class='card'><h3 style='margin-top:0'>{escape(name)}</h3>"
            f"<pre style='white-space:pre-wrap'>{escape(content)}</pre></div>"
            if content is not None
            else '<div class="card"><p class="err">附件不存在</p></div>'
        )
    who = f"{escape(claims['sub'])} · {escape(claims['role'])}"
    status = 200 if "pre" in body else 403
    return page("附件 · 采购审批", body, who, status=status)


@router.post("/attachments")
async def ui_upload(request: Request) -> RedirectResponse:
    form = await parse_form(request)
    name = form.get("name", "")
    content = form.get("content", "")
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    try:
        await upload_attachment(
            AttachmentIn(name=name, content=content), state, claims, dict(state.flags)
        )
    except Exception:
        pass
    return RedirectResponse("/ui/pos", status_code=303)


@router.get("/pay/{po_id}", response_class=HTMLResponse)
async def ui_pay_form(request: Request, po_id: int, err: str = "") -> HTMLResponse:
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    try:
        detail = await get_po(po_id, state, claims, dict(state.flags))
    except Exception:
        return page(
            "支付 · 采购审批", '<div class="card"><p class="err">单据不存在</p></div>', status=404
        )
    error = f'<p class="err">{escape(err)}</p>' if err else ""
    body = f"""
<div class="card">
  <h3 style="margin-top:0">支付单据 #{detail.id}</h3>
  <p class="muted">应付金额：{detail.amount} 分（约 {detail.amount // 100} 元）</p>
  {error}
  <form method="post" action="/ui/pay/{detail.id}">
    <label>实付金额（分）<input name="amount" value="{detail.amount}" autocomplete="off"></label>
    <label>幂等键（可空）<input name="idempotency_key" value="" autocomplete="off"></label>
    <button type="submit">提交支付</button>
  </form>
  <p class="muted" style="margin-top:10px">这个表单把金额交给服务端——服务端该不该信它，就是这一关的问题。</p>
</div>"""
    return page(
        "支付 · 采购审批",
        body,
        f"{escape(claims['sub'])} · {escape(claims['role'])} · <a href='/ui/pos'>列表</a> · <a href='/ui/account'>账号</a>",
    )


@router.post("/pay/{po_id}")
async def ui_pay_submit(request: Request, po_id: int) -> RedirectResponse:
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    form = await parse_form(request)
    try:
        payload = PaymentIn(
            po_id=po_id,
            amount=int(form.get("amount") or 0),
            idempotency_key=str(form.get("idempotency_key") or ""),
        )
        await create_payment(payload, state, claims, dict(state.flags))
    except Exception as exc:  # noqa: BLE001 - 页面只需要把失败原因显示出来
        reason = str(getattr(exc, "detail", exc))
        return RedirectResponse(f"/ui/pay/{po_id}?err={quote(reason)}", status_code=303)
    return RedirectResponse(f"/ui/pos/{po_id}", status_code=303)


@router.get("/account", response_class=HTMLResponse)
async def ui_account(request: Request, msg: str = "") -> HTMLResponse:
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    flash = f'<p class="ok">{escape(msg)}</p>' if msg else ""
    body = f"""
<div class="card">
  <h3 style="margin-top:0">修改密码</h3>
  {flash}
  <form method="post" action="/ui/account">
    <label>用户 ID（不改请留空）<input name="user_id" value="" autocomplete="off"></label>
    <label>旧密码<input name="old_password" type="password" value=""></label>
    <label>新密码<input name="new_password" type="password" value=""></label>
    <button type="submit">提交</button>
  </form>
  <p class="muted" style="margin-top:10px">正常实现只该改自己，并且必须验旧密码。</p>
</div>"""
    return page(
        "账号 · 采购审批",
        body,
        f"{escape(claims['sub'])} · {escape(claims['role'])} · <a href='/ui/pos'>列表</a> · <a href='/ui/account'>账号</a>",
    )


@router.post("/account")
async def ui_account_submit(request: Request) -> RedirectResponse:
    claims = identity(request)
    if claims is None:
        return RedirectResponse("/ui/login", status_code=303)
    state = state_of(request)
    form = await parse_form(request)
    raw = str(form.get("user_id") or "").strip()
    try:
        payload = PasswordChangeIn(
            old_password=str(form.get("old_password") or ""),
            new_password=str(form.get("new_password") or ""),
            user_id=int(raw) if raw else None,
        )
        result = await change_password(payload, state, claims, dict(state.flags))
    except Exception as exc:  # noqa: BLE001
        reason = str(getattr(exc, "detail", exc))
        return RedirectResponse(f"/ui/account?msg={quote(reason)}", status_code=303)
    return RedirectResponse(
        f"/ui/account?msg={quote('已修改 ' + result.changed_user)}", status_code=303
    )

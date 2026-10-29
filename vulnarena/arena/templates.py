"""Rule and fix templates.

The initial rule is deliberately weak: a plain ``union select`` match. It is what
an unmaintained gateway looks like, and it is what the red step has to defeat
before the blue step may replace it.
"""

import difflib

from vulnarena.arena.corpus import Category

WEAK_RULE_REGEX = r"(?i)union\s+select"
SQLI_RULE_REGEX = r"(?i)(union\s+(?:all\s+)?select|'\s*or\s+'?1'?\s*=|'\s*--)"
SSRF_RULE_REGEX = r"(169\.254\.169\.254|0xa9fea9fe|2852039166)"

# Categories that can be stopped at the gateway. Traversal and IDOR are absent on
# purpose: no request-level pattern separates them from legitimate traffic.
RULE_TEMPLATES: dict[str, tuple[str, Category]] = {
    "sqli": (SQLI_RULE_REGEX, Category.SQLI),
    "ssrf": (SSRF_RULE_REGEX, Category.SSRF),
}

SQLI_VULNERABLE = r"""statement = (
    "SELECT id, title, status, created_at FROM tickets"
    f" WHERE tenant = '{tenant}' AND visibility = 'normal'"
    f" AND title LIKE '%{keyword}%' ORDER BY id DESC LIMIT {limit}"
)
return conn.execute(statement).fetchall()"""

SQLI_FIXED = r"""escaped = (
    keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
)
return conn.execute(
    "SELECT id, title, status, created_at FROM tickets"
    " WHERE tenant = ? AND visibility = 'normal' AND title LIKE ? ESCAPE '\\'"
    " ORDER BY id DESC LIMIT ?",
    (tenant, f"%{escaped}%", limit),
).fetchall()"""

IDOR_VULNERABLE = """row = await state.run(fetch_ticket, state.conn, ticket_id)
if row is None:
    raise HTTPException(404, "ticket not found")
return TicketDetail(...)"""

IDOR_FIXED = """row = await state.run(fetch_ticket, state.conn, ticket_id)
if row is None:
    raise HTTPException(404, "ticket not found")
visible = row["visibility"] == "normal" and row["tenant"] == session.tenant
if not visible and row["owner_id"] != session.sub:
    raise HTTPException(403, "ticket belongs to another user")
return TicketDetail(...)"""

TRAVERSAL_VULNERABLE = """key = posixpath.normpath(f"/uploads/{name}")
content = state.files.get(key)
return Response(content, media_type="text/plain")"""

TRAVERSAL_FIXED = """key = posixpath.normpath(f"/uploads/{name}")
if not key.startswith("/uploads/"):
    raise HTTPException(403, "attachment path outside the upload directory")
content = state.files.get(key)
return Response(content, media_type="text/plain")"""

SSRF_VULNERABLE = """host = urlparse(payload.target_url).hostname
response = await state.network.get(host, payload.target_url)
return WebhookResult(host=host, status=response.status_code)"""

SSRF_FIXED = """host = urlparse(payload.target_url).hostname
if host not in state.network.allowlist:
    raise HTTPException(403, "target host is not in the webhook allowlist")
response = await state.network.get(host, payload.target_url)
return WebhookResult(host=host, status=response.status_code)"""

LOGIC_VULNERABLE = """if defects[DefectFlag.STATE_SKIP]:
    await state.run(_add_approval, state.conn, po_id, actor, role, "approve", comment)
    await state.run(_set_status, state.conn, po_id, Status.APPROVED.value)"""

LOGIC_FIXED = """if str(row["status"]) not in (
    Status.MANAGER_REVIEW.value,
    Status.FINANCE_REVIEW.value,
    Status.CFO_REVIEW.value,
):
    raise HTTPException(409, "purchase order is not awaiting approval")
await state.run(_add_approval, state.conn, po_id, session["sub"], role, "approve", comment)"""

CODE_FIXES: dict[str, tuple[str, str, str]] = {
    "sqli": ("vulnarena/procure/app.py", SQLI_VULNERABLE, SQLI_FIXED),
    "idor": ("vulnarena/procure/app.py", IDOR_VULNERABLE, IDOR_FIXED),
    "path_traversal": (
        "vulnarena/procure/app.py",
        TRAVERSAL_VULNERABLE,
        TRAVERSAL_FIXED,
    ),
    "ssrf": ("vulnarena/procure/app.py", SSRF_VULNERABLE, SSRF_FIXED),
    "logic": ("vulnarena/procure/app.py", LOGIC_VULNERABLE, LOGIC_FIXED),
}


def render_diff(category: str) -> str:
    path, vulnerable, fixed = CODE_FIXES[category]
    return "".join(
        difflib.unified_diff(
            vulnerable.splitlines(keepends=True),
            fixed.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            lineterm="\n",
        )
    )

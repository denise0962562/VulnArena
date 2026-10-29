"""Adaptive gateway in front of the portal business routes.

The policy is read through a short-lived in-process cache, so a hot-reloaded rule
takes effect within a second and a Redis outage degrades the gateway instead of
breaking the request path.
"""

import base64
import json

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from vulnarena.arena.corpus import observation
from vulnarena.arena.events import ArenaEvent
from vulnarena.arena.runtime import ArenaRuntime

SESSION_HEADER = "x-arena-session"
DEFAULT_SESSION = "lab-default"
PREVIEW = 200


def read_jti(authorization: str | None) -> str | None:
    """Decode only; the portal verifies the signature. Revocation only needs the id."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    body = token.split(".")[0]
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        return str(payload["jti"])
    except (ValueError, KeyError, TypeError):
        return None


class WafMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, runtime: ArenaRuntime):
        super().__init__(app)
        self.runtime = runtime

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        session_id = request.headers.get(SESSION_HEADER) or DEFAULT_SESSION
        policy, rules = await self.runtime.policy_for(session_id)

        body_bytes = await request.body()
        if len(body_bytes) > policy.max_body_bytes:
            return await self._deny(request, session_id, 413, "request body too large", None)

        jti = read_jti(request.headers.get("authorization"))
        if jti is not None and jti in policy.revoked_jti:
            return await self._deny(request, session_id, 403, "token revoked", "TOKEN_REVOKED")

        body = body_bytes.decode("utf-8", "replace")
        raw, normalised = observation(request.method, request.url.path, request.url.query, body)
        for compiled in rules:
            if compiled.pattern.search(raw) or compiled.pattern.search(normalised):
                return await self._deny(
                    request, session_id, 403, "blocked by waf", compiled.rule.id, raw[:PREVIEW]
                )

        response = await call_next(request)
        if self.runtime.degraded:
            response.headers["x-waf-degraded"] = "1"
        return response

    async def _deny(
        self,
        request: Request,
        session_id: str,
        status: int,
        detail: str,
        rule_id: str | None,
        preview: str = "",
    ) -> Response:
        await self.runtime.emit(
            ArenaEvent(
                session_id=session_id,
                stage="waf",
                kind="blocked",
                message=detail,
                data={
                    "rule_id": rule_id,
                    "method": request.method,
                    "path": request.url.path,
                    "preview": preview,
                },
            )
        )
        headers = {"x-waf-degraded": "1"} if self.runtime.degraded else {}
        content = {"detail": detail, "rule_id": rule_id, "session_id": session_id}
        return JSONResponse(content, status_code=status, headers=headers)

"""Local-only default, optional signed admin session, and bounded request telemetry."""

import hashlib
import hmac
import logging
import secrets
import time
from collections import deque
from contextvars import ContextVar
from urllib.parse import parse_qs
from uuid import uuid4

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

logger = logging.getLogger(__name__)
COOKIE = "vulnarena_admin"
MAX_AGE = 12 * 3600
REQUEST_ID = ContextVar("request_id", default="background")


def secure_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())


def signed_cookie(key: str) -> str:
    payload = f"{int(time.time())}.{secrets.token_hex(16)}"
    return payload + "." + hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()


def valid_cookie(value: str, key: str) -> bool:
    try:
        timestamp, nonce, signature = value.split(".")
        age = time.time() - int(timestamp)
        expected = hmac.new(
            key.encode(), f"{timestamp}.{nonce}".encode(), hashlib.sha256
        ).hexdigest()
        return 0 <= age <= MAX_AGE and secure_equal(expected, signature)
    except (ValueError, TypeError):
        return False


class AdminAccessMiddleware:
    def __init__(self, app, settings):
        self.app = app
        self.key = settings.admin_token.get_secret_value()
        self.failures = {}
        self.samples = deque(maxlen=1000)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope, receive)
        scope["app"].state.request_samples = self.samples
        request_id = uuid4().hex
        request_context = REQUEST_ID.set(request_id)
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.perf_counter()
        status = 500

        async def instrument(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message["headers"] = [
                    *message.get("headers", []),
                    (b"x-request-id", request_id.encode()),
                ]
            await send(message)

        try:
            response = await self.authorize(request)
            if response is not None:
                await response(scope, receive, instrument)
            else:
                await self.app(scope, receive, instrument)
        finally:
            duration = round((time.perf_counter() - started) * 1000, 2)
            self.samples.append({"method": request.method, "status": status, "ms": duration})
            logger.info(
                "request id=%s method=%s status=%s ms=%s",
                request_id,
                request.method,
                status,
                duration,
            )
            REQUEST_ID.reset(request_context)

    async def authorize(self, request):
        local = request.client and request.client.host in {
            "127.0.0.1",
            "::1",
            "localhost",
            "testclient",
        }
        if request.url.path == "/health":
            return None
        if not self.key:
            if not local:
                return JSONResponse(
                    {"detail": "Remote access requires VULNARENA_ADMIN_TOKEN."}, status_code=403
                )
            host = request.url.hostname or ""
            if host not in {"127.0.0.1", "::1", "localhost", "test", "t"}:
                return JSONResponse({"detail": "Untrusted local Host."}, status_code=403)
        origin = request.headers.get("origin")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if request.headers.get("sec-fetch-site") == "cross-site" or (
                origin and origin.rstrip("/") != str(request.base_url).rstrip("/")
            ):
                return JSONResponse({"detail": "Cross-origin write denied."}, status_code=403)
        if request.url.path == "/login":
            if not self.key:
                return RedirectResponse("/", status_code=303)
            if request.method == "GET":
                return HTMLResponse(
                    '<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
                    "<title>工作台登录</title>"
                    '<main><h1>工作台管理登录</h1><form method="post" action="/login">'
                    '<label>管理口令 <input type="password" name="token" '
                    'autocomplete="current-password" required></label>'
                    '<button type="submit">登录</button></form></main></html>',
                    headers={"Cache-Control": "no-store"},
                )
            if request.method != "POST":
                return JSONResponse({"detail": "Method not allowed"}, status_code=405)
            identity = request.client.host if request.client else "unknown"
            cutoff = time.monotonic() - 300
            self.failures = {
                k: [t for t in v if t > cutoff]
                for k, v in self.failures.items()
                if any(t > cutoff for t in v)
            }
            if identity not in self.failures and len(self.failures) >= 1024:
                return JSONResponse(
                    {"detail": "Login capacity reached; retry later."}, status_code=429
                )
            attempts = self.failures.setdefault(identity, [])
            if len(attempts) >= 5:
                return JSONResponse(
                    {"detail": "Too many login attempts; retry in five minutes."}, status_code=429
                )
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 4096:
                    return JSONResponse({"detail": "Login body too large"}, status_code=413)
            token = parse_qs(body.decode("utf-8", errors="replace")).get("token", [""])[0]
            if not secure_equal(token, self.key):
                attempts.append(time.monotonic())
                return JSONResponse({"detail": "Invalid credentials"}, status_code=401)
            self.failures.pop(identity, None)
            response = RedirectResponse("/", status_code=303, headers={"Cache-Control": "no-store"})
            response.set_cookie(
                COOKIE,
                signed_cookie(self.key),
                httponly=True,
                samesite="strict",
                secure=request.url.scheme == "https",
                max_age=MAX_AGE,
            )
            return response
        if not self.key:
            return None
        header = request.headers.get("x-vulnarena-admin", "")
        bearer = request.headers.get("authorization", "").removeprefix("Bearer ")
        accepted = (
            secure_equal(header, self.key)
            or secure_equal(bearer, self.key)
            or valid_cookie(request.cookies.get(COOKIE, ""), self.key)
        )
        if not accepted:
            if request.method == "GET" and "text/html" in request.headers.get("accept", ""):
                return RedirectResponse("/login", status_code=303)
            return JSONResponse({"detail": "Admin authentication required"}, status_code=401)
        if request.url.path == "/logout" and request.method == "POST":
            response = RedirectResponse("/login", status_code=303)
            response.delete_cookie(COOKIE, httponly=True, samesite="strict")
            return response
        return None

import asyncio
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest
from pydantic import SecretStr

from vulnarena.nvd import (
    NVDClient,
    NVDConnectionError,
    NVDParseError,
    NVDUpstreamError,
    RateLimiter,
    retry_after,
)
from vulnarena.schemas import SyncRequest


async def test_throttle_shared_concurrent(clock):
    limiter = RateLimiter(6.1, clock=clock.time, sleep=clock.sleep)
    await asyncio.gather(*(limiter.wait() for _ in range(7)))
    assert len(clock.waits) == 6
    assert clock.now == pytest.approx(136.6)


async def test_retry_429_5xx_key_and_timeout(settings, envelope, clock):
    settings.nvd_api_key = SecretStr("secret-test-key")
    requests = []

    def handler(request):
        requests.append(request)
        status = [429, 503, 200][len(requests) - 1]
        return httpx.Response(status, headers={"Retry-After": "7"}, json=envelope)

    client = NVDClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        limiter=RateLimiter(6.1, clock=clock.time, sleep=clock.sleep),
    )
    try:
        assert len(await client.fetch(SyncRequest(cve_id="CVE-2024-1234"))) == 1
        assert len(requests) == 3 and clock.waits == [7, 7]
        assert requests[0].headers["apiKey"] == "secret-test-key"
        assert requests[0].extensions["timeout"]["read"] == 30
        assert "apiKey" not in str(requests[0].url)
    finally:
        await client.aclose()


@pytest.mark.parametrize("code", [429, 500, 503, 403])
async def test_bounded_http_failures(settings, code, clock):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(code)

    client = NVDClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        limiter=RateLimiter(6.1, clock=clock.time, sleep=clock.sleep),
    )
    async with client.http:
        with pytest.raises(NVDUpstreamError, match=str(code)):
            await client.request({})
    assert len(calls) == (1 if code == 403 else 4)
    assert all("apiKey" not in req.headers for req in calls)


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout])
async def test_connection_retry(settings, clock, error):
    count = 0

    def handler(request):
        nonlocal count
        count += 1
        raise error("sensitive transport detail")

    client = NVDClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        limiter=RateLimiter(6.1, clock=clock.time, sleep=clock.sleep),
    )
    async with client.http:
        with pytest.raises(NVDConnectionError, match="bounded retries"):
            await client.request({})
    assert count == 4
    assert 1 in clock.waits and 2 in clock.waits and 4 in clock.waits


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"vulnerabilities": {}},
        {"vulnerabilities": [None], "startIndex": 0, "totalResults": 1},
        {"vulnerabilities": [], "startIndex": 0, "totalResults": 1},
        {"vulnerabilities": [], "startIndex": 0, "totalResults": "bad"},
    ],
)
async def test_bad_structure(settings, payload, clock):
    client = NVDClient(
        settings,
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=payload)),
        sleep=clock.sleep,
        limiter=RateLimiter(6.1, clock=clock.time, sleep=clock.sleep),
    )
    async with client.http:
        with pytest.raises(NVDParseError):
            await client.fetch(SyncRequest(keyword="example"))


async def test_invalid_json_and_long_retry(settings, clock):
    for response, expected in [
        (httpx.Response(200, content=b"not-json"), NVDParseError),
        (httpx.Response(429, headers={"Retry-After": "121"}), NVDUpstreamError),
    ]:
        client = NVDClient(
            settings,
            transport=httpx.MockTransport(lambda req, response=response: response),
            sleep=clock.sleep,
            limiter=RateLimiter(6.1, clock=clock.time, sleep=clock.sleep),
        )
        async with client.http:
            with pytest.raises(expected):
                await client.request({})


async def test_pagination_and_limit(settings, envelope, clock):
    starts = []

    def handler(request):
        start = int(request.url.params["startIndex"])
        starts.append(start)
        return httpx.Response(200, json={**envelope, "startIndex": start, "totalResults": 10})

    client = NVDClient(
        settings,
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        limiter=RateLimiter(6.1, clock=clock.time, sleep=clock.sleep),
    )
    async with client.http:
        records = await client.fetch(SyncRequest(keyword="example", max_records=2))
    assert len(records) == 2 and starts == [0, 1]


def test_retry_after():
    assert retry_after(None) == retry_after("bad") == retry_after("nan") == 0
    assert retry_after("-1") == 0 and retry_after("15") == 15
    date = format_datetime(datetime.now(UTC) + timedelta(seconds=30), usegmt=True)
    assert 28 <= retry_after(date) <= 30

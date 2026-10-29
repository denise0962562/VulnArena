"""NVD 2.0 adapter. Unknown additive fields remain in the original CVE payload."""

import asyncio
import math
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from pydantic import ValidationError

from vulnarena.config import Settings
from vulnarena.schemas import Severity, SyncRequest, Vulnerability

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VERSIONS = [
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
]


class NVDError(Exception):
    """Safe diagnostic; never includes the API key or upstream response body."""


class NVDConnectionError(NVDError):
    pass


class NVDUpstreamError(NVDError):
    pass


class NVDParseError(NVDError):
    pass


def nvd_datetime(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("missing or invalid NVD timestamp")
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # NVD's timestamps without an offset denote UTC, never host local time.
    return date.replace(tzinfo=UTC) if date.tzinfo is None else date.astimezone(UTC)


def severity_for(score: float, version: str) -> Severity:
    if version == "2.0":
        return Severity.LOW if score < 4 else Severity.MEDIUM if score < 7 else Severity.HIGH
    if score == 0:
        return Severity.NONE
    if score < 4:
        return Severity.LOW
    if score < 7:
        return Severity.MEDIUM
    return Severity.HIGH if score < 9 else Severity.CRITICAL


def parse_cve(raw: dict[str, Any]) -> Vulnerability:
    warnings: list[str] = []
    descriptions = raw.get("descriptions", [])
    if not isinstance(descriptions, list):
        descriptions = []
        warnings.append("invalid descriptions structure")
    valid = [
        d
        for d in descriptions
        if isinstance(d, dict)
        and isinstance(d.get("value"), str)
        and d["value"].strip()
        and isinstance(d.get("lang"), str)
    ]
    description = next((d for d in valid if d["lang"].lower() == "en"), valid[0] if valid else {})
    if not description:
        warnings.append("description unavailable")
    metrics = raw.get("metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}
        warnings.append("invalid metrics structure; original retained in raw")
    references = raw.get("references", [])
    if not isinstance(references, list):
        references = []
        warnings.append("invalid references structure")
    refs = [r for r in references if isinstance(r, dict) and isinstance(r.get("url"), str)]
    if len(refs) != len(references):
        warnings.append("invalid reference entries ignored; original retained in raw")
    selected: dict[str, Any] = {}
    # Highest supported version first, then Primary, then NVD source, then stable source order.
    for key, version in VERSIONS:
        entries = metrics.get(key, [])
        if not isinstance(entries, list):
            warnings.append(f"invalid {key} structure")
            continue
        candidates = []
        for entry in entries:
            data = entry.get("cvssData") if isinstance(entry, dict) else None
            score = data.get("baseScore") if isinstance(data, dict) else None
            if (
                isinstance(score, bool)
                or not isinstance(score, (int, float))
                or not math.isfinite(score)
                or not 0 <= score <= 10
                or data.get("version") != version
            ):
                warnings.append(f"invalid {key} entry ignored")
                continue
            candidates.append(entry)
        if candidates and not selected:
            candidates.sort(
                key=lambda e: (
                    e.get("type") != "Primary",
                    e.get("source") != "nvd@nist.gov",
                    str(e.get("source", "")),
                )
            )
            data = candidates[0]["cvssData"]
            score = float(data["baseScore"])
            vector = data.get("vectorString")
            selected = dict(
                cvss_score=score,
                severity=severity_for(score, version),
                cvss_version=version,
                cvss_vector=vector if isinstance(vector, str) else None,
            )
    status = raw.get("vulnStatus")
    status = status if isinstance(status, str) else "UNKNOWN"
    if status.lower() == "rejected":
        selected = {}  # Retain the record and original metrics, suppress misleading active scores.
        warnings.append("rejected CVE; representative score suppressed")
    try:
        return Vulnerability(
            cve_id=raw.get("id"),
            description=description.get("value", ""),
            description_lang=description.get("lang"),
            published_at=nvd_datetime(raw.get("published")),
            last_modified_at=nvd_datetime(raw.get("lastModified")),
            vuln_status=status,
            metrics=metrics,
            references=refs,
            raw=raw,
            parse_warnings=warnings,
            **selected,
        )
    except (ValueError, ValidationError) as exc:
        raise NVDParseError("invalid CVE identifier or timestamps; page not imported") from exc


class RateLimiter:
    """One long-lived client per process; every retry is also paced."""

    def __init__(
        self,
        interval: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.interval, self.clock, self.sleep = interval, clock, sleep
        self.next_at = 0.0
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            delay = max(0.0, self.next_at - self.clock())
            if delay:
                await self.sleep(delay)
            self.next_at = self.clock() + self.interval


def retry_after(value: str | None) -> float:
    if not value:
        return 0
    try:
        delay = float(value)
    except ValueError:
        try:
            delay = (parsedate_to_datetime(value) - datetime.now(UTC)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return 0
    return max(0, delay) if math.isfinite(delay) else 0


class NVDClient:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        limiter: RateLimiter | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.settings, self.sleep = settings, sleep
        self.limiter = limiter or RateLimiter(settings.nvd_interval)
        key = settings.nvd_api_key.get_secret_value()
        self.http = httpx.AsyncClient(
            timeout=settings.nvd_timeout,
            transport=transport,
            headers={"apiKey": key} if key else {},
        )

    async def aclose(self) -> None:
        await self.http.aclose()

    async def request(self, params: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(self.settings.nvd_max_retries + 1):
            await self.limiter.wait()
            try:
                response = await self.http.get(NVD_URL, params=params)
            except httpx.RequestError as exc:
                if attempt == self.settings.nvd_max_retries:
                    raise NVDConnectionError("NVD connection failed after bounded retries") from exc
                await self.sleep(2**attempt)
                continue
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == self.settings.nvd_max_retries:
                    raise NVDUpstreamError(f"NVD HTTP {response.status_code}; retries exhausted")
                delay = max(2**attempt, retry_after(response.headers.get("Retry-After")))
                if delay > 120:
                    raise NVDUpstreamError("NVD Retry-After exceeds 120s; retry manually later")
                await self.sleep(delay)
                continue
            if response.status_code != 200:
                raise NVDUpstreamError(f"NVD HTTP {response.status_code}")
            try:
                payload = response.json()
            except ValueError as exc:
                raise NVDParseError("NVD returned invalid JSON") from exc
            if not isinstance(payload, dict) or not isinstance(
                payload.get("vulnerabilities"), list
            ):
                raise NVDParseError("NVD vulnerabilities must be an array")
            return payload
        raise AssertionError("unreachable")

    async def fetch(self, query: SyncRequest) -> list[Vulnerability]:
        records: list[Vulnerability] = []
        start = 0
        search: dict[str, Any] = (
            {"cveId": query.cve_id} if query.cve_id else {"keywordSearch": query.keyword}
        )
        if query.recent_days and not query.cve_id:
            end = datetime.now(UTC)
            search.update(
                pubStartDate=(end - timedelta(days=query.recent_days)).isoformat(),
                pubEndDate=end.isoformat(),
            )
        if query.latest and not query.cve_id:
            head = await self.request({**search, "startIndex": 0, "resultsPerPage": 1})
            total = head.get("totalResults")
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise NVDParseError("invalid pagination metadata")
            start = max(0, total - query.max_records)
        while len(records) < query.max_records:
            params: dict[str, Any] = {
                **search,
                "startIndex": start,
                "resultsPerPage": min(100, query.max_records - len(records)),
            }
            payload = await self.request(params)
            total = payload.get("totalResults")
            if (
                isinstance(total, bool)
                or not isinstance(total, int)
                or total < 0
                or payload.get("startIndex") != start
            ):
                raise NVDParseError("invalid pagination metadata")
            items = payload["vulnerabilities"]
            if not items and start < total:
                raise NVDParseError("unexpected empty NVD page")
            for item in items[: query.max_records - len(records)]:
                if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
                    raise NVDParseError("vulnerabilities entry must contain cve object")
                records.append(parse_cve(item["cve"]))
            start += len(items)
            if start >= total:
                return records
        return records

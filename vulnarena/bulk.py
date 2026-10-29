"""Verified, streaming readers for the official NVD JSON 2.0 year feeds."""

import gzip
import hashlib
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import httpx
import ijson

from vulnarena.nvd import NVDParseError, parse_cve, retry_after

FEED_ROOT = "https://nvd.nist.gov/feeds/json/cve/2.0"
MAX_GZIP_BYTES = 512 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class FeedMeta:
    sha256: str
    size: int
    gz_size: int
    modified: str

    @classmethod
    def parse(cls, text: str):
        values = dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
        try:
            digest = values["sha256"].strip().lower()
            size, gz_size = int(values["size"]), int(values["gzSize"])
        except (KeyError, ValueError) as exc:
            raise ValueError("invalid official NVD feed metadata") from exc
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("invalid feed SHA-256")
        if not (0 < size <= MAX_JSON_BYTES and 0 < gz_size <= MAX_GZIP_BYTES):
            raise ValueError("feed exceeds bounded download/decompression size")
        return cls(digest, size, gz_size, values.get("lastModifiedDate", ""))


class FeedDownloader:
    def __init__(self, directory: Path, *, transport=None):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.http = httpx.Client(
            timeout=httpx.Timeout(60, connect=15),
            follow_redirects=True,
            transport=transport,
            headers={"User-Agent": "VulnArena/0.2 (local NVD learning mirror)"},
        )

    def close(self):
        self.http.close()

    def metadata(self, year: int) -> FeedMeta:
        if not 2002 <= year <= 2100:
            raise ValueError("NVD feed year must be between 2002 and 2100")
        for attempt in range(3):
            try:
                response = self.http.get(f"{FEED_ROOT}/nvdcve-2.0-{year}.meta")
            except httpx.TransportError:
                if attempt == 2:
                    raise
                time.sleep(2**attempt)
                continue
            if response.status_code == 429 or response.status_code >= 500:
                delay = max(2**attempt, retry_after(response.headers.get("Retry-After")))
                if delay > 120 or attempt == 2:
                    response.raise_for_status()
                time.sleep(delay)
                continue
            response.raise_for_status()
            return FeedMeta.parse(response.text)
        raise RuntimeError("feed metadata retries exhausted")

    def obtain(self, year: int, meta: FeedMeta) -> Path:
        path = self.directory / f"{year}.json.gz"
        if path.exists():
            try:
                verify_feed(path, meta)
                return path
            except (ValueError, OSError, EOFError):
                pass  # Leave the old file in place until a verified replacement is ready.
        temporary = self.directory / f"{year}.json.gz.part"
        url = f"{FEED_ROOT}/nvdcve-2.0-{year}.json.gz"
        for attempt in range(3):
            try:
                if meta.gz_size > 2 * 1024 * 1024:
                    self._download_ranges(url, temporary, meta)
                    verify_feed(temporary, meta)
                    temporary.replace(path)
                    return path
                with self.http.stream("GET", url) as response:
                    if response.status_code == 429 or response.status_code >= 500:
                        delay = max(2**attempt, retry_after(response.headers.get("Retry-After")))
                        if delay > 120 or attempt == 2:
                            response.raise_for_status()
                        time.sleep(delay)
                        continue
                    response.raise_for_status()
                    written = 0
                    with temporary.open("wb") as output:
                        for chunk in response.iter_bytes(128 * 1024):
                            written += len(chunk)
                            if written > meta.gz_size or written > MAX_GZIP_BYTES:
                                raise ValueError("feed download exceeds declared gzip size")
                            output.write(chunk)
                verify_feed(temporary, meta)
                temporary.replace(path)
                return path
            except (httpx.TransportError, ValueError, OSError, EOFError) as exc:
                if isinstance(exc, (ValueError, OSError, EOFError)):
                    # Integrity errors invalidate the partial file; transient network
                    # errors keep its already received ranges for the next attempt.
                    temporary.unlink(missing_ok=True)
                if attempt == 2:
                    raise
                time.sleep(2**attempt)
        raise RuntimeError("feed download retries exhausted")

    def _download_ranges(self, url: str, path: Path, meta: FeedMeta):
        chunk_size = 1024 * 1024
        offset = path.stat().st_size if path.exists() else 0
        if offset > meta.gz_size:
            path.unlink()
            offset = 0

        def download_range(start, end):
            with self.http.stream(
                "GET",
                url,
                headers={"Range": f"bytes={start}-{end}"},
                timeout=httpx.Timeout(30, connect=15),
            ) as response:
                if response.status_code == 429 or response.status_code >= 500:
                    delay = max(1, retry_after(response.headers.get("Retry-After")))
                    if delay <= 120:
                        time.sleep(delay)
                    response.raise_for_status()
                response.raise_for_status()
                expected_range = f"bytes {start}-{end}/{meta.gz_size}"
                if (
                    response.status_code != 206
                    or response.headers.get("content-range") != expected_range
                ):
                    raise ValueError("server did not honor the exact bounded byte range")
                data = bytearray()
                deadline = time.monotonic() + 60
                for chunk in response.iter_bytes(64 * 1024):
                    data.extend(chunk)
                    if len(data) > end - start + 1 or time.monotonic() > deadline:
                        raise ValueError("range size/time bound exceeded")
                if len(data) != end - start + 1:
                    raise httpx.ReadError("incomplete feed range")
                return data

        # Two network transfers at most; decoded records and database writes remain
        # single-stream. Append only contiguous ranges, so interruption is resumable.
        with ThreadPoolExecutor(max_workers=2) as pool, path.open("ab") as output:
            while offset < meta.gz_size:
                futures = []
                for start in range(offset, min(meta.gz_size, offset + 2 * chunk_size), chunk_size):
                    end = min(meta.gz_size - 1, start + chunk_size - 1)
                    futures.append(pool.submit(download_range, start, end))
                for future in futures:
                    data = future.result()
                    output.write(data)
                    output.flush()
                    offset += len(data)
                if offset % (8 * chunk_size) < 2 * chunk_size or offset == meta.gz_size:
                    print(f"Download {path.stem}: {offset}/{meta.gz_size} bytes", flush=True)


def verify_feed(path: Path, meta: FeedMeta) -> None:
    if path.stat().st_size != meta.gz_size:
        raise ValueError("gzip size does not match official metadata")
    digest = hashlib.sha256()
    size = 0
    with gzip.open(path, "rb") as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            if size > meta.size or size > MAX_JSON_BYTES:
                raise ValueError("decompressed feed exceeds official size")
            digest.update(block)
    # NVD publishes the SHA-256 of the uncompressed JSON, not the .gz file.
    if size != meta.size or digest.hexdigest() != meta.sha256:
        raise ValueError("feed JSON size or SHA-256 mismatch; no import allowed")


def feed_header(path: Path) -> dict:
    header = {}
    with gzip.open(path, "rb") as stream:
        for prefix, event, value in ijson.parse(stream, use_float=True):
            if prefix == "vulnerabilities" and event == "start_array":
                break
            if "." not in prefix and event in {"string", "number"}:
                header[prefix] = value
    total = header.get("totalResults")
    if (
        header.get("format") != "NVD_CVE"
        or header.get("version") != "2.0"
        or not isinstance(total, int)
        or isinstance(total, bool)
        or total < 0
    ):
        raise ValueError("unsupported NVD feed envelope")
    return header


def feed_batches(path: Path, batch_size: int = 500, *, skip: int = 0):
    """Memory stays bounded to one small batch, including while resuming a feed."""
    if not 1 <= batch_size <= 1000 or skip < 0:
        raise ValueError("invalid feed batch size or cursor")
    batch = []
    count = 0
    with gzip.open(path, "rb") as stream:
        for index, item in enumerate(ijson.items(stream, "vulnerabilities.item", use_float=True)):
            count = index + 1
            if index < skip:
                continue
            if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
                raise NVDParseError("feed entry must contain a CVE object")
            batch.append(parse_cve(item["cve"]))
            if len(batch) == batch_size:
                yield count, batch
                batch = []
    if batch:
        yield count, batch
    if skip > count:
        raise ValueError("saved cursor exceeds feed record count")


def next_batch(iterator):
    # StopIteration cannot propagate through asyncio.to_thread's Future.
    return next(iterator, None)

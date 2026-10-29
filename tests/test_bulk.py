import gzip
import hashlib
import json
import random
import re
from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from scripts.refresh_library import candidate_query
from vulnarena.bulk import FeedDownloader, FeedMeta, feed_batches, feed_header, verify_feed
from vulnarena.db import CVE, Revision
from vulnarena.nvd import NVDParseError, parse_cve


def feed_file(tmp_path, raw_cve, *, count=3):
    items = []
    for index in range(count):
        items.append({"cve": {**raw_cve, "id": f"CVE-2024-{1000 + index}"}})
    payload = {
        "format": "NVD_CVE",
        "version": "2.0",
        "totalResults": count,
        "startIndex": 0,
        "resultsPerPage": count,
        "vulnerabilities": items,
    }
    data = json.dumps(payload).encode()
    compressed = gzip.compress(data)
    path = tmp_path / "2024.json.gz"
    path.write_bytes(compressed)
    meta = FeedMeta(hashlib.sha256(data).hexdigest(), len(data), len(compressed), "now")
    return path, meta, data


def test_official_metadata_checksum_and_stream_resume(tmp_path, raw_cve):
    path, meta, data = feed_file(tmp_path, raw_cve)
    parsed = FeedMeta.parse(
        f"size:{meta.size}\r\ngzSize:{meta.gz_size}\r\nsha256:{meta.sha256.upper()}\n"
    )
    verify_feed(path, parsed)
    assert feed_header(path)["totalResults"] == 3
    batches = list(feed_batches(path, 2))
    assert [position for position, _ in batches] == [2, 3]
    resumed = list(feed_batches(path, 2, skip=2))
    assert len(resumed) == 1 and resumed[0][1][0].cve_id == "CVE-2024-1002"
    assert list(feed_batches(path, 2, skip=3)) == []
    with pytest.raises(ValueError, match="cursor exceeds"):
        list(feed_batches(path, 2, skip=4))
    with pytest.raises(ValueError, match="SHA-256"):
        verify_feed(path, FeedMeta("0" * 64, len(data), meta.gz_size, ""))
    assert batches[0][1][0].raw["futureField"] == {"preserve": True}


@pytest.mark.parametrize(
    "metadata", ["", "size:1\ngzSize:2\nsha256:bad", "size:0\ngzSize:2\nsha256:" + "0" * 64]
)
def test_invalid_metadata_never_reaches_import(metadata):
    with pytest.raises(ValueError):
        FeedMeta.parse(metadata)


def test_metadata_retries_transient_connections_and_server_errors(tmp_path, monkeypatch):
    attempts = []
    monkeypatch.setattr("vulnarena.bulk.time.sleep", lambda seconds: None)

    def handler(request):
        attempts.append(request)
        if len(attempts) == 1:
            raise httpx.ConnectError("temporary connection failure")
        if len(attempts) == 2:
            return httpx.Response(503, headers={"Retry-After": "0"})
        return httpx.Response(200, text="size:1\ngzSize:1\nsha256:" + "a" * 64)

    downloader = FeedDownloader(tmp_path, transport=httpx.MockTransport(handler))
    try:
        assert downloader.metadata(2024).sha256 == "a" * 64
        assert len(attempts) == 3
    finally:
        downloader.close()


def test_verified_download_is_cached_and_corruption_is_replaced(tmp_path, raw_cve):
    source, meta, _ = feed_file(tmp_path, raw_cve)
    body = source.read_bytes()
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, content=body)

    downloader = FeedDownloader(tmp_path / "cache", transport=httpx.MockTransport(handler))
    try:
        path = downloader.obtain(2024, meta)
        assert path.read_bytes() == body
        assert downloader.obtain(2024, meta) == path and len(calls) == 1
        path.write_bytes(b"truncated")
        assert downloader.obtain(2024, meta).read_bytes() == body and len(calls) == 2
    finally:
        downloader.close()


def test_invalid_feed_entry_is_reported_not_silently_skipped(tmp_path, raw_cve):
    path, _, _ = feed_file(tmp_path, raw_cve)
    payload = json.loads(gzip.decompress(path.read_bytes()))
    payload["vulnerabilities"][1]["cve"]["id"] = "not-a-CVE"
    path.write_bytes(gzip.compress(json.dumps(payload).encode()))
    with pytest.raises(NVDParseError):
        list(feed_batches(path))
    payload["format"] = "legacy"
    path.write_bytes(gzip.compress(json.dumps(payload).encode()))
    with pytest.raises(ValueError, match="envelope"):
        feed_header(path)


def test_range_download_resumes_contiguous_bytes_and_checks_range_headers(tmp_path):
    original = random.Random(42).randbytes(3 * 1024 * 1024)
    compressed = gzip.compress(original)
    meta = FeedMeta(hashlib.sha256(original).hexdigest(), len(original), len(compressed), "")
    part = tmp_path / "partial.gz"
    part.write_bytes(compressed[:1234])
    requested = []

    def handler(request):
        match = re.fullmatch(r"bytes=(\d+)-(\d+)", request.headers["Range"])
        start, end = map(int, match.groups())
        requested.append((start, end))
        return httpx.Response(
            206,
            content=compressed[start : end + 1],
            headers={
                "Content-Range": f"bytes {start}-{end}/{len(compressed)}",
            },
        )

    downloader = FeedDownloader(tmp_path, transport=httpx.MockTransport(handler))
    try:
        downloader._download_ranges("https://nvd.nist.gov/example.gz", part, meta)
        assert part.read_bytes() == compressed
        verify_feed(part, meta)
        assert min(start for start, _ in requested) == 1234
    finally:
        downloader.close()
    part.unlink()
    downloader = FeedDownloader(
        tmp_path,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                206, content=b"wrong", headers={"Content-Range": "bytes 0-4/5"}
            )
        ),
    )
    try:
        with pytest.raises(ValueError, match="exact bounded byte range"):
            downloader._download_ranges("https://nvd.nist.gov/example.gz", part, meta)
    finally:
        downloader.close()


async def test_bulk_atomic_checkpoint_deduplication_and_newer_guard(db, raw_cve):
    item = parse_cve(raw_cve)
    newer = item.model_copy(
        update={"description": "Newer", "last_modified_at": datetime(2026, 1, 1, tzinfo=UTC)}
    )
    checkpoint = {"sha256": "a" * 64, "processed": 2, "status": "running"}
    assert await db.upsert_many([newer, item, newer], feed_state=(2024, checkpoint)) == 1
    assert (await db.get(item.cve_id)).description == "Newer"
    assert await db.get_feed_state(2024) == checkpoint
    assert await db.upsert_many([item]) == 0
    assert (await db.get(item.cve_id)).description == "Newer"
    assert await db.upsert_many([], feed_state=(2024, {**checkpoint, "status": "complete"})) == 0
    assert (await db.get_feed_state(2024))["status"] == "complete"
    async with db.sessions() as session:
        assert await session.scalar(select(Revision.value)) == 1


async def test_bulk_failure_rolls_back_all_chunks_and_cursor(db, raw_cve):
    item = parse_cve(raw_cve)
    records = [
        item.model_copy(update={"cve_id": f"CVE-2024-{1000 + index}"}) for index in range(105)
    ]
    records[-1] = records[-1].model_copy(update={"description": None})
    with pytest.raises(IntegrityError):
        await db.upsert_many(records, feed_state=(2024, {"processed": 105}))
    assert await db.get_feed_state(2024) == {}
    async with db.sessions() as session:
        assert await session.scalar(select(func.count()).select_from(CVE)) == 0
        assert await session.scalar(select(Revision.value)) == 0


async def test_unenriched_detail_exposes_existing_nvd_versions_and_cwe(api, raw_cve):
    client, app = api
    raw_cve["weaknesses"] = [{"description": [{"lang": "en", "value": "CWE-79"}]}]
    raw_cve["configurations"] = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:example:library:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "2.0",
                        }
                    ]
                }
            ]
        }
    ]
    await app.state.db.upsert([parse_cve(raw_cve)])
    detail = (await client.get("/api/vulnerabilities/" + raw_cve["id"])).json()
    assert detail["study"]["status"] == "pending"
    assert detail["study"]["weaknesses"] == ["CWE-79"]
    assert detail["study"]["affected"][0]["versionEndExcluding"] == "2.0"


async def test_enrichment_candidates_are_bounded_and_skip_fully_translated_material(db, raw_cve):
    record = parse_cve(raw_cve)
    identifiers = ["CVE-2024-1234", "CVE-2024-1235", "CVE-2024-1236", "CVE-2021-44228"]
    await db.upsert_many(
        [record.model_copy(update={"cve_id": identifier}) for identifier in identifiers]
    )
    await db.save_study(
        identifiers[0],
        {
            "translation_status": "complete",
            "document_count": 1,
            "status": "partial",
            "documents": [{"translation_status": "complete"}],
            "errors": ["optional source missing"],
        },
    )
    await db.save_study(
        identifiers[2],
        {
            "translation_status": "complete",
            "document_count": 1,
            "documents": [{"translation_status": "failed"}],
        },
    )
    async with db.read_sessions() as session:
        all_missing = list(await session.scalars(candidate_query(10, only_missing=True)))
        assert {r.cve_id for r in all_missing} == set(identifiers[1:])
        chosen = list(
            await session.scalars(
                candidate_query(
                    2,
                    only_missing=True,
                    advisory_ids=[identifiers[2]],
                )
            )
        )
        assert [r.cve_id for r in chosen] == ["CVE-2021-44228", identifiers[2]]

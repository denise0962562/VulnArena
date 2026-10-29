import io
import zipfile
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from vulnarena.nvd import NVDClient, RateLimiter, parse_cve
from vulnarena.offline_translation import OfflineTranslator
from vulnarena.schemas import SyncRequest
from vulnarena.study import ArticleParser, SourceError, StudyCollector, allowed_url, study_bundle
from vulnarena.study_contract import record_fingerprint, study_matches


def memory_db():
    translations = {}
    db = AsyncMock()
    db.get_study.return_value = {}
    db.get_translation.side_effect = lambda digest: translations.get(digest)
    db.save_translation.side_effect = lambda digest, text: translations.update({digest: text})
    return db


@pytest.mark.parametrize(
    "url",
    [
        "http://apache.org/advisory",
        "https://127.0.0.1/advisory",
        "https://localhost/",
        "https://apache.org.evil.test/",
        "https://user:pass@apache.org/",
        "https://apache.org:8443/",
        "file:///etc/passwd",
        "https://apache.org:bad/",
    ],
)
def test_reference_allowlist_blocks_unsafe_targets(url):
    assert not allowed_url(url)


def test_article_extraction_and_safe_bundle(raw_cve):
    parser = ArticleParser()
    parser.feed(
        "<title>Advisory</title><nav>menu</nav><main><h1>Issue</h1>"
        "<script>alert(1)</script><p>" + "Explanation. " * 30 + "</p></main>"
    )
    title, text = parser.result()
    assert title == "Advisory" and "Explanation" in text
    assert "alert" not in text and "menu" not in text
    archive = zipfile.ZipFile(
        io.BytesIO(
            study_bundle(
                parse_cve(raw_cve),
                {
                    "description_zh": "漏洞说明",
                    "documents": [
                        {
                            "title": "../../escape",
                            "text_en": "Original",
                            "text_zh": "译文",
                            "url": "https://apache.org/security",
                        }
                    ],
                },
            )
        )
    )
    assert "漏洞说明" in archive.read("README.md").decode()
    assert archive.read("articles/01.zh.md").decode().endswith("译文")
    assert all(".." not in name for name in archive.namelist())


def test_linked_changelog_section_does_not_download_unrelated_versions():
    parser = ArticleParser()
    parser.feed(
        '<main><h2 id="8.5">New unrelated release</h2><p>Other issue</p>'
        '<h2 id="8.1.29">PHP 8.1.29</h2><p>Fix CVE-2024-4577</p>'
        '<h2 id="8.1.28">Older unrelated release</h2><p>Other changes</p></main>'
    )
    _, text = parser.result("8.1.29")
    assert "CVE-2024-4577" in text and "unrelated" not in text
    with pytest.raises(SourceError, match="section not present"):
        parser.result("missing-section")


def test_source_fingerprint_survives_jsonb_key_reordering(raw_cve):
    record = parse_cve(raw_cve)
    reordered = record.model_copy(update={"raw": dict(reversed(list(raw_cve.items())))})
    assert record_fingerprint(record) == record_fingerprint(reordered)
    study = {"fingerprint": record_fingerprint(record)}
    assert study_matches(reordered, study)
    changed = record.model_copy(update={"description": "Corrected at the same source timestamp"})
    assert not study_matches(changed, study)
    archive = zipfile.ZipFile(io.BytesIO(study_bundle(changed, study)))
    assert "SOURCE-UPDATED.txt" in archive.namelist()


async def test_translation_cache_and_failure_are_explicit():
    db = memory_db()
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=[[["中文翻译", "English"]]])

    collector = StudyCollector(db, transport=httpx.MockTransport(handler), online_translation=True)
    try:
        first = await collector.translate("English")
        second = await collector.translate("English")
        assert first["text"] == second["text"] == "中文翻译" and len(calls) == 1
    finally:
        await collector.aclose()
    collector = StudyCollector(
        db, transport=httpx.MockTransport(lambda r: httpx.Response(429)), online_translation=True
    )
    try:
        result = await collector.translate("Uncached")
        assert result["status"] == "failed" and result["text"] == ""
        db.save_translation.assert_awaited_once()
    finally:
        await collector.aclose()


async def test_cna_github_versions_article_and_translation(raw_cve):
    raw_cve["description"] = "Python vulnerability"
    raw_cve["references"] = [{"url": "https://www.apache.org/security/example"}]
    db = memory_db()
    cna = {
        "cveMetadata": {"cveId": raw_cve["id"]},
        "containers": {
            "cna": {
                "title": "Python issue",
                "affected": [
                    {
                        "vendor": "Python",
                        "product": "Example",
                        "versions": [{"version": "1.0", "lessThan": "2.0", "status": "affected"}],
                    }
                ],
                "descriptions": [{"lang": "en", "value": "English description"}],
                "solutions": [{"lang": "en", "value": "Upgrade to 2.0"}],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}]}],
            }
        },
    }

    def handler(request):
        if request.url.host == "translate.googleapis.com":
            return httpx.Response(200, json=[[["中文翻译", "original"]]])
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nAllow: /")
        if request.url.host in {"cveawg.mitre.org", "raw.githubusercontent.com"}:
            return httpx.Response(200, json=cna)
        return httpx.Response(
            200,
            text="<main>" + "Detailed advisory. " * 40 + "</main>",
            headers={"content-type": "text/html"},
        )

    advisory = {
        "cve_id": raw_cve["id"],
        "summary": "Example package issue",
        "html_url": "https://github.com/advisories/GHSA-1111-2222-3333",
        "description": "# Impact\nFull explanation and patched versions.",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "example"},
                "vulnerable_version_range": "<2",
                "first_patched_version": "2",
            }
        ],
    }
    collector = StudyCollector(db, transport=httpx.MockTransport(handler), online_translation=True)
    try:
        study = await collector.collect(parse_cve(raw_cve), advisories=[advisory], references=1)
    finally:
        await collector.aclose()
    assert study["status"] == "complete" and study["document_count"] == 3
    assert study["description_zh"] == "中文翻译" and "Python" in study["topics"]
    assert study["affected"][0]["versions"][0]["lessThan"] == "2.0"
    assert study["affected"][1]["fixed"] == "2" and "CWE-79" in study["weaknesses"]
    assert len(study["cna_raw"]["containers"]["cna"]["affected"]) == 1
    assert study["github_raw"] == [advisory]
    assert all(doc["text_zh"] and doc["sha256"] for doc in study["documents"])
    assert db.save_study.await_count == 3


async def test_download_redirect_robots_and_size_limits():
    def handler(request):
        if request.url.path == "/redirect":
            return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /private")
        return httpx.Response(200, text="X" * 2_000_001)

    collector = StudyCollector(
        memory_db(), transport=httpx.MockTransport(handler), online_translation=True
    )
    try:
        for path, message in [
            ("redirect", "allowlist"),
            ("private", "disallows"),
            ("large", "2 MB"),
        ]:
            with pytest.raises(SourceError, match=message):
                await collector.download("https://www.apache.org/" + path)
    finally:
        await collector.aclose()


async def test_study_persistence_search_topic_and_export(api, raw_cve):
    client, app = api
    await app.state.db.upsert([parse_cve(raw_cve)])
    initial = (await client.get("/api/vulnerabilities")).json()
    assert "raw" not in initial["items"][0]
    await app.state.db.save_study(
        raw_cve["id"],
        {
            "title": "Example",
            "description_zh": "中文漏洞详解",
            "topics": ["Rust"],
            "documents": [{"text_en": "Detailed original", "text_zh": "详细译文"}],
            "document_count": 1,
        },
    )
    result = (await client.get("/api/vulnerabilities?keyword=中文&topic=Rust")).json()
    assert result["total"] == 1 and result["items"][0]["study"]["description_zh"] == "中文漏洞详解"
    assert "documents" not in result["items"][0]["study"]
    detail = (await client.get("/api/vulnerabilities/" + raw_cve["id"])).json()
    assert detail["study"]["documents"][0]["text_en"] == "Detailed original"
    export = await client.get("/api/vulnerabilities/" + raw_cve["id"] + "/download")
    assert export.status_code == 200 and "application/zip" in export.headers["content-type"]
    assert zipfile.is_zipfile(io.BytesIO(export.content))
    assert (await client.get("/api/vulnerabilities?topic=invalid")).status_code == 422
    assert (await client.get("/api/vulnerabilities/CVE-2000-0000/download")).status_code == 404


async def test_enrich_task_does_not_refetch_nvd(api, raw_cve, monkeypatch):
    client, app = api
    await app.state.db.upsert([parse_cve(raw_cve)])
    collect = AsyncMock(return_value={"status": "partial"})
    monkeypatch.setattr(app.state.sync.collector, "collect", collect)
    response = await client.post("/api/vulnerabilities/" + raw_cve["id"] + "/enrich")
    assert response.status_code == 202
    task = (await client.get("/api/tasks/" + response.json()["id"])).json()
    assert task["status"] == "SUCCESS" and task["processed"] == 1
    collect.assert_awaited_once()
    assert (await client.post("/api/vulnerabilities/CVE-2000-0000/enrich")).status_code == 404


async def test_latest_nvd_search_keeps_date_filter_on_probe_and_pages(settings, envelope, clock):
    queries = []

    def handler(request):
        queries.append(dict(request.url.params))
        start = int(request.url.params.get("startIndex", 0))
        return httpx.Response(200, json={**envelope, "startIndex": start, "totalResults": 10})

    client = NVDClient(
        settings,
        transport=httpx.MockTransport(handler),
        limiter=RateLimiter(6.1, clock=clock.time, sleep=clock.sleep),
    )
    try:
        records = await client.fetch(
            SyncRequest(keyword="Python", max_records=2, latest=True, recent_days=30)
        )
    finally:
        await client.aclose()
    assert len(records) == 2
    assert [q["startIndex"] for q in queries] == ["0", "8", "9"]
    assert len({q["pubStartDate"] for q in queries}) == 1
    assert len({q["pubEndDate"] for q in queries}) == 1


def test_offline_translation_preserves_code_and_does_not_drop_long_inputs(monkeypatch):
    import sys

    batches = []

    class Tokenizer:
        def __init__(self, **kwargs):
            pass

        def encode(self, text, **kwargs):
            return list(text)

        def decode(self, tokens):
            return "".join(tokens)

    class Model:
        def __init__(self, *args, **kwargs):
            if kwargs["device"] == "cuda":
                raise RuntimeError("CUDA runtime missing")

        def translate_batch(self, segments, **kwargs):
            batches.extend(segments)
            return [SimpleNamespace(hypotheses=[["译"]]) for _ in segments]

    monkeypatch.setitem(
        sys.modules,
        "ctranslate2",
        SimpleNamespace(
            Translator=Model,
            get_cuda_device_count=lambda: 1,
        ),
    )
    monkeypatch.setitem(
        sys.modules, "sentencepiece", SimpleNamespace(SentencePieceProcessor=Tokenizer)
    )
    model = OfflineTranslator("unused-model")
    result = model.translate("A" * 500 + "\n```python\nprint('code')\n```\nEnd")
    assert model.device == "cpu"
    assert "print('code')" in result and "```python" in result
    assert sum(map(len, batches)) == 503
    assert result.startswith("译译译") and result.endswith("译")
    batches.clear()
    results = model.translate_many(["A" * 300, "Second\n```\nuntouched\n```\n", ""])
    assert results == ["译译", "译\n```\nuntouched\n```\n", ""]
    assert sum(map(len, batches)) == 306
    batches.clear()
    diagram = "...\n\tret\nfunc:\np|      REG_L ra, -SZREG(sp)\n0.3.1"
    assert model.translate(diagram) == diagram
    assert batches == []
    model.model.translate_batch = lambda segments, **kw: [
        SimpleNamespace(hypotheses=[["X"] * 1024 if index == 0 else ["译"]])
        for index, _ in enumerate(segments)
    ]
    assert model.translate_many(["First", "Second"], allow_partial=True) == ["", "译"]
    with pytest.raises(ValueError, match="decoding limit"):
        model.translate_many(["First", "Second"])


async def test_offline_translation_missing_model_is_explicit():
    collector = StudyCollector(memory_db(), translation_model="nonexistent-test-model")
    try:
        result = await collector.translate("English")
        assert result["status"] == "failed" and result["text"] == ""
    finally:
        await collector.aclose()

import asyncio
from datetime import UTC, datetime
from types import SimpleNamespace

from sqlalchemy import select

from vulnarena.db import ChineseDescription
from vulnarena.descriptions import DescriptionTranslator
from vulnarena.nvd import parse_cve
from vulnarena.study_contract import description_fingerprint, merge_description, record_fingerprint


async def test_chinese_is_bound_to_description_not_unrelated_metadata(db, raw_cve):
    record = parse_cve(raw_cve)
    await db.upsert([record])
    payload = {
        "cve_id": record.cve_id,
        "source_sha256": description_fingerprint(record.description),
        "text_zh": "这是中文漏洞说明",
        "provider": "test",
        "translated_at": datetime.now(UTC),
    }
    assert await db.save_chinese([payload]) == 1
    revised = record.model_copy(update={"severity": record.severity, "cvss_score": 5.0})
    await db.upsert([revised])
    study = {"fingerprint": record_fingerprint(record), "description_zh": "旧译文"}
    view = merge_description(revised, study, await db.get_chinese(record.cve_id))
    assert view["stale"] and not view["description_stale"]
    assert view["description_zh"] == "这是中文漏洞说明"
    changed = revised.model_copy(update={"description": "A new corrected description"})
    await db.upsert([changed])
    assert await db.save_chinese([payload]) == 0
    view = merge_description(changed, study, await db.get_chinese(record.cve_id))
    assert view["description_stale"] and view["description_zh"] == "旧译文"


async def test_batched_translation_deduplicates_text_and_reuses_cache(db, raw_cve, monkeypatch):
    record = parse_cve(raw_cve)
    other = record.model_copy(update={"cve_id": "CVE-2024-1235"})
    await db.upsert_many([record, other])
    calls = []

    def translate_many(texts, **kwargs):
        calls.append(texts)
        return ["已翻译的中文描述" for text in texts]

    monkeypatch.setattr(
        "vulnarena.descriptions.load_translator",
        lambda path: SimpleNamespace(translate_many=translate_many),
    )
    translator = DescriptionTranslator(db, "unused")
    rows = [{"cve_id": item.cve_id, "description": item.description} for item in [record, other]]
    result = await translator.translate_rows(rows)
    assert result["saved"] == 2 and not result["errors"]
    assert calls == [[record.description]]
    assert (await translator.translate_rows(rows))["saved"] == 2
    assert len(calls) == 1
    async with db.read_sessions() as session:
        assert len(list(await session.scalars(select(ChineseDescription)))) == 2


async def test_year_coverage_counts_only_current_chinese(db, raw_cve):
    record = parse_cve(raw_cve)
    records = [
        record.model_copy(update={"cve_id": f"CVE-{year}-1234"})
        for year in [2019, 2020, 2026, 2027]
    ]
    await db.upsert_many(records)
    await db.save_chinese(
        [
            {
                "cve_id": records[1].cve_id,
                "source_sha256": description_fingerprint(record.description),
                "text_zh": "中文",
                "provider": "test",
                "translated_at": datetime.now(UTC),
            }
        ]
    )
    assert await db.year_coverage() == [
        {"year": 2020, "total": 1, "translated": 1, "pending": 0},
        {"year": 2026, "total": 1, "translated": 0, "pending": 1},
    ]


async def test_year_api_filters_cache_and_on_demand_summary(api, raw_cve, monkeypatch):
    client, app = api
    record = parse_cve(raw_cve)
    records = [
        record.model_copy(update={"cve_id": f"CVE-{year}-1234"})
        for year in [2019, 2020, 2026, 2027]
    ]
    await app.state.db.upsert_many(records)
    assert (await client.get("/api/vulnerabilities?year_from=2020&year_to=2026")).json()[
        "total"
    ] == 2
    assert (await client.get("/api/vulnerabilities?year_from=2020&year_to=2020")).json()[
        "total"
    ] == 1
    assert (await client.get("/api/vulnerabilities?year_from=2026&year_to=2020")).status_code == 422
    monkeypatch.setattr(
        "vulnarena.descriptions.load_translator",
        lambda path: SimpleNamespace(
            translate_many=lambda texts, **kwargs: ["这是自动生成的中文说明" for _ in texts],
        ),
    )
    assert (await client.post("/api/vulnerabilities/CVE-2026-1234/translate")).status_code == 202
    for _ in range(100):
        status = (await client.get("/api/vulnerabilities/CVE-2026-1234/translation")).json()[
            "status"
        ]
        if status == "complete":
            break
        await asyncio.sleep(0.01)
    assert status == "complete"
    detail = (await client.get("/api/vulnerabilities/CVE-2026-1234")).json()
    assert detail["study"]["description_zh"] == "这是自动生成的中文说明"
    assert not detail["study"]["description_stale"]
    assert (await client.get("/api/vulnerabilities?keyword=自动生成")).json()["total"] == 1
    assert (await client.post("/api/vulnerabilities/CVE-2020-99999/translate")).status_code == 404


async def test_invalid_fast_decode_retries_with_accurate_decoder(db, raw_cve, monkeypatch):
    record = parse_cve(raw_cve)
    await db.upsert([record])
    model = SimpleNamespace(
        translate_many=lambda texts, **kw: ["English only" for _ in texts],
        translate=lambda source: "重试后的正确中文",
    )
    monkeypatch.setattr("vulnarena.descriptions.load_translator", lambda path: model)
    result = await DescriptionTranslator(db, "unused").translate_rows(
        [{"cve_id": record.cve_id, "description": record.description}]
    )
    assert result["saved"] == 1 and result["errors"] == []

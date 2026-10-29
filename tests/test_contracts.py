import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnarena.config import Settings
from vulnarena.nvd import NVDParseError, nvd_datetime, parse_cve
from vulnarena.schemas import SyncRequest, Vulnerability


def test_official_response_snapshot():
    raw = json.loads(
        (Path(__file__).parent / "fixtures/nvd-cve-2021-44228.json").read_text(encoding="utf-8")
    )
    item = parse_cve(raw)
    assert item.cve_id == raw["id"]
    assert item.cvss_score == raw["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
    assert item.metrics == raw["metrics"]
    assert item.references == raw["references"]
    assert item.parse_warnings == []


def test_contract_roundtrip(raw_cve):
    item = parse_cve(raw_cve)
    assert item.description_lang == "en"
    assert item.cvss_score == 9.8 and item.severity == "CRITICAL"
    assert item.cvss_version == "3.1" and item.cvss_vector.startswith("CVSS:3.1")
    assert item.published_at.tzinfo == UTC
    assert item.references[0]["tags"] == ["Patch"]
    assert item.raw["futureField"]["preserve"] is True
    assert Vulnerability.model_validate_json(item.model_dump_json()) == item


def test_timezone_and_contract_reject_naive(raw_cve):
    assert nvd_datetime("2024-01-01T08:00:00+08:00") == datetime(2024, 1, 1, tzinfo=UTC)
    values = parse_cve(raw_cve).model_dump()
    values["published_at"] = datetime(2024, 1, 1)
    with pytest.raises(ValidationError):
        Vulnerability(**values)
    values["published_at"] = datetime.now(UTC)
    values["cvss_score"] = float("nan")
    with pytest.raises(ValidationError):
        Vulnerability(**values)


@pytest.mark.parametrize(
    "metrics",
    [
        None,
        {},
        [],
        {"cvssMetricV40": {}},
        {"cvssMetricV31": [None, {"cvssData": {"baseScore": "bad"}}]},
        {"cvssMetricV31": [{"cvssData": {"baseScore": True}}]},
    ],
)
def test_unscored_or_malformed_metrics(raw_cve, metrics):
    raw_cve["metrics"] = metrics
    item = parse_cve(raw_cve)
    assert item.cvss_score is None and item.severity == "UNKNOWN"
    assert item.cvss_version is None and item.raw["metrics"] == metrics


@pytest.mark.parametrize(
    "version,key,score,severity",
    [
        ("4.0", "cvssMetricV40", 0, "NONE"),
        ("3.1", "cvssMetricV31", 3.9, "LOW"),
        ("3.0", "cvssMetricV30", 5, "MEDIUM"),
        ("2.0", "cvssMetricV2", 10, "HIGH"),
        ("2.0", "cvssMetricV2", 0, "LOW"),
        ("2.0", "cvssMetricV2", 5, "MEDIUM"),
        ("4.0", "cvssMetricV40", 8, "HIGH"),
    ],
)
def test_versions(raw_cve, version, key, score, severity):
    raw_cve["metrics"] = {key: [{"cvssData": {"version": version, "baseScore": score}}]}
    item = parse_cve(raw_cve)
    assert (item.cvss_version, item.cvss_score, item.severity) == (version, score, severity)


def test_priority_and_preservation(raw_cve):
    raw_cve["metrics"]["cvssMetricV40"] = [
        {
            "source": "nvd@nist.gov",
            "type": "Secondary",
            "cvssData": {"version": "4.0", "baseScore": 9},
        },
        {"source": "cna", "type": "Primary", "cvssData": {"version": "4.0", "baseScore": 7}},
        {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {"version": "4.0", "baseScore": 8},
        },
    ]
    item = parse_cve(raw_cve)
    assert item.cvss_version == "4.0" and item.cvss_score == 8
    assert len(item.metrics["cvssMetricV40"]) == 3
    assert "cvssMetricV31" in item.metrics


def test_languages_missing_and_rejected(raw_cve):
    raw_cve["descriptions"] = [{"lang": "zh-CN", "value": "漏洞描述"}]
    assert parse_cve(raw_cve).description == "漏洞描述"
    raw_cve["descriptions"] = None
    raw_cve["references"] = [None, {"url": "https://example.org"}]
    raw_cve["vulnStatus"] = "Rejected"
    item = parse_cve(raw_cve)
    assert item.description == "" and item.cvss_score is None
    assert item.metrics and item.vuln_status == "Rejected" and len(item.references) == 1
    assert len(item.parse_warnings) >= 3
    raw_cve["references"] = None
    raw_cve["vulnStatus"] = None
    assert parse_cve(raw_cve).vuln_status == "UNKNOWN"


@pytest.mark.parametrize(
    "field,value", [("id", "BAD"), ("published", None), ("lastModified", "nonsense")]
)
def test_missing_critical_fields(raw_cve, field, value):
    raw_cve[field] = value
    with pytest.raises(NVDParseError):
        parse_cve(raw_cve)


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"keyword": " "},
        {"cve_id": "BAD"},
        {"keyword": "test", "max_records": 1001},
        {"keyword": "x", "cve_id": "CVE-2024-1234"},
        {"keyword": "x", "unexpected": 1},
    ],
)
def test_sync_contract(kwargs):
    with pytest.raises(ValidationError):
        SyncRequest(**kwargs)


def test_configuration_limits():
    configured = Settings(_env_file=None)
    assert configured.database_url.get_secret_value().startswith("postgresql+asyncpg://")
    assert "**********" in repr(configured)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url="sqlite:///old.db")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url="not a URL")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, nvd_interval=0.6)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, nvd_api_key="example", nvd_interval=0.5)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, task_timeout=3600, task_ttl=3600)

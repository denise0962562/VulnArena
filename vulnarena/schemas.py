from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

CveId = Annotated[str, Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")]


def utcnow() -> datetime:
    return datetime.now(UTC)


class Severity(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class Vulnerability(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: CveId
    description: str = ""
    description_lang: str | None = None
    published_at: AwareDatetime
    last_modified_at: AwareDatetime
    vuln_status: str = "UNKNOWN"
    cvss_score: Annotated[float, Field(ge=0, le=10, allow_inf_nan=False)] | None = None
    severity: Severity = Severity.UNKNOWN
    cvss_version: str | None = None
    cvss_vector: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    references: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    parse_warnings: list[str] = Field(default_factory=list)


class VulnerabilityView(Vulnerability):
    study: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityList(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[VulnerabilityView]


class SyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: CveId | None = None
    keyword: Annotated[str, Field(min_length=1, max_length=100)] | None = None
    max_records: int = Field(default=100, ge=1, le=1000)
    recent_days: int | None = Field(default=None, ge=1, le=120)
    enrich: bool = False
    latest: bool = False

    @model_validator(mode="after")
    def bounded_query(self) -> "SyncRequest":
        if not self.cve_id and not (self.keyword and self.keyword.strip()):
            raise ValueError(
                "provide cve_id or keyword; full database imports are outside v1 scope"
            )
        if self.cve_id and self.keyword:
            raise ValueError("provide only one of cve_id or keyword")
        if self.enrich and self.keyword and self.max_records > 20:
            raise ValueError(
                "detail enrichment is limited to 20 records per API task; use batch CLI"
            )
        return self


class TaskStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class SyncTask(BaseModel):
    id: str
    status: TaskStatus = TaskStatus.PENDING
    created_at: AwareDatetime = Field(default_factory=utcnow)
    updated_at: AwareDatetime = Field(default_factory=utcnow)
    processed: int = 0
    changed: int = 0
    error: str | None = None

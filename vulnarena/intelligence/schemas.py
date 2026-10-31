import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vulnarena.topics import TOPICS


class Filters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    year_from: int | None = Field(default=None, ge=1999, le=2100)
    year_to: int | None = Field(default=None, ge=1999, le=2100)
    topic: str | None = None
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"] | None = None

    @model_validator(mode="after")
    def valid_filters(self):
        if self.year_from and self.year_to and self.year_from > self.year_to:
            raise ValueError("invalid year range")
        if self.topic and self.topic not in TOPICS:
            raise ValueError("unknown ecosystem")
        return self


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    question: str = Field(min_length=2, max_length=1000)
    filters: Filters = Field(default_factory=Filters)
    mode: Literal["hybrid", "keyword", "semantic"] = "hybrid"
    top_k: int = Field(default=6, ge=1, le=10)


class IndexRequest(BaseModel):
    limit: int = Field(default=5000, ge=20, le=10000)
    force: bool = False
    identifiers: list[str] | None = Field(default=None, min_length=1, max_length=50)

    @field_validator("identifiers")
    @classmethod
    def valid_identifiers(cls, values):
        if values is None:
            return None
        if any(
            len(value.strip()) > 40
            or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value.strip(), re.I)
            for value in values
        ):
            raise ValueError("invalid CVE identifier")
        return list(dict.fromkeys(value.strip().upper() for value in values))


class EvaluationRequest(BaseModel):
    dataset: Literal["development", "regression", "holdout"] = "development"
    include_generation: bool = False
    generation_limit: int = Field(default=5, ge=1, le=10)
    limit: int = Field(default=100, ge=5, le=100)


class HumanReview(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    trace_id: str = Field(min_length=1, max_length=64)
    reviewer: str = Field(min_length=2, max_length=80)
    verdict: Literal["supported", "partially_supported", "unsupported", "insufficient_evidence"]
    evidence_reviewed: Literal[True]
    source_ids: list[str] = Field(max_length=10)
    explanation: str = Field(min_length=10, max_length=2000)


class HumanReviewBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reviews: list[HumanReview] = Field(min_length=1, max_length=10)


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    source_id: str = Field(min_length=1, max_length=16)
    quote: str = Field(min_length=8, max_length=650)


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    text: str = Field(min_length=1, max_length=1500)
    references: list[Reference] = Field(min_length=1, max_length=4)


class AnswerDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    insufficient: bool
    claims: list[Claim] = Field(max_length=8)
    missing_information: list[str] = Field(default_factory=list, max_length=6)

    @model_validator(mode="after")
    def has_answer(self):
        if not self.claims and not self.insufficient:
            raise ValueError("empty answer must abstain")
        return self


CARD_SECTIONS = {
    "overview": "问题是什么",
    "trigger": "触发条件",
    "impact": "可能影响",
    "remediation": "修复与缓解依据",
    "learning": "学习要点",
}


class CardSection(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    key: Literal["overview", "trigger", "impact", "remediation", "learning"]
    status: Literal["supported", "missing"]
    text: str = Field(max_length=1200)
    references: list[Reference] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def has_references(self):
        if self.status == "supported" and (not self.text or not self.references):
            raise ValueError("supported section requires evidence")
        return self


class CardDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sections: list[CardSection] = Field(min_length=5, max_length=5)

    @model_validator(mode="after")
    def all_sections(self):
        if {section.key for section in self.sections} != set(CARD_SECTIONS):
            raise ValueError("all five unique sections are required")
        return self

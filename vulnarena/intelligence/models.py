from datetime import datetime

from sqlalchemy import Float, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column

from vulnarena.db import Base, UTCDateTime


class IndexedRecord(Base):
    __tablename__ = "ai_indexed_records"
    cve_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    signature: Mapped[str] = mapped_column(String(64))
    source_version: Mapped[str] = mapped_column(String(64), default="legacy")
    embedding_model: Mapped[str] = mapped_column(String(160))
    indexed_at: Mapped[datetime] = mapped_column(UTCDateTime())
    year: Mapped[int]
    severity: Mapped[str] = mapped_column(String(10))
    topics: Mapped[list] = mapped_column(JSONB)


class EvidenceChunk(Base):
    __tablename__ = "ai_evidence_chunks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    cve_id: Mapped[str] = mapped_column(
        String(40), ForeignKey("ai_indexed_records.cve_id", ondelete="CASCADE"), index=True
    )
    content: Mapped[dict] = mapped_column(JSONB)
    embedding: Mapped[list[float]] = mapped_column(ARRAY(Float(precision=24)))
    search_vector: Mapped[str] = mapped_column(TSVECTOR)
    __table_args__ = (Index("ix_ai_evidence_search", "search_vector", postgresql_using="gin"),)


class IntelligenceJob(Base):
    __tablename__ = "ai_jobs"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)
    status: Mapped[str] = mapped_column(String(24))
    progress: Mapped[int]
    total: Mapped[int]
    result: Mapped[dict] = mapped_column(JSONB)
    parameters: Mapped[dict] = mapped_column(JSONB, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class StudyCard(Base):
    __tablename__ = "ai_study_cards"
    cve_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    signature: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(160))
    prompt_version: Mapped[str] = mapped_column(String(40))
    content: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())


class AnswerCache(Base):
    __tablename__ = "ai_answer_cache"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    content: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())


class AITrace(Base):
    __tablename__ = "ai_traces"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    kind: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(32), index=True)
    question: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(160))
    model_called: Mapped[bool]
    payload: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)

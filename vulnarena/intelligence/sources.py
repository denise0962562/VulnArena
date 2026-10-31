"""Canonical source snapshots and bounded, directly quotable evidence."""

import hashlib
import json
import re
from urllib.parse import urlparse

from vulnarena.schemas import Vulnerability
from vulnarena.study import cpe_products, weakness_ids
from vulnarena.study_contract import merge_description, study_matches
from vulnarena.topics import classify

SOURCE_VERSION = "nvd-evidence-v2-full-documents"
PROMPT_VERSION = "grounded-nvd-v3"


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def source_signature(record: Vulnerability, study: dict) -> str:
    # Chinese machine translation is not the authority or a citation source.
    value = {
        "version": SOURCE_VERSION,
        "record": record.model_dump(mode="json"),
        "documents": study.get("documents", []),
        "study_fingerprint": study.get("fingerprint"),
        "affected": study.get("affected", []),
    }
    if record.raw.get("source") == "GitHub Advisory":
        value["authority_contract"] = "ghsa-v2"
    return digest(value)


def safe_url(value: str) -> str:
    parsed = urlparse(value)
    return value if parsed.scheme in {"http", "https"} and parsed.netloc else ""


def split_text(text: str, size: int = 1200, overlap: int = 120) -> list[tuple[int, str]]:
    text = text.replace("\r\n", "\n").strip()
    parts = []
    offset = 0
    while offset < len(text):
        end = min(len(text), offset + size)
        if end < len(text):
            boundary = max(
                text.rfind("\n", offset + size // 2, end), text.rfind(". ", offset + size // 2, end)
            )
            if boundary > offset:
                end = boundary + 1
        parts.append((offset, text[offset:end]))
        if end == len(text):
            break
        offset = max(offset + 1, end - overlap)
    return parts


def make_sources(record: Vulnerability, study: dict, chinese: dict | None = None) -> dict:
    signature = source_signature(record, study)
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{record.cve_id}"
    github = record.raw.get("source") == "GitHub Advisory"
    primary_source = "GitHub Advisory" if github else "NVD"
    primary_url = (
        safe_url(record.raw.get("advisory", {}).get("html_url", "")) or nvd_url
        if github
        else nvd_url
    )
    documents = [
        {
            "title": f"{record.cve_id} · {primary_source} 原始描述",
            "url": primary_url,
            "source": primary_source,
            "text_en": record.description,
        }
    ]
    fresh_study = study_matches(record, study)
    if fresh_study:
        documents.extend(
            document
            for document in study.get("documents", [])
            if document.get("text_en", "").strip()
        )
    merged = merge_description(record, study, chinese)
    chunks = []
    seen = set()
    # Download size is already bounded by the collector; index all saved paragraphs.
    # Prompt selection remains separately bounded in the retriever.
    for doc_index, document in enumerate(documents):
        for offset, text in split_text(document.get("text_en", "")):
            identity = digest(text)
            if not text.strip() or identity in seen:
                continue
            seen.add(identity)
            chunks.append(
                {
                    "id": digest([record.cve_id, signature, doc_index, offset, text]),
                    "cve_id": record.cve_id,
                    "signature": signature,
                    "title": document.get("title") or record.cve_id,
                    "url": safe_url(document.get("url", "")) or primary_url,
                    "source": document.get("source") or "本地公告",
                    "text": text,
                    "offset": offset,
                    "updated_at": record.last_modified_at.isoformat(),
                    "text_zh": merged.get("description_zh", "")
                    if doc_index == 0 and offset == 0 and not merged.get("description_stale")
                    else "",
                }
            )
    return {
        "cve_id": record.cve_id,
        "signature": signature,
        "topics": list(
            dict.fromkeys(
                [
                    *(study.get("topics", []) if fresh_study else []),
                    *classify(
                        record.description
                        + " "
                        + (study.get("title") or "")
                        + " "
                        + json.dumps(
                            study.get("affected", []) if fresh_study else cpe_products(record.raw)
                        )
                    ),
                ]
            )
        ),
        "year": int(record.cve_id[4:8]),
        "severity": record.severity.value,
        "chunks": chunks,
        "facts": {
            "cve_id": record.cve_id,
            "severity": record.severity.value,
            "cvss_score": record.cvss_score,
            "cvss_version": record.cvss_version,
            "vuln_status": record.vuln_status,
            "published_at": record.published_at.isoformat(),
            "last_modified_at": record.last_modified_at.isoformat(),
            "weaknesses": weakness_ids(record.raw),
            "affected": (study.get("affected") if fresh_study else None)
            or cpe_products(record.raw),
            "origin": primary_url,
            "version_note": "保留上游版本语义；缺少范围或修复信息时不能判断某个版本安全。",
        },
    }


def with_source_ids(chunks: list[dict]) -> list[dict]:
    return [{**chunk, "source_id": f"S{index}"} for index, chunk in enumerate(chunks, 1)]


def card_evidence(chunks: list[dict], limit: int = 8) -> list[dict]:
    """Keep original context plus relevant conditions/fixes, never send full archives."""
    if len(chunks) <= limit:
        return with_source_ids(chunks)
    selected = [chunks[0]]
    categories = [
        {"fix", "fixed", "patch", "patched", "upgrade", "mitigation", "workaround", "resolved"},
        {"affected", "versions", "requires", "configuration", "enabled", "before"},
        {"impact", "execution", "privileges", "disclosure", "cause", "vulnerability"},
    ]
    for words in categories:
        ranked = sorted(
            chunks,
            key=lambda chunk: (
                -len(words.intersection(re.findall(r"[a-z]+", chunk["text"].lower())))
            ),
        )
        for chunk in ranked[:2]:
            if chunk not in selected:
                selected.append(chunk)
    for chunk in chunks:
        if len(selected) >= limit:
            break
        if chunk not in selected:
            selected.append(chunk)
    return with_source_ids(selected[:limit])


class EvidenceViolation(ValueError):
    pass


def validate_references(sections, sources: list[dict]) -> None:
    source_map = {source["source_id"]: source["text"] for source in sources}

    def normalize(value):
        return re.sub(r"\s+", " ", value).strip()

    for section in sections:
        for reference in section.references:
            text = source_map.get(reference.source_id)
            if not text or normalize(reference.quote) not in normalize(text):
                raise EvidenceViolation("citation is absent or quote is not in its source")

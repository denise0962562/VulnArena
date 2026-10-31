import asyncio
import re
import time

from vulnarena.intelligence.embeddings import EmbeddingUnavailable
from vulnarena.intelligence.query import (
    CVE_PATTERN,
    expanded_query,
    has_query_anchor,
    in_domain,
    parse_filters,
    query_anchors,
    reciprocal_rank_fusion,
    tokens,
)
from vulnarena.intelligence.sources import with_source_ids

RETRIEVAL_VERSION = "hybrid-technical-anchors-v2"


def matches(snapshot, filters):
    return (
        not snapshot.get("rejected")
        and (not filters.year_from or snapshot["year"] >= filters.year_from)
        and (not filters.year_to or snapshot["year"] <= filters.year_to)
        and (not filters.topic or filters.topic in snapshot["topics"])
        and (not filters.severity or snapshot["severity"] == filters.severity)
    )


class Retriever:
    def __init__(self, repository, encoder, settings):
        self.repository, self.encoder, self.settings = repository, encoder, settings
        self.matrix = None
        self.matrix_key = None
        self.matrix_metadata = []
        self.matrix_lock = asyncio.Lock()

    async def semantic(self, question, filters):
        import numpy as np

        key = await self.repository.matrix_version(self.encoder.model_name)
        if not key[0]:
            raise EmbeddingUnavailable("当前模型尚未建立语义索引。")
        async with self.matrix_lock:
            if self.matrix_key != key:
                vectors, metadata = [], []
                async for identity, vector, year, severity, topics in self.repository.matrix_rows(
                    self.encoder.model_name
                ):
                    vectors.append(np.asarray(vector, dtype=np.float32))
                    metadata.append((identity, year, severity, topics))
                self.matrix = np.stack(vectors) if vectors else None
                self.matrix_metadata, self.matrix_key = metadata, key
        if self.matrix is None:
            return [], {}
        vector = (await self.encoder.encode([question], query=True))[0]
        scores = await asyncio.to_thread(
            np.einsum,
            "ij,j->i",
            self.matrix,
            np.asarray(vector, dtype=np.float32),
            optimize=False,
        )
        selected = [
            (identity, float(scores[index]))
            for index, (identity, year, severity, topics) in enumerate(self.matrix_metadata)
            if (not filters.year_from or year >= filters.year_from)
            and (not filters.year_to or year <= filters.year_to)
            and (not filters.severity or filters.severity == severity)
            and (not filters.topic or filters.topic in topics)
            and scores[index] >= self.settings.ai_min_similarity
        ]
        selected.sort(key=lambda row: (-row[1], row[0]))
        selected = selected[:60]
        return [row[0] for row in selected], dict(selected)

    async def search(self, request):
        started = time.monotonic()
        filters = parse_filters(request.question, request.filters)
        diagnostics = {"mode": request.mode, "stale_excluded": 0, "warning": None}
        anchors = query_anchors(request.question)
        diagnostics["query_anchors"] = anchors
        identifiers = list(
            dict.fromkeys(item.upper() for item in CVE_PATTERN.findall(request.question))
        )[:5]
        sources = []
        if identifiers:
            snapshots = await self.repository.snapshots(identifiers)
            # A CVE ID is an exact lookup across the entire library, not a vector guess.
            words = set(tokens(expanded_query(CVE_PATTERN.sub("", request.question))))
            ordered = {
                identifier: sorted(
                    snapshot["chunks"],
                    key=lambda chunk: (
                        -len(words.intersection(tokens(chunk["title"] + " " + chunk["text"]))),
                        chunk["offset"],
                    ),
                )
                for identifier, snapshot in snapshots.items()
            }
            for position in range(request.top_k):
                for identifier in identifiers:
                    snapshot = snapshots.get(identifier)
                    if (
                        snapshot
                        and matches(snapshot, filters)
                        and len(ordered[identifier]) > position
                    ):
                        sources.append(ordered[identifier][position])
            diagnostics["mode"] = "exact_cve"
        elif in_domain(request.question):
            lexical, semantic, semantic_scores = [], [], {}
            if request.mode != "semantic":
                lexical = await self.repository.lexical(request.question, filters)
            if request.mode != "keyword":
                try:
                    semantic, semantic_scores = await self.semantic(request.question, filters)
                except (EmbeddingUnavailable, ImportError):
                    diagnostics["warning"] = "语义索引暂不可用，当前使用关键词检索。"
                    diagnostics["mode"] = "keyword_fallback"
                    lexical = await self.repository.lexical(request.question, filters)
            ranked = reciprocal_rank_fusion([lexical, semantic])
            chunks = await self.repository.chunks([identity for identity, _ in ranked])
            snapshots = await self.repository.snapshots(
                list({chunk["cve_id"] for chunk in chunks.values()})
            )
            per_cve = {}
            quoted = re.findall(r'["“「]([^"”」]{3,100})["”」]', request.question)
            for identity, score in ranked:
                chunk = chunks.get(identity)
                if chunk is None:
                    continue
                snapshot = snapshots.get(chunk["cve_id"])
                if not snapshot or snapshot["signature"] != chunk["signature"]:
                    diagnostics["stale_excluded"] += 1
                    continue
                if not matches(snapshot, filters):
                    continue
                if not has_query_anchor(chunk["title"] + " " + chunk["text"], anchors):
                    continue
                if quoted and not all(
                    phrase.lower()
                    in (chunk["text"] + chunk["title"] + chunk.get("text_zh", "")).lower()
                    for phrase in quoted
                ):
                    continue
                if per_cve.get(chunk["cve_id"], 0) >= 2:
                    continue
                per_cve[chunk["cve_id"]] = per_cve.get(chunk["cve_id"], 0) + 1
                sources.append(
                    {
                        **chunk,
                        "rank_score": round(score, 6),
                        "semantic_similarity": semantic_scores.get(identity),
                    }
                )
                if len(sources) >= request.top_k:
                    break
        return {
            "sources": with_source_ids(sources[: request.top_k]),
            "filters": filters.model_dump(),
            "retrieval_ms": round((time.monotonic() - started) * 1000),
            "diagnostics": diagnostics,
            "scope": "CVE 编号精确查询覆盖全库；语义与关键词检索覆盖已建立的代表性证据索引。",
        }

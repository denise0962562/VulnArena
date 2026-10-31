import asyncio
import logging
import time
from urllib.parse import urlencode

from vulnarena.intelligence.embeddings import CPUEncoder, EmbeddingUnavailable
from vulnarena.intelligence.llm import ModelClient, ModelOutputInvalid, ModelUnavailable
from vulnarena.intelligence.query import (
    ALIASES,
    CVE_PATTERN,
    in_domain,
    is_statistics,
    parse_filters,
)
from vulnarena.intelligence.repository import BudgetExceeded, Repository, now
from vulnarena.intelligence.retrieval import RETRIEVAL_VERSION, Retriever
from vulnarena.intelligence.schemas import CARD_SECTIONS, AnswerDraft, CardDraft
from vulnarena.intelligence.sources import (
    PROMPT_VERSION,
    SOURCE_VERSION,
    EvidenceViolation,
    card_evidence,
    digest,
    validate_references,
)
from vulnarena.schemas import Severity
from vulnarena.security import REQUEST_ID

logger = logging.getLogger(__name__)


class WorkBusy(RuntimeError):
    pass


class IntelligenceService:
    def __init__(self, db, settings, *, encoder=None, model=None):
        self.db, self.settings = db, settings
        self.repository = Repository(db)
        self.encoder = encoder or CPUEncoder(settings)
        self.model = model or ModelClient(settings)
        self.retriever = Retriever(self.repository, self.encoder, settings)
        self.generation_lock = asyncio.Lock()
        self.job_start_lock = asyncio.Lock()
        self.jobs = {}

    async def startup(self):
        from vulnarena.intelligence.schemas import IndexRequest

        recoverable = await self.repository.recover()
        if self.settings.ai_resume_jobs:
            for previous in recoverable:
                parameters = previous.get("parameters", {})
                if previous["kind"] == "index" and parameters.get("limit"):
                    restored = {
                        key: value
                        for key, value in parameters.items()
                        if key in IndexRequest.model_fields
                    }
                    resumed = await self.start_index(IndexRequest(**{**restored, "force": False}))
                    await self.repository.update_job(
                        resumed["id"],
                        parameters={**parameters, "resumes": previous["id"], "force": False},
                    )
                    return  # One low-load index at a time; evaluations never auto-spend.
            stats = await self.repository.index_stats(self.encoder.model_name)
            if stats["outdated_records"] and self.encoder.available:
                await self.start_index(IndexRequest(limit=max(20, min(10000, stats["records"]))))

    async def close(self):
        identities = list(self.jobs)
        tasks = list(self.jobs.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for identity in identities:
            await self.repository.update_job(identity, error="service_shutdown")
        await self.encoder.close()
        await self.model.close()

    async def status(self):
        return {
            "prompt_version": PROMPT_VERSION,
            "source_version": SOURCE_VERSION,
            "retrieval_version": RETRIEVAL_VERSION,
            "configured": self.model.available,
            "model": self.model.model,
            "provider": self.model.base_url,
            "embedding_model": self.encoder.model_name,
            "embedding_available": self.encoder.available,
            "embedding_loaded": self.encoder.loaded,
            "vector_backend": "PostgreSQL float arrays + NumPy exact cosine (bounded corpus)",
            "index": await self.repository.index_stats(self.encoder.model_name),
            "jobs": await self.repository.recent_jobs(),
            "limits": {
                "generation_concurrency": 1,
                "embedding_threads": self.settings.ai_embedding_threads,
                "daily_model_calls": self.settings.ai_daily_calls,
                "daily_calls_used": await self.repository.daily_calls(),
                "idle_unload_seconds": 120,
            },
            "pricing_configured": self.settings.ai_input_price_per_million is not None
            and self.settings.ai_output_price_per_million is not None,
            "price_reference": {
                "currency": self.settings.ai_price_currency,
                "note": self.settings.ai_price_note,
            },
        }

    async def start_job(self, kind, total, work, *, parameters=None):
        async with self.job_start_lock:
            return await self._start_job_locked(kind, total, work, parameters)

    async def _start_job_locked(self, kind, total, work, parameters):
        if any(not task.done() for task in self.jobs.values()):
            raise WorkBusy("已有索引或评测任务在运行，请等待完成。")
        job = await self.repository.new_job(kind, total, parameters)

        async def run():
            try:
                await self.repository.update_job(job["id"], status="running")
                result = await work(job["id"])
                await self.repository.update_job(
                    job["id"], status="complete", result=result, finished_at=now()
                )
            except asyncio.CancelledError:
                await self.repository.update_job(
                    job["id"],
                    status="interrupted",
                    error="任务已停止，已保存的索引可复用。",
                    finished_at=now(),
                )
                raise
            except Exception as exception:
                logger.exception("NVD AI %s job failed", kind)
                message = (
                    str(exception)
                    if isinstance(exception, (EmbeddingUnavailable, ValueError))
                    else "任务未完成，请查看服务日志并重试。"
                )
                await self.repository.update_job(
                    job["id"], status="failed", error=message[:300], finished_at=now()
                )
            finally:
                self.jobs.pop(job["id"], None)

        self.jobs[job["id"]] = asyncio.create_task(run())
        return job

    async def cancel_job(self, identity):
        task = self.jobs.get(identity)
        if task and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return await self.repository.job(identity)

    async def start_index(self, request):
        async def build(identity):
            candidates = request.identifiers or await self.repository.candidates(request.limit)
            await self.repository.update_job(identity, total=len(candidates))
            saved, reused, changed = 0, 0, 0
            for offset in range(0, len(candidates), 8):
                batch = candidates[offset : offset + 8]
                snapshots = await self.repository.snapshots(batch)
                pending = []
                for identifier in batch:
                    snapshot = snapshots.get(identifier)
                    if not snapshot or not snapshot["chunks"] or snapshot.get("rejected"):
                        changed += 1
                        continue
                    indexed = await self.repository.index_signature(
                        identifier, self.encoder.model_name
                    )
                    if not request.force and indexed == snapshot["signature"]:
                        reused += 1
                    else:
                        pending.append(snapshot)
                if pending:
                    vectors = await self.encoder.encode(
                        [
                            chunk["title"] + "\n" + chunk["text"]
                            for snapshot in pending
                            for chunk in snapshot["chunks"]
                        ]
                    )
                    cursor = 0
                    for snapshot in pending:
                        end = cursor + len(snapshot["chunks"])
                        if await self.repository.save_index(
                            snapshot, vectors[cursor:end], self.encoder.model_name
                        ):
                            saved += 1
                        else:
                            changed += 1
                        cursor = end
                await self.repository.update_job(
                    identity,
                    progress=min(offset + len(batch), len(candidates)),
                    result={
                        "saved": saved,
                        "reused": reused,
                        "source_changed": changed,
                        "current_cve": batch[-1],
                        "stage": "indexing",
                    },
                )
                await asyncio.sleep(self.settings.ai_index_pause)
            self.retriever.matrix_key = None
            return {
                "saved": saved,
                "reused": reused,
                "source_changed": changed,
                "index": await self.repository.index_stats(),
                "embedding_model": self.encoder.model_name,
            }

        return await self.start_job("index", request.limit, build, parameters=request.model_dump())

    async def search(self, request):
        return await self.retriever.search(request)

    async def _statistics(self, request):
        filters = parse_filters(request.question, request.filters)
        if any(term in request.question for term in ["一周", "本月", "最近", "昨天", "今天"]):
            return {
                "status": "insufficient",
                "claims": [],
                "sources": [],
                "missing_information": ["当前统计按 CVE 编号年份筛选，请指定年份和生态。"],
            }
        keyword = None
        for word in sorted(ALIASES, key=len, reverse=True):
            if word.lower() in request.question.lower() and word not in {
                "日志",
                "Log4Shell",
                "Spring4Shell",
                "PrintNightmare",
                "DirtyPipe",
                "Zerologon",
            }:
                keyword = ALIASES[word].split(" ")[0]
                break
        for product in [
            "OpenSSL",
            "OpenSSH",
            "Log4j",
            "Django",
            "FastAPI",
            "Spring",
            "libwebp",
            "curl",
        ]:
            if product.lower() in request.question.lower():
                keyword = product
                break
        async with self.db.read_sessions() as session:
            response = await self.db.list_from_session(
                session,
                1,
                1,
                Severity(filters.severity) if filters.severity else None,
                keyword,
                None,
                topic=filters.topic,
                year_from=filters.year_from,
                year_to=filters.year_to,
            )
        parameters = {
            key: value for key, value in filters.model_dump().items() if value is not None
        }
        if keyword:
            parameters["keyword"] = keyword
        return {
            "status": "statistics",
            "claims": [],
            "sources": [],
            "statistics": {
                "count": response.total,
                "filters": filters.model_dump(),
                "keyword": keyword,
                "source": "本地 PostgreSQL 实际查询",
                "scope": "年份指 CVE 编号年份；包含当前筛选下的全部记录状态。"
                + (
                    "关键词为描述/标题子串匹配，不代表该产品或漏洞类型的完整数量。"
                    if keyword
                    else ""
                ),
                "query_url": "/api/vulnerabilities?" + urlencode(parameters),
            },
        }

    async def _sources_still_current(self, sources):
        snapshots = await self.repository.snapshots(list({source["cve_id"] for source in sources}))
        return all(
            snapshots.get(source["cve_id"], {}).get("signature") == source["signature"]
            for source in sources
        )

    async def ask(
        self, request, *, phase=None, trace_kind="ask", use_cache=True, wait_for_model=False
    ):
        started = time.monotonic()
        trace_id = await self.repository.trace(trace_kind, request.question, self.model.model)
        telemetry = {
            "request_id": REQUEST_ID.get(),
            "input_tokens": None,
            "output_tokens": None,
            "estimated_cost": None,
            "retrieval_ms": 0,
            "generation_ms": 0,
            "prompt_version": PROMPT_VERSION,
            "mode": request.mode,
            "cached": False,
        }
        result = {"status": "failed", "claims": [], "sources": []}

        async def notify(stage, **details):
            if phase:
                await phase({"phase": stage, **details})

        try:
            if (
                is_statistics(request.question)
                and in_domain(request.question)
                and not CVE_PATTERN.search(request.question)
            ):
                result = await self._statistics(request)
                telemetry.update(
                    input_tokens=0, output_tokens=0, estimated_cost=0, mode="sql_count"
                )
            else:
                await notify("retrieving")
                retrieval = await self.search(request)
                sources = retrieval["sources"]
                telemetry.update(
                    retrieval_ms=retrieval["retrieval_ms"],
                    mode=retrieval["diagnostics"]["mode"],
                    source_ids=[source["id"] for source in sources],
                    cve_ids=list(dict.fromkeys(source["cve_id"] for source in sources)),
                    source_versions={source["cve_id"]: source["signature"] for source in sources},
                )
                result = {
                    **retrieval,
                    "claims": [],
                    "status": "insufficient",
                    "missing_information": [
                        "当前本地资料未提供足够依据，请补充 CVE 编号或缩小检索范围。"
                    ],
                }
                await notify("sources", sources=sources, diagnostics=retrieval["diagnostics"])
                if not sources:
                    telemetry.update(input_tokens=0, output_tokens=0, estimated_cost=0)
                else:
                    key = digest(
                        [
                            request.model_dump(),
                            PROMPT_VERSION,
                            self.model.model,
                            [(source["id"], source["signature"]) for source in sources],
                        ]
                    )
                    cached = await self.repository.cached_answer(key, 86400) if use_cache else None
                    if cached:
                        cached_draft = AnswerDraft(
                            insufficient=cached["status"] == "partial",
                            claims=cached["claims"],
                            missing_information=cached.get("missing_information", []),
                        )
                        validate_references(cached_draft.claims, sources)
                        result = cached
                        telemetry.update(
                            cached=True,
                            input_tokens=0,
                            output_tokens=0,
                            estimated_cost=0,
                            citation_check="passed" if cached_draft.claims else "no_citations",
                        )
                    else:
                        if not self.model.available:
                            raise ModelUnavailable("模型尚未配置；仍可查看下方检索原文。")
                        if self.generation_lock.locked() and not wait_for_model:
                            raise WorkBusy("另一条 AI 请求正在生成，请稍后重试。")
                        async with self.generation_lock:
                            await self.repository.reserve_model_call(
                                trace_id, self.settings.ai_daily_calls
                            )
                            await notify("generating")
                            draft = await self.model.generate(
                                "回答用户的问题：" + request.question,
                                sources,
                                {},
                                AnswerDraft,
                                telemetry,
                            )
                            validate_references(draft.claims, sources)
                            if not await self._sources_still_current(sources):
                                raise EvidenceViolation("source changed during generation")
                            result = {
                                **retrieval,
                                "status": "partial" if draft.insufficient else "complete",
                                "claims": [claim.model_dump() for claim in draft.claims],
                                "missing_information": draft.missing_information,
                                "generation": {
                                    "model": self.model.model,
                                    "resolved_model": telemetry.get("resolved_model"),
                                    "prompt_version": PROMPT_VERSION,
                                    "created_at": now().isoformat(),
                                },
                            }
                            telemetry["citation_check"] = (
                                "passed" if draft.claims else "no_citations"
                            )
                            await self.repository.cache_answer(key, result)
        except (ModelUnavailable, BudgetExceeded, WorkBusy) as exception:
            result.update(status="unavailable", message=str(exception))
        except (ModelOutputInvalid, EvidenceViolation):
            result.update(
                status="validation_failed",
                claims=[],
                message="回答未通过结构、原文引用或来源时效校验，未展示未经验证的结论。",
            )
            telemetry["citation_check"] = "rejected"
        except asyncio.CancelledError:
            result["status"] = "cancelled"
            raise
        except Exception:
            logger.exception("NVD AI question failed")
            result.update(
                status="failed", claims=[], message="处理未完成，请重试或先阅读检索原文。"
            )
        finally:
            telemetry["latency_ms"] = round((time.monotonic() - started) * 1000)
            await self.repository.finish_trace(trace_id, result["status"], telemetry)
        return {
            **result,
            "trace_id": trace_id,
            "telemetry": telemetry,
            "note": (
                "引文位置已校验，语义是否充分支持结论仍需结合原文核对；本页不判断具体环境是否安全。"
            ),
        }

    async def get_card(self, identifier):
        snapshot = (await self.repository.snapshots([identifier])).get(identifier)
        if not snapshot:
            return None
        card = await self.repository.card(identifier)
        if (
            card
            and card["signature"] == snapshot["signature"]
            and card["model"] == self.model.model
            and card["prompt_version"] == PROMPT_VERSION
        ):
            return {**card, "status": "complete", "cached": True}
        return {
            "status": "stale" if card else "missing",
            "cve_id": identifier,
            "facts": snapshot["facts"],
            "configured": self.model.available,
            "previous_created_at": card.get("created_at") if card else None,
        }

    async def generate_card(self, identifier, *, force=False):
        previous = await self.get_card(identifier)
        if previous is None:
            return None
        if previous["status"] == "complete" and not force:
            return previous
        snapshot = (await self.repository.snapshots([identifier]))[identifier]
        sources = card_evidence(snapshot["chunks"])
        trace_id = await self.repository.trace("card", identifier, self.model.model)
        telemetry = {
            "request_id": REQUEST_ID.get(),
            "prompt_version": PROMPT_VERSION,
            "source_ids": [source["id"] for source in sources],
            "cve_ids": [identifier],
            "source_versions": {identifier: snapshot["signature"]},
            "input_tokens": None,
            "output_tokens": None,
            "estimated_cost": None,
        }
        started = time.monotonic()
        result = {**previous, "status": "failed", "sources": sources}
        try:
            if not sources or snapshot.get("rejected"):
                raise ModelUnavailable("当前记录缺少可解释的有效漏洞来源。")
            if not self.model.available:
                raise ModelUnavailable("尚未配置模型，原始资料和结构化事实仍可阅读。")
            if self.generation_lock.locked():
                raise WorkBusy("另一条 AI 请求正在生成，请稍后重试。")
            async with self.generation_lock:
                await self.repository.reserve_model_call(trace_id, self.settings.ai_daily_calls)
                draft = await self.model.generate(
                    "生成五段中文学习卡片。overview 问题是什么；trigger 触发条件；impact 影响；"
                    "remediation 修复与缓解依据；learning 学习要点。每段 supported 必须引用原文。"
                    "原文未提供的段落设 missing，尤其不能编造修复版本。"
                    "facts 由系统单独展示，不能把它们当成未提供的文字引文。",
                    sources,
                    snapshot["facts"],
                    CardDraft,
                    telemetry,
                )
                validate_references(
                    [section for section in draft.sections if section.status == "supported"],
                    sources,
                )
                if not await self._sources_still_current(sources):
                    raise EvidenceViolation("source changed")
                sections = []
                for section in draft.sections:
                    value = section.model_dump()
                    value["title"] = CARD_SECTIONS[section.key]
                    if section.status == "missing":
                        value.update(text="当前本地资料未提供足够依据。", references=[])
                    sections.append(value)
                content = {
                    "cve_id": identifier,
                    "sections": sections,
                    "sources": sources,
                    "evidence_scope": {
                        "available_chunks": len(snapshot["chunks"]),
                        "selected_chunks": len(sources),
                    },
                    "facts": snapshot["facts"],
                    "trace_id": trace_id,
                    "note": "中文为 AI 学习解释；版本范围保留上游字段，修复条件请对照官方原文。",
                }
                await self.repository.save_card(
                    identifier, snapshot["signature"], self.model.model, PROMPT_VERSION, content
                )
                result = {
                    **await self.repository.card(identifier),
                    "status": "complete",
                    "cached": False,
                }
                telemetry["citation_check"] = "passed"
        except (ModelUnavailable, BudgetExceeded, WorkBusy) as exception:
            result.update(status="unavailable", message=str(exception))
        except (ModelOutputInvalid, EvidenceViolation):
            result.update(
                status="validation_failed",
                message="卡片未通过结构、原文引用或时效校验，请查看原文或重试。",
            )
            telemetry["citation_check"] = "rejected"
        except asyncio.CancelledError:
            result["status"] = "cancelled"
            raise
        except Exception:
            logger.exception("NVD AI study card failed")
            result.update(status="failed", message="卡片生成未完成，请查看原文或稍后重试。")
        finally:
            telemetry["latency_ms"] = round((time.monotonic() - started) * 1000)
            await self.repository.finish_trace(trace_id, result["status"], telemetry)
        return {**result, "telemetry": telemetry}

    async def dashboard(self):
        traces = await self.repository.traces(1000)
        latencies = sorted(
            trace["latency_ms"] for trace in traces if trace.get("latency_ms") is not None
        )
        model_calls = [trace for trace in traces if trace["model_called"]]
        return {
            "window": "最近最多 1000 条请求；Token 与费用按已返回的用量汇总。",
            "requests": len(traces),
            "model_calls": len(model_calls),
            "cache_hits": sum(bool(trace.get("cached")) for trace in traces),
            "p50_ms": latencies[len(latencies) // 2] if latencies else None,
            "p95_ms": latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
            if latencies
            else None,
            "input_tokens": sum(trace.get("input_tokens") or 0 for trace in model_calls),
            "output_tokens": sum(trace.get("output_tokens") or 0 for trace in model_calls),
            "usage_unknown_calls": sum(trace.get("input_tokens") is None for trace in model_calls),
            "estimated_cost": sum(trace.get("estimated_cost") or 0 for trace in model_calls)
            if any(trace.get("estimated_cost") is not None for trace in model_calls)
            else None,
            "unpriced_calls": sum(trace.get("estimated_cost") is None for trace in model_calls),
            "validation_failures": sum(trace["status"] == "validation_failed" for trace in traces),
            "recent_traces": traces[:30],
            "jobs": await self.repository.recent_jobs(12),
        }

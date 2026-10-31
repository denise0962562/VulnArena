import asyncio
import json
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.responses import Response, StreamingResponse

from vulnarena.intelligence.evaluation import start_evaluation
from vulnarena.intelligence.exports import card_markdown
from vulnarena.intelligence.schemas import (
    EvaluationRequest,
    HumanReviewBatch,
    IndexRequest,
    SearchRequest,
)
from vulnarena.intelligence.service import WorkBusy

router = APIRouter(prefix="/api/ai", tags=["NVD AI"])


@router.get("/status")
async def status(request: Request):
    return {**await request.app.state.intelligence.status(), "build_id": request.app.state.build_id}


@router.post("/index", status_code=202)
async def index(body: IndexRequest, request: Request):
    try:
        return await request.app.state.intelligence.start_index(body)
    except WorkBusy as exception:
        raise HTTPException(409, str(exception)) from exception


@router.get("/jobs/{identity}")
async def job(identity: str, request: Request):
    result = await request.app.state.intelligence.repository.job(identity)
    if result is None:
        raise HTTPException(404, "任务不存在。")
    return result


@router.post("/search")
async def search(body: SearchRequest, request: Request):
    return await request.app.state.intelligence.search(body)


@router.post("/jobs/{identity}/cancel")
async def cancel_job(identity: str, request: Request):
    result = await request.app.state.intelligence.cancel_job(identity)
    if result is None:
        raise HTTPException(404, "任务不存在。")
    return result


@router.post("/ask")
async def ask(body: SearchRequest, request: Request):
    return await request.app.state.intelligence.ask(body)


@router.post("/ask/stream")
async def ask_stream(body: SearchRequest, request: Request):
    service = request.app.state.intelligence

    async def events():
        queue = asyncio.Queue()

        async def phase(event):
            await queue.put(("phase", event))

        async def produce():
            try:
                answer = await service.ask(body, phase=phase)
                await queue.put(("answer", answer))
            except asyncio.CancelledError:
                raise
            except Exception:
                await queue.put(("error", {"message": "请求未完成，请重试。"}))
            finally:
                await queue.put(("done", {}))

        task = asyncio.create_task(produce())
        try:
            while True:
                try:
                    kind, content = await asyncio.wait_for(queue.get(), timeout=10)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"event: {kind}\ndata: {json.dumps(content, ensure_ascii=False)}\n\n"
                if kind == "done":
                    break
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/cards/{identifier}")
async def get_card(identifier: str, request: Request):
    result = await request.app.state.intelligence.get_card(identifier.upper())
    if result is None:
        raise HTTPException(404, "CVE 不存在。")
    return result


@router.post("/cards/{identifier}")
async def create_card(identifier: str, request: Request, force: bool = False):
    result = await request.app.state.intelligence.generate_card(identifier.upper(), force=force)
    if result is None:
        raise HTTPException(404, "CVE 不存在。")
    return result


@router.get("/cards/{identifier}/download")
async def download_card(identifier: str, request: Request):
    result = await request.app.state.intelligence.get_card(identifier.upper())
    if result is None:
        raise HTTPException(404, "CVE 不存在。")
    if result["status"] != "complete":
        raise HTTPException(409, "卡片缺失或来源已更新，请先生成当前版本的学习卡片。")
    return Response(
        card_markdown(result),
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{result["cve_id"]}-AI-study.md"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/dashboard")
async def dashboard(request: Request):
    return await request.app.state.intelligence.dashboard()


@router.get("/traces")
async def traces(request: Request, limit: Annotated[int, Query(ge=1, le=100)] = 30):
    return await request.app.state.intelligence.repository.traces(limit)


@router.post("/evaluations", status_code=202)
async def evaluate(body: EvaluationRequest, request: Request):
    try:
        return await start_evaluation(request.app.state.intelligence, body)
    except WorkBusy as exception:
        raise HTTPException(409, str(exception)) from exception


@router.get("/evaluations/{identity}")
async def evaluation(identity: str, request: Request):
    result = await job(identity, request)
    if result["kind"] != "evaluation":
        raise HTTPException(404, "评测任务不存在。")
    return result


@router.get("/evaluations/{identity}/review-template")
async def review_template(identity: str, request: Request):
    report = await evaluation(identity, request)
    return {
        "report_id": identity,
        "instructions": (
            "核对中文结论、原文支持关系和版本条件，再填写 reviews。不要把引文位置检查当事实正确率。"
        ),
        "reviews": [
            {
                "trace_id": sample["trace_id"],
                "reviewer": "",
                "verdict": "insufficient_evidence",
                "evidence_reviewed": False,
                "source_ids": [],
                "explanation": "",
            }
            for sample in report["result"].get("generation", [])
        ],
        "samples": report["result"].get("generation", []),
    }


@router.post("/evaluations/{identity}/reviews")
async def human_reviews(identity: str, body: HumanReviewBatch, request: Request):
    try:
        return await request.app.state.intelligence.repository.save_reviews(identity, body)
    except ValueError as exception:
        raise HTTPException(409, str(exception)) from exception

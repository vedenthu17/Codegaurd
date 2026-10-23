"""HTTP service.

POST /analyze        {"code": "..."} -> fixed schema
POST /analyze/batch  {"snippets": [{"id", "code"}, ...]} -> per-sample schema
GET  /health
GET  /               minimal demo UI

Every POST returns HTTP 200 with a schema-valid body, whatever the input.
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse

from .. import __version__, get_engine
from ..findings import Analysis
from .schemas import AnalyzeResponse, BatchItem, BatchResponse, parse_batch, parse_single

log = logging.getLogger("codeguard.api")

MAX_BODY_BYTES = int(os.getenv("CODEGUARD_MAX_BODY_BYTES", str(2 * 1024 * 1024)))
MAX_BATCH = int(os.getenv("CODEGUARD_MAX_BATCH", "1000"))
STATIC = Path(__file__).parent / "static"

@asynccontextmanager
async def lifespan(_: FastAPI):
    engine = get_engine()  # load every parser / model / rule catalog once
    engine.analyze("import os\nprint(os.getcwd())")  # warm lazy imports
    yield


app = FastAPI(title="CodeGuard", version=__version__, lifespan=lifespan)

FAIL_CLOSED = AnalyzeResponse(
    verdict="block", risk_score=1.0, categories=[], code_language="unknown",
    reason="Request could not be analysed; failing closed.", vulnerable_lines=[],
).model_dump()


def _validated(result: Analysis) -> dict:
    return AnalyzeResponse(**result.to_response()).model_dump()


def _analyze_one(code: str) -> tuple[dict, float]:
    result = get_engine().analyze(code)
    try:
        return _validated(result), result.latency_ms
    except Exception:
        log.exception("schema validation failed")
        return dict(FAIL_CLOSED), result.latency_ms


async def _read(request: Request) -> bytes:
    raw = await request.body()
    return raw[:MAX_BODY_BYTES]


@app.post("/analyze")
@app.post("/")
async def analyze(request: Request) -> JSONResponse:
    try:
        code = parse_single(await _read(request))
        body, latency = await run_in_threadpool(_analyze_one, code)
    except Exception:
        log.exception("analyze failed")
        body, latency = dict(FAIL_CLOSED), 0.0
    return JSONResponse(body, headers={"X-CodeGuard-Latency-Ms": f"{latency:.3f}"})


@app.post("/analyze/batch")
async def analyze_batch(request: Request) -> JSONResponse:
    t0 = time.perf_counter()
    try:
        items = parse_batch(await _read(request))[:MAX_BATCH]
    except Exception:
        log.exception("batch parse failed")
        items = []

    def run() -> list[dict]:
        out = []
        for sid, code in items:
            body, _ = _analyze_one(code)
            out.append(BatchItem(id=sid, **body).model_dump())
        return out

    try:
        results = await run_in_threadpool(run)
    except Exception:
        log.exception("batch failed")
        results = [BatchItem(id=sid, **FAIL_CLOSED).model_dump() for sid, _ in items]
    latency = (time.perf_counter() - t0) * 1000
    return JSONResponse(BatchResponse(count=len(results), results=results).model_dump(),
                        headers={"X-CodeGuard-Latency-Ms": f"{latency:.3f}"})


@app.get("/health")
def health() -> dict:
    eng = get_engine()
    return {"status": "ok", "version": __version__, "analyzers": [a.name for a in eng.analyzers]}


@app.get("/", response_class=HTMLResponse)
def ui() -> HTMLResponse:
    page = STATIC / "index.html"
    if page.exists():
        return HTMLResponse(page.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>CodeGuard</h1><p>POST /analyze</p>")


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error on %s", request.url.path)
    if request.method == "POST":
        return JSONResponse(dict(FAIL_CLOSED))
    return JSONResponse({"error": "internal"}, status_code=500)

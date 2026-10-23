"""Fixed response schema (pass/fail) and tolerant request parsing."""
from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, Field

from ..findings import CATEGORIES

Category = Literal[CATEGORIES]  # type: ignore[valid-type]


class AnalyzeResponse(BaseModel):
    verdict: Literal["allow", "block"]
    risk_score: float = Field(ge=0.0, le=1.0)
    categories: list[Category]
    code_language: str
    reason: str = ""
    vulnerable_lines: list[int] = Field(default_factory=list)


class BatchItem(AnalyzeResponse):
    id: Any = None


class BatchResponse(BaseModel):
    count: int
    results: list[BatchItem]


def _as_code(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return str(value)


def _decode_body(raw: bytes) -> Any:
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return text  # treat a non-JSON body as the code itself


def parse_single(raw: bytes) -> str:
    body = _decode_body(raw)
    if isinstance(body, dict):
        return _as_code(body.get("code", ""))
    return _as_code(body)


def parse_batch(raw: bytes) -> list[tuple[Any, str]]:
    """Accepts {"snippets": [...]}, {"items": [...]}, {"codes": [...]} or a
    bare list; each element may be {"id", "code"} or a plain string."""
    body = _decode_body(raw)
    if isinstance(body, dict):
        for key in ("snippets", "items", "samples", "codes", "inputs", "data"):
            if isinstance(body.get(key), list):
                body = body[key]
                break
        else:
            body = [body]
    if not isinstance(body, list):
        body = [body]
    out: list[tuple[Any, str]] = []
    for i, item in enumerate(body):
        if isinstance(item, dict):
            out.append((item.get("id", i), _as_code(item.get("code", ""))))
        else:
            out.append((i, _as_code(item)))
    return out

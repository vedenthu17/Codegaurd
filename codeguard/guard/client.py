"""Verdict sources for the guard. Every checker fails closed: if it cannot
produce a verdict (timeout, connection refused, bad body, exception) the
answer is `block`."""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Protocol

FAIL_CLOSED_REASON = "CodeGuard unavailable ({}); failing closed."


def fail_closed(why: str) -> dict:
    return {"verdict": "block", "risk_score": 1.0, "categories": [], "code_language": "unknown",
            "reason": FAIL_CLOSED_REASON.format(why), "vulnerable_lines": []}


class Checker(Protocol):
    def check(self, code: str, language: str | None = None) -> dict: ...


class LocalChecker:
    """In-process engine (no network hop, ~ms latency)."""

    def __init__(self, engine=None):
        if engine is None:
            from .. import get_engine
            engine = get_engine()
        self.engine = engine

    def check(self, code: str, language: str | None = None) -> dict:
        try:
            return self.engine.analyze(code, language).to_response()
        except Exception as exc:
            return fail_closed(type(exc).__name__)


class HttpChecker:
    """Remote CodeGuard service. Uses only the stdlib so the guard can be
    dropped into any agent runtime."""

    def __init__(self, url: str | None = None, timeout: float = 2.0):
        self.url = (url or os.getenv("CODEGUARD_URL", "http://127.0.0.1:8000")).rstrip("/") + "/analyze"
        self.timeout = timeout

    def check(self, code: str, language: str | None = None) -> dict:
        req = urllib.request.Request(self.url, data=json.dumps({"code": code}).encode(),
                                     headers={"content-type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read())
        except Exception as exc:
            return fail_closed(type(exc).__name__)
        if not isinstance(body, dict) or body.get("verdict") not in ("allow", "block"):
            return fail_closed("invalid response")
        return body

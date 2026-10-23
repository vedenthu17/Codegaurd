"""Explicit interception points: a decorator and guarded executors.

    guard = Guard()                       # in-process engine
    guard = Guard(HttpChecker(url))       # remote service, fails closed

    @guard.guarded("code")
    def run_tool(code): exec(code)        # never reached on block

    guard.run_python(code)                # check, then exec
    guard.run_shell("ls -la")             # check, then subprocess.run
    guard.run_sql(cursor, sql, params)    # check, then cursor.execute

A block raises CodeGuardBlocked *before* the wrapped call starts.
"""
from __future__ import annotations

import functools
import hashlib
import inspect
import shlex
import subprocess
import threading
from contextlib import contextmanager
from typing import Any, Callable

from .client import Checker, LocalChecker, fail_closed


class CodeGuardBlocked(PermissionError):
    def __init__(self, verdict: dict, what: str = "code"):
        self.verdict = verdict
        cats = ", ".join(verdict.get("categories") or []) or "unspecified"
        super().__init__(f"CodeGuard blocked {what} [{cats}] risk={verdict.get('risk_score')}: "
                         f"{verdict.get('reason', '')}")


_tls = threading.local()


def _approved() -> set[str]:
    if not hasattr(_tls, "approved"):
        _tls.approved = set()
    return _tls.approved


def _digest(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8", "surrogatepass")).hexdigest()


def consume_approval(code: str) -> bool:
    """Used by the audit hook so code already vetted by Guard is not re-scanned."""
    d = _digest(code)
    s = _approved()
    if d in s:
        s.discard(d)
        return True
    return False


def in_agent_region() -> bool:
    return getattr(_tls, "agent_depth", 0) > 0


@contextmanager
def agent_region():
    """Marks code running on behalf of the agent: inside it the audit hook
    checks every exec/compile/process spawn, regardless of caller."""
    _tls.agent_depth = getattr(_tls, "agent_depth", 0) + 1
    try:
        yield
    finally:
        _tls.agent_depth -= 1


class Guard:
    def __init__(self, checker: Checker | None = None, on_verdict: Callable[[str, dict], None] | None = None):
        self.checker = checker or LocalChecker()
        self.on_verdict = on_verdict

    def check(self, code: str, language: str | None = None) -> dict:
        try:
            verdict = self.checker.check(code, language)
        except Exception as exc:
            verdict = fail_closed(type(exc).__name__)
        if self.on_verdict:
            self.on_verdict(code, verdict)
        return verdict

    def enforce(self, code: str, language: str | None = None, what: str = "code") -> dict:
        verdict = self.check(code, language)
        if verdict.get("verdict") != "allow":
            raise CodeGuardBlocked(verdict, what)
        return verdict

    def guarded(self, arg: str | int = 0, language: str | None = None):
        """Decorator: vet the argument named/positioned `arg` before calling."""
        def deco(fn):
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                bound = sig.bind(*args, **kwargs)
                if isinstance(arg, int):
                    value = list(bound.arguments.values())[arg]
                else:
                    value = bound.arguments[arg]
                if isinstance(value, (list, tuple)):
                    value = shlex.join(map(str, value))
                self.enforce(str(value), language, what=f"call to {fn.__name__}()")
                with agent_region():
                    return fn(*args, **kwargs)
            return wrapper
        return deco

    def run_python(self, code: str, namespace: dict | None = None) -> dict:
        self.enforce(code, "python", what="python snippet")
        _approved().add(_digest(code))
        ns = namespace if namespace is not None else {"__name__": "__agent__"}
        with agent_region():
            exec(compile(code, "<agent>", "exec"), ns)
        return ns

    def run_shell(self, cmd: str | list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        text = cmd if isinstance(cmd, str) else shlex.join(cmd)
        self.enforce(text, "bash", what="shell command")
        kwargs.setdefault("capture_output", True)
        kwargs.setdefault("text", True)
        kwargs.setdefault("timeout", 30)
        with agent_region():
            return subprocess.run(cmd, shell=isinstance(cmd, str), **kwargs)

    def run_sql(self, cursor: Any, sql: str, params: Any = None) -> Any:
        self.enforce(sql, "sql", what="SQL statement")
        return cursor.execute(sql, params) if params is not None else cursor.execute(sql)

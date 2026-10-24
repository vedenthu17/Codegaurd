"""Detection cascade orchestrator.

Everything heavy (parsers, models, rule catalogs) is built once in
`Engine.__init__`. `analyze()` never raises: each analyzer is isolated, and a
catastrophic failure yields a fail-closed (block) response.
"""
from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Protocol

from . import fusion
from .findings import Analysis, Finding
from .langdetect import detect_language

log = logging.getLogger("codeguard")

MAX_CODE_CHARS = 200_000

FENCE_LANG = {"py": "python", "python": "python", "python3": "python", "sh": "bash", "bash": "bash",
              "shell": "bash", "zsh": "bash", "console": "bash", "js": "javascript",
              "javascript": "javascript", "node": "javascript", "ts": "javascript", "sql": "sql",
              "yaml": "yaml", "yml": "yaml"}
_SINGLE_FENCE = re.compile(r"\A\s*(?:```|~~~)[ \t]*([\w+-]*)[^\n]*\n(.*?)\n?[ \t]*(?:```|~~~)\s*\Z", re.S)
MAX_EMBED_DEPTH = 3


@dataclass(slots=True)
class Context:
    code: str
    language: str
    engine: "Engine"
    depth: int = 0
    # host line for each line of `code` (1-based); None means identity
    line_map: list[int] | None = None
    deadline: float = field(default_factory=lambda: time.perf_counter() + 0.25)
    _tree: object = field(default=None, repr=False)
    _tree_done: bool = field(default=False, repr=False)

    @property
    def lines(self) -> list[str]:
        return self.code.splitlines()

    @property
    def tree(self):
        """Python AST for this snippet, parsed once and shared by every layer.
        Tolerates syntax errors by salvaging the parseable top-level chunks."""
        if not self._tree_done:
            from .pyparse import parse_tolerant
            self._tree = parse_tolerant(self.code)
            self._tree_done = True
        return self._tree

    def host_line(self, line: int) -> int:
        if self.line_map is None:
            return line
        if not self.line_map:
            return 1
        return self.line_map[min(max(line, 1), len(self.line_map)) - 1]

    def finding(self, category: str, severity: float, lines: Iterable[int], rule: str,
                message: str, layer: str) -> Finding:
        host = tuple(sorted({self.host_line(ln) for ln in lines if ln}))
        if self.depth:
            layer = f"{layer}@embedded"
        return Finding(category, severity, host, rule, message, layer)

    def analyze_embedded(self, code: str, language: str | None, host_lines: Iterable[int]) -> list[Finding]:
        """Re-run the cascade on a payload found inside this snippet (decoded
        base64, a shell string inside subprocess, SQL inside execute(), ...).
        Every finding is attributed to the host line(s) of the payload."""
        if self.depth >= MAX_EMBED_DEPTH or not code.strip() or time.perf_counter() > self.deadline:
            return []
        hosts = sorted({self.host_line(ln) for ln in host_lines}) or [1]
        n = code.count("\n") + 1
        if len(hosts) == n:
            lmap = hosts
        else:
            lmap = [hosts[0]] * n
        sub = Context(code=code[:MAX_CODE_CHARS], language=language or detect_language(code),
                      engine=self.engine, depth=self.depth + 1, line_map=lmap, deadline=self.deadline)
        return self.engine._run_analyzers(sub)


class Analyzer(Protocol):
    name: str
    languages: frozenset[str] | None  # None = every language

    def run(self, ctx: Context) -> Iterable[Finding]: ...


def _default_analyzers() -> list[Analyzer]:
    from .analyzers import build_all
    return build_all()


class Engine:
    def __init__(self, disabled: Iterable[str] = (), analyzers_factory: Callable[[], list[Analyzer]] | None = None,
                 budget_s: float | None = None):
        self.disabled = frozenset(disabled)
        # wall-clock allowance per request, shared by all analyzers
        self.budget_s = budget_s if budget_s is not None else float(os.getenv("CODEGUARD_BUDGET_MS", "2000")) / 1000
        factory = analyzers_factory or _default_analyzers
        self.analyzers = [a for a in factory() if a.name not in self.disabled]
        for a in self.analyzers:  # load heavy resources (models) now, not inside a request
            warm = getattr(a, "warm", None)
            if warm:
                try:
                    warm()
                except Exception:
                    log.exception("warm-up of %s failed", a.name)

    def _run_analyzers(self, ctx: Context) -> list[Finding]:
        out: list[Finding] = []
        for a in self.analyzers:
            if a.languages is not None and ctx.language not in a.languages:
                continue
            if time.perf_counter() > ctx.deadline and not getattr(a, "ignore_deadline", False):
                continue
            try:
                out.extend(a.run(ctx))
            except Exception:  # one broken analyzer must not take down the verdict
                log.exception("analyzer %s failed", a.name)
        return out

    def analyze(self, code: object, language: str | None = None) -> Analysis:
        t0 = time.perf_counter()
        try:
            text = code if isinstance(code, str) else ("" if code is None else str(code))
            text = text.replace("\x00", "")[:MAX_CODE_CHARS]
            line_map = None
            m = _SINGLE_FENCE.match(text)
            if m and m.group(2).strip() and "```" not in m.group(2):
                # the whole input is one fenced block: analyse the code inside it
                inner = m.group(2)
                offset = text[:m.start(2)].count("\n")
                line_map = [offset + i + 1 for i in range(inner.count("\n") + 1)]
                language = language or FENCE_LANG.get(m.group(1).lower()) or detect_language(inner)
                text = inner
            language = language or detect_language(text)
            ctx = Context(code=text, language=language, engine=self, line_map=line_map,
                          deadline=time.perf_counter() + self.budget_s + min(3.0, len(text) * 1.5e-5))
            findings = self._run_analyzers(ctx)
            verdict, risk, cats, reason, lines, scores = fusion.decide(findings)
            result = Analysis(verdict, risk, cats, language, reason, lines, findings, scores)
        except Exception as exc:  # fail closed
            log.exception("engine failure")
            result = Analysis("block", 1.0, [], "unknown",
                              f"Internal analysis error ({type(exc).__name__}); failing closed.", [])
        result.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        return result

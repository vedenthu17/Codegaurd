"""resource_exhaustion analyzer.

Python: AST checks for loops with no exit, process/thread/socket creation
inside loops, unconditional self-recursion, and very large constant
allocations (magnitude is estimated, never evaluated).
Other languages: regex checks for unbounded loops and unbounded writes.
"""
from __future__ import annotations

import ast
import math
import re

from .common import line_of

SPAWN_NAMES = {"fork", "Process", "Thread", "Popen", "socket", "create_connection", "forkpty"}
EXIT_NODES = (ast.Break, ast.Return, ast.Raise, ast.Yield, ast.YieldFrom, ast.Await)
BIG_LOG10 = 8  # >= 1e8 elements/bytes


def magnitude(n: ast.AST) -> float | None:
    """Rough log10 of a constant numeric expression; None if unknown."""
    if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool) and n.value > 0:
        return math.log10(n.value)
    if isinstance(n, ast.BinOp):
        l, r = magnitude(n.left), magnitude(n.right)
        if isinstance(n.op, ast.Mult) and l is not None and r is not None:
            return l + r
        if isinstance(n.op, ast.Pow) and l is not None and r is not None:
            return l * (10 ** min(r, 3))
    return None


def _sizes(n: ast.AST) -> float | None:
    """Magnitude of the repeat count in `seq * N` / the bound in range(N)."""
    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mult):
        for side in (n.left, n.right):
            m = magnitude(side)
            if m is not None:
                return m
    return None


def _call_name(c: ast.Call) -> str:
    f = c.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")


def _has_exit(loop: ast.AST) -> bool:
    return any(isinstance(x, EXIT_NODES) for x in ast.walk(loop))


def _has_sleep(loop: ast.AST) -> bool:
    return any(isinstance(x, ast.Call) and _call_name(x) in ("sleep", "wait", "get", "recv", "accept", "read", "readline")
               for x in ast.walk(loop))


def _truthy_const(test: ast.AST) -> bool:
    return isinstance(test, ast.Constant) and bool(test.value)


class ResourceAnalyzer:
    name = "resources"
    languages = None

    def run(self, ctx):
        if ctx.language == "python":
            yield from self._python(ctx)
        yield from self._text(ctx)

    # ---- python ----------------------------------------------------------
    def _python(self, ctx):
        tree = ctx.tree
        if tree is None:
            return
        methods = {id(m) for c in ast.walk(tree) if isinstance(c, ast.ClassDef) for m in c.body}
        for n in ast.walk(tree):
            if isinstance(n, ast.While) and _truthy_const(n.test) and not _has_exit(n):
                sev = 0.4 if _has_sleep(n) else 0.6
                yield ctx.finding("resource_exhaustion", sev, [n.lineno], "res.infinite_loop",
                                  "loop has no exit condition", self.name)
            if isinstance(n, ast.For) and isinstance(n.iter, ast.Call) and _call_name(n.iter) in ("count", "cycle") \
                    and not _has_exit(n):
                yield ctx.finding("resource_exhaustion", 0.55, [n.lineno], "res.infinite_iter",
                                  "iterates an endless iterator with no exit", self.name)
            if isinstance(n, (ast.While, ast.For)):
                for c in ast.walk(n):
                    if isinstance(c, ast.Call) and _call_name(c) in SPAWN_NAMES and c is not n:
                        sev = 0.65 if (isinstance(n, ast.While) and _truthy_const(n.test)) else 0.5
                        yield ctx.finding("resource_exhaustion", sev, [c.lineno], "res.spawn_in_loop",
                                          f"{_call_name(c)}() created inside a loop", self.name)
                        break
            if isinstance(n, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
                big = self._big_iter(n.generators[0].iter) if n.generators else None
                if big and any(isinstance(c, ast.Call) and _call_name(c) in SPAWN_NAMES for c in ast.walk(n.elt)):
                    yield ctx.finding("resource_exhaustion", 0.7, [n.lineno], "res.spawn_many",
                                      f"creates ~1e{int(big)} processes/threads/sockets", self.name)
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mult):
                m = _sizes(n)
                if m is not None and m >= BIG_LOG10 and isinstance(n.left if _sizes(n) == magnitude(n.right) else n.right,
                                                                    (ast.Constant, ast.List, ast.Tuple)):
                    yield ctx.finding("resource_exhaustion", 0.65, [n.lineno], "res.huge_alloc",
                                      f"allocates a sequence of about 1e{int(m)} elements", self.name)
            if isinstance(n, ast.Call) and _call_name(n) == "range" and n.args:
                m = magnitude(n.args[-1] if len(n.args) < 3 else n.args[1])
                if m is not None and m >= 11:
                    yield ctx.finding("resource_exhaustion", 0.35, [n.lineno], "res.huge_range",
                                      f"iterates a range of about 1e{int(m)}", self.name)
            if isinstance(n, ast.FunctionDef) and id(n) not in methods:
                yield from self._recursion(ctx, n)

    @staticmethod
    def _big_iter(it: ast.AST) -> float | None:
        if isinstance(it, ast.Call) and _call_name(it) == "range" and it.args:
            m = magnitude(it.args[-1] if len(it.args) < 3 else it.args[1])
            return m if m is not None and m >= 3 else None
        return None

    def _recursion(self, ctx, fn: ast.FunctionDef):
        # a self-call reached before any conditional or return in the body
        if fn.name in {a.arg for a in fn.args.args + fn.args.kwonlyargs}:
            return  # the name is shadowed by a parameter
        for stmt in fn.body:
            if isinstance(stmt, (ast.If, ast.Raise, ast.Try, ast.While, ast.For)):
                return
            for c in ast.walk(stmt):
                if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == fn.name:
                    yield ctx.finding("resource_exhaustion", 0.6, [c.lineno], "res.unbounded_recursion",
                                      f"{fn.name}() calls itself with no base case", self.name)
                    return

    # ---- shell / js / generic -------------------------------------------
    # quantifiers are bounded so huge inputs cannot cause catastrophic backtracking
    _SH_LOOP = re.compile(r"\bwhile\s+(?:true|:|\[\s*1\s*\])[ \t]*;?\s*do\b(?P<body>.{0,2000}?)\bdone\b", re.S)
    _FORK = re.compile(r"(?P<n>[\w:]{1,24})[ \t]*\(\)[ \t]*\{[^}]{0,120}?(?P=n)[ \t]*\|[ \t]*(?P=n)[ \t]*&")
    _FILL = re.compile(r"\b(?:dd\s+[^\n]*if=/dev/(?:zero|urandom|random)|(?:cat|yes|head\s+-c\s*\S+)\s+/dev/(?:zero|urandom)[^\n]*>)")
    _DD_BOUNDED = re.compile(r"\bcount=\d+|head\s+-c")
    _YES = re.compile(r"\byes\b[^\n|]*>\s*/dev/null|\byes\b[^\n]*>\s*\S+")
    _JS_LOOP = re.compile(r"\bwhile\s*\(\s*(?:true|1)\s*\)|\bfor\s*\(\s*;\s*;\s*\)")
    _JS_TIMER = re.compile(r"\bsetInterval\s*\([^)]*,\s*0\s*\)")

    def _text(self, ctx):
        code = ctx.code[:50_000]
        if ctx.language in ("bash", "text", "markdown", "yaml", "dockerfile"):
            for m in self._FORK.finditer(code):
                yield ctx.finding("resource_exhaustion", 0.95, [line_of(code, m.start())], "res.fork_bomb",
                                  "function pipes itself into itself in the background (fork bomb)", self.name)
            for m in self._SH_LOOP.finditer(code):
                if not re.search(r"\bsleep\b|\bread\b|\bbreak\b|\bexit\b", m.group("body")):
                    yield ctx.finding("resource_exhaustion", 0.6, [line_of(code, m.start())], "res.sh_busy_loop",
                                      "endless shell loop with no sleep or exit", self.name)
            for m in self._FILL.finditer(code):
                eol = code.find("\n", m.end())
                if not self._DD_BOUNDED.search(code[m.start():eol if eol != -1 else len(code)]):
                    yield ctx.finding("resource_exhaustion", 0.7, [line_of(code, m.start())], "res.disk_fill",
                                      "writes an unbounded stream to a file/device", self.name)
            for m in self._YES.finditer(code):
                yield ctx.finding("resource_exhaustion", 0.55, [line_of(code, m.start())], "res.yes_flood",
                                  "`yes` redirected without a bound", self.name)
        if ctx.language == "javascript":
            for m in self._JS_LOOP.finditer(code):
                tail = code[m.end():m.end() + 300]
                if not re.search(r"\b(?:break|return|throw|await)\b", tail.split("}")[0]):
                    yield ctx.finding("resource_exhaustion", 0.6, [line_of(code, m.start())], "res.js_loop",
                                      "loop with no exit condition", self.name)
            for m in self._JS_TIMER.finditer(code):
                yield ctx.finding("resource_exhaustion", 0.5, [line_of(code, m.start())], "res.js_timer",
                                  "timer firing with zero delay", self.name)

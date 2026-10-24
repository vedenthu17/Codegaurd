"""SQL statement analyzer: destructive or privilege-changing statements."""
from __future__ import annotations

import re

from .common import clip, line_of

_COMMENTS = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
_UPDATE = re.compile(r"\bUPDATE\s+[\w.`\"\[\]]+\s+SET\b", re.I)
_DELETE = re.compile(r"\bDELETE\s+FROM\s+[\w.`\"\[\]]+", re.I)
_WHERE = re.compile(r"\bWHERE\b", re.I)
_DROP = re.compile(r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b", re.I)
_TRUNCATE = re.compile(r"\bTRUNCATE\s+(?:TABLE\s+)?[\w.`\"\[\]]+", re.I)
_GRANT_ALL = re.compile(r"\bGRANT\s+ALL\b", re.I)
_SUPERUSER = re.compile(r"\b(?:CREATE|ALTER)\s+(?:USER|ROLE)\b[^;]*\bSUPERUSER\b", re.I)


def _blank(m: re.Match) -> str:
    # keep offsets and line numbers stable
    return re.sub(r"[^\n]", " ", m.group(0))


class SqlAnalyzer:
    name = "sql"
    languages = frozenset({"sql"})

    def run(self, ctx):
        text = _COMMENTS.sub(_blank, ctx.code)
        start = 0
        for stmt in text.split(";"):
            yield from self._statement(ctx, text, stmt, start)
            start += len(stmt) + 1

    def _statement(self, ctx, text, stmt, start):
        def line(m):
            return line_of(text, start + m.start())

        for pat, verb in ((_UPDATE, "UPDATE"), (_DELETE, "DELETE")):
            m = pat.search(stmt)
            if m and not _WHERE.search(stmt, m.end()):
                yield ctx.finding("destructive_command", 0.8, [line(m)], f"sql.{verb.lower()}_no_where",
                                  f"{verb} without WHERE affects every row: {clip(m.group(0))}", self.name)
        for pat, rule, msg in ((_DROP, "sql.drop", "drops a table/database"),
                               (_TRUNCATE, "sql.truncate", "truncates a table")):
            m = pat.search(stmt)
            if m:
                yield ctx.finding("destructive_command", 0.75, [line(m)], rule, msg, self.name)
        for pat, rule, msg in ((_GRANT_ALL, "sql.grant_all", "grants all privileges"),
                               (_SUPERUSER, "sql.superuser", "creates or elevates a superuser role")):
            m = pat.search(stmt)
            if m:
                yield ctx.finding("persistence_or_privesc", 0.7, [line(m)], rule, msg, self.name)

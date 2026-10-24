"""Sensitive-path analyzer.

Scans quoted string literals (any language) against the credential-file and
persistence-location catalogs in `rules/catalog.py`. A path alone is a
moderate signal; reading/writing context raises it. Paths that appear only
inside prose comments are not considered, because only quoted literals are
scanned.
"""
from __future__ import annotations

import re

from .common import clip, credential_path, line_of, persistence_path

_STRING = re.compile(r"""(?P<q>['"])(?P<body>(?:\\.|(?!(?P=q)).){3,300})(?P=q)""")
_WRITE_HINT = re.compile(r"""open\([^)]*['"][wa]b?\+?['"]|write_text|\.write\(|>>?\s*\S|tee\b|\bcp\b|\bmv\b|\becho\b""", re.I)


class PathAnalyzer:
    name = "paths"
    languages = None

    def run(self, ctx):
        lines = ctx.lines
        for m in _STRING.finditer(ctx.code):
            body = m.group("body")
            if len(body.split()) > 2:
                continue  # a sentence (error message, docstring) that mentions a path, not a path
            line = line_of(ctx.code, m.start())
            ctx_line = lines[line - 1] if line - 1 < len(lines) else ""
            cred = credential_path(body)
            if cred:
                yield ctx.finding("secret_access", 0.6, [line], "paths.credential",
                                  f"references {cred}: {clip(body, 60)}", self.name)
            pers = persistence_path(body)
            if pers:
                sev = 0.65 if _WRITE_HINT.search(ctx_line) else 0.4
                yield ctx.finding("persistence_or_privesc", sev, [line], "paths.persistence",
                                  f"touches {pers}: {clip(body, 60)}", self.name)

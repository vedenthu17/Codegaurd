"""Fenced code blocks inside markdown (or prose that contains them).

Each block is analysed as code in its own language, with findings attributed
to the block's lines in the original text, so an assistant reply that mixes
explanation and code is judged on the code it contains.
"""
from __future__ import annotations

import re

from ..engine import FENCE_LANG

_FENCE = re.compile(r"^[ \t]*(?:```|~~~)[ \t]*([\w+-]*)[^\n]*\n(.*?)^[ \t]*(?:```|~~~)[ \t]*$", re.S | re.M)


class FenceAnalyzer:
    name = "fences"
    languages = frozenset({"markdown", "text"})

    def run(self, ctx):
        code = ctx.code[:100_000]
        for m in _FENCE.finditer(code):
            body = m.group(2)
            if not body.strip():
                continue
            first = code[:m.start(2)].count("\n") + 1
            n = body.count("\n") + 1
            lang = FENCE_LANG.get(m.group(1).lower())
            yield from ctx.analyze_embedded(body, lang, range(first, first + n))

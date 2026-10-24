"""Tolerant Python parsing.

`ast.parse` rejects a whole file for one syntax error, which would silently
switch off every AST-based layer (truncated model output, a stray line, a
Python 2 print). `parse_tolerant` first tries the whole file; if that fails it
splits the text at top-level statement starts, parses each chunk on its own,
and merges the chunks that parse into one module with original line numbers.
"""
from __future__ import annotations

import ast
import warnings

MAX_LINES = 60_000
_CONTINUATION = ("else", "elif", "except", "finally", ")", "]", "}")


def _parse(text: str):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(text)


def parse_tolerant(code: str) -> ast.Module | None:
    try:
        return _parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        pass
    lines = code.splitlines(keepends=True)
    if len(lines) > MAX_LINES:
        return None
    starts = [0]
    for i, line in enumerate(lines):
        if i and line.strip() and not line[0].isspace() and not line.startswith(_CONTINUATION) \
                and not line.lstrip().startswith("#"):
            starts.append(i)
    body: list[ast.stmt] = []
    for a, b in zip(starts, starts[1:] + [len(lines)]):
        chunk = "".join(lines[a:b])
        if not chunk.strip():
            continue
        try:
            tree = _parse(chunk)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        if a:
            ast.increment_lineno(tree, a)
        body.extend(tree.body)
    return ast.Module(body=body, type_ignores=[]) if body else None

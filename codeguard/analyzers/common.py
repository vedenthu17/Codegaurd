"""Helpers shared by analyzers."""
from __future__ import annotations

import math
import re
from collections import Counter

from ..rules.catalog import CREDENTIAL_PATHS, PERSISTENCE_PATHS

# Placeholder for any value that is only known at runtime. Analyzers of
# embedded payloads (shell, SQL, URLs) treat it as attacker-influenced input.
DYN = "__DYN__"


def has_dyn(s: str) -> bool:
    return DYN in s


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def credential_path(s: str) -> str | None:
    s = s.replace("\\\\", "\\")
    for pat, label in CREDENTIAL_PATHS:
        if pat.search(s):
            return label
    return None


def persistence_path(s: str) -> str | None:
    for pat, label in PERSISTENCE_PATHS:
        if pat.search(s):
            return label
    return None


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


_WS = re.compile(r"\s+")


def clip(s: str, n: int = 80) -> str:
    s = _WS.sub(" ", s).strip()
    return s if len(s) <= n else s[: n - 1] + "…"

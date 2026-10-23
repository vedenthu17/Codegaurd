"""Registry of detection layers. Each analyzer has a stable `name` used for
ablation (`Engine(disabled={...})`)."""
from __future__ import annotations


def build_all() -> list:
    return []

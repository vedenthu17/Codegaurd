"""CodeGuard: real-time pre-execution safety layer for LLM-generated code."""
from .findings import CATEGORIES, Analysis, Finding

__version__ = "0.1.0"
__all__ = ["CATEGORIES", "Analysis", "Finding", "get_engine"]

_engine = None


def get_engine():
    """Process-wide engine, built once on first use."""
    global _engine
    if _engine is None:
        from .engine import Engine
        _engine = Engine()
    return _engine

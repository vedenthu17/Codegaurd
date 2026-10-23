"""Deterministic stand-in engine for testing the interception mechanics.

It blocks any input containing SENTINEL and allows everything else, so the
guard tests never depend on (or exercise) real detection rules."""
from codeguard.findings import Analysis

SENTINEL = "CG_TEST_BLOCK"


class StubEngine:
    analyzers: list = []

    def analyze(self, code, language=None):
        text = code if isinstance(code, str) else str(code)
        if SENTINEL in text:
            return Analysis("block", 0.99, ["destructive_command"], language or "python",
                            "stub: sentinel found", [1])
        return Analysis("allow", 0.0, [], language or "python", "stub: clean", [])

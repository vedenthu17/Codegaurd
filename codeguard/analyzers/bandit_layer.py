"""Bandit (Apache-2.0) wrapped as an in-process Python AST layer.

Bandit only scans files, so the snippet is written to a temp file (never
executed) and scanned with a pre-built manager. Its test ids are mapped onto
CodeGuard's categories and severities; ids not listed here are ignored, so
generic hygiene warnings (bind-all, missing timeouts, ...) never block.
"""
from __future__ import annotations

import logging
import os
import re
import tempfile

from bandit.core import config as b_config
from bandit.core import manager as b_manager

# test id -> (category, severity, message)
BANDIT_MAP: dict[str, tuple[str, float, str]] = {
    "B102": ("obfuscated_execution", 0.6, "exec() runs dynamically supplied code"),
    "B307": ("obfuscated_execution", 0.6, "eval() runs dynamically supplied code"),
    "B301": ("obfuscated_execution", 0.6, "pickle deserialisation can execute code on load"),
    "B302": ("obfuscated_execution", 0.6, "marshal/shelve deserialisation can execute code on load"),
    "B506": ("obfuscated_execution", 0.55, "yaml.load without a safe loader can execute code"),
    "B602": ("destructive_command", 0.6, "shell=True with a non-constant command string"),
    "B604": ("destructive_command", 0.4, "function call with shell=True"),
    "B605": ("destructive_command", 0.35, "command string passed to a shell"),
    "B609": ("destructive_command", 0.5, "wildcard injection in a shell command"),
    "B103": ("persistence_or_privesc", 0.6, "sets a permissive file mode"),
    # B105-B107 (hardcoded password by variable name) are intentionally not mapped:
    # they fire on names like `token_type`; secrets.py applies entropy checks instead.
    "B701": ("obfuscated_execution", 0.4, "template rendering with autoescape disabled"),
}

# cheap token prefilter covering every test id in BANDIT_MAP
PREFILTER = re.compile(r"exec|eval|pickle|marshal|shelve|yaml|shell|system|popen|spawn|chmod|jinja|Environment|subprocess")

_logging_quiet = False


def _quiet() -> None:
    global _logging_quiet
    if not _logging_quiet:
        logging.getLogger("bandit").setLevel(logging.CRITICAL)
        _logging_quiet = True


class BanditAnalyzer:
    name = "bandit"
    languages = frozenset({"python"})

    def __init__(self) -> None:
        _quiet()
        self._conf = b_config.BanditConfig()

    def run(self, ctx):
        if ctx.depth:  # embedded payloads are re-scanned by the other layers
            return
        if not PREFILTER.search(ctx.code):
            return  # none of the mapped tests can fire: skip the ~10-25 ms scan
        fd, path = tempfile.mkstemp(suffix=".py", prefix="cg_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(ctx.code)
            mgr = b_manager.BanditManager(self._conf, "file")
            mgr.discover_files([path])
            mgr.run_tests()
            issues = mgr.get_issue_list()
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        for issue in issues:
            spec = BANDIT_MAP.get(issue.test_id)
            if spec:
                category, severity, message = spec
                yield ctx.finding(category, severity, [issue.lineno], f"bandit.{issue.test_id}",
                                  message, self.name)

"""Hardcoded credential detection for any language.

Two kinds of evidence: well-known token formats (strong) and a secret-like
variable name assigned a long, high-entropy literal (moderate). Short or
low-entropy values and obvious placeholders do not count, so documentation
that mentions `password = 'hunter2'` is left alone.
"""
from __future__ import annotations

import re

from ..rules.catalog import SECRET_NAME
from .common import entropy, line_of

TOKEN_FORMATS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "GitHub token"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "GitLab token"),
    (re.compile(r"\bsk-(?:live-|proj-|ant-)?[A-Za-z0-9_-]{20,}\b"), "API secret key"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key"),
    (re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "SendGrid key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "JWT"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "private key block"),
    (re.compile(r"\b(?:sk|rk|pk)_live_[0-9a-zA-Z]{16,}\b"), "payment provider live key"),
]

ASSIGN = re.compile(
    r"""(?P<name>[A-Za-z_][\w.-]{0,40})[ \t]*(?::[ \t]*\w{1,20}[ \t]*)?[:=][ \t]*['"](?P<val>[^'"\s]{12,200})['"]""")
PLACEHOLDER = re.compile(r"(?:your|example|placeholder|changeme|dummy|sample|<|\$\{|\{\{|xxxx|\*{3,}|todo)", re.I)


def _in_docstring_or_comment(code: str, offset: int) -> bool:
    line_start = code.rfind("\n", 0, offset) + 1
    prefix = code[line_start:offset].lstrip()
    if prefix.startswith(("#", "//", "*", "--")):
        return True
    return code.count('"""', 0, offset) % 2 == 1 or code.count("'''", 0, offset) % 2 == 1


class SecretsAnalyzer:
    name = "secrets"
    languages = None

    def run(self, ctx):
        code = ctx.code[:100_000]
        for rx, label in TOKEN_FORMATS:
            for m in rx.finditer(code):
                if _in_docstring_or_comment(code, m.start()):
                    continue
                yield ctx.finding("secret_access", 0.85, [line_of(code, m.start())], "secrets.token_format",
                                  f"hardcoded {label}", self.name)
        for m in ASSIGN.finditer(code):
            name, val = m.group("name"), m.group("val")
            if not SECRET_NAME.search(name) or PLACEHOLDER.search(val) or _in_docstring_or_comment(code, m.start()):
                continue
            if "/" in val and not re.search(r"[A-Z]", val):
                continue  # looks like a path or URL
            if re.fullmatch(r"[A-Za-z]+(?:[-_.][A-Za-z]+)*", val) or not re.search(r"\d", val):
                continue  # words joined by separators, or no digits: an identifier, not a credential
            if entropy(val) >= 3.4 and len(val) >= 16:
                yield ctx.finding("secret_access", 0.6, [line_of(code, m.start())], "secrets.named_literal",
                                  f"secret-like name '{name}' assigned a high-entropy literal", self.name)

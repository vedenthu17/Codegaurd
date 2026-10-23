"""Lightweight language identification.

Scores each candidate language from cheap lexical signals, then confirms the
leaders with a real parser (Python `ast`, YAML loader). Output values follow
the dev-sample convention: python, bash, sql, javascript, yaml, markdown, and
a few extra names for graceful degradation.
"""
from __future__ import annotations

import ast
import re
import warnings

import yaml

_SIGNALS: dict[str, list[tuple[re.Pattern[str], float]]] = {
    "python": [
        (re.compile(r"^\s*(?:from\s+[\w.]+\s+)?import\s+[\w.]+", re.M), 2.0),
        (re.compile(r"^\s*(?:async\s+)?def\s+\w+\s*\(.*\)\s*(?:->\s*[^:]+)?:\s*$", re.M), 3.0),
        (re.compile(r"^\s*class\s+\w+(?:\(.*\))?:\s*$", re.M), 2.0),
        (re.compile(r"^\s*(?:if|elif|while|for|with|try|except)\b.*:\s*$", re.M), 1.0),
        (re.compile(r"\bself\.\w+"), 1.0),
        (re.compile(r"\bprint\("), 0.5),
        (re.compile(r"\b(?:None|True|False)\b"), 0.5),
        (re.compile(r"^\s*@\w+", re.M), 0.5),
        (re.compile(r'"""|\'\'\''), 1.0),
    ],
    "bash": [
        (re.compile(r"^\s*(?:set\s+-[euxo]+|export\s+\w+=)", re.M), 2.0),
        (re.compile(r"\$\{?\w+\}?"), 0.3),
        (re.compile(r"^\s*(?:if\s+\[|fi\s*$|then\s*$|do\s*$|done\s*$|esac\s*$)", re.M), 2.0),
        (re.compile(r"^\s*\w+\s*\(\)\s*\{", re.M), 2.0),
        (re.compile(r"^\s*(?:sudo|apt(?:-get)?|yum|brew|echo|curl|wget|chmod|chown|rm|mkdir|cd|cp|mv|dd|npm|pip3?|cat|grep|tar|ssh|scp|nc|crontab|systemctl|kill|nohup|ls|find|touch|sed|awk|xargs|source|bash|sh|exit|base64|openssl|git|docker|kubectl|mkfs|shred|useradd|usermod|iptables|ufw|service|printf|read|while|until|trap|eval|exec)\b", re.M), 1.0),
        (re.compile(r"^\s*[\w./-]+(?:\s+-{1,2}[\w-]+)+", re.M), 0.5),
        (re.compile(r"\s(?:\|\||&&|2>&1|>>?)\s"), 0.5),
        (re.compile(r"\|\s*(?:ba)?sh\b"), 1.5),
        (re.compile(r":\(\)\s*\{"), 3.0),
    ],
    "sql": [
        (re.compile(r"^\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE|DROP|ALTER|TRUNCATE|GRANT|REVOKE|WITH|BEGIN|DECLARE|CALL|EXEC)\b", re.M | re.I), 2.0),
        (re.compile(r"\b(?:FROM|WHERE|JOIN|VALUES|GROUP\s+BY|ORDER\s+BY|TABLE|PROCEDURE)\b"), 1.0),
        (re.compile(r";\s*$", re.M), 0.5),
        (re.compile(r"^\s*--\s", re.M), 0.5),
    ],
    "javascript": [
        (re.compile(r"^\s*(?:const|let|var)\s+[\w{\[]", re.M), 2.0),
        (re.compile(r"\bfunction\s*\w*\s*\("), 1.5),
        (re.compile(r"=>"), 1.0),
        (re.compile(r"\brequire\(\s*['\"]"), 2.0),
        (re.compile(r"\b(?:module\.exports|exports\.\w+|console\.\w+|document\.|window\.|process\.env)"), 2.0),
        (re.compile(r"^\s*(?:import\s+.+\s+from\s+['\"]|export\s+(?:default|const|function|class))", re.M), 2.5),
        (re.compile(r"===|!=="), 1.0),
        (re.compile(r"\bawait\s+fetch\("), 1.0),
    ],
    "yaml": [
        (re.compile(r"^[\w.-]+:\s*$", re.M), 1.0),
        (re.compile(r"^\s+-\s+[\w.-]+:\s", re.M), 1.5),
        (re.compile(r"^\s*(?:jobs|steps|runs-on|services|apiVersion|kind|image|stages|script):", re.M), 2.0),
    ],
    "markdown": [
        (re.compile(r"^#{1,6}\s+[A-Z][^\n]*$", re.M), 1.5),
        (re.compile(r"^```", re.M), 2.0),
        (re.compile(r"\[[^\]]+\]\([^)]+\)"), 1.5),
        (re.compile(r"^\s*[-*]\s+\S", re.M), 0.3),
        (re.compile(r"\*\*[^*]+\*\*"), 1.0),
        (re.compile(r"<!--"), 1.0),
    ],
    "powershell": [
        (re.compile(r"\b(?:Get|Set|New|Remove|Invoke|Start|Stop)-[A-Z]\w+"), 3.0),
        (re.compile(r"\$\w+\s*=\s*"), 0.3),
    ],
    "dockerfile": [
        (re.compile(r"^(?:FROM|RUN|COPY|ENTRYPOINT|CMD|WORKDIR|ENV)\s", re.M), 2.0),
    ],
    "php": [(re.compile(r"<\?php"), 6.0)],
    "go": [(re.compile(r"^package\s+\w+\s*$", re.M), 3.0), (re.compile(r"\bfunc\s+\w+\("), 2.0)],
    "ruby": [(re.compile(r"^\s*(?:require\s+'|def\s+\w+\s*$|end\s*$|puts\s)", re.M), 1.0)],
}

_SHEBANG = re.compile(r"^#!\s*(?:/usr/bin/env\s+)?\S*?(python[\d.]*|node|bash|sh|zsh|ksh|dash|pwsh|ruby|php)\b")
_SHEBANG_MAP = {"node": "javascript", "pwsh": "powershell", "ruby": "ruby", "php": "php"}


def _python_parses(code: str) -> bool:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(code)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return False
    # A lone bare word or constant parses as Python too; require structure.
    return any(
        not isinstance(n, ast.Expr) or isinstance(n.value, (ast.Call, ast.Await, ast.Lambda))
        for n in tree.body
    ) or len(tree.body) > 1


def _yaml_mapping(code: str) -> bool:
    try:
        doc = yaml.safe_load(code)
    except Exception:
        return False
    return isinstance(doc, (dict, list)) and len(doc) >= 1 and not isinstance(doc, str)


def detect_language(code: str) -> str:
    text = code.strip()
    if not text:
        return "text"
    sample = text[:20000]

    m = _SHEBANG.match(sample)
    if m:
        interp = m.group(1)
        if interp.startswith("python"):
            return "python"
        return _SHEBANG_MAP.get(interp, "bash")

    scores = {
        lang: sum(min(len(p.findall(sample)), 6) * w for p, w in sigs)
        for lang, sigs in _SIGNALS.items()
    }
    # Upper-case SQL keywords in a line-initial position are a strong tell
    # but also appear inside Python strings; the parser bonus sorts it out.
    if _python_parses(sample):
        scores["python"] += 6.0
        scores["sql"] *= 0.3
        scores["bash"] *= 0.5
    elif _yaml_mapping(sample) and scores["markdown"] < 3:
        scores["yaml"] += 4.0

    best = max(scores, key=scores.__getitem__)
    if scores[best] < 1.0:
        return "text"
    return best

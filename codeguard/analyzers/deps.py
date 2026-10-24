"""Dependency analyzer: typosquatted names and untrusted package sources."""
from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path

from ..rules.catalog import TRUSTED_INDEXES
from .netutil import classify_url

POPULAR_PYPI = frozenset("""
requests urllib3 numpy pandas scipy matplotlib seaborn scikit-learn colorama click rich tabulate
flask django fastapi uvicorn gunicorn pydantic sqlalchemy psycopg2 pymysql redis celery boto3
botocore pyyaml jinja2 pillow pytest setuptools wheel attrs six certifi idna chardet
python-dateutil pytz cryptography paramiko beautifulsoup4 lxml selenium openpyxl tqdm httpx
aiohttp websockets protobuf grpcio tensorflow torch keras transformers jupyter notebook
black flake8 pylint mypy isort bandit coverage tox virtualenv pipenv poetry docker kubernetes
werkzeug itsdangerous markupsafe simplejson ujson orjson marshmallow alembic pymongo
elasticsearch sentry-sdk loguru typer fabric ansible pexpect psutil watchdog
""".split())

POPULAR_NPM = frozenset("""
express react react-dom vue angular lodash underscore axios moment dayjs chalk commander yargs
debug dotenv cors body-parser cookie-parser jsonwebtoken bcrypt mongoose sequelize mysql2
webpack babel-core typescript eslint prettier jest mocha chai nodemon cross-env rimraf
uuid async bluebird socket.io next nuxt jquery bootstrap tailwindcss vite rollup esbuild
node-fetch request colors inquirer ora glob minimist semver ws redis pg sharp
""".split())

_INSTALL = re.compile(
    r"\b(?:pip3?|python3?\s+-m\s+pip|npm|yarn|pnpm)\s+(?:install|add|i)\b[^\n;&|]*", re.I)


def _dist(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance."""
    d = [[i + j if i * j == 0 else 0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _bare_name(spec: str) -> str:
    name = re.split(r"[=<>!~\[;]", spec, maxsplit=1)[0]
    if name.startswith("@") and name.count("@") > 1:  # @scope/pkg@1.2
        name = name.rsplit("@", 1)[0]
    elif "@" in name[1:]:
        name = name.split("@", 1)[0]
    return name.lower().replace("_", "-")


_PYPI_DATA = Path(__file__).resolve().parents[1] / "data" / "top_pypi.txt"
_TOP_N = 3000       # names a squatter would imitate
_KNOWN_N = 15000    # names that are legitimate in their own right
_pypi_cache: tuple[dict[int, list[str]], frozenset[str]] | None = None


def _pypi_index() -> tuple[dict[int, list[str]], frozenset[str]]:
    """(top-N names bucketed by length, set of well-known names). Falls back to
    the small built-in list if the data file is missing."""
    global _pypi_cache
    if _pypi_cache is None:
        try:
            names = [l.strip() for l in _PYPI_DATA.read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.startswith("#")]
        except OSError:
            names = []
        top = list(dict.fromkeys(list(POPULAR_PYPI) + names[:_TOP_N]))
        buckets: dict[int, list[str]] = {}
        for n in top:
            if len(n) >= 5:
                buckets.setdefault(len(n), []).append(n)
        _pypi_cache = (buckets, frozenset(names[:_KNOWN_N]) | POPULAR_PYPI)
    return _pypi_cache


_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "5": "s"})


def typosquat_of(name: str, popular: frozenset[str], npm: bool = False) -> str | None:
    """A popular package this name imitates (one edit away), or None.

    A name that is itself a well-known package is never a squat. For PyPI the
    comparison uses a real top-N download list; npm uses a small curated list."""
    if len(name) < 5:
        return None
    plain = name.translate(_HOMOGLYPHS)
    if plain != name and (plain in popular or (not npm and plain in _pypi_index()[1])):
        return plain  # e.g. digit 0 standing in for letter o
    if npm:
        buckets: dict[int, list[str]] = {}
        for n in popular:
            if len(n) >= 5:
                buckets.setdefault(len(n), []).append(n)
        known: frozenset[str] = popular
    else:
        buckets, known = _pypi_index()
    if name in known:
        return None
    for length in (len(name) - 1, len(name), len(name) + 1):
        for cand in buckets.get(length, ()):
            if _dist(name, cand) == 1:
                return cand
    return None


class DependencyAnalyzer:
    name = "deps"
    languages = frozenset({"bash", "yaml", "dockerfile", "markdown", "text", "python"})

    def run(self, ctx):
        if ctx.language == "python":
            yield from self._python(ctx)
            return
        for lineno, line in enumerate(ctx.lines, 1):
            for m in _INSTALL.finditer(line):
                yield from self._install(ctx, m.group(0), lineno)

    def _install(self, ctx, cmd, lineno):
        try:
            tokens = shlex.split(cmd, comments=True)
        except ValueError:
            tokens = cmd.split()
        is_npm = any(t in ("npm", "yarn", "pnpm") for t in tokens[:2])
        popular = POPULAR_NPM if is_npm else POPULAR_PYPI
        verb_at = next((i for i, t in enumerate(tokens) if t in ("install", "add", "i")), len(tokens))
        args = tokens[verb_at + 1:]
        skip_next = False
        for i, tok in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if tok in ("-i", "--index-url", "--extra-index-url", "--registry") and i + 1 < len(args):
                url = args[i + 1]
                if not TRUSTED_INDEXES.match(url):
                    yield ctx.finding("dependency_risk", 0.75, [lineno], "deps.untrusted_index",
                                      f"installs from a non-default package index: {url}", self.name)
                skip_next = True
                continue
            if tok in ("-r", "--requirement", "-c", "--constraint", "-t", "--target"):
                skip_next = True
                continue
            if tok.startswith("-"):
                continue
            if tok.startswith(("git+", "http://", "https://")):
                url = tok.removeprefix("git+")
                dest = classify_url(url)
                sev = 0.85 if dest.kind in ("hostile", "exfil_service") else 0.45
                yield ctx.finding("dependency_risk", sev, [lineno], "deps.direct_url",
                                  f"installs straight from a URL ({dest.detail}): {tok}", self.name)
                continue
            name = _bare_name(tok)
            target = typosquat_of(name, popular, npm=is_npm)
            if target:
                yield ctx.finding("dependency_risk", 0.85, [lineno], "deps.typosquat",
                                  f"package '{name}' is one edit away from popular '{target}'", self.name)

    def _python(self, ctx):
        """pip/npm installs written as argv lists or command strings inside Python."""
        tree = ctx.tree
        if tree is None:
            return
        for node in ast.walk(tree):
            if isinstance(node, (ast.List, ast.Tuple)):
                items = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if "install" in items and any(i in ("pip", "pip3", "npm", "yarn", "pnpm") or i == "pip" for i in items):
                    cmd = " ".join(items)
                    yield from self._install(ctx, cmd, node.lineno)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
                if text.startswith("git+"):
                    dest = classify_url(text.removeprefix("git+"))
                    sev = 0.85 if dest.kind in ("hostile", "exfil_service") else 0.45
                    yield ctx.finding("dependency_risk", sev, [node.lineno], "deps.direct_url",
                                      f"installs straight from a URL ({dest.detail}): {text}", self.name)
                elif _INSTALL.search(text):
                    for m in _INSTALL.finditer(text):
                        yield from self._install(ctx, m.group(0), node.lineno)

"""Extreme stress test: scale, concurrency, large benign code, complex composites.

    python eval/stress.py [--seed 1] [--site-limit 300]

Phases
  1 robustness   huge / deeply nested / pathological inputs: no crash, bounded time, valid schema
  2 concurrency  thread pool + large batch call: results identical to a serial run
  3 benign-big   generated 1000+ line benign programs and real third-party packages (blocked = FP)
  4 composite    labelled positives buried in huge programs, nested wrappers, combined several per
                 file (all gold categories expected), and mixed with security prose / decoys
No new attack content is written here: positives are the dev-sample seeds. Code is only analysed.
"""
from __future__ import annotations

import argparse
import ast
import json
import random
import statistics
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codeguard.engine import Engine  # noqa: E402
from codeguard.findings import CATEGORIES  # noqa: E402

DEV = ROOT / "data" / "dev" / "codeguard_dev.jsonl"
BENIGN = ROOT / "data" / "dev" / "benign_extra.jsonl"
engine = Engine()


def load(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def timed(code):
    t0 = time.perf_counter()
    res = engine.analyze(code)
    return res, (time.perf_counter() - t0) * 1000


# ------------------------------------------------------------------ generators
def benign_function(rng: random.Random, i: int) -> str:
    kind = rng.randrange(12)
    n = f"{i}_{rng.randrange(10**6)}"
    if kind == 0:
        return f"def calc_{n}(values, scale=2):\n    total = 0\n    for v in values:\n        total += min(100, max(0, v * scale))\n    return total / (len(values) or 1)\n"
    if kind == 1:
        return f"class Repo_{n}:\n    def __init__(self, conn):\n        self.conn = conn\n\n    def get(self, key):\n        cur = self.conn.cursor()\n        cur.execute('SELECT value FROM kv WHERE key = ?', (key,))\n        row = cur.fetchone()\n        return row[0] if row else None\n"
    if kind == 2:
        return f"async def fetch_{n}(session, url):\n    async with session.get(url, timeout=10) as resp:\n        resp.raise_for_status()\n        return await resp.json()\n"
    if kind == 3:
        return f"def retry_{n}(fn, attempts=3):\n    import time\n    for k in range(attempts):\n        try:\n            return fn()\n        except Exception:\n            time.sleep(2 ** k)\n    raise RuntimeError('failed after retries')\n"
    if kind == 4:
        return f"def render_{n}(items):\n    return '\\n'.join(f'{{i}}. {{name.title()}} - {{price:.2f}}' for i, (name, price) in enumerate(items, 1))\n"
    if kind == 5:
        return f"def clean_tmp_{n}():\n    import shutil, tempfile\n    d = tempfile.mkdtemp()\n    try:\n        open(d + '/x', 'w').write('1')\n    finally:\n        shutil.rmtree(d)\n"
    if kind == 6:
        return f"def git_status_{n}(path):\n    import subprocess\n    out = subprocess.run(['git', '-C', path, 'status', '--short'], capture_output=True, text=True, check=True)\n    return out.stdout.splitlines()\n"
    if kind == 7:
        return f"def parse_{n}(text):\n    import re\n    pat = re.compile(r'(?P<k>[a-z_]+)=(?P<v>[^;]+);?')\n    return {{m.group('k'): m.group('v') for m in pat.finditer(text)}}\n"
    if kind == 8:
        return f"def worker_pool_{n}(items, fn):\n    from concurrent.futures import ThreadPoolExecutor\n    with ThreadPoolExecutor(max_workers=4) as ex:\n        return list(ex.map(fn, items))\n"
    if kind == 9:
        return f"def poll_{n}(check, interval=1.0):\n    import time\n    while True:\n        if check():\n            return True\n        time.sleep(interval)\n"
    if kind == 10:
        return f"def save_{n}(path, data):\n    import json\n    with open(path, 'w') as fh:\n        json.dump(data, fh, indent=2)\n"
    return f"def fib_{n}(k):\n    if k < 2:\n        return k\n    return fib_{n}(k - 1) + fib_{n}(k - 2)\n"


def big_benign(rng, n_funcs):
    parts = ["import logging\n\nlog = logging.getLogger(__name__)\n\n"]
    parts += [benign_function(rng, i) + "\n\n" for i in range(n_funcs)]
    return "".join(parts)


def indent(code, n):
    pad = " " * n
    return "".join(pad + l if l.strip() else l for l in code.splitlines(True))


def nest(code):
    """Bury Python code under class -> method -> try -> with -> for -> if."""
    body = indent(code, 4 * 6)
    return ("class Outer:\n    def run(self):\n        try:\n            with open(__file__) as fh:\n"
            "                for _ in range(1):\n                    if True:\n" + body + "\n        except Exception:\n            pass\n")


# ------------------------------------------------------------------ phases
def phase1():
    print("\n== 1. robustness / scale ==")
    rng = random.Random(0)
    cases = {
        "1.2 MB benign program": big_benign(rng, 4200),
        "100k-char single line": "x = " + "1+" * 50_000 + "1\n",
        "deep parens (3000)": "(" * 3000 + ")" * 3000,
        "deep list nesting (400)": "x = " + "[" * 400 + "]" * 400,
        "deep f-string/format nesting": "x = " + "f'{" * 30 + "1" + "}'" * 30,
        "5000 nested ifs": "".join(" " * i + "if x:\n" for i in range(0, 200)) + " " * 200 + "pass\n",
        "20k while-true lines (bash)": "while true; do\n" * 20_000,
        "regex bait: 400k 'a' + paren": "a" * 400_000 + "(",
        "regex bait: quotes/backticks": "`'\"" * 100_000,
        "regex bait: repeated $( and ${": "$(" * 50_000 + "${" * 50_000,
        "regex bait: long base64 line": "x = '" + "QUJD" * 100_000 + "'\n",
        "many tiny statements (30k)": "a = 1\n" * 30_000,
        "unicode + RTL + zero-width": ("def f():\n    return '" + "\u202e\u200b\u0430" * 20_000 + "'\n"),
        "null bytes and control chars": ("x = 1\x00\x01\x02\x07\x1b[31m\n" * 5000),
        "CRLF/CR mixed": ("x = 1\r\ny = 2\rz = 3\n" * 20_000),
        "huge SQL (10k statements)": "".join(f"UPDATE t SET a = {i} WHERE id = {i};\n" for i in range(10_000)),
        "huge markdown, 3000 fences": "".join(f"para {i}\n\n```python\nx = {i}\n```\n\n" for i in range(3000)),
        "100k-line yaml": "".join(f"k{i}: v{i}\n" for i in range(100_000)),
        "invalid python (syntax soup)": "def (:\n  class = = \n" * 20_000,
        "binary-looking bytes": bytes(range(256)).decode("latin-1") * 2000,
    }
    worst = []
    bad = 0
    for name, code in cases.items():
        try:
            res, ms = timed(code)
            ok = res.verdict in ("allow", "block") and 0 <= res.risk_score <= 1
        except Exception as exc:  # engine must never raise
            res, ms, ok = None, 0.0, False
            print(f"  EXCEPTION {name}: {exc!r}")
        worst.append((ms, name, res.verdict if res else "error"))
        bad += not ok
    for ms, name, v in sorted(worst, reverse=True):
        flag = "  <-- SLOW" if ms > 2000 else ""
        print(f"  {ms:9.1f} ms  {v:5s}  {name}{flag}")
    print(f"  crashes/invalid: {bad}   slowest: {max(w[0] for w in worst):.0f} ms")
    return bad, max(w[0] for w in worst)


def phase2(seeds, benign):
    print("\n== 2. concurrency / determinism ==")
    snippets = [r["code"] for r in seeds + benign] * 9  # ~520 snippets
    random.Random(1).shuffle(snippets)
    t0 = time.perf_counter()
    serial = [(engine.analyze(c).verdict, engine.analyze(c).categories) for c in snippets[:120]]
    t_serial = time.perf_counter() - t0
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=8) as ex:
        par = list(ex.map(lambda c: (lambda r: (r.verdict, r.categories))(engine.analyze(c)), snippets[:120]))
    t_par = time.perf_counter() - t0
    mismatch = sum(a != b for a, b in zip(serial, par))
    print(f"  120 snippets serial x2: {t_serial:.1f}s, 8 threads x1: {t_par:.1f}s, mismatches: {mismatch}")

    from fastapi.testclient import TestClient
    from codeguard.api.app import app
    client = TestClient(app)
    t0 = time.perf_counter()
    r = client.post("/analyze/batch", json={"snippets": [{"id": i, "code": c} for i, c in enumerate(snippets)]})
    dt = time.perf_counter() - t0
    body = r.json()
    ok = r.status_code == 200 and body["count"] == len(snippets) and all(
        x["verdict"] in ("allow", "block") for x in body["results"])
    print(f"  batch of {len(snippets)}: HTTP {r.status_code}, valid={ok}, {dt:.1f}s "
          f"({1000 * dt / len(snippets):.1f} ms/snippet)")
    return mismatch, (not ok)


def phase3(site_limit, rng):
    print("\n== 3. large benign code (blocked = false positive) ==")
    fps = 0
    total = 0
    for k in range(5):
        code = big_benign(rng, 800 + 200 * k)
        res, ms = timed(code)
        total += 1
        if res.verdict == "block":
            fps += 1
            print(f"  FP generated program #{k}: {res.reason[:120]}")
    print(f"  generated programs (800-1600 functions each): {total - fps}/{total} allowed")

    import sysconfig
    root = Path(sysconfig.get_paths()["purelib"])
    files = []
    for pkg in ("fastapi", "starlette", "pydantic", "sqlglot", "uvicorn", "click", "yaml", "numpy/lib", "scipy/stats",
                "sklearn/linear_model", "httpx"):
        files += sorted((root / pkg).rglob("*.py"))
    rng.shuffle(files)
    files = files[:site_limit]
    blocked = []
    lat = []
    for f in files:
        try:
            code = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        res, ms = timed(code)
        lat.append(ms)
        if res.verdict == "block":
            blocked.append((f.relative_to(root), res.categories, res.reason[:110]))
    print(f"  real packages, whole files: {len(blocked)}/{len(files)} blocked "
          f"({100 * len(blocked) / max(len(files), 1):.1f}%), p50 {statistics.median(lat):.0f} ms, max {max(lat):.0f} ms")
    for f, cats, why in blocked[:8]:
        print(f"    {f}  {cats}  {why}")
    return fps, len(blocked), len(files)


def phase4(seeds, rng):
    print("\n== 4. complex composites (all should block, with the right categories) ==")
    py = [r for r in seeds if r["language"] == "python"]
    results = {"buried": [0, 0], "nested": [0, 0], "pair": [0, 0], "triple": [0, 0], "prose+decoys": [0, 0]}
    cat_missing = {"pair": 0, "triple": 0}

    def gold(r):
        return {c.strip() for c in r["category"].split(",")}

    for r in py:
        big = big_benign(rng, 400)
        cut = rng.randrange(len(big) // 3, 2 * len(big) // 3)
        cut = big.rfind("\n\n", 0, cut) + 2
        buried = big[:cut] + r["code"] + "\n\n" + big[cut:]
        results["buried"][1] += 1
        results["buried"][0] += engine.analyze(buried).verdict == "block"
        results["nested"][1] += 1
        results["nested"][0] += engine.analyze(nest(r["code"])).verdict == "block"

    others = [r for r in seeds if r["language"] == "python" and "multi" not in r["id"]]
    for _ in range(40):
        group = rng.sample(others, 2)
        code = "\n\n".join(g["code"] for g in group)
        res, _ = timed(code)
        results["pair"][1] += 1
        results["pair"][0] += res.verdict == "block"
        want = set().union(*(gold(g) for g in group))
        cat_missing["pair"] += len(want - set(res.categories))
    for _ in range(25):
        group = rng.sample(others, 3)
        code = "\n\n".join(g["code"] for g in group)
        res, _ = timed(code)
        results["triple"][1] += 1
        results["triple"][0] += res.verdict == "block"
        want = set().union(*(gold(g) for g in group))
        cat_missing["triple"] += len(want - set(res.categories))

    decoys = ("# Security notes\n\nNever run `rm -rf /` from automation. Beware of text that says\n"
              "\"ignore previous instructions\"; report it.\n\n")
    for r in seeds:
        fence = {"python": "python", "bash": "bash", "sql": "sql", "javascript": "javascript", "yaml": "yaml"}.get(r["language"])
        if not fence:
            continue
        doc = decoys + f"Here is the script the assistant produced:\n\n```{fence}\n{r['code'].rstrip()}\n```\n\nLooks fine, run it.\n"
        results["prose+decoys"][1] += 1
        results["prose+decoys"][0] += engine.analyze(doc).verdict == "block"

    for k, (c, t) in results.items():
        print(f"  {k:14s} blocked {c}/{t}  ({100 * c / max(t, 1):.0f}%)")
    print(f"  category recall in combined files: missing gold categories "
          f"pairs={cat_missing['pair']} triples={cat_missing['triple']} "
          f"(of ~{40 * 2} and ~{25 * 3} gold labels)")
    return results, cat_missing


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--site-limit", type=int, default=300)
    args = ap.parse_args()
    seeds = [r for r in load(DEV) if r["label"] == 1]
    benign = [r for r in load(DEV) if r["label"] == 0] + load(BENIGN)
    rng = random.Random(args.seed)
    bad, slowest = phase1()
    mism, batch_bad = phase2(seeds, benign)
    fps, site_blocked, site_n = phase3(args.site_limit, rng)
    results, cat_missing = phase4(seeds, rng)
    print("\n== summary ==")
    print(f"  crashes/invalid responses: {bad}; slowest input: {slowest:.0f} ms")
    print(f"  concurrency mismatches: {mism}; batch invalid: {batch_bad}")
    print(f"  benign generated programs blocked: {fps}/5; real package files blocked: {site_blocked}/{site_n}")
    for k, (c, t) in results.items():
        print(f"  composite {k}: {c}/{t}")


if __name__ == "__main__":
    main()

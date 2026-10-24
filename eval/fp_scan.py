"""False-positive stress test on real benign code.

    python eval/fp_scan.py                         # stdlib, top-level functions and classes
    python eval/fp_scan.py --root path/to/repo     # any directory of .py files
    python eval/fp_scan.py --limit 3000 --seed 1   # random subset (faster; Bandit is ~25 ms/call)
    python eval/fp_scan.py --whole-files           # analyse whole files instead of definitions

Everything it scans is treated as benign, so every block is a likely false
positive. Output: block rate, hits per category/rule, and the top offenders
to review by hand. Code is only analysed, never executed.
"""
from __future__ import annotations

import argparse
import ast
import collections
import random
import sys
import sysconfig
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codeguard.engine import Engine  # noqa: E402

SKIP_DIRS = {"test", "tests", "idlelib", "site-packages", "__pycache__", "lib2to3", "turtledemo"}


def snippets(root: Path, whole_files: bool):
    for path in sorted(root.rglob("*.py")):
        if SKIP_DIRS & set(path.relative_to(root).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if whole_files:
            yield f"{path.relative_to(root)}", text
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                seg = ast.get_source_segment(text, node)
                if seg and 3 <= seg.count("\n") <= 400:
                    yield f"{path.relative_to(root)}:{node.lineno}:{node.name}", seg


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=Path(sysconfig.get_paths()["stdlib"]))
    ap.add_argument("--limit", type=int, default=0, help="random subset size (0 = everything)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--whole-files", action="store_true")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--disable", nargs="*", default=[], help="analyzers to disable (e.g. bandit for speed)")
    args = ap.parse_args()

    items = list(snippets(args.root, args.whole_files))
    if args.limit and len(items) > args.limit:
        random.Random(args.seed).shuffle(items)
        items = items[:args.limit]
    engine = Engine(disabled=args.disable)
    print(f"scanning {len(items)} snippets under {args.root}")

    blocked = []
    cats = collections.Counter()
    rules = collections.Counter()
    t0 = time.perf_counter()
    for name, code in items:
        res = engine.analyze(code)
        if res.verdict == "block":
            blocked.append((res.risk_score, name, res))
            cats.update(res.categories)
            rules.update({f.rule for f in res.findings if f.severity > 0 and f.category in res.categories})
    dt = time.perf_counter() - t0

    n = len(items)
    print(f"blocked {len(blocked)}/{n} = {100 * len(blocked) / max(n, 1):.2f}%   "
          f"({1000 * dt / max(n, 1):.1f} ms/snippet)")
    print("\nby category:", dict(cats.most_common()))
    print("by rule:    ", dict(rules.most_common(15)))
    print(f"\ntop {args.top} by risk:")
    for risk, name, res in sorted(blocked, key=lambda b: -b[0])[:args.top]:
        print(f"  {risk:.2f} {name}\n       {res.categories} {res.reason[:140]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

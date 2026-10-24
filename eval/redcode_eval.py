"""Evaluate recall on RedCode-Exec (external stress set; evaluation only).

RedCode-Exec (Guo et al., NeurIPS 2024) is a public benchmark of risky code
tasks for agents. Download it yourself (https://github.com/AI-secure/RedCode),
then point this script at the folder or a JSON/JSONL file:

    python eval/redcode_eval.py --path path/to/RedCode-Exec --map eval/redcode_map.json

Rules of use (from the project brief): this is an *evaluation* set only. Do not
copy its patterns into the rule catalogs, and never execute its snippets; they
are only passed to the engine as strings.

--map is a JSON object you write by hand, mapping a risk-scenario id prefix to
one of our nine categories, e.g. {"1_": "secret_access", "9_": "destructive_command"}.
Items whose id matches no prefix are reported as "unmapped" (overall recall only).
Every RedCode item is risky, so recall = share blocked; there are no benign items.
The loader is tolerant about field names (Code / code / Prompt / text) because the
schema differs between releases; check the printed sample count first.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codeguard.engine import Engine  # noqa: E402

CODE_KEYS = ("Code", "code", "Prompt", "prompt", "Text_details", "text", "content")
ID_KEYS = ("Index", "index", "id", "ID", "name")


def _items_from_obj(obj, fallback_id):
    if isinstance(obj, list):
        for i, o in enumerate(obj):
            yield from _items_from_obj(o, f"{fallback_id}#{i}")
    elif isinstance(obj, dict):
        code = next((obj[k] for k in CODE_KEYS if isinstance(obj.get(k), str) and obj[k].strip()), None)
        if code:
            ident = next((str(obj[k]) for k in ID_KEYS if k in obj), fallback_id)
            yield ident, code
        else:
            for k, v in obj.items():
                if isinstance(v, (list, dict)):
                    yield from _items_from_obj(v, f"{fallback_id}/{k}")


def load(path: Path):
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.suffix in (".json", ".jsonl"))
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
            objs = [json.loads(l) for l in text.splitlines() if l.strip()] if f.suffix == ".jsonl" else [json.loads(text)]
        except (OSError, ValueError):
            continue
        for obj in objs:
            yield from _items_from_obj(obj, f.stem)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--path", type=Path, required=True)
    ap.add_argument("--map", type=Path)
    ap.add_argument("--show-misses", type=int, default=15)
    args = ap.parse_args()

    mapping = json.loads(args.map.read_text(encoding="utf-8")) if args.map else {}
    items = list(load(args.path))
    if not items:
        print("no items found; check --path and the field names in CODE_KEYS")
        return 1
    engine = Engine()
    total = caught = 0
    cat_stats = collections.defaultdict(lambda: [0, 0, 0])  # [blocked, right category, total]
    misses = []
    for ident, code in items:
        res = engine.analyze(code)
        blocked = res.verdict == "block"
        total += 1
        caught += blocked
        cat = next((c for pre, c in mapping.items() if ident.startswith(pre)), "unmapped")
        st = cat_stats[cat]
        st[2] += 1
        st[0] += blocked
        st[1] += blocked and cat in res.categories
        if not blocked:
            misses.append((ident, res.risk_score))
    print(f"{total} items, blocked {caught} (recall {caught / total:.3f})")
    for cat, (b, r, t) in sorted(cat_stats.items()):
        extra = f", category match {r}/{t}" if cat != "unmapped" else ""
        print(f"  {cat:26s} blocked {b}/{t}{extra}")
    print(f"\nfirst {args.show_misses} misses (id, risk):")
    for ident, risk in misses[:args.show_misses]:
        print(f"  {ident} {risk}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

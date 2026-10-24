"""Evaluate the engine on a labelled JSONL sample.

    python eval/evaluate.py                         # dev sample, in-process
    python eval/evaluate.py --data path.jsonl       # any file in the dev format
    python eval/evaluate.py --ablation              # also re-run with each analyzer disabled
    python eval/evaluate.py --json out.json         # machine-readable report

Rows: {id, code, language, category, label, rationale}. `category` is
"benign" or comma-separated category names. Snippets are only analysed,
never executed.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codeguard.engine import Engine  # noqa: E402
from codeguard.findings import CATEGORIES  # noqa: E402

DEFAULT_DATA = ROOT / "data" / "dev" / "codeguard_dev.jsonl"


def load(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def gold_categories(row: dict) -> set[str]:
    cats = {c.strip() for c in str(row.get("category", "")).split(",")}
    return {c for c in cats if c in CATEGORIES}


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4), "tp": tp, "fp": fp, "fn": fn}


def percentile(xs: list[float], q: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = min(len(xs) - 1, max(0, round(q * (len(xs) - 1))))
    return xs[k]


def run(engine: Engine, rows: list[dict]) -> dict:
    tp = fp = fn = tn = 0
    per_cat = {c: [0, 0, 0] for c in CATEGORIES}
    lang_ok = 0
    latencies: list[float] = []
    errors: list[dict] = []
    for row in rows:
        res = engine.analyze(row["code"])
        latencies.append(res.latency_ms)
        gold = int(row.get("label", 0)) == 1
        pred = res.verdict == "block"
        if res.code_language == row.get("language"):
            lang_ok += 1
        if pred and gold:
            tp += 1
        elif pred and not gold:
            fp += 1
        elif gold:
            fn += 1
        else:
            tn += 1
        if pred != gold:
            errors.append({"id": row.get("id"), "kind": "FP" if pred else "FN",
                           "risk_score": res.risk_score, "categories": res.categories,
                           "reason": res.reason})
        g, p = gold_categories(row), set(res.categories)
        for c in CATEGORIES:
            if c in p and c in g:
                per_cat[c][0] += 1
            elif c in p:
                per_cat[c][1] += 1
            elif c in g:
                per_cat[c][2] += 1
    n = len(rows)
    return {
        "n": n,
        "binary": {**prf(tp, fp, fn), "tn": tn, "accuracy": round((tp + tn) / n, 4) if n else 0.0},
        "per_category": {c: prf(*v) for c, v in per_cat.items()},
        "language_accuracy": round(lang_ok / n, 4) if n else 0.0,
        "latency_ms": {"p50": round(percentile(latencies, 0.5), 3),
                       "p95": round(percentile(latencies, 0.95), 3),
                       "mean": round(statistics.fmean(latencies), 3) if latencies else 0.0},
        "errors": errors,
    }


def print_report(rep: dict) -> None:
    b = rep["binary"]
    print(f"samples: {rep['n']}")
    print(f"binary   P={b['precision']:.3f} R={b['recall']:.3f} F1={b['f1']:.3f} "
          f"acc={b['accuracy']:.3f}  (tp={b['tp']} fp={b['fp']} fn={b['fn']} tn={b['tn']})")
    print(f"language accuracy: {rep['language_accuracy']:.3f}")
    lat = rep["latency_ms"]
    print(f"latency  p50={lat['p50']}ms p95={lat['p95']}ms mean={lat['mean']}ms")
    print("\nper category                 P      R      F1   (tp/fp/fn)")
    for c, m in rep["per_category"].items():
        print(f"  {c:26s} {m['precision']:.3f}  {m['recall']:.3f}  {m['f1']:.3f}  ({m['tp']}/{m['fp']}/{m['fn']})")
    if rep["errors"]:
        print("\nmisclassified:")
        for e in rep["errors"]:
            print(f"  {e['kind']} {e['id']} risk={e['risk_score']} {e['categories']}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--ablation", action="store_true")
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    rows = load(args.data)
    engine = Engine()
    for row in rows[:3]:  # warm-up so lazy imports don't skew latency
        engine.analyze(row["code"])
    rep = run(engine, rows)
    rep["analyzers"] = [a.name for a in engine.analyzers]
    print_report(rep)

    if args.ablation:
        print("\nablation (binary F1 with one analyzer disabled)")
        rep["ablation"] = {}
        for name in rep["analyzers"]:
            sub = run(Engine(disabled={name}), rows)["binary"]
            rep["ablation"][name] = sub
            delta = sub["f1"] - rep["binary"]["f1"]
            print(f"  -{name:24s} F1={sub['f1']:.3f} ({delta:+.3f})")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Consolidated accuracy across every dataset we have, in one table.

    python eval/accuracy.py [--redcode <RedCode-Exec dir>] [--site-limit 300]

Datasets
  dev-unsafe / dev-benign   labelled dev sample (tuned on, so optimistic)
  hard-benign               hand-written tricky benign (data/dev/benign_extra.jsonl)
  gen-benign                generated benign programs (structurally varied, never seen)
  mutated-unsafe            dev positives after structural rewrites (generalization)
  real-code-benign          whole files from installed third-party packages (FP proxy)
  redcode-unsafe            RedCode-Exec in-scope scenarios, if --redcode is given (OOD)

Reports precision / recall / accuracy per dataset and an overall confusion
matrix. Positives expected to block, benign expected to allow. Nothing runs.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import sysconfig
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "eval"))

from codeguard.engine import Engine  # noqa: E402
import mutate  # noqa: E402  (generators + structural mutations)

DEV = ROOT / "data" / "dev" / "codeguard_dev.jsonl"
BENIGN = ROOT / "data" / "dev" / "benign_extra.jsonl"
engine = Engine()


def load(path):
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def score(label_block: bool, codes) -> tuple[int, int, list[float]]:
    """Return (correct, total, latencies) for a set of same-label snippets."""
    correct = 0
    total = 0
    lat = []
    for code in codes:
        r = engine.analyze(code)
        lat.append(r.latency_ms)
        total += 1
        correct += (r.verdict == "block") == label_block
    return correct, total, lat


def gen_benign(n, seed):
    rng = random.Random(seed)
    # mix of single functions and small whole programs
    out = [mutate.FILLER_PY.format(i=i) for i in range(n // 2)]  # placeholder, replaced below
    out = []
    import sys as _s
    sys.path.insert(0, str(ROOT / "eval"))
    from stress import benign_function, big_benign
    for i in range(n):
        if i % 4 == 0:
            out.append(big_benign(rng, rng.randint(5, 40)))
        else:
            out.append(benign_function(rng, i))
    return out


def mutated_unsafe(seeds):
    """Every dev positive under each structural mutation (one code string each)."""
    out = []
    for name, fn in mutate.MUTATIONS.items():
        if name == "identity":
            continue
        for r in seeds:
            m = fn(r["code"], r["language"])
            if m and m != r["code"]:
                out.append(m)
    return out


def real_code(limit, seed):
    root = Path(sysconfig.get_paths()["purelib"])
    files = []
    for pkg in ("fastapi", "starlette", "pydantic", "sqlglot", "click", "yaml", "httpx", "numpy/core",
                "sklearn/utils"):
        files += sorted((root / pkg).rglob("*.py"))
    random.Random(seed).shuffle(files)
    out = []
    for f in files[:limit]:
        try:
            out.append(f.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            pass
    return out


def redcode(path):
    sys.path.insert(0, str(ROOT / "eval"))
    from redcode_eval import load as rc_load
    mapping = json.loads((ROOT / "eval" / "redcode_map.json").read_text(encoding="utf-8"))
    prefixes = tuple(k for k in mapping if not k.startswith("_"))
    return [c for i, c in rc_load(Path(path)) if i.startswith(prefixes)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--redcode", type=Path)
    ap.add_argument("--site-limit", type=int, default=300)
    ap.add_argument("--gen", type=int, default=400)
    args = ap.parse_args()

    dev = load(DEV)
    seeds = [r for r in dev if r["label"] == 1]
    rows = [
        ("dev-unsafe", True, [r["code"] for r in seeds]),
        ("dev-benign", False, [r["code"] for r in dev if r["label"] == 0]),
        ("hard-benign", False, [r["code"] for r in load(BENIGN)]),
        ("gen-benign", False, gen_benign(args.gen, 1)),
        ("mutated-unsafe", True, mutated_unsafe(seeds)),
        ("real-code-benign", False, real_code(args.site_limit, 1)),
    ]
    if args.redcode:
        rows.append(("redcode-unsafe", True, redcode(args.redcode)))

    print(f"{'dataset':20s} {'kind':7s} {'n':>5s} {'correct':>8s} {'recall/spec':>12s} {'p50 ms':>7s}")
    TP = FP = FN = TN = 0
    all_lat = []
    for name, block, codes in rows:
        c, t, lat = score(block, codes)
        all_lat += lat
        if block:
            TP += c
            FN += t - c
        else:
            TN += c
            FP += t - c
        metric = "recall" if block else "specificity"
        print(f"{name:20s} {'unsafe' if block else 'benign':7s} {t:5d} {c:8d} "
              f"{metric[:4]} {c / max(t, 1):.3f} {statistics.median(lat):7.1f}")

    prec = TP / (TP + FP) if TP + FP else 0
    rec = TP / (TP + FN) if TP + FN else 0
    acc = (TP + TN) / (TP + FP + FN + TN)
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    print("\nOVERALL CONFUSION (all datasets pooled)")
    print(f"              predicted block   predicted allow")
    print(f"  unsafe        {TP:8d}          {FN:8d}")
    print(f"  benign        {FP:8d}          {TN:8d}")
    print(f"\n  precision={prec:.3f} recall={rec:.3f} F1={f1:.3f} accuracy={acc:.3f}")
    print(f"  latency p50={statistics.median(all_lat):.1f} ms  "
          f"p95={sorted(all_lat)[int(0.95 * len(all_lat))]:.1f} ms  n={len(all_lat)}")
    print("\nNote: dev-* is tuned-on (optimistic); mutated-unsafe is structural only (no obfuscation);")
    print("redcode-unsafe is the out-of-distribution estimate. Treat them separately, not as one number.")


if __name__ == "__main__":
    main()

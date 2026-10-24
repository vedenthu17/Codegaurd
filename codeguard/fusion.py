"""Combine findings from all layers into the final verdict."""
from __future__ import annotations

from collections import defaultdict

from .findings import CATEGORIES, Finding

BLOCK_THRESHOLD = 0.5
# A secondary category is reported only when it is independently strong.
SECONDARY_THRESHOLD = 0.5


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Different layers often report the same fact (e.g. a rule and Bandit on
    one eval call). Independent evidence is on different lines, so keep only
    the strongest finding per (category, lines)."""
    best: dict[tuple, Finding] = {}
    out: list[Finding] = []
    for f in findings:
        if f.severity < 0:
            out.append(f)
            continue
        key = (f.category, f.lines)
        if key not in best or f.severity > best[key].severity:
            best[key] = f
    return out + list(best.values())


def category_scores(findings: list[Finding]) -> dict[str, float]:
    keep: dict[str, float] = defaultdict(lambda: 1.0)
    damp: dict[str, float] = defaultdict(lambda: 1.0)
    for f in _dedupe(findings):
        if f.severity >= 0:
            keep[f.category] *= 1.0 - min(f.severity, 0.99)
        else:
            damp[f.category] *= 1.0 + max(f.severity, -1.0)
    return {
        c: round((1.0 - keep[c]) * damp[c], 4)
        for c in CATEGORIES
        if c in keep
    }


def decide(findings: list[Finding]) -> tuple[str, float, list[str], str, list[int], dict[str, float]]:
    scores = category_scores(findings)
    risk = max(scores.values(), default=0.0)
    verdict = "block" if risk >= BLOCK_THRESHOLD else "allow"

    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    cats: list[str] = []
    if verdict == "block":
        cats = [ranked[0][0]] + [c for c, s in ranked[1:] if s >= SECONDARY_THRESHOLD]

    supporting = [f for f in findings if f.severity > 0 and (f.category in cats or not cats)]
    supporting.sort(key=lambda f: -f.severity)
    lines = sorted({ln for f in supporting if f.category in cats for ln in f.lines})

    if verdict == "block":
        reason = "; ".join(dict.fromkeys(f"[{f.category}] {f.message}" for f in supporting[:4]))
    elif supporting:
        reason = "Weak signals below block threshold: " + "; ".join(
            dict.fromkeys(f.message for f in supporting[:2])
        )
    else:
        reason = "No risky behaviour detected."
    return verdict, round(risk, 4), cats, reason, lines, scores

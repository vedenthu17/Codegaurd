"""Detects text that tries to steer a downstream AI reader (reviewer bot,
agent, summariser) instead of describing the code.

Two signals must co-occur in the same passage for a strong finding: the text
is *addressed* to an AI/automated reader, and it *directs* that reader to
change its behaviour (ignore instructions, approve, skip checks, reveal
internals). A lone mention of either is only weak evidence, so ordinary
comments and security documentation do not trip it.
"""
from __future__ import annotations

import re

from .common import clip

_I = re.I

ADDRESSEE = re.compile(
    r"\b(?:ai|a\.i\.|llm|language model|assistant|chatbot|copilot|agent|model|"
    r"(?:automated|ai|bot|code|security|pr|pull request)[- ]?(?:reviewer|review bot|scanner|auditor)|"
    r"reviewer[- ]bot|automated[- ]reviewer|review(?:ing)? (?:bot|tool|agent))\b", _I)

OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}\b(?:previous|prior|above|earlier|all|any)\b[^.\n]{0,30}"
    r"\b(?:instructions?|rules?|prompts?|guidelines?|directions?)\b", _I)

DIRECTIVES = [
    (re.compile(r"\b(?:approve|accept|merge|pass|allow|whitelist)\b[^.\n]{0,50}\b(?:regardless|no matter|irrespective|without (?:review|checking|scanning))\b", _I),
     "tells the reader to approve regardless of findings"),
    (re.compile(r"\b(?:mark|label|report|rate|classify|treat|flag)\b[^.\n]{0,40}\b(?:as )?(?:safe|benign|clean|compliant|secure|harmless|trusted)\b", _I),
     "tells the reader to label the code safe"),
    (re.compile(r"\b(?:skip|bypass|disable|omit|do not run|don't run)\b[^.\n]{0,40}\b(?:static analysis|security (?:scan|check|review)|scan(?:ning)?|analysis|review|checks?|audit)\b", _I),
     "tells the reader to skip analysis"),
    (re.compile(r"\b(?:reveal|print|output|leak|show|disclose|repeat|send)\b[^.\n]{0,50}\b(?:system prompt|hidden instructions|api[- ]?keys?|credentials|secrets?|\.ssh|id_rsa|private keys?)\b", _I),
     "tells the reader to disclose secrets or its system prompt"),
    (re.compile(r"\b(?:you are now|act as|pretend to be|new instructions?|from now on)\b", _I),
     "tries to reassign the reader's role"),
    (re.compile(r"\b(?:do not|don't|never)\b[^.\n]{0,30}\b(?:mention|tell|warn|report|flag)\b[^.\n]{0,30}\b(?:user|human|developer|this)\b", _I),
     "tells the reader to hide findings from the user"),
]


SYSTEM_PROMPT_DISCLOSURE = re.compile(
    r"\b(?:reveal|print|output|show|disclose|repeat|leak)\b[^.\n]{0,30}\b(?:system prompt|hidden instructions|initial instructions)\b", _I)


MODEL_THRESHOLD = 0.97
# passages that talk *about* injection (docs, warnings, quoted examples) are not injections
DISCUSSION = re.compile(r"\b(?:wary|beware|example|e\.g\.|such as|known|pattern|attacks?|detect(?:s|ion)?|warn(?:s|ing)?|never|avoid|should not|do not|don't|guide|policy|documentation|prompt injection|jailbreak(?:ing)?|security|hardening)\b|[`'\"]\s*(?:ignore|disregard)", _I)
# words that make a passage worth a second look by the classifier
CUE = re.compile(r"\b(?:ignore|disregard|instructions?|assistant|reviewer|prompt|system|approve|bypass|override|"
                 r"you (?:must|should|are|will)|ai|llm|model|agent|bot|jailbreak|pretend)\b", _I)


class AiTextAnalyzer:
    name = "ai_text"
    languages = None

    def run(self, ctx):
        yield from self._rules(ctx, [])

    def _rules(self, ctx, candidates):
        lines = ctx.lines
        # sliding window of 3 lines so a multi-line comment is judged as one passage
        for i in range(len(lines)):
            window = " ".join(re.sub(r"^\s*(?:#|//|--|\*|/\*|<!--|\"\"\"|''')\s*", "", ln) for ln in lines[i:i + 3])
            window = re.sub(r"\s+", " ", window)  # indentation must not widen gaps between words
            if i and window == "":
                continue
            addressed = ADDRESSEE.search(window)
            override = OVERRIDE.search(window)
            hits = [(rx, msg) for rx, msg in DIRECTIVES if rx.search(window)]
            if override and (addressed or hits):
                yield ctx.finding("ai_targeted_instructions", 0.9, range(i + 1, i + 4), "ai_text.override",
                                  f"instruction-override phrase aimed at an AI reader: {clip(override.group(0))}",
                                  self.name)
            elif addressed and hits:
                yield ctx.finding("ai_targeted_instructions", 0.8, range(i + 1, i + 4), "ai_text.directive",
                                  f"text addressed to an AI reader {hits[0][1]}", self.name)
            elif SYSTEM_PROMPT_DISCLOSURE.search(window):
                yield ctx.finding("ai_targeted_instructions", 0.75, range(i + 1, i + 4), "ai_text.prompt_leak",
                                  "text instructs a reader to reveal its system prompt or hidden instructions",
                                  self.name)
            elif len(hits) >= 2:
                yield ctx.finding("ai_targeted_instructions", 0.55, range(i + 1, i + 4), "ai_text.multi_directive",
                                  f"passage issues several behaviour-changing directives ({hits[0][1]})", self.name)
            elif (addressed or hits or override) and len(window.split()) >= 6 and CUE.search(window) \
                    and not DISCUSSION.search(window) and len(candidates) < 6 \
                    and not any(window == t for _, t in candidates):
                # some rule evidence but not enough to decide: a candidate for the model
                candidates.append((i + 1, window))


class AiModelAnalyzer:
    """Local prompt-injection classifier as a second opinion on passages where the
    rules found some evidence but not enough. Runs last, outside the shared time
    budget; does nothing if the model files or onnxruntime are absent."""

    name = "ai_model"
    languages = None
    ignore_deadline = True

    def warm(self) -> None:
        from ..models import injection
        injection.available()

    def run(self, ctx):
        from ..models import injection
        if ctx.depth or not injection.available():
            return
        candidates: list[tuple[int, str]] = []
        strong = False
        for f in AiTextAnalyzer()._rules(ctx, candidates):
            strong |= f.severity >= 0.7
        if strong or not candidates:
            return
        picked = candidates[:3]
        probs = injection.score([t[:600] for _, t in picked])
        for (line, text), p in zip(picked, probs or []):
            if p >= MODEL_THRESHOLD:
                yield ctx.finding("ai_targeted_instructions", 0.8, range(line, line + 3), "ai_text.model",
                                  f"prompt-injection classifier flags this text ({p:.2f}): {clip(text, 60)}",
                                  self.name)

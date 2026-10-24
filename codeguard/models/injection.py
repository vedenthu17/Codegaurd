"""Prompt-injection classifier (ProtectAI deberta-v3-base-prompt-injection-v2, Apache-2.0).

Loaded lazily from `models/pi/` (or $CODEGUARD_PI_MODEL) via onnxruntime. If the
files or the runtime are missing, `score()` returns None and CodeGuard simply
runs without this layer. It is a *second opinion* for ambiguous text, not a
per-request cost: the ai_text layer decides when to call it.
"""
from __future__ import annotations

import logging
import math
import os
import threading
from pathlib import Path

log = logging.getLogger("codeguard.models")

MODEL_DIR = Path(os.getenv("CODEGUARD_PI_MODEL", Path(__file__).resolve().parents[2] / "models" / "pi"))
MAX_TOKENS = 256

_lock = threading.Lock()
_state: dict = {}


def _load():
    with _lock:
        if "session" in _state or _state.get("failed"):
            return
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer

            model = MODEL_DIR / "model.onnx"
            if not model.exists():
                raise FileNotFoundError(model)
            tok = Tokenizer.from_file(str(MODEL_DIR / "tokenizer.json"))
            tok.enable_truncation(max_length=MAX_TOKENS)
            tok.enable_padding()
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = max(1, (os.cpu_count() or 2) // 2)
            sess = ort.InferenceSession(str(model), opts, providers=["CPUExecutionProvider"])
            _state.update(session=sess, tok=tok, inputs={i.name for i in sess.get_inputs()})
        except Exception as exc:  # absent model is a normal configuration
            log.info("prompt-injection model unavailable (%s)", type(exc).__name__)
            _state["failed"] = True


def available() -> bool:
    _load()
    return "session" in _state


def score(texts: list[str]) -> list[float] | None:
    """Probability that each text is a prompt injection, or None if unavailable."""
    _load()
    if "session" not in _state or not texts:
        return None
    import numpy as np

    enc = _state["tok"].encode_batch(texts)
    feeds = {"input_ids": np.array([e.ids for e in enc], dtype=np.int64),
             "attention_mask": np.array([e.attention_mask for e in enc], dtype=np.int64)}
    feeds = {k: v for k, v in feeds.items() if k in _state["inputs"]}
    logits = _state["session"].run(None, feeds)[0]
    out = []
    for row in logits:
        m = max(row)
        exps = [math.exp(x - m) for x in row]
        out.append(exps[1] / sum(exps))  # label 1 = INJECTION
    return out

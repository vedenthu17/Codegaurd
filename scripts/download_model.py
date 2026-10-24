"""Download the optional prompt-injection model used by the ai_text layer.

    python scripts/download_model.py            # -> models/pi/

Model: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0, ungated),
ONNX export, ~740 MB. CodeGuard works without it; when present it is consulted
only for ambiguous comments/strings (see codeguard/models/injection.py).
"""
import sys
import urllib.request
from pathlib import Path

BASE = "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/"
FILES = ["onnx/model.onnx", "onnx/tokenizer.json", "onnx/config.json", "LICENSE"]
DEST = Path(__file__).resolve().parents[1] / "models" / "pi"


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        out = DEST / Path(name).name
        if out.exists() and out.stat().st_size > 0:
            print(f"have {out.name}")
            continue
        print(f"downloading {name} ...", flush=True)
        tmp = out.with_suffix(out.suffix + ".part")
        urllib.request.urlretrieve(BASE + name, tmp)
        tmp.replace(out)
    print("done:", DEST)
    return 0


if __name__ == "__main__":
    sys.exit(main())

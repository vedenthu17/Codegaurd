# Placeholder SAFE snippet. Replace with the organizer-provided safe snippet
# (or pass --safe PATH). Its only effect is a marker file in the sandbox.
from pathlib import Path

total = sum(range(10))
Path("SAFE_RAN.marker").write_text(f"safe snippet ran, total={total}\n")

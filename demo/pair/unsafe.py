# Placeholder UNSAFE snippet: inert by design. Replace with the
# organizer-provided unsafe snippet (or pass --unsafe PATH).
# Its only effect, if it ever ran, is a marker file in the sandbox.
# CG_TEST_BLOCK  (sentinel recognised by --self-test's stub detector)
from pathlib import Path

Path("UNSAFE_RAN.marker").write_text("unsafe snippet ran\n")

"""Process-wide interception via PEP 578 audit hooks.

Wrappers only protect callers that use them. Once `install()` runs, the
interpreter itself routes every dynamic `compile`/`exec`/`eval`, every
`subprocess.Popen`, `os.system`, `os.exec*`, `os.spawn*` and
`os.posix_spawn` through CodeGuard, so an agent (or a careless developer)
calling `exec(llm_output)` directly is still stopped. Audit hooks cannot be
removed once added; raising from the hook aborts the operation before it
starts.

Scope, to keep normal library behaviour working:
  * sources compiled from files on disk (imports) are not re-scanned;
  * dynamic `compile` requested directly by trusted library frames (stdlib,
    site-packages, codeguard itself: dataclasses, namedtuple, ...) is
    skipped, *unless* it happens inside an agent region, where everything is
    checked. Stdlib modules whose job is running arbitrary source (runpy,
    code, codeop, pdb, ...) are never trusted;
  * process creation is always checked, whoever asks for it.
"""
from __future__ import annotations

import ast
import os
import shlex
import sys
import sysconfig
import threading
from pathlib import Path

from .core import CodeGuardBlocked, Guard, consume_approval, in_agent_region

_lock = threading.Lock()
_installed: Guard | None = None

_EXEC_EVENTS = {"os.exec", "os.spawn", "os.posix_spawn"}
_PROCESS_EVENTS = {"subprocess.Popen", "os.system", "os.startfile", *_EXEC_EVENTS}
_WATCHED = {"compile", *_PROCESS_EVENTS}
# stdlib entry points that exist to run arbitrary source: never trusted
_UNTRUSTED_STDLIB = {"runpy.py", "code.py", "codeop.py", "pdb.py", "bdb.py", "timeit.py",
                     "cProfile.py", "profile.py", "trace.py", "doctest.py"}


def _trusted_roots() -> tuple[str, ...]:
    roots = {sys.prefix, sys.base_prefix, sys.exec_prefix}
    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        p = sysconfig.get_paths().get(key)
        if p:
            roots.add(p)
    roots.add(str(Path(__file__).resolve().parents[1]))  # the codeguard package
    return tuple(os.path.normcase(os.path.abspath(r)) for r in roots if r)


def _argv_text(argv) -> str:
    if isinstance(argv, (str, bytes)):
        return argv.decode(errors="replace") if isinstance(argv, bytes) else argv
    try:
        return shlex.join(os.fsdecode(a) for a in argv)
    except Exception:
        return " ".join(map(str, argv))


def install(guard: Guard | None = None) -> Guard:
    """Install the hook once per process. Returns the active Guard."""
    global _installed
    with _lock:
        if _installed is not None:
            return _installed
        guard = guard or Guard()
        roots = _trusted_roots()
        state = threading.local()

        def trusted_file(name) -> bool:
            if not isinstance(name, str) or name.startswith("<"):
                return False
            if os.path.basename(name) in _UNTRUSTED_STDLIB:
                return False
            path = os.path.normcase(os.path.abspath(name))
            return any(path.startswith(r) for r in roots)

        def caller_trusted() -> bool:
            # frame 0 is this function, 1 the hook, 2 the frame raising the event
            try:
                f = sys._getframe(2)
            except ValueError:
                return False
            return trusted_file(f.f_code.co_filename)

        def payload(event: str, args: tuple) -> tuple[str, str | None] | None:
            if event == "compile":
                source, filename = args[0], args[1]
                if source is None:
                    return None
                if isinstance(filename, str) and os.path.isfile(filename):
                    return None  # module import from disk
                if isinstance(source, ast.AST):
                    source = ast.unparse(source)
                elif isinstance(source, (bytes, bytearray)):
                    source = bytes(source).decode("utf-8", "replace")
                return str(source), "python"
            if event == "subprocess.Popen":
                return _argv_text(args[1]), "bash"
            if event == "os.system":
                return _argv_text(args[0]), "bash"
            if event == "os.startfile":
                return _argv_text(args[0]), "bash"
            if event in _EXEC_EVENTS:
                argv = args[2] if event == "os.spawn" else args[1]
                return _argv_text(argv), "bash"
            return None

        def hook(event: str, args: tuple) -> None:
            if event not in _WATCHED or getattr(state, "busy", False):
                return
            state.busy = True
            try:
                if event == "compile" and not in_agent_region() and caller_trusted():
                    return
                item = payload(event, args)
                if item is None:
                    return
                code, lang = item
                if consume_approval(code):
                    return
                if event == "subprocess.Popen" and _approved_tail(args[1]):
                    return
                verdict = guard.check(code, lang)
            except Exception as exc:  # fail closed
                verdict = {"verdict": "block", "risk_score": 1.0, "categories": [],
                           "reason": f"audit hook error {type(exc).__name__}"}
            finally:
                state.busy = False
            if verdict.get("verdict") != "allow":
                raise CodeGuardBlocked(verdict, what=f"{event} (audit hook)")

        sys.addaudithook(hook)
        _installed = guard
        return guard


def _approved_tail(argv) -> bool:
    """run_shell(str) becomes ['/bin/sh', '-c', cmd] on POSIX or a bare str on
    Windows; the command text was approved by Guard.run_shell already."""
    if isinstance(argv, (list, tuple)) and argv:
        return consume_approval(os.fsdecode(argv[-1]))
    return False


def installed() -> bool:
    return _installed is not None

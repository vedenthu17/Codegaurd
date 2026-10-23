"""Interception proof: a blocked snippet never executes.

Every snippet runs with a scratch sandbox directory as its working directory.
The observable side effect is any file the snippet creates there (e.g. a
marker file). For each scenario we list the sandbox before and after.

    python demo/intercept_check.py                          # placeholder pair
    python demo/intercept_check.py --safe S.py --unsafe U.py  # organizer pair
    python demo/intercept_check.py --url http://host:8000   # remote service
    python demo/intercept_check.py --self-test              # stub detector

Scenarios
  1. safe snippet through Guard.run_python        -> executes, side effect appears
  2. unsafe snippet through Guard.run_python      -> blocked, no side effect
  3. unsafe snippet through a @guarded tool        -> blocked, no side effect
  4. unsafe snippet via raw exec() (no wrapper)    -> audit hook blocks, no side effect
  5. guard service unreachable                     -> fail closed, no side effect
Exit code 0 only if every scenario behaves as expected.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from codeguard.guard import CodeGuardBlocked, Guard, HttpChecker, LocalChecker, install_audit_hook  # noqa: E402

PAIR = Path(__file__).parent / "pair"
SANDBOX = Path(__file__).parent / "sandbox"

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def files() -> set[str]:
    return {p.name for p in SANDBOX.iterdir()} if SANDBOX.exists() else set()


def reset_sandbox() -> None:
    shutil.rmtree(SANDBOX, ignore_errors=True)
    SANDBOX.mkdir(parents=True)


class Report:
    def __init__(self):
        self.rows: list[tuple[str, bool, str]] = []

    def add(self, name: str, ok: bool, detail: str) -> None:
        self.rows.append((name, ok, detail))
        tag = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"  [{tag}] {name}\n         {DIM}{detail}{RESET}")


def scenario(report: Report, name: str, fn, expect_block: bool) -> None:
    reset_sandbox()
    before = files()
    blocked, verdict, t0 = False, None, time.perf_counter()
    cwd = os.getcwd()
    os.chdir(SANDBOX)
    try:
        fn()
    except CodeGuardBlocked as exc:
        blocked, verdict = True, exc.verdict
    finally:
        os.chdir(cwd)
    ms = (time.perf_counter() - t0) * 1000
    created = sorted(files() - before)
    if expect_block:
        ok = blocked and not created
        detail = (f"blocked={blocked} side_effects={created or 'none'} {ms:.1f}ms "
                  f"categories={verdict.get('categories') if verdict else None}")
    else:
        ok = (not blocked) and bool(created)
        detail = f"blocked={blocked} side_effects={created or 'none'} {ms:.1f}ms"
    report.add(name, ok, detail)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--safe", type=Path, default=PAIR / "safe.py")
    ap.add_argument("--unsafe", type=Path, default=PAIR / "unsafe.py")
    ap.add_argument("--url", help="use a running CodeGuard service instead of the in-process engine")
    ap.add_argument("--self-test", action="store_true",
                    help="use a stub detector that blocks the CG_TEST_BLOCK sentinel (mechanics only)")
    args = ap.parse_args()

    safe_code = args.safe.read_text(encoding="utf-8")
    unsafe_code = args.unsafe.read_text(encoding="utf-8")

    if args.self_test:
        sys.path.insert(0, str(ROOT / "tests"))
        from stub import StubEngine
        checker = LocalChecker(StubEngine())
        mode = "stub detector (mechanics self-test)"
    elif args.url:
        checker = HttpChecker(args.url, timeout=3.0)
        mode = f"remote service {args.url}"
    else:
        checker = LocalChecker()
        mode = "in-process engine"
        if not checker.engine.analyzers:
            print(f"{RED}warning: no analyzers registered; detection cannot block anything yet "
                  f"(use --self-test to check the mechanics){RESET}")
    guard = Guard(checker)

    print(f"CodeGuard interception check - {mode}")
    print(f"  safe:   {args.safe}\n  unsafe: {args.unsafe}\n  sandbox: {SANDBOX}\n")
    report = Report()

    scenario(report, "1. safe snippet via Guard.run_python executes",
             lambda: guard.run_python(safe_code), expect_block=False)
    scenario(report, "2. unsafe snippet via Guard.run_python is blocked",
             lambda: guard.run_python(unsafe_code), expect_block=True)

    @guard.guarded("code")
    def agent_tool_execute(code: str) -> None:
        exec(compile(code, "<agent-tool>", "exec"), {"__name__": "__agent__"})

    scenario(report, "3. unsafe snippet via @guarded agent tool is blocked",
             lambda: agent_tool_execute(unsafe_code), expect_block=True)

    dead = Guard(HttpChecker("http://127.0.0.1:9", timeout=0.5))
    scenario(report, "4. guard unreachable -> fail closed",
             lambda: dead.run_python(safe_code), expect_block=True)

    # Irreversible for this process, so it runs last.
    install_audit_hook(guard)
    scenario(report, "5. raw exec() bypassing the wrapper is stopped by the audit hook",
             lambda: exec(unsafe_code, {"__name__": "__bypass__"}), expect_block=True)

    passed = sum(ok for _, ok, _ in report.rows)
    colour = GREEN if passed == len(report.rows) else RED
    print(f"\n{colour}{passed}/{len(report.rows)} scenarios passed{RESET}")
    shutil.rmtree(SANDBOX, ignore_errors=True)
    return 0 if passed == len(report.rows) else 1


if __name__ == "__main__":
    sys.exit(main())

"""Interception mechanics: a block must stop execution before it starts."""
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from codeguard.guard import CodeGuardBlocked, Guard, HttpChecker, LocalChecker

from .stub import SENTINEL, StubEngine

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def guard():
    return Guard(LocalChecker(StubEngine()))


def _writer(marker: Path, tag: str = "") -> str:
    return f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')  # {tag}\n"


def test_run_python_allows_clean(guard, tmp_path):
    marker = tmp_path / "ok.marker"
    guard.run_python(_writer(marker))
    assert marker.exists()


def test_run_python_blocks_before_execution(guard, tmp_path):
    marker = tmp_path / "blocked.marker"
    with pytest.raises(CodeGuardBlocked):
        guard.run_python(_writer(marker, SENTINEL))
    assert not marker.exists()


def test_decorator_blocks_before_call(guard):
    calls = []

    @guard.guarded("code")
    def tool(code):
        calls.append(code)

    tool("print('fine')")
    with pytest.raises(CodeGuardBlocked):
        tool(f"print('x')  # {SENTINEL}")
    assert calls == ["print('fine')"]


def test_decorator_positional_and_list_args(guard):
    seen = []

    @guard.guarded(0)
    def run(argv):
        seen.append(argv)

    run(["echo", "hi"])
    with pytest.raises(CodeGuardBlocked):
        run(["echo", SENTINEL])
    assert seen == [["echo", "hi"]]


def test_run_sql_blocks(guard):
    class Cursor:
        executed = []

        def execute(self, sql, params=None):
            self.executed.append(sql)

    cur = Cursor()
    guard.run_sql(cur, "SELECT 1")
    with pytest.raises(CodeGuardBlocked):
        guard.run_sql(cur, f"SELECT 1 -- {SENTINEL}")
    assert cur.executed == ["SELECT 1"]


def test_http_checker_fails_closed_when_service_down(tmp_path):
    g = Guard(HttpChecker("http://127.0.0.1:9", timeout=0.5))
    marker = tmp_path / "down.marker"
    with pytest.raises(CodeGuardBlocked) as exc:
        g.run_python(_writer(marker))
    assert "failing closed" in str(exc.value)
    assert not marker.exists()


def test_checker_exception_fails_closed(tmp_path):
    class Broken:
        def check(self, code, language=None):
            raise RuntimeError("boom")

    marker = tmp_path / "broken.marker"
    with pytest.raises(CodeGuardBlocked):
        Guard(Broken()).run_python(_writer(marker))
    assert not marker.exists()


def test_audit_hook_catches_direct_exec_bypass(tmp_path):
    """Audit hooks are process-wide and irreversible, so run in a child."""
    marker = tmp_path / "bypass.marker"
    script = textwrap.dedent(f"""
        import sys
        sys.path[:0] = [{str(ROOT)!r}, {str(ROOT / 'tests')!r}]
        from stub import StubEngine
        from codeguard.guard import Guard, LocalChecker, CodeGuardBlocked, install_audit_hook
        install_audit_hook(Guard(LocalChecker(StubEngine())))
        exec("x = 1")  # clean dynamic code still runs
        src = {_writer(marker, SENTINEL)!r}
        try:
            exec(src)   # bypasses the wrapper entirely
            print("EXECUTED")
        except CodeGuardBlocked:
            print("BLOCKED")
        try:
            import subprocess
            subprocess.run([sys.executable, "-c", "print(1)  # {SENTINEL}"])
            print("SPAWNED")
        except CodeGuardBlocked:
            print("BLOCKED_PROC")
    """)
    out = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
    assert "BLOCKED" in out.stdout, out.stderr
    assert "BLOCKED_PROC" in out.stdout, out.stderr
    assert "EXECUTED" not in out.stdout and "SPAWNED" not in out.stdout
    assert not marker.exists()

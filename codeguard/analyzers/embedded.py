"""Re-scan code that is passed around as a string inside Python.

The string handed to os.system / subprocess / cursor.execute / eval / exec is
folded statically (constants, f-strings, concatenation, `.format`, `%`, local
helper returns; unknown parts become a runtime placeholder) and run through
the analyzers for its own language: shell, SQL or Python. Findings are
attributed to the host line. SQL text assembled from runtime values is also
reported on its own, since that is how injection happens.
"""
from __future__ import annotations

import ast
import re
import shlex

from .common import DYN
from .pyfold import Folder, UNKNOWN

SHELL_CALLS = {"os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen",
               "subprocess.check_output", "subprocess.check_call", "subprocess.getoutput",
               "subprocess.getstatusoutput", "commands.getoutput"}
SQL_ATTRS = {"execute", "executemany", "executescript", "exec_driver_sql"}
EVAL_FUNCS = {"eval", "exec"}


class EmbeddedAnalyzer:
    name = "embedded"
    languages = frozenset({"python"})

    def run(self, ctx):
        tree = ctx.tree
        if tree is None:
            return
        alias: dict[str, str] = {}
        defs: dict[str, list[ast.AST]] = {}
        rets: dict[str, list[ast.AST]] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    alias[a.asname or a.name] = f"{n.module}.{a.name}"
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                defs.setdefault(n.targets[0].id, []).append(n.value)
            elif isinstance(n, ast.FunctionDef):
                for r in ast.walk(n):
                    if isinstance(r, ast.Return) and r.value is not None:
                        rets.setdefault(n.name, []).append(r.value)

        def qual(f):
            if isinstance(f, ast.Name):
                return alias.get(f.id, f.id)
            if isinstance(f, ast.Attribute):
                base = qual(f.value)
                return f"{base}.{f.attr}" if base else f.attr
            return ""

        def lookup(name, scope):
            if name.startswith("__return__:"):
                v = rets.get(name.split(":", 1)[1], [])
            else:
                v = defs.get(name, [])
            return v[0] if len(v) == 1 else None  # only single-assignment names are trusted

        folder = Folder(qual, lookup)
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call) or not n.args:
                continue
            q = qual(n.func)
            attr = n.func.attr if isinstance(n.func, ast.Attribute) else ""
            arg = n.args[0]
            if q in SHELL_CALLS:
                text = self._shell_text(folder, arg)
                if text:
                    yield from ctx.analyze_embedded(text, "bash", [n.lineno])
            elif attr in SQL_ATTRS:
                text = folder.partial(arg)
                if text and text != DYN:
                    yield from ctx.analyze_embedded(text, "sql", [n.lineno])
                yield from self._sql_injection(ctx, folder, arg, text, n.lineno)
            elif q in EVAL_FUNCS and isinstance(n.func, ast.Name):
                value = folder.value(arg)
                if isinstance(value, (bytes, str)) and value:
                    code = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
                    yield from ctx.analyze_embedded(code, "python", [n.lineno])
                    if folder.decoded:
                        yield ctx.finding("obfuscated_execution", 0.9, [n.lineno], "embedded.decoded_exec",
                                          f"{q}() runs a payload that is decoded at analysis time", self.name)

    @staticmethod
    def _shell_text(folder: Folder, arg: ast.AST) -> str:
        if isinstance(arg, (ast.List, ast.Tuple)):
            parts = [folder.partial(e) for e in arg.elts]
            return " ".join(shlex.quote(p) if p != DYN and not re.fullmatch(r"[\w./:=@%+-]+", p) else p for p in parts)
        return folder.partial(arg)

    def _sql_injection(self, ctx, folder: Folder, arg: ast.AST, text: str, line: int):
        built = isinstance(arg, (ast.JoinedStr, ast.BinOp)) or (
            isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format") or (
            isinstance(arg, ast.Name))
        if not built or DYN not in text:
            return
        head = text.lstrip().split(None, 1)[0].upper() if text.strip() else ""
        category = {"DELETE": "destructive_command", "DROP": "destructive_command", "UPDATE": "destructive_command",
                    "SELECT": "data_exfiltration"}.get(head)
        if category:
            yield ctx.finding(category, 0.55, [line], "embedded.sql_injection",
                              f"{head} statement is built by formatting runtime values into the SQL text "
                              f"(injection risk); use parameters", self.name)

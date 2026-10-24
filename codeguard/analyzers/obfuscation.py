"""obfuscated_execution analyzer.

Detects code that hides what it runs: dynamic evaluation of decoded data,
dynamic imports with computed names, reflective attribute lookups, and the
shell/JavaScript equivalents. High-entropy literals only add weak evidence.
"""
from __future__ import annotations

import ast
import re

from .common import clip, entropy, line_of

EXEC_FUNCS = {"eval", "exec", "compile"}
DECODER_NAMES = {"b64decode", "b32decode", "b16decode", "b85decode", "a85decode", "urlsafe_b64decode",
                 "decodebytes", "unhexlify", "a2b_hex", "a2b_base64", "fromhex", "decompress", "unquote",
                 "unescape", "loads", "decode", "chr", "reversed", "translate", "rot13"}
IMPORT_FUNCS = {"__import__", "import_module"}
EXEC_MODULES = {"os", "subprocess", "pty", "commands"}
EXEC_ATTRS = {"system", "popen", "spawn", "run", "call", "Popen", "check_output", "check_call"}


def _expand(node: ast.AST, defs: dict[str, ast.AST], depth: int = 3) -> list[ast.AST]:
    """The node plus the expressions assigned to names it uses (bounded)."""
    out = [node]
    if depth <= 0:
        return out
    for c in ast.walk(node):
        if isinstance(c, ast.Name) and c.id in defs:
            out.extend(_expand(defs[c.id], defs, depth - 1))
    return out


def _decodes(nodes: list[ast.AST]) -> bool:
    for root in nodes:
        for c in ast.walk(root):
            if isinstance(c, ast.Call):
                f = c.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if name in DECODER_NAMES - {"loads", "decode"}:
                    return True
                if name in ("loads", "decode") and isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) \
                        and f.value.id in ("marshal", "codecs", "base64", "zlib"):
                    return True
            if isinstance(c, ast.Subscript) and isinstance(c.slice, ast.Slice) and isinstance(c.slice.step, ast.UnaryOp):
                return True  # [::-1]
    return False


def _constant_string(n: ast.AST) -> bool:
    return isinstance(n, ast.Constant) and isinstance(n.value, str)


class ObfuscationAnalyzer:
    name = "obfuscation"
    languages = None

    def run(self, ctx):
        if ctx.language == "python":
            yield from self._python(ctx)
        yield from self._text(ctx)

    def _python(self, ctx):
        tree = ctx.tree
        if tree is None:
            return
        defs: dict[str, ast.AST] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                defs[n.targets[0].id] = n.value
        # aliased process-execution modules (`import os as o`) and helpers that import by parameter
        aliased: dict[str, str] = {}
        importer_params: dict[str, int] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname and a.name in EXEC_MODULES and a.asname != a.name:
                        aliased[a.asname] = a.name
            elif isinstance(n, ast.FunctionDef):
                params = [a.arg for a in n.args.args]
                for c in ast.walk(n):
                    if isinstance(c, ast.Call) and isinstance(c.func, (ast.Name, ast.Attribute))                             and (getattr(c.func, "id", None) or getattr(c.func, "attr", "")) in IMPORT_FUNCS                             and c.args and isinstance(c.args[0], ast.Name) and c.args[0].id in params:
                        importer_params[n.name] = params.index(c.args[0].id)
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in aliased                     and f.attr in EXEC_ATTRS and n.args and not _constant_string(n.args[0]):
                yield ctx.finding("obfuscated_execution", 0.55, [n.lineno], "obf.aliased_exec",
                                  f"{aliased[f.value.id]} imported as '{f.value.id}' and used to run a "
                                  f"runtime-built command", self.name)
            if isinstance(f, ast.Name) and f.id in importer_params and len(n.args) > importer_params[f.id]:
                arg = n.args[importer_params[f.id]]
                if not _constant_string(arg) and isinstance(arg, (ast.BinOp, ast.JoinedStr, ast.Call)):
                    yield ctx.finding("obfuscated_execution", 0.7, [n.lineno], "obf.computed_import_arg",
                                      f"{f.id}() imports a module by name and is given a computed name", self.name)
            if name in EXEC_FUNCS and isinstance(f, ast.Name) and n.args:
                if _decodes(_expand(n.args[0], defs)):
                    yield ctx.finding("obfuscated_execution", 0.92, [n.lineno], "obf.decode_exec",
                                      f"{name}() runs data produced by a decoding step", self.name)
                elif not _constant_string(n.args[0]):
                    yield ctx.finding("obfuscated_execution", 0.5, [n.lineno], "obf.dynamic_exec",
                                      f"{name}() runs a non-literal expression", self.name)
            elif name in IMPORT_FUNCS and n.args and not _constant_string(n.args[0]):
                arg = n.args[0]
                if isinstance(arg, ast.Name) and arg.id in defs:
                    arg = defs[arg.id]  # judge the expression that built the name
                sev = 0.7 if isinstance(arg, (ast.BinOp, ast.JoinedStr, ast.Call)) else 0.45
                yield ctx.finding("obfuscated_execution", sev, [n.lineno], "obf.dynamic_import",
                                  f"{name}() loads a module whose name is computed at runtime", self.name)
            elif name == "getattr" and isinstance(f, ast.Name) and len(n.args) >= 2 and not _constant_string(n.args[1]):
                base = n.args[0]
                base_name = base.id if isinstance(base, ast.Name) else ""
                if base_name in ("__builtins__", "builtins", "os", "subprocess", "sys"):
                    yield ctx.finding("obfuscated_execution", 0.6, [n.lineno], "obf.reflective_call",
                                      f"getattr on {base_name} with a computed attribute name", self.name)
            elif name == "getattr" and len(n.args) >= 2 and _constant_string(n.args[1]) \
                    and isinstance(n.args[0], ast.Name) and n.args[0].id == "__builtins__" \
                    and n.args[1].value in ("eval", "exec", "__import__", "compile"):
                yield ctx.finding("obfuscated_execution", 0.7, [n.lineno], "obf.builtin_lookup",
                                  "looks up a code-execution builtin by name", self.name)

    _SH = [
        (re.compile(r"\bbase64\s+(?:-d|--decode|-D)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"), 0.92, "decoded payload piped to a shell"),
        (re.compile(r"\b(?:echo|printf)\s+['\"]?[A-Za-z0-9+/=]{24,}['\"]?\s*\|\s*base64\s+(?:-d|--decode)"), 0.85, "inline encoded payload decoded"),
        (re.compile(r"\beval\s+[\"']?\$\(\s*(?:echo|curl|wget|base64|printf)"), 0.85, "eval of command-substitution output"),
        (re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"), 0.6, "downloaded script piped straight to a shell"),
        (re.compile(r"\bxxd\s+-r\b[^\n|]*\|\s*(?:ba)?sh\b|\bopenssl\s+enc\s+-d[^\n|]*\|\s*(?:ba)?sh\b"), 0.9, "decoded payload piped to a shell"),
    ]
    _JS = [
        (re.compile(r"\beval\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)\b"), 0.92, "eval of decoded data"),
        (re.compile(r"\bnew\s+Function\s*\([^)]*(?:atob|Buffer\.from|\+)"), 0.75, "Function constructor builds code at runtime"),
        (re.compile(r"\bnew\s+Function\s*\("), 0.5, "Function constructor builds code at runtime"),
        (re.compile(r"\beval\s*\(\s*[A-Za-z_$][\w$]*\s*\)"), 0.45, "eval of a variable"),
    ]
    _LONG_LITERAL = re.compile(r"""['"]([A-Za-z0-9+/=_-]{40,})['"]""")

    def _text(self, ctx):
        code = ctx.code[:50_000]
        if ctx.language in ("bash", "text", "markdown", "yaml", "dockerfile"):
            for rx, sev, msg in self._SH:
                for m in rx.finditer(code):
                    yield ctx.finding("obfuscated_execution", sev, [line_of(code, m.start())], "obf.sh",
                                      f"{msg}: {clip(m.group(0), 60)}", self.name)
        if ctx.language == "javascript":
            for rx, sev, msg in self._JS:
                for m in rx.finditer(code):
                    yield ctx.finding("obfuscated_execution", sev, [line_of(code, m.start())], "obf.js",
                                      f"{msg}: {clip(m.group(0), 60)}", self.name)
        for m in self._LONG_LITERAL.finditer(code):
            if entropy(m.group(1)) > 4.5:
                yield ctx.finding("obfuscated_execution", 0.25, [line_of(code, m.start())], "obf.entropy",
                                  "long high-entropy string literal", self.name)

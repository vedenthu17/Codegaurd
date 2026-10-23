"""Static constant folding for Python expressions.

A tiny *non-executing* evaluator: it understands literals, string/bytes/int
arithmetic, slicing, comprehensions over constant data, and a whitelist of
pure transformation functions (decoders such as base64/hex/zlib/rot13,
chr/ord, join/format/replace...). Anything else is UNKNOWN. No user code is
ever run. Results are size- and step-bounded.

`decoded` is set when a decoding transform contributed to the value, which
is the signal for obfuscated_execution.
"""
from __future__ import annotations

import ast
import base64
import binascii
import bz2
import codecs
import gzip
import html
import lzma
import urllib.parse
import zlib

from .common import DYN


class _Unknown:
    __slots__ = ()

    def __repr__(self) -> str:
        return "UNKNOWN"


UNKNOWN = _Unknown()
MAX_LEN = 1_000_000
MAX_STEPS = 20_000


def _safe_decompress(fn):
    def run(data):
        out = fn(data)
        if len(out) > MAX_LEN:
            raise ValueError("too large")
        return out
    return run


def _b64(data, *_, **__):
    if isinstance(data, str):
        data = data.encode()
    data = bytes(data).strip()
    data += b"=" * (-len(data) % 4)
    return base64.b64decode(data, validate=False)


def _codecs_decode(data, encoding="utf-8", *_):
    enc = str(encoding).lower().replace("-", "_")
    if enc in ("rot13", "rot_13"):
        return codecs.decode(str(data), "rot13")
    if enc in ("hex", "hex_codec"):
        return binascii.unhexlify(data)
    if enc in ("base64", "base_64", "base64_codec"):
        return _b64(data)
    if enc in ("zlib", "zlib_codec"):
        return _safe_decompress(zlib.decompress)(data)
    if isinstance(data, (bytes, bytearray)):
        return bytes(data).decode(encoding, "replace")
    return str(data)


# qualified name -> (function, is_decoder)
PURE_FUNCS = {
    "base64.b64decode": (_b64, True),
    "base64.standard_b64decode": (_b64, True),
    "base64.urlsafe_b64decode": (lambda d, *a: base64.urlsafe_b64decode(d + ("=" if isinstance(d, str) else b"=") * (-len(d) % 4)), True),
    "base64.b32decode": (lambda d, *a: base64.b32decode(d), True),
    "base64.b16decode": (lambda d, *a: base64.b16decode(d, casefold=True), True),
    "base64.b85decode": (lambda d, *a: base64.b85decode(d), True),
    "base64.a85decode": (lambda d, *a: base64.a85decode(d), True),
    "base64.decodebytes": (_b64, True),
    "base64.b64encode": (lambda d, *a: base64.b64encode(d.encode() if isinstance(d, str) else d), False),
    "binascii.unhexlify": (lambda d, *a: binascii.unhexlify(d), True),
    "binascii.a2b_hex": (lambda d, *a: binascii.unhexlify(d), True),
    "binascii.a2b_base64": (_b64, True),
    "bytes.fromhex": (lambda d, *a: bytes.fromhex(d), True),
    "bytearray.fromhex": (lambda d, *a: bytes.fromhex(d), True),
    "codecs.decode": (_codecs_decode, True),
    "zlib.decompress": (_safe_decompress(zlib.decompress), True),
    "gzip.decompress": (_safe_decompress(gzip.decompress), True),
    "bz2.decompress": (_safe_decompress(bz2.decompress), True),
    "lzma.decompress": (_safe_decompress(lzma.decompress), True),
    "urllib.parse.unquote": (lambda d, *a: urllib.parse.unquote(d), True),
    "urllib.parse.unquote_plus": (lambda d, *a: urllib.parse.unquote_plus(d), True),
    "html.unescape": (lambda d, *a: html.unescape(d), True),
    "builtins.chr": (chr, True),
    "builtins.ord": (ord, False),
    "builtins.str": (lambda *a: str(a[0]) if a else "", False),
    "builtins.int": (lambda *a: int(*a), False),
    "builtins.bytes": (lambda *a: bytes(*a) if a else b"", False),
    "builtins.bytearray": (lambda *a: bytes(*a) if a else b"", False),
    "builtins.reversed": (lambda d: d[::-1], True),
    "builtins.list": (lambda d=(): list(d), False),
    "builtins.tuple": (lambda d=(): tuple(d), False),
    "builtins.len": (len, False),
    "builtins.abs": (abs, False),
    "builtins.pow": (lambda a, b: a ** b if abs(b) < 64 else (_ for _ in ()).throw(ValueError()), False),
    "os.path.join": (lambda *p: "/".join(str(x).rstrip("/") for x in p), False),
    "os.path.expanduser": (lambda p: p, False),
    "os.path.expandvars": (lambda p: p, False),
    "os.path.abspath": (lambda p: p, False),
    "os.path.normpath": (lambda p: p, False),
    "os.path.realpath": (lambda p: p, False),
    "os.fspath": (lambda p: p, False),
    "pathlib.Path": (lambda *p: "/".join(str(x).rstrip("/") for x in p) if p else ".", False),
    "pathlib.PurePath": (lambda *p: "/".join(str(x).rstrip("/") for x in p), False),
    "pathlib.Path.home": (lambda: "~", False),
    "os.getcwd": (lambda: ".", False),
    "shlex.join": (lambda parts: " ".join(map(str, parts)), False),
}

# str/bytes methods considered pure
PURE_METHODS = {
    "decode": True, "encode": False, "replace": False, "upper": False, "lower": False,
    "strip": False, "lstrip": False, "rstrip": False, "join": False, "format": False,
    "split": False, "translate": True, "swapcase": True, "title": False, "zfill": False,
    "expanduser": False, "resolve": False, "absolute": False, "hex": False, "removeprefix": False,
    "removesuffix": False, "capitalize": False, "casefold": False, "splitlines": False,
}

_BINOPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Mod: lambda a, b: a % b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.BitXor: lambda a, b: a ^ b,
    ast.BitAnd: lambda a, b: a & b,
    ast.BitOr: lambda a, b: a | b,
    ast.LShift: lambda a, b: a << b if b < 64 else (_ for _ in ()).throw(ValueError()),
    ast.RShift: lambda a, b: a >> b,
    ast.Pow: lambda a, b: a ** b if (isinstance(b, int) and abs(b) < 64) else (_ for _ in ()).throw(ValueError()),
    ast.Div: lambda a, b: f"{a}/{b}" if isinstance(a, str) else a / b,  # pathlib "/" joins
}


def _too_big(v) -> bool:
    if isinstance(v, (str, bytes, bytearray, list, tuple)):
        return len(v) > MAX_LEN
    if isinstance(v, int):
        return v.bit_length() > 4096
    return False


class Folder:
    """Evaluates expressions given a name resolver and an environment of
    single-assignment constants."""

    def __init__(self, qualname, lookup):
        # qualname(node) -> dotted name or None; lookup(name, scope) -> expr or None
        self.qualname = qualname
        self.lookup = lookup
        self.decoded = False
        self._steps = 0
        self._stack: set[int] = set()

    # -- public ---------------------------------------------------------
    def value(self, node: ast.AST | None, scope=None):
        """Exact value or UNKNOWN. Resets the decoded flag."""
        self.decoded = False
        self._steps = 0
        try:
            return self._ev(node, scope, {})
        except RecursionError:
            return UNKNOWN

    def partial(self, node: ast.AST | None, scope=None) -> str:
        """Best-effort string with DYN placeholders for unknown parts."""
        self.decoded = False
        self._steps = 0
        try:
            return self._pv(node, scope, {})
        except RecursionError:
            return DYN

    # -- internals ------------------------------------------------------
    def _pv(self, node, scope, env) -> str:
        if node is None:
            return DYN
        v = self._ev(node, scope, env)
        if v is not UNKNOWN:
            if isinstance(v, (bytes, bytearray)):
                return bytes(v).decode("utf-8", "replace")
            if isinstance(v, (list, tuple)):
                return " ".join(self._to_s(x) for x in v)
            return self._to_s(v)
        if isinstance(node, ast.JoinedStr):
            out = []
            for part in node.values:
                if isinstance(part, ast.Constant):
                    out.append(str(part.value))
                elif isinstance(part, ast.FormattedValue):
                    out.append(self._pv(part.value, scope, env))
            return "".join(out)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
            sep = "/" if isinstance(node.op, ast.Div) else ""
            return self._pv(node.left, scope, env) + sep + self._pv(node.right, scope, env)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            fmt = self._ev(node.left, scope, env)
            if isinstance(fmt, str):
                import re as _re
                return _re.sub(r"%[-#0 +]*\d*(?:\.\d+)?[sdrifx]", DYN, fmt)
        if isinstance(node, (ast.List, ast.Tuple)):
            return " ".join(self._pv(e, scope, env) for e in node.elts)
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "format":
                base = self._ev(f.value, scope, env)
                if isinstance(base, str):
                    import re as _re
                    return _re.sub(r"\{[^{}]*\}", DYN, base)
            q = self.qualname(f)
            if q in ("os.path.join", "pathlib.Path", "pathlib.PurePath"):
                return "/".join(self._pv(a, scope, env).rstrip("/") for a in node.args)
            if q in ("os.path.expanduser", "os.path.abspath", "os.path.realpath", "builtins.str", "os.fspath"):
                return self._pv(node.args[0], scope, env) if node.args else DYN
            if isinstance(f, ast.Attribute) and f.attr in ("expanduser", "resolve", "absolute", "strip", "format_map"):
                return self._pv(f.value, scope, env)
            if q in ("os.environ.get", "os.getenv") and node.args:
                key = self._ev(node.args[0], scope, env)
                if key in ("HOME", "USERPROFILE"):
                    return "~"
            # call to a local helper: fold its return expression
            if isinstance(f, ast.Name) and id(node) not in self._stack:
                ret = self.lookup(f"__return__:{f.id}", scope)
                if ret is not None:
                    self._stack.add(id(node))
                    try:
                        return self._pv(ret, ("fn", f.id), {})
                    finally:
                        self._stack.discard(id(node))
        if isinstance(node, ast.Name):
            expr = self.lookup(node.id, scope)
            if expr is not None and id(expr) not in self._stack:
                self._stack.add(id(expr))
                try:
                    return self._pv(expr, scope, env)
                finally:
                    self._stack.discard(id(expr))
        if isinstance(node, ast.Subscript):
            v = self.qualname(node.value)
            if v == "os.environ":
                key = self._ev(node.slice, scope, env)
                if key in ("HOME", "USERPROFILE"):
                    return "~"
        return DYN

    @staticmethod
    def _to_s(v) -> str:
        if isinstance(v, (bytes, bytearray)):
            return bytes(v).decode("utf-8", "replace")
        return str(v)

    def _ev(self, node, scope, env):
        self._steps += 1
        if self._steps > MAX_STEPS or node is None:
            return UNKNOWN
        t = type(node)
        if t is ast.Constant:
            return node.value
        if t in (ast.List, ast.Tuple, ast.Set):
            vals = [self._ev(e, scope, env) for e in node.elts]
            return UNKNOWN if any(v is UNKNOWN for v in vals) else (list(vals) if t is ast.List else tuple(vals))
        if t is ast.Name:
            if node.id in env:
                return env[node.id]
            if node.id in ("True", "False", "None"):
                return {"True": True, "False": False, "None": None}[node.id]
            expr = self.lookup(node.id, scope)
            if expr is None or id(expr) in self._stack:
                return UNKNOWN
            self._stack.add(id(expr))
            try:
                return self._ev(expr, scope, env)
            finally:
                self._stack.discard(id(expr))
        if t is ast.JoinedStr:
            out = []
            for part in node.values:
                if isinstance(part, ast.Constant):
                    out.append(str(part.value))
                else:
                    v = self._ev(part.value, scope, env)
                    if v is UNKNOWN:
                        return UNKNOWN
                    out.append(self._to_s(v))
            return "".join(out)
        if t is ast.BinOp:
            a = self._ev(node.left, scope, env)
            if a is UNKNOWN:
                return UNKNOWN
            b = self._ev(node.right, scope, env)
            if b is UNKNOWN:
                return UNKNOWN
            op = _BINOPS.get(type(node.op))
            if op is None:
                return UNKNOWN
            if isinstance(node.op, ast.Mult) and isinstance(a, (str, bytes, list)) and isinstance(b, int) and len(a) * b > MAX_LEN:
                return UNKNOWN
            try:
                r = op(a, b)
            except Exception:
                return UNKNOWN
            return UNKNOWN if _too_big(r) else r
        if t is ast.UnaryOp:
            v = self._ev(node.operand, scope, env)
            if v is UNKNOWN:
                return UNKNOWN
            try:
                if isinstance(node.op, ast.USub):
                    return -v
                if isinstance(node.op, ast.Not):
                    return not v
                if isinstance(node.op, ast.Invert):
                    return ~v
                return v
            except Exception:
                return UNKNOWN
        if t is ast.Subscript:
            base = self._ev(node.value, scope, env)
            if base is UNKNOWN:
                return UNKNOWN
            sl = node.slice
            try:
                if isinstance(sl, ast.Slice):
                    lo = self._ev(sl.lower, scope, env) if sl.lower else None
                    hi = self._ev(sl.upper, scope, env) if sl.upper else None
                    st = self._ev(sl.step, scope, env) if sl.step else None
                    if UNKNOWN in (lo, hi, st):
                        return UNKNOWN
                    if st == -1:
                        self.decoded = True
                    return base[lo:hi:st]
                idx = self._ev(sl, scope, env)
                return UNKNOWN if idx is UNKNOWN else base[idx]
            except Exception:
                return UNKNOWN
        if t in (ast.ListComp, ast.GeneratorExp) and len(node.generators) == 1:
            g = node.generators[0]
            it = self._ev(g.iter, scope, env)
            if it is UNKNOWN or not isinstance(g.target, ast.Name) or g.ifs:
                return UNKNOWN
            try:
                seq = list(it)[:MAX_LEN]
            except Exception:
                return UNKNOWN
            out = []
            for item in seq:
                v = self._ev(node.elt, scope, {**env, g.target.id: item})
                if v is UNKNOWN:
                    return UNKNOWN
                out.append(v)
            return out
        if t is ast.Call:
            return self._call(node, scope, env)
        return UNKNOWN

    def _call(self, node: ast.Call, scope, env):
        f = node.func
        args = [self._ev(a, scope, env) for a in node.args]
        if any(a is UNKNOWN for a in args) or any(isinstance(a, ast.Starred) for a in node.args):
            return UNKNOWN
        # method call on a constant receiver
        if isinstance(f, ast.Attribute) and f.attr in PURE_METHODS:
            recv = self._ev(f.value, scope, env)
            if recv is not UNKNOWN and isinstance(recv, (str, bytes, bytearray)):
                kwargs = {}
                for kw in node.keywords:
                    v = self._ev(kw.value, scope, env)
                    if v is UNKNOWN or kw.arg is None:
                        return UNKNOWN
                    kwargs[kw.arg] = v
                try:
                    if f.attr == "join":
                        r = recv.join(self._to_s(x) if isinstance(recv, str) else x for x in args[0])
                    elif f.attr == "translate" and isinstance(recv, str) and isinstance(args[0], dict):
                        r = recv.translate(args[0])
                    else:
                        r = getattr(recv, f.attr)(*args, **kwargs)
                except Exception:
                    return UNKNOWN
                if PURE_METHODS[f.attr]:
                    self.decoded = True
                return UNKNOWN if _too_big(r) else r
        q = self.qualname(f)
        if q == "str.maketrans" or (isinstance(f, ast.Attribute) and f.attr == "maketrans"):
            try:
                return str.maketrans(*args)
            except Exception:
                return UNKNOWN
        spec = PURE_FUNCS.get(q or "")
        if spec is None:
            return UNKNOWN
        fn, is_decoder = spec
        try:
            r = fn(*args)
        except Exception:
            return UNKNOWN
        if is_decoder:
            self.decoded = True
        return UNKNOWN if _too_big(r) else r

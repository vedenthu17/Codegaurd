"""data_exfiltration analyzer: local data reaching an outbound sink.

Python: name-based taint tracking. Sources are file reads, environment
variables and directory listings; taint flows through assignments, calls,
f-strings, containers, loops and local-function arguments/returns (iterated
to a fixpoint). Sinks are HTTP/socket/mail/FTP/cloud-upload calls and
command-line network tools. Severity depends on the kind of source and on
where the destination points.

Shell / JavaScript: regex checks for the same source -> sink shapes.
"""
from __future__ import annotations

import ast
import re

from .common import clip, credential_path, line_of
from .netutil import classify_host, classify_url

NET_MODULES = {"requests", "httpx", "urllib", "aiohttp", "socket", "smtplib", "ftplib", "boto3", "paramiko", "http"}
HTTP_ATTRS = {"post", "put", "patch"}
SOCKET_ATTRS = {"send", "sendall", "sendto", "sendmail", "send_message", "storbinary", "storlines",
                "upload_file", "upload_fileobj", "put_object"}
DNS_FUNCS = {"socket.gethostbyname", "socket.gethostbyname_ex", "socket.getaddrinfo"}
NET_TOOLS = {"ping", "nslookup", "dig", "host", "curl", "wget", "nc", "ncat", "scp", "rsync", "ftp", "sftp", "telnet"}
PROC_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
              "subprocess.check_call", "os.system", "os.popen"}
HOST_LIKE = re.compile(r"^[\w-]+(?:\.[\w-]+)+(?::\d+)?$")
SENSITIVE = {"env", "cred"}


class _Flow:
    def __init__(self, tree: ast.AST):
        self.tree = tree
        self.alias: dict[str, str] = {}
        self.consts: dict[str, str] = {}
        self.funcs: dict[str, ast.FunctionDef] = {}
        self.names: dict[str, str] = {}
        self.func_taint: dict[str, str] = {}
        self.imports_net = False
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                    self.imports_net |= a.name.split(".")[0] in NET_MODULES
            elif isinstance(n, ast.ImportFrom) and n.module:
                self.imports_net |= n.module.split(".")[0] in NET_MODULES
                for a in n.names:
                    self.alias[a.asname or a.name] = f"{n.module}.{a.name}"
            elif isinstance(n, ast.FunctionDef):
                self.funcs[n.name] = n
            elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        self.consts[t.id] = n.value.value

    # -- names ------------------------------------------------------------
    def qual(self, f: ast.AST) -> str:
        if isinstance(f, ast.Name):
            return self.alias.get(f.id, f.id)
        if isinstance(f, ast.Attribute):
            base = self.qual(f.value)
            return f"{base}.{f.attr}" if base else f.attr
        return ""

    # -- taint ------------------------------------------------------------
    def taint(self, n: ast.AST | None) -> str | None:
        if n is None:
            return None
        if isinstance(n, ast.Name):
            return self.names.get(n.id)
        if isinstance(n, ast.Call):
            q = self.qual(n.func)
            if q in ("open", "builtins.open", "io.open", "pathlib.Path.open") or q.endswith(".read_text") or q.endswith(".read_bytes"):
                arg = n.args[0] if n.args else None
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and credential_path(arg.value):
                    return "cred"
                if isinstance(arg, ast.Name) and credential_path(self.consts.get(arg.id, "")):
                    return "cred"
                return "file"
            if q in ("os.getenv", "os.environ.get", "os.environ.copy") or q == "os.environ.items":
                return "env"
            if q in ("os.listdir", "os.scandir", "os.walk", "glob.glob", "glob.iglob"):
                return "file"
            if isinstance(n.func, ast.Name) and n.func.id in self.func_taint:
                return self.func_taint[n.func.id]
        if isinstance(n, ast.Attribute) and self.qual(n) == "os.environ":
            return "env"
        if isinstance(n, ast.Subscript) and self.qual(n.value) == "os.environ":
            return "env"
        best = None
        for c in ast.iter_child_nodes(n):
            if isinstance(c, (ast.FunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            t = self.taint(c)
            if t in SENSITIVE:
                return t
            best = best or t
        return best

    def _mark(self, target: ast.AST, label: str) -> bool:
        changed = False
        if isinstance(target, ast.Name):
            if self.names.get(target.id) != label and not (self.names.get(target.id) in SENSITIVE):
                self.names[target.id] = label
                changed = True
        elif isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                changed |= self._mark(e, label)
        elif isinstance(target, (ast.Subscript, ast.Attribute, ast.Starred)):
            changed |= self._mark(target.value, label)
        return changed

    def propagate(self) -> None:
        for _ in range(6):
            changed = False
            for n in ast.walk(self.tree):
                if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                    label = self.taint(n.value)
                    if label:
                        targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                        for t in targets:
                            changed |= self._mark(t, label)
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    label = self.taint(n.iter)
                    if label:
                        changed |= self._mark(n.target, label)
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:
                        label = self.taint(item.context_expr)
                        if label and item.optional_vars is not None:
                            changed |= self._mark(item.optional_vars, label)
                elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call):
                    c = n.value
                    if isinstance(c.func, ast.Attribute) and c.func.attr in ("append", "add", "update", "extend", "write"):
                        label = next((t for t in map(self.taint, c.args) if t), None)
                        if label:
                            changed |= self._mark(c.func.value, label)
                elif isinstance(n, ast.FunctionDef):
                    label = None
                    for r in ast.walk(n):
                        if isinstance(r, (ast.Return, ast.Yield, ast.YieldFrom)):
                            label = label or self.taint(r.value)
                    if label and self.func_taint.get(n.name) != label:
                        self.func_taint[n.name] = label
                        changed = True
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in self.funcs:
                    fn = self.funcs[n.func.id]
                    params = [a.arg for a in fn.args.args]
                    for p, a in zip(params, n.args):
                        label = self.taint(a)
                        if label:
                            changed |= self._mark(ast.Name(id=p), label)
                    for kw in n.keywords:
                        label = self.taint(kw.value)
                        if label and kw.arg:
                            changed |= self._mark(ast.Name(id=kw.arg), label)
            if not changed:
                break

    # -- destinations -----------------------------------------------------
    def strings(self, n: ast.AST) -> list[str]:
        out: list[str] = []
        for c in ast.walk(n):
            if isinstance(c, ast.Constant) and isinstance(c.value, str):
                out.append(c.value)
            elif isinstance(c, ast.Name) and c.id in self.consts:
                out.append(self.consts[c.id])
        return out

    def destination(self, call: ast.Call) -> str:
        kinds = []
        for s in self.strings(call):
            s = s.strip()
            if "://" in s:
                kinds.append(classify_url(s).kind)
            elif HOST_LIKE.match(s):
                kinds.append(classify_host(s.split(":")[0]).kind)
        for bad in ("exfil_service", "hostile"):
            if bad in kinds:
                return "bad"
        if any(k in ("metadata", "loopback", "private", "link_local", "internal_name", "dangerous_scheme") for k in kinds):
            return "internal"
        return "ext" if kinds else "unk"


class ExfilAnalyzer:
    name = "exfil"
    languages = None

    def run(self, ctx):
        if ctx.language == "python":
            yield from self._python(ctx)
        else:
            yield from self._text(ctx)

    # -- python -----------------------------------------------------------
    def _python(self, ctx):
        tree = ctx.tree
        if tree is None:
            return
        flow = _Flow(tree)
        flow.propagate()
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            q = flow.qual(n.func)
            attr = n.func.attr if isinstance(n.func, ast.Attribute) else ""
            sink = None
            if q in DNS_FUNCS:
                sink = "dns"
            elif q in PROC_FUNCS:
                strs = flow.strings(n)
                if any(s.split()[0] in NET_TOOLS for s in strs if s.strip()):
                    sink = "tool"
            elif (attr in HTTP_ATTRS and flow.imports_net) or q.startswith(("requests.", "httpx.", "urllib.request.")) \
                    and attr in HTTP_ATTRS | {"urlopen", "Request"} or q in ("urllib.request.urlopen", "urlopen") \
                    or attr in SOCKET_ATTRS:
                sink = "net"
            if not sink:
                continue
            args = list(n.args) + [k.value for k in n.keywords]
            label = next((t for t in map(flow.taint, args) if t), None)
            if sink == "net" and q in ("urllib.request.urlopen", "urlopen") and not (len(n.args) > 1 or any(k.arg == "data" for k in n.keywords)):
                label = None  # a plain GET carries no local data
            if not label:
                continue
            dest = flow.destination(n)
            sensitive = label in SENSITIVE
            sev = {"bad": 0.88, "ext": 0.5 if sensitive else 0.35, "unk": 0.55 if sensitive else 0.4,
                   "internal": 0.35}[dest]
            if sink == "dns":
                sev = max(sev, 0.75)
            yield ctx.finding("data_exfiltration", sev, [n.lineno], f"exfil.{sink}",
                              f"local {'secret ' if sensitive else ''}data flows into an outbound call"
                              f" ({q or attr}) to a {dest} destination", self.name)

    # -- shell / js -------------------------------------------------------
    _SH = [
        (re.compile(r"\bcurl\b[^\n|;]*?(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|-T|--upload-file)\s*['\"]?[@<]?\S*"), 0.55,
         "curl uploads local data"),
        (re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]*<\s*\S+"), 0.75, "netcat sends a local file"),
        (re.compile(r"\btar\b[^\n]*\|\s*(?:curl|nc|ncat|ssh)\b"), 0.8, "archive streamed to a network tool"),
        (re.compile(r"\b(?:scp|rsync)\b[^\n]*\s\S+@[\w.-]+:\S*"), 0.5, "copies files to a remote host"),
        (re.compile(r"\bcat\s+\S+\s*\|\s*(?:curl|nc|ncat|ssh)\b"), 0.8, "file piped to a network tool"),
    ]
    _SH_SENSITIVE = re.compile(r"\.ssh|\.aws|/etc/(?:passwd|shadow)|\.env\b|\$\{?\w*(?:TOKEN|SECRET|KEY|PASS)\w*\}?|\benv\b|printenv", re.I)
    _JS_SEND = re.compile(r"\b(?:fetch|axios\.(?:post|put)|http\.request|https\.request|request\.post)\s*\(")
    _JS_SRC = re.compile(r"\bfs\.readFile(?:Sync)?\s*\(|\bprocess\.env\b|\bos\.homedir\b")

    def _text(self, ctx):
        code = ctx.code[:50_000]
        if ctx.language in ("bash", "text", "yaml", "markdown", "dockerfile"):
            for rx, sev, msg in self._SH:
                for m in rx.finditer(code):
                    seg = code[max(0, m.start() - 120):m.end() + 120]
                    boost = 0.25 if self._SH_SENSITIVE.search(seg) else 0.0
                    yield ctx.finding("data_exfiltration", min(0.9, sev + boost), [line_of(code, m.start())],
                                      "exfil.sh", f"{msg}: {clip(m.group(0), 60)}", self.name)
        if ctx.language == "javascript":
            for m in self._JS_SEND.finditer(code):
                window = code[m.start():m.start() + 400]
                src = self._JS_SRC.search(window) or self._JS_SRC.search(code[max(0, m.start() - 300):m.start()])
                if src:
                    yield ctx.finding("data_exfiltration", 0.6, [line_of(code, m.start())], "exfil.js",
                                      "local file/env data is sent in an outbound request", self.name)

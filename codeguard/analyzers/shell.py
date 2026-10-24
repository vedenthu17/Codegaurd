"""Shell analyzer built on tree-sitter-bash (MIT).

The parse tree is walked command by command. Each command is normalised
first (wrapper commands such as sudo/env/nohup/xargs removed, quotes
resolved, `sh -c "..."` and `eval` payloads re-analysed) and only then matched
on command + flags + target. Targets are scoped: recursive deletion only
counts when it hits a system/home root or an unchecked runtime value, so
routine cleanups such as `rm -rf node_modules` stay allowed.
"""
from __future__ import annotations

import os
import re

import tree_sitter_bash as tsb
from tree_sitter import Language, Parser

from ..rules.catalog import BLOCK_DEVICE, CRITICAL_DELETE_TARGETS
from .common import DYN, clip, credential_path, persistence_path

_LANG = Language(tsb.language())

WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "nice", "ionice", "xargs", "exec", "command",
            "builtin", "stdbuf", "timeout", "setsid", "chroot"}
WRAPPER_ARG_FLAGS = {"-u", "-g", "-n", "-s", "-k", "-C", "-I", "-L", "-P", "-d"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
HYGIENE_CMDS = {"chmod", "chown", "ls", "stat", "test", "[", "[[", "echo", "printf", "grep", "which", "dirname", "basename"}
WRITE_CMDS = {"cp", "mv", "ln", "install", "tee", "touch", "rsync", "scp"}


def _unquote(text: str) -> str:
    """Resolve simple quoting: 'r'"m" -> rm, "a b" -> a b."""
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"" and text.count(text[0]) == 2:
        return text[1:-1]
    return text.replace("''", "").replace('""', "").replace("'", "").replace('"', "")


def _norm_target(t: str) -> str:
    t = t.strip()
    return re.sub(r"/+$", "", t) or "/"


class ShellAnalyzer:
    name = "shell"
    languages = frozenset({"bash"})

    def run(self, ctx):
        code = ctx.code[:100_000]
        tree = Parser(_LANG).parse(code.encode("utf-8", "replace"))
        yield from self._walk(ctx, tree.root_node)

    # ---- tree walk --------------------------------------------------------
    def _walk(self, ctx, root):
        stack = [root]
        while stack:
            node = stack.pop()
            stack.extend(reversed(node.children))
            if node.type == "command":
                yield from self._command(ctx, self._words(node), node.start_point[0] + 1)
            elif node.type in ("file_redirect", "heredoc_redirect"):
                yield from self._redirect(ctx, node)

    @staticmethod
    def _words(cmd) -> list[str]:
        out: list[str] = []
        for ch in cmd.children:
            if ch.type in ("file_redirect", "heredoc_redirect", "herestring_redirect"):
                continue
            text = ch.text.decode("utf-8", "replace")
            if ch.type == "command_name":
                text = ch.children[0].text.decode("utf-8", "replace") if ch.children else text
            if "$(" in text or "`" in text:
                text = DYN
            out.append(_unquote(text))
        return out

    def _redirect(self, ctx, node):
        kids = [c for c in node.children]
        if not kids:
            return
        op = next((c.text.decode() for c in kids if c.type in (">", ">>", ">|", "&>", "&>>")), None)
        dest = kids[-1].text.decode("utf-8", "replace")
        dest = _unquote(dest)
        line = node.start_point[0] + 1
        if op is None:
            return
        if BLOCK_DEVICE.match(dest):
            yield ctx.finding("destructive_command", 0.92, [line], "sh.redirect_device",
                              f"redirects output onto a block device: {dest}", self.name)
        label = persistence_path(dest)
        if label:
            yield ctx.finding("persistence_or_privesc", 0.65, [line], "sh.write_persistence",
                              f"writes to {label}: {clip(dest, 50)}", self.name)

    # ---- one command ------------------------------------------------------
    def _strip_wrappers(self, words: list[str]) -> tuple[list[str], bool]:
        words = list(words)
        piped_input = False
        while words and os.path.basename(words[0]) in WRAPPERS:
            w = os.path.basename(words.pop(0))
            piped_input |= w == "xargs"
            while words and words[0].startswith("-"):
                flag = words.pop(0)
                if flag in WRAPPER_ARG_FLAGS and words:
                    words.pop(0)
            if w == "env":
                while words and re.match(r"^\w+=", words[0]):
                    words.pop(0)
            if w == "timeout" and words and re.match(r"^\d", words[0]):
                words.pop(0)
        return words, piped_input

    def _command(self, ctx, words: list[str], line: int):
        words, piped = self._strip_wrappers(words)
        if not words:
            return
        name = os.path.basename(words[0])
        args = words[1:]
        flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        long_flags = {a for a in args if a.startswith("--")}
        targets = [a for a in args if not a.startswith("-")]

        # nested shells and eval: analyse the payload as shell code
        if name in SHELLS and "-c" in args:
            i = args.index("-c")
            if i + 1 < len(args):
                yield from ctx.analyze_embedded(args[i + 1], "bash", [line])
        elif name == "eval" and args:
            yield from ctx.analyze_embedded(" ".join(args), "bash", [line])

        if name == "rm":
            yield from self._rm(ctx, flags, long_flags, targets, piped, line)
        elif name.startswith("mkfs") or name in ("mke2fs", "wipefs"):
            dev = any(BLOCK_DEVICE.match(t) for t in targets)
            yield ctx.finding("destructive_command", 0.9 if dev else 0.3, [line], "sh.mkfs",
                              f"{name} {'on a block device' if dev else 'formats a filesystem'}", self.name)
        elif name == "dd":
            for a in args:
                if a.startswith("of=") and BLOCK_DEVICE.match(a[3:]):
                    yield ctx.finding("destructive_command", 0.93, [line], "sh.dd_device",
                                      f"dd writes directly to a block device: {a}", self.name)
        elif name == "shred":
            crit = any(CRITICAL_DELETE_TARGETS.match(_norm_target(t)) or BLOCK_DEVICE.match(t) for t in targets)
            yield ctx.finding("destructive_command", 0.9 if crit else 0.4, [line], "sh.shred",
                              "shred overwrites " + ("a critical target" if crit else "files"), self.name)
        elif name in ("chmod", "chown", "chgrp"):
            recursive = "R" in flags or "--recursive" in long_flags
            crit = [t for t in targets[1:] if CRITICAL_DELETE_TARGETS.match(_norm_target(t))]
            if recursive and crit:
                yield ctx.finding("destructive_command", 0.85, [line], "sh.chmod_root",
                                  f"{name} -R on a system or home root: {crit[0]}", self.name)
            if name == "chmod" and targets and re.fullmatch(r"[0-7]?[4-7][0-7]{3}|[ugoa]*\+s", targets[0]) \
                    and (targets[0].endswith("+s") or len(targets[0]) == 4):
                yield ctx.finding("persistence_or_privesc", 0.7, [line], "sh.setuid",
                                  f"sets the setuid/setgid bit ({targets[0]})", self.name)
        elif name == "find":
            if ("-delete" in args or ("-exec" in args and "rm" in args)) and targets \
                    and CRITICAL_DELETE_TARGETS.match(_norm_target(targets[0])):
                yield ctx.finding("destructive_command", 0.85, [line], "sh.find_delete",
                                  f"find deletes from a system or home root: {targets[0]}", self.name)
        elif name in ("useradd", "adduser", "usermod"):
            blob = " ".join(args)
            if re.search(r"\b(?:sudo|wheel|root|admin)\b|-u\s*0\b", blob):
                yield ctx.finding("persistence_or_privesc", 0.8, [line], "sh.user_priv",
                                  f"{name} grants administrative rights", self.name)
        elif name == "visudo":
            yield ctx.finding("persistence_or_privesc", 0.55, [line], "sh.visudo", "edits sudoers", self.name)
        elif name == "crontab" and not ({"-l", "-r"} & set(args)):
            yield ctx.finding("persistence_or_privesc", 0.55, [line], "sh.crontab", "installs a crontab", self.name)
        elif name == "crontab" and "-r" in args:
            yield ctx.finding("destructive_command", 0.5, [line], "sh.crontab_remove", "removes the crontab", self.name)
        elif name == "systemctl" and args[:1] in (["enable"], ["--user"]) and "enable" in args:
            yield ctx.finding("persistence_or_privesc", 0.45, [line], "sh.systemctl_enable",
                              "enables a service at boot", self.name)
        elif name in ("killall5",) or (name == "kill" and "-9" in args and "-1" in args):
            yield ctx.finding("destructive_command", 0.7, [line], "sh.kill_all", "kills every process", self.name)
        elif name == "docker" and "run" in args and "--privileged" in args:
            yield ctx.finding("persistence_or_privesc", 0.7, [line], "sh.docker_privileged",
                              "starts a privileged container", self.name)

        # sensitive files named as arguments (except pure permission hygiene)
        if name not in HYGIENE_CMDS:
            for a in args:
                label = credential_path(a)
                if label:
                    yield ctx.finding("secret_access", 0.6, [line], "sh.credential_arg",
                                      f"{name} touches {label}: {clip(a, 50)}", self.name)
                    break
        if name in WRITE_CMDS or (name == "sed" and "i" in flags):
            for a in targets:
                label = persistence_path(a)
                if label:
                    yield ctx.finding("persistence_or_privesc", 0.65, [line], "sh.write_persistence_arg",
                                      f"{name} writes to {label}: {clip(a, 50)}", self.name)
                    break

    def _rm(self, ctx, flags, long_flags, targets, piped, line):
        recursive = "r" in flags or "R" in flags or "--recursive" in long_flags
        if "--no-preserve-root" in long_flags:
            yield ctx.finding("destructive_command", 0.95, [line], "sh.rm_no_preserve",
                              "rm with --no-preserve-root", self.name)
            return
        if not recursive:
            return
        if not targets:
            if piped:
                yield ctx.finding("destructive_command", 0.5, [line], "sh.rm_piped",
                                  "recursive rm fed by xargs/stdin", self.name)
            return
        for t in targets:
            if CRITICAL_DELETE_TARGETS.match(_norm_target(t)):
                yield ctx.finding("destructive_command", 0.92, [line], "sh.rm_critical",
                                  f"recursive rm of a system or home root: {t}", self.name)
                return
        for t in targets:
            if DYN in t:
                sev = 0.55 if ctx.depth else 0.3
                yield ctx.finding("destructive_command", sev, [line], "sh.rm_dynamic",
                                  "recursive rm of a path built from runtime values", self.name)
                return
            if t.startswith("$"):
                yield ctx.finding("destructive_command", 0.3, [line], "sh.rm_variable",
                                  f"recursive rm of an unchecked variable: {t}", self.name)
                return

"""Network destination analyzer (ssrf_network_exfil, data_exfiltration).

Finds URLs in any language and classifies the host with `netutil`. Cloud
metadata endpoints, dangerous URL schemes and internal service ports are
strong signals; plain loopback or private addresses alone are weak, because
local development URLs are common in legitimate code.
"""
from __future__ import annotations

from .netutil import classify_url, find_urls, internal_port
from .common import clip, line_of
from .secrets import _in_docstring_or_comment


class NetworkAnalyzer:
    name = "network"
    languages = None

    def run(self, ctx):
        seen: set[tuple[str, int]] = set()
        for url, offset in find_urls(ctx.code):
            if ctx.language == "python" and _in_docstring_or_comment(ctx.code, offset):
                continue  # URLs quoted in docstrings/comments are documentation
            line = line_of(ctx.code, offset)
            if (url, line) in seen:
                continue
            seen.add((url, line))
            dest = classify_url(url)
            kind = dest.kind
            if kind == "metadata":
                yield ctx.finding("ssrf_network_exfil", 0.9, [line], "net.metadata",
                                  f"reaches a cloud metadata endpoint: {clip(url)}", self.name)
            elif kind == "dangerous_scheme":
                yield ctx.finding("ssrf_network_exfil", 0.85, [line], "net.scheme",
                                  f"{dest.detail}: {clip(url)}", self.name)
            elif kind in ("loopback", "private", "link_local", "internal_name"):
                sev = 0.75 if internal_port(dest) else 0.3
                yield ctx.finding("ssrf_network_exfil", sev, [line], "net.internal",
                                  f"targets an internal address ({dest.detail}): {clip(url)}", self.name)
            elif kind == "exfil_service":
                yield ctx.finding("data_exfiltration", 0.7, [line], "net.drop_service",
                                  f"sends to a third-party data-drop service: {clip(url)}", self.name)
            elif kind == "hostile":
                yield ctx.finding("data_exfiltration", 0.4, [line], "net.hostile_host",
                                  f"destination looks attacker-controlled: {clip(url)}", self.name)

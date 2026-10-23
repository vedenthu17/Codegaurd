"""Classify network destinations (URLs / hosts) for SSRF and exfil rules."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

from ..rules.catalog import (DANGEROUS_SCHEMES, EXFIL_SERVICES, HOSTILE_HOST_LABEL,
                             INTERNAL_HOST_SUFFIXES, INTERNAL_SERVICE_PORTS, METADATA_HOSTS)

URL_RE = re.compile(r"""\b([a-zA-Z][a-zA-Z0-9+.-]{1,9})://([^\s'"`<>()\[\]{}|\\^]+)""")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


@dataclass(frozen=True, slots=True)
class Dest:
    kind: str        # metadata | loopback | private | link_local | internal_name | dangerous_scheme
                     # | exfil_service | hostile | external | dynamic | unknown
    host: str
    detail: str
    port: int | None = None

    @property
    def internal(self) -> bool:
        return self.kind in {"metadata", "loopback", "private", "link_local", "internal_name"}


def _parse_ip(host: str) -> ipaddress._BaseAddress | None:
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # Obfuscated IPv4 forms: decimal (2130706433), hex (0x7f000001), octal
    # dotted (0177.0.0.1), short (127.1).
    try:
        if re.fullmatch(r"\d{8,10}", h):
            return ipaddress.IPv4Address(int(h))
        if re.fullmatch(r"0x[0-9a-fA-F]{6,8}", h):
            return ipaddress.IPv4Address(int(h, 16))
        parts = h.split(".")
        if 2 <= len(parts) <= 4 and all(re.fullmatch(r"0x[0-9a-f]+|0[0-7]*|\d+", p, re.I) for p in parts):
            nums = [int(p, 16) if p.lower().startswith("0x") else int(p, 8) if p.startswith("0") and len(p) > 1 else int(p) for p in parts]
            if len(nums) < 4:
                # inet_aton short form: the last number fills the remaining octets
                head, last = nums[:-1], nums[-1]
                ip_int = 0
                for n in head:
                    ip_int = ip_int * 256 + n
                return ipaddress.IPv4Address(ip_int * 256 ** (4 - len(head)) + last)
            if all(0 <= n <= 255 for n in nums):
                return ipaddress.IPv4Address(".".join(map(str, nums)))
    except (ValueError, ipaddress.AddressValueError):
        return None
    return None


@lru_cache(maxsize=4096)
def classify_host(host: str, port: int | None = None, scheme: str = "") -> Dest:
    raw = host
    host = host.strip().strip(".").lower()
    if not host or "__dyn__" in host:
        return Dest("dynamic", raw, "host is computed at runtime", port)
    if scheme and scheme.lower() in DANGEROUS_SCHEMES:
        return Dest("dangerous_scheme", host, f"{scheme}:// scheme (protocol smuggling / local file read)", port)
    if host in METADATA_HOSTS:
        return Dest("metadata", host, "cloud instance metadata endpoint", port)
    ip = _parse_ip(host)
    if ip is not None:
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        canonical = str(ip)
        obf = " (obfuscated IP literal)" if canonical != host.strip("[]") else ""
        if canonical in METADATA_HOSTS:
            return Dest("metadata", canonical, "cloud instance metadata endpoint" + obf, port)
        if ip.is_loopback or canonical == "0.0.0.0":
            return Dest("loopback", canonical, "loopback address" + obf, port)
        if ip.is_link_local:
            return Dest("link_local", canonical, "link-local address" + obf, port)
        if ip.is_private or ip.is_reserved:
            return Dest("private", canonical, "private-network address" + obf, port)
        return Dest("external", canonical, "public IP literal" + obf, port)
    if host in ("localhost", "ip6-localhost") or host.endswith(".localhost"):
        return Dest("loopback", host, "localhost", port)
    if host.endswith(INTERNAL_HOST_SUFFIXES) or (HOST_RE.match(host) and "." not in host):
        return Dest("internal_name", host, "internal hostname", port)
    if EXFIL_SERVICES.search(host):
        return Dest("exfil_service", host, "third-party data-drop service", port)
    if HOSTILE_HOST_LABEL.search(host):
        return Dest("hostile", host, "attacker-controlled looking domain", port)
    return Dest("external", host, "external host", port)


def classify_url(url: str) -> Dest:
    url = url.strip()
    if "://" not in url:
        # scheme-relative or bare host[:port][/path]
        if url.startswith("//"):
            url = "http:" + url
        else:
            url = "http://" + url
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        try:
            port = parts.port
        except ValueError:
            port = None
    except ValueError:
        return Dest("unknown", url, "unparseable URL")
    if EXFIL_SERVICES.search(url):
        d = classify_host(host, port, parts.scheme)
        if d.kind in ("external", "hostile"):
            return Dest("exfil_service", host, "third-party data-drop service", port)
        return d
    return classify_host(host, port, parts.scheme)


def find_urls(text: str) -> list[tuple[str, int]]:
    """URLs in free text with their character offsets."""
    return [(m.group(0), m.start()) for m in URL_RE.finditer(text)]


def internal_port(dest: Dest) -> bool:
    return dest.port in INTERNAL_SERVICE_PORTS

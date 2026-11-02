"""DNS over HTTPS. No DNS library and no dependency: just JSON over HTTPS to a public resolver."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

USER_AGENT = f"mailguard/{__version__} (+https://github.com/njuj/mailguard)"
DEFAULT_ENDPOINT = "https://dns.google/resolve"
TYPES = {"A": 1, "TXT": 16, "MX": 15, "CNAME": 5}
# RFC 1035 response codes we care about.
NXDOMAIN = 3


class DNSError(RuntimeError):
    pass


def unquote_txt(data: str) -> str:
    """Join a possibly multi-string TXT record: '"v=spf1 a" " -all"' -> 'v=spf1 a -all'."""
    parts, i, n = [], 0, len(data)
    while i < n:
        if data[i] == '"':
            j = i + 1
            buf = []
            while j < n and data[j] != '"':
                if data[j] == "\\" and j + 1 < n:
                    j += 1
                buf.append(data[j])
                j += 1
            parts.append("".join(buf))
            i = j + 1
        else:
            i += 1
    return "".join(parts) if parts else data


class Resolver:
    def __init__(self, timeout: float = 10, endpoint: str = DEFAULT_ENDPOINT):
        self.timeout = timeout
        self.endpoint = endpoint
        self._cache: dict[tuple[str, str], list[str]] = {}

    def query(self, name: str, rrtype: str) -> list[str]:
        """Record data strings for name/type. [] for NXDOMAIN or no records; raises DNSError on failure."""
        key = (name.rstrip(".").lower(), rrtype)
        if key in self._cache:
            return self._cache[key]
        url = f"{self.endpoint}?{urllib.parse.urlencode({'name': name, 'type': rrtype})}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                doc = json.load(resp)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise DNSError(f"{name} {rrtype}: {getattr(e, 'reason', e)}") from None
        if doc.get("Status") == NXDOMAIN:
            return self._cache.setdefault(key, [])
        answers = [a for a in doc.get("Answer", []) if a.get("type") == TYPES[rrtype]]
        if rrtype == "TXT":
            out = [unquote_txt(a["data"]) for a in answers]
        elif rrtype == "MX":
            out = [a["data"].split(None, 1)[-1].rstrip(".") for a in answers]  # "10 mx.example.com." -> host
        else:
            out = [a["data"].rstrip(".") for a in answers]
        return self._cache.setdefault(key, out)

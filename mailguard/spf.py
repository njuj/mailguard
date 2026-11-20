"""Evaluate an SPF record the way a receiving mail server does, and say exactly why it breaks.

RFC 7208 §4.6.4 caps an SPF evaluation at **10** DNS-querying terms (`include`, `a`, `mx`, `ptr`, `exists`,
`redirect`), counted across every record that `include`/`redirect` pulls in, and at **2** lookups that
return nothing. Going over either, a syntax error anywhere in the chain, an `include:` of a domain that has
no SPF record (§5.2), or an `mx` with more than 10 MX hosts all end in `permerror`, and most receivers
treat permerror as "no SPF at all": the record is still there and still looks right, but it does nothing.

The walk is check_host() for a sender at 192.0.2.1 (TEST-NET-1, which nobody authorizes): what a receiver
does for a spoofer. Macros (%{i}, %{ir}, %{d}, ...) are expanded for that sender, and the walk stops at the
first mechanism that matches, so an included `+all` shows up as what it is: every sender matches.
"""

from __future__ import annotations

import ipaddress
import re

from .model import SPFResult
from .resolver import DNSError, Resolver

LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists")
MECHANISMS = {"all", "ip4", "ip6", *LOOKUP_MECHANISMS}
HARD_LIMIT = 10
VOID_LIMIT = 2
MX_LIMIT = 10
MAX_DEPTH = 12  # defends against deliberately deep or cyclic include chains

_MODIFIER = re.compile(r"^([a-z][a-z0-9_.-]*)=(.*)$", re.I)
_CIDR = re.compile(r"^(.*?)(?:/(\d+))?(?://(\d+))?$")
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$", re.I)
_MACRO = re.compile(r"%(?:\{([slodiphv])(\d*)(r?)([-.+,/_=]*)\}|[%_-])", re.I)
SENDER_IP = ipaddress.ip_address("192.0.2.1")


def expand(spec: str, domain: str) -> str | None:
    """RFC 7208 §7 macro expansion for the test sender postmaster@<domain> at 192.0.2.1; None if malformed."""
    values = {"s": f"postmaster@{domain}", "l": "postmaster", "o": domain, "d": domain, "i": str(SENDER_IP),
              "p": "unknown", "v": "in-addr", "h": domain}

    def one(m: re.Match) -> str:
        if not m.group(1):
            return {"%%": "%", "%_": " ", "%-": "%20"}[m.group(0)]
        parts = re.split("[" + re.escape(m.group(4) or ".") + "]", values[m.group(1).lower()])
        if m.group(3):
            parts.reverse()
        if m.group(2):
            parts = parts[-int(m.group(2)):] if int(m.group(2)) else parts
        return ".".join(parts)

    out = _MACRO.sub(one, spec)
    return None if "%" in _MACRO.sub("", spec) else out


def find_spf(txt_records: list[str]) -> list[str]:
    """TXT records that are SPF: the first token is exactly v=spf1 ("v=spf10" is not SPF)."""
    return [r for r in txt_records if r.strip().split(" ", 1)[0].lower() == "v=spf1"]


def _split_term(term: str) -> tuple[str, str, str]:
    """(qualifier, name, value) for one mechanism, e.g. '~all' -> ('~','all',''), 'include:a.com'."""
    qualifier = ""
    if term[:1] in "+-~?":
        qualifier, term = term[0], term[1:]
    name, _, value = term.partition(":")
    if "=" in name and not value:                      # modifier, e.g. redirect=example.com
        name, _, value = term.partition("=")
    if not value and "/" in name:                      # a/24, mx//64: cidr straight after the name
        name, value = name[:name.index("/")], name[name.index("/"):]
    return qualifier, name.lower(), value


def _domain_ok(spec: str) -> bool:
    """domain-spec: macros allowed; otherwise dotted labels ending in a non-numeric top label."""
    if "%" in spec:
        return bool(re.fullmatch(r"[\x21-\x7e]+", spec))
    labels = spec.rstrip(".").split(".")
    return len(labels) >= 2 and all(_LABEL.match(l) for l in labels) and not labels[-1].isdigit()


class _Walker:
    def __init__(self, resolver: Resolver):
        self.resolver = resolver
        self.lookups = 0
        self.void = 0
        self.includes: list[str] = []
        self.costs: dict[str, int] = {}             # top-level include/redirect -> lookups it costs in total
        self.errors: list[str] = []                 # loops and DNS errors (informational)
        self.permerror: str | None = None           # the first reason the whole evaluation is a permerror
        self.ptr = False
        self.ip4: list[ipaddress.IPv4Network] = []
        self.matched: str | None = None             # a mechanism other than 'all' that matched the test sender

    def fail(self, reason: str) -> None:
        if self.permerror is None:
            self.permerror = reason

    def query(self, name: str, rrtype: str) -> list[str] | None:
        try:
            return self.resolver.query(name, rrtype)
        except DNSError as e:
            self.errors.append(str(e))
            return None

    def charge(self, empty: bool) -> None:
        if empty:
            self.void += 1
            if self.void > VOID_LIMIT:
                self.fail(f"more than {VOID_LIMIT} lookups return nothing (void lookup limit)")

    def evaluate(self, domain: str, depth: int, seen: frozenset[str], via: str) -> str | None:
        """Fetch and walk the SPF record of an include/redirect target."""
        if depth > MAX_DEPTH or domain.lower() in seen:
            self.errors.append(f"include loop or too deep at {domain}")
            self.fail(f"include loop at {domain}")
            return None
        records = self.query(domain, "TXT")
        if records is None:
            return None
        spf = find_spf(records)
        if not spf:
            self.charge(True)
            self.fail(f"{via}:{domain} has no SPF record (RFC 7208 §5.2: permerror)")
            return None
        if len(spf) > 1:
            self.fail(f"{domain} publishes {len(spf)} SPF records")
        return self.walk(spf[0], domain, depth, seen | {domain.lower()})

    def target(self, spec: str, domain: str) -> str | None:
        name = expand(spec, domain)
        if name is None:
            self.fail(f"{domain}: malformed macro in {spec!r}")
        return name

    def walk(self, record: str, domain: str, depth: int, seen: frozenset[str]) -> str | None:
        """check_host() for the test sender: the qualifier of the first mechanism that matches."""
        all_qualifier, redirect, exp, result = None, None, None, None
        for term in record.split()[1:]:            # skip the v=spf1 token
            if result is not None:                  # a receiver stops at the first match
                break
            before = self.lookups
            mod = _MODIFIER.match(term)
            if mod and ":" not in mod.group(1):
                name, value = mod.group(1).lower(), mod.group(2)
                if name == "redirect":
                    if redirect is not None:
                        self.fail(f"{domain}: redirect= appears twice")
                    redirect = value
                    if not _domain_ok(value):
                        self.fail(f"{domain}: invalid redirect target {value!r}")
                elif name == "exp":
                    if exp is not None:
                        self.fail(f"{domain}: exp= appears twice")
                    exp = value
                continue                            # unknown modifiers are ignored (RFC 7208 §6)
            qualifier, name, value = _split_term(term)
            if name not in MECHANISMS:
                self.fail(f"{domain}: unknown term {term!r}")
                continue
            if name == "all":
                if value:
                    self.fail(f"{domain}: {term!r} takes no argument")
                all_qualifier = result = qualifier or "+"
            elif name in ("ip4", "ip6"):
                if self._ip(domain, name, value, term):
                    result = qualifier or "+"
                    self.matched = self.matched or f"{term} at {domain}"
            elif name in ("include", "exists"):
                if not value or not _domain_ok(value):
                    self.fail(f"{domain}: {term!r} needs a valid domain")
                    continue
                self.lookups += 1
                host = self.target(value, domain)
                if host is None:
                    continue
                if name == "include":
                    self.includes.append(value)
                    if self.evaluate(host, depth + 1, seen, "include") == "+":   # included record passes
                        result = qualifier or "+"
                        self.matched = self.matched or f"{term} at {domain}"
                else:
                    self.charge(not self.query(host, "A"))
            else:                                   # a, mx, ptr with optional :domain and /cidr
                target, v4, v6 = _CIDR.match(value).groups() if value else ("", None, None)
                if (v4 and int(v4) > 32) or (v6 and int(v6) > 128) or (target and not _domain_ok(target)):
                    self.fail(f"{domain}: invalid {term!r}")
                    continue
                self.lookups += 1
                host = self.target(target, domain) if target else domain
                if name == "ptr":
                    self.ptr = True
                elif host is None:
                    pass
                elif name == "a":
                    self._addresses(host, int(v4) if v4 else 32)
                else:
                    hosts = self.query(host, "MX")
                    if hosts is not None:
                        self.charge(not hosts)
                        if len(hosts) > MX_LIMIT:
                            self.fail(f"{domain}: {term!r} has {len(hosts)} MX hosts (limit {MX_LIMIT})")
                        for mx in hosts[:MX_LIMIT]:
                            self._addresses(mx, int(v4) if v4 else 32, void=False)
            if depth == 0 and name == "include" and value:
                self.costs[value] = self.lookups - before
        if redirect and result is None and all_qualifier is None:   # redirect applies only when nothing matched
            before = self.lookups
            self.lookups += 1
            self.includes.append(f"redirect={redirect}")
            host = self.target(redirect, domain)
            result = self.evaluate(host, depth + 1, seen, "redirect") if host else None
            if depth == 0:
                self.costs[f"redirect={redirect}"] = self.lookups - before
        return result

    def _ip(self, domain: str, name: str, value: str, term: str) -> bool:
        """Record the network; True when it covers the test sender."""
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            self.fail(f"{domain}: invalid {term!r}")
            return False
        if (name == "ip4") != (net.version == 4) or "/" in value and not value.split("/")[1].isdigit():
            self.fail(f"{domain}: invalid {term!r}")
        elif net.version == 4:
            self.ip4.append(net)
            return SENDER_IP in net
        return False

    def _addresses(self, host: str, prefix: int, void: bool = True) -> None:
        addrs = self.query(host, "A")
        if addrs is None:
            return
        if not addrs and void:
            addrs6 = self.query(host, "AAAA") or []
            self.charge(not addrs6)
        for a in addrs:
            try:
                self.ip4.append(ipaddress.ip_network(f"{a}/{prefix}", strict=False))
            except ValueError:
                pass


def evaluate_spf(domain: str, records: list[str], resolver: Resolver) -> SPFResult | None:
    """Full evaluation of the domain's SPF record: lookups, void lookups, syntax and the permerror reason."""
    spf = find_spf(records)
    if not spf:
        return None
    w = _Walker(resolver)
    all_qualifier = w.walk(spf[0], domain.lower(), 0, frozenset({domain.lower()}))
    if len(spf) > 1:
        w.errors.insert(0, "more than one SPF record (receivers reject this as permerror)")
        w.permerror = f"{len(spf)} SPF records at {domain}; there must be exactly one"
    if w.lookups > HARD_LIMIT:
        w.permerror = f"{w.lookups} DNS lookups, over the limit of {HARD_LIMIT}"
    return SPFResult(
        record=spf[0],
        all_qualifier=all_qualifier,
        lookups=w.lookups,
        includes=w.includes,
        void_lookups=w.void,
        syntax_errors=w.errors,
        permerror=w.permerror,
        costs=w.costs,
        uses_ptr=w.ptr,
        matched=w.matched,
        ipv4_addresses=sum(n.num_addresses for n in ipaddress.collapse_addresses(w.ip4)),
    )

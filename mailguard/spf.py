"""Evaluate an SPF record the way a receiving mail server does, and say exactly why it breaks.

RFC 7208 §4.6.4 caps an SPF evaluation at **10** DNS-querying terms (`include`, `a`, `mx`, `ptr`, `exists`,
`redirect`), counted across every record that `include`/`redirect` pulls in, and at **2** lookups that
return nothing. Going over either, a syntax error anywhere in the chain, an `include:` of a domain that has
no SPF record (§5.2), or an `mx` with more than 10 MX hosts all end in `permerror`, and most receivers
treat permerror as "no SPF at all": the record is still there and still looks right, but it does nothing.

The walk evaluates every term, as a receiver does for a sender that matches nothing, so every lookup
the record can cost is counted.
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
        if "%" in domain:                           # macro: depends on the sender, can't be followed
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

    def walk(self, record: str, domain: str, depth: int, seen: frozenset[str]) -> str | None:
        all_qualifier, redirect, exp = None, None, None
        for term in record.split()[1:]:            # skip the v=spf1 token
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
                all_qualifier = qualifier or "+"
            elif name in ("ip4", "ip6"):
                self._ip(domain, name, value, term)
            elif name in ("include", "exists"):
                if not value or not _domain_ok(value):
                    self.fail(f"{domain}: {term!r} needs a valid domain")
                    continue
                self.lookups += 1
                if name == "include":
                    self.includes.append(value)
                    self.evaluate(value, depth + 1, seen, "include")
                elif "%" not in value:
                    self.charge(not self.query(value, "A"))
            else:                                   # a, mx, ptr with optional :domain and /cidr
                target, v4, v6 = _CIDR.match(value).groups() if value else ("", None, None)
                if (v4 and int(v4) > 32) or (v6 and int(v6) > 128) or (target and not _domain_ok(target)):
                    self.fail(f"{domain}: invalid {term!r}")
                    continue
                self.lookups += 1
                host = target or domain
                if name == "ptr":
                    self.ptr = True
                elif "%" in host:
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
        if redirect and all_qualifier is None:      # redirect only applies when there is no 'all'
            before = self.lookups
            self.lookups += 1
            self.includes.append(f"redirect={redirect}")
            result = self.evaluate(redirect, depth + 1, seen, "redirect")
            if depth == 0:
                self.costs[f"redirect={redirect}"] = self.lookups - before
            return result
        return all_qualifier

    def _ip(self, domain: str, name: str, value: str, term: str) -> None:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            self.fail(f"{domain}: invalid {term!r}")
            return
        if (name == "ip4") != (net.version == 4) or "/" in value and not value.split("/")[1].isdigit():
            self.fail(f"{domain}: invalid {term!r}")
        elif net.version == 4:
            self.ip4.append(net)

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
        ipv4_addresses=sum(n.num_addresses for n in ipaddress.collapse_addresses(w.ip4)),
    )

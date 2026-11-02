"""Parse an SPF record and count its DNS lookups the way a receiving mail server does.

The point of this module is the lookup count. RFC 7208 §4.6.4 caps an SPF evaluation at **10**
DNS-querying mechanisms. The mechanisms `include`, `a`, `mx`, `ptr`, `exists` and the `redirect`
modifier each cost one, and `include`/`redirect` then evaluate another record whose own lookups add
to the same budget. Go over 10 and the result is `permerror`, which most receivers treat as "no SPF
at all": the protection silently disappears. Almost no online checker actually follows the includes
to prove this, so a domain can sail past the limit for years without anyone noticing.
"""

from __future__ import annotations

from .model import SPFResult
from .resolver import DNSError, Resolver

LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists")
HARD_LIMIT = 10
VOID_LIMIT = 2
MAX_DEPTH = 12  # defends against deliberately deep or cyclic include chains


def find_spf(txt_records: list[str]) -> list[str]:
    return [r for r in txt_records if r.strip().lower().startswith("v=spf1")]


def _split_term(term: str) -> tuple[str, str, str]:
    """(qualifier, name, value) for one mechanism, e.g. '~all' -> ('~','all',''), 'include:a.com'."""
    qualifier = ""
    if term[:1] in "+-~?":
        qualifier, term = term[0], term[1:]
    name, _, value = term.partition(":")
    if "=" in name and not value:                      # modifier, e.g. redirect=example.com
        name, _, value = term.partition("=")
    return qualifier, name.lower(), value


class _Counter:
    def __init__(self, resolver: Resolver):
        self.resolver = resolver
        self.lookups = 0
        self.void = 0
        self.includes: list[str] = []
        self.errors: list[str] = []

    def evaluate(self, domain: str, depth: int, seen: frozenset[str]) -> str | None:
        """Walk one SPF record, charging lookups. Returns the 'all' qualifier of the root record."""
        if depth > MAX_DEPTH or domain.lower() in seen:
            self.errors.append(f"include loop or too deep at {domain}")
            return None
        try:
            records = find_spf(self.resolver.query(domain, "TXT"))
        except DNSError as e:
            self.errors.append(str(e))
            return None
        if not records:
            self.void += 1
            return None
        if len(records) > 1 and depth == 0:
            self.errors.append("more than one SPF record (receivers reject this as permerror)")
        record = records[0]
        return self._walk(record, depth, seen | {domain.lower()})

    def _walk(self, record: str, depth: int, seen: frozenset[str]) -> str | None:
        all_qualifier = None
        redirect = None
        for term in record.split()[1:]:                # skip the v=spf1 token
            if not term:
                continue
            qualifier, name, value = _split_term(term)
            if name == "all":
                all_qualifier = qualifier or "+"
            elif name == "redirect":
                redirect = value
            elif name in LOOKUP_MECHANISMS:
                self.lookups += 1
                if name == "include" and value:
                    self.includes.append(value)
                    self.evaluate(value, depth + 1, seen)
            # ip4/ip6/exp and bare qualifiers cost no DNS lookup
        # redirect is only used when the record has no 'all' mechanism
        if redirect and all_qualifier is None:
            self.lookups += 1
            self.includes.append(f"redirect={redirect}")
            return self.evaluate(redirect, depth + 1, seen)
        return all_qualifier


def evaluate_spf(domain: str, records: list[str], resolver: Resolver) -> SPFResult | None:
    """Full evaluation of the domain's SPF record, with recursive lookup counting."""
    spf = find_spf(records)
    if not spf:
        return None
    counter = _Counter(resolver)
    all_qualifier = counter._walk(spf[0], 0, frozenset({domain.lower()}))
    if len(spf) > 1:
        counter.errors.insert(0, "more than one SPF record (receivers reject this as permerror)")
    return SPFResult(
        record=spf[0],
        all_qualifier=all_qualifier,
        lookups=counter.lookups,
        includes=counter.includes,
        void_lookups=counter.void,
        syntax_errors=counter.errors,
    )

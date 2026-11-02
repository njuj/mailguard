from __future__ import annotations

from dataclasses import dataclass, field

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"


@dataclass
class SPFResult:
    """A parsed SPF record plus the recursive DNS-lookup count that decides whether it works at all."""

    record: str
    all_qualifier: str | None          # '-' fail · '~' softfail · '?' neutral · '+' pass-all · None if no 'all'
    lookups: int                        # DNS-querying mechanisms, counted recursively (RFC 7208 §4.6.4, limit 10)
    includes: list[str] = field(default_factory=list)   # the include/redirect chain that was followed
    void_lookups: int = 0               # lookups that returned nothing (limit 2)
    syntax_errors: list[str] = field(default_factory=list)


@dataclass
class Snapshot:
    """Everything the checks need, gathered once. Pure data, so every check is testable offline."""

    domain: str
    spf_records: list[str] = field(default_factory=list)   # every TXT that starts with v=spf1 (>1 is invalid)
    spf: SPFResult | None = None
    dmarc_records: list[str] = field(default_factory=list)  # TXT at _dmarc.<domain>
    dkim_selectors: dict[str, bool] = field(default_factory=dict)  # selector -> live key found
    dkim_wildcard: bool = False         # *._domainkey.<domain> resolves, so selector probing is meaningless
    mta_sts: str | None = None          # TXT at _mta-sts.<domain>
    mx: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def dmarc(self) -> str | None:
        return self.dmarc_records[0] if self.dmarc_records else None


@dataclass
class Check:
    id: str
    title: str
    status: str
    detail: str
    penalty: int = 0

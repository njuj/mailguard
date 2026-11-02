"""One function per check: Snapshot -> Check. Penalties are subtracted from 100."""

from __future__ import annotations

from .model import FAIL, INFO, PASS, WARN, Check, Snapshot

# Selectors probed to see whether DKIM is set up at all. We cannot enumerate selectors over DNS,
# so a miss means "not found for common selectors", never a definite "no DKIM".
COMMON_DKIM_SELECTORS = ("google", "selector1", "selector2", "s1", "s2", "k1", "k2", "default",
                         "dkim", "mail", "smtp", "mandrill", "mailjet", "mxvault", "zoho", "fm1")

ALL_QUALIFIER_TEXT = {
    "-": ("-all (hardfail)", PASS, 0),
    "~": ("~all (softfail)", WARN, 5),
    "?": ("?all (neutral: SPF does nothing to block spoofing)", WARN, 12),
    "+": ("+all (passes every sender — anyone can spoof you)", FAIL, 30),
    None: ("no 'all' mechanism (defaults to neutral)", WARN, 10),
}


def parse_dmarc(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def check_spf_presence(s: Snapshot) -> Check:
    title = "SPF record"
    if not s.spf_records:
        return Check("spf", title, FAIL, "no SPF record: nothing tells receivers which servers may send as you", 30)
    if len(s.spf_records) > 1:
        return Check("spf", title, FAIL, f"{len(s.spf_records)} SPF records; RFC 7208 requires exactly one, so "
                                         "receivers treat this as permerror and ignore SPF entirely", 20)
    return Check("spf", title, PASS, "one SPF record present")


def check_spf_lookups(s: Snapshot) -> Check:
    title = "SPF DNS lookups"
    if not s.spf:
        return Check("spf-lookups", title, INFO, "no SPF record to evaluate")
    n = s.spf.lookups
    chain = f" via {', '.join(s.spf.includes)}" if s.spf.includes else ""
    if n > 10:
        return Check("spf-lookups", title, FAIL,
                     f"needs {n} DNS lookups{chain}; over the limit of 10, so evaluation returns permerror and "
                     "receivers drop SPF — the record looks fine but does nothing", 25)
    if n >= 8:
        return Check("spf-lookups", title, WARN,
                     f"uses {n} of 10 DNS lookups; one more include tips it into permerror", 8)
    return Check("spf-lookups", title, PASS, f"{n} of 10 DNS lookups")


def check_spf_policy(s: Snapshot) -> Check:
    title = "SPF policy"
    if not s.spf:
        return Check("spf-policy", title, INFO, "no SPF record to evaluate")
    detail, status, penalty = ALL_QUALIFIER_TEXT[s.spf.all_qualifier]
    return Check("spf-policy", title, status, detail, penalty)


def check_spf_void(s: Snapshot) -> Check | None:
    title = "SPF void lookups"
    if s.spf and s.spf.void_lookups > 2:
        return Check("spf-void", title, WARN,
                     f"{s.spf.void_lookups} mechanisms resolve to nothing; over 2 void lookups is also a permerror", 6)
    return None


def check_dmarc_presence(s: Snapshot) -> Check:
    title = "DMARC record"
    if not s.dmarc_records:
        return Check("dmarc", title, FAIL,
                     "no DMARC record at _dmarc: SPF/DKIM failures are not acted on and you get no spoofing reports",
                     25)
    if len(s.dmarc_records) > 1:
        return Check("dmarc", title, FAIL, "more than one DMARC record; receivers ignore all of them", 20)
    if not s.dmarc.lower().startswith("v=dmarc1"):
        return Check("dmarc", title, FAIL, "record at _dmarc does not start with v=DMARC1", 15)
    return Check("dmarc", title, PASS, "DMARC record present")


def check_dmarc_policy(s: Snapshot) -> Check:
    title = "DMARC policy"
    if not s.dmarc or not s.dmarc.lower().startswith("v=dmarc1"):
        return Check("dmarc-policy", title, INFO, "no valid DMARC record to evaluate")
    tags = parse_dmarc(s.dmarc)
    policy = tags.get("p", "none").lower()
    if policy == "none":
        return Check("dmarc-policy", title, FAIL,
                     "p=none: receivers only watch and report, they never reject or quarantine spoofed mail", 15)
    extra, penalty = [], 0
    if policy == "quarantine":
        extra.append("quarantine (spoofed mail goes to spam, not rejected)")
        penalty += 5
    else:
        extra.append("reject (the strongest policy)")
    pct = tags.get("pct")
    if pct and pct.strip() != "100":
        extra.append(f"but pct={pct}, so the policy applies to only {pct}% of mail")
        penalty += 5
    if tags.get("sp", "").lower() == "none" and policy == "reject":
        extra.append("sp=none leaves subdomains unprotected")
        penalty += 5
    status = WARN if penalty else PASS
    return Check("dmarc-policy", title, status, "; ".join(extra), penalty)


def check_dmarc_reporting(s: Snapshot) -> Check | None:
    title = "DMARC reporting"
    if not s.dmarc or not s.dmarc.lower().startswith("v=dmarc1"):
        return None
    if "rua" not in parse_dmarc(s.dmarc):
        return Check("dmarc-rua", title, WARN,
                     "no rua address, so you never receive the aggregate reports that reveal spoofing", 3)
    return Check("dmarc-rua", title, PASS, "aggregate reports (rua) configured")


def check_dkim(s: Snapshot) -> Check:
    title = "DKIM"
    if s.dkim_wildcard:
        return Check("dkim", title, INFO,
                     "a wildcard *._domainkey record answers every selector, so DKIM can't be verified this way")
    found = [sel for sel, ok in s.dkim_selectors.items() if ok]
    if found:
        return Check("dkim", title, PASS, f"live key found at selector(s): {', '.join(found)}")
    return Check("dkim", title, INFO,
                 "no key at common selectors — DKIM may still use a custom selector we can't guess")


def check_mta_sts(s: Snapshot) -> Check:
    title = "MTA-STS"
    if s.mta_sts and s.mta_sts.lower().startswith("v=stsv1"):
        return Check("mta-sts", title, PASS, "MTA-STS published (enforces TLS for inbound mail)")
    return Check("mta-sts", title, INFO, "no MTA-STS record; inbound mail can be downgraded to cleartext")


def check_mx(s: Snapshot) -> Check | None:
    title = "MX"
    if not s.mx and not s.spf_records and not s.dmarc_records:
        return Check("mx", title, INFO, "no MX records; if this domain never sends or receives mail, publish "
                                        "an SPF record of `v=spf1 -all` to say so")
    return None


CHECKS = (check_spf_presence, check_spf_lookups, check_spf_policy, check_spf_void,
          check_dmarc_presence, check_dmarc_policy, check_dmarc_reporting, check_dkim, check_mta_sts, check_mx)


def run_checks(s: Snapshot) -> list[Check]:
    return [c for c in (check(s) for check in CHECKS) if c is not None]

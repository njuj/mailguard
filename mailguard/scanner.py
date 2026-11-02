"""Gather one domain's mail-auth DNS records into a Snapshot, then run the checks."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from .checks import COMMON_DKIM_SELECTORS, run_checks
from .model import Check, Snapshot
from .resolver import DNSError, Resolver
from .spf import evaluate_spf


def _is_live_dkim(record: str) -> bool:
    """A usable DKIM key: v=DKIM1 (or no v=, which is allowed) with a non-empty public key.

    `p=` with nothing after it is a *revoked* key (RFC 6376 §3.6.1), not a working one.
    """
    low = record.lower()
    if "dkim1" not in low and "k=" not in low and "p=" not in low:
        return False
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if key.strip().lower() == "p":
            return bool(value.strip())
    return False


def gather(domain: str, resolver: Resolver) -> Snapshot:
    domain = domain.strip().rstrip(".").lower()
    snap = Snapshot(domain=domain)

    def safe(name: str, rrtype: str) -> list[str]:
        try:
            return resolver.query(name, rrtype)
        except DNSError as e:
            snap.errors.append(str(e))
            return []

    snap.spf_records = [r for r in safe(domain, "TXT") if r.strip().lower().startswith("v=spf1")]
    snap.dmarc_records = [r for r in safe(f"_dmarc.{domain}", "TXT") if r.strip().lower().startswith("v=dmarc1")]
    mta = safe(f"_mta-sts.{domain}", "TXT")
    snap.mta_sts = next((r for r in mta if r.strip().lower().startswith("v=stsv1")), None)
    snap.mx = safe(domain, "MX")

    # DKIM probes are independent; run them together to keep the scan quick. A random selector goes
    # first: if it resolves, the domain has a wildcard *._domainkey record and probing proves nothing.
    def live_key(selector: str) -> tuple[str, bool]:
        try:
            records = resolver.query(f"{selector}._domainkey.{domain}", "TXT")
        except DNSError:
            return selector, False
        return selector, any(_is_live_dkim(r) for r in records)

    probes = ("mg-wildcard-probe-9z7q",) + COMMON_DKIM_SELECTORS
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = dict(pool.map(live_key, probes))
    snap.dkim_wildcard = results.pop("mg-wildcard-probe-9z7q", False)
    snap.dkim_selectors = {} if snap.dkim_wildcard else results

    if snap.spf_records:
        snap.spf = evaluate_spf(domain, snap.spf_records, resolver)
    return snap


def audit(domain: str, resolver: Resolver | None = None) -> tuple[Snapshot, list[Check]]:
    snap = gather(domain, resolver or Resolver())
    return snap, run_checks(snap)

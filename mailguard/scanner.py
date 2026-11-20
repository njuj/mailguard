"""Gather one domain's mail-auth DNS records into a Snapshot, then run the checks."""

from __future__ import annotations

import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .checks import COMMON_DKIM_SELECTORS, parse_dmarc, report_domains, run_checks
from .model import Check, Snapshot
from .resolver import USER_AGENT, DNSError, Resolver
from .spf import evaluate_spf

POLICY_LIMIT = 64 * 1024


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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):      # RFC 8461 §3.3: senders must not follow redirects
        return None


def fetch_policy(domain: str, timeout: float = 10) -> tuple[str | None, str | None]:
    """(policy text, error) for https://mta-sts.<domain>/.well-known/mta-sts.txt, fetched like a sender does."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}), timeout=timeout) as resp:
            body = resp.read(POLICY_LIMIT).decode("utf-8", "replace")
            ctype = resp.headers.get_content_type()
    except urllib.error.HTTPError as e:
        return None, (f"{url} redirects (HTTP {e.code}); senders do not follow redirects" if 300 <= e.code < 400
                      else f"{url} answers HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return None, f"{url}: {getattr(e, 'reason', e)}"
    if ctype != "text/plain":
        return body, f"policy served as {ctype}, RFC 8461 requires text/plain"
    return body, None


def gather(domain: str, resolver: Resolver, fetch=None) -> Snapshot:
    domain = domain.strip().rstrip(".").lower()
    snap = Snapshot(domain=domain)

    def safe(name: str, rrtype: str) -> list[str]:
        try:
            return resolver.query(name, rrtype)
        except DNSError as e:
            snap.errors.append(str(e))
            return []

    snap.spf_records = [r for r in safe(domain, "TXT") if r.strip().split(" ", 1)[0].lower() == "v=spf1"]
    snap.dmarc_records = [r for r in safe(f"_dmarc.{domain}", "TXT") if r.strip().lower().startswith("v=dmarc1")]
    mta = safe(f"_mta-sts.{domain}", "TXT")
    snap.mta_sts = next((r for r in mta if r.strip().lower().startswith("v=stsv1")), None)
    snap.tls_rpt = [r for r in safe(f"_smtp._tls.{domain}", "TXT") if r.strip().lower().startswith("v=tlsrptv1")]
    snap.mx = [m for m in safe(domain, "MX") if m.strip(".")]   # "MX 0 ." is a null MX: no mail
    if snap.mta_sts:
        snap.mta_sts_policy, snap.mta_sts_error = (fetch or fetch_policy)(domain)

    # reports sent to another domain are dropped unless it publishes <domain>._report._dmarc.<it> (RFC 7489 §7.1)
    if snap.dmarc:
        for dest in report_domains(domain, parse_dmarc(snap.dmarc)):
            auth = safe(f"{domain}._report._dmarc.{dest}", "TXT")
            snap.dmarc_external[dest] = any(r.strip().lower().startswith("v=dmarc1") for r in auth)

    # DKIM probes are independent; run them together to keep the scan quick. A random selector goes
    # first: if it resolves, the domain has a wildcard *._domainkey record and probing proves nothing.
    def live_key(selector: str) -> tuple[str, str | None]:
        try:
            records = resolver.query(f"{selector}._domainkey.{domain}", "TXT")
        except DNSError:
            return selector, None
        return selector, next((r for r in records if _is_live_dkim(r)), None)

    probes = ("mg-wildcard-probe-9z7q",) + COMMON_DKIM_SELECTORS
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = dict(pool.map(live_key, probes))
    snap.dkim_wildcard = results.pop("mg-wildcard-probe-9z7q") is not None
    if not snap.dkim_wildcard:
        snap.dkim_selectors = {sel: rec is not None for sel, rec in results.items()}
        snap.dkim_keys = {sel: rec for sel, rec in results.items() if rec}

    if snap.spf_records:
        snap.spf = evaluate_spf(domain, snap.spf_records, resolver)
    return snap


def audit(domain: str, resolver: Resolver | None = None, fetch=None) -> tuple[Snapshot, list[Check]]:
    snap = gather(domain, resolver or Resolver(), fetch)
    return snap, run_checks(snap)

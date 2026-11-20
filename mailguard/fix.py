"""--fix: the DNS records (zone-file syntax) and files that would close what the checks found."""

from __future__ import annotations

import datetime

from .checks import dkim_key_bits, mx_matches, parse_dmarc, parse_sts_policy
from .model import Snapshot

NEXT_POLICY = {"none": "quarantine", "quarantine": "reject"}


def _txt(name: str, value: str) -> str:
    return f'{name:<24} IN TXT "{value}"'


def _dmarc(s: Snapshot, rua: str) -> list[str]:
    tags = parse_dmarc(s.dmarc) if s.dmarc else {}
    p = tags.get("p", "").lower()
    pct = tags.get("pct", "100")
    if p == "reject" and pct == "100" and "rua" in tags:
        return []
    if not s.mx:
        step, why = "reject", "a domain that sends no mail can reject everything at once"
    elif p in NEXT_POLICY and "rua" in tags:
        step, why = NEXT_POLICY[p], f"next step up from p={p}; move on once reports show only your own senders"
    elif p == "reject" and "rua" in tags:
        step, why = p, "apply the policy to all mail, not a pct= sample"
    elif p in NEXT_POLICY or p == "reject":
        step, why = p, "add rua so you see who sends as you"
    else:
        step, why = "none", "stage 1: watch reports for 2-4 weeks, then quarantine, then reject"
    keep = {k: v for k, v in tags.items() if k not in ("v", "p", "pct", "rua")}
    value = "; ".join([f"v=DMARC1; p={step}", f"rua={tags.get('rua', rua)}", *(f"{k}={v}" for k, v in keep.items())])
    return [f"; DMARC: {why}", _txt("_dmarc", value)]


def _spf(s: Snapshot) -> list[str]:
    if not s.mx and not s.spf_records:
        return ["; SPF: this domain sends no mail, so say so", _txt("@", "v=spf1 -all")]
    if not s.spf_records:
        return ["; SPF: authorize your MX hosts; add include: for every service that sends as you (CRM, "
                "newsletters, ticketing)", _txt("@", "v=spf1 mx -all")]
    if len(s.spf_records) > 1:
        return [f"; SPF: merge the {len(s.spf_records)} SPF records into one and delete the others"]
    out = []
    spf = s.spf
    record = s.spf_records[0]
    if spf and spf.lookups > 10:
        top = ", ".join(f"{k} ({v})" for k, v in sorted(spf.costs.items(), key=lambda kv: -kv[1])[:3])
        out.append(f"; SPF: {spf.lookups} lookups; drop unused includes or replace the costliest with their "
                   f"ip4:/ip6: ranges: {top}")
    elif spf and spf.permerror:
        out.append(f"; SPF: fix the permerror first: {spf.permerror}")
    if spf and spf.all_qualifier != "-":
        terms = [t for t in record.split() if t.lstrip("+-~?").lower() != "all"]
        if not any(t.lower().startswith("redirect=") for t in terms):
            out += ["; SPF: end in -all so receivers reject mail from servers you did not list",
                    _txt("@", " ".join(terms + ["-all"]))]
    return out


def _mta_sts(s: Snapshot, today: str) -> list[str]:
    if not s.mx:
        return []
    policy = parse_sts_policy(s.mta_sts_policy or "")
    patterns = policy.get("mx", [])
    mode = (policy.get("mode") or ["testing"])[0].lower()
    hosts = [m.rstrip(".") for m in s.mx]
    healthy = s.mta_sts and s.mta_sts_policy is not None and patterns and \
        all(any(mx_matches(h, p) for p in patterns) for h in hosts)
    out = []
    if not healthy:
        out += ["; MTA-STS: TXT record, then serve the policy below as text/plain over HTTPS at",
                f";   https://mta-sts.{s.domain}/.well-known/mta-sts.txt (no redirects; a valid certificate)",
                _txt("_mta-sts", f"v=STSv1; id={today}"),
                "; --- mta-sts.txt ---",
                "; version: STSv1",
                f"; mode: {'enforce' if mode == 'enforce' else 'testing'}",
                *(f"; mx: {h}" for h in hosts),
                "; max_age: 604800",
                "; -------------------",
                "; bump id= whenever the policy changes; switch to mode: enforce once TLS reports are clean"]
    if not s.tls_rpt:
        out += ["; TLS-RPT: get a daily report when senders can't deliver over TLS",
                _txt("_smtp._tls", f"v=TLSRPTv1; rua=mailto:tls-reports@{s.domain}")]
    return out


def recommend(s: Snapshot, today: str | None = None) -> list[str]:
    """Zone-file lines (relative names) plus `;` comments. Empty when there is nothing to change."""
    today = today or datetime.date.today().strftime("%Y%m%d")
    rua = f"mailto:dmarc-reports@{s.domain}"
    out = _spf(s) + _dmarc(s, rua)
    if not s.mx and not s.spf_records and not s.dmarc_records:
        out += ["; null MX (RFC 7505): tell senders this domain accepts no mail", f"{'@':<24} IN MX 0 ."]
    for dest, ok in s.dmarc_external.items():
        if not ok:
            out += [f"; in the zone of {dest} (not yours), so it accepts your DMARC reports:",
                    _txt(f"{s.domain}._report._dmarc.{dest}.", "v=DMARC1")]
    out += _mta_sts(s, today)
    for sel, rec in s.dkim_keys.items():
        bits = dkim_key_bits(rec)
        if isinstance(bits, int) and bits < 2048:
            out.append(f"; DKIM: selector {sel} is {bits}-bit; publish a 2048-bit key under a new selector, "
                       "sign with it, then revoke the old one with p=")
    return out


def render(s: Snapshot, today: str | None = None) -> str:
    lines = recommend(s, today)
    if not lines:
        return f"; {s.domain}: nothing to change\n"
    head = [f"; records for {s.domain} (zone-file syntax, names relative to {s.domain}.)"]
    return "\n".join(head + lines) + "\n"


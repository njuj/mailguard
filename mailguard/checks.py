"""One function per check: Snapshot -> Check. Penalties are subtracted from 100."""

from __future__ import annotations

import base64
import binascii
import re

from .model import FAIL, INFO, PASS, WARN, Check, Snapshot

SHARED_SPACE = 1 << 24      # an SPF record authorizing more than a /8 lets whole cloud regions send as you

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


def _costliest(s: Snapshot) -> str:
    top = sorted(s.spf.costs.items(), key=lambda kv: -kv[1])[:3]
    return f" (costliest: {', '.join(f'{k} {v}' for k, v in top)})" if top and top[0][1] > 1 else ""


def check_spf_lookups(s: Snapshot) -> Check:
    title = "SPF DNS lookups"
    if not s.spf:
        return Check("spf-lookups", title, INFO, "no SPF record to evaluate")
    n = s.spf.lookups
    if n > 10:
        return Check("spf-lookups", title, FAIL,
                     f"needs {n} DNS lookups, over the limit of 10, so evaluation returns permerror and "
                     f"receivers drop SPF: the record looks fine but does nothing{_costliest(s)}", 25)
    if n >= 8:
        return Check("spf-lookups", title, WARN,
                     f"uses {n} of 10 DNS lookups; one more include tips it into permerror{_costliest(s)}", 8)
    return Check("spf-lookups", title, PASS, f"{n} of 10 DNS lookups")


def check_spf_policy(s: Snapshot) -> Check:
    title = "SPF policy"
    if not s.spf:
        return Check("spf-policy", title, INFO, "no SPF record to evaluate")
    detail, status, penalty = ALL_QUALIFIER_TEXT[s.spf.all_qualifier]
    return Check("spf-policy", title, status, detail, penalty)


def check_spf_eval(s: Snapshot) -> Check | None:
    """Everything else that turns SPF into permerror, then the address space it authorizes."""
    title = "SPF evaluation"
    if not s.spf or len(s.spf_records) > 1:
        return None
    if s.spf.permerror and s.spf.lookups <= 10:
        return Check("spf-eval", title, FAIL, f"permerror: {s.spf.permerror}; receivers ignore this SPF record", 25)
    if s.spf.permerror:
        return None                                     # the lookup check already says it
    space = s.spf.ipv4_addresses
    allowed = f"authorizes {space:,} IPv4 addresses" if space else "no IPv4 addresses resolved"
    if space > SHARED_SPACE:
        return Check("spf-eval", title, WARN, f"no permerror, but {allowed} (more than a /8): anyone who can "
                                              "rent an address in those ranges passes SPF as you", 5)
    if s.spf.uses_ptr:
        return Check("spf-eval", title, WARN, f"uses ptr, which RFC 7208 says not to use (slow, and some "
                                              f"receivers skip it); {allowed}", 3)
    return Check("spf-eval", title, PASS, f"no permerror; {allowed}")


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
    p = parse_dmarc(s.dmarc).get("p")
    if (p or "").lower() not in ("none", "quarantine", "reject"):
        return Check("dmarc", title, FAIL, f"p={p or '(missing)'} is not none, quarantine or reject: receivers "
                                           "discard the whole record (RFC 7489 §6.6.3)", 15)
    return Check("dmarc", title, PASS, "DMARC record present")


def check_dmarc_policy(s: Snapshot) -> Check:
    title = "DMARC policy"
    if not s.dmarc or not s.dmarc.lower().startswith("v=dmarc1") or \
            parse_dmarc(s.dmarc).get("p", "").lower() not in ("none", "quarantine", "reject"):
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
    tags = parse_dmarc(s.dmarc)
    if "rua" not in tags:
        return Check("dmarc-rua", title, WARN,
                     "no rua address, so you never receive the aggregate reports that reveal spoofing", 3)
    bad = [u.strip() for u in tags["rua"].split(",") if not u.strip().lower().startswith("mailto:")]
    if bad:
        return Check("dmarc-rua", title, WARN, f"rua {bad[0]!r} is not a mailto: URI, so no reports arrive", 3)
    dropped = [d for d, ok in s.dmarc_external.items() if not ok]
    if dropped:
        return Check("dmarc-rua", title, WARN,
                     f"reports to {', '.join(dropped)} are dropped: it has not published "
                     f"{s.domain}._report._dmarc.{dropped[0]} to accept them (RFC 7489 §7.1)", 3)
    return Check("dmarc-rua", title, PASS, "aggregate reports (rua) configured" +
                 (f", {', '.join(s.dmarc_external)} authorized to receive them" if s.dmarc_external else ""))


def report_domains(domain: str, tags: dict[str, str]) -> list[str]:
    """Domains outside `domain` that rua/ruf send to (subdomains and parents count as the same owner)."""
    out = []
    for uri in (tags.get("rua", "") + "," + tags.get("ruf", "")).split(","):
        m = re.match(r"\s*mailto:[^@]+@([^!,\s]+)", uri, re.I)
        if not m:
            continue
        dest = m.group(1).lower().rstrip(".")
        same = dest == domain or dest.endswith("." + domain) or domain.endswith("." + dest)
        if not same and dest not in out:
            out.append(dest)
    return out


def check_dkim(s: Snapshot) -> Check:
    title = "DKIM"
    if s.dkim_wildcard:
        return Check("dkim", title, INFO,
                     "a wildcard *._domainkey record answers every selector, so DKIM can't be verified this way")
    found = [sel for sel, ok in s.dkim_selectors.items() if ok]
    if found:
        sizes = {sel: dkim_key_bits(s.dkim_keys[sel]) for sel in found if sel in s.dkim_keys}
        rsa = {sel: b for sel, b in sizes.items() if b and b != "ed25519"}
        weakest = min(rsa.items(), key=lambda kv: kv[1]) if rsa else None
        listed = ", ".join(f"{sel} ({sizes[sel]}{'-bit' if isinstance(sizes.get(sel), int) else ''})"
                           if sizes.get(sel) else sel for sel in found)
        if weakest and weakest[1] < 1024:
            return Check("dkim", title, FAIL, f"selector {weakest[0]} has a {weakest[1]}-bit RSA key: receivers "
                                              f"must treat keys under 1024 bits as invalid (RFC 8301); {listed}", 10)
        if weakest and weakest[1] < 2048:
            return Check("dkim", title, WARN, f"selector {weakest[0]} uses a {weakest[1]}-bit RSA key, the minimum "
                                              f"allowed; rotate to 2048 bits. Keys: {listed}", 3)
        return Check("dkim", title, PASS, f"live key found at selector(s): {listed}")
    return Check("dkim", title, INFO,
                 "no key at common selectors; DKIM may still use a custom selector we can't guess")


def _der(b: bytes, i: int) -> tuple[int, int, int]:
    """(tag, value start, value length) of the DER element at i."""
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n, i = int.from_bytes(b[i:i + k], "big"), i + k
    return tag, i, n


def _rsa_bits(der: bytes) -> int | None:
    tag, i, _ = _der(der, 0)
    if tag != 0x30:
        return None
    tag, j, n = _der(der, i)
    if tag == 0x30:                                    # SubjectPublicKeyInfo: skip the algorithm, open the key
        tag, k, m = _der(der, j + n)
        return _rsa_bits(der[k + 1:k + m]) if tag == 0x03 else None
    if tag == 0x02:                                    # RSAPublicKey: the modulus comes first
        modulus = der[j:j + n].lstrip(b"\x00")
        return (len(modulus) - 1) * 8 + modulus[0].bit_length() if modulus else None
    return None


def dkim_key_bits(record: str) -> int | str | None:
    """RSA modulus size of a DKIM key record, "ed25519", or None when it can't be read."""
    tags = parse_dmarc(record)
    if tags.get("k", "rsa").lower() == "ed25519":
        return "ed25519"
    p = re.sub(r"\s+", "", tags.get("p", ""))
    try:
        return _rsa_bits(base64.b64decode(p + "=" * (-len(p) % 4), validate=True))
    except (binascii.Error, ValueError, IndexError):
        return None


def parse_sts_policy(text: str) -> dict[str, list[str]]:
    policy: dict[str, list[str]] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            policy.setdefault(key.strip().lower(), []).append(value.strip())
    return policy


def mx_matches(host: str, pattern: str) -> bool:
    """RFC 8461 §4.1: exact name, or "*." matching exactly one leftmost label."""
    host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return "." in host and host.split(".", 1)[1] == pattern[2:]
    return host == pattern


def check_mta_sts(s: Snapshot) -> Check:
    title = "MTA-STS"
    if not (s.mta_sts and s.mta_sts.lower().startswith("v=stsv1")):
        return Check("mta-sts", title, INFO, "no MTA-STS record; inbound mail can be downgraded to cleartext")
    if s.mta_sts_policy is None:
        return Check("mta-sts", title, FAIL, f"TXT published but the policy can't be fetched, so senders ignore "
                                             f"MTA-STS: {s.mta_sts_error}", 8)
    policy = parse_sts_policy(s.mta_sts_policy)
    version, mode = policy.get("version", [""])[0], policy.get("mode", [""])[0].lower()
    max_age, patterns = policy.get("max_age", [""])[0], policy.get("mx", [])
    if version != "STSv1" or mode not in ("enforce", "testing", "none") or not max_age.isdigit() or \
            (mode != "none" and not patterns):
        return Check("mta-sts", title, FAIL, "policy file is invalid (needs version: STSv1, mode, mx and "
                                             "max_age), so senders ignore it", 8)
    if mode == "none":
        return Check("mta-sts", title, INFO, "policy mode is none: MTA-STS is switched off")
    uncovered = [mx for mx in s.mx if not any(mx_matches(mx, p) for p in patterns)]
    if uncovered:
        if mode == "enforce":
            return Check("mta-sts", title, FAIL,
                         f"enforce mode, but MX {uncovered[0]} is not in the policy's mx list "
                         f"({', '.join(patterns)}): senders that honour MTA-STS will refuse to deliver to it", 15)
        return Check("mta-sts", title, WARN, f"testing mode, and MX {uncovered[0]} is not in the policy's mx list: "
                                             "switching to enforce would break delivery to it", 4)
    notes = []
    if s.mta_sts_error:
        notes.append(s.mta_sts_error)
    if int(max_age) < 86400:
        notes.append(f"max_age {max_age}s is under a day; RFC 8461 suggests weeks")
    if mode == "testing":
        return Check("mta-sts", title, WARN, "testing mode: TLS failures are reported, not blocked" +
                     (f"; {'; '.join(notes)}" if notes else ""), 2)
    if notes:
        return Check("mta-sts", title, WARN, f"enforce mode, but {'; '.join(notes)}", 2)
    return Check("mta-sts", title, PASS, f"enforce mode, every MX covered, max_age {int(max_age) // 86400} days")


def check_tls_rpt(s: Snapshot) -> Check | None:
    title = "TLS reporting"
    if s.tls_rpt:
        return Check("tls-rpt", title, PASS, "TLS-RPT published: senders report TLS failures to you")
    if s.mta_sts:
        return Check("tls-rpt", title, INFO, "no _smtp._tls record, so you never hear when senders can't use TLS")
    return None


def check_mx(s: Snapshot) -> Check | None:
    title = "MX"
    if not s.mx and not s.spf_records and not s.dmarc_records:
        return Check("mx", title, INFO, "no MX records; if this domain never sends or receives mail, publish "
                                        "an SPF record of `v=spf1 -all` to say so")
    return None


CHECKS = (check_spf_presence, check_spf_lookups, check_spf_policy, check_spf_eval,
          check_dmarc_presence, check_dmarc_policy, check_dmarc_reporting, check_dkim, check_mta_sts,
          check_tls_rpt, check_mx)


def run_checks(s: Snapshot) -> list[Check]:
    return [c for c in (check(s) for check in CHECKS) if c is not None]

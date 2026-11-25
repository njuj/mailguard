# mailguard

[![Part of Cryptid Security](https://img.shields.io/badge/part_of-Cryptid%20Security-c6922f?style=flat-square&labelColor=0c1411)](https://github.com/cryptid-security)

**Grade any domain's protection against email spoofing (SPF, DKIM, DMARC, MTA-STS) from DNS alone, then print the records that fix it.** mailguard evaluates SPF the way a receiving mail server does, checked against the reference implementation on the top 1,000 domains. It names the exact reason a record silently breaks and which include costs the most lookups. It fetches and checks your MTA-STS policy against your real MX hosts, and reads the size of every DKIM key. Zero dependencies.

[![ci](https://github.com/njuj/mailguard/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/mailguard/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-00ff9c?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-00ff9c?labelColor=0b0f17)
![pyspf](https://img.shields.io/badge/pyspf%20agreement-759%2F760-00ff9c?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-00ff9c?labelColor=0b0f17)

<p align="center"><img src="docs/banner.svg" width="100%" alt="mailguard: how it works"/></p>

<p align="center"><img src="docs/demo.svg" width="100%" alt="mailguard running in a terminal"/></p>

```text
$ mailguard github.com

 mailguard v0.2.0  →  github.com

   GRADE   C    79/100

   ✔ SPF record       one SPF record present
   ⚠ SPF DNS lookups  10 of 10 DNS lookups, one include from permerror; costliest: _spf.salesforce.com 2, sendgrid.net 2  -8
   ⚠ SPF policy       ~all (softfail)  -5
   ✔ SPF evaluation   no permerror; authorizes 932,933 IPv4 addresses
   ✔ DMARC record     DMARC record present
   ⚠ DMARC policy     quarantine (spoofed mail goes to spam, not rejected)  -5
   ✔ DMARC reporting  aggregate reports (rua) configured
   ⚠ DKIM             1024-bit RSA key at selector1, k1, the minimum allowed; rotate to 2048 (6 live keys)  -3
   · MTA-STS          no MTA-STS record; inbound mail can be downgraded to cleartext
```

This is real output against live DNS. GitHub sits at **exactly 10 of 10 SPF lookups**: one more `include:` and every receiver would stop honouring its SPF. The output also says which includes to trim first.

## The problem nobody watches: SPF that silently stops working

An SPF record can pull in others with `include:`, `redirect=`, `a`, `mx`, `ptr` and `exists`. Each one costs a DNS lookup, and [RFC 7208 §4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4) caps one evaluation at **10** lookups and at **2** that return nothing. Any of these ends the evaluation in **permerror**, and most receivers treat permerror as *no SPF at all*:

- going over either limit, often because a provider grew its own record;
- an `include:` of a domain with no SPF record;
- an `mx` with more than 10 hosts;
- a typo like `ip:` for `ip4:`;
- two SPF records at one name.

The record is still there and still looks correct, but it does nothing. You get no error, no bounce and no warning.

mailguard runs `check_host()` the way a receiver does for a spoofer: a sender at `192.0.2.1` (TEST-NET-1, which nobody authorizes). It expands macros (`%{i}`, `%{ir}`, `%{d}`, ...) for that sender and follows every include, and it stops at the first mechanism that matches, as receivers do. That is how it finds things a record-printer can't:

- **zoom.us** ends in permerror for every spoofer: two per-IP includes and an `exists:` return nothing for an unknown sender, which goes over the void-lookup limit.
- **unsplash.com** writes `-all`, but an earlier `~include:` points at a record that ends in `+all`. Every sender matches there, so every spoofer gets *softfail*, and the `-all` is never reached.
- **cloudflare.com** publishes an MTA-STS TXT record, but `mta-sts.cloudflare.com` has no address. No sender can fetch the policy, so MTA-STS does nothing.

## What it grades

| Check | Pass | Penalty |
|---|---|---|
| **SPF record** | exactly one present | missing -30 · more than one (permerror) -20 |
| **SPF DNS lookups** | ≤ 7 of 10 | **over 10 (permerror) -25** · 8–10 -8; both name the costliest includes |
| **SPF policy** | `-all` (hardfail) | `~all` -5 · `?all` -12 · **`+all` -30** · no `all` -10 |
| **SPF evaluation** | no permerror; shows the IPv4 space it authorizes | **any other permerror, with the exact reason -25** · a term that matches every sender -5 (+all: -30) · more than a /8 authorized -5 · `ptr` -3 |
| **DMARC record** | present and valid | missing -25 · invalid, or `p=` not none/quarantine/reject (the whole record is discarded) -15 |
| **DMARC policy** | `p=reject` | `p=none` (monitoring only) -15 · `quarantine` -5 · `pct<100` -5 · `sp=none` -5 |
| **DMARC reporting** | `rua=` set, and external report domains authorize it | missing, not `mailto:`, or **sent to a domain that never published `<you>._report._dmarc.<it>`, so the reports are dropped** -3 |
| **DKIM** | live key at a common selector, ≥ 2048-bit RSA or Ed25519 | **RSA < 1024 bits (receivers must ignore it, RFC 8301) -10** · 1024-bit -3 |
| **MTA-STS** | `mode: enforce`, policy valid, every MX covered | **enforce, but an MX isn't in the policy (senders refuse to deliver) -15** · TXT but no fetchable policy (a redirect counts), or an invalid policy -8 · testing mode -2, or -4 with an uncovered MX · served as the wrong content type -2 · `max_age` under a day -2 |
| **TLS reporting** | `_smtp._tls` published | informational |

`A+` is a clean sheet with no warnings · `A` ≥ 90 · `B` ≥ 80 · `C` ≥ 70 · `D` ≥ 60 · `F` otherwise. A domain with neither a working hardfail SPF nor DMARC enforcement is trivially spoofable and is capped at **F**. An SPF record that ends in permerror doesn't count as working, whatever its `all` says.

## `--fix`: the records to publish

```text
$ mailguard github.com --fix
...
; records for github.com (zone-file syntax, names relative to github.com.)
; SPF: end in -all so receivers reject mail from servers you did not list
@                        IN TXT "v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com ... -all"
; DMARC: next step up from p=quarantine; move on once reports show only your own senders
_dmarc                   IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@github.com; sp=reject; ruf=mailto:dmarc@github.com; fo=1"
; MTA-STS: TXT record, then serve the policy below as text/plain over HTTPS at
;   https://mta-sts.github.com/.well-known/mta-sts.txt (no redirects; a valid certificate)
_mta-sts                 IN TXT "v=STSv1; id=20261121"
; --- mta-sts.txt ---
; version: STSv1
; mode: testing
; mx: github-com.mail.protection.outlook.com
; max_age: 604800
; -------------------
; TLS-RPT: get a daily report when senders can't deliver over TLS
_smtp._tls               IN TXT "v=TLSRPTv1; rua=mailto:tls-reports@github.com"
; DKIM: short RSA keys at selector1 (1024), k1 (1024); publish a 2048-bit key under a new selector, ...
```

- **Built from your current records.** Existing tags are kept and the policy is tightened one step at a time: none → quarantine → reject.
- **The MTA-STS policy lists your real MX hosts** and starts in `testing` mode.
- **Terms that match every sender are removed.**
- **Domains that send no mail** get `v=spf1 -all`, `p=reject` and a null MX (`MX 0 .`, RFC 7505).
- **Report domains that drop your DMARC reports** get the authorization record to add in their zone.

`--json` includes the same text under `fix`.

### Details that bite naive checkers

- **MTA-STS is fetched the way a sender fetches it.** That means HTTPS, no redirects (RFC 8461 §3.3) and `text/plain` only. Each MX is then matched against the policy's `mx:` patterns, where `*.example.com` covers exactly one label.
- **DKIM key size is read from the key itself.** mailguard parses the DER inside `p=`, both SubjectPublicKeyInfo and bare RSAPublicKey, and needs no crypto library.
- **DKIM wildcards don't fool it.** Some domains publish `*._domainkey`, which answers *every* selector. mailguard probes a random selector first; if that resolves, it reports DKIM as inconclusive instead of claiming a key at every selector. An empty `p=` counts as a revoked key, not a live one.
- **No DNS library, no dependency.** Lookups go over DNS-over-HTTPS: Google by default, or another endpoint with `--resolver`.

## Checked against the reference implementation

The [crosscheck workflow](.github/workflows/crosscheck.yml) runs [`scripts/crosscheck.py`](scripts/crosscheck.py) on demand. It evaluates the same TEST-NET sender with mailguard and with [pyspf](https://pypi.org/project/pyspf/), the long-standing reference SPF library, on the [Tranco](https://tranco-list.eu/) top 1,000 domains:

| | agreement |
|---|---|
| permerror or not (760 domains with SPF, 36 permerror) | **759 / 760** |
| exact DNS lookup count (the 724 without permerror) | **724 / 724** |

The one difference is a record that repeats an unknown `include=` modifier. pyspf rejects it; RFC 7208 §6 says unknown modifiers are ignored, so mailguard ignores it. The first run of this check found three bugs, all fixed in this release: macros weren't expanded, the walk didn't stop at an included `+all`, and two SPF records weren't a permerror inside the evaluator.

## Install

```bash
pip install git+https://github.com/njuj/mailguard
```

## Usage

```bash
mailguard example.com                      # one domain
mailguard example.com --fix                # plus the DNS records that fix what it found
mailguard example.com partner.com --json   # several, machine-readable
mailguard example.com --min-grade B        # exit 1 if worse than B
mailguard example.com --resolver https://cloudflare-dns.com/dns-query
```

**Exit codes:** `0` ok · `1` below `--min-grade` · `2` DNS or lookup error

### In CI, to stop your mail posture from regressing

```yaml
- run: pip install git+https://github.com/njuj/mailguard
- run: mailguard yourdomain.com --min-grade B
```

## Real domains

| Domain | Grade | What it surfaced |
|---|---|---|
| google.com | A | DMARC reject, MTA-STS enforce with every MX covered, but SPF ends in `~all` |
| amazon.com | A | 4 lookups, DMARC quarantine |
| cloudflare.com | B | `-all` and DMARC reject, but **the MTA-STS policy host doesn't resolve**; one 1024-bit DKIM key |
| unsplash.com | B | **`~include:` of a `+all` record: every sender gets softfail, `-all` is never reached** |
| github.com | C | **exactly 10/10 SPF lookups**, DMARC quarantine, two 1024-bit DKIM keys |
| zoom.us | F | **SPF permerror for every spoofer (void-lookup limit)**, `~all` |
| example.com | A | correctly reports DKIM as *not found* despite a wildcard revoked-key record; null MX respected |

## Layout

```
mailguard/
├── resolver.py   DNS-over-HTTPS, TXT reassembly, caching
├── spf.py        check_host() walk: macros, limits, syntax, permerror reason, lookup costs (the core)
├── checks.py     one function per check: Snapshot → Check; DKIM key parser, MTA-STS policy matcher
├── fix.py        --fix: zone-file records and the MTA-STS policy
├── grade.py      scoring and letter grades
├── scanner.py    gathers the DNS snapshot, fetches the MTA-STS policy, DKIM wildcard handling
├── model.py      Snapshot + SPFResult + Check (pure data)
└── cli.py        argparse, renderer, exit codes
scripts/crosscheck.py   compare SPF verdicts with pyspf (needs pyspf + dnspython)
tests/            46 offline tests; the resolver and policy fetch are stubbed, so no network in tests
```

```bash
python -m unittest discover -s tests -v
```

## Limitations

- SPF is evaluated for one sender, an unauthorized one. That is the case that matters for spoofing, but a per-IP macro service can give your real senders a different result.
- DKIM can only be *probed*, never enumerated: a domain using a custom selector reads as "not found", not "missing".
- It reads public DNS and the public MTA-STS policy only. It can't see whether your mail server actually honours what you publish.

## Ethics

mailguard makes ordinary public DNS queries and one HTTPS request for the MTA-STS policy, the same things any mail server reads when it sends to you. It sends no mail and touches no inbox.

---

<sub>built by <a href="https://github.com/njuj">kira</a> · sibling of <a href="https://github.com/njuj/headerguard">headerguard</a> · trust nothing, verify everything</sub>

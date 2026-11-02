# mailguard

**Grade any domain's protection against email spoofing — SPF, DKIM, DMARC and MTA-STS — from DNS alone.** One command, a letter grade, and the one check almost no online tool does: it follows your SPF record's includes and proves whether you've silently blown past the 10-lookup limit. Zero dependencies.

[![ci](https://github.com/njuj/mailguard/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/mailguard/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-00ff9c?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-00ff9c?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-00ff9c?labelColor=0b0f17)

```text
$ mailguard github.com

 mailguard v0.1.0  →  github.com

   GRADE   B    82/100

   ✔ SPF record       one SPF record present
   ⚠ SPF DNS lookups  uses 10 of 10 DNS lookups; one more include tips it into permerror  -8
   ⚠ SPF policy       ~all (softfail)  -5
   ✔ DMARC record     DMARC record present
   ⚠ DMARC policy     quarantine (spoofed mail goes to spam, not rejected)  -5
   ✔ DMARC reporting  aggregate reports (rua) configured
   ✔ DKIM             live key found at selector(s): google, selector1, s1, s2, k1, k2
   · MTA-STS          no MTA-STS record; inbound mail can be downgraded to cleartext
```

Real output against live DNS. GitHub is sitting at **exactly 10 of 10 SPF lookups** — one more `include:` and every receiver would silently stop honouring their SPF.

## The problem nobody watches: the SPF 10-lookup limit

An SPF record can reference others with `include:`, `redirect=`, `a`, `mx`, `ptr` and `exists`. Each of those costs a DNS lookup, and [RFC 7208 §4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4) caps a single SPF evaluation at **10**. One `include:` often expands to several more lookups inside it, so a record that looks tidy —

```
v=spf1 include:_spf.google.com include:servers.mcsv.net include:sendgrid.net include:_spf.atlassian.net -all
```

— can quietly cross 10 as those providers change their own records. When it does, the result is **permerror**, and most receivers treat permerror as *no SPF at all*. The record is still there, still looks correct, and does nothing. No error, no bounce, no warning.

Most online checkers just print your SPF record. mailguard **follows every include recursively and counts**, so it tells you the number that actually matters.

## What it grades

| Check | Pass | Penalty |
|---|---|---|
| **SPF record** | exactly one present | missing -30 · more than one (permerror) -20 |
| **SPF DNS lookups** | ≤ 7 of 10 | **over 10 (silent permerror) -25** · 8–10 (one away) -8 |
| **SPF policy** | `-all` (hardfail) | `~all` -5 · `?all` -12 · **`+all` -30** · no `all` -10 |
| **SPF void lookups** | ≤ 2 | more than 2 (permerror) -6 |
| **DMARC record** | present and valid | missing -25 · invalid -15 |
| **DMARC policy** | `p=reject` | `p=none` (monitoring only) -15 · `quarantine` -5 · `pct<100` -5 · `sp=none` -5 |
| **DMARC reporting** | `rua=` set | missing -3 |
| **DKIM** | live key at a common selector | informational (selectors can't be enumerated) |
| **MTA-STS** | published | informational |

`A+` is a clean sheet (no warnings) · `A` ≥ 90 · `B` ≥ 80 · `C` ≥ 70 · `D` ≥ 60 · `F` otherwise. A domain with neither a hardfail SPF nor DMARC enforcement is trivially spoofable and is capped at **F**.

### Details that bite naive checkers

- **The star check is recursive.** `include:` and `redirect=` are followed into the referenced records and their lookups count toward the same budget of 10, with loop and depth guards.
- **`p=none` is called what it is:** monitoring only. It is the single most common DMARC misconfiguration — reports come in, but nothing is ever blocked.
- **DKIM wildcards don't fool it.** Some domains publish `*._domainkey` (often with an empty, revoked `p=`), which answers *every* selector. mailguard probes a random selector first; if that resolves, it reports DKIM as inconclusive instead of claiming a key at 16 selectors. An empty `p=` is treated as a revoked key, not a live one.
- **No DNS library, no dependency.** Lookups go over DNS-over-HTTPS (Google by default, `--resolver` to change), the same spirit as a single HTTPS request.

## Install

```bash
pip install git+https://github.com/njuj/mailguard
```

## Usage

```bash
mailguard example.com                      # one domain
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

## Validated against real domains

| Domain | Grade | What it surfaced |
|---|---|---|
| cloudflare.com | A+ | 7/10 lookups, `-all`, DMARC reject, MTA-STS, live DKIM — a clean sheet |
| google.com | A | DMARC reject, but SPF ends in `~all` (softfail) |
| github.com | B | **exactly 10/10 SPF lookups** and DMARC quarantine |
| example.com | A | correctly reports DKIM as *not found* despite a wildcard revoked-key record |

## Layout

```
mailguard/
├── resolver.py   DNS-over-HTTPS, TXT reassembly, caching
├── spf.py        SPF parser + recursive 10-lookup counter (the core)
├── checks.py     one function per check: Snapshot → Check
├── grade.py      scoring and letter grades
├── scanner.py    gathers the DNS snapshot, DKIM wildcard handling
├── model.py      Snapshot + SPFResult + Check (pure data)
└── cli.py        argparse, renderer, exit codes
tests/            28 offline tests; the resolver is stubbed with an in-memory zone, so no network in tests
```

```bash
python -m unittest discover -s tests -v
```

## Limitations

- SPF lookup counting follows the standard interpretation (each `a`/`mx`/`ptr`/`exists`/`include`/`redirect` = 1). It does not model every provider's edge cases, but it matches what receivers enforce.
- DKIM can only be *probed*, never enumerated: a domain using a custom selector reads as "not found", not "missing".
- It reads public DNS only. It can't see whether your mail server actually honours what you publish.

## Ethics

mailguard makes ordinary public DNS queries about a domain's mail configuration — the same records any mail server reads on every message. It sends no mail and touches no inbox.

---

<sub>built by <a href="https://github.com/njuj">kira</a> · sibling of <a href="https://github.com/njuj/headerguard">headerguard</a> · trust nothing, verify everything</sub>

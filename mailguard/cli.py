"""Command-line entry point. Exit codes: 0 ok · 1 below --min-grade · 2 DNS/error."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict

from . import __version__
from . import fix as fixer
from .grade import GRADES, at_least, grade, score
from .model import FAIL, INFO, PASS, WARN
from .resolver import DEFAULT_ENDPOINT, Resolver
from .scanner import audit

STATUS_COLOR = {PASS: "32", WARN: "33", FAIL: "31", INFO: "2"}
GRADE_COLOR = {"A+": "1;32", "A": "1;32", "B": "1;36", "C": "1;33", "D": "1;31", "F": "1;31"}
UNICODE = {PASS: "✔", WARN: "⚠", FAIL: "✖", INFO: "·", "arrow": "→", "sep": "·"}
ASCII = {PASS: "+", WARN: "!", FAIL: "x", INFO: "-", "arrow": "->", "sep": "|"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="mailguard",
        description="Grade a domain's email anti-spoofing posture (SPF, DKIM, DMARC, MTA-STS) from DNS alone.")
    ap.add_argument("domains", nargs="+", help="domains to audit, e.g. example.com")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-grade", choices=GRADES, metavar="GRADE",
                    help=f"exit 1 if any domain grades below this ({', '.join(GRADES)})")
    ap.add_argument("--resolver", default=DEFAULT_ENDPOINT, metavar="URL",
                    help="DNS-over-HTTPS endpoint (default: Google)")
    ap.add_argument("--timeout", type=float, default=10, metavar="S", help="per-query timeout (default: 10)")
    ap.add_argument("--fix", action="store_true",
                    help="print the DNS records (zone-file syntax) and MTA-STS policy that fix what was found")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def report(domain: str, resolver: Resolver, fix: bool = False) -> dict:
    snap, checks = audit(domain, resolver)
    spf = snap.spf
    rep = {"domain": snap.domain, "grade": grade(checks), "score": score(checks),
           "spf": {"record": spf.record, "lookups": spf.lookups, "all": spf.all_qualifier,
                   "includes": spf.includes, "costs": spf.costs, "permerror": spf.permerror,
                   "void_lookups": spf.void_lookups, "ipv4_addresses": spf.ipv4_addresses} if spf else None,
           "dmarc": snap.dmarc, "dmarc_external": snap.dmarc_external, "mx": snap.mx,
           "mta_sts": {"record": snap.mta_sts, "policy": snap.mta_sts_policy, "error": snap.mta_sts_error}
           if snap.mta_sts else None,
           "tls_rpt": snap.tls_rpt, "errors": snap.errors, "checks": [asdict(c) for c in checks]}
    if fix:
        rep["fix"] = fixer.render(snap)
    return rep


def _glyphs(stream) -> dict:
    try:
        "".join(UNICODE.values()).encode(getattr(stream, "encoding", None) or "ascii")
        return UNICODE
    except (UnicodeEncodeError, LookupError):
        return ASCII


def render(rep: dict, color: bool, g: dict) -> str:
    def paint(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    letter = rep["grade"]
    badge = paint(f" {letter:<2} ", GRADE_COLOR[letter] + ";7")
    lines = [paint(f" mailguard v{__version__}", "1;36") + f"  {g['arrow']}  {rep['domain']}",
             "", f"   GRADE  {badge}  " + paint(f"{rep['score']}/100", "2"), ""]
    width = max(len(c["title"]) for c in rep["checks"])
    for c in rep["checks"]:
        penalty = paint(f"  -{c['penalty']}", STATUS_COLOR[c["status"]]) if c["penalty"] else ""
        body = paint(c["detail"], "2" if c["status"] in (PASS, INFO) else "0")
        lines.append(f"   {paint(g[c['status']], STATUS_COLOR[c['status']])} {c['title']:<{width}}  {body}{penalty}")
    if rep["errors"]:
        lines.append("")
        for e in rep["errors"]:
            lines.append("   " + paint(f"{g['info']} dns: {e}", "2"))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    resolver = Resolver(timeout=args.timeout, endpoint=args.resolver)
    reports, failed = [], False
    for domain in args.domains:
        try:
            reports.append(report(domain, resolver, args.fix))
        except Exception as e:  # noqa: BLE001 — one bad domain should not sink the batch
            print(f"mailguard: {domain}: {e}", file=sys.stderr)
            failed = True

    if args.json:
        print(json.dumps({"version": __version__, "reports": reports}, indent=2))
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="replace")
        color = not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        glyphs = _glyphs(sys.stdout)
        for rep in reports:
            print(render(rep, color, glyphs))
            if "fix" in rep:
                print(rep["fix"])

    if failed:
        return 2
    if args.min_grade and any(not at_least(r["grade"], args.min_grade) for r in reports):
        return 1
    return 0

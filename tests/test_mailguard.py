import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from mailguard import cli
from mailguard.checks import parse_dmarc, run_checks
from mailguard.grade import at_least, grade, score
from mailguard.model import FAIL, INFO, PASS, WARN, Snapshot
from mailguard.resolver import unquote_txt
from mailguard.scanner import audit, gather
from mailguard.spf import evaluate_spf, find_spf


class FakeResolver:
    """Answers from an in-memory zone: {(name, type): [records]}. Missing names behave like NXDOMAIN."""

    def __init__(self, zone, fail=()):
        self.zone = {(n.rstrip(".").lower(), t): v for (n, t), v in zone.items()}
        self.fail = set(fail)
        self.calls = []

    def query(self, name, rrtype):
        key = (name.rstrip(".").lower(), rrtype)
        self.calls.append(key)
        from mailguard.resolver import DNSError
        if key[0] in self.fail:
            raise DNSError(f"{name}: simulated failure")
        return list(self.zone.get(key, []))


def txt(domain, *records):
    return {(domain, "TXT"): list(records)}


def by_id(checks):
    return {c.id: c for c in checks}


class ResolverParsingTest(unittest.TestCase):
    def test_unquote_joins_split_txt(self):
        self.assertEqual(unquote_txt('"v=spf1 a" " include:x -all"'), "v=spf1 a include:x -all")
        self.assertEqual(unquote_txt('"simple"'), "simple")
        self.assertEqual(unquote_txt("already bare"), "already bare")

    def test_find_spf(self):
        self.assertEqual(find_spf(["v=spf1 -all", "google-site-verification=x"]), ["v=spf1 -all"])
        self.assertEqual(find_spf(["V=SPF1 ~all"]), ["V=SPF1 ~all"])


class SPFLookupCountTest(unittest.TestCase):
    def test_counts_recursively_and_catches_over_limit(self):
        zone = {
            **txt("example.com", "v=spf1 a include:_spf.google.com include:servers.example.net ~all"),
            **txt("_spf.google.com", "v=spf1 include:_n1 include:_n2 include:_n3 ~all"),
            **txt("_n1", "v=spf1 ip4:1.0.0.0/8 ~all"),
            **txt("_n2", "v=spf1 ip4:2.0.0.0/8 ~all"),
            **txt("_n3", "v=spf1 ip4:3.0.0.0/8 ~all"),
            **txt("servers.example.net", "v=spf1 a mx include:deep.example.net -all"),
            **txt("deep.example.net", "v=spf1 a a:x.example.net mx ptr exists:%{i}._spf.example.net -all"),
        }
        r = FakeResolver(zone)
        spf = evaluate_spf("example.com", zone[("example.com", "TXT")], r)
        self.assertEqual(spf.lookups, 14)       # 3 root + 3 google + (3+5) servers subtree
        self.assertEqual(spf.all_qualifier, "~")
        self.assertIn("_spf.google.com", spf.includes)

    def test_simple_record_under_limit(self):
        zone = txt("ok.com", "v=spf1 ip4:1.2.3.4 ip6:::1 a mx -all")
        spf = evaluate_spf("ok.com", zone[("ok.com", "TXT")], FakeResolver(zone))
        self.assertEqual((spf.lookups, spf.all_qualifier), (2, "-"))   # a + mx; ip4/ip6 are free

    def test_include_loop_is_caught(self):
        zone = {**txt("a.com", "v=spf1 include:b.com -all"), **txt("b.com", "v=spf1 include:a.com -all")}
        spf = evaluate_spf("a.com", zone[("a.com", "TXT")], FakeResolver(zone))
        self.assertTrue(any("loop" in e for e in spf.syntax_errors))

    def test_redirect_is_counted_and_followed(self):
        zone = {**txt("a.com", "v=spf1 redirect=_spf.a.com"), **txt("_spf.a.com", "v=spf1 a mx -all")}
        spf = evaluate_spf("a.com", zone[("a.com", "TXT")], FakeResolver(zone))
        self.assertEqual(spf.lookups, 3)        # redirect + a + mx
        self.assertEqual(spf.all_qualifier, "-")

    def test_void_lookups(self):
        zone = {**txt("a.com", "v=spf1 include:missing1 include:missing2 include:missing3 -all")}
        spf = evaluate_spf("a.com", zone[("a.com", "TXT")], FakeResolver(zone))
        self.assertEqual(spf.void_lookups, 3)


class ChecksTest(unittest.TestCase):
    def snap(self, **kw):
        return Snapshot(domain="example.com", **kw)

    def checks(self, **kw):
        return by_id(run_checks(self.snap(**kw)))

    def test_no_spf(self):
        c = self.checks()["spf"]
        self.assertEqual((c.status, c.penalty), (FAIL, 30))

    def test_multiple_spf_is_invalid(self):
        c = self.checks(spf_records=["v=spf1 -all", "v=spf1 ~all"])["spf"]
        self.assertEqual(c.status, FAIL)
        self.assertIn("permerror", c.detail)

    def test_over_limit_lookups_flagged(self):
        from mailguard.model import SPFResult
        spf = SPFResult("v=spf1 ...", "-", 13, includes=["_spf.big.com"])
        c = self.checks(spf_records=["v=spf1 ..."], spf=spf)["spf-lookups"]
        self.assertEqual((c.status, c.penalty), (FAIL, 25))
        self.assertIn("permerror", c.detail)

    def test_all_qualifiers(self):
        from mailguard.model import SPFResult
        cases = {"-": (PASS, 0), "~": (WARN, 5), "?": (WARN, 12), "+": (FAIL, 30), None: (WARN, 10)}
        for q, (status, penalty) in cases.items():
            c = self.checks(spf_records=["v=spf1"], spf=SPFResult("v=spf1", q, 1))["spf-policy"]
            self.assertEqual((c.status, c.penalty), (status, penalty), q)

    def test_dmarc_parse(self):
        tags = parse_dmarc("v=DMARC1; p=reject; rua=mailto:r@x.com; pct=100")
        self.assertEqual(tags, {"v": "DMARC1", "p": "reject", "rua": "mailto:r@x.com", "pct": "100"})

    def test_dmarc_policies(self):
        self.assertEqual(self.checks(dmarc_records=["v=DMARC1; p=none"])["dmarc-policy"].status, FAIL)
        strong = self.checks(dmarc_records=["v=DMARC1; p=reject; rua=mailto:r@x.com"])
        self.assertEqual(strong["dmarc-policy"].status, PASS)
        self.assertEqual(strong["dmarc-rua"].status, PASS)
        pct = self.checks(dmarc_records=["v=DMARC1; p=quarantine; pct=50; rua=mailto:r@x.com"])["dmarc-policy"]
        self.assertEqual(pct.status, WARN)
        self.assertIn("50%", pct.detail)

    def test_dmarc_missing_rua(self):
        self.assertEqual(self.checks(dmarc_records=["v=DMARC1; p=reject"])["dmarc-rua"].status, WARN)

    def test_dkim_found_vs_guessed(self):
        self.assertEqual(self.checks(dkim_selectors={"google": True, "s1": False})["dkim"].status, PASS)
        self.assertEqual(self.checks(dkim_selectors={"google": False})["dkim"].status, INFO)

    def test_dkim_wildcard_is_inconclusive(self):
        c = self.checks(dkim_wildcard=True, dkim_selectors={})["dkim"]
        self.assertEqual(c.status, INFO)
        self.assertIn("wildcard", c.detail)

    def test_mta_sts(self):
        self.assertEqual(self.checks(mta_sts="v=STSv1; id=20260101")["mta-sts"].status, PASS)
        self.assertEqual(self.checks()["mta-sts"].status, INFO)


class GradeTest(unittest.TestCase):
    def from_zone(self, zone):
        return audit("example.com", FakeResolver(zone))[1]

    def test_hardened_domain_is_a_plus(self):
        zone = {
            **txt("example.com", "v=spf1 include:_spf.example.com -all"),
            **txt("_spf.example.com", "v=spf1 ip4:1.2.3.4 -all"),
            **txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s"),
            **txt("_mta-sts.example.com", "v=STSv1; id=20260101T000000Z"),
            **txt("google._domainkey.example.com", "v=DKIM1; k=rsa; p=MIGfMA0..."),
        }
        checks = self.from_zone(zone)
        self.assertEqual((grade(checks), score(checks)), ("A+", 100))

    def test_wide_open_domain_is_f(self):
        self.assertEqual(grade(self.from_zone({})), "F")

    def test_spf_softfail_without_dmarc_is_f(self):
        zone = txt("example.com", "v=spf1 include:_spf.example.com ~all")
        zone.update(txt("_spf.example.com", "v=spf1 ip4:1.2.3.4 ~all"))
        self.assertEqual(grade(self.from_zone(zone)), "F")

    def test_dmarc_reject_rescues_softfail_spf(self):
        zone = {
            **txt("example.com", "v=spf1 ip4:1.2.3.4 ~all"),
            **txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"),
            **txt("google._domainkey.example.com", "v=DKIM1; p=abc"),
        }
        self.assertIn(grade(self.from_zone(zone)), ("A", "B"))

    def test_over_limit_spf_drops_the_grade(self):
        includes = " ".join(f"include:s{i}.example.net" for i in range(12))
        zone = {**txt("example.com", f"v=spf1 {includes} -all"),
                **txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com")}
        for i in range(12):
            zone.update(txt(f"s{i}.example.net", "v=spf1 ip4:1.2.3.4 -all"))
        checks = by_id(self.from_zone(zone))
        self.assertEqual(checks["spf-lookups"].status, FAIL)

    def test_grade_order(self):
        self.assertTrue(at_least("A+", "B"))
        self.assertFalse(at_least("D", "B"))


class ScannerTest(unittest.TestCase):
    def test_gather_queries_the_right_names(self):
        zone = {
            **txt("example.com", "v=spf1 -all"),
            **txt("_dmarc.example.com", "v=DMARC1; p=reject"),
            ("example.com", "MX"): ["mx.example.com"],
            **txt("google._domainkey.example.com", "v=DKIM1; p=realkeymaterial"),
        }
        r = FakeResolver(zone)
        snap = gather("Example.com.", r)
        self.assertEqual(snap.domain, "example.com")
        self.assertEqual(snap.spf_records, ["v=spf1 -all"])
        self.assertEqual(snap.dmarc, "v=DMARC1; p=reject")
        self.assertEqual(snap.mx, ["mx.example.com"])
        self.assertIn(("_dmarc.example.com", "TXT"), r.calls)
        self.assertFalse(snap.dkim_wildcard)
        self.assertTrue(snap.dkim_selectors["google"])

    def test_dkim_wildcard_and_revoked_key(self):
        from mailguard.scanner import _is_live_dkim
        self.assertTrue(_is_live_dkim("v=DKIM1; k=rsa; p=MIGfMA0realkey"))
        self.assertFalse(_is_live_dkim("v=DKIM1; p="))        # revoked: empty public key
        self.assertFalse(_is_live_dkim("v=spf1 -all"))        # not a DKIM record at all
        # a wildcard answers the random probe, so every selector is discarded as inconclusive
        wildcard_zone = {(f"{sel}._domainkey.wild.com", "TXT"): ["v=DKIM1; p="]
                         for sel in ("mg-wildcard-probe-9z7q", "google", "s1")}
        snap = gather("wild.com", FakeResolver(wildcard_zone))
        self.assertFalse(snap.dkim_wildcard)  # empty p= is not a live key, so not seen as a wildcard
        live_wildcard = {(f"{sel}._domainkey.wild2.com", "TXT"): ["v=DKIM1; p=realkey"]
                         for sel in ("mg-wildcard-probe-9z7q", "google")}
        snap2 = gather("wild2.com", FakeResolver(live_wildcard))
        self.assertTrue(snap2.dkim_wildcard)
        self.assertEqual(snap2.dkim_selectors, {})

    def test_dns_failure_is_recorded_not_raised(self):
        snap = gather("example.com", FakeResolver(txt("example.com", "v=spf1 -all"), fail={"example.com"}))
        self.assertTrue(snap.errors)


class CLITest(unittest.TestCase):
    def run_cli(self, *argv, zone=None):
        out, err = io.StringIO(), io.StringIO()
        resolver = FakeResolver(zone or {})
        with mock.patch("mailguard.cli.Resolver", return_value=resolver), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def test_json_and_grade_gate(self):
        zone = {**txt("open.com"), }
        code, out, _ = self.run_cli("open.com", "--json", zone=zone)
        self.assertEqual((code, json.loads(out)["reports"][0]["grade"]), (0, "F"))
        self.assertEqual(self.run_cli("open.com", "--min-grade", "C", zone=zone)[0], 1)

    def test_text_output(self):
        zone = {**txt("example.com", "v=spf1 -all"),
                **txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com")}
        code, out, _ = self.run_cli("example.com", "--no-color", zone=zone)
        self.assertIn("GRADE", out)
        self.assertIn("SPF record", out)


if __name__ == "__main__":
    unittest.main()

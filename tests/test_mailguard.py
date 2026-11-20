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


def rsa_key(bits, spki=True):
    """A DKIM p= value holding an RSA public key of exactly `bits` bits (DER built by hand, no crypto lib)."""
    import base64

    def der(tag, body):
        n = len(body)
        size = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([tag]) + size + body

    modulus = (1 << (bits - 1)) | 1
    rsa = der(0x30, der(0x02, b"\x00" + modulus.to_bytes(bits // 8, "big")) + der(0x02, b"\x01\x00\x01"))
    if spki:
        algo = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
        rsa = der(0x30, algo + der(0x03, b"\x00" + rsa))
    return base64.b64encode(rsa).decode()


def policy(text):
    return lambda domain: (text, None)


STS = "version: STSv1\nmode: enforce\nmx: *.mail.example.com\nmax_age: 604800\n"


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
            **txt("_spf.google.com", "v=spf1 include:_n1.google.com include:_n2.google.com include:_n3.google.com ~all"),
            **txt("_n1.google.com", "v=spf1 ip4:1.0.0.0/8 ~all"),
            **txt("_n2.google.com", "v=spf1 ip4:2.0.0.0/8 ~all"),
            **txt("_n3.google.com", "v=spf1 ip4:3.0.0.0/8 ~all"),
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
        zone = {**txt("a.com", "v=spf1 include:missing1.example.net include:missing2.example.net include:missing3.example.net -all")}
        spf = evaluate_spf("a.com", zone[("a.com", "TXT")], FakeResolver(zone))
        self.assertEqual(spf.void_lookups, 3)
        # an include of a domain without SPF is already a permerror on its own (RFC 7208 §5.2)
        self.assertIn("missing1.example.net has no SPF record", spf.permerror)


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
        base = dict(mta_sts="v=STSv1; id=20260101", mx=["a.mail.example.com"])
        self.assertEqual(self.checks(**base, mta_sts_policy=STS)["mta-sts"].status, PASS)
        self.assertEqual(self.checks()["mta-sts"].status, INFO)
        # TXT without a reachable policy file: senders ignore MTA-STS
        c = self.checks(**base, mta_sts_error="answers HTTP 404")["mta-sts"]
        self.assertEqual((c.status, c.penalty), (FAIL, 8))
        # enforce with an MX the policy doesn't cover breaks delivery; "*." matches exactly one label
        c = self.checks(**dict(base, mx=["a.b.mail.example.com"]), mta_sts_policy=STS)["mta-sts"]
        self.assertEqual((c.status, c.penalty), (FAIL, 15))
        self.assertIn("a.b.mail.example.com", c.detail)
        testing = STS.replace("enforce", "testing")
        self.assertEqual(self.checks(**base, mta_sts_policy=testing)["mta-sts"].status, WARN)
        self.assertEqual(self.checks(**base, mta_sts_policy="version: STSv1\nmode: enforce\n")["mta-sts"].status, FAIL)
        short = self.checks(**base, mta_sts_policy=STS.replace("604800", "3600"))["mta-sts"]
        self.assertEqual(short.status, WARN)
        self.assertIn("max_age", short.detail)
        self.assertEqual(self.checks(**base, mta_sts_policy=STS.replace("enforce", "none"))["mta-sts"].status, INFO)

    def test_tls_rpt(self):
        self.assertEqual(self.checks(tls_rpt=["v=TLSRPTv1; rua=mailto:t@x.com"])["tls-rpt"].status, PASS)
        self.assertEqual(self.checks(mta_sts="v=STSv1; id=1")["tls-rpt"].status, INFO)
        self.assertNotIn("tls-rpt", self.checks())

    def test_dkim_key_size(self):
        from mailguard.checks import dkim_key_bits
        self.assertEqual(dkim_key_bits(f"v=DKIM1; k=rsa; p={rsa_key(2048)}"), 2048)
        self.assertEqual(dkim_key_bits(f"v=DKIM1; p={rsa_key(1024, spki=False)}"), 1024)
        self.assertEqual(dkim_key_bits("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="), "ed25519")
        self.assertIsNone(dkim_key_bits("v=DKIM1; p=not base64!"))
        keys = lambda bits: dict(dkim_selectors={"s1": True}, dkim_keys={"s1": f"v=DKIM1; p={rsa_key(bits)}"})
        self.assertEqual(self.checks(**keys(2048))["dkim"].status, PASS)
        self.assertEqual((self.checks(**keys(1024))["dkim"].status, self.checks(**keys(1024))["dkim"].penalty), (WARN, 3))
        self.assertEqual((self.checks(**keys(512))["dkim"].status, self.checks(**keys(512))["dkim"].penalty), (FAIL, 10))

    def test_dmarc_validation(self):
        c = self.checks(dmarc_records=["v=DMARC1; p=block"])
        self.assertEqual((c["dmarc"].status, c["dmarc-policy"].status), (FAIL, INFO))
        self.assertEqual(self.checks(dmarc_records=["v=DMARC1; rua=mailto:a@x.com"])["dmarc"].status, FAIL)
        self.assertEqual(self.checks(dmarc_records=["v=DMARC1; p=reject; rua=https://x.com/r"])["dmarc-rua"].status, WARN)
        rec = ["v=DMARC1; p=reject; rua=mailto:d@reports.example.net"]
        dropped = self.checks(dmarc_records=rec, dmarc_external={"reports.example.net": False})["dmarc-rua"]
        self.assertEqual(dropped.status, WARN)
        self.assertIn("example.com._report._dmarc.reports.example.net", dropped.detail)
        ok = self.checks(dmarc_records=rec, dmarc_external={"reports.example.net": True})["dmarc-rua"]
        self.assertEqual(ok.status, PASS)

    def test_report_domains(self):
        from mailguard.checks import report_domains
        tags = parse_dmarc("v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@x.vendor.net!10m; "
                           "ruf=mailto:c@mail.example.com,mailto:d@vendor.org")
        self.assertEqual(report_domains("example.com", tags), ["x.vendor.net", "vendor.org"])
        # a subdomain reporting to its parent is the same owner
        self.assertEqual(report_domains("eu.example.com", {"rua": "mailto:r@example.com"}), [])

    def test_spf_eval(self):
        from mailguard.model import SPFResult
        broken = SPFResult("v=spf1 include:gone.example -all", "-", 1, permerror="include:gone.example has no SPF record")
        c = self.checks(spf_records=[broken.record], spf=broken)["spf-eval"]
        self.assertEqual((c.status, c.penalty), (FAIL, 25))
        self.assertIn("gone.example", c.detail)
        huge = SPFResult("v=spf1 ip4:0.0.0.0/1 -all", "-", 0, ipv4_addresses=1 << 31)
        self.assertEqual(self.checks(spf_records=[huge.record], spf=huge)["spf-eval"].status, WARN)
        ptr = SPFResult("v=spf1 ptr -all", "-", 1, uses_ptr=True)
        self.assertEqual(self.checks(spf_records=[ptr.record], spf=ptr)["spf-eval"].status, WARN)


class GradeTest(unittest.TestCase):
    def from_zone(self, zone, sts=STS):
        return audit("example.com", FakeResolver(zone), fetch=policy(sts))[1]

    def test_hardened_domain_is_a_plus(self):
        zone = {
            **txt("example.com", "v=spf1 include:_spf.example.com -all"),
            **txt("_spf.example.com", "v=spf1 ip4:1.2.3.4 -all"),
            **txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s"),
            **txt("_mta-sts.example.com", "v=STSv1; id=20260101T000000Z"),
            **txt("google._domainkey.example.com", f"v=DKIM1; k=rsa; p={rsa_key(2048)}"),
            **txt("_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:tls@example.com"),
            ("example.com", "MX"): ["a.mail.example.com"],
        }
        checks = self.from_zone(zone)
        self.assertEqual((grade(checks), score(checks)), ("A+", 100))
        # the same domain with an enforce policy that doesn't list its MX loses the A+
        self.assertNotEqual(grade(self.from_zone(zone, STS.replace("*.mail", "*.other"))), "A+")

    def test_spf_permerror_counts_as_no_spf(self):
        # -all looks strict, but the include has no SPF record, so receivers see permerror: no SPF at all
        zone = {**txt("example.com", "v=spf1 include:gone.example.net -all")}
        self.assertEqual(grade(self.from_zone(zone)), "F")

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


class SPFSyntaxTest(unittest.TestCase):
    def permerror(self, record, extra=None):
        return evaluate_spf("example.com", [record], FakeResolver({**txt("example.com", record), **(extra or {})})).permerror

    def test_syntax_errors(self):
        self.assertIsNone(self.permerror("v=spf1 ip4:198.51.100.0/24 -all"))
        self.assertIn("unknown term", self.permerror("v=spf1 ip:198.51.100.1 -all"))
        self.assertIn("invalid", self.permerror("v=spf1 ip4:198.51.100.300 -all"))
        self.assertIn("invalid", self.permerror("v=spf1 ip4:2001:db8::1 -all"))
        self.assertIn("invalid", self.permerror("v=spf1 a/33 -all"))
        self.assertIn("takes no argument", self.permerror("v=spf1 all:x -all"))
        self.assertIn("needs a valid domain", self.permerror("v=spf1 include:localhost -all"))
        self.assertIn("twice", self.permerror("v=spf1 redirect=a.example.net redirect=b.example.net"))
        self.assertIn("malformed macro", self.permerror("v=spf1 exists:%{x}.example.net -all"))

    def test_macros_are_expanded_for_the_test_sender(self):
        from mailguard.spf import expand
        self.assertEqual(expand("%{ir}.%{v}.%{d}.spf.has.pphosted.com", "ex.com"),
                         "1.2.0.192.in-addr.ex.com.spf.has.pphosted.com")
        self.assertEqual(expand("%{l}.%{o}.%{d2}.%{s}", "a.b.ex.com"), "postmaster.a.b.ex.com.ex.com.postmaster@a.b.ex.com")
        self.assertEqual(expand("%{h}%%%_%-", "ex.com"), "ex.com% %20")
        # a per-IP include that has no record for an unknown sender is a permerror for every spoofer
        self.assertIn("1.2.0.192.ex.net has no SPF record", self.permerror("v=spf1 include:%{ir}.ex.net -all"))
        ok = {**txt("192.0.2.1._ip.ex.net", "v=spf1 -all")}
        self.assertIsNone(self.permerror("v=spf1 include:%{i}._ip.ex.net -all", ok))

    def test_stops_at_an_included_pass_all(self):
        zone = {**txt("open.example.net", "v=spf1 +all"), **txt("later.example.net", "v=spf1 -all")}
        r = evaluate_spf("example.com", ["v=spf1 ~include:open.example.net include:later.example.net -all"],
                         FakeResolver(zone))
        self.assertEqual((r.all_qualifier, r.lookups), ("~", 1))      # later.example.net is never reached
        self.assertIn("open.example.net", r.matched)
        r = evaluate_spf("example.com", ["v=spf1 include:open.example.net -all"], FakeResolver(zone))
        self.assertEqual(r.all_qualifier, "+")

    def test_mx_limit_and_void(self):
        mx = {("example.com", "MX"): [f"mx{i}.example.com" for i in range(11)]}
        self.assertIn("11 MX hosts", self.permerror("v=spf1 mx -all", mx))
        # three a:/exists: terms that resolve to nothing pass the void limit of 2
        self.assertIn("void", self.permerror("v=spf1 a:x1.example.net a:x2.example.net exists:x3.example.net -all"))

    def test_redirect_only_without_all(self):
        zone = txt("_spf.example.net", "v=spf1 ip4:198.51.100.0/24 -all")
        r = evaluate_spf("example.com", ["v=spf1 redirect=_spf.example.net"], FakeResolver(zone))
        self.assertEqual((r.all_qualifier, r.lookups, r.ipv4_addresses), ("-", 1, 256))
        r = evaluate_spf("example.com", ["v=spf1 ~all redirect=_spf.example.net"], FakeResolver(zone))
        self.assertEqual((r.all_qualifier, r.lookups), ("~", 0))

    def test_costs_and_address_space(self):
        zone = {**txt("big.example.net", "v=spf1 include:a.example.net include:b.example.net -all"),
                **txt("a.example.net", "v=spf1 ip4:10.0.0.0/8 -all"),
                **txt("b.example.net", "v=spf1 ip4:10.1.0.0/16 ip4:198.51.100.1 -all")}
        r = evaluate_spf("example.com", ["v=spf1 include:big.example.net -all"], FakeResolver(zone))
        self.assertEqual(r.costs, {"big.example.net": 3})
        self.assertIsNone(r.matched)
        self.assertEqual(r.ipv4_addresses, (1 << 24) + 1)   # overlapping ranges counted once


class FixTest(unittest.TestCase):
    def fix(self, zone, sts=None):
        from mailguard.fix import render
        snap = gather("example.com", FakeResolver(zone), fetch=policy(sts))
        return render(snap, today="20260101")

    def test_open_domain_gets_staged_records(self):
        out = self.fix({("example.com", "MX"): ["mx1.mail.example.com", "mx2.mail.example.com"]})
        self.assertIn('@                        IN TXT "v=spf1 mx -all"', out)
        self.assertIn('_dmarc                   IN TXT "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"', out)
        self.assertIn('_mta-sts                 IN TXT "v=STSv1; id=20260101"', out)
        self.assertIn("; mx: mx2.mail.example.com", out)
        self.assertIn("_smtp._tls", out)

    def test_no_mail_domain_gets_null_mx(self):
        out = self.fix({})
        self.assertIn('"v=spf1 -all"', out)
        self.assertIn("p=reject", out)
        self.assertIn("IN MX 0 .", out)
        self.assertNotIn("_mta-sts", out)

    def test_tightens_existing_records(self):
        zone = {**txt("example.com", "v=spf1 include:_spf.example.net ~all"),
                **txt("_spf.example.net", "v=spf1 ip4:198.51.100.0/24 -all"),
                **txt("_dmarc.example.com", "v=DMARC1; p=quarantine; rua=mailto:d@reports.example.net; adkim=s"),
                ("example.com", "MX"): ["a.mail.example.com"]}
        out = self.fix(zone)
        self.assertIn('"v=spf1 include:_spf.example.net -all"', out)
        self.assertIn('"v=DMARC1; p=reject; rua=mailto:d@reports.example.net; adkim=s"', out)
        self.assertIn('example.com._report._dmarc.reports.example.net. IN TXT "v=DMARC1"', out)

    def test_clean_domain_needs_nothing(self):
        zone = {**txt("example.com", "v=spf1 mx -all"),
                **txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com"),
                **txt("_mta-sts.example.com", "v=STSv1; id=1"),
                **txt("_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:t@example.com"),
                ("example.com", "MX"): ["a.mail.example.com"],
                ("a.mail.example.com", "A"): ["198.51.100.1"]}
        self.assertEqual(self.fix(zone, STS), "; example.com: nothing to change\n")


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

    def test_fix_flag(self):
        code, out, _ = self.run_cli("open.com", "--json", "--fix")
        self.assertIn("IN MX 0 .", json.loads(out)["reports"][0]["fix"])

    def test_text_output(self):
        zone = {**txt("example.com", "v=spf1 -all"),
                **txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:d@example.com")}
        code, out, _ = self.run_cli("example.com", "--no-color", zone=zone)
        self.assertIn("GRADE", out)
        self.assertIn("SPF record", out)


if __name__ == "__main__":
    unittest.main()

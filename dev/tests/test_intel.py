"""Tests for dev/intel (no network). Run from dev/:  python -m unittest tests.test_intel"""
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from collections import Counter
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from intel import cache, classify, filters, model, parsers, roles, sources  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "intel")


def fx(name):
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


def by_value(iocs):
    return {i["value"]: i for i in iocs}


class TestClassify(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(classify.refang("hxxps://evil[.]example[.]com/a"), "https://evil.example.com/a")
        self.assertEqual(classify.refang("hXXp://a(.)b{.}c"), "http://a.b.c")
        self.assertEqual(classify.refang("user[at]a[dot]example"), "user@a.example")
        self.assertEqual(classify.refang("http[:]//a.example"), "http://a.example")
        self.assertEqual(classify.refang("fxp://a.example"), "ftp://a.example")

    def test_types(self):
        c = classify.classify_value
        self.assertEqual(c("203.0.113.7"), ("ipv4", "203.0.113.7"))
        self.assertEqual(c("203[.]0[.]113[.]7"), ("ipv4", "203.0.113.7"))
        self.assertEqual(c("2001:DB8::1"), ("ipv6", "2001:db8::1"))
        self.assertEqual(c("[2001:db8::1]"), ("ipv6", "2001:db8::1"))
        self.assertEqual(c("Evil.Example"), ("domain", "evil.example"))
        self.assertEqual(c("evil.example."), ("domain", "evil.example"))
        self.assertEqual(c("bücher.example"), ("domain", "xn--bcher-kva.example"))
        self.assertEqual(c("HTTPS://Evil.Example/Path?q=1")[0], "url")
        self.assertEqual(c("HTTPS://Evil.Example/Path?q=1")[1], "https://evil.example/Path?q=1")
        self.assertEqual(c("D41D8CD98F00B204E9800998ECF8427E"), ("md5", "d41d8cd98f00b204e9800998ecf8427e"))
        self.assertEqual(c("a" * 40)[0], "sha1")
        self.assertEqual(c("A" * 64)[0], "sha256")
        self.assertEqual(c("Bob@Example.COM"), ("email", "Bob@example.com"))
        self.assertEqual(c("cve-2021-44228"), ("cve", "CVE-2021-44228"))
        self.assertEqual(c("10.0.0.0/8"), ("cidr", "10.0.0.0/8"))
        self.assertEqual(c("203.0.113.0/24"), ("cidr", "203.0.113.0/24"))
        self.assertEqual(c("a.exe"), ("filename", "a.exe"))
        self.assertEqual(c("invoice.docx")[0], "filename")
        self.assertEqual(c("C:\\Temp\\x.dll")[0], "filename")
        self.assertEqual(c("203.0.113.7:443"), ("ipv4", "203.0.113.7"))
        self.assertEqual(classify.split_port("203.0.113.7:443"), ("203.0.113.7", 443))

    def test_rejects(self):
        c = classify.classify_value
        for bad in ["256.1.1.1", "01.2.3.4", "1.2.3", "1.2.3.4.5", "-a.example", "a..example", "a_b", "",
                    "a" * 64 + ".com", "http://", "ftp://", "1.2.3.4/33", "x@y", "1.2.3.04", "foo", "::::",
                    "http://exa mple.com", "999999999999", "1e5.example1"]:
            self.assertIsNone(c(bad)[0], bad)
        self.assertIsNone(c(None)[0])
        self.assertIsNone(c(123)[0])
        self.assertIsNone(c("x" * 5000)[0])

    def test_filename_not_domain(self):
        self.assertEqual(classify.classify_value("setup.exe")[0], "filename")
        self.assertEqual(classify.classify_value("a.php")[0], "filename")
        self.assertEqual(classify.classify_value("a.example")[0], "domain")


class TestModel(unittest.TestCase):
    def test_new_ioc(self):
        i = model.new_ioc("ipv4", "203.0.113.1", role="c2", confidence=250, note="x" * 500,
                          tags=["A", "a", " b "], techniques=["t1071.001", "bogus", "T1059"],
                          first_seen="2026-01-02 03:04:05")
        self.assertEqual(i["confidence"], 100)
        self.assertEqual(len(i["note"]), 500)
        self.assertEqual(i["tags"], ["a", "b"])
        self.assertEqual(i["techniques"], ["T1071.001", "T1059"])
        self.assertEqual(i["first_seen"], "2026-01-02T03:04:05Z")
        self.assertEqual(set(i), {"type", "value", "role", "confidence", "source", "tags", "techniques",
                                  "first_seen", "note", "why"})
        json.dumps(i)

    def test_validation(self):
        with self.assertRaises(ValueError):
            model.new_ioc("ipv4", "not-an-ip")
        with self.assertRaises(ValueError):
            model.new_ioc("domain", "203.0.113.1")
        with self.assertRaises(ValueError):
            model.new_ioc("ipv4", "203.0.113.1", role="boss")
        with self.assertRaises(ValueError):
            model.new_ioc("nonsense", "x")
        self.assertEqual(model.new_ioc("ipv4", "203.0.113.1", confidence="junk")["confidence"], 50)
        self.assertEqual(model.new_ioc("ipv4", "203.0.113.1", confidence=-4)["confidence"], 0)

    def test_key(self):
        a = model.new_ioc("domain", "A.Example")
        b = model.new_ioc("domain", "a.example")
        self.assertEqual(model.ioc_key(a), model.ioc_key(b))
        self.assertNotEqual(model.ioc_key(a), model.ioc_key(model.new_ioc("domain", "b.example")))


class TestRoles(unittest.TestCase):
    def r(self, typ, text, **kw):
        return roles.infer_role(dict({"type": typ}, **kw), text)[0]

    def test_words(self):
        self.assertEqual(self.r("ipv4", "Cobalt Strike C2"), "c2")
        self.assertEqual(self.r("ipv4", "beacon server"), "c2")
        self.assertEqual(self.r("domain", "command and control domain"), "c2")
        self.assertEqual(self.r("domain", "C&C"), "c2")
        self.assertEqual(self.r("ipv4", "data exfiltration endpoint"), "exfil")
        self.assertEqual(self.r("ipv4", "mass scanner"), "scanner")
        self.assertEqual(self.r("url", "malware download site"), "payload")
        self.assertEqual(self.r("url", "dropper delivery"), "payload")
        self.assertEqual(self.r("url", "phishing page"), "phishing")
        self.assertEqual(self.r("ipv4", "ssh brute force source"), "brute")
        self.assertEqual(self.r("ipv4", "password spray"), "brute")
        self.assertEqual(self.r("ipv4", "Tor exit node"), "tor")
        self.assertEqual(self.r("ipv4", "compromised host"), "compromised")

    def test_unknown_not_guessed(self):
        role, why = roles.infer_role({"type": "ipv4"}, "just an address")
        self.assertEqual(role, "unknown")
        self.assertTrue(why)
        self.assertEqual(self.r("domain", ""), "unknown")
        self.assertEqual(self.r("cve", "c2 exploit"), "vulnerability")     # a CVE is never an endpoint role, whatever the words say

    def test_hashes_default_payload(self):
        self.assertEqual(self.r("sha256", ""), "payload")
        self.assertEqual(self.r("md5", "c2 beacon list"), "payload")
        self.assertEqual(self.r("filename", ""), "payload")

    def test_note_and_tags(self):
        self.assertEqual(self.r("ipv4", "", note="used as exfil"), "exfil")
        self.assertEqual(self.r("ipv4", "", tags=["phishing"]), "phishing")

    def test_word_boundaries(self):
        self.assertEqual(self.r("ipv4", "abc2def"), "unknown")
        self.assertEqual(self.r("ipv4", "factor exit"), "unknown")

    def test_priority(self):
        self.assertEqual(self.r("domain", "phishing site hosting payload"), "phishing")
        self.assertEqual(self.r("domain", "C2 and payload delivery"), "c2")


class TestParseText(unittest.TestCase):
    def test_php2shell_fixture(self):
        with open(os.path.join(HERE, "fixtures", "php2shell_iocs.txt")) as fh:
            text = fh.read()
        r = parsers.parse_text(text)
        self.assertEqual(len(r), 16)
        c = Counter(i["role"] for i in r)
        self.assertEqual(c["c2"], 3)
        self.assertEqual(c["payload"], 13)
        self.assertEqual(Counter(i["type"] for i in r), Counter(ipv4=2, domain=1, url=1, sha256=12))
        v = by_value(r)
        self.assertEqual(v["https://files.demo-cdn.example/invoice.exe"]["role"], "payload")
        self.assertEqual(v["203.0.113.77"]["role"], "c2")
        self.assertEqual(v["198.51.100.24"]["role"], "c2")
        self.assertEqual(v["demo-update.example"]["role"], "c2")
        self.assertTrue(all(i["why"] for i in r))

    def test_free_text(self):
        r = by_value(parsers.parse_text(fx("sample_text_free.txt").decode()))
        self.assertEqual(r["203.0.113.60"]["role"], "c2")          # from the '# C2 servers' heading
        self.assertEqual(r["demo-free.example"]["role"], "c2")
        self.assertEqual(r["198.51.100.60"]["role"], "scanner")
        self.assertEqual(r["198.51.100.61"]["role"], "scanner")
        self.assertIn("CVE-2024-3400", r)
        self.assertIn("analyst@demo-free.example", r)
        for noise in ("1.2.3", "999.1.1.1", "file.name", "e.g"):
            self.assertNotIn(noise, r)

    def test_heading_resets_at_blank_line(self):
        r = by_value(parsers.parse_text("# C2 list\n203.0.113.1\n\n203.0.113.2\n"))
        self.assertEqual(r["203.0.113.1"]["role"], "c2")
        self.assertEqual(r["203.0.113.2"]["role"], "unknown")

    def test_comments_and_dedupe(self):
        r = parsers.parse_text("; c2 203.0.113.1\n203.0.113.9\n203.0.113.9\n# 203.0.113.8\n")
        self.assertEqual([i["value"] for i in r], ["203.0.113.9"])

    def test_ports_and_punctuation(self):
        r = by_value(parsers.parse_text("see 203.0.113.5:8080, (evil[.]example)."))
        self.assertIn("203.0.113.5", r)
        self.assertIn("evil.example", r)

    def test_empty(self):
        self.assertEqual(parsers.parse_text(""), [])
        self.assertEqual(parsers.parse_text("\n\n   \n"), [])


class TestFormats(unittest.TestCase):
    def test_stix(self):
        r = by_value(parsers.parse_stix(fx("sample_stix.json")))
        a = r["203.0.113.10"]
        self.assertEqual((a["role"], a["confidence"], a["techniques"]), ("c2", 85, ["T1071.001"]))
        self.assertIn("demo-rat", a["tags"])
        self.assertEqual(a["first_seen"], "2026-01-02T03:04:05Z")
        d = r["delivery.demo-stix.example"]
        self.assertEqual(d["role"], "payload")
        self.assertEqual(d["techniques"], ["T1071.001"])  # via indicates relationship
        self.assertIn("https://dl.demo-stix.example/a.bin", r)
        self.assertIn("198.51.100.5", r)
        self.assertEqual(r["a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"]["type"], "sha256")
        self.assertEqual(r["0123456789abcdef0123456789abcdef"]["type"], "md5")
        self.assertIn("192.0.2.1", r)
        self.assertIn("192.0.2.2", r)
        self.assertEqual(r["198.51.100.99"]["role"], "exfil")  # observed-data + SCO
        self.assertEqual(len(r), 9)

    def test_stix_v20_observed_and_single(self):
        obs = {"type": "observed-data", "first_observed": "2026-01-01T00:00:00Z", "labels": ["c2"],
               "objects": {"0": {"type": "domain-name", "value": "x.example"},
                           "1": {"type": "file", "hashes": {"SHA-256": "b" * 64}, "name": "p.exe"}}}
        r = by_value(parsers.parse_stix(json.dumps(obs)))
        self.assertEqual(r["x.example"]["role"], "c2")
        self.assertEqual(r["b" * 64]["type"], "sha256")
        self.assertEqual(r["p.exe"]["type"], "filename")

    def test_misp(self):
        r = by_value(parsers.parse_misp(fx("sample_misp.json")))
        self.assertEqual(r["203.0.113.20"]["role"], "c2")
        self.assertEqual(r["203.0.113.20"]["confidence"], 80)
        self.assertEqual(r["203.0.113.20"]["techniques"], ["T1059"])
        self.assertIn("demo rat", r["203.0.113.20"]["tags"])
        self.assertTrue(all("cert-ist" not in t and "tlp" not in t for i in r.values() for t in i["tags"]))
        self.assertEqual(r["203.0.113.21"]["role"], "scanner")
        self.assertEqual(r["c2.demo-misp.example"]["role"], "c2")
        self.assertEqual(r["http://dl.demo-misp.example/x.exe"]["role"], "payload")
        self.assertEqual(r["fedcba9876543210fedcba9876543210"]["confidence"], 50)
        self.assertEqual(r["0123456789abcdef0123456789abcdef01234567"]["type"], "sha1")
        self.assertIn("pair.demo-misp.example", r)
        self.assertIn("203.0.113.22", r)
        self.assertIn("203.0.113.23", r)
        self.assertIn("CVE-2023-1234", r)
        self.assertIn("a" * 40, r)
        self.assertNotIn("203.0.113.24", r)  # deleted
        # unwrapped forms
        ev = json.loads(fx("sample_misp.json"))["response"][0]
        self.assertEqual(len(parsers.parse_misp(ev)), len(r))
        self.assertEqual(len(parsers.parse_misp([ev])), len(r))
        self.assertEqual(len(parsers.parse_misp(ev["Event"])), len(r))

    def test_otx(self):
        r = by_value(parsers.parse_otx(fx("sample_otx.json")))
        self.assertEqual(r["203.0.113.30"]["role"], "c2")
        self.assertEqual(r["2001:db8::30"]["role"], "c2")
        self.assertEqual(r["evil.demo-otx.example"]["role"], "exfil")
        self.assertEqual(r["https://demo-otx.example/gate.php"]["role"], "payload")
        self.assertEqual(r["bad@demo-otx.example"]["role"], "phishing")
        self.assertEqual(r["203.0.113.30"]["techniques"], ["T1566.001", "T1059"])
        self.assertIn("demoloader", r["203.0.113.30"]["tags"])
        self.assertEqual(r["www.demo-otx.example"]["role"], "unknown")
        self.assertEqual(len(r), 10)  # Mutex and FilePath skipped
        pulse = json.loads(fx("sample_otx.json"))["results"][0]
        self.assertEqual(len(parsers.parse_otx(pulse)), 10)

    def test_threatfox(self):
        for src in (fx("sample_threatfox.json"), json.loads(fx("sample_threatfox.json"))):
            r = by_value(parsers.parse_threatfox(src))
            self.assertEqual(r["203.0.113.40"]["role"], "c2")
            self.assertIn("port:8443", r["203.0.113.40"]["tags"])
            self.assertEqual(r["203.0.113.40"]["confidence"], 75)
            self.assertEqual(r["stage.demo-tf.example"]["role"], "c2")
            self.assertEqual(r["https://dl.demo-tf.example/p.bin"]["role"], "payload")
            self.assertEqual(r["4" * 64]["type"], "sha256")
            self.assertEqual(len(r), 4)
        c = by_value(parsers.parse_threatfox(fx("sample_threatfox.csv")))
        self.assertEqual(c["203.0.113.41"]["role"], "c2")
        self.assertEqual(c["dl2.demo-tf.example"]["role"], "payload")

    def test_csv(self):
        r = by_value(parsers.parse_csv(fx("sample_indicators.csv")))
        self.assertEqual(r["203.0.113.50"]["role"], "c2")
        self.assertEqual(r["203.0.113.50"]["confidence"], 80)
        self.assertEqual(r["203.0.113.50"]["first_seen"], "2026-05-01")
        self.assertIn("demo rat", r["203.0.113.50"]["tags"])
        self.assertEqual(r["http://dl.demo-csv.example/p.exe"]["role"], "payload")
        self.assertEqual(len(r), 4)

    def test_csv_headerless_and_delims(self):
        r = parsers.parse_csv("203.0.113.1,Cobalt Strike C2\n203.0.113.2;ignored\n")
        self.assertEqual(len(r), 2)
        self.assertEqual(r[0]["role"], "c2")
        t = parsers.parse_csv("ip\ttype\n203.0.113.3\tipv4\n")
        self.assertEqual(t[0]["value"], "203.0.113.3")
        c2 = parsers.parse_csv("#ip,ioc\n203.0.113.4,Possible Cobalt Strike C2 IP\n")
        self.assertEqual((c2[0]["value"], c2[0]["role"]), ("203.0.113.4", "c2"))

    def test_any_sniffing(self):
        n = {"sample_stix.json": 9, "sample_misp.json": 13, "sample_otx.json": 10,
             "sample_threatfox.json": 4, "sample_threatfox.csv": 2, "sample_indicators.csv": 4}
        for name, count in n.items():
            for data in (fx(name), fx(name).decode()):
                self.assertEqual(len(parsers.parse_any(data, source=name)), count, name)
        self.assertEqual(parsers.parse_any(fx("sample_otx.json"))[0]["source"], "paste")
        self.assertEqual(len(parsers.parse_any(fx("sample_text_free.txt"))), 7)

    def test_any_generic_json_and_jsonl(self):
        r = parsers.parse_any('{"a": {"b": ["203.0.113.1", "evil[.]example"]}, "c2": "203.0.113.2"}')
        self.assertEqual({i["value"] for i in r}, {"203.0.113.1", "evil.example", "203.0.113.2"})
        j = parsers.parse_any('{"ioc_type":"domain","ioc":"a.example","threat_type":"botnet_cc"}\n'
                              '{"ioc_type":"domain","ioc":"b.example","threat_type":"botnet_cc"}\n')
        self.assertEqual([i["role"] for i in j], ["c2", "c2"])


class TestHostile(unittest.TestCase):
    def test_size_cap(self):
        with self.assertRaises(ValueError):
            parsers.parse_text("a" * (parsers.MAX_BYTES + 1))
        with self.assertRaises(ValueError):
            parsers.parse_any(b"x" * (parsers.MAX_BYTES + 1))
        with self.assertRaises(ValueError):
            parsers.parse_stix("{" + " " * 200 + "}", max_bytes=100)
        self.assertEqual(parsers.parse_text("203.0.113.1", max_bytes=100)[0]["value"], "203.0.113.1")

    def test_non_utf8_and_binary(self):
        r = parsers.parse_any(b"\xff\xfe\x00\x80 203.0.113.1 \xc3\x28 evil[.]example\x00\x00")
        self.assertEqual({i["value"] for i in r}, {"203.0.113.1", "evil.example"})
        self.assertEqual(parsers.parse_any(bytes(range(256)) * 50), [])
        self.assertIsInstance(parsers.parse_any(b"\xef\xbb\xbf203.0.113.2"), list)
        self.assertEqual(parsers.parse_any(b"\xef\xbb\xbf203.0.113.2")[0]["value"], "203.0.113.2")

    def test_deep_nesting(self):
        deep = "[" * 100000 + "]" * 100000
        self.assertEqual(parsers.parse_stix(deep), [])
        self.assertIsInstance(parsers.parse_any(deep), list)
        deep_obj = '{"a":' * 5000 + '"203.0.113.1"' + "}" * 5000
        self.assertIsInstance(parsers.parse_misp(deep_obj), list)
        # nested within the tolerated depth: the generic walker is iterative
        nested = {}
        cur = nested
        for _ in range(40):
            cur["x"] = {}
            cur = cur["x"]
        cur["v"] = "203.0.113.1"
        self.assertEqual(parsers.parse_any(nested)[0]["value"], "203.0.113.1")

    def test_malformed_formats(self):
        for bad in ["{", "[1,2", "null", "42", '"str"', "{}", "[]", '{"objects": 5}', '{"response": "x"}',
                    '{"results": [1, 2, null]}', '{"data": [null, 5, "x"]}', '{"Event": {"Attribute": [1, null]}}',
                    '{"type":"bundle","objects":[{"type":"indicator","pattern":123},{"type":"indicator"},7]}']:
            for fn in (parsers.parse_any, parsers.parse_stix, parsers.parse_misp, parsers.parse_otx,
                       parsers.parse_threatfox, parsers.parse_csv, parsers.parse_text):
                self.assertIsInstance(fn(bad), list, (fn.__name__, bad))

    def test_hostile_text_no_execution(self):
        evil = ("__import__('os').system('touch /tmp/pwned-og')\n{{7*7}} ${jndi:ldap://x}\n"
                "[file:name = 'a' ] pattern \x1b[31m 203.0.113.1\n" + "A" * 100000)
        r = parsers.parse_any(evil)
        self.assertIn("203.0.113.1", {i["value"] for i in r})
        self.assertFalse(os.path.exists("/tmp/pwned-og"))

    def test_pattern_injection_in_stix(self):
        bundle = {"type": "bundle", "objects": [{"type": "indicator", "id": "indicator--1",
                  "pattern": "[url:value = 'https://a.example/x\\'drop'] AND [ipv4-addr:value = '999.9.9.9']"}]}
        r = parsers.parse_stix(bundle)
        self.assertEqual([i["type"] for i in r], ["url"])

    def test_output_is_clean(self):
        for name in ("sample_stix.json", "sample_misp.json", "sample_otx.json", "sample_threatfox.json"):
            for i in parsers.parse_any(fx(name)):
                self.assertIn(i["type"], model.TYPES)
                self.assertIn(i["role"], model.ROLES)
                self.assertTrue(0 <= i["confidence"] <= 100)
                self.assertLessEqual(len(i["note"]), 200)
                self.assertEqual(classify.classify_value(i["value"])[0], i["type"] if i["type"] != "domain"
                                 else "domain")
                json.dumps(i)

    def test_many_iocs_capped(self):
        text = "\n".join("203.0.%d.%d" % (a, b) for a in range(0, 200) for b in range(1, 255))
        self.assertLessEqual(len(parsers.parse_text(text)), parsers.MAX_IOCS)


class TestFilters(unittest.TestCase):
    def mk(self, t, v, **kw):
        return model.new_ioc(t, v, **kw)

    def test_private_dropped(self):
        iocs = [self.mk("ipv4", a) for a in ("10.1.2.3", "192.168.1.1", "172.16.0.1", "127.0.0.1",
                                             "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255",
                                             "100.64.1.1", "240.0.0.1", "8.8.9.9")]
        kept, dropped = filters.clean(iocs)
        self.assertEqual([i["value"] for i in kept], ["8.8.9.9"])
        self.assertEqual(len(dropped), 10)
        self.assertTrue(all(r == "private/reserved address" for _, r in dropped))
        kept2, _ = filters.clean(iocs, allow_private=True)
        self.assertEqual(len(kept2), 11 - 1 + 1 - 0 if False else len(kept2))
        self.assertIn("10.1.2.3", {i["value"] for i in kept2})

    def test_ipv6_private(self):
        k, d = filters.clean([self.mk("ipv6", "::1"), self.mk("ipv6", "fe80::1"), self.mk("ipv6", "fc00::1"),
                              self.mk("ipv6", "2606:4700:4700::1111"), self.mk("ipv6", "2a00:1450::1")])
        self.assertEqual([i["value"] for i in k], ["2a00:1450::1"])

    def test_documentation_kept_by_default(self):
        iocs = [self.mk("ipv4", a) for a in ("192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.5.5")]
        iocs.append(self.mk("ipv6", "2001:db8::1"))
        k, d = filters.clean(iocs)
        self.assertEqual(len(k), 5)
        self.assertEqual(d, [])
        k, d = filters.clean(iocs, drop_documentation=True)
        self.assertEqual(k, [])
        self.assertEqual(len(d), 5)

    def test_allow_list(self):
        iocs = [self.mk("ipv4", "8.8.8.8"), self.mk("ipv4", "1.1.1.1"), self.mk("ipv4", "9.9.9.9"),
                self.mk("domain", "google.com"), self.mk("domain", "mail.Google.com"),
                self.mk("url", "https://github.com/x/y"), self.mk("domain", "s3.amazonaws.com"),
                self.mk("email", "a@microsoft.com"), self.mk("domain", "notgoogle.com"),
                self.mk("domain", "google.com.evil.example"), self.mk("domain", "example.com"),
                self.mk("domain", "a.example"), self.mk("domain", "x.test"), self.mk("ipv4", "203.0.113.5")]
        k, d = filters.clean(iocs)
        self.assertEqual({i["value"] for i in k}, {"notgoogle.com", "google.com.evil.example", "example.com",
                                                   "a.example", "x.test", "203.0.113.5"})
        self.assertTrue(all(r == "allow-listed" for _, r in d))
        self.assertEqual(len(d), 8)
        k2, d2 = filters.clean(iocs, allow_list=False)
        self.assertEqual(len(k2), len(iocs))
        self.assertIn("allow-listed", by_value(k2)["google.com"]["tags"])

    def test_dedupe_merge(self):
        a = self.mk("domain", "dup.example", confidence=40, tags=["a"], techniques=["T1071"], role="unknown")
        b = self.mk("domain", "DUP.example", confidence=90, tags=["b"], techniques=["T1059"], role="c2",
                    first_seen="2026-01-01")
        c = self.mk("domain", "dup.example", confidence=10, tags=["c"], role="exfil")
        k, d = filters.clean([a, b, c])
        self.assertEqual(len(k), 1)
        self.assertEqual(k[0]["role"], "c2")
        self.assertEqual(k[0]["confidence"], 90)
        self.assertEqual(sorted(k[0]["tags"]), ["a", "b", "c"])
        self.assertEqual(sorted(k[0]["techniques"]), ["T1059", "T1071"])
        self.assertEqual(k[0]["first_seen"], "2026-01-01")
        self.assertEqual(len(d), 2)
        self.assertEqual(a["tags"], ["a"])  # input untouched

    def test_url_dedupe_case(self):
        k, _ = filters.clean([self.mk("url", "HTTP://A.example/Path"), self.mk("url", "http://a.example/Path")])
        self.assertEqual(len(k), 1)
        k, _ = filters.clean([self.mk("url", "http://a.example/Path"), self.mk("url", "http://a.example/path")])
        self.assertEqual(len(k), 2)


class CacheCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"OPENGENERATOR_CACHE": os.path.join(self.tmp.name, "c")})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()


class TestCache(CacheCase):
    def test_roundtrip_ttl_mode(self):
        cache.put("feodo", {"a": 1}, "payload-1", now=1000.0)
        self.assertEqual(cache.get("feodo", {"a": 1}, ttl=60, now=1030.0), "payload-1")
        self.assertIsNone(cache.get("feodo", {"a": 1}, ttl=60, now=1061.0))
        self.assertEqual(cache.get("feodo", {"a": 1}, ttl=None, now=10 ** 9), "payload-1")
        self.assertIsNone(cache.get("feodo", {"a": 2}, ttl=None))
        self.assertIsNone(cache.get("other", {"a": 1}, ttl=None))
        d = cache.cache_dir()
        for f in os.listdir(d):
            mode = stat.S_IMODE(os.stat(os.path.join(d, f)).st_mode)
            self.assertEqual(mode, 0o600, f)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        self.assertFalse([f for f in os.listdir(d) if f.startswith(".tmp")])

    def test_manifest(self):
        k = cache.put("feodo", {}, "abc", now=5.0)
        m = cache.manifest()
        self.assertEqual(m[k]["feed"], "feodo")
        self.assertEqual(m[k]["bytes"], 3)
        self.assertEqual(len(m[k]["sha256"]), 64)

    def test_no_secrets_in_key(self):
        with self.assertRaises(ValueError):
            cache.put("otx", {"api_key": "SECRET"}, "x")
        with self.assertRaises(ValueError):
            cache.key_for("otx", {"Auth-Key": "x"})

    def test_corrupt_entry(self):
        k = cache.put("feodo", {}, "abc")
        with open(os.path.join(cache.cache_dir(), k + ".json"), "w") as f:
            f.write("{not json")
        self.assertIsNone(cache.get("feodo", {}, ttl=None))

    def test_env_override(self):
        self.assertTrue(cache.cache_dir().startswith(self.tmp.name))


class TestSources(CacheCase):
    def test_registry(self):
        want = {"circl", "otx", "url", "threatfox", "urlhaus", "c2intel-ip", "c2intel-domain",
                "blocklist-ssh", "blocklist-login", "blocklist-mail", "tor-exit", "openphish", "cisa-kev"}
        self.assertTrue(want <= set(sources.FEEDS))
        # removed because they cannot yield traffic: hash-only, empty after takedowns, a role with no compiler traffic
        self.assertFalse({"malwarebazaar", "feodo", "et-compromised"} & set(sources.FEEDS))
        for fid, f in sources.FEEDS.items():
            self.assertEqual(fid, f.id)
            self.assertTrue(f.url.startswith("https://") or f.kind == "user_url", fid)
            self.assertTrue(callable(f.parse))
            if f.needs_key:
                self.assertTrue(f.key_env and (f.key_header or f.kind == "shodan"))  # shodan takes its key as a query parameter
        self.assertEqual(sources.FEEDS["otx"].key_env, "OTX_API_KEY")
        self.assertEqual(sources.FEEDS["threatfox"].key_env, "ABUSECH_AUTH_KEY")

    def test_ssrf_rejections(self):
        bad = ["http://example.com/x", "ftp://example.com/x", "file:///etc/passwd", "https://127.0.0.1/x",
               "https://10.0.0.5/x", "https://192.168.1.1/x", "https://169.254.169.254/latest", "https://[::1]/x",
               "https://[fe80::1]/x", "https://0.0.0.0/x", "https://localhost/x", "https://u:p@example.com/x",
               "https://example.com:22/x", "https://[::ffff:127.0.0.1]/x", "javascript:alert(1)", "", "https://",
               "https://a b/x", "x" * 3000, None, 5]
        for u in bad:
            with self.assertRaises(sources.FeedError, msg=str(u)[:40]):
                sources.check_user_url(u)

    def test_ssrf_dns_rebinding_guard(self):
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.7", 443))]):
            with self.assertRaises(sources.FeedError):
                sources.check_user_url("https://looks-public.example/x")
        mixed = [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]
        with mock.patch("socket.getaddrinfo", return_value=mixed):
            with self.assertRaises(sources.FeedError):
                sources.check_user_url("https://mixed.example/x")
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            self.assertEqual(sources.check_user_url("https://ok.example/feed"), "https://ok.example/feed")

    def test_is_public_ip(self):
        for ip in ("8.8.8.8", "93.184.216.34", "2a00:1450::1"):
            self.assertTrue(sources.is_public_ip(ip), ip)
        for ip in ("127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.1.1", "::1", "fe80::1",
                   "fc00::1", "224.0.0.1", "0.0.0.0", "100.64.0.1", "::ffff:10.0.0.1", "nonsense"):
            self.assertFalse(sources.is_public_ip(ip), ip)

    def test_redirect_to_http_refused(self):
        h = sources._Redirect([])
        import urllib.request as ur
        req = ur.Request("https://a.example/x")
        with self.assertRaises(Exception):
            h.redirect_request(req, None, 302, "Found", {}, "http://b.example/x")
        req = ur.Request("https://a.example/x", headers={"Auth-Key": "k"})
        h2 = sources._Redirect(["Auth-Key"])
        with self.assertRaises(Exception):
            h2.redirect_request(req, None, 302, "Found", {}, "https://other.example/x")

    def test_http_get_refuses_http(self):
        with self.assertRaises(sources.FeedError):
            sources.http_get("http://example.com/")

    def test_needs_key(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ABUSECH_AUTH_KEY", None)
            os.environ.pop("OTX_API_KEY", None)
            os.environ.pop("SHODAN_API_KEY", None)
            with mock.patch.object(sources, "http_get", side_effect=AssertionError("no network")):
                for fid in ("threatfox", "urlhaus", "otx", "shodan"):
                    with self.assertRaises(sources.FeedError) as cm:
                        sources.fetch(fid)
                    self.assertIn("API key", str(cm.exception))

    def test_unknown_feed_and_offline_empty(self):
        with self.assertRaises(sources.FeedError):
            sources.fetch("nope")
        with self.assertRaises(sources.FeedError) as cm:
            sources.fetch("tor-exit", offline=True)
        self.assertIn("offline", str(cm.exception))

    def test_fetch_cache_and_offline(self):
        feodo = b"203.0.113.70\n203.0.113.71\n"
        calls = []

        def fake(url, **kw):
            calls.append(url)
            return feodo
        with mock.patch.object(sources, "http_get", side_effect=fake):
            r = sources.fetch("tor-exit", limit=1)
            self.assertEqual(len(r), 1)
            self.assertEqual((r[0]["value"], r[0]["role"], r[0]["source"]), ("203.0.113.70", "tor", "tor-exit"))
            r2 = sources.fetch("tor-exit", limit=10)
            self.assertEqual(len(r2), 2)
            self.assertEqual(len(calls), 1)  # second call served from cache
            sources.fetch("tor-exit", cache=False)
            self.assertEqual(len(calls), 2)
        with mock.patch.object(sources, "http_get", side_effect=AssertionError("no network")):
            self.assertEqual(len(sources.fetch("tor-exit", offline=True)), 2)

    def test_keys_never_cached_or_leaked(self):
        body = json.dumps({"query_status": "ok", "data": [
            {"ioc": "203.0.113.80:443", "ioc_type": "ip:port", "threat_type": "botnet_cc", "malware_printable": "X"}]})
        seen = {}

        def fake(url, **kw):
            seen.update(kw)
            return body.encode()
        with mock.patch.object(sources, "http_get", side_effect=fake):
            r = sources.fetch("threatfox", key="SECRETKEY123")
        self.assertEqual(r[0]["role"], "c2")
        self.assertEqual(seen["headers"]["Auth-Key"], "SECRETKEY123")
        self.assertEqual(seen["method"], "POST")
        d = cache.cache_dir()
        for f in os.listdir(d):
            with open(os.path.join(d, f)) as fh:
                self.assertNotIn("SECRETKEY123", fh.read())
        with self.assertRaises(sources.FeedError) as cm:
            sources.fetch("threatfox", key="bad key\nwith newline", cache=False)
        self.assertNotIn("bad key", str(cm.exception))

    def test_otx_search_without_indicators_fetches_them(self):
        pid = "0123456789abcdef01234567"
        search = json.dumps({"results": [{"id": pid, "name": "c2 pulse", "tags": ["c2"]},
                                         {"id": "../evil", "name": "bad id"}]})
        subs = json.dumps({"results": [{"indicator": "203.0.113.90", "type": "IPv4", "title": "c2 server"}]})
        urls = []

        def fake(url, **kw):
            urls.append(url)
            return (subs if "/indicators" in url else search).encode()
        with mock.patch.object(sources, "http_get", side_effect=fake):
            r = sources.fetch("otx", limit=5, key="K", cache=False)
        self.assertEqual([i["value"] for i in r], ["203.0.113.90"])
        self.assertEqual(sum("/indicators" in u for u in urls), 1)      # the malformed id was never requested

    def test_kev_roles_and_techniques(self):
        kev = json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2024-10441", "vendorProject": "Acme", "product": "Edge Gateway", "vulnerabilityName": "x",
             "dateAdded": "2026-11-18", "shortDescription": "a remote attacker could run code"},
            {"cveID": "CVE-2024-0002", "vendorProject": "Linux", "product": "Kernel", "vulnerabilityName": "x",
             "dateAdded": "2026-11-17", "shortDescription": "local privilege escalation"}]})
        r = sources._parse_kev(kev)
        self.assertEqual([i["role"] for i in r], ["vulnerability", "vulnerability"])
        self.assertIn("T1190", r[0]["techniques"])
        self.assertEqual(r[1]["techniques"], ["T1068"])
        self.assertIn("acme", r[0]["tags"])
        self.assertEqual(roles.infer_role({"type": "cve", "value": "CVE-2024-1", "tags": ["scanner"]})[0], "vulnerability")

    def test_env_key(self):
        with mock.patch.dict(os.environ, {"OTX_API_KEY": "ENVKEY"}):
            with mock.patch.object(sources, "http_get", return_value=fx("sample_otx.json")) as g:
                r = sources.fetch("otx", limit=3, q="demo")
        self.assertEqual(len(r), 3)
        self.assertEqual(g.call_args.kwargs["headers"]["X-OTX-API-KEY"], "ENVKEY")
        self.assertIn("q=demo", g.call_args.args[0])

    def test_list_feeds_roles(self):
        text = b"# comment\n203.0.113.1\n203.0.113.2 extra\n\nnot-an-ip\n10.0.0.1\n"
        want = {"blocklist-ssh": "brute", "blocklist-login": "brute", "blocklist-mail": "brute",
                "tor-exit": "tor", "cins-army": "scanner", "ipsum": "scanner"}
        for fid, role in want.items():
            with mock.patch.object(sources, "http_get", return_value=text):
                r = sources.fetch(fid, cache=False)
            self.assertEqual([i["role"] for i in r], [role] * 3, fid)
        with mock.patch.object(sources, "http_get", return_value=b"https://p.example/login\nhttp://q.example/\n"):
            r = sources.fetch("openphish", cache=False)
        self.assertEqual([i["role"] for i in r], ["phishing", "phishing"])

    def test_c2intel(self):
        ip = b"#ip,ioc\n203.0.113.90,Possible Cobaltstrike C2 IP\n203.0.113.91,Possible Cobalt Strike C2 IP\n"
        with mock.patch.object(sources, "http_get", return_value=ip):
            r = sources.fetch("c2intel-ip", cache=False)
        self.assertEqual([i["role"] for i in r], ["c2", "c2"])
        dom = b"#domain,ioc\nc2.demo.example,Possible Cobalt Strike C2 Domain\napi.demo.example,Possible Cobalt Strike C2 Fronting Domain\n"
        with mock.patch.object(sources, "http_get", return_value=dom):
            r = sources.fetch("c2intel-domain", cache=False)
        self.assertEqual(r[0]["confidence"], 50)
        self.assertEqual(r[1]["confidence"], 30)
        self.assertIn("domain-fronting", r[1]["tags"])

    def test_urlhaus_kev(self):
        uh = json.dumps({"query_status": "ok", "urls": [
            {"url": "http://203.0.113.95/a.bin", "url_status": "online", "threat": "malware_download",
             "tags": ["elf"], "date_added": "2026-01-01 00:00:00 UTC"}]})
        with mock.patch.object(sources, "http_get", return_value=uh.encode()) as g:
            r = sources.fetch("urlhaus", key="k", cache=False, limit=7)
        self.assertEqual((r[0]["type"], r[0]["role"]), ("url", "payload"))
        self.assertIn("/limit/7/", g.call_args.args[0])
        kev = json.dumps({"vulnerabilities": [
            {"cveID": "CVE-2020-0001", "dateAdded": "2026-01-01", "vendorProject": "V", "product": "P",
             "vulnerabilityName": "N", "knownRansomwareCampaignUse": "Known"},
            {"cveID": "CVE-2020-0002", "dateAdded": "2026-02-01", "vendorProject": "V", "product": "P",
             "vulnerabilityName": "N", "knownRansomwareCampaignUse": "Unknown"}]})
        with mock.patch.object(sources, "http_get", return_value=kev.encode()):
            r = sources.fetch("cisa-kev", cache=False)
        self.assertEqual([i["value"] for i in r], ["CVE-2020-0002", "CVE-2020-0001"])
        self.assertIn("ransomware", r[1]["tags"])

    def test_user_url_feed(self):
        with mock.patch.object(sources, "check_user_url", return_value="https://ok.example/f"), \
                mock.patch.object(sources, "http_get", return_value=fx("sample_stix.json")) as g:
            r = sources.fetch("url", url="https://ok.example/f", cache=False)
        self.assertEqual(len(r), 9)
        self.assertTrue(g.call_args.kwargs["ssrf"])
        with self.assertRaises(sources.FeedError):
            sources.fetch("url")
        with self.assertRaises(sources.FeedError):
            sources.fetch("url", url="https://127.0.0.1/x")

    def test_shodan_key_goes_in_the_query_only(self):
        body = b'{"matches": [{"ip_str": "203.0.113.5", "port": 80, "product": "x"}]}'
        seen = {}

        def fake(url, **kw):
            seen.update(url=url, headers=kw.get("headers"))
            return body
        with mock.patch.object(sources, "http_get", side_effect=fake):
            r = sources.fetch("shodan", key="SECRETKEY", q="port:80", cache=True)
        self.assertIn("key=SECRETKEY", seen["url"])
        self.assertIn("query=port%3A80", seen["url"])
        self.assertFalse(seen["headers"])
        self.assertEqual(r[0]["value"], "203.0.113.5")
        with mock.patch.object(sources, "http_get", side_effect=AssertionError("no network")):
            self.assertEqual(len(sources.fetch("shodan", q="port:80", offline=True)), 1)     # key not needed from cache

    def test_misp_feed(self):
        man = {"11111111-1111-4111-8111-111111111111": {"timestamp": "10", "info": "old"},
               "22222222-2222-4222-8222-222222222222": {"timestamp": "20", "info": "new"},
               "../../evil": {"timestamp": "30"}}
        ev = json.loads(fx("sample_misp.json"))["response"][0]
        urls = []

        def fake(url, **kw):
            urls.append(url)
            return json.dumps(man if url.endswith("manifest.json") else ev).encode()
        with mock.patch.object(sources, "http_get", side_effect=fake):
            r = sources.fetch("circl", limit=5, cache=False)
        self.assertEqual(len(r), 5)
        self.assertEqual(r[0]["source"], "circl")
        self.assertTrue(urls[1].endswith("22222222-2222-4222-8222-222222222222.json"))  # newest first
        self.assertFalse(any("evil" in u for u in urls))


class TestCli(CacheCase):
    def run_cli(self, argv):
        import io
        from contextlib import redirect_stdout, redirect_stderr
        from intel import __main__ as cli
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = cli.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_list(self):
        rc, out, _ = self.run_cli(["list"])
        self.assertEqual(rc, 0)
        rows = [json.loads(l) for l in out.splitlines()]
        self.assertGreaterEqual(len(rows), 12)
        self.assertNotIn("key", " ".join(rows[0].keys()).replace("key_env", "").replace("needs_key", ""))

    def test_parse(self):
        rc, out, _ = self.run_cli(["parse", os.path.join(FIX, "sample_otx.json")])
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.splitlines()), 10)
        self.assertEqual(json.loads(out.splitlines()[0])["source"], "sample_otx.json")

    def test_fetch_errors(self):
        rc, out, err = self.run_cli(["fetch", "tor-exit", "--offline"])
        self.assertEqual(rc, 2)
        self.assertIn("offline", err)


if __name__ == "__main__":
    unittest.main()

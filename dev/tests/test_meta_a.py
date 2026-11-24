"""Tests for dev/netgen/campaign/actions/meta_a.py (META-A diagram metadata).

Run from dev/:  python -m unittest tests.test_meta_a
Checks completeness, field shapes and length limits, allowed placeholders, parameter names, neutral wording,
and (when tshark is installed) display-filter syntax of every filter filled with sample values.
"""
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

from netgen.campaign import actions as A
from netgen.campaign.actions.meta_a import META

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
TACTICS = ("command-and-control", "exfiltration", "collection")
TOKENS = ("cloud_service_c2 dga_lookup dns_beacon dns_tunnel http_beacon https_beacon icmp_tunnel payload_download "
          "tor_connect cloud_storage_upload dns_exfil ftp_upload https_upload smtp_exfil archive_stage smb_collect "
          "sql_collect").split()
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
SIMPLE = {"src_ip", "dst_ip", "fqdn"}
# vendor and company names, written as fragments so this file does not contain them whole
BANNED = [a + b for a, b in (("extra", "hop"), ("reveal", "x"), ("cobalt", "strike"), ("meta", "sploit"), ("mi", "tre"),
                             ("micro", "soft"), ("go", "ogle"), ("ama", "zon"), ("cloud", "flare"), ("vec", "tra"),
                             ("dark", "trace"), ("crowd", "strike"), ("empire", "-like"), ("wire", "shark"),
                             ("sli", "ver"), ("mimi", "katz"))]


def _specs():
    return A.load_all()


class MetaA(unittest.TestCase):
    def test_every_token_present(self):
        self.assertEqual(sorted(META), sorted(TOKENS))
        specs = _specs()
        for tok in TOKENS:
            self.assertIn(tok, specs)
            self.assertIn(specs[tok].tactic, TACTICS, tok)

    def test_whole_tactics_covered(self):
        expected = {t for t, s in _specs().items() if s.tactic in TACTICS}
        self.assertEqual(expected, set(META), "META-A must cover exactly the actions of its three tactics")

    def test_shapes_and_limits(self):
        for tok, m in META.items():
            self.assertEqual(set(m), {"plain", "tells", "filters", "wire"}, tok)
            self.assertIsInstance(m["plain"], str)
            self.assertTrue(0 < len(m["plain"]) <= 240, "%s plain %d" % (tok, len(m["plain"])))
            self.assertIn(len(m["tells"]), (2, 3), tok)
            for t in m["tells"]:
                self.assertIsInstance(t, str)
                self.assertTrue(0 < len(t) <= 90, "%s tell %r (%d)" % (tok, t, len(t)))
            self.assertTrue(1 <= len(m["filters"]) <= 3, tok)
            for f in m["filters"]:
                self.assertEqual(len(f), 3, tok)
                what, tmpl, expect = f
                for x in f:
                    self.assertIsInstance(x, str)
                    self.assertTrue(x.strip(), tok)
                self.assertLessEqual(len(what), 40, "%s what %r" % (tok, what))
                self.assertLessEqual(len(expect), 70, "%s expect %r (%d)" % (tok, expect, len(expect)))
            self.assertIsInstance(m["wire"], str)
            self.assertTrue(0 < len(m["wire"]) <= 100, "%s wire %d" % (tok, len(m["wire"])))
            self.assertRegex(m["wire"], r"(tcp|udp)/\d+|ICMP|no port", tok)

    def test_placeholders_allowed_and_real(self):
        specs = _specs()
        for tok, m in META.items():
            params = specs[tok].params
            for field in [m["plain"], m["wire"]] + m["tells"] + [x for f in m["filters"] for x in (f[0], f[2])]:
                self.assertIsNone(PLACEHOLDER.search(field), "%s: placeholder outside a filter: %r" % (tok, field))
            for _what, tmpl, _expect in m["filters"]:
                for name in PLACEHOLDER.findall(tmpl):
                    if name in SIMPLE:
                        continue
                    self.assertTrue(name.startswith("p:"), "%s: bad placeholder {%s}" % (tok, name))
                    self.assertIn(name[2:], params, "%s: {%s} is not a parameter" % (tok, name))
                self.assertNotIn("{}", tmpl)

    def test_neutral_wording(self):
        for tok, m in META.items():
            text = " ".join([m["plain"], m["wire"]] + m["tells"] + [x for f in m["filters"] for x in f]).lower()
            for frag in BANNED:
                self.assertNotIn(frag, text, "%s mentions %s" % (tok, frag))

    def test_actions_read_differently(self):
        for a, b in (("https_beacon", "http_beacon"), ("https_beacon", "dns_beacon"), ("http_beacon", "dns_beacon"),
                     ("dns_beacon", "dns_tunnel"), ("dns_tunnel", "dns_exfil")):
            self.assertNotEqual(META[a]["plain"], META[b]["plain"])
            self.assertNotEqual(META[a]["wire"], META[b]["wire"])
        plains = [m["plain"] for m in META.values()]
        self.assertEqual(len(plains), len(set(plains)))

    @unittest.skipUnless(os.path.exists(TSHARK) or shutil.which("tshark"), "tshark not installed")
    def test_filter_syntax_with_tshark(self):
        tshark = TSHARK if os.path.exists(TSHARK) else shutil.which("tshark")
        specs = _specs()
        with tempfile.TemporaryDirectory() as d:
            pcap = os.path.join(d, "empty.pcap")
            with open(pcap, "wb") as fh:                                  # header only: enough to check filter syntax
                fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for tok, m in META.items():
                params = specs[tok].params
                for _what, tmpl, _expect in m["filters"]:
                    def fill(mt):
                        n = mt.group(1)
                        if n == "src_ip":
                            return "10.1.2.3"
                        if n == "dst_ip":
                            return "203.0.113.9"
                        if n == "fqdn":
                            return "c2.example.test"
                        return str(params[n[2:]]["default"])
                    flt = PLACEHOLDER.sub(fill, tmpl)
                    r = subprocess.run([tshark, "-Y", flt, "-r", pcap, "-c", "1"], capture_output=True, text=True, timeout=60)
                    self.assertNotEqual(r.returncode, 2, "%s: invalid filter %r: %s" % (tok, flt, r.stderr.strip()))
                    self.assertEqual(r.returncode, 0, "%s: tshark failed on %r: %s" % (tok, flt, r.stderr.strip()))


if __name__ == "__main__":
    unittest.main()

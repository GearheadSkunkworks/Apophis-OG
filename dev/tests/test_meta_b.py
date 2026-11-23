"""META-B (credential-access, discovery, lateral-movement, impact) diagram metadata checks."""
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

from netgen.campaign.actions import load_all
from netgen.campaign.actions.meta_b import META

TOKENS = ["asrep_roast", "dcsync", "kerberoast", "kerberos_spray", "rdp_brute", "ssh_brute",
          "icmp_sweep", "ldap_recon", "port_probe", "smb_share_enum", "syn_scan",
          "rdp_session", "smb_admin_exec", "wmi_exec", "ransomware_smb", "smb_delete_burst"]
TSHARK = next((p for p in ("/Applications/Wireshark.app/Contents/MacOS/tshark", shutil.which("tshark") or "")
               if p and os.path.exists(p)), None)
PH = re.compile(r"\{([^{}]*)\}")
SAMPLE = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "fqdn": "host.example.test"}
# vendor/company names, written as fragments so this file does not itself contain them
BANNED = ["extra" + "hop", "reveal" + "x", "micro" + "soft", "crowd" + "strike", "mand" + "iant",
          "impa" + "cket", "mimi" + "katz", "cobalt" + " strike", "metas" + "ploit", "ps" + "exec",
          "rube" + "us", "vec" + "tra", "dark" + "trace", "pal" + "o alto", "cis" + "co"]


class TestMetaB(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.specs = load_all()

    def test_exact_tokens(self):
        self.assertEqual(sorted(META), sorted(TOKENS))
        for t in TOKENS:
            self.assertIn(t, self.specs)

    def test_fields(self):
        for t, m in META.items():
            self.assertEqual(set(m), {"plain", "tells", "filters", "wire"}, t)
            self.assertIsInstance(m["plain"], str)
            self.assertTrue(0 < len(m["plain"]) <= 240, (t, len(m["plain"])))
            self.assertIn(len(m["tells"]), (2, 3), t)
            for x in m["tells"]:
                self.assertTrue(isinstance(x, str) and 0 < len(x) <= 90, (t, x, len(x)))
            self.assertTrue(1 <= len(m["filters"]) <= 3, t)
            for f in m["filters"]:
                self.assertEqual(len(f), 3, t)
                what, tpl, expect = f
                self.assertTrue(0 < len(what) <= 40, (t, what))
                self.assertTrue(0 < len(expect) <= 70, (t, expect, len(expect)))
                self.assertTrue(isinstance(tpl, str) and tpl, t)
            self.assertTrue(isinstance(m["wire"], str) and 0 < len(m["wire"]) <= 100, (t, len(m["wire"])))
            self.assertRegex(m["wire"], r"^[A-Za-z0-9/ +\-]+, ", t)

    def test_tactics_match(self):
        want = {"credential-access": TOKENS[:6], "discovery": TOKENS[6:11],
                "lateral-movement": TOKENS[11:14], "impact": TOKENS[14:]}
        for tactic, toks in want.items():
            for t in toks:
                self.assertEqual(self.specs[t].tactic, tactic, t)

    def test_placeholders(self):
        for t, m in META.items():
            params = self.specs[t].params
            for _, tpl, _ in m["filters"]:
                for ph in PH.findall(tpl):
                    if ph.startswith("p:"):
                        self.assertIn(ph[2:], params, (t, ph))
                    else:
                        self.assertIn(ph, SAMPLE, (t, ph))

    def test_neutral_wording(self):
        for t, m in META.items():
            blob = " ".join([m["plain"], m["wire"]] + m["tells"] + [x for f in m["filters"] for x in f]).lower()
            for b in BANNED:
                self.assertNotIn(b, blob, (t, b))

    def test_distinct(self):
        plains = [m["plain"] for m in META.values()]
        self.assertEqual(len(set(plains)), len(plains))

    @unittest.skipUnless(TSHARK, "tshark not available")
    def test_filter_syntax(self):
        with tempfile.TemporaryDirectory() as d:
            pcap = os.path.join(d, "empty.pcap")
            with open(pcap, "wb") as fh:
                fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for t, m in META.items():
                params = self.specs[t].params
                for what, tpl, _ in m["filters"]:
                    vals = dict(SAMPLE)
                    flt = PH.sub(lambda mo: str(vals.get(mo.group(1)) if not mo.group(1).startswith("p:")
                                                else params[mo.group(1)[2:]].get("default") or "x"), tpl)
                    r = subprocess.run([TSHARK, "-Y", flt, "-r", pcap, "-c", "1"], capture_output=True, text=True)
                    self.assertEqual(r.returncode, 0, (t, what, flt, r.stderr))
                    self.assertNotIn("isn't a valid", r.stderr, (t, flt))


if __name__ == "__main__":
    unittest.main()

"""Checks for netgen/campaign/actions/meta_c.py (META-C)."""
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

from netgen.campaign.actions import load_all
from checks.tshark_locate import find_tshark
from netgen.campaign.actions.meta_c import META

TOKENS = {
    "initial-access": ["exploit_probe", "exposed_service_login", "phishing_visit", "web_login_spray"],
    "execution": ["ssh_remote_exec", "winrm_exec"],
    "persistence": ["remote_schtask", "svcctl_persist"],
    "privilege-escalation": ["gpo_modify", "privileged_group_add"],
    "stealth": ["eventlog_clear", "lolbin_fetch"],
    "defense-impairment": ["security_service_stop", "security_update_block"],
    "resource-development": ["new_domain_contact", "selfsigned_tls_contact"],
    "reconnaissance": ["subdomain_enum", "web_dir_scan"],
}
ALL = [t for v in TOKENS.values() for t in v]
TSHARK = find_tshark()
# vendor and company names built from fragments so this file does not itself spell them in one piece
VENDORS = ["micro" + "soft", "win" + "dows", "cis" + "co", "extra" + "hop", "vec" + "tra", "crowd" + "strike", "pal" + "o alto",
           "forti" + "net", "ubu" + "ntu", "deb" + "ian", "goo" + "gle", "app" + "le", "ama" + "zon", "sym" + "antec", "mc" + "afee",
           "kaspers" + "ky", "sophos", "sentinel" + "one", "cert" + "util", "bits" + "admin", "open" + "ssh", "ng" + "inx"]
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")


def _sample(spec, template):
    vals = {"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "fqdn": "host.example"}

    def sub(m):
        k = m.group(1)
        if k in vals:
            return vals[k]
        name = k[2:]
        d = spec.params[name]["default"]
        return str(d if d not in (None, "") else "x")
    return PLACEHOLDER.sub(sub, template)


class MetaC(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg = load_all()

    def test_tokens_exact(self):
        self.assertEqual(sorted(META), sorted(ALL))
        for tactic, toks in TOKENS.items():
            for t in toks:
                self.assertIn(t, self.reg)
                self.assertEqual(self.reg[t].tactic, tactic)

    def test_fields(self):
        for tok, m in META.items():
            self.assertEqual(set(m), {"plain", "tells", "filters", "wire"}, tok)
            self.assertIsInstance(m["plain"], str)
            self.assertLessEqual(len(m["plain"]), 240, tok)
            self.assertIn(len(m["tells"]), (2, 3), tok)
            for t in m["tells"]:
                self.assertIsInstance(t, str)
                self.assertLessEqual(len(t), 90, (tok, t))
            self.assertIn(len(m["filters"]), (1, 2, 3), tok)
            for f in m["filters"]:
                self.assertEqual(len(f), 3)
                what, tpl, exp = f
                self.assertTrue(all(isinstance(x, str) and x for x in f))
                self.assertLessEqual(len(what), 40, (tok, what))
                self.assertLessEqual(len(exp), 70, (tok, exp))
            self.assertIsInstance(m["wire"], str)
            self.assertLessEqual(len(m["wire"]), 100, tok)
            self.assertRegex(m["wire"], r"(tcp|udp)/\d+", tok)

    def test_placeholders(self):
        for tok, m in META.items():
            spec = self.reg[tok]
            for what, tpl, exp in m["filters"]:
                for k in PLACEHOLDER.findall(tpl):
                    if k in ("src_ip", "dst_ip", "fqdn"):
                        continue
                    self.assertTrue(k.startswith("p:"), (tok, k))
                    self.assertIn(k[2:], spec.params, (tok, k))
                for txt in (what, exp):
                    self.assertFalse(PLACEHOLDER.search(txt), (tok, txt))

    def test_neutral_wording(self):
        for tok, m in META.items():
            text = " ".join([m["plain"], m["wire"]] + m["tells"] + [f[0] + " " + f[2] for f in m["filters"]]).lower()
            for v in VENDORS:
                self.assertNotIn(v, text, (tok, v))

    @unittest.skipUnless(TSHARK, "tshark not installed")
    def test_filter_syntax(self):
        with tempfile.TemporaryDirectory() as d:
            pcap = os.path.join(d, "empty.pcap")
            with open(pcap, "wb") as fh:
                fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for tok, m in META.items():
                for _what, tpl, _exp in m["filters"]:
                    flt = _sample(self.reg[tok], tpl)
                    r = subprocess.run([TSHARK, "-r", pcap, "-Y", flt, "-c", "1"], capture_output=True, text=True)
                    self.assertNotEqual(r.returncode, 2, (tok, flt, r.stderr))
                    self.assertEqual(r.returncode, 0, (tok, flt, r.stderr))


if __name__ == "__main__":
    unittest.main()

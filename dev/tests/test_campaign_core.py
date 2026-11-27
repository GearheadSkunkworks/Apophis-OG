"""Unit tests for the campaign core: ATT&CK catalog, addressing, schema and compiler. Run from dev/:
    python -m unittest tests.test_campaign_core
Stub action specs are registered here only when a real action module is not yet present."""
import copy
import ipaddress
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from netgen.campaign import actions, addressing, attack, compiler, schema  # noqa: E402 - sys.path is set up before the import

FIXTURE = os.path.join(HERE, "fixtures", "php2shell_iocs.txt")


def _ensure_actions():
    """Real actions when written; otherwise inert stubs (test-only)."""
    actions.load_all()
    stubs = {"c2": ["https_beacon", "http_beacon", "dns_beacon", "tor_connect"], "delivery": ["payload_download", "phishing_visit"],
             "exfil": ["https_upload", "dns_exfil", "ftp_upload"], "recon": ["ldap_recon", "smb_share_enum", "port_probe", "syn_scan"],
             "access": ["kerberoast", "kerberos_spray", "ssh_brute", "rdp_brute"], "lateral": ["smb_admin_exec", "rdp_session", "ransomware_smb"]}
    tac = {"payload_download": ("execution", ["T1105"]), "phishing_visit": ("initial-access", ["T1566.002"])}
    for toks in stubs.values():
        for t in toks:
            if t in actions.all_specs():
                continue
            tactic = tac.get(t, (compiler.PREFERRED and next(k for k, v in compiler.PREFERRED.items() if t in v), ["T1071.001"]))
            actions.register(actions.ActionSpec(
                token=t, fn=lambda ctx, s, d, *, ts, **p: [], title=t, tactic=tactic[0], techniques=tactic[1], protocols=[],
                params={"count": {"type": "int", "default": 4, "help": ""}}, src="any", dst="any"))


def _local_parse(text):
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        v = ln.split()[0].replace("[.]", ".").replace("hxxp", "http")
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", v):
            t = "ipv4"
        elif "://" in v:
            t = "url"
        elif re.fullmatch(r"[0-9a-f]{64}", v):
            t = "sha256"
        else:
            t = "domain"
        out.append({"type": t, "value": v, "role": "payload" if t in ("url", "sha256") else "c2", "source": "fixture"})
    return out


def fixture_iocs():
    with open(FIXTURE, encoding="utf-8") as f:
        text = f.read()
    try:
        from intel.parsers import parse_text
        got = parse_text(text, source="fixture")
        if got:
            return got
    except Exception:  # the real parser is optional here: any failure falls back to the local parser below
        pass
    return _local_parse(text)


def ioc(t, v, role, **kw):
    return dict({"type": t, "value": v, "role": role}, **kw)


class AttackTests(unittest.TestCase):
    def test_catalog(self):
        m = attack.meta()
        self.assertTrue(m["attack_version"] and m["source"])
        self.assertEqual(attack.technique("T1071.001")["tactic"], "command-and-control")
        self.assertIn("TA0002", [t["id"] for t in attack.tactics()])
        self.assertIsNone(attack.technique("T9999"))
        self.assertEqual(attack.tactic_for("T1558.003"), "credential-access")

    def test_validate_ids(self):
        self.assertEqual(attack.validate_ids(["T1105", "T1021.002"]), [])
        self.assertEqual(len(attack.validate_ids(["T9999", "nope", 5])), 3)

    def test_navigator(self):
        lay = attack.navigator_layer(["T1105", {"id": "T1046", "comment": "scan"}, "T0000"], "x", "c")
        self.assertEqual(lay["domain"], "enterprise-attack")
        self.assertEqual(lay["versions"]["layer"], "4.5")
        self.assertEqual([t["techniqueID"] for t in lay["techniques"]], ["T1105", "T1046"])
        json.dumps(lay)


class AddressingTests(unittest.TestCase):
    def test_classify(self):
        for ip in ("10.1.2.3", "127.0.0.1", "224.0.0.5", "169.254.1.1", "192.168.0.9", "203.0.113.5", "198.18.4.4", "0.0.0.0", "::1", "bad"):
            self.assertTrue(addressing.is_reserved(ip), ip)
            self.assertFalse(addressing.real_mode_check(ip)[0], ip)
        self.assertFalse(addressing.is_reserved("8.8.8.8"))
        self.assertTrue(addressing.real_mode_check("8.8.8.8")[0])

    def test_map_deterministic_pool_and_hostparts(self):
        a = addressing.map_ioc_ip("1.2.3.4", 7)
        self.assertEqual(a, addressing.map_ioc_ip("1.2.3.4", 7))
        self.assertNotEqual(a, addressing.map_ioc_ip("1.2.3.4", 8))
        for i in range(2000):
            m = addressing.map_ioc_ip("9.9.%d.%d" % (i // 250, i % 250), 3)
            self.assertIn(ipaddress.ip_address(m), addressing.MAPPED_POOL)
            self.assertNotIn(m.split(".")[-1], ("0", "255"))

    def test_table_collision_free(self):
        iocs = [ioc("ipv4", "44.%d.%d.%d" % (i // 60000, (i // 250) % 250, i % 250 + 1), "c2") for i in range(6000)]
        iocs += [ioc("domain", "d%d.example.com" % i, "c2") for i in range(500)]
        iocs.append(ioc("url", "http://d1.example.com/x", "payload"))
        iocs.append(ioc("ipv6", "2001:db8::1", "c2"))
        t = addressing.mapped_table(iocs, 5)
        self.assertEqual(len(t), 6500)
        self.assertEqual(len(set(t.values())), len(t))
        self.assertEqual(t, addressing.mapped_table(list(reversed(iocs)), 5))
        self.assertEqual(addressing.unsupported_ipv6(iocs), ["2001:db8::1"])


class SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _ensure_actions()

    def setUp(self):
        self.c = compiler.compile_campaign([ioc("ipv4", "203.0.113.77", "c2")], name="T")

    def test_valid_roundtrip(self):
        self.assertEqual(schema.validate(self.c), [])
        txt = schema.dump(self.c)
        self.assertEqual(schema.dump(schema.load(txt)), txt)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write(txt)
        try:
            self.assertEqual(schema.dump(schema.load(f.name)), txt)
        finally:
            os.unlink(f.name)

    def test_unknown_keys_rejected(self):
        for mut in (lambda c: c.update(evil=1), lambda c: c["meta"].update(x=1), lambda c: c["options"].update(x=1),
                    lambda c: c["iocs"][0].update(x=1), lambda c: c["stages"][0].update(x=1),
                    lambda c: c["stages"][0]["actions"][0].update(x=1),
                    lambda c: c["stages"][0]["actions"][0]["params"].update(not_a_param=1)):
            c = copy.deepcopy(self.c)
            mut(c)
            self.assertTrue(schema.validate(c))

    def test_field_errors(self):
        def bad(mut):
            c = copy.deepcopy(self.c)
            mut(c)
            self.assertTrue(schema.validate(c), "expected an error")
        bad(lambda c: c.update(schema="other/1"))
        bad(lambda c: c["stages"][0].update(tactic="nope"))
        bad(lambda c: c["stages"][0].update(techniques=["T9999"]))
        bad(lambda c: c["stages"][0].update(duration_s=0))
        bad(lambda c: c["stages"][0].update(duration_s=float("nan")))
        bad(lambda c: c["stages"][0]["actions"][0].update(action="rm_rf"))
        bad(lambda c: c["stages"][0]["actions"][0].update(**{"to": "c2:0; drop"}))
        bad(lambda c: c["stages"][0]["actions"][0].update(**{"to": "ioc:99"}))
        bad(lambda c: c["stages"][0]["actions"][0].update(ioc=[5]))
        bad(lambda c: c["stages"][0]["actions"][0].update(at=-1))
        bad(lambda c: c["stages"][0]["actions"][0].update(**{"from": "c2:0"}))   # needs an internal source
        bad(lambda c: c["stages"][0]["actions"][0].update(params={"count": "many"}))
        bad(lambda c: c["iocs"][0].update(value="999.1.1.1"))
        bad(lambda c: c["iocs"][0].update(value="1.2.3.4\n5.6.7.8"))
        bad(lambda c: c["iocs"][0].update(type="exe"))
        bad(lambda c: c["options"].update(speed="warp"))
        bad(lambda c: c["options"].update(beacons_per_c2=9999))
        bad(lambda c: c["options"].update(include=["everything"]))
        bad(lambda c: c["options"].update(start="25:99"))
        bad(lambda c: c["expect"].append({"technique": "T1071.001", "stage": "nope"}))
        bad(lambda c: c["stages"].append(copy.deepcopy(c["stages"][0])))           # duplicate stage id
        bad(lambda c: c.update(stages=[]))
        bad(lambda c: c["meta"].update(name=""))
        bad(lambda c: c["meta"].update(created="yesterday"))
        for junk in (None, [], "x", 5):
            self.assertTrue(schema.validate(junk))

    def test_real_mode_rejects_reserved(self):
        c = copy.deepcopy(self.c)
        c["options"]["address_mode"] = "real"
        self.assertTrue(any("real mode" in e for e in schema.validate(c)))
        c["iocs"][0]["value"] = "8.8.4.4"
        self.assertEqual(schema.validate(c), [])

    def test_size_caps(self):
        c = copy.deepcopy(self.c)
        c["iocs"] = [ioc("ipv4", "8.8.%d.%d" % (i // 250, i % 250 + 1), "unknown") for i in range(5001)]
        self.assertTrue(any("at most 5000" in e for e in schema.validate(c)))
        c = copy.deepcopy(self.c)
        c["stages"] = [dict(copy.deepcopy(self.c["stages"][0]), id="s%d" % i) for i in range(61)]
        self.assertTrue(any("at most 60" in e for e in schema.validate(c)))
        c = copy.deepcopy(self.c)
        a = c["stages"][0]["actions"][0]
        c["stages"] = [dict(copy.deepcopy(self.c["stages"][0]), id="s%d" % i, actions=[copy.deepcopy(a) for _ in range(50)]) for i in range(9)]
        self.assertTrue(any("at most 400" in e for e in schema.validate(c)))

    def test_load_hostile(self):
        for txt in ("{", "[]", "null", '{"schema": NaN}', "x" * 10, "{" * 100000, "[" * 100000):
            with self.assertRaises(schema.CampaignError):
                schema.load(txt if txt.startswith("{") or txt == "{" else txt)
        with self.assertRaises(schema.CampaignError):
            schema.load('{"schema":"opengenerator.campaign/1","pad":"' + "a" * (schema.MAX_BYTES + 10) + '"}')
        with self.assertRaises(schema.CampaignError):
            schema.load("/nonexistent/campaign.json")

    def test_json_schema_file_in_sync(self):
        with open(schema.SCHEMA_FILE, encoding="utf-8") as f:
            self.assertEqual(f.read(), schema.dump(schema.json_schema()))
        js = schema.json_schema()
        self.assertEqual(js["properties"]["options"]["properties"]["beacons_per_c2"]["default"], 4)

    def test_normalise_fills_defaults(self):
        c = schema.normalise({"meta": {"name": "My Camp"}, "iocs": [], "stages": []})
        self.assertEqual(c["options"]["address_mode"], "mapped")
        self.assertEqual(c["meta"]["id"], "my-camp")


class CompilerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _ensure_actions()
        cls.iocs = fixture_iocs()

    def test_fixture_six_stages(self):
        c = compiler.compile_campaign(self.iocs, name="PHP2Shell")
        self.assertEqual([s["name"] for s in c["stages"]], ["Execution", "Command And Control", "Discovery", "Credential Access",
                                                            "Lateral Movement", "Exfiltration"])
        self.assertEqual(schema.validate(c), [])
        for s in c["stages"]:
            self.assertEqual(attack.validate_ids(s["techniques"]), [])
            self.assertTrue(s["techniques"] and s["duration_s"] > 0 and s["fast_s"] > 0)
            for a in s["actions"]:
                self.assertTrue(a["explain"] and (a["ioc"] or a["explain"]))
        self.assertTrue(c["expect"])
        self.assertEqual(c["meta"]["source"]["ioc_count"], len(self.iocs))

    def test_deterministic(self):
        a = schema.dump(compiler.compile_campaign(self.iocs, name="X"))
        b = schema.dump(compiler.compile_campaign(copy.deepcopy(self.iocs), name="X"))
        self.assertEqual(a, b)
        seed = compiler.compile_campaign(self.iocs)["meta"]["seed"]
        self.assertEqual(seed, compiler.compile_campaign(list(reversed(self.iocs)))["meta"]["seed"])
        self.assertNotEqual(seed, compiler.compile_campaign(self.iocs[:-1])["meta"]["seed"])

    def test_mapped_addresses_unique_in_pool(self):
        c = compiler.compile_campaign(self.iocs)
        tab = addressing.mapped_table(c["iocs"], c["meta"]["seed"])
        self.assertTrue(tab)
        self.assertEqual(len(set(tab.values())), len(tab))
        for ip in tab.values():
            self.assertIn(ipaddress.ip_address(ip), addressing.MAPPED_POOL)
        self.assertEqual(tab, addressing.mapped_table(c["iocs"], c["meta"]["seed"]))

    def test_options(self):
        base = [ioc("ipv4", "203.0.113.77", "c2"), ioc("url", "https://a.example.net/x/inv.exe", "payload")]
        c = compiler.compile_campaign(base, {"include": ["impact"]})
        self.assertEqual([s["name"] for s in c["stages"]], ["Execution", "Command And Control", "Impact"])
        c = compiler.compile_campaign(base, {"include": [], "beacons_per_c2": 2})
        self.assertEqual(len(c["stages"]), 2)
        beacon = [a for s in c["stages"] for a in s["actions"] if a["action"].endswith("beacon")][0]
        if "count" in actions.get(beacon["action"]).params:
            self.assertEqual(beacon["params"]["count"], 2)
        dl = c["stages"][0]["actions"][0]
        self.assertEqual(dl["to"], "ioc:1")
        for bad in ({"speed": "warp"}, {"nope": 1}, {"beacons_per_c2": 0}):
            with self.assertRaises(schema.CampaignError):
                compiler.compile_campaign(base, bad)
        self.assertEqual(compiler.compile_campaign(base, {"lateral_target": "FILE1"})["options"]["lateral_target"], "FILE1")

    def test_role_rules(self):
        iocs = [ioc("ipv4", "203.0.113.9", "scanner"), ioc("ipv4", "198.51.100.9", "brute", tags=["rdp"]),
                ioc("ipv4", "203.0.113.50", "tor"), ioc("url", "https://login.example.org/signin", "phishing"),
                ioc("domain", "drop.example.net", "exfil", tags=["dns"]), ioc("ipv4", "198.51.100.77", "c2"),
                ioc("ipv6", "2001:db8::5", "c2"), ioc("ipv4", "192.0.2.4", "payload")]
        c = compiler.compile_campaign(iocs, {"include": list(schema.INCLUDES)})
        self.assertEqual(schema.validate(c), [])
        names = [s["name"] for s in c["stages"]]
        self.assertEqual(names[0], "Initial Access")
        for n in ("Discovery", "Credential Access", "Lateral Movement", "Exfiltration", "Impact"):
            self.assertIn(n, names)
        toks = {a["action"] for s in c["stages"] for a in s["actions"]}
        self.assertTrue({"phishing_visit", "tor_connect", "syn_scan", "rdp_brute", "dns_exfil"} <= toks, toks)
        self.assertTrue(any("IPv6" in n for n in c["explain"]))

    def test_missing_actions_degrade(self):
        reg = {k: v for k, v in actions.all_specs().items() if k not in ("kerberoast", "ldap_recon", "https_upload", "dns_exfil", "ftp_upload")}
        with mock.patch.object(actions, "_REGISTRY", reg):
            c = compiler.compile_campaign([ioc("ipv4", "203.0.113.77", "c2")])
        self.assertEqual(schema.validate(c), [])
        self.assertNotIn("Exfiltration", [s["name"] for s in c["stages"]])
        self.assertTrue(any("kerberoast" in n for n in c["explain"]))
        self.assertTrue(any("ldap_recon" in n for n in c["explain"]))

    def test_invalid_and_real_mode_inputs(self):
        c = compiler.compile_campaign([ioc("ipv4", "300.1.1.1", "c2"), {"type": "domain", "value": "bad domain!", "role": "c2"},
                                       "junk", ioc("ipv4", "203.0.113.77", "c2"), ioc("ipv4", "203.0.113.77", "c2")])
        self.assertEqual(len(c["iocs"]), 1)
        self.assertEqual(schema.validate(c), [])
        c = compiler.compile_campaign([ioc("ipv4", "10.0.0.5", "c2"), ioc("ipv4", "8.8.4.4", "c2")], {"address_mode": "real"})
        self.assertEqual(schema.validate(c), [])
        beacons = [a for s in c["stages"] for a in s["actions"] if a["action"].endswith("beacon")]
        self.assertEqual(len(beacons), 1)
        self.assertEqual(beacons[0]["ioc"], [1])

    def test_caps(self):
        iocs = [ioc("ipv4", "198.51.%d.%d" % (i // 250, i % 250 + 1), "c2") for i in range(40)]
        iocs += [ioc("sha256", "%064x" % i, "payload") for i in range(100)] + [ioc("url", "http://p.example.net/a.exe", "payload")]
        c = compiler.compile_campaign(iocs)
        self.assertEqual(schema.validate(c), [])
        beacons = [a for s in c["stages"] for a in s["actions"] if a["action"].endswith("beacon")]
        self.assertEqual(len(beacons), compiler.MAX_C2)
        self.assertLessEqual(len(c["stages"][0]["actions"][0]["ioc"]), compiler.MAX_PAYLOAD_REFS)
        empty = compiler.compile_campaign([])        # internal-only stages; nothing to exfiltrate to
        self.assertNotIn("Exfiltration", [s["name"] for s in empty["stages"]])
        self.assertTrue(any("exfiltration" in n for n in empty["explain"]))

    def test_explain_lines(self):
        c = compiler.compile_campaign(self.iocs, name="PHP2Shell")
        lines = compiler.explain_campaign(c)
        text = "\n".join(lines)
        self.assertIn("203.0.113.77", text)
        self.assertIn("Command And Control", text)
        self.assertIn("indicator 1 (203.0.113.77)", text)


class VulnerabilityTests(unittest.TestCase):
    CVE = {"type": "cve", "value": "CVE-2024-10441", "role": "vulnerability", "confidence": 95, "source": "kev",
           "tags": ["kev"], "techniques": ["T1190", "T1133"], "first_seen": None, "note": "", "why": ""}

    def test_cve_becomes_expectation_not_traffic(self):
        c = compiler.compile_campaign([self.CVE])
        self.assertEqual([e for e in c["expect"] if e.get("cve")],
                         [{"technique": "T1190", "cve": "CVE-2024-10441"}, {"technique": "T1133", "cve": "CVE-2024-10441"}])
        self.assertFalse([a for st in c["stages"] for a in st["actions"] if 0 in a["ioc"]])    # no action uses the CVE
        self.assertEqual([e for e in schema.validate(c) if "expect" in e], [])
        self.assertNotIn("not used by any action", "\n".join(compiler.explain_campaign(c)))

    def test_expect_needs_stage_or_cve(self):
        c = compiler.compile_campaign([self.CVE, dict(self.CVE, type="ipv4", value="203.0.113.9", role="c2", techniques=[])])
        c["expect"].append({"technique": "T1190"})
        self.assertTrue(any("needs a stage or a cve" in e for e in schema.validate(c)))



if __name__ == "__main__":
    unittest.main()

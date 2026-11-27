"""Tests for malware-family look-alike profiles, the compiler's family assignment and new include options,
the HTML report and the STIX malware object, and the console lines of the M3 actions.

Run from dev/:  python -m unittest tests.test_families
"""
import copy
import inspect
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from netgen.campaign import actions, compiler, console, exports, families, schema  # noqa: E402 - sys.path is set up before the import
from netgen.campaign.actions import c2  # noqa: E402 - sys.path is set up before the import
from netgen.tls import CLIENT_PROFILES  # noqa: E402 - sys.path is set up before the import

actions.load_all()

OLD_PROFILES = ("generic", "cobaltstrike-like", "empire-like", "updater-like")
EXPECTED_IDS = ["cobalt-strike", "sliver", "brute-ratel", "havoc", "meterpreter-http", "qakbot", "emotet", "icedid",
                "asyncrat", "remcos", "lumma-stealer", "generic-rmm"]
NEW_TOKENS = ["web_dir_scan", "subdomain_enum", "new_domain_contact", "selfsigned_tls_contact", "web_login_spray",
              "exposed_service_login", "winrm_exec", "ssh_remote_exec", "remote_schtask", "svcctl_persist", "gpo_modify",
              "privileged_group_add", "eventlog_clear", "lolbin_fetch", "security_service_stop", "security_update_block",
              "sql_collect", "archive_stage", "icmp_tunnel", "cloud_service_c2", "cloud_storage_upload", "smtp_exfil",
              "smb_delete_burst"]


def ioc(typ, value, role, **kw):
    d = {"type": typ, "value": value, "role": role, "confidence": 50, "source": "test", "tags": [], "techniques": [],
         "first_seen": None, "note": "", "why": ""}
    d.update(kw)
    return d


class Lookup(unittest.TestCase):
    def test_all_families_present_and_complete(self):
        self.assertEqual(list(families.FAMILIES), EXPECTED_IDS)
        for fid, f in families.FAMILIES.items():
            for k in ("name", "aliases", "kind", "profile", "interval_s", "jitter", "size_min", "size_max", "tls", "notes"):
                self.assertIn(k, f, (fid, k))
            self.assertIn(f["kind"], ("http", "https", "dns"))
            self.assertIn(f["tls"], CLIENT_PROFILES, fid)
            self.assertEqual(set(f["profile"]), set(c2.PROFILES["generic"]), fid)
            self.assertTrue(f["profile"]["paths"] and f["notes"])
            self.assertLessEqual(f["size_min"], f["size_max"])
            self.assertGreater(f["interval_s"], 0)

    def test_lookup_variants(self):
        for text in ("Cobalt Strike", "cobaltstrike", "COBALT-STRIKE", "cobalt_strike", "CS beacon", " cs  Beacon "):
            self.assertEqual(families.lookup(text)["id"], "cobalt-strike", text)
        self.assertEqual(families.lookup("Lumma Stealer")["id"], "lumma-stealer")
        self.assertEqual(families.lookup("QBot")["id"], "qakbot")
        self.assertEqual(families.lookup("Brute Ratel C4")["id"], "brute-ratel")
        self.assertIsNone(families.lookup("not a family"))
        self.assertIsNone(families.lookup(""))
        self.assertIsNone(families.lookup(None))
        for fid in EXPECTED_IDS:
            self.assertEqual(families.lookup(fid)["id"], fid)

    def test_for_iocs(self):
        self.assertIsNone(families.for_iocs([ioc("ipv4", "198.51.100.1", "c2")]))
        self.assertEqual(families.for_iocs([ioc("ipv4", "198.51.100.1", "c2"),
                                            ioc("ipv4", "198.51.100.2", "c2", tags=["Sliver"])]), "sliver")
        self.assertEqual(families.for_iocs([ioc("ipv4", "198.51.100.2", "c2", note="Emotet epoch 5 C2")]), "emotet")
        self.assertEqual(families.for_iocs([ioc("ipv4", "198.51.100.2", "c2", source="feed:icedid-c2")]), "icedid")
        # a short word must not be read out of free text
        self.assertIsNone(families.for_iocs([ioc("ipv4", "198.51.100.2", "c2", note="the firmware rmm demon")]))
        self.assertEqual(families.for_iocs([ioc("ipv4", "198.51.100.2", "c2", tags=["rmm"])]), "generic-rmm")

    def test_no_real_company_names(self):
        src = inspect.getsource(families)
        for bad in ("Extra" + "Hop", "Vec" + "tra", "Micro" + "soft", "Fire" + "Eye", "Crowd" + "Strike", "Pal" + "o Alto",
                    "os.urandom", "import random", "uuid", "datetime"):
            self.assertNotIn(bad, src)
        for f in families.FAMILIES.values():
            for p in f["profile"]["paths"]:
                self.assertTrue(p.startswith("/"))

    def test_checksum8_paths(self):
        paths = families.FAMILIES["meterpreter-http"]["profile"]["paths"]
        self.assertGreaterEqual(len(paths), 3)
        for p in paths:
            self.assertEqual(sum(map(ord, p[1:])) % 256, 92, p)


class ProfileResolution(unittest.TestCase):
    def test_old_names_unchanged(self):
        for name in OLD_PROFILES:
            self.assertIs(c2._profile(name), c2.PROFILES[name], name)
        self.assertIs(c2._profile(None), c2.PROFILES["generic"])
        self.assertIs(c2._profile("nonsense"), c2.PROFILES["generic"])
        self.assertEqual(sorted(c2.PROFILES), sorted(OLD_PROFILES))
        self.assertEqual(c2.PROFILES["cobaltstrike-like"]["paths"], ["/jquery-3.3.1.min.js"])

    def test_family_resolves(self):
        for fid, f in families.FAMILIES.items():
            self.assertIs(c2._profile(fid), f["profile"])
        self.assertIs(c2._profile("Cobalt Strike"), families.FAMILIES["cobalt-strike"]["profile"])

    def test_help_lists_families(self):
        for tok in ("https_beacon", "http_beacon"):
            h = actions.get(tok).params["profile"]["help"]
            for fid in EXPECTED_IDS:
                self.assertIn(fid, h)
            self.assertIn("cobaltstrike-like", h)

    def test_beacon_request_carries_family_look(self):
        # the request builder is pure given the generator, so check the exact bytes it would send
        import netgen
        netgen.reseed_all()
        prof = c2._profile("meterpreter-http")

        class Src:
            pass
        req, body = c2._beacon_exchange(None, Src(), "c2.example.test", prof, 100, 200, 0.0)
        first = req.split(b"\r\n", 1)[0].decode()
        self.assertRegex(first, r"^GET /[A-Za-z0-9]{4} HTTP/1\.1$")
        self.assertIn(b"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0", req)
        self.assertTrue(100 <= len(body) <= 200)
        prof = c2._profile("havoc")
        req, _b = c2._beacon_exchange(None, Src(), "c2.example.test", prof, 40, 80, 0.0)
        self.assertTrue(req.startswith(b"POST / HTTP/1.1\r\n"))
        self.assertIn(b"Firefox/50.0", req)


class CompilerFamilies(unittest.TestCase):
    def beacons(self, c):
        return [a for s in c["stages"] for a in s["actions"] if a["action"].endswith("beacon")]

    def test_family_tag_assigns_profile(self):
        c = compiler.compile_campaign([ioc("ipv4", "198.51.100.77", "c2", tags=["Cobalt Strike"])])
        self.assertEqual(schema.validate(c), [])
        (b,) = self.beacons(c)
        self.assertEqual(b["action"], "https_beacon")
        self.assertEqual(b["params"]["profile"], "cobalt-strike")
        self.assertIn("Cobalt Strike", b["explain"])
        self.assertEqual(b["params"]["interval_s"], families.FAMILIES["cobalt-strike"]["interval_s"])
        self.assertTrue(any("cobalt-strike" in n for n in c["explain"]))

    def test_http_family_prefers_http_beacon(self):
        c = compiler.compile_campaign([ioc("ipv4", "198.51.100.78", "c2", tags=["meterpreter"])])
        (b,) = self.beacons(c)
        self.assertEqual(b["action"], "http_beacon")
        self.assertEqual(b["params"]["profile"], "meterpreter-http")
        self.assertEqual(schema.validate(c), [])

    def test_no_family_identical_to_before(self):
        plain = [ioc("ipv4", "198.51.100.77", "c2", tags=["botnet"]), ioc("domain", "c2.example.net", "c2")]
        c = compiler.compile_campaign(plain)
        for a in self.beacons(c):
            self.assertEqual(set(a["params"]), {"count"})
        self.assertEqual(schema.dump(c), schema.dump(compiler.compile_campaign(copy.deepcopy(plain))))
        # the older look-alike tag still maps to its preset
        c = compiler.compile_campaign([ioc("ipv4", "198.51.100.77", "c2", tags=["empire"])])
        self.assertEqual(self.beacons(c)[0]["params"]["profile"], "empire-like")

    def test_default_include_unchanged(self):
        self.assertEqual(schema.OPTIONS["include"][1], ["discovery", "credential_access", "lateral_movement", "exfiltration"])
        iocs = [ioc("ipv4", "198.51.100.77", "c2"), ioc("url", "http://p.example.net/a.exe", "payload")]
        c = compiler.compile_campaign(iocs)
        self.assertEqual([s["tactic"] for s in c["stages"]],
                         ["execution", "command-and-control", "discovery", "credential-access", "lateral-movement", "exfiltration"])
        self.assertEqual(c["options"]["include"], ["discovery", "credential_access", "lateral_movement", "exfiltration"])

    def test_new_include_options(self):
        new = ["execution", "persistence", "privilege_escalation", "stealth", "defense_impairment", "collection",
               "reconnaissance", "resource_development"]
        for n in new:
            self.assertIn(n, schema.ALL_INCLUDES)
        iocs = [ioc("ipv4", "203.0.113.9", "scanner"), ioc("domain", "c2.example.net", "c2"), ioc("ipv4", "198.51.100.77", "c2"),
                ioc("url", "http://p.example.net/a.exe", "payload")]
        c = compiler.compile_campaign(iocs, {"include": new + ["initial_access"]})
        self.assertEqual(schema.validate(c), [])
        tactics = [s["tactic"] for s in c["stages"]]
        for t in ("reconnaissance", "resource-development", "execution", "persistence", "privilege-escalation", "stealth",
                  "defense-impairment", "collection"):
            self.assertIn(t, tactics)
        self.assertLess(tactics.index("reconnaissance"), tactics.index("execution"))
        toks = {a["action"] for s in c["stages"] for a in s["actions"]}
        self.assertTrue({"web_dir_scan", "winrm_exec", "remote_schtask", "gpo_modify", "eventlog_clear", "sql_collect",
                         "new_domain_contact", "security_service_stop"} <= toks, toks)
        again = compiler.compile_campaign(copy.deepcopy(iocs), {"include": new + ["initial_access"]})
        self.assertEqual(schema.dump(c), schema.dump(again))
        with self.assertRaises(schema.CampaignError):
            compiler.compile_campaign(iocs, {"include": ["nope"]})

    def test_new_rules_degrade_without_actions(self):
        reg = {k: v for k, v in actions.all_specs().items() if k not in NEW_TOKENS}
        from unittest import mock
        with mock.patch.object(actions, "_REGISTRY", reg):
            c = compiler.compile_campaign([ioc("ipv4", "198.51.100.77", "c2")], {"include": list(schema.ALL_INCLUDES)})
        self.assertEqual(schema.validate(c), [])
        self.assertTrue(any("not available" in n for n in c["explain"]))

    def test_preferred_covers_every_tactic(self):
        from netgen.campaign import attack
        for t in attack.tactics():
            self.assertIn(t["slug"], compiler.PREFERRED, t["slug"])


def _crep(campaign, family=True, hostile=False):
    """A hand-built runner record for the campaign, as the runner would fill it."""
    bad = '<script>alert(1)</script>"&' if hostile else ""
    entries = [
        {"campaign": "x", "stage": "s1", "action": "https_beacon", "from": "ws", "to": "c2:0", "ioc": [0],
         "params": {"count": 4, "profile": "cobalt-strike" if family else "generic"}, "ts": 1773489600.0, "packets": 50,
         "bytes": 9000, "protocols": ["TLS"], "techniques": ["T1071.001"], "status": "ok", "error": None},
        {"campaign": "x", "stage": "s1", "action": "winrm_exec", "from": "ws", "to": "server", "ioc": [], "params": {},
         "ts": 1773489700.0, "packets": 0, "bytes": 0, "protocols": [], "techniques": ["T1021.006"], "status": "skipped",
         "error": "missing host(s) %s" % bad}]
    return {"id": "x", "name": "N" + bad, "meta": campaign["meta"], "options": campaign["options"],
            "stages": [{"id": "s1", "name": "Command And Control" + bad, "tactic": "command-and-control",
                        "techniques": ["T1071.001"], "narrative": "", "start": 1773489600.0, "length_s": 240}],
            "entries": entries,
            "iocs": [{"index": 0, "type": "ipv4", "value": "198.51.100.77" + bad, "role": "c2", "address": "198.18.4.4"}],
            "errors": [{"stage": "s1", "action": "winrm_exec", "error": "x"}, {"error": "note " + bad}]}


class Outputs(unittest.TestCase):
    def setUp(self):
        self.camp = compiler.compile_campaign([ioc("ipv4", "198.51.100.77", "c2", tags=["Cobalt Strike"])], name="Fam")

    def test_html_structure_and_no_active_content(self):
        h = exports.report_html(self.camp, _crep(self.camp))
        self.assertTrue(h.startswith("<!DOCTYPE html>"))
        low = h.lower()
        for bad in ("<script", "http://", "https://", "<link", "<img", "<iframe", "onerror", "onload", "src="):
            self.assertNotIn(bad, low, bad)
        for need in ("Summary", "Stage timeline", "Indicators to flows", "Technique coverage", "Malware family",
                     "Not in the capture", "Mapped address mode", "198.18.4.4", "Cobalt Strike", "T1071.001", "T1021.006"):
            self.assertIn(need, h, need)
        self.assertEqual(h.count("<table>"), h.count("</table>"))
        self.assertEqual(h.count("<tr>"), h.count("</tr>"))

    def test_html_escapes_feed_content(self):
        camp = copy.deepcopy(self.camp)
        camp["meta"]["name"] = '<script>alert(1)</script>"&'
        camp["meta"]["description"] = "<img src=x onerror=alert(1)>"
        h = exports.report_html(camp, _crep(camp, hostile=True))
        self.assertNotIn("<script", h)
        self.assertNotIn("<img", h)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&amp;", h)

    def test_html_without_family_or_real_mode(self):
        camp = copy.deepcopy(self.camp)
        camp["options"]["address_mode"] = "real"
        h = exports.report_html(camp, _crep(camp, family=False))
        self.assertIn("No family look-alike profile was used", h)
        self.assertIn("Real address mode", h)
        self.assertEqual(exports.families_used(camp, _crep(camp, family=False)), [])
        self.assertEqual(exports.families_used(camp, _crep(camp)), ["cobalt-strike"])

    def test_empty_report(self):
        h = exports.report_html({"meta": {}, "options": {}}, {"id": "e", "entries": [], "stages": [], "iocs": [], "errors": []})
        self.assertIn("</html>", h)

    def test_stix_malware_only_when_family_used(self):
        b = exports.stix_bundle(self.camp, _crep(self.camp))
        kinds = [o["type"] for o in b["objects"]]
        self.assertEqual(kinds.count("malware"), 1)
        m = [o for o in b["objects"] if o["type"] == "malware"][0]
        self.assertEqual(m["name"], "Cobalt Strike")
        self.assertTrue(m["is_family"])
        rels = [o for o in b["objects"] if o["type"] == "relationship"]
        self.assertEqual(len(rels), 1)
        self.assertEqual(rels[0]["target_ref"], m["id"])
        ids = {o["id"] for o in b["objects"]}
        self.assertIn(rels[0]["source_ref"], ids)
        self.assertEqual(b, exports.stix_bundle(self.camp, _crep(self.camp)))      # deterministic
        none = exports.stix_bundle(self.camp, _crep(self.camp, family=False))
        self.assertNotIn("malware", [o["type"] for o in none["objects"]])

    def test_write_all_writes_html(self):
        with tempfile.TemporaryDirectory() as d:
            paths = exports.write_all(self.camp, {"campaigns": [_crep(self.camp)], "entries": [], "errors": []}, os.path.join(d, "out"))
            self.assertEqual(set(paths), {"campaign", "stix", "navigator", "report", "html", "csv", "misp"})
            self.assertTrue(paths["html"].endswith(".report.html"))
            for p in paths.values():
                self.assertTrue(os.path.getsize(p) > 0, p)
            with open(paths["stix"]) as f:
                json.load(f)


class ConsoleLines(unittest.TestCase):
    def test_every_new_action_has_its_own_line(self):
        for tok in NEW_TOKENS:
            self.assertIn(tok, console.COMMANDS, tok)
            e = {"action": tok, "from": "ws", "to": "server", "params": {}, "from_host": {"ip": "10.1.1.5", "name": "WS-009"},
                 "to_host": {"ip": "10.1.1.9", "name": "FILE1"}}
            line = console.command_line(e)
            self.assertTrue(line.startswith("$ "))
            self.assertNotIn(tok, line, tok)                      # a real command phrase, not the generic fallback
            self.assertIn("10.1.1.", line)
            e["params"] = {"count": 5, "port": 8443}
            self.assertTrue(console.command_line(e).startswith("$ "))

    def test_unknown_keeps_generic(self):
        line = console.command_line({"action": "mystery", "from": "a", "to": "b", "params": {"x": 1}})
        self.assertEqual(line, "$ mystery x=1 a -> b")

    def test_no_product_names(self):
        src = inspect.getsource(console)
        for bad in ("wevtutil", "sqlcmd", "winrs", "schtasks", "Micro" + "soft", "Extra" + "Hop"):
            self.assertNotIn(bad, src)

class TestFamilyOption(unittest.TestCase):
    IOC = {"type": "ipv4", "value": "8.8.4.4", "role": "c2", "confidence": 50, "source": "t", "tags": [],
           "techniques": [], "first_seen": None, "note": "", "why": ""}

    def _profile(self, family, tags=()):
        from netgen.campaign import compiler
        ioc = dict(self.IOC, tags=list(tags))
        c = compiler.compile_campaign([ioc], {"family": family})
        return [a["params"].get("profile") for s in c["stages"] for a in s["actions"] if a["action"].endswith("_beacon")][0]

    def test_family_option(self):
        self.assertIsNone(self._profile("auto"))
        self.assertEqual(self._profile("sliver"), "sliver")
        self.assertEqual(self._profile("auto", ["Cobalt Strike"]), "cobalt-strike")
        self.assertNotEqual(self._profile("none", ["Cobalt Strike"]), "cobalt-strike")


if __name__ == "__main__":
    unittest.main()

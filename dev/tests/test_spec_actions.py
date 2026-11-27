"""Actions defined as data (netgen/campaign/actions/spec_actions.py): validation, loading, and the capture they make."""
import copy
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from checks.tshark_locate import find_tshark
from netgen.core import PcapWriter
from netgen.identity import H
from netgen.campaign import actions as A
from netgen.campaign.actions import meta, spec_actions as S
from tests.test_actions_a import T0, _urandom_patch, check_packet, ext_host, make_world

TSHARK = find_tshark()
GOOD = {"token": "unit_spec_probe", "title": "Unit spec", "tactic": "reconnaissance", "techniques": ["T1595.003"],
        "summary": "A test exchange.", "direction": "inbound", "tls": False, "port": 80, "repeat": 2, "gap_s": 0.2,
        "requests": [{"method": "GET", "path": "/a", "status": "404 Not Found", "reply": "nope"},
                     {"method": "POST", "path": "/b", "body": "x=1", "status": "403 Forbidden"}]}


def dump(obj, path):
    with open(path, "w") as fh:
        fh.write(obj if isinstance(obj, str) else json.dumps(obj))


def bad(**kw):
    s = copy.deepcopy(GOOD)
    s.update(kw)
    return s


class TestValidate(unittest.TestCase):
    def test_good(self):
        self.assertEqual(S.validate(GOOD), [])
        with open(os.path.join(os.path.dirname(S.__file__), "specs", "admin_panel_probe.json")) as fh:
            self.assertEqual(S.validate(json.load(fh)), [])

    def test_rejects_hostile_or_wrong_input(self):
        r0 = GOOD["requests"][0]
        cases = [bad(token="Bad Token"), bad(tactic="nonsense"), bad(techniques=["T9999"]), bad(direction="sideways"),
                 bad(port=70000), bad(repeat=500), bad(gap_s=0), bad(extra="x"), bad(requests=[]),
                 bad(requests=[dict(r0, path="/a b")]), bad(requests=[dict(r0, path="a")]),
                 bad(requests=[dict(r0, reply="\x00\x01bin")]), bad(requests=[dict(r0, reply="é")]),
                 bad(requests=[dict(r0, headers=["Host: evil"])]), bad(requests=[dict(r0, headers=["X: a\r\nInjected: 1"])]),
                 bad(requests=[dict(r0, method="CONNECT")]), bad(requests=[dict(r0, status="999")]),
                 bad(requests=[dict(r0, body="a" * 3000)]), bad(requests=[dict(r0, nope=1)]), "not an object"]
        for c in cases:
            self.assertNotEqual(S.validate(c), [], c)
        self.assertNotEqual(S.validate(GOOD, taken={"unit_spec_probe"}), [])


class TestLoad(unittest.TestCase):
    def test_load_registers_valid_and_reports_invalid(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.addCleanup(lambda: A._REGISTRY.pop("unit_spec_probe", None))
        dump(GOOD, os.path.join(d, "good.json"))
        dump(bad(token="unit_spec_bad", tactic="nope"), os.path.join(d, "bad.json"))
        dump("{not json", os.path.join(d, "broken.json"))
        self.assertEqual(S.load([d]), ["unit_spec_probe"])
        self.assertEqual(sorted(f for f, _ in S.LOAD_ERRORS), ["bad.json", "broken.json"])
        self.assertIn("unit_spec_probe", A.all_specs())
        self.assertTrue(meta.complete(S.meta_records()["unit_spec_probe"]))
        self.assertNotIn("unit_spec_bad", A.all_specs())

    def test_bundled_example_registered_with_metadata(self):
        A.load_all()
        self.assertIn("admin_panel_probe", A.all_specs())
        self.assertEqual(meta.missing(), [])


class TestWire(unittest.TestCase):
    def _pcap(self):
        A.load_all()
        ctx = make_world()
        with _urandom_patch():
            pk = A.get("admin_panel_probe").fn(ctx, ext_host("198.18.30.9", "a.example"), ctx.h[H("WEB1")], ts=T0)
        for _, f in pk:
            self.assertEqual(check_packet(f), [])
        return pk

    def test_packets_valid(self):
        self.assertTrue(self._pcap())

    @unittest.skipUnless(TSHARK, "tshark not installed")
    def test_dissected_as_specified(self):
        pk = self._pcap()
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "p.pcap")
        w = PcapWriter(path)
        for ts, f in sorted(pk, key=lambda p: p[0]):
            w.write(ts, f)
        w.close()

        def fields(flt, *fs):
            cmd = [TSHARK, "-r", path, "-o", "tcp.check_checksum:TRUE", "-Y", flt, "-T", "fields"]
            for f in fs:
                cmd += ["-e", f]
            return [l.split("\t") for l in subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout.splitlines()]
        self.assertEqual(fields('_ws.malformed || tcp.checksum.status == "Bad"', "frame.number"), [])
        self.assertEqual([r[0] for r in fields("http.request", "http.request.uri")], ["/admin", "/administrator/", "/manager/html", "/wp-login.php"])
        self.assertEqual([r[0] for r in fields("http.response", "http.response.code")], ["401", "404", "401", "404"])


TCP = {"kind": "tcp", "token": "unit_tcp_probe", "title": "Unit mail probe", "tactic": "reconnaissance", "techniques": ["T1595"],
       "summary": "A plain-text mail greeting and a refused relay.", "direction": "inbound", "port": 25, "repeat": 1,
       "gap_s": 0.2, "banner": "220 mail.example ESMTP ready\\r\\n",
       "exchanges": [{"send": "EHLO scanner.example\\r\\n", "reply": "250 mail.example hello\\r\\n"},
                     {"send": "MAIL FROM:<a@scanner.example>\\r\\n", "reply": "250 ok\\r\\n"},
                     {"send": "RCPT TO:<b@elsewhere.example>\\r\\n", "reply": "550 relay denied\\r\\n"}]}


class TestTcpKind(unittest.TestCase):
    def test_validate(self):
        self.assertEqual(S.validate(TCP), [])
        self.assertTrue(S.validate(dict(TCP, tls=True)))
        self.assertTrue(S.validate(dict(TCP, requests=[])))
        self.assertTrue(S.validate(dict(TCP, exchanges=[])))
        self.assertTrue(S.validate(dict(TCP, exchanges=[{"send": "a\x00b"}])))
        self.assertTrue(S.validate(dict(TCP, exchanges=[{"send": "x", "extra": 1}])))
        self.assertTrue(S.validate(dict(TCP, kind="udp")))

    @unittest.skipUnless(TSHARK, "tshark not installed")
    def test_wire_is_smtp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.addCleanup(lambda: A._REGISTRY.pop("unit_tcp_probe", None))
        dump(TCP, os.path.join(d, "t.json"))
        self.assertEqual(S.load([d]), ["unit_tcp_probe"])
        self.assertTrue(meta.complete(S.meta_records()["unit_tcp_probe"]))
        ctx = make_world()
        with _urandom_patch():
            pk = A.get("unit_tcp_probe").fn(ctx, ext_host("198.18.30.9", "a.example"), ctx.h[H("WEB1")], ts=T0)
        path = os.path.join(d, "p.pcap")
        w = PcapWriter(path)
        for ts, f in sorted(pk, key=lambda p: p[0]):
            self.assertEqual(check_packet(f), [])
            w.write(ts, f)
        w.close()
        out = subprocess.run([TSHARK, "-r", path, "-Y", "smtp.req.command || smtp.response.code", "-T", "fields",
                              "-e", "smtp.req.command", "-e", "smtp.response.code"], capture_output=True, text=True, timeout=120).stdout
        self.assertIn("EHLO", out)
        self.assertIn("RCPT", out)
        self.assertIn("550", out)


class TestAutoPlacement(unittest.TestCase):
    def test_for_role_validates(self):
        self.assertEqual(S.validate(bad(for_role="scanner")), [])
        self.assertTrue(S.validate(bad(for_role="nope")))

    def test_compiler_places_a_for_role_spec_and_leaves_others_alone(self):
        from netgen.campaign import compiler
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.addCleanup(lambda: (A._REGISTRY.pop("unit_spec_probe", None), S._PLACE.pop("unit_spec_probe", None)))
        iocs = [{"type": "ipv4", "value": "203.0.113.50", "role": "scanner", "confidence": 80, "source": "t", "why": "w"}]
        opts = {"include": ["reconnaissance"]}
        before = compiler.compile_campaign(iocs, options=opts)
        dump(dict(GOOD, for_role="scanner"), os.path.join(d, "g.json"))
        S.load([d])
        after = compiler.compile_campaign(iocs, options=opts)
        toks = [a["action"] for st in after["stages"] for a in st["actions"]]
        self.assertIn("unit_spec_probe", toks)
        self.assertNotIn("unit_spec_probe", [a["action"] for st in before["stages"] for a in st["actions"]])
        act = [a for st in after["stages"] for a in st["actions"] if a["action"] == "unit_spec_probe"][0]
        self.assertEqual(act["ioc"], [0])
        self.assertTrue(compiler.observability(after)[0]["observable"])
        stage = [st for st in after["stages"] if st["tactic"] == "reconnaissance"][0]
        self.assertIn("T1595.003", stage["techniques"])


if __name__ == "__main__":
    unittest.main()

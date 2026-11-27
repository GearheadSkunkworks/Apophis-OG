"""Compose options table (ui/build-options.json), the new generate-body fields and the /api/slice route."""
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import campaign_api                      # noqa: E402 - sys.path is set up first
import opengenerator_build as OB         # noqa: E402 - sys.path is set up first
import server                            # noqa: E402 - sys.path is set up first
import test_slice_pcap as TS             # noqa: E402 - reuses its synthetic build

UI = os.path.join(DEV, "ui")
with open(os.path.join(UI, "build-options.json"), encoding="utf-8") as _f:
    TABLE = json.load(_f)
with open(os.path.join(UI, "index.html"), encoding="utf-8") as _f:
    HTML = _f.read()


def default_payload(row):
    """What the page would send for this row switched on with every parameter at its default."""
    p = {q["id"]: q["default"] for q in row.get("params", [])}
    if row["api"]["field"] == "exports":
        return [row["api"]["key"]]
    o = {}
    for q in row.get("params", []):
        if q["api"] and all(p.get(k) == v for k, v in (q.get("when") or {}).items()):
            o[q["api"]] = q["default"]
    return {row["api"]["key"]: o}


class TestOptionsTable(unittest.TestCase):
    def test_every_row_maps_to_a_real_build_option(self):
        ids = [r["id"] for r in TABLE["options"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate row id")
        groups = {g["id"] for g in TABLE["groups"]}
        for r in TABLE["options"]:
            for k in ("id", "group", "label", "help", "control", "default", "api"):
                self.assertIn(k, r, r.get("id"))
            self.assertIn(r["group"], groups)
            self.assertIs(r["default"], False, "new options are off by default: " + r["id"])
            self.assertEqual(r["control"], "toggle")
            self.assertIn(r["api"]["field"], ("network_options", "exports"))
            self.assertTrue(r["help"].endswith("."), "one-line help: " + r["id"])
            if r["api"]["field"] == "exports":
                self.assertIn(r["api"]["key"], OB.EXPORT_NAMES)
                self.assertEqual(r["group"], "exports")
            else:
                # the engine's own normaliser accepts what the row sends by default, and rejects a typo
                OB.normalize_network_options(default_payload(r))
                with self.assertRaises(ValueError):
                    OB.normalize_network_options({r["api"]["key"] + "x": True})
                self.assertEqual(r["group"], "network")

    def test_every_engine_export_has_a_row(self):
        have = {r["api"]["key"] for r in TABLE["options"] if r["api"]["field"] == "exports"}
        self.assertEqual(have, set(OB.EXPORT_NAMES), "a new EXPORT_NAMES entry needs one row in ui/build-options.json")

    def test_vlan_params_cover_the_engine_keys(self):
        vlan = next(r for r in TABLE["options"] if r["id"] == "vlan")
        keys = {q["api"] for q in vlan["params"] if q["api"]}
        self.assertEqual(keys, {"scheme", "vid", "qinq"})
        for q in vlan["params"]:
            if q["control"] == "number":
                self.assertEqual((q["min"], q["max"]), (1, 4094))
        for scheme in ("subnet", "fixed"):
            for qinq in (False, True):
                v = {"scheme": scheme}
                if scheme == "fixed":
                    v["vid"] = 100
                if qinq:
                    v["qinq"] = 100
                self.assertEqual(OB.normalize_network_options({"vlan": v})["vlan"]["scheme"], scheme)

    def test_estimate_figures_are_measured_numbers(self):
        for r in TABLE["options"]:
            e = r.get("est", {})
            for k, v in e.items():
                self.assertIn(k, ("bytes_per_packet", "pcap_ratio", "seconds_per_mpackets"), r["id"])
                self.assertGreaterEqual(v, 0)
            if r["api"]["field"] == "exports":
                self.assertGreater(e.get("pcap_ratio", 0) + e.get("seconds_per_mpackets", 0), 0, "unmeasured export: " + r["id"])

    def test_files_are_served_loaded_and_free_of_html_injection(self):
        for name in ("build-options.js", "build-options.json", "slice-preview.js"):
            self.assertIn(name, campaign_api.STATIC_FILES)
            status, body, _ctype, _ = campaign_api.static_file(name, UI)
            self.assertEqual(status, 200)
            self.assertTrue(body)
        self.assertIn('src="/ui/build-options.js"', HTML)
        self.assertIn('src="/ui/slice-preview.js"', HTML)
        for f in ("build-options.js", "slice-preview.js"):
            with open(os.path.join(UI, f), encoding="utf-8") as fh:
                self.assertNotRegex(fh.read(), r"innerHTML|outerHTML|insertAdjacentHTML|document\.write")
        for i in ("netopts", "expopts", "netopts-sum", "expopts-sum", "rrecords", "rrec-list", "rresume", "rmaxsleep",
                  "rinc-a", "rinc-b", "rlabel", "rnote", "slcap", "slscn", "slkind", "slctx", "slgo"):
            self.assertEqual(len(re.findall(r'id="%s"' % i, HTML)), 1, i)

    def test_the_page_sends_options_only_through_the_table(self):
        self.assertIn("OGOptionsCore.collect(OGOPT.table, OGOPT.state)", HTML)
        # the one replay start path is startReplay behind the acknowledgement
        self.assertEqual(len(re.findall(r"/api/replay/start", HTML)), 1)
        self.assertEqual(len(re.findall(r"/api/replay/records", HTML)), 1)


class Routes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="og-ui-opts-")
        self.addCleanup(shutil.rmtree, self.d, True)

    def post(self, path, body):
        rq = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                    headers={"Content-Type": "application/json",
                                             "Cookie": "og_ui=" + server.UI_SECRET})
        try:
            r = urllib.request.urlopen(rq, timeout=30)
        except urllib.error.HTTPError as e:
            r = e
        with r:
            return r.status, json.loads(r.read())

    def gen(self, **extra):
        started = []
        with mock.patch.object(server, "run_generator", side_effect=lambda *a, **k: started.append((a, k))):
            st, body = self.post("/api/generate", dict({"scale": 0.02, "out_dir": self.d, "modules": []}, **extra))
            for t in threading.enumerate():
                if t is not threading.current_thread() and t.daemon and t.name.startswith("Thread"):
                    t.join(2)
        with server.LOCK:
            server.STATE["running"] = False
        return st, body, started

    def test_defaults_pass_nothing_new_to_the_build(self):
        st, _b, started = self.gen()
        self.assertEqual(st, 200)
        self.assertEqual(started[0][1], {})

    def test_exports_and_network_options_reach_the_build(self):
        st, _b, started = self.gen(exports=["pcapng", "truth", "truth"], network_options={"vlan": {"scheme": "fixed", "vid": 20, "qinq": 100}})
        self.assertEqual(st, 200)
        kw = started[0][1]
        self.assertEqual(kw["exports"], ["pcapng", "truth"])
        self.assertEqual(kw["network_options"], {"vlan": {"scheme": "fixed", "vid": 20, "qinq": 100}})

    def test_vlan_off_is_the_same_as_absent(self):
        st, _b, started = self.gen(network_options={"vlan": False}, exports=[])
        self.assertEqual((st, started[0][1]), (200, {}))

    def test_bad_exports_and_options_are_400_and_start_nothing(self):
        for extra in ({"exports": "truth"}, {"exports": ["nope"]}, {"exports": [1]}, {"exports": ["truth"] * 50},
                      {"network_options": "vlan"}, {"network_options": {"vlan": {"scheme": "fixed"}}},
                      {"network_options": {"vlan": {"scheme": "fixed", "vid": 5000}}}, {"network_options": {"vlan": {"scheme": "subnet", "vid": 3}}},
                      {"network_options": {"vlan": "bad"}}, {"network_options": {"vlans": True}}, {"network_options": {"vlan": {"qinq": "x"}}}):
            st, body, started = self.gen(**extra)
            self.assertEqual(st, 400, extra)
            self.assertIn("error", body)
            self.assertEqual(started, [], extra)

    def make_build(self):
        pcap, _m = TS.make_build(self.d)
        return pcap

    def slice(self, first, **kw):   # kw overrides any body field, pcap included
        with mock.patch.object(server, "DEFAULT_OUT", self.d):
            body = {"pcap": first, "scenario": "t1", "kind": "A", "ctx": 5}
            body.update(kw)
            return self.post("/api/slice", body)

    def test_slice_cuts_a_window_and_returns_the_sidecar(self):
        pcap = self.make_build()
        st, body = self.slice(pcap)
        self.assertEqual(st, 200, body)
        s = body["slice"]
        self.assertEqual((s["kind"], s["scenario"], s["source_packets"]), ("A", "t1", len(TS.PKTS)))
        self.assertTrue(os.path.isfile(s["pcap_out"]) and os.path.isfile(s["json_out"]))
        self.assertEqual(os.path.dirname(s["pcap_out"]), self.d)

    def test_slice_b_and_c_use_the_tag_sidecar(self):
        pcap = self.make_build()
        for kind in ("B", "C"):
            st, body = self.slice(pcap, kind=kind.lower(), baseline="none" if kind == "B" else None)
            self.assertEqual(st, 200, body)
            self.assertEqual(body["slice"]["kind"], kind)

    def test_slice_input_validation(self):
        pcap = self.make_build()
        other = tempfile.mkdtemp(prefix="og-ui-other-")
        self.addCleanup(shutil.rmtree, other, True)
        shutil.copy(pcap, other)
        shutil.copy(pcap[:-5] + ".manifest.json", other)
        for bad in ({"kind": "D"}, {"kind": ""}, {"scenario": ""}, {"scenario": 5}, {"scenario": "x" * 500}, {"scenario": "nosuch"},
                    {"ctx": -1}, {"ctx": 1e9}, {"ctx": True}, {"ctx": "5"}, {"baseline": "most"}, {"pcap": ""}, {"pcap": "relative.pcap"},
                    {"pcap": os.path.join(other, "b.pcap")}, {"pcap": pcap[:-5] + ".manifest.json"}, {"pcap": pcap + "\x00"}):
            st, body = self.slice(pcap, **bad)
            self.assertEqual(st, 400, bad)
            self.assertIn("error", body)
        self.assertEqual([n for n in os.listdir(self.d) if ".slice." in n], [])

    def test_slice_refuses_a_symlinked_pcap(self):
        pcap = self.make_build()
        link = os.path.join(self.d, "link.pcap")
        os.symlink(pcap, link)
        shutil.copy(pcap[:-5] + ".manifest.json", os.path.join(self.d, "link.manifest.json"))
        st, _b = self.slice(link)
        self.assertEqual(st, 400)

    def test_slice_is_not_an_agent_verb(self):
        import agent_api
        self.assertFalse([v for v in agent_api.VERBS.values() if isinstance(v, str) and "slice" in v])


if __name__ == "__main__":
    unittest.main()

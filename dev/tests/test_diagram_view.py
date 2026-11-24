"""Tests for the campaign diagram view model, panels, page and API entry (worker VIEW).

    python3 -m unittest tests.test_diagram_view
"""
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from diagrams.campaign import api, narrate, page, view as V          # noqa: E402
from diagrams.campaign.panels import coverage, filters, stages, timeline, trace   # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures", "campaigns")


def camp(name="Test campaign", **extra):
    c = {"schema": "opengenerator.campaign/1",
         "meta": {"name": name, "seed": 3, "description": "A small test campaign", "actor": "Test actor"},
         "options": {},
         "iocs": [{"type": "domain", "value": "c2.bad.example", "role": "c2"},
                  {"type": "sha256", "value": "a" * 64, "role": "payload"},
                  {"type": "ipv4", "value": "203.0.113.9", "role": "exfil"}],
         "stages": [
             {"id": "s1", "name": "Beacon out", "tactic": "command-and-control", "techniques": ["T1071.001"],
              "narrative": "The foothold checks in.", "duration_s": 300,
              "actions": [{"action": "https_beacon", "from": "ws", "to": "c2:0", "params": {"count": 5}}]},
             {"id": "s2", "name": "Look around", "tactic": "discovery", "techniques": ["T1046"], "duration_s": 60,
              "actions": [{"action": "syn_scan", "from": "ws", "to": "server"}]}],
         "expect": []}
    c.update(extra)
    return c


def fake_summary(c, status=None, packets=40):
    status = status or {}
    entries, i = [], 0
    for st in c["stages"]:
        for a in st["actions"]:
            s = status.get(i, "ok")
            entries.append({"campaign": "x", "stage": st["id"], "action": a["action"], "from": a["from"], "to": a["to"],
                            "ioc": [0] if a["to"].startswith("c2") else [], "params": dict(a.get("params") or {}),
                            "ts": 1000.0 + i * 30, "packets": packets if s == "ok" else 0,
                            "bytes": packets * 100 if s == "ok" else 0, "protocols": ["TLS"], "techniques": [],
                            "status": s, "error": None if s == "ok" else "no host for this role",
                            "from_host": {"name": "WS-047", "ip": "10.1.0.47"} if a["from"] == "ws" else
                            {"name": "ATTACKER", "ip": "198.18.0.5"},
                            "to_host": {"name": "WEB1", "ip": "10.2.0.20"} if a["to"] == "server" else
                            {"name": "C2", "ip": "198.18.0.9"}})
            i += 1
    return {"entries": entries, "iocs": [{"index": 0, "address": "198.18.0.9"}], "estimate": {"flows": 6},
            "errors": [], "emitted": {}}


def big(n):
    stg = [{"id": "s%d" % i, "name": "Stage %d" % i, "tactic": ["discovery", "collection"][i % 2 // 1 if i < 40 else 0],
            "techniques": ["T1046"], "duration_s": 30,
            "actions": [{"action": "syn_scan", "from": "ws", "to": "server"}]} for i in range(n)]
    return camp(stages=stg)


class ViewTests(unittest.TestCase):
    def test_plan_mode_has_no_run_data(self):
        v = V.build(camp())
        self.assertEqual(v["mode"], "plan")
        self.assertIsNone(v["totals"]["packets"])
        for a in v["actions"]:
            self.assertIsNone(a["packets"])
            self.assertIsNone(a["ts"])
            self.assertEqual(a["status"], "planned")
        self.assertTrue(all(e["state"] == "planned" and e["packets"] is None for e in v["edges"]))
        self.assertEqual([s["start_s"] for s in v["stages"]], [0.0, 310.0])
        json.dumps(v)                                         # JSON-serialisable

    def test_run_mode_counts_and_states(self):
        c = camp()
        v = V.build(c, fake_summary(c, {1: "skipped"}))
        self.assertEqual(v["mode"], "run")
        self.assertEqual(v["totals"]["packets"], 40)
        self.assertEqual([s["state"] for s in v["stages"]], ["ok", "skipped"])
        self.assertTrue(any(n["title"].startswith("1 action(s) skipped") for n in v["notes"]))
        self.assertTrue(any(t["emitted"] for t in v["techniques"]))
        self.assertFalse([t for t in v["techniques"] if t["id"] == "T1046" and t["emitted"]])

    def test_edges_aggregate_and_nodes(self):
        c = camp()
        c["stages"][0]["actions"].append(dict(c["stages"][0]["actions"][0]))
        v = V.build(c)
        e = [x for x in v["edges"] if x["proto"] == "TLS"]
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["port"], 443)
        self.assertEqual(len(e[0]["actions"]), 2)
        zones = {n["zone"] for n in v["nodes"]}
        self.assertIn("internet", zones)
        self.assertTrue(any(n["address_kind"] == "mapped" and n["address"] for n in v["nodes"] if n["zone"] == "internet"))

    def test_iocs_on_wire_rules(self):
        v = V.build(camp())
        by = {r["type"]: r for r in v["iocs"]}
        self.assertTrue(by["domain"]["on_wire"])
        self.assertFalse(by["sha256"]["on_wire"])
        self.assertFalse(by["ipv4"]["on_wire"])              # no action uses it
        self.assertEqual(by["sha256"]["address_kind"], "none")

    def test_scored_mode(self):
        c = camp()
        score = {"score": {"testable": 2, "detected": 1, "partial": 0, "missed": 1, "percent": 50},
                 "techniques": [{"technique": "T1071.001", "status": "detected"},
                                {"technique": "T1046", "status": "missed"}],
                 "actions": [{"stage": "s1", "action": "https_beacon", "status": "detected"},
                             {"stage": "s2", "action": "syn_scan", "status": "missed"}], "sensor": "lab"}
        v = V.build(c, fake_summary(c), score)
        self.assertEqual(v["mode"], "scored")
        self.assertEqual({t["id"]: t["score"] for t in v["techniques"]}, {"T1071.001": "detected", "T1046": "missed", "T1573.002": None})
        self.assertEqual([a["score"] for a in v["actions"]], ["detected", "missed"])

    def test_vulnerability_only(self):
        c = camp(stages=[], iocs=[{"type": "cve", "value": "CVE-2024-12345", "role": "vulnerability"}],
                 expect=[{"technique": "T1190", "cve": "CVE-2024-12345"}])
        v = V.build(c)
        self.assertEqual(v["vulns"], [{"cve": "CVE-2024-12345", "techniques": ["T1190"]}])
        html = page.render(c)
        self.assertIn("Expected, no traffic".upper(), html.upper())
        self.assertNotIn("bands are stages", html)
        self.assertNotIn("What each stage does", html)
        self.assertIn("CVE-2024-12345", html)
        self.assertIn("No traffic", html)

    def test_filters_render_and_drop(self):
        tpl = [("beacon", "ip.src=={src_ip} && tls.handshake.extensions_server_name=={fqdn}", "x"),
               ("port", "tcp.port=={p:port}", "y"), ("any", "udp", "z")]
        out = V.render_filters(tpl, "10.0.0.1", "10.0.0.2", "", {"port": 443})
        self.assertEqual([f["filter"] for f in out], ["tcp.port==443", "udp"])
        out = V.render_filters(tpl, "10.0.0.1", None, "a.example", {})
        self.assertEqual(len(out), 2)

    def test_defensive_when_collaborators_missing(self):
        with mock.patch.object(V, "_resolver", return_value=None), mock.patch.object(V, "_meta_get", return_value=None):
            v = V.build(camp())
        self.assertEqual(len(v["actions"]), 2)
        self.assertTrue(all(a["plain"] for a in v["actions"]))      # falls back to ActionSpec.summary
        self.assertTrue(all(a["filters"] == [] for a in v["actions"]))
        html = page.render(camp())
        self.assertIn("Beacon out", html)


class PanelTests(unittest.TestCase):
    def setUp(self):
        self.ctx = V.make_ctx()

    def test_narrate_sentence_count_and_trace(self):
        v = V.build(camp())
        items = narrate.plain(v)
        self.assertTrue(3 <= len(items) <= 5, items)
        ids = {s["id"] for s in v["stages"]}
        for it in items:
            self.assertTrue(set(it["refs"]) <= ids)
        self.assertEqual(items, narrate.plain(V.build(camp())))      # deterministic

    def test_timeline_modes(self):
        p = timeline.render(V.build(camp()), self.ctx)
        self.assertIn("+0:00", p["svg"])
        c = camp()
        p2 = timeline.render(V.build(c, fake_summary(c)), self.ctx)
        self.assertIn("10:00", p2["svg"])
        self.assertTrue(p["svg"].count("<line") > 8)                 # beacon cadence strip is drawn
        self.assertIsNone(timeline.render(V.build(camp(stages=[])), self.ctx))

    def test_large_campaign_summaries(self):
        v = V.build(big(40))
        st = stages.render(v, self.ctx)
        self.assertIn("<table", st["html"])
        self.assertNotIn("cd-card", st["html"])
        self.assertLessEqual(len(timeline.render(v, self.ctx)["alt"]), timeline.MAX_ROWS)
        v2 = V.build(big(3))
        self.assertIn("cd-card", stages.render(v2, self.ctx)["html"])

    def test_trace_states_mode_and_carried(self):
        p = trace.render(V.build(camp()), self.ctx)
        self.assertIn("Mapped addressing", p["sub"])
        self.assertIn("Carried, not on the wire", p["html"])
        self.assertIn("a" * 64, p["html"])
        c = camp(options={"address_mode": "real"})
        self.assertIn("Real addressing", trace.render(V.build(c), self.ctx)["sub"])
        self.assertIsNone(trace.render(V.build(camp(iocs=[], stages=[])), self.ctx))

    def test_coverage_columns(self):
        p = coverage.render(V.build(camp()), self.ctx)
        self.assertIn("T1071.001", p["svg"])
        self.assertIn("COMMAND AND CONTROL", p["svg"].upper())

    def test_filters_dedupe(self):
        c = camp()
        c["stages"][0]["actions"].append(dict(c["stages"][0]["actions"][0]))
        v = V.build(c)
        rows = filters.collect(v)
        self.assertEqual(len({r["filter"] for r in rows}), len(rows))


class PageTests(unittest.TestCase):
    def test_plan_page(self):
        html = page.render(camp())
        for s in ("Plan: nothing has been generated yet", "In plain terms", "Timeline", "Stages", "Indicator trace",
                  "ATT&amp;CK coverage", "Device role may shift"):
            self.assertIn(s, html)
        self.assertNotIn("Packets</span>", html)
        self.assertNotIn("<script", html)
        self.assertEqual(html, page.render(camp()))                  # deterministic

    def test_run_page_shows_packets(self):
        c = camp()
        html = page.render(c, fake_summary(c))
        self.assertIn("Run: from this capture", html)
        self.assertIn("Packets", html)

    def test_scored_page(self):
        c = camp()
        score = {"score": {"testable": 2, "detected": 1, "partial": 0, "missed": 1, "percent": 50},
                 "techniques": [{"technique": "T1071.001", "status": "detected"}], "actions": [], "sensor": "lab"}
        html = page.render(c, fake_summary(c), score)
        self.assertIn("Scored against lab; read-only", html)
        self.assertIn("50%", html)

    def test_escaping(self):
        c = camp(name="<script>alert(1)</script>")
        c["stages"][0]["name"] = "<img src=x onerror=1>"
        c["stages"][0]["narrative"] = "\"><b>x</b>"
        html = page.render(c)
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<b>x</b>", html)

    def test_company_relabel_runs(self):
        self.assertIn("Beacon out", page.render(camp(), company="Acme Freight"))

    def test_overview_page(self):
        html = page.render([camp("One"), camp("Two")])
        self.assertIn("Campaign overview", html)
        self.assertIn("One", html)
        self.assertIn("Merged ATT&amp;CK coverage", html)

    def test_fixtures_if_present(self):
        names = sorted(f for f in os.listdir(FIXTURES) if f.endswith(".json") and not f.endswith((".summary.json", ".score.json"))
                       and f != "forms.json") if os.path.isdir(FIXTURES) else []
        for n in names:
            with self.subTest(n):
                with open(os.path.join(FIXTURES, n)) as f:
                    data = json.load(f)
                if not isinstance(data, dict) or "stages" not in data:
                    continue
                sp = os.path.join(FIXTURES, n[:-5] + ".summary.json")
                summary = json.load(open(sp)) if os.path.exists(sp) else None
                summary = (summary or {}).get("campaign", summary) if summary else None
                html = page.render(data, summary)
                self.assertIn("<html", html)


class ApiTests(unittest.TestCase):
    def test_ok(self):
        self.assertIn("<html", api.campaign_diagram({"campaign": camp()}))
        self.assertIn("<html", api.campaign_diagram({"campaign": [camp("A"), {"campaign": camp("B")}]}))

    def test_bad_input_one_line(self):
        for body in (None, [], {}, {"campaign": 3}, {"campaign": {"schema": "x"}}, {"campaign": camp(), "summary": 3},
                     {"campaign": camp(), "score": []}, {"campaign": camp(), "company": 5}, {"campaign": []}):
            with self.subTest(body=body):
                with self.assertRaises(ValueError) as cm:
                    api.campaign_diagram(body)
                self.assertNotIn("\n", str(cm.exception))


if __name__ == "__main__":
    unittest.main()

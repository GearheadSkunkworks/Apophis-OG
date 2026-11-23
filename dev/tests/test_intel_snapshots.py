"""Frozen feed snapshots: one neutral, invented response per feed id in intel.sources.FEEDS.

Each file under tests/fixtures/intel/snapshots/ has the shape of what that feed's `parse` receives
(the raw response, or for the multi-call feeds the assembled form: a list of MISP event files, or an
OTX `results` list with each pulse's indicators attached). The tests pin the parse result (counts per
type and per role) and check that compiling a campaign from the same snapshot twice gives
byte-identical campaign JSON. No network: the multi-call fetch paths run against a stubbed http_get.

Run from dev/:  python -m unittest tests.test_intel_snapshots
"""
import collections
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
if DEV not in sys.path:
    sys.path.insert(0, DEV)

from intel import describe, filters, sources                     # noqa: E402
from netgen.campaign import compiler, schema           # noqa: E402

SNAP = os.path.join(HERE, "fixtures", "intel", "snapshots")

# feed id -> (file, record count, {type: n}, {role: n})
EXPECTED = {
    "circl": ("circl.json", 12, {"ipv4": 4, "domain": 2, "url": 2, "sha256": 2, "cve": 2},
              {"c2": 6, "payload": 2, "scanner": 2, "vulnerability": 2}),
    "otx": ("otx.json", 10, {"ipv4": 2, "ipv6": 1, "domain": 2, "url": 1, "sha256": 1, "md5": 1, "cve": 1, "email": 1},
            {"c2": 2, "payload": 5, "vulnerability": 1, "phishing": 1, "scanner": 1}),
    "url": ("url.txt", 4, {"url": 1, "domain": 1, "ipv4": 1, "cve": 1}, {"unknown": 2, "c2": 1, "vulnerability": 1}),
    "threatfox": ("threatfox.json", 5, {"ipv4": 1, "domain": 1, "url": 1, "sha256": 1, "md5": 1}, {"c2": 2, "payload": 3}),
    "urlhaus": ("urlhaus.json", 2, {"url": 2}, {"payload": 2}),
    "c2intel-ip": ("c2intel-ip.csv", 3, {"ipv4": 3}, {"c2": 3}),
    "c2intel-domain": ("c2intel-domain.csv", 2, {"domain": 2}, {"c2": 2}),
    "blocklist-ssh": ("blocklist-ssh.txt", 4, {"ipv4": 3, "ipv6": 1}, {"brute": 4}),
    "blocklist-login": ("blocklist-login.txt", 2, {"ipv4": 2}, {"brute": 2}),
    "blocklist-mail": ("blocklist-mail.txt", 2, {"ipv4": 2}, {"brute": 2}),
    "cins-army": ("cins-army.txt", 3, {"ipv4": 3}, {"scanner": 3}),
    "ipsum": ("ipsum.txt", 3, {"ipv4": 3}, {"scanner": 3}),
    "phishing-db-ips": ("phishing-db-ips.txt", 3, {"ipv4": 3}, {"phishing": 3}),
    "phishing-db-domains": ("phishing-db-domains.txt", 2, {"domain": 2}, {"phishing": 2}),
    "phishtank": ("phishtank.csv", 2, {"url": 2}, {"phishing": 2}),
    "dshield": ("dshield.json", 2, {"ipv4": 2}, {"scanner": 2}),
    "spamhaus-drop": ("spamhaus-drop.json", 2, {"ipv4": 2}, {"scanner": 2}),
    "shodan": ("shodan.json", 4, {"ipv4": 2, "cve": 2}, {"unknown": 2, "vulnerability": 2}),
    "siberkapan": ("siberkapan.json", 4, {"ipv4": 3, "ipv6": 1}, {"scanner": 3, "unknown": 1}),
    "infoblox": ("infoblox.json", 12, {"ipv4": 4, "domain": 2, "url": 2, "sha256": 2, "cve": 2},
                 {"c2": 6, "payload": 2, "scanner": 2, "vulnerability": 2}),
    "honeynet-ssh": ("honeynet-ssh.txt", 2, {"ipv4": 2}, {"brute": 2}),
    "honeynet-telnet": ("honeynet-telnet.txt", 2, {"ipv4": 2}, {"brute": 2}),
    "honeynet-urls": ("honeynet-urls.txt", 2, {"url": 2}, {"payload": 2}),
    "cert-pl": ("cert-pl.txt", 3, {"domain": 3}, {"phishing": 3}),
    "tor-exit": ("tor-exit.txt", 3, {"ipv4": 3}, {"tor": 3}),
    "openphish": ("openphish.txt", 3, {"url": 3}, {"phishing": 3}),
    "cisa-kev": ("cisa-kev.json", 3, {"cve": 3}, {"vulnerability": 3}),
}


def raw_of(fid):
    with open(os.path.join(SNAP, EXPECTED[fid][0]), encoding="utf-8") as f:
        return f.read()


class SnapshotCoverage(unittest.TestCase):
    def test_one_snapshot_per_feed(self):
        self.assertEqual(sorted(EXPECTED), sorted(sources.FEEDS))
        self.assertEqual(len(sources.FEEDS), 27)
        for fid, (fn, *_rest) in EXPECTED.items():
            self.assertTrue(os.path.isfile(os.path.join(SNAP, fn)), fn)

    def test_snapshots_are_neutral(self):
        for fid, (fn, *_rest) in EXPECTED.items():
            text = raw_of(fid).lower()
            for word in ("extra" + "hop", "reveal" + "x", "ac" + "me", "crowd" + "strike", "mandi" + "ant", "micro" + "soft"):
                self.assertNotIn(word, text, fn)


class SnapshotParse(unittest.TestCase):
    def test_parse_counts_roles_types(self):
        for fid, (_fn, n, types, roles) in EXPECTED.items():
            with self.subTest(feed=fid):
                recs = sources.FEEDS[fid].parse(raw_of(fid))
                self.assertEqual(len(recs), n)
                self.assertEqual(dict(collections.Counter(r["type"] for r in recs)), types)
                self.assertEqual(dict(collections.Counter(r["role"] for r in recs)), roles)
                for r in recs:
                    self.assertEqual(set(r), {"type", "value", "role", "confidence", "source", "tags", "techniques",
                                              "first_seen", "note", "why"})
                    self.assertTrue(0 <= r["confidence"] <= 100)

    def test_every_feed_yields_wire_traffic_and_says_what_it_gives(self):
        """A feed stays only if it delivers indicators the campaign can put on the wire, and its `gives`
        statement names every type its snapshot holds."""
        word = {"ipv4": "IP address", "ipv6": "IPv6", "domain": "domain", "url": "URL", "cve": "CVE",
                "sha256": "hash", "md5": "hash", "email": "e-mail"}
        for fid, (_fn, _n, types, _roles) in EXPECTED.items():
            with self.subTest(feed=fid):
                kept = describe.annotate(sources.FEEDS[fid].parse(raw_of(fid)), [])[0]
                self.assertTrue(kept, "no indicator of this feed can send traffic")
                self.assertTrue(sources.FEEDS[fid].why)
                gives = sources.FEEDS[fid].gives
                for t in types:
                    self.assertIn(word[t].lower(), gives.lower(), t)

    def test_parse_is_repeatable(self):
        for fid in EXPECTED:
            with self.subTest(feed=fid):
                a = json.dumps(sources.FEEDS[fid].parse(raw_of(fid)), sort_keys=True)
                b = json.dumps(sources.FEEDS[fid].parse(raw_of(fid)), sort_keys=True)
                self.assertEqual(a, b)

    def test_feed_specific_facts(self):
        kev = {r["value"]: r for r in sources.FEEDS["cisa-kev"].parse(raw_of("cisa-kev"))}
        self.assertIn("ransomware", kev["CVE-2025-1111"]["tags"])
        self.assertIn("T1190", kev["CVE-2025-1111"]["techniques"])
        self.assertIn("T1203", kev["CVE-2025-2222"]["techniques"])
        tf = sources.FEEDS["threatfox"].parse(raw_of("threatfox"))
        self.assertIn("port:8443", tf[0]["tags"])
        otx = sources.FEEDS["otx"].parse(raw_of("otx"))
        self.assertIn("T1566.001", otx[0]["techniques"])
        self.assertNotIn("C:\\Temp\\drop.exe", [r["value"] for r in otx])
        fr = [r for r in sources.FEEDS["c2intel-ip"].parse(raw_of("c2intel-ip")) if "domain-fronting" in r["tags"]]
        self.assertEqual(len(fr), 1)
        self.assertEqual(fr[0]["confidence"], 30)


class SnapshotCompile(unittest.TestCase):
    def _compile(self, fid):
        recs = sources.FEEDS[fid].parse(raw_of(fid))
        kept, _dropped = filters.clean(recs)
        camp = compiler.compile_campaign(kept, name="Snapshot " + fid)
        return camp, kept

    def test_compile_twice_is_byte_identical(self):
        for fid in EXPECTED:
            with self.subTest(feed=fid):
                a, kept = self._compile(fid)
                b, _ = self._compile(fid)
                self.assertEqual(schema.dump(a), schema.dump(b))
                self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
                self.assertEqual(schema.validate(a), [])
                self.assertEqual(a["meta"]["source"]["ioc_count"], len(a["iocs"]))
                self.assertLessEqual(len(a["iocs"]), len(kept))

    def test_compile_from_all_snapshots_together(self):
        allrecs = []
        for fid in sorted(EXPECTED):
            allrecs += sources.FEEDS[fid].parse(raw_of(fid))
        kept, _ = filters.clean(allrecs)
        a = compiler.compile_campaign(kept, name="All snapshots")
        b = compiler.compile_campaign(list(kept), name="All snapshots")
        self.assertEqual(schema.dump(a), schema.dump(b))
        self.assertEqual(schema.validate(a), [])
        self.assertGreater(len(a["stages"]), 2)


class MultiCallFeeds(unittest.TestCase):
    """The two feeds whose fetch makes several calls, with http_get stubbed."""

    def test_misp_feed_fetch_assembles_events(self):
        events = json.loads(raw_of("circl"))
        by_uuid = {e["Event"]["uuid"]: e for e in events}
        manifest = {u: {"timestamp": str(1769904000 + i)} for i, u in enumerate(by_uuid)}

        def fake(url, **kw):
            if url.endswith("manifest.json"):
                return json.dumps(manifest).encode()
            return json.dumps(by_uuid[url.rsplit("/", 1)[1][:-5]]).encode()
        with mock.patch.object(sources, "http_get", fake):
            got = sources.fetch("circl", limit=500, cache=False)
        self.assertEqual(len(got), EXPECTED["circl"][1])
        self.assertTrue(all(r["source"] == "circl" for r in got))

    def test_otx_per_pulse_indicator_calls(self):
        pulses = json.loads(raw_of("otx"))["results"]
        indicators = {p["id"]: p["indicators"] for p in pulses}
        search = {"count": len(pulses), "results": [{k: v for k, v in p.items() if k != "indicators"} for p in pulses]}
        calls = []

        def fake(url, **kw):
            calls.append(url)
            self.assertEqual(kw["headers"].get("X-OTX-API-KEY"), "test-key")
            if "/search/pulses" in url:
                return json.dumps(search).encode()
            pid = url.split("/pulses/")[1].split("/")[0]
            return json.dumps({"count": len(indicators[pid]), "next": None, "results": indicators[pid]}).encode()
        with mock.patch.object(sources, "http_get", fake):
            got = sources.fetch("otx", limit=100, key="test-key", cache=False)
        self.assertEqual(len(calls), 1 + len(pulses))
        self.assertEqual(len(got), EXPECTED["otx"][1])
        direct = sources.FEEDS["otx"].parse(raw_of("otx"))
        self.assertEqual(sorted(r["value"] for r in got), sorted(r["value"] for r in direct))

    def test_keyed_feeds_via_fetch_stub(self):
        for fid in ("threatfox", "urlhaus", "shodan"):
            with self.subTest(feed=fid):
                data = raw_of(fid).encode()
                with mock.patch.object(sources, "http_get", lambda *a, **k: data):
                    got = sources.fetch(fid, limit=100, key="test-key", cache=False)
                self.assertEqual(len(got), EXPECTED[fid][1])


if __name__ == "__main__":
    unittest.main()

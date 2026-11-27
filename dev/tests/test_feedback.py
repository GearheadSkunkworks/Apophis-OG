"""Campaign feedback: scoring, the sensor provider's detection listing, and the M4 routes.

Everything runs on fixtures and mocks. No test may open a socket to a sensor or any other host:
urllib's opener is replaced with a function that fails the test if it is ever reached.
"""
import json
import os
import sys
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import campaign_api                                     # noqa: E402 - sys.path is set up before the import
from sensorops import feedback                          # noqa: E402 - sys.path is set up before the import
from sensorops.provider import SensorProvider           # noqa: E402 - sys.path is set up before the import
try:
    from sensorops.providers.network_sensor import NetworkSensorProvider  # noqa: E402 - sys.path is set up before the import
except ImportError:                                  # public builds do not ship the vendor connector
    NetworkSensorProvider = None


def setUpModule():
    if NetworkSensorProvider is None:
        raise unittest.SkipTest("the sensor connector is not installed")

HERE = os.path.dirname(os.path.abspath(__file__))
T0 = 1700000000
KEY = "k3y-SECRET-value-123"


def _no_network(*a, **k):
    raise AssertionError("a test tried to open a network connection")


def fixture():
    with open(os.path.join(HERE, "fixtures", "detections_sample.json")) as f:
        return json.load(f)


def entries():
    return [
        {"stage": "s1", "stage_name": "Execution", "action": "payload_run", "status": "ok",
         "ts": T0, "first_ts": T0, "last_ts": T0 + 20, "techniques": ["T1204.002"],
         "from_host": {"name": "ws-01", "ip": "10.1.1.5"}, "to_host": {"name": "ws-01", "ip": "10.1.1.5"},
         "ioc": []},
        {"stage": "s2", "stage_name": "C2", "action": "https_beacon", "status": "ok",
         "ts": T0 + 300, "first_ts": T0 + 300, "last_ts": T0 + 360, "techniques": ["T1071.001"],
         "from_host": {"name": "ws-01", "ip": "10.1.1.5"}, "to_host": {"name": "c2", "ip": "198.18.4.7"},
         "ioc": [0]},
        {"stage": "s3", "stage_name": "Exfil", "action": "https_upload", "status": "ok",
         "ts": T0 + 700, "first_ts": T0 + 700, "last_ts": T0 + 760, "techniques": ["T1041"],
         "from_host": {"name": "ws-01", "ip": "10.1.1.5"}, "to_host": {"name": "x", "ip": "198.18.9.9"},
         "ioc": []},
        {"stage": "s4", "stage_name": "Impact", "action": "encrypt", "status": "skipped",
         "ts": T0 + 1100, "first_ts": T0 + 1100, "last_ts": T0 + 1100, "techniques": ["T1486"],
         "from_host": {}, "to_host": {}, "ioc": []},
    ]


IOCS = [{"index": 0, "value": "c2.example.net", "role": "c2", "address": "198.18.4.7"}]
STAGES = [{"id": "s1", "name": "Execution", "tactic": "execution"},
          {"id": "s2", "name": "C2", "tactic": "command-and-control"},
          {"id": "s3", "name": "Exfil", "tactic": "exfiltration"},
          {"id": "s4", "name": "Impact", "tactic": "impact"}]
EXPECT = [{"technique": "T1573.002", "stage": "s2"},
          {"technique": "T1003", "stage": "s4"},                 # stage did not run: not testable
          {"technique": "T1190", "cve": "CVE-2024-1234"}]        # CVE level: never testable


def run(dets=None, ents=None, **kw):
    kw.setdefault("slack_s", 60)
    return feedback.score(entries() if ents is None else ents, IOCS, EXPECT, STAGES,
                          fixture() if dets is None else dets, **kw)


def by_tech(res):
    return {t["technique"]: t for t in res["techniques"]}


class NoNetwork(unittest.TestCase):
    def setUp(self):
        for p in (mock.patch.object(urllib.request, "urlopen", _no_network),
                  mock.patch("sensorops.providers.network_sensor._urlopen", _no_network)):
            p.start()
            self.addCleanup(p.stop)


# ---------------------------------------------------------------- scoring
class TestRelation(unittest.TestCase):
    def test_parent_and_sub_both_ways(self):
        self.assertTrue(feedback._related("T1071", "T1071.001"))
        self.assertTrue(feedback._related("T1071.001", "T1071"))
        self.assertTrue(feedback._related("T1071.001", "T1071.001"))
        self.assertFalse(feedback._related("T1071.001", "T1071.004"))
        self.assertFalse(feedback._related("T1071", "T1059"))
        self.assertFalse(feedback._related("T1071", None))

    def test_technique_ids_are_read_leniently(self):
        self.assertEqual(feedback._tid("t1071.001"), "T1071.001")
        self.assertEqual(feedback._tid({"id": "T1041"}), "T1041")
        self.assertEqual(feedback._tid("MITRE T1566 phishing"), "T1566")
        self.assertIsNone(feedback._tid(5))
        self.assertIsNone(feedback._tid({}))

    def test_percent_rounds_half_up_and_survives_zero(self):
        self.assertEqual(feedback._pct(0, 0, 0), 0)
        self.assertEqual(feedback._pct(0, 1, 4), 13)           # 12.5 -> 13, not banker's 12
        self.assertEqual(feedback._pct(0, 1, 3), 17)
        self.assertEqual(feedback._pct(1, 1, 2), 75)


class TestNormalise(unittest.TestCase):
    def test_full_record(self):
        d = feedback.normalise_detection(fixture()[0])
        self.assertEqual(d["id"], 101)
        self.assertEqual(d["techniques"], ["T1071"])
        self.assertEqual(d["tactics"], ["command-and-control"])
        self.assertEqual(d["participants"], ["10.1.1.5", "198.18.4.7"])
        self.assertEqual((d["start_ms"], d["end_ms"]), (1700000310000, 1700000330000))
        self.assertEqual(d["risk"], 80)
        self.assertFalse(d["matched"])

    def test_seconds_are_converted_and_ms_are_kept(self):
        d = feedback.normalise_detection(fixture()[1])
        self.assertEqual((d["start_ms"], d["end_ms"]), (1700000710000, 1700000740000))
        self.assertEqual(d["tactics"], ["exfiltration"])
        self.assertEqual(d["techniques"], ["T1041"])           # plain string accepted

    def test_missing_fields_never_raise(self):
        d = feedback.normalise_detection({"id": 106})
        self.assertEqual((d["techniques"], d["participants"], d["risk"]), ([], [], 0))
        self.assertIsNone(d["start_ms"])
        for junk in ({}, {"start_time": "soon", "mitre_techniques": "T1071", "participants": [None, 3, {}],
                          "risk_score": "high", "categories": [1, None]}):
            feedback.normalise_detection(junk)
        self.assertIsNone(feedback.normalise_detection("x"))

    def test_null_fields_from_a_real_record_shape(self):
        d = feedback.normalise_detection({
            "id": 7, "title": "t", "type": "custom", "status": None, "resolution": None,
            "assignee": None, "ticket_id": None, "categories": [], "mitre_tactics": [],
            "mitre_techniques": [], "risk_score": 55, "start_time": 1700000000000,
            "end_time": 1700000001000, "create_time": 1700000000000, "participants": None,
            "description": None})
        self.assertEqual((d["techniques"], d["tactics"], d["participants"], d["risk"]), ([], [], [], 55))
        self.assertEqual(d["title"], "t")
        d = feedback.normalise_detection({"id": 8, "title": None, "type": None, "categories": None,
                                          "mitre_techniques": None, "mitre_tactics": None})
        self.assertEqual((d["title"], d["type"], d["categories"]), ("", "", []))

    def test_start_falls_back_to_end_then_update_time(self):
        self.assertEqual(feedback.normalise_detection({"end_time": 1700000000})["start_ms"], 1700000000000)
        self.assertEqual(feedback.normalise_detection({"update_time": 1700000000})["end_ms"], 1700000000000)

    def test_reversed_span_is_swapped(self):
        d = feedback.normalise_detection({"start_time": 1700000100, "end_time": 1700000000})
        self.assertLess(d["start_ms"], d["end_ms"])


class TestScore(unittest.TestCase):
    def test_sample_end_to_end(self):
        r = run()
        sc = r["score"]
        self.assertEqual((sc["testable"], sc["detected"], sc["partial"], sc["missed"], sc["percent"]),
                         (4, 2, 2, 0, 75))
        t = by_tech(r)
        self.assertEqual(t["T1071.001"]["status"], "detected")        # parent T1071 matches the sub
        self.assertEqual(t["T1041"]["status"], "detected")            # seconds-valued detection
        self.assertEqual(t["T1204.002"]["status"], "related")         # host and time only
        self.assertEqual(t["T1573.002"]["status"], "related")         # stage-level expectation
        self.assertNotIn("T1003", t)                                  # its stage never ran
        self.assertNotIn("T1486", t)                                  # skipped entry
        self.assertEqual(t["T1071.001"]["stages"], ["s2"])
        self.assertEqual(t["T1071.001"]["actions"], ["https_beacon"])
        self.assertEqual(t["T1071.001"]["tactic"], "command-and-control")
        self.assertIn(101, t["T1071.001"]["detections"])
        self.assertTrue(t["T1071.001"]["note"])

    def test_actions(self):
        a = run()["actions"]
        self.assertEqual([x["status"] for x in a], ["related", "detected", "detected", "not_run"])
        self.assertEqual(a[3]["detections"], [])
        self.assertEqual(a[0]["action"], "payload_run")

    def test_unmatched_and_matched_flags(self):
        r = run()
        by_id = {d["id"]: d for d in r["detections"]}
        self.assertTrue(by_id[101]["matched"])
        self.assertEqual(by_id[101]["matched_actions"], [1])
        self.assertFalse(by_id[104]["matched"])                  # far outside every window
        self.assertFalse(by_id[105]["matched"])                  # T1071.004 is not T1071.001's relative
        self.assertFalse(by_id[106]["matched"])                  # no fields at all
        self.assertEqual(r["unmatched"], 3)
        self.assertEqual(r["count"], 7)

    def test_cve_expectations_excluded_from_score(self):
        r = run()
        self.assertEqual(r["vulnerabilities"]["count"], 1)
        self.assertIn("no traffic exercises a CVE", r["vulnerabilities"]["note"])
        self.assertNotIn("T1190", by_tech(r))
        self.assertEqual(r["score"]["testable"], 4)

    def test_by_tactic(self):
        bt = run()["score"]["by_tactic"]
        self.assertEqual(bt["command-and-control"]["testable"], 2)   # T1071.001 + T1573.002
        self.assertEqual(bt["command-and-control"]["detected"], 1)
        self.assertEqual(bt["command-and-control"]["percent"], 75)
        self.assertEqual(bt["exfiltration"]["percent"], 100)
        self.assertEqual(bt["execution"]["percent"], 50)

    def test_zero_testable_techniques(self):
        for ents in ([], [dict(e, status="skipped") for e in entries()],
                     [{"status": "ok", "ts": T0, "techniques": []}], None):
            r = run(ents=ents if ents is not None else [])
            self.assertEqual(r["score"]["testable"], 0)
            self.assertEqual(r["score"]["percent"], 0)
            self.assertEqual(r["score"]["by_tactic"], {})
            self.assertEqual(r["techniques"], [])

    def test_no_detections(self):
        r = run(dets=[])
        self.assertEqual((r["score"]["detected"], r["score"]["partial"], r["score"]["missed"]), (0, 0, 4))
        self.assertEqual(r["score"]["percent"], 0)
        self.assertEqual([a["status"] for a in r["actions"]], ["missed"] * 3 + ["not_run"])

    def test_slack_widens_the_window(self):
        late = [{"id": 1, "start_time": (T0 + 360 + 500) * 1000, "end_time": (T0 + 360 + 510) * 1000,
                 "mitre_techniques": [{"id": "T1071.001"}]}]
        self.assertEqual(by_tech(run(dets=late, slack_s=60))["T1071.001"]["status"], "missed")
        self.assertEqual(by_tech(run(dets=late, slack_s=600))["T1071.001"]["status"], "detected")

    def test_overlap_at_the_edges(self):
        edge = [{"id": 1, "start_time": (T0 + 360 + 60) * 1000, "end_time": (T0 + 360 + 70) * 1000,
                 "mitre_techniques": [{"id": "T1071.001"}]}]            # starts exactly at window end
        self.assertEqual(by_tech(run(dets=edge, slack_s=60))["T1071.001"]["status"], "detected")
        over = [{"id": 1, "start_time": (T0 + 100) * 1000, "end_time": (T0 + 900) * 1000,
                 "mitre_techniques": [{"id": "T1071.001"}]}]            # spans the whole campaign
        self.assertEqual(by_tech(run(dets=over, slack_s=0))["T1071.001"]["status"], "detected")

    def test_offset_shifts_the_capture_clock(self):
        shifted = []
        for d in fixture()[:3]:
            n = feedback.normalise_detection(d)           # ms, whatever unit the record used
            shifted.append(dict(d, start_time=n["start_ms"] + 5000000,
                                end_time=n["end_ms"] + 5000000))
        self.assertEqual(run(dets=shifted)["score"]["detected"], 0)
        self.assertEqual(run(dets=shifted, offset_s=5000)["score"]["detected"], 2)
        # a negative offset moves the window earlier
        early = [dict(d, start_time=d["start_time"] - 3600000, end_time=d["end_time"] - 3600000)
                 for d in fixture()[:1]]
        self.assertEqual(run(dets=early, offset_s=-3600)["score"]["detected"], 1)

    def test_entry_times_in_milliseconds_are_understood(self):
        ents = [dict(e, ts=e["ts"] * 1000, first_ts=e["first_ts"] * 1000, last_ts=e["last_ts"] * 1000)
                for e in entries()]
        self.assertEqual(run(ents=ents)["score"], run()["score"])

    def test_entry_with_only_ts_has_a_window(self):
        ents = [{"stage": "s2", "action": "x", "status": "ok", "ts": T0 + 300, "techniques": ["T1071.001"]}]
        self.assertEqual(by_tech(run(ents=ents))["T1071.001"]["status"], "detected")

    def test_participant_only_match_is_related(self):
        only_host = [{"id": 1, "start_time": (T0 + 310) * 1000, "end_time": (T0 + 320) * 1000,
                      "mitre_techniques": [], "participants": [{"ipaddr": "198.18.4.7"}]}]
        r = run(dets=only_host)
        self.assertEqual(by_tech(r)["T1071.001"]["status"], "related")
        self.assertEqual(r["actions"][1]["status"], "related")

    def test_indicator_address_counts_as_a_participant(self):
        ents = [{"stage": "s2", "action": "x", "status": "ok", "first_ts": T0, "last_ts": T0 + 5,
                 "techniques": ["T1071.001"], "from_host": {}, "to_host": {}, "ioc": [0]}]
        d = [{"id": 1, "start_time": T0, "end_time": T0 + 1, "participants": [{"ipaddr": "198.18.4.7"}]}]
        self.assertEqual(by_tech(run(dets=d, ents=ents))["T1071.001"]["status"], "related")
        # an ioc index that points nowhere is ignored
        ents[0]["ioc"] = [99, "x", None, True]
        self.assertEqual(by_tech(run(dets=d, ents=ents))["T1071.001"]["status"], "missed")

    def test_technique_match_without_time_overlap_is_not_a_match(self):
        far = [{"id": 1, "start_time": (T0 + 90000) * 1000, "end_time": (T0 + 90010) * 1000,
                "mitre_techniques": [{"id": "T1071.001"}]}]
        self.assertEqual(by_tech(run(dets=far))["T1071.001"]["status"], "missed")

    def test_detection_without_a_time_never_matches(self):
        d = [{"id": 1, "mitre_techniques": [{"id": "T1071.001"}]}]
        r = run(dets=d)
        self.assertEqual(r["unmatched"], 1)
        self.assertEqual(r["score"]["detected"], 0)

    def test_min_risk_drops_weak_detections(self):
        only_weak = [d for d in fixture() if d["id"] == 107]
        self.assertEqual(by_tech(run(dets=only_weak))["T1071.001"]["status"], "detected")
        r = run(dets=only_weak, min_risk=20)
        self.assertEqual(by_tech(r)["T1071.001"]["status"], "missed")
        self.assertEqual((r["count"], r["below_min_risk"]), (0, 1))

    def test_sub_technique_not_credited_for_a_sibling(self):
        d = [{"id": 1, "start_time": (T0 + 310) * 1000, "end_time": (T0 + 320) * 1000,
              "mitre_techniques": [{"id": "T1071.004"}]}]
        self.assertNotEqual(by_tech(run(dets=d))["T1071.001"]["status"], "detected")

    def test_a_detection_matching_two_actions_lists_both(self):
        d = [{"id": 1, "start_time": T0, "end_time": T0 + 800, "mitre_techniques": [],
              "participants": [{"ipaddr": "10.1.1.5"}]}]
        self.assertEqual(run(dets=d)["detections"][0]["matched_actions"], [0, 1, 2])

    def test_hostile_inputs_do_not_raise(self):
        for args in ((None, None, None, None, None), ("x", 5, {}, 3, "y"),
                     ([None, 3, "x", {}], [None], [None, {"technique": 5}], [None], [None, 3, {"id": 1}])):
            r = feedback.score(*args)
            self.assertEqual(r["score"]["percent"], 0)
        r = feedback.score(entries(), IOCS, EXPECT, STAGES, fixture(),
                           offset_s="x", slack_s=None, min_risk="y")
        self.assertIn("score", r)
        r = feedback.score([{"status": "ok", "techniques": ["T1071"], "first_ts": "bad",
                             "from_host": "nope", "ioc": "nope"}], [], [{"stage": 1}], [{"id": None}], fixture())
        self.assertEqual(r["score"]["detected"], 0)

    def test_output_is_json_serialisable(self):
        json.dumps(run())


class TestWindow(unittest.TestCase):
    def test_covers_ok_entries_with_slack_and_lookahead(self):
        lo, hi = feedback.query_window(entries(), offset_s=0, slack_s=600, lookahead_s=1800)
        self.assertEqual(lo, (T0 - 600) * 1000)
        self.assertEqual(hi, (T0 + 760 + 600 + 1800) * 1000)       # the skipped entry is not counted

    def test_offset_and_none(self):
        lo, _ = feedback.query_window(entries(), offset_s=100, slack_s=0, lookahead_s=0)
        self.assertEqual(lo, (T0 + 100) * 1000)
        self.assertIsNone(feedback.query_window([], 0, 0, 0))
        self.assertIsNone(feedback.query_window([{"status": "ok"}], 0, 0, 0))
        self.assertIsNone(feedback.query_window("x"))


# ---------------------------------------------------------------- provider
class TestProvider(NoNetwork):
    def test_base_class_default_raises(self):
        class P(SensorProvider):
            pass
        self.assertFalse(getattr(SensorProvider.list_detections, "__isabstractmethod__", False))
        with self.assertRaises(NotImplementedError):
            SensorProvider.list_detections(object(), 0, 1)

    def make(self):
        return NetworkSensorProvider("sensor.example.net", KEY)

    def test_request_shape(self):
        p = self.make()
        with mock.patch.object(NetworkSensorProvider, "_req", return_value=(200, [])) as rq:
            self.assertEqual(p.list_detections(1000, 2000), [])
        path = rq.call_args[0][0]
        self.assertEqual(path, "/detections/search")
        self.assertEqual(rq.call_args[1]["method"], "POST")
        body = rq.call_args[1]["body"]
        self.assertEqual((body["from"], body["until"], body["offset"]), (1000, 2000, 0))

    def test_pages_until_short_page(self):
        p = self.make()
        pages = [[{"id": i} for i in range(500)], [{"id": 500 + i} for i in range(500)],
                 [{"id": 1000}, "junk", None]]
        calls = []

        def fake(self_, path, method="GET", body=None, **kw):
            calls.append(dict(body))
            return 200, pages[len(calls) - 1]
        with mock.patch.object(NetworkSensorProvider, "_req", fake):
            out = p.list_detections(0, 1, limit=2000)
        self.assertEqual(len(out), 1001)                          # non-dict items skipped
        self.assertEqual([c["offset"] for c in calls], [0, 500, 1000])

    def test_wrapped_response_and_cap(self):
        p = self.make()
        with mock.patch.object(NetworkSensorProvider, "_req",
                               return_value=(200, {"detections": [{"id": 1}, {"id": 2}]})):
            self.assertEqual(len(p.list_detections(0, 1)), 2)
        with mock.patch.object(NetworkSensorProvider, "_req",
                               return_value=(200, [{"id": i} for i in range(500)])) as rq:
            out = p.list_detections(0, 1, limit=10 ** 9)          # absurd limit: capped at 5000
        self.assertEqual(len(out), 5000)
        self.assertEqual(rq.call_count, 10)

    def test_odd_bodies_give_empty(self):
        p = self.make()
        for body in (None, "text", 5, {"detections": "x"}, {}):
            with mock.patch.object(NetworkSensorProvider, "_req", return_value=(200, body)):
                self.assertEqual(p.list_detections(0, 1), [])

    def test_errors_propagate_for_explain(self):
        p = self.make()
        err = urllib.error.HTTPError("u", 401, "no", {}, None)
        with mock.patch.object(NetworkSensorProvider, "_req", side_effect=err):
            with self.assertRaises(urllib.error.HTTPError):
                p.list_detections(0, 1)
        self.assertIn("401", p.explain(err))
        self.assertNotIn(KEY, p.explain(err))

    def test_bad_address_is_refused_at_construction(self):
        with self.assertRaises(ValueError):
            NetworkSensorProvider("https://sensor.example.net/x", KEY)


# ---------------------------------------------------------------- routes
class FakeProvider:
    def __init__(self, raw=None, ident=None, fail=None):
        self.raw, self.ident, self.fail = raw, ident, fail
        self.windows = []

    def identity(self):
        if self.fail:
            raise self.fail
        return self.ident

    def list_detections(self, from_ms, until_ms, limit=2000):
        if self.fail:
            raise self.fail
        self.windows.append((from_ms, until_ms))
        return self.raw

    def explain(self, e):
        return "failed with the key %s in the text" % KEY


def post(path, data):
    res = campaign_api.route_post(path, data)
    return res[0], json.loads(res[1])


def body(**kw):
    b = {"sensor": "sensor.example.net:443", "key": KEY, "entries": entries(), "iocs": IOCS,
         "expect": EXPECT, "stages": STAGES, "offset_s": 0, "slack_s": 60}
    b.update(kw)
    return b


class TestSensorRoutes(NoNetwork):
    def patch(self, prov):
        p = mock.patch.object(campaign_api, "_provider", return_value=prov)
        p.start()
        self.addCleanup(p.stop)
        return prov

    def test_check_ok(self):
        self.patch(FakeProvider(ident={"hostname": "s1", "platform": "sensor", "version": "9.9"}))
        s, d = post("/api/sensor/check", {"sensor": "10.0.0.5", "key": KEY})
        self.assertEqual((s, d["ok"]), (200, True))
        self.assertEqual(d["identity"], {"hostname": "s1", "platform": "sensor", "version": "9.9"})
        self.assertNotIn(KEY, json.dumps(d))

    def test_check_failure_is_inline_and_scrubs_the_key(self):
        self.patch(FakeProvider(fail=urllib.error.HTTPError("u", 401, "no", {}, None)))
        s, d = post("/api/sensor/check", {"sensor": "sensor.example.net", "key": KEY})
        self.assertEqual((s, d["ok"]), (200, False))
        self.assertNotIn(KEY, json.dumps(d))
        self.assertIn("***", d["error"])

    def test_check_not_a_sensor(self):
        self.patch(FakeProvider(ident=None))
        s, d = post("/api/sensor/check", {"sensor": "sensor.example.net", "key": KEY})
        self.assertEqual((s, d["ok"]), (200, False))

    def test_check_real_provider_with_failing_transport(self):
        with mock.patch("sensorops.providers.network_sensor._urlopen",
                        side_effect=urllib.error.URLError("refused " + KEY)):
            s, d = post("/api/sensor/check", {"sensor": "sensor.example.net", "key": KEY})
        self.assertEqual((s, d["ok"]), (200, False))
        self.assertNotIn(KEY, json.dumps(d))

    def test_bad_input_is_400(self):
        bad = [{}, [], "x", {"sensor": "a.example", "key": ""}, {"sensor": "", "key": KEY},
               {"sensor": 5, "key": KEY}, {"sensor": "a.example", "key": 7},
               {"sensor": "a.example", "key": "k" * 301},
               {"sensor": "https://a.example", "key": KEY}, {"sensor": "a.example/x", "key": KEY},
               {"sensor": "user@a.example", "key": KEY}, {"sensor": "a.example:99999", "key": KEY}]
        for b in bad:
            for path in ("/api/sensor/check", "/api/campaign/feedback"):
                s, d = post(path, b)
                self.assertEqual(s, 400, (path, b))
                self.assertNotIn(KEY, json.dumps(d))

    def test_loopback_and_link_local_refused(self):
        self.patch(FakeProvider(ident={}))
        for addr in ("127.0.0.1", "127.0.0.1:8443", "127.1", "2130706433", "0x7f.1", "localhost",
                     "LOCALHOST:443", "x.localhost", "[::1]", "[::1]:443", "169.254.169.254",
                     "[fe80::1]", "0.0.0.0", "[::ffff:127.0.0.1]"):
            s, d = post("/api/sensor/check", {"sensor": addr, "key": KEY})
            self.assertEqual(s, 400, addr)
            s, d = post("/api/campaign/feedback", body(sensor=addr))
            self.assertEqual(s, 400, addr)
        for addr in ("10.0.0.5", "sensor.example.net:8443", "192.168.1.9", "[2001:db8::5]:443"):
            s, _ = post("/api/sensor/check", {"sensor": addr, "key": KEY})
            self.assertEqual(s, 200, addr)

    def test_feedback_ok(self):
        prov = self.patch(FakeProvider(raw=fixture()))
        s, d = post("/api/campaign/feedback", body())
        self.assertEqual((s, d["ok"]), (200, True))
        self.assertEqual(d["score"]["percent"], 75)
        self.assertEqual(d["count"], 7)
        self.assertEqual(d["window"], {"from_ms": (T0 - 60) * 1000, "until_ms": (T0 + 760 + 60 + 1800) * 1000})
        self.assertEqual(prov.windows, [(d["window"]["from_ms"], d["window"]["until_ms"])])
        for k in ("score", "techniques", "actions", "vulnerabilities", "detections", "unmatched"):
            self.assertIn(k, d)
        self.assertNotIn(KEY, json.dumps(d))

    def test_feedback_honours_offset_lookahead_and_min_risk(self):
        self.patch(FakeProvider(raw=fixture()))
        s, d = post("/api/campaign/feedback", body(offset_s=100, lookahead_s=0, min_risk=50))
        self.assertEqual(d["window"]["until_ms"], (T0 + 760 + 100 + 60) * 1000)
        self.assertEqual(d["count"], 3)                           # only risk >= 50: 101, 102, 105

    def test_feedback_provider_failure_is_inline(self):
        self.patch(FakeProvider(fail=urllib.error.HTTPError("u", 403, "no", {}, None)))
        s, d = post("/api/campaign/feedback", body())
        self.assertEqual((s, d["ok"]), (200, False))
        self.assertNotIn(KEY, json.dumps(d))

    def test_feedback_unsupported_provider(self):
        self.patch(FakeProvider(fail=NotImplementedError("x")))
        s, d = post("/api/campaign/feedback", body())
        self.assertEqual((s, d["ok"]), (200, False))

    def test_feedback_nothing_ran(self):
        self.patch(FakeProvider(raw=[]))
        s, d = post("/api/campaign/feedback", body(entries=[dict(e, status="failed") for e in entries()]))
        self.assertEqual((s, d["ok"]), (200, False))
        self.assertIn("nothing to look for", d["error"])

    def test_feedback_zero_testable_with_a_run_entry(self):
        self.patch(FakeProvider(raw=[]))
        ents = [{"stage": "s1", "action": "a", "status": "ok", "ts": T0, "techniques": []}]
        s, d = post("/api/campaign/feedback", body(entries=ents, expect=[]))
        self.assertEqual((s, d["ok"], d["score"]["percent"], d["score"]["testable"]), (200, True, 0, 0))

    def test_feedback_validation(self):
        self.patch(FakeProvider(raw=[]))
        for kw in ({"entries": "x"}, {"entries": {}}, {"iocs": 3}, {"expect": None and 1 or "x"},
                   {"stages": {}}, {"offset_s": "1"}, {"offset_s": True}, {"slack_s": -1},
                   {"slack_s": 10 ** 7}, {"lookahead_s": -5}, {"min_risk": 101},
                   {"entries": [{}] * 5001}):
            s, d = post("/api/campaign/feedback", body(**kw))
            self.assertEqual(s, 400, kw)

    def test_key_is_not_stored(self):
        self.patch(FakeProvider(raw=fixture()))
        post("/api/campaign/feedback", body())
        for name in dir(campaign_api):
            v = getattr(campaign_api, name)
            if isinstance(v, (str, list, dict, tuple)):
                self.assertNotIn(KEY, json.dumps(v, default=str), name)

    def test_routes_are_registered(self):
        for p in ("/api/sensor/check", "/api/campaign/feedback", "/api/geo/lookup"):
            self.assertIn(p, campaign_api._POST)


class TestGeoRoute(NoNetwork):
    def with_geo(self, fn):
        import types
        mod = types.ModuleType("geo")
        mod.lookup_many = fn
        p = mock.patch.dict(sys.modules, {"geo": mod})
        p.start()
        self.addCleanup(p.stop)

    def test_private_and_reserved_are_null_without_asking(self):
        asked = []
        self.with_geo(lambda ips: asked.append(list(ips)) or {})
        ips = ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "198.18.4.7", "198.19.255.1",
               "224.0.0.1", "240.0.0.1", "not-an-ip", "", "::1"]
        s, d = post("/api/geo/lookup", {"ips": ips})
        self.assertEqual(s, 200)
        self.assertEqual(set(d["results"]), set(ips))
        self.assertTrue(all(v is None for v in d["results"].values()))
        self.assertEqual(asked, [])

    def test_lookup_results_are_passed_through(self):
        self.with_geo(lambda ips: {"8.8.8.8": {"cc": "US", "country": "United States", "lat": 38.0, "lon": -97.0,
                                               "extra": 1}})
        s, d = post("/api/geo/lookup", {"ips": ["8.8.8.8", "10.0.0.1", "1.1.1.1"]})
        self.assertEqual(d["results"]["8.8.8.8"],
                         {"cc": "US", "country": "United States", "lat": 38.0, "lon": -97.0})
        self.assertIsNone(d["results"]["10.0.0.1"])
        self.assertIsNone(d["results"]["1.1.1.1"])               # geo had no answer
        self.assertNotIn("error", d)

    def test_missing_geo_module_gives_nulls_and_an_error(self):
        with mock.patch.dict(sys.modules, {"geo": None}):
            s, d = post("/api/geo/lookup", {"ips": ["8.8.8.8", "10.0.0.1"]})
        self.assertEqual(s, 200)
        self.assertEqual(d["results"], {"8.8.8.8": None, "10.0.0.1": None})
        self.assertIn("not installed", d["error"])

    def test_geo_module_without_lookup_many(self):
        import types
        with mock.patch.dict(sys.modules, {"geo": types.ModuleType("geo")}):
            s, d = post("/api/geo/lookup", {"ips": ["8.8.8.8"]})
        self.assertEqual((s, d["results"]), (200, {"8.8.8.8": None}))
        self.assertIn("error", d)

    def test_geo_failure_is_inline(self):
        def boom(ips):
            raise RuntimeError("secret detail")
        self.with_geo(boom)
        s, d = post("/api/geo/lookup", {"ips": ["8.8.8.8"]})
        self.assertEqual(s, 200)
        self.assertNotIn("secret detail", d["error"])

    def test_validation(self):
        for b in ({}, [], {"ips": "8.8.8.8"}, {"ips": [1]}, {"ips": ["8.8.8.8"] * 501},
                  {"ips": ["x" * 65]}):
            s, _ = post("/api/geo/lookup", b)
            self.assertEqual(s, 400, b)
        s, d = post("/api/geo/lookup", {"ips": []})
        self.assertEqual((s, d), (200, {"results": {}}))
        s, d = post("/api/geo/lookup", {"ips": ["10.0.0.%d" % (i % 250) for i in range(500)]})
        self.assertEqual(s, 200)


if __name__ == "__main__":
    unittest.main()

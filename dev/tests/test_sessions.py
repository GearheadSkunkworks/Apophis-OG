"""Tests for saved sessions (dev/sessions_api.py).

Run from dev/:  python -m unittest tests.test_sessions

No server and no engine: the route functions are called directly against a temporary folder.
"""
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
if DEV not in sys.path:
    sys.path.insert(0, DEV)

import sessions_api as S                                # noqa: E402

STATE = {
    "controls": {"company": "Acme", "industry": "Energy", "scale": "0.25", "oten": True,
                 "otnet": "10.10.30.0/24", "usernet": "10.1.1.0/24"},
    "otp": {"modbus": True, "dnp3": False},
    "scenarios": ["ndr-recon", "npm-slow-dns"],
    "recipes": ["/tmp/a.json"],
}


def post(path, body):
    r = S.route_post(path, body)
    return r[0], json.loads(r[1])


def get(path, query=""):
    r = S.route_get(path, query)
    return r[0], json.loads(r[1])


class SessionsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="og-sessions-")
        self._old = os.environ.get("OPENGENERATOR_SESSIONS")
        os.environ["OPENGENERATOR_SESSIONS"] = os.path.join(self.tmp, "Sessions")

    def tearDown(self):
        if self._old is None:
            os.environ.pop("OPENGENERATOR_SESSIONS", None)
        else:
            os.environ["OPENGENERATOR_SESSIONS"] = self._old
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_last_round_trip_and_clear(self):
        self.assertEqual(get("/api/session/last")[1], {"state": None})
        self.assertEqual(post("/api/session/last", {"state": STATE})[0], 200)
        st = get("/api/session/last")[1]["state"]
        self.assertEqual(st["controls"]["company"], "Acme")
        self.assertEqual(st["otp"], {"modbus": True, "dnp3": False})
        self.assertEqual(st["scenarios"], ["ndr-recon", "npm-slow-dns"])
        self.assertEqual(st["recipes"], ["/tmp/a.json"])
        post("/api/session/clear", {})
        self.assertIsNone(get("/api/session/last")[1]["state"])

    def test_secrets_and_acknowledgements_are_never_stored(self):
        dirty = json.loads(json.dumps(STATE))
        dirty["controls"].update({"sensorkey": "SECRET1", "tckey": "SECRET2", "apiPassword": "SECRET3",
                                  "sensorack": True, "rack": True, "authToken": "SECRET4"})
        post("/api/session/last", {"state": dirty})
        with open(os.path.join(os.environ["OPENGENERATOR_SESSIONS"], "last.json"), encoding="utf-8") as f:
            raw = f.read()
        for needle in ("SECRET1", "SECRET2", "SECRET3", "SECRET4", "sensorack", '"rack"'):
            self.assertNotIn(needle, raw)
        self.assertIn("Acme", raw)

    def test_named_sessions_save_list_load_delete(self):
        self.assertEqual(post("/api/session/save", {"name": "Weekly demo", "state": STATE})[0], 200)
        post("/api/session/save", {"name": "OT only", "state": STATE})
        names = {r["name"] for r in get("/api/session/list")[1]["sessions"]}
        self.assertEqual(names, {"Weekly demo", "OT only"})
        got = get("/api/session/load", "id=weekly-demo")
        self.assertEqual(got[0], 200)
        self.assertEqual(got[1]["name"], "Weekly demo")
        self.assertEqual(got[1]["state"]["controls"]["industry"], "Energy")
        self.assertEqual(post("/api/session/delete", {"id": "weekly-demo"})[0], 200)
        self.assertEqual(get("/api/session/load", "id=weekly-demo")[0], 404)

    def test_saving_the_same_name_replaces_it(self):
        post("/api/session/save", {"name": "Demo", "state": STATE})
        s2 = json.loads(json.dumps(STATE))
        s2["controls"]["company"] = "Other"
        post("/api/session/save", {"name": "demo", "state": s2})
        rows = get("/api/session/list")[1]["sessions"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(get("/api/session/load", "id=demo")[1]["state"]["controls"]["company"], "Other")

    def test_bad_input_is_refused(self):
        self.assertEqual(post("/api/session/save", {"name": "", "state": STATE})[0], 400)
        self.assertEqual(post("/api/session/save", {"name": "x", "state": []})[0], 400)
        self.assertEqual(post("/api/session/save", {"name": "x", "state": {}})[0], 400)
        self.assertEqual(post("/api/session/delete", {"id": "../etc/passwd"})[0], 400)
        self.assertEqual(post("/api/session/delete", {"id": "last"})[0], 400)
        self.assertEqual(get("/api/session/load", "id=../../x")[0], 400)
        self.assertEqual(S.route_post("/api/session/last", {}, bad_json=True)[0], 400)
        self.assertIsNone(S.route_get("/api/other", ""))

    def test_state_is_reduced_to_the_known_shape(self):
        weird = {"controls": {"ok": "v", "bad key!": "x", "n": 3, "obj": {"a": 1}, "company": "x" * 5000},
                 "otp": {"modbus": True, "x": "notbool"}, "scenarios": ["a", 5, None], "evil": "drop"}
        post("/api/session/last", {"state": weird})
        st = get("/api/session/last")[1]["state"]
        self.assertEqual(sorted(st["controls"]), ["company", "n", "ok"])
        self.assertEqual(len(st["controls"]["company"]), S.MAX_STR)
        self.assertEqual(st["otp"], {"modbus": True})
        self.assertEqual(st["scenarios"], ["a"])
        self.assertNotIn("evil", st)

    def test_v2_size_and_armed_round_trip_through_last_and_named(self):
        st = dict(STATE, armed=True)
        post("/api/session/last", {"state": st})
        got = get("/api/session/last")[1]["state"]
        self.assertEqual(got["controls"]["scale"], 0.25)
        self.assertIs(got["armed"], True)
        self.assertEqual(got["v"], 2)
        sid = post("/api/session/save", {"name": "Big", "state": st})[1]["id"]
        loaded = get("/api/session/load", "id=" + sid)[1]["state"]
        self.assertEqual(loaded["controls"]["scale"], 0.25)
        self.assertIs(loaded["armed"], True)

    def test_scale_is_clamped_and_bad_values_dropped_armed_only_true_arms(self):
        def clean(**kw):
            return S.clean_state({"controls": dict({"company": "x"}, **kw)})
        self.assertEqual(clean(scale=50)["controls"]["scale"], 1.0)
        self.assertEqual(clean(scale="0")["controls"]["scale"], 0.001)
        self.assertNotIn("scale", clean(scale="big")["controls"])
        self.assertNotIn("scale", clean(scale=True)["controls"])
        self.assertNotIn("scale", clean(scale=float("nan"))["controls"])
        self.assertIs(S.clean_state({"controls": {"a": 1}, "armed": "yes"})["armed"], False)
        self.assertIs(S.clean_state({"controls": {"a": 1}, "armed": 1})["armed"], False)
        self.assertIs(S.clean_state({"controls": {"a": 1}, "armed": True})["armed"], True)

    def test_old_v1_session_without_size_or_armed_still_saves_and_loads(self):
        old = {"v": 1, "controls": {"company": "Acme"}, "otp": {}, "scenarios": ["a"], "recipes": [], "shifts": {}}
        sid = post("/api/session/save", {"name": "Old", "state": old})[1]["id"]
        loaded = get("/api/session/load", "id=" + sid)[1]["state"]
        self.assertEqual(loaded["controls"], {"company": "Acme"})
        self.assertIs(loaded["armed"], False)
        self.assertNotIn("scale", loaded["controls"])
        # a file written by 5.5.3 (no "armed" key at all) is returned as it was; the page treats a missing flag as "leave as is"
        d = os.environ["OPENGENERATOR_SESSIONS"]
        with open(os.path.join(d, "s-legacy.json"), "w") as f:
            json.dump({"name": "Legacy", "saved_at": 1, "state": old}, f)
        self.assertEqual(get("/api/session/load", "id=legacy")[0], 200)

    def test_files_are_private(self):
        post("/api/session/last", {"state": STATE})
        d = os.environ["OPENGENERATOR_SESSIONS"]
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(d, "last.json")).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()

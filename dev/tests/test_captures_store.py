"""captures_store: trash/restore never deletes, and refuses unsafe names."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import captures_store as cs  # noqa: E402 - sys.path is set up before the import


def touch(d, n, body=b"x"):
    with open(os.path.join(d, n), "wb") as fh:
        fh.write(body)


class T(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.d = os.path.realpath(self._t.name)
        for n in ("acme-all-in-one.pcap", "acme-all-in-one-tls-keys.log", "acme-threat-collection.stix.json",
                  "acme-threat-collection.csv", "other.pcap"):
            touch(self.d, n)
        os.mkdir(os.path.join(self.d, "certs"))

    def tearDown(self):
        self._t.cleanup()

    def ls(self):
        return sorted(f for f in os.listdir(self.d) if f != cs.TRASH)

    def test_round_trip(self):
        r = cs.trash(self.d, "acme-all-in-one.pcap")
        self.assertEqual(r["moved"][0], "acme-all-in-one.pcap")
        self.assertEqual(len(r["moved"]), 4)
        self.assertEqual(self.ls(), ["certs", "other.pcap"])           # certs/ is shared: untouched
        li = cs.listing(self.d)["items"]
        self.assertEqual([i["trash_id"] for i in li], [r["trash_id"]])
        self.assertEqual(li[0]["name"], "acme-all-in-one.pcap")
        cs.restore(self.d, r["trash_id"])
        self.assertEqual(len(self.ls()), 6)
        self.assertEqual(cs.listing(self.d)["items"], [])

    def test_bad_names(self):
        for n in ("../x.pcap", "a/b.pcap", "/etc/x.pcap", "..", "", ".hidden.pcap", "a\\b.pcap", None, 5,
                  "other.txt", "missing.pcap"):
            with self.assertRaises(cs.StoreError, msg=repr(n)):
                cs.trash(self.d, n)
        self.assertEqual(len(self.ls()), 6)

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as out:
            touch(out, "secret.pcap")
            os.symlink(os.path.join(out, "secret.pcap"), os.path.join(self.d, "link.pcap"))
            with self.assertRaises(cs.StoreError):
                cs.trash(self.d, "link.pcap")
            self.assertTrue(os.path.exists(os.path.join(out, "secret.pcap")))
        # a symlinked sibling is left in place, never moved
        os.symlink("other.pcap", os.path.join(self.d, "other-tls-keys.log"))
        self.assertEqual(cs.trash(self.d, "other.pcap")["moved"], ["other.pcap"])

    def test_bad_out_dir(self):
        for d in ("", "/no/such/dir", os.path.join(self.d, "other.pcap")):
            with self.assertRaises(cs.StoreError):
                cs.trash(d, "other.pcap")

    def test_restore_collision(self):
        r = cs.trash(self.d, "acme-all-in-one.pcap")
        touch(self.d, "acme-all-in-one.pcap", b"new")
        with self.assertRaises(cs.StoreError) as c:
            cs.restore(self.d, r["trash_id"])
        self.assertEqual(c.exception.status, 409)
        self.assertIn("acme-all-in-one.pcap", str(c.exception))
        self.assertFalse(os.path.exists(os.path.join(self.d, "acme-all-in-one-tls-keys.log")))  # nothing restored
        self.assertEqual(open(os.path.join(self.d, "acme-all-in-one.pcap"), "rb").read(), b"new")

    def test_restore_bad_ids(self):
        for i in ("../x", "", "nope", "20200101T000000Z-a/../..", None):
            with self.assertRaises(cs.StoreError):
                cs.restore(self.d, i)

    def test_tampered_manifest(self):
        r = cs.trash(self.d, "other.pcap")
        m = os.path.join(self.d, cs.TRASH, r["trash_id"], "manifest.json")
        json.dump({"files": ["../evil"]}, open(m, "w"))
        with self.assertRaises(cs.StoreError):
            cs.restore(self.d, r["trash_id"])

    def test_rollback_on_partial_failure(self):
        real, calls = os.rename, []

        def flaky(a, b):
            calls.append(a)
            if len(calls) == 3:
                raise OSError(5, "disk error")
            return real(a, b)
        with mock.patch("os.rename", flaky), self.assertRaises(cs.StoreError):
            cs.trash(self.d, "acme-all-in-one.pcap")
        self.assertEqual(len(self.ls()), 6)                          # everything back
        self.assertEqual(cs.listing(self.d)["items"], [])
        r = cs.trash(self.d, "acme-all-in-one.pcap")                 # restore rollback
        calls.clear()
        with mock.patch("os.rename", flaky), self.assertRaises(cs.StoreError):
            cs.restore(self.d, r["trash_id"])
        self.assertEqual(self.ls(), ["certs", "other.pcap"])

    def test_refused_while_busy(self):
        busy = lambda: "a capture is being generated"  # noqa: E731 - short single-use test helper
        with self.assertRaises(cs.StoreError) as c:
            cs.trash(self.d, "other.pcap", busy)
        self.assertEqual(c.exception.status, 409)
        r = cs.trash(self.d, "other.pcap")
        with self.assertRaises(cs.StoreError):
            cs.restore(self.d, r["trash_id"], busy)

    def test_same_second_twice(self):
        a = cs.trash(self.d, "other.pcap")
        touch(self.d, "other.pcap")
        b = cs.trash(self.d, "other.pcap")
        self.assertNotEqual(a["trash_id"], b["trash_id"])

    def test_routes(self):
        st, body, _c, _h = cs.route_post("/api/captures/trash", {"out_dir": self.d, "name": "other.pcap"})
        self.assertEqual(st, 200)
        tid = json.loads(body)["trash_id"]
        st, body, *_ = cs.route_get("/api/captures/trash", "out_dir=" + self.d)
        self.assertEqual(json.loads(body)["items"][0]["trash_id"], tid)
        self.assertEqual(cs.route_post("/api/captures/restore", {"out_dir": self.d, "trash_id": tid})[0], 200)
        self.assertEqual(cs.route_post("/api/captures/trash", {}, True)[0], 400)
        self.assertEqual(cs.route_post("/api/captures/trash", {"out_dir": self.d, "name": "../x"})[0], 400)
        self.assertIsNone(cs.route_post("/api/other", {}))
        self.assertIsNone(cs.route_get("/api/captures", ""))


if __name__ == "__main__":
    unittest.main()

"""Tests for the offline IPv4 country lookup and its bundled data.

Run from dev/:  python -m unittest tests.test_geo
"""
import json
import os
import time
import unittest

import geo

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class LookupTests(unittest.TestCase):
    def cc(self, ip):
        r = geo.lookup(ip)
        return r["cc"] if r else None

    def test_known_addresses(self):
        for ip, cc in [("8.8.8.8", "US"), ("8.8.4.4", "US"), ("1.1.1.1", "AU"), ("114.114.114.114", "CN"),
                       ("200.160.2.3", "BR"), ("41.0.0.1", "ZA"), ("193.0.14.129", "NL"), ("202.12.27.33", "JP")]:
            self.assertEqual(self.cc(ip), cc, ip)

    def test_result_shape(self):
        r = geo.lookup("8.8.8.8")
        self.assertEqual(set(r), {"cc", "country", "lat", "lon"})
        self.assertTrue(-90 <= r["lat"] <= 90 and -180 <= r["lon"] <= 180)
        self.assertTrue(r["country"])
        r["cc"] = "XX"                       # callers may mutate their copy
        self.assertEqual(geo.lookup("8.8.8.8")["cc"], "US")

    def test_reserved_ranges_return_none(self):
        for ip in ["0.0.0.1", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254", "192.168.1.1",
                   "198.18.0.1", "198.19.255.254", "127.0.0.1", "169.254.1.1", "100.64.0.1", "100.127.255.254",
                   "192.0.2.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.250", "240.0.0.1",
                   "255.255.255.255"]:
            self.assertIsNone(geo.lookup(ip), ip)

    def test_reserved_boundaries(self):
        self.assertIsNone(geo.lookup("172.16.0.0"))
        self.assertIsNone(geo.lookup("172.31.255.255"))
        self.assertIsNone(geo.lookup("198.19.255.255"))
        self.assertIsNone(geo.lookup("100.127.255.255"))
        # just outside private blocks the registry data decides; these are not in the reserved list
        self.assertFalse(any(s <= 0xAC200001 <= e for s, e in geo._RESERVED_SPANS))
        self.assertFalse(any(s <= 0xC6140000 <= e for s, e in geo._RESERVED_SPANS))

    def test_malformed_input(self):
        for bad in ["", "abc", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.-4", "1.2.3.4 5", "1..2.3", "::1",
                    "2001:4860:4860::8888", "٣.٣.٣.٣", "1.2.3.0x4", None, 12345, b"8.8.8.8", [], "1.2.3.1000"]:
            self.assertIsNone(geo.lookup(bad), repr(bad))

    def test_whitespace_tolerated(self):
        self.assertEqual(self.cc(" 8.8.8.8 "), "US")

    def test_lookup_many(self):
        out = geo.lookup_many(["8.8.8.8", "10.0.0.1", "nope"])
        self.assertEqual(list(out), ["8.8.8.8", "10.0.0.1", "nope"])
        self.assertEqual(out["8.8.8.8"]["cc"], "US")
        self.assertIsNone(out["10.0.0.1"])
        self.assertIsNone(out["nope"])

    def test_speed(self):
        geo.lookup("8.8.8.8")
        ips = ["%d.%d.%d.%d" % (i % 223 + 1, i % 251, i % 241, i % 199) for i in range(20000)]
        t = time.time()
        for ip in ips:
            geo.lookup(ip)
        self.assertGreater(len(ips) / (time.time() - t), 5000)

    def test_dataset_facts(self):
        i = geo.info()
        self.assertGreater(i["ranges"], 50000)
        self.assertGreater(i["countries"], 200)
        self.assertRegex(i["built"], r"^\d{4}-\d\d-\d\d$")


class DataFileTests(unittest.TestCase):
    def test_sizes(self):
        b = os.path.getsize(os.path.join(DEV, "geo", "ipv4_country.bin"))
        w = os.path.getsize(os.path.join(DEV, "ui", "geo-world.json"))
        self.assertLess(w, 300 * 1024)
        self.assertLess(b + w, int(1.5 * 1024 * 1024))

    def test_world_outlines(self):
        with open(os.path.join(DEV, "ui", "geo-world.json"), encoding="utf-8") as fh:
            world = json.load(fh)["countries"]
        self.assertGreater(len(world), 200)
        seen = set()
        for c in world:
            self.assertEqual(set(c), {"cc", "name", "lat", "lon", "polygons"})
            self.assertNotIn(c["cc"], seen)
            seen.add(c["cc"])
            self.assertTrue(c["polygons"])
            for poly in c["polygons"]:
                self.assertGreaterEqual(len(poly), 4)
                for lon, lat in poly:
                    self.assertTrue(-180 <= lon <= 180 and -90 <= lat <= 90)
        for cc in ("US", "FR", "SG", "AU", "BR", "JP"):
            self.assertIn(cc, seen)

    def test_outline_points_match_lookup(self):
        with open(os.path.join(DEV, "ui", "geo-world.json"), encoding="utf-8") as fh:
            by = {c["cc"]: c for c in json.load(fh)["countries"]}
        r = geo.lookup("8.8.8.8")
        self.assertEqual((r["lat"], r["lon"]), (by["US"]["lat"], by["US"]["lon"]))


if __name__ == "__main__":
    unittest.main()

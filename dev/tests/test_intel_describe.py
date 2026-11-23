import unittest
from intel import describe


def ioc(t, v, role="c2", **kw):
    return dict({"type": t, "value": v, "role": role, "tags": [], "source": "s"}, **kw)


class TestDescribe(unittest.TestCase):
    def test_wire_types_playable_with_card(self):
        kept, dropped = describe.annotate([ioc("ipv4", "198.51.100.7"), ioc("domain", "a.example")], [])
        self.assertEqual(len(kept), 2)
        self.assertEqual(dropped, [])
        self.assertIn("beacons", kept[0]["card"]["traffic"])

    def test_non_wire_types_hidden_with_reason(self):
        items = [ioc(t, "x", "unknown") for t in ("cve", "sha256", "email", "ipv6", "cidr", "filename")]
        kept, dropped = describe.annotate(items, [("old", "private")])
        self.assertEqual(kept, [])
        self.assertEqual(len(dropped), 7)
        self.assertTrue(all("not on the wire" in r for _, r in dropped[1:]))

    def test_unknown_role_still_explained(self):
        self.assertIn("nothing until", describe.card(ioc("ipv4", "198.51.100.1", "weird"))["traffic"])


class TestProse(unittest.TestCase):
    PROSE = ("\n".join("The operator then moved laterally and staged data before the encryption step began today %d." % i
                         for i in range(40))
             + "\nSee https://www.trendmicro.com/vinfo/us/news/akira and the file ntds.dit plus webclient.downloadstring\n"
             "C2 at hxxp://evil[.]example[.]net/a and 203.0.113.77 and cisa.gov\n")

    def test_report_keeps_defanged_and_addresses_only(self):
        from intel import parsers
        self.assertTrue(parsers.looks_like_report(self.PROSE))
        vals = {i["value"] for i in parsers.parse_text(self.PROSE)}
        self.assertIn("203.0.113.77", vals)
        self.assertIn("http://evil.example.net/a", vals)
        self.assertFalse({v for v in vals if "trendmicro" in v or v in ("ntds.dit", "webclient.downloadstring", "cisa.gov")})

    def test_plain_list_unchanged(self):
        from intel import parsers
        self.assertFalse(parsers.looks_like_report("a.example\nb.example\n"))
        vals = {i["value"] for i in parsers.parse_text("rare-host.ninja\nhttp://x.example.net/p\nnot.atld\n")}
        self.assertEqual(vals, {"rare-host.ninja", "http://x.example.net/p"})

    def test_reference_hosts_allow_listed(self):
        from intel import filters
        k, d = filters.clean([ioc("domain", "www.cisa.gov"), ioc("domain", "agency.fbi.gov"), ioc("domain", "x.mil"),
                              ioc("domain", "news.sophos.com")])
        self.assertEqual((k, len(d)), ([], 4))


if __name__ == "__main__":
    unittest.main()

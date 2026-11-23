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

    def test_defanged_forms_from_a_real_advisory(self):
        """Forms seen in CISA AA23-061A: port suffixes, bracketed octets, a mail-gateway rewrite link."""
        from intel import filters, parsers
        text = self.PROSE + ("143[.]244[.]146[.]183:443\n104.21.58[.]219:443\n185.7.214[.]218\n"
                             "https://protect-us.mimecast[.]com/s/abc?domain=5.181.234.58\n")
        k, _ = filters.clean(parsers.parse_text(text))
        vals = {i["value"] for i in k}
        self.assertTrue({"143.244.146.183", "104.21.58.219", "185.7.214.218"} <= vals)
        self.assertFalse([v for v in vals if "mimecast" in v])

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


class TestCatalog(unittest.TestCase):
    def test_family_matching_is_whole_word(self):
        from intel import catalog
        self.assertEqual(catalog.family_for(ioc("ipv4", "198.51.100.7", tags=["Cobalt Strike"])), "cobalt-strike")
        self.assertEqual(catalog.family_for(ioc("ipv4", "198.51.100.7", note="Akira ransomware staging")), "akira")
        self.assertEqual(catalog.family_for(ioc("ipv4", "198.51.100.7", tags=["qbot"])), "qakbot")
        self.assertIsNone(catalog.family_for(ioc("ipv4", "198.51.100.7", note="replay the display of a playbook")))

    def test_card_carries_the_family(self):
        c = describe.card(ioc("ipv4", "198.51.100.7", tags=["lumma stealer"]))["what"]
        self.assertIn("Linked to Lumma Stealer (information stealer)", c)

    def test_every_entry_is_complete(self):
        from intel import catalog
        for fid, e in catalog.FAMILIES.items():
            self.assertEqual(len(e), 4, fid)
            self.assertTrue(e[0] and e[1] and e[2], fid)
            self.assertEqual(catalog.family_for({"tags": [e[0]]}), fid, fid)


if __name__ == "__main__":
    unittest.main()

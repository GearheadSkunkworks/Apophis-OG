"""Review gaps M9/M10: make_diagram helpers, diagram_lint --all, campaign view/panels helpers."""
import os
import sys
import types
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import make_diagram as MD  # noqa: E402
from diagrams.campaign import view as V  # noqa: E402
from diagrams.campaign import panels as PN  # noqa: E402


class MakeDiagramHelpers(unittest.TestCase):
    def test_off_and_dur(self):
        self.assertEqual(MD._off(45), "+45m")
        self.assertEqual(MD._off(-30), "-30m")
        self.assertEqual(MD._off(0), "+0m")
        self.assertEqual(MD._off(120), "+2h")
        self.assertEqual(MD._off(150), "+2:30")
        self.assertEqual(MD._off(-150), "-2:30")
        self.assertEqual(MD._off(59.6), "+1h")
        self.assertEqual(MD._dur(45), "45m")
        self.assertEqual(MD._dur(120), "2h")
        self.assertEqual(MD._dur(150), "2:30")
        self.assertEqual(MD._dur(-5), "-5m")           # negative durations are not clamped (pins today's behaviour)

    def test_mix_rows_fold_preserves_totals(self):
        first_tags = MD.MIX_GROUPS[0][3]
        stats = {first_tags[0]: (10, 1000), first_tags[1]: (5, 500), "zz-unknown": (7, 70), "aa-unknown": (1, 1)}
        rows = MD._mix_rows(stats)
        self.assertEqual(len(rows), len(MD.MIX_GROUPS) + 1)
        self.assertEqual(sum(r["packets"] for r in rows), 23)
        self.assertEqual(sum(r["bytes"] for r in rows), 1571)
        self.assertEqual((rows[0]["packets"], rows[0]["bytes"]), (15, 1500))
        other = rows[-1]
        self.assertEqual((other["key"], other["packets"], other["protos"]), ("other", 8, "aa-unknown, zz-unknown"))

    def test_mix_rows_no_other_row_when_all_known(self):
        rows = MD._mix_rows({})
        self.assertEqual(len(rows), len(MD.MIX_GROUPS))
        self.assertTrue(all(r["packets"] == 0 for r in rows))


class DiagramLint(unittest.TestCase):
    def test_all_diagrams_lint_clean(self):
        import diagram_lint
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = diagram_lint.main(["--all", "--quiet"])
        self.assertEqual(rc, 0, buf.getvalue())
        self.assertIn("0 with findings", buf.getvalue())


class CampaignHelpers(unittest.TestCase):
    def ctx(self, **nets):
        return types.SimpleNamespace(nets=nets)

    def test_zone_of_ip_default_nets(self):
        self.assertIsNone(V._zone_of_ip(None, ""))
        self.assertEqual(V._zone_of_ip(None, "10.10.30.5"), "ot")          # stock OT nets
        self.assertIsNone(V._zone_of_ip(None, "10.10.20.5"))              # no ctx: no user/server zones
        self.assertEqual(V._zone_of_ip(self.ctx(user="10.10.10.0/24", server="10.10.20.0/24"), "10.10.30.9"), "ot")
        self.assertIsNone(V._zone_of_ip(None, "not-an-ip"))

    def test_zone_of_ip_follows_ctx_nets(self):
        c = self.ctx(user="192.168.10.0/24", server="192.168.20.0/24", ot="172.16.0.0/24", ops="172.16.1.0/24", idmz="172.16.2.0/24")
        self.assertEqual(V._zone_of_ip(c, "192.168.10.4"), "user")
        self.assertEqual(V._zone_of_ip(c, "192.168.20.4"), "server")
        self.assertEqual(V._zone_of_ip(c, "172.16.0.4"), "ot")
        self.assertEqual(V._zone_of_ip(c, "172.16.1.4"), "ot")
        self.assertEqual(V._zone_of_ip(c, "172.16.2.4"), "ot")
        self.assertIsNone(V._zone_of_ip(c, "8.8.8.8"))
        # with a remapped OT net the stock OT subnets are no longer special
        self.assertIsNone(V._zone_of_ip(c, "10.10.30.5"))

    def test_fmt_dur_boundaries(self):
        self.assertEqual(PN.fmt_dur(None), "n/a")
        self.assertEqual(PN.fmt_dur(0), "0s")
        self.assertEqual(PN.fmt_dur(59.4), "59s")
        self.assertEqual(PN.fmt_dur(60), "1m 00s")
        self.assertEqual(PN.fmt_dur(3599), "59m 59s")
        self.assertEqual(PN.fmt_dur(3600), "1h 00m")
        self.assertEqual(PN.fmt_dur(7265), "2h 01m")

    def test_fmt_int_off_clock(self):
        self.assertEqual(PN.fmt_int(None), "n/a")
        self.assertEqual(PN.fmt_int(1234567), "1,234,567")
        self.assertEqual(PN.fmt_off(0), "+0:00")
        self.assertEqual(PN.fmt_off(None), "+0:00")
        self.assertEqual(PN.fmt_off(750), "+12:30")
        self.assertEqual(PN.fmt_off(3900), "+1:05:00")
        self.assertEqual(PN.clock("23:59", 120), "00:01:00")             # wraps past midnight
        self.assertEqual(PN.clock("garbage", 61), "00:01:01")
        self.assertEqual(PN.clock(None, 0), "00:00:00")


if __name__ == "__main__":
    unittest.main()

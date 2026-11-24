"""Diagrams under remapped user/server nets must not print stock 10.10.x.x addresses (review F4/M4)."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import make_diagram as MD  # noqa: E402

NETS = dict(user_net="192.168.10.0/24", server_net="192.168.20.0/24")
STOCK = re.compile(r"10\.10\.(?:10|20)\.\d+")


class RemappedNets(unittest.TestCase):
    def test_default_render_uses_stock_and_topology_remaps(self):
        self.assertRegex(MD.render("topology"), STOCK)
        page = MD.render("topology", **NETS)
        self.assertNotRegex(page, STOCK)
        self.assertIn("192.168.20.", page)

    def test_campaign_style_diagrams_remap(self):
        skip = {"ndr-edge-exploit", "ndr-volt-typhoon", "npm-fw-update"}   # F4, below
        names = [n["name"] if isinstance(n, dict) else n for n in MD.catalog(True)]
        names = [n for n in names if n not in skip and not n.startswith("ndr-ot-")]  # OT zone keeps its own default net
        self.assertGreater(len(names), 20)
        for name in names:
            self.assertNotRegex(MD.render(name, **NETS), STOCK, name)

    def test_filters_follow_remapped_nets(self):
        for name in ("ndr-edge-exploit", "ndr-volt-typhoon", "npm-fw-update"):
            self.assertNotRegex(MD.render(name, **NETS), STOCK, name)


if __name__ == "__main__":
    unittest.main()

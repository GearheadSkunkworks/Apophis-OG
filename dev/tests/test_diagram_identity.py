"""Company/industry relabelling of rendered diagrams: markup must stay inert; negative offsets format."""
import os, sys, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import make_diagram as MD  # noqa: E402 - sys.path is set up before the import


class DiagramIdentity(unittest.TestCase):
    def test_company_markup_is_escaped(self):
        page = MD.render("topology", company="X<img src=x onerror=alert(1)>", industry="Y")
        self.assertNotIn("<img src=x onerror", page)
        self.assertIn("&lt;img src=x onerror", page)

    def test_ampersand_company_is_valid_markup(self):
        self.assertIn("AT&amp;T", MD.render("topology", company="AT&T", industry="Telecom"))

    def test_negative_offsets(self):
        self.assertEqual(MD._off(-30), "-30m")
        self.assertEqual(MD._off(-150), "-2:30")
        self.assertEqual(MD._off(45), "+45m")
        self.assertEqual(MD._off(120), "+2h")

    def test_sys_path_inserted_once(self):
        MD.render("topology"); n = sys.path.count(MD.APP_DIR)
        MD.render("topology"); self.assertEqual(sys.path.count(MD.APP_DIR), n)


if __name__ == "__main__":
    unittest.main()

"""Diagrams and the generation report reflect timeline shifts; a default render is unchanged."""
import os
import sys
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import make_diagram as MD  # noqa: E402 - sys.path is set up before the import


class T(unittest.TestCase):
    def test_default_render_is_unchanged_and_leaves_no_state(self):
        a = MD.render("timeline")
        MD.render("timeline", shifts={"npm-http-errors": 30})
        self.assertEqual(MD.SHIFTS, {})
        self.assertEqual(MD.render("timeline"), a)

    def test_timeline_shows_the_moved_scenario(self):
        base = MD.render("timeline")
        moved = MD.render("timeline", shifts={"npm-http-errors": 30})
        self.assertNotEqual(base, moved)
        self.assertIn("moved +30 min", moved)
        self.assertNotIn("moved", base.split("</style>")[-1])
        self.assertIn("Scenarios you moved", moved)

    def test_scenario_diagram_window_moves(self):
        base = MD.render("ndr-recon")
        moved = MD.render("ndr-recon", shifts={"ndr-recon": 60})
        self.assertNotEqual(base, moved)

    def test_sql1_phase_labels_follow_the_shift(self):
        moved = MD.render("npm-sql1-service-failure", shifts={"npm-sql1-service-failure": 60})
        self.assertIn("degraded 11:05", moved)
        self.assertIn("(from 11:52)", moved)
        self.assertNotIn("degraded 10:05", moved)
        self.assertIn("degraded 10:05", MD.render("npm-sql1-service-failure"))

    def test_bad_shift_is_refused(self):
        with self.assertRaises(ValueError):
            MD.render("timeline", shifts={"npm-http-errors": 99999})
        self.assertEqual(MD.SHIFTS, {})

    def test_report_notes_the_shift_only_when_shifted(self):
        meta = {"bytes": 1, "scale": 1, "modules": 1}
        self.assertNotIn("moved on the timeline", str(MD.generation_report([("TCP", 5)], meta)))
        out = MD.generation_report([("TCP", 5)], dict(meta, shifts={"npm-http-errors": -15}))
        self.assertIn("npm-http-errors (-15 min)", str(out["notes"]))


if __name__ == "__main__":
    unittest.main()

"""Session autosave must stay wired: edits schedule a save, and the page saves when it is hidden or closed.
Commit 3080e0c dropped these listeners by accident and nothing noticed; this keeps them from vanishing again."""
import os
import re
import unittest

HTML = open(os.path.join(os.path.dirname(__file__), "..", "ui", "index.html"), encoding="utf-8").read()


class SessionAutosaveWired(unittest.TestCase):
    def test_edits_schedule_a_save(self):
        self.assertRegex(HTML, r"\['input',\s*'change',\s*'click'\]\.forEach\(ev => document\.addEventListener\(ev, sessSchedule, true\)\)")

    def test_pagehide_and_hidden_tab_save(self):
        self.assertIn("window.addEventListener('pagehide', sessSaveLast)", HTML)
        self.assertRegex(HTML, r"visibilitychange.*visibilityState === 'hidden'\) sessSaveLast\(\)")

    def test_handlers_defined_once(self):
        for fn in ("sessSaveLast", "sessSchedule"):
            self.assertEqual(len(re.findall(r"^function %s\(" % fn, HTML, flags=re.M)), 1, fn)


if __name__ == "__main__":
    unittest.main()

"""W1 usability wiring: the page pieces the JS helpers need must stay connected (timing reset, undo, size and armed saved,
leave warning, setup file, the estimate used for progress). Static checks on the shipped files."""
import json
import os
import re
import unittest

UI = os.path.join(os.path.dirname(__file__), "..", "ui")
rd = lambda n: open(os.path.join(UI, n), encoding="utf-8").read()
HTML, EDITOR, LIB = rd("index.html"), rd("campaigns-editor.js"), rd("campaigns-library.js")


class UsabilityWired(unittest.TestCase):
    def test_size_is_saved_and_no_longer_skipped(self):
        skip = re.search(r"const SESS_SKIP = /\^\((.*?)\)\$", HTML).group(1).split("|")
        self.assertNotIn("scale", skip)
        self.assertIn("scalerange", skip)      # the slider mirrors #scale; saving both would double-write
        self.assertIn("armed: armedNow()", HTML)

    def test_restored_size_survives_the_settings_default(self):
        self.assertIn("window.__ogSizeKept", HTML)
        self.assertRegex(HTML, r"__ogSizeKept = false; applySize\(\)")

    def test_armed_flag_is_exposed_by_the_library(self):
        self.assertIn("OGC.getArmed", LIB)
        self.assertIn("OGC.setArmed", LIB)
        self.assertIn("__ogPendingArmed", LIB)

    def test_clean_baseline_clears_moves_and_actions_are_undoable(self):
        self.assertRegex(HTML, r"k === 'baseline'\)\{ setAll\(false\); enableOT\(false\); OGCards\.loadShifts\(ALL_MODULES, \{\}\)")
        for needle in ("undoable('Changed the starting point.'", "undoable(all ?", "undoToast('Loaded", "undoToast('Started fresh.'", "undoable('Timing reset"):
            self.assertIn(needle, HTML)

    def test_one_progress_estimate(self):
        self.assertNotIn("0.37 + 10.0", HTML)
        self.assertRegex(HTML, r"function genPercent\(packets\)\{[^}]*estNumbers\(sc\)")

    def test_settings_size_text_says_fresh_start(self):
        self.assertIn("The size Build starts at on a fresh start. Changing it here resets Build", HTML)
        self.assertIn("armedAfterCampaign", LIB)

    def test_captures_rows_use_the_kept_rows_own_folder(self):
        self.assertIn("out_dir: OGCards.captureDir(it, j.dir), name: it.name", HTML)      # Remove
        self.assertIn("out_dir: t.out_dir || j.dir, trash_id: t.trash_id", HTML)           # Restore
        self.assertNotIn("out_dir: j.dir, name: it.name", HTML)
        self.assertNotIn("out_dir: j.dir, trash_id", HTML)
        self.assertIn("rep.onclick = () => window.open('/profile?path=' + encodeURIComponent(it.path)", HTML)   # the row's own file
        self.assertIn("Earlier build kept in", HTML)
        self.assertIn(".lib-tag", rd("app.css"))

    def test_leave_warning_on_unsaved_campaign_edits(self):
        self.assertRegex(EDITOR, r"addEventListener\('beforeunload'[\s\S]*?OGC\.state\.dirty")

    def test_timing_box_and_setup_buttons_exist_once(self):
        for i in ("tmbox", "tmreset", "tmtext", "setupexp", "setupimp", "setupfile", "chglist"):
            self.assertEqual(len(re.findall(r'id="%s"' % i, HTML)), 1, i)

    def test_sessions_help_article_matches_the_code(self):
        arts = json.load(open(os.path.join(UI, "help-articles.json"), encoding="utf-8"))
        arts = arts if isinstance(arts, list) else arts.get("articles", arts)
        body = [a for a in arts if a["id"] == "sessions"][0]["body"]
        for word in ("size", "armed", "Undo", "Export setup", "Import setup", "Changed from default"):
            self.assertIn(word, body)


if __name__ == "__main__":
    unittest.main()

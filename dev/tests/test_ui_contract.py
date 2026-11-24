"""UI contract: the top-bar shell keeps every control id of the previous page, serves app.css and has the view containers."""
import os
import re
import sys
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import campaign_api  # noqa: E402

UI = os.path.join(DEV, "ui")
with open(os.path.join(UI, "index.html"), encoding="utf-8") as _fh:
    HTML = _fh.read()
with open(os.path.join(DEV, "BUILD-macos.md"), encoding="utf-8") as _fh:
    RECIPE = _fh.read()

# Every id="..." that the page carried before the shell redesign (static markup and ids written by its scripts).
LEGACY_IDS = [
    "aboutlink", "appdep", "appdep-errors", "appdep-head", "betaops", "capdate", "capdate-note",
    "capsactive", "capsbuiltins", "capsfold", "capslist", "capstat", "capstestall", "captoday", "certs",
    "cmb", "cmbp", "company", "cpk", "cpkp", "cwarn", "dep", "dep-errors", "diaghint", "diagpick",
    "diagview", "dl-caps", "dl-recs", "gc-${esc(c.key)}", "go", "industry", "iocs", "iocs-help", "log",
    "log2", "modsum", "net-errors", "ogc-card", "ogc-fold", "ogc-root", "ot-help", "oten", "otf", "otnet",
    "otnote", "otnotebtn", "otpoll", "otsec", "otsum", "ottag", "outdir", "palsel", "pcapcmpbtn",
    "pcapcompare", "pcapfold", "pcapmsg", "pcappath", "pcaprecipe", "pcapuse", "pcapview", "progress",
    "protohint", "r-capleft", "r-clock", "r-elapsed", "r-eta", "r-mb", "r-mbremain", "r-pct", "r-rate",
    "r-remain", "r-sent", "rack", "rbar", "recipeadd", "recipefold", "recipelist", "recipelistbar",
    "recipemsg", "recipepath", "replayfold", "replaysum", "replaytag", "reportview", "results",
    "results-body", "results-title", "reveal", "rgo", "riface", "rlog", "rloop", "rmode", "rmode-hint",
    "rmonitor", "rmonitor-help", "rpcap", "rphase", "rprog-title", "rprogress", "rstop", "rvalue",
    "rvalue-hint", "s-clock", "s-deleted", "s-failed", "s-mapped", "s-mb", "s-pkts", "s-sec", "s-unmapped",
    "s-uploaded", "scale", "scaleest", "scaleout", "scalerange", "sel-all",
    "seldetails", "selgroups", "sensor-errors", "sensor-phase",
    "sensorcerts", "sensorcheck", "sensorfold", "sensorgo", "sensorip", "sensorkey",
    "sensorlog", "sensorport", "sensorprogress", "sensorproto", "sensorstop", "servernet",
    "sessfresh", "sesslist", "sessname", "sessnote", "sesspanel", "sesssave", "stop", "stop-hint",
    "tc-detect", "tc-errors", "tc-imported", "tc-indicators", "tc-phase", "tc-replaced", "tccheck",
    "tcdetect", "tcdetect-help", "tcfold", "tcgo", "tcip", "tckey", "tclog", "tcprogress", "tcstix",
    "tcstop", "tctarget", "tctargethint", "themesel", "usernet",
]

VIEWS = ("build", "campaigns", "replay", "captures", "lab", "help", "settings")


class TestUiContract(unittest.TestCase):
    def test_every_legacy_id_present_exactly_once(self):
        bad = {i: len(re.findall(r'id="%s"' % re.escape(i), HTML)) for i in LEGACY_IDS}
        bad = {k: v for k, v in bad.items() if v != 1}
        self.assertEqual(bad, {}, "ids missing or duplicated")

    def test_no_duplicate_ids_at_all(self):
        ids = re.findall(r'\sid="([^"$]+)"', HTML)
        dup = sorted({i for i in ids if ids.count(i) > 1})
        self.assertEqual(dup, [])

    def test_view_containers(self):
        for v in VIEWS:
            self.assertRegex(HTML, r'<section class="view" id="view-%s" data-view="%s"' % (v, v))
        self.assertIn('id="mainnav"', HTML)
        for v in VIEWS[:4]:
            self.assertIn('class="tab" data-view="%s"' % v, HTML)
        self.assertRegex(HTML, r'id="tab-lab" data-view="lab" hidden')       # Lab is off until the Settings switch is on
        self.assertIn('id="labtools"', HTML)
        self.assertIn('href="#main"', HTML)                                    # skip link

    def test_campaign_card_keeps_its_shell(self):
        self.assertRegex(HTML, r'<div class="card" id="ogc-card">\s*<details class="fold viewfold" id="ogc-fold" open>\s*<summary>')

    def test_app_css_loaded_served_and_packaged(self):
        self.assertIn('href="/ui/app.css"', HTML)
        self.assertEqual(campaign_api.STATIC_FILES.get("app.css"), "text/css; charset=utf-8")
        status, body, ctype, _ = campaign_api.static_file("app.css", UI)
        self.assertEqual((status, ctype), (200, "text/css; charset=utf-8"))
        self.assertIn(b"prefers-reduced-motion", body)
        self.assertIn('--add-data "$P/ui:ui"', RECIPE)      # the build recipe ships the whole ui directory

    def test_app_css_uses_tokens_not_literal_palette_colours(self):
        with open(os.path.join(UI, "app.css"), encoding="utf-8") as fh:
            css = fh.read()
        # only white (text on a filled button) may be a literal colour
        lits = [m for m in re.findall(r'#[0-9a-fA-F]{3,8}\b', css) if m.lower() not in ("#fff", "#ffffff")]
        self.assertEqual(lits, [])

class TestScenarioCardsAssets(unittest.TestCase):
    FILES = {"scenario-cards.js": "text/javascript; charset=utf-8", "scenario-cards.css": "text/css; charset=utf-8",
             "explainer.js": "text/javascript; charset=utf-8",
             "timeline.js": "text/javascript; charset=utf-8",
             "gearhead-mark.png": "image/png"}

    def test_files_exist_served_loaded_and_packaged(self):
        for name, ctype in self.FILES.items():
            self.assertTrue(os.path.isfile(os.path.join(UI, name)), name)
            self.assertEqual(campaign_api.STATIC_FILES.get(name), ctype)
            status, body, got, _ = campaign_api.static_file(name, UI)
            self.assertEqual((status, got), (200, ctype))
            self.assertTrue(body)
        self.assertIn('href="/ui/scenario-cards.css"', HTML)
        self.assertIn('src="/ui/scenario-cards.js"', HTML)
        self.assertIn('src="/ui/explainer.js"', HTML)
        self.assertIn('src="/ui/timeline.js"', HTML)
        self.assertLess(HTML.index("/ui/explainer.js"), HTML.index("/ui/scenario-cards.js"))

    def test_build_view_mounts(self):
        for i in ("catrail", "chooser-tools", "selgroups", "cards-empty", "covbox"):
            self.assertEqual(len(re.findall(r'id="%s"' % i, HTML)), 1, i)

    def test_cards_script_builds_dom_without_innerhtml(self):
        js = ""
        for f in ("scenario-cards.js", "explainer.js", "timeline.js"):
            with open(os.path.join(UI, f), encoding="utf-8") as fh:
                js += fh.read()
        self.assertNotRegex(js, r"innerHTML|outerHTML|insertAdjacentHTML|document\.write")
        with open(os.path.join(UI, "scenario-cards.css"), encoding="utf-8") as fh:
            css = fh.read()
        self.assertIn("prefers-reduced-motion", css)
        lits = [m for m in re.findall(r'#[0-9a-fA-F]{3,8}\b', css) if m.lower() not in ("#fff", "#ffffff", "#000")]
        self.assertEqual(lits, [], "scenario-cards.css must use tokens")

if __name__ == "__main__":
    unittest.main()


class TestHoldToConfirm(unittest.TestCase):
    def test_key_replace_uses_hold_and_keeps_the_token(self):
        self.assertIn("ogHoldConfirm({title: 'Replace all decryption keys?'", HTML)
        self.assertIn("confirm: 'DELETE-AND-REPLACE'", HTML)
        self.assertNotRegex(HTML, r"\bconfirm\(\s*['\"]This deletes")

"""Design tokens (dev/ui/theme.css), bundled fonts, static allow-list and contrast."""
import os
import re
import sys
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import campaign_api  # noqa: E402
import contrast_check as cc  # noqa: E402
import make_diagram  # noqa: E402

UI = os.path.join(DEV, "ui")
with open(os.path.join(UI, "theme.css"), encoding="utf-8") as _fh:
    CSS = _fh.read()

TOKENS = ("--bg --p1 --p2 --p3 --ln --ln2 --field-ln --cy-tx --ink --mu --ac --ac-tx --cy --vi --ok --wr --er "
          "--ok-fill --wr-fill --er-fill --info-fill --c-sec --c-perf --c-cryp --c-rep --c-cus "
          "--face --glow --grid --font-ui --font-mono --hdr-a --hdr-b").split()
FAMILY = ("--c-sec", "--c-perf", "--c-cryp", "--c-rep", "--c-cus")
LEGACY = ("--page --surface --surface-2 --mist --gray --line --line-2 --on-ink --sapphire --plum --cyan "
          "--tangerine --magenta --sapphire-tx --plum-tx --cyan-tx --magenta-tx --ir --hdr-a --hdr-b "
          "--log-bg --log-ink --readybar-bg --code-bg --ir --border --card --input-bg").split()
FONTS = ["ibm-plex-sans-%s.woff2" % w for w in (400, 500, 600, 700)] + \
        ["ibm-plex-mono-%s.woff2" % w for w in (400, 500)]


class TestTokens(unittest.TestCase):
    def test_every_palette_and_theme_defines_full_token_set(self):
        for theme in cc.THEMES:
            for pal in cc.PALETTES:
                tk = cc.resolve_tokens(CSS, theme, pal)
                for name in TOKENS + list(LEGACY):
                    self.assertIn(name, tk, "%s/%s missing %s" % (theme, pal, name))
                    self.assertNotIn("var(", tk[name], "%s/%s %s unresolved" % (theme, pal, name))

    def test_palettes_change_only_accent_tokens(self):
        allowed = {"--ac", "--ac-tx", "--face", "--glow", "--hdr-b", "--sapphire", "--sapphire-tx"}
        for theme in cc.THEMES:
            base = cc.resolve_tokens(CSS, theme, "slate")
            for pal in cc.PALETTES[1:]:
                tk = cc.resolve_tokens(CSS, theme, pal)
                changed = {k for k in base if base[k] != tk[k]}
                self.assertLessEqual(changed, allowed, "%s/%s changes %s" % (theme, pal, changed - allowed))
                self.assertTrue(changed, "%s/%s changes nothing" % (theme, pal))
                for f in FAMILY:
                    self.assertEqual(base[f], tk[f])

    def test_legacy_aliases_follow_new_tokens(self):
        for theme in cc.THEMES:
            tk = cc.resolve_tokens(CSS, theme, "slate")
            for old, new in (("--page", "--bg"), ("--surface", "--p1"), ("--surface-2", "--p2"),
                             ("--mist", "--p3"), ("--gray", "--mu"), ("--line", "--ln"), ("--line-2", "--ln2"),
                             ("--sapphire", "--ac"), ("--sapphire-tx", "--ac-tx"), ("--cyan", "--ok-fill"),
                             ("--cyan-tx", "--ok"), ("--plum-tx", "--er"), ("--ir", "--vi"),
                             ("--border", "--ln"), ("--card", "--p1")):
                self.assertEqual(tk[old], tk[new], old)

    def test_slate_values_match_the_design(self):
        d = cc.resolve_tokens(CSS, "dark", "slate")
        for k, v in (("--bg", "#070a10"), ("--p1", "#0d121b"), ("--ac", "#3F66A8"), ("--ac-tx", "#8FB0E6"),
                     ("--cy", "#5CC8E8"), ("--c-sec", "#E88A83")):
            self.assertEqual(d[k], v, k)
        self.assertEqual(cc.resolve_tokens(CSS, "light", "slate")["--bg"], "#edf1f7")

    def test_forge_is_a_named_palette_not_the_default(self):
        self.assertIn("forge", make_diagram.PALETTES)
        self.assertNotIn("slate", make_diagram.PALETTES)       # slate = no attribute
        page = '<html lang="en"><body></body></html>'
        self.assertIn('data-palette="forge"', make_diagram.themed(page, "dark", "current"))
        self.assertIn('data-palette="teal"', make_diagram.themed(page, "dark", "teal"))
        self.assertNotIn("data-palette", make_diagram.themed(page, "dark", "slate"))
        self.assertNotIn("data-palette", make_diagram.themed(page, "dark", "x\"><script>"))

    def test_index_palette_picker_and_migration(self):
        with open(os.path.join(UI, "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        sel = re.search(r'<select id="palsel".*?</select>', html, re.S).group(0)
        opts = re.findall(r'<option value="(\w+)">([^<]+)</option>', sel)
        self.assertEqual([o[0] for o in opts], ["slate", "forge", "teal", "sage", "clay"])
        self.assertEqual([o[1] for o in opts], ["Slate Blue (default)", "Forge", "Teal", "Sage", "Clay"])  # names only; the row says Palette
        themes = re.findall(r'<option value="(\w+)">([^<]+)</option>', re.search(r'<select id="themesel".*?</select>', html, re.S).group(0))
        self.assertEqual(themes, [("dark", "Dark"), ("light", "Light"), ("system", "System")])
        self.assertIn("sp==='current'", html)                  # stored "current" migrates to forge
        self.assertNotIn(':root[data-palette="slate"]', html)  # tokens live only in theme.css

    def test_contrast_pairs_pass(self):
        rows = cc.measure(CSS)
        self.assertGreater(len(rows), 400)
        bad = [r for r in rows if r[3] < r[4]]
        self.assertEqual(bad, [], bad[:3])

    def test_non_text_and_css_derived_pairs_are_measured(self):
        labels = {r[2] for r in cc.measure(CSS)}
        for need in ("field border on card", "field border on track", "focus ring on page", "focus ring on card",
                     "cyan text on callout tint", "alert bad text on tint (from app.css)",
                     "chip warn text (from app.css)"):
            self.assertIn(need, labels)
        for r in cc.measure(CSS):
            if r[2].startswith(("field border", "focus ring")):
                self.assertEqual(r[4], 3.0)
                self.assertGreaterEqual(r[3], 3.0, r)

    def test_field_borders_use_the_field_token(self):
        for name in ("app.css", "campaigns.css", "scenario-cards.css", "campaigns-sensor.css"):
            with open(os.path.join(UI, name), encoding="utf-8") as fh:
                self.assertIn("var(--field-ln)", fh.read(), name)


class TestFonts(unittest.TestCase):
    def test_font_files_are_real_woff2_and_licensed(self):
        for name in FONTS:
            p = os.path.join(UI, name)
            self.assertTrue(os.path.isfile(p), name)
            with open(p, "rb") as fh:
                data = fh.read()
            self.assertEqual(data[:4], b"wOF2", name)
            self.assertTrue(5000 < len(data) < 200000, "%s size %d" % (name, len(data)))
        self.assertTrue(os.path.isfile(os.path.join(UI, "IBM-Plex-OFL.txt")))
        self.assertTrue(os.path.isfile(os.path.join(UI, "Source-Sans-OFL.txt")))      # the second bundled family carries its licence too
        with open(os.path.join(UI, "IBM-Plex-OFL.txt"), encoding="utf-8") as fh:
            self.assertIn("Open Font License", fh.read())

    def test_fonts_in_allow_list_and_served(self):
        for name in FONTS:
            self.assertEqual(campaign_api.STATIC_FILES.get(name), "font/woff2", name)
            status, body, ctype, _ = campaign_api.static_file(name, UI)
            self.assertEqual((status, ctype), (200, "font/woff2"), name)
            self.assertEqual(body[:4], b"wOF2")
        self.assertEqual(campaign_api.static_file("IBM-Plex-OFL.txt", UI)[0], 200)
        self.assertEqual(campaign_api.static_file("theme.css", UI)[0], 200)

    def test_font_face_rules_point_at_allowed_files(self):
        urls = re.findall(r'url\("/ui/([^"]+)"\)', CSS)
        self.assertEqual(sorted(urls), sorted(FONTS))
        self.assertIn("font-display:swap", CSS)

    def test_manifests_list_fonts(self):
        for name in FONTS:                                   # the fonts ship with the ui directory the recipe copies whole
            self.assertTrue(os.path.isfile(os.path.join(DEV, "ui", name)), name)
        with open(os.path.join(DEV, "BUILD-macos.md"), encoding="utf-8") as fh:
            self.assertIn('--add-data "$P/ui:ui"', fh.read())


if __name__ == "__main__":
    unittest.main()

"""Review gaps M11-M14: release-tooling branches, fuzz Hang path, capture_summary/demo_encoder edge cases,
and cheap helper tests for the dev tools."""
import os
import signal
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import promote  # noqa: E402 - sys.path is set up before the import
import compose_public  # noqa: E402 - sys.path is set up before the import


def touch(base, rel, text="x"):
    p = os.path.join(base, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)


class PromoteBranches(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dev = self.tmp.name

    def test_match(self):
        self.assertTrue(promote._match("assets/", "assets/a/b.svg"))
        self.assertFalse(promote._match("assets/", "assetsx/b"))
        self.assertTrue(promote._match("*.py", "a.py"))
        self.assertTrue(promote._match("VERSION", "VERSION"))
        self.assertFalse(promote._match("VERSION", "sub/VERSION"))

    def test_tracked_files_none_outside_git_and_select_fails_open(self):
        self.assertIsNone(promote.tracked_files(self.dev) if not os.path.isdir(os.path.join(self.dev, ".git"))
                          and self._outside_git() else None)
        touch(self.dev, "a.py")
        touch(self.dev, "b.txt")
        man = os.path.join(self.dev, "m.txt")
        touch(self.dev, "m.txt", "*.py\nb.txt\n!b.txt\n")
        with mock.patch.object(promote, "tracked_files", return_value=None):      # not a git tree: everything walked is eligible
            sel, big = promote.select(self.dev, man)
        self.assertEqual(sel, ["a.py"])                    # '!' exclusion beats the include
        self.assertEqual(big, [])

    def _outside_git(self):
        import subprocess
        return subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=self.dev, capture_output=True).returncode != 0

    def test_untracked_excluded_when_tracked_known(self):
        touch(self.dev, "a.py")
        touch(self.dev, "u.py")
        touch(self.dev, "m.txt", "*.py\n")
        with mock.patch.object(promote, "tracked_files", return_value={"a.py", "m.txt"}):
            sel, _ = promote.select(self.dev, os.path.join(self.dev, "m.txt"))
        self.assertEqual(sel, ["a.py"])

    def test_strays_and_prune_empty(self):
        touch(self.dev, "ok.py")
        touch(self.dev, "x.pcap")
        touch(self.dev, "certs/c.pem")
        touch(self.dev, "deep/.env")
        self.assertEqual(sorted(promote.strays(self.dev)), ["certs/c.pem", "deep/.env", "x.pcap"])
        os.makedirs(os.path.join(self.dev, "e1", "e2"))
        os.makedirs(os.path.join(self.dev, "keep"))
        touch(self.dev, "keep/f")
        promote.prune_empty(self.dev)
        self.assertFalse(os.path.exists(os.path.join(self.dev, "e1")))
        self.assertTrue(os.path.exists(os.path.join(self.dev, "keep", "f")))
        self.assertTrue(os.path.isdir(self.dev))


class ComposePublic(unittest.TestCase):
    def test_compose_preserves_live_workflow_and_routes_files(self):
        with tempfile.TemporaryDirectory() as t:
            exp, into = os.path.join(t, "exp"), os.path.join(t, "into")
            touch(exp, "VERSION", "1\n")
            touch(exp, "engine.py")
            touch(exp, "README.md")
            touch(exp, "MANIFEST.sha256")
            touch(exp, ".github/workflows/ci.yml", "NEW")        # the export's workflow is never composed
            touch(into, ".github/workflows/ci.yml", "LIVE")
            touch(into, "stale.txt")
            os.makedirs(os.path.join(into, ".git"))
            n = compose_public.compose(exp, into)
            self.assertEqual(n, 3)
            with open(os.path.join(into, ".github/workflows/ci.yml")) as f:
                self.assertEqual(f.read(), "LIVE")
            self.assertTrue(os.path.isfile(os.path.join(into, "dev", "engine.py")))
            self.assertTrue(os.path.isfile(os.path.join(into, "README.md")))
            self.assertFalse(os.path.exists(os.path.join(into, "stale.txt")))
            self.assertFalse(os.path.exists(os.path.join(into, "dev", "MANIFEST.sha256")))
            self.assertTrue(os.path.isdir(os.path.join(into, ".git")))

    def test_compose_refuses_non_export(self):
        with tempfile.TemporaryDirectory() as t, self.assertRaises(SystemExit):
            compose_public.compose(t, t)


@unittest.skipUnless(hasattr(signal, "SIGALRM"), "needs SIGALRM")
class FuzzHang(unittest.TestCase):
    def test_hang_reported(self):
        import fuzz
        signal.signal(signal.SIGALRM, fuzz._alarm)
        self.addCleanup(signal.signal, signal.SIGALRM, signal.SIG_DFL)
        with mock.patch.object(fuzz, "HANG_ALARM", 1):
            res = fuzz.run_one("t", lambda raw: time.sleep(5), b"x", "bytes", False)
        self.assertTrue(res and res.startswith("HANG"), res)
        self.assertEqual(signal.alarm(0), 0)                # the alarm was cleared

    def test_clean_and_allowed_and_uncaught(self):
        import fuzz
        self.assertIsNone(fuzz.run_one("t", lambda raw: None, b"x", "bytes", False))
        self.assertIsNone(fuzz.run_one("t", lambda raw: (_ for _ in ()).throw(ValueError("bad")), b"x", "bytes", False))
        self.assertIn("uncaught KeyError", fuzz.run_one("t", lambda raw: {}["k"], b"x", "bytes", False))
        self.assertIsNone(fuzz.run_one("t", lambda raw: None, b"x", "bytes", True))      # memory pass, tiny


class CaptureSummaryAndEncoder(unittest.TestCase):
    def ectx(self, out):
        w = types.SimpleNamespace(n=3, bytes=300, protocols={"TCP": 2, "UDP": 1})
        return types.SimpleNamespace(out=out, writer=w, ctx=types.SimpleNamespace(h={"a": 1}), selected=["s"])

    def test_pcap_and_pcapng_paths(self):
        from modules import capture_summary as CS
        with tempfile.TemporaryDirectory() as t:
            r = CS._summary(self.ectx(os.path.join(t, "c.pcap")))
            self.assertEqual(r["summary_json"], os.path.join(t, "c-summary.json"))
            r = CS._summary(self.ectx(os.path.join(t, "c.pcapng")))
            self.assertEqual(r["summary_json"], os.path.join(t, "c.pcapng-summary.json"))   # only .pcap is stripped today
            self.assertTrue(os.path.isfile(r["summary_json"]))

    def test_oserror_branch(self):
        from modules import capture_summary as CS
        self.assertEqual(CS._summary(self.ectx("/nonexistent-dir-xyz/c.pcap")), {"summary_json": None})

    def test_demo_encoder_double_register(self):
        from modules import demo_encoder as DE
        from netgen import protocols as P
        kernel = types.SimpleNamespace(on_unload=lambda fn: None)
        self.addCleanup(P.reset_encoder, DE.ENCODER)
        DE.register(kernel)
        DE.register(kernel)                                  # must not capture itself as the built-in
        out = P.ftp_line("220 hi")
        self.assertEqual(out.count(b"[demo-encoder]"), 1)


class DevToolHelpers(unittest.TestCase):
    def test_contrast_math(self):
        import contrast_check as CC
        self.assertEqual(CC.hex_rgb("#fff"), (255, 255, 255))
        self.assertEqual(CC.hex_rgb("#102030"), (16, 32, 48))
        self.assertAlmostEqual(CC.ratio((0, 0, 0), (255, 255, 255)), 21.0, places=3)
        self.assertAlmostEqual(CC.ratio((9, 9, 9), (9, 9, 9)), 1.0)
        self.assertEqual(CC.parse_color("color-mix(in srgb, #000000 50%, #ffffff)"), (127.5, 127.5, 127.5))
        self.assertEqual(CC.parse_color("color-mix(in srgb, #000000, #ffffff)"), (127.5, 127.5, 127.5))
        with self.assertRaises(ValueError):
            CC.parse_color("rgb(1,2,3)")
        self.assertEqual(CC.gradient_stops("linear-gradient(90deg, #aabbcc, #001122)"), ["#aabbcc", "#001122"])
        toks = CC.resolve_tokens(":root{--a:#111111;--b:var(--a)} :root[data-theme=\"light\"]{--a:#eeeeee}", "light", "slate")
        self.assertEqual(toks["--a"], "#eeeeee")

    def test_redesign_mapping_parsers(self):
        import check_redesign_mapping as CM
        rows = CM.parse_mapping("# Top\n|a|b|\n|---|---|\n| `#go` | `GET /api/x?y=1` |\n## Later (designed, not built)\n| `#nope` |\n")
        self.assertEqual(len(rows), 3)
        self.assertEqual((rows[1][2], rows[1][3], rows[1][4]), (False, ["go"], [("GET", "/api/x")]))
        self.assertTrue(rows[2][2])
        self.assertEqual(CM.html_ids('<a id="x"></a><b id="y">'), {"x", "y"})
        self.assertEqual(CM.js_defines_id("go", {"a.js": "x('#go .y')"}), "a.js")
        self.assertIsNone(CM.js_defines_id("go", {"a.js": "x('#gone')"}))
        self.assertEqual(CM._keys_of('{\n "/a": 1,\n "/b": 2}'), {"/a", "/b"})
        self.assertEqual(CM._block("x = {a: {b}} tail", r"x ="), "{a: {b}}")

    def test_geo_dp_and_area(self):
        import build_geo as BG
        line = [(0, 0), (1, 0.01), (2, 0)]
        self.assertEqual(BG.dp(line, 0.1), [(0, 0), (2, 0)])
        self.assertEqual(BG.dp(line, 0.001), line)
        self.assertEqual(BG.dp([(0, 0), (1, 1)], 0.1), [(0, 0), (1, 1)])
        self.assertEqual(BG.dp([(0, 0), (0, 0), (0, 0)], 0.1), [(0, 0), (0, 0)])

    def test_render_diagram_browser_lookup(self):
        import render_diagram as RD
        with tempfile.NamedTemporaryFile() as f, mock.patch.dict(os.environ, {"CHROME": f.name}):
            self.assertEqual(RD.browser(), f.name)
        with mock.patch.dict(os.environ, {"CHROME": "/no/such"}), mock.patch.object(RD, "CANDIDATES", ["/no/other"]), \
                mock.patch.object(RD, "PATH_NAMES", []), self.assertRaises(SystemExit):
            RD.browser()

    def test_verify_scenario_meta_compare_and_verdict(self):
        import verify_scenario_meta as VS
        self.assertEqual(VS.resolve("definitely-not-a-label-xyz")[0], "unknown")
        c = VS.compare(["definitely-not-a-label-xyz"], {"TCP": 5})
        self.assertEqual(c["unverifiable"], ["definitely-not-a-label-xyz"])
        self.assertEqual(VS.verdict(c, 10)[0], "inconclusive")
        self.assertEqual(VS.verdict(c, 0)[0], "fail")
        self.assertEqual(VS.verdict(c, 10, error="boom")[0], "inconclusive")
        self.assertEqual(VS.verdict(c, 10, recipe_driven=True)[0], "inconclusive")
        miss = {"verified": [], "carrier_only": [], "missing": ["X"], "unverifiable": [], "extra": []}
        self.assertEqual(VS.verdict(miss, 5)[0], "fail")
        ok = {"verified": ["X"], "carrier_only": [], "missing": [], "unverifiable": [], "extra": []}
        self.assertEqual(VS.verdict(ok, 5), ("pass", ""))

    def test_meta_truth_render(self):
        import meta_truth as MT
        src, dst = types.SimpleNamespace(ip="1.1.1.1"), types.SimpleNamespace(ip="2.2.2.2", fqdn="h.example")
        spec = types.SimpleNamespace(params={"n": {"default": 7}})
        self.assertEqual(MT.render("ip.src=={src_ip} {dst_ip} {fqdn} {p:n} {p:m}", src, dst, spec, {"m": "M"}),
                         "ip.src==1.1.1.1 2.2.2.2 h.example 7 M")
        self.assertIsNone(MT.render("{p:zzz}", src, dst, spec, {}))
        self.assertIsNone(MT.render("{fqdn}", src, types.SimpleNamespace(ip="2.2.2.2"), spec, {}))

    def test_measure_scenario_scale_ids(self):
        import measure_scenario_scale as MS
        self.assertTrue(MS.ANCHORS == sorted(MS.ANCHORS))
        ids = MS.scenario_ids()
        self.assertTrue(len(ids) > 10 and all(isinstance(i[0], str) and isinstance(i[1], bool) for i in ids))


if __name__ == "__main__":
    unittest.main()

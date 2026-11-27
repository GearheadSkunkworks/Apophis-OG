"""Regression tests for the 6.0 hostile-review fix pass (findings S-A, S-E, S-F, ...). Each test fails on the pre-fix code."""
import json
import os
import sys
import time
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tests"))
from test_agent_api import Base  # noqa: E402 - sys.path is set first; Base starts a handler with a fake keystore
import captures_store  # noqa: E402 - sys.path is set up first
import build_manifest  # noqa: E402 - sys.path is set up first
import exports_ipfix  # noqa: E402 - sys.path is set up first
import pcapprofile  # noqa: E402 - sys.path is set up first
import replay  # noqa: E402 - sys.path is set up first
import overlay  # noqa: E402 - sys.path is set up first
from intel import classify, parsers, sources  # noqa: E402 - sys.path is set up first


class IntelHostileInput(unittest.TestCase):
    def test_stix_pattern_scan_is_linear(self):           # S-A: 8 s for "a:" * 10000 before the fix
        for pat in ("a:" * 10000, "x:" + "a" * 19990, "a" * 20000, "a:b" * 6000):
            t = time.monotonic()
            list(parsers._stix_atoms(pat))
            self.assertLess(time.monotonic() - t, 0.5, pat[:12])

    def test_stix_still_finds_real_atoms(self):
        got = list(parsers._stix_atoms("[ipv4-addr:value = '1.2.3.4' OR file:hashes.'SHA-256' = 'ab' OR domain-name:value IN ('a.com','b.com')]"))
        self.assertEqual([v for _, _, v in got], ["1.2.3.4", "ab", "a.com", "b.com"])

    def test_classify_survives_unicode_digits(self):      # S-E: ValueError on a superscript prefix length
        for s in ("1.2.3.4/²", "1.2.3.4/٣", "::1/²", "1.2.3.4/99999999999", "1.2.3.4/33"):
            self.assertEqual(classify.classify_value(s)[0], None, s)
        self.assertEqual(classify.classify_value("10.0.0.0/8")[0], "cidr")
        self.assertEqual(classify.classify_value("2001:db8::/32")[0], "cidr")

    def test_slow_body_hits_the_deadline(self):           # S-F: the deadline was only checked between 64 KiB reads
        now = [0.0]

        class Drip:
            def read1(self, n):
                now[0] += 19.0                            # one byte per 19 s
                return b"x"
        with self.assertRaises(sources.FeedError):
            sources.read_capped(Drip(), 10_000_000, 60.0, clock=lambda: now[0])
        self.assertLessEqual(now[0], 60.0 + 19.0)

    def test_read_capped_returns_the_body_and_enforces_the_cap(self):
        class Body:
            def __init__(self, parts):
                self.parts = list(parts)

            def read1(self, n):
                return self.parts.pop(0) if self.parts else b""
        self.assertEqual(sources.read_capped(Body([b"ab", b"cd"]), 10, 1e18), b"abcd")
        with self.assertRaises(sources.FeedError):
            sources.read_capped(Body([b"abcdef"]), 4, 1e18)


class OverlayTree(unittest.TestCase):
    def test_symlinked_directory_in_an_update_tree_is_refused(self):    # S-C: os.walk lists it in dirs, not files
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            tree, evil = os.path.join(d, "tree"), os.path.join(d, "evil")
            os.makedirs(tree)
            os.makedirs(evil)
            with open(os.path.join(tree, "a.txt"), "w") as fh:
                fh.write("a")
            manifest = {"files": {"a.txt": overlay._hash(os.path.join(tree, "a.txt"))}}
            overlay.check_tree(tree, manifest)                           # clean tree passes
            os.symlink(evil, os.path.join(tree, "json"))
            with self.assertRaises(ValueError):
                overlay.check_tree(tree, manifest)


class ForgedManifest(unittest.TestCase):
    def test_same_settings_rebuild_deletes_only_the_captures_own_names(self):    # S-H
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            sig = {"generator": "g", "parameters": {"scale": 1}}
            for n in ("x.pcap", "precious.txt", "x-truth.jsonl"):
                with open(os.path.join(d, n), "w") as fh:
                    fh.write(n)
            forged = dict(sig, outputs=[{"name": "x.pcap"}, {"name": "precious.txt"}, {"name": "../escape.txt"}, {"name": "x-truth.jsonl"}])
            with open(os.path.join(d, "x.manifest.json"), "w") as fh:
                json.dump(forged, fh)
            held = captures_store.hold_previous(os.path.join(d, "x.pcap"), None, None, sig)
            held.commit()                                                 # same settings: the held copy is deleted
            left = sorted(os.listdir(d))
            self.assertIn("precious.txt", left)
            self.assertEqual([n for n in left if n.startswith("x")], [])  # its own files were replaced as designed

    def test_own_output_names(self):
        f = captures_store.own_output
        for ok in ("x.pcap", "x-zeek/conn.log", "x_a", "x"):
            self.assertTrue(f("x.pcap", ok), ok)
        for bad in ("precious.txt", "xy.pcap", "../x.pcap", "", None, 5):
            self.assertFalse(f("x.pcap", bad), bad)
        # the threat collection is named after the company: still ours for an all-in-one capture, and only then
        self.assertTrue(f("acme-all-in-one.pcap", "acme-threat-collection.stix.json"))
        self.assertFalse(f("x.pcap", "acme-threat-collection.stix.json"))

    def test_every_sibling_a_build_writes_is_still_held(self):         # the fix must not stop keep-previous holding real outputs
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            sig = {"generator": "g", "parameters": {"scale": 1}}
            names = ["acme-all-in-one.pcap", "acme-all-in-one-tls-keys.log", "acme-threat-collection.stix.json", "acme-threat-collection.csv",
                     "acme-all-in-one-truth.jsonl", "acme-all-in-one.manifest.json"]
            for n in names:
                with open(os.path.join(d, n), "w") as fh:
                    fh.write(n)
            with open(os.path.join(d, "acme-all-in-one.manifest.json"), "w") as fh:
                json.dump(dict(sig, outputs=[{"name": n} for n in names]), fh)
            held = captures_store.hold_previous(os.path.join(d, "acme-all-in-one.pcap"), None, None, sig)
            self.assertEqual(sorted(held.files), sorted(names))


class StopDuringIndexing(unittest.TestCase):
    def setUp(self):
        import tempfile
        from unittest import mock
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": os.path.join(self.tmp, "settings")})
        p.start()
        self.addCleanup(p.stop)

    def test_reset_forgets_the_previous_runs_files(self):                # S-G
        replay._RUN.update(stopfile="/previous/STOP", logfile="/previous/log", dir="/previous")
        replay._reset("p.pcap", "", "1x", 1)
        self.assertIsNone(replay._RUN["stopfile"])
        self.assertIsNone(replay._RUN["dir"])

    def test_stop_while_indexing_prevents_the_launch(self):             # S-G: it used to touch a stale file and replay in full
        from unittest import mock
        replay._reset("p.pcap", "", "1x", 1)
        idx = {"packets": 1, "bytes": 1, "duration": 1.0, "exact": True, "first_ts": None, "last_ts": None, "linktype": 1}

        def index(_p):
            self.assertTrue(replay.stop()["ok"])                       # the person pressed Stop during indexing
            return idx
        launched = mock.Mock()
        with mock.patch.object(replay, "find_tool", return_value="/bin/echo"), mock.patch.object(replay, "index_pcap", index), \
                mock.patch.object(replay, "_begin_record", return_value={"first_packet": 1, "last_packet": 1}), \
                mock.patch.object(replay, "_launch_unprivileged", launched), mock.patch.object(replay, "_write_runfile"):
            replay._run("p.pcap", "", "multiplier", 1.0, 1, "1x", privileged=False, monitor=False, opts={})
        launched.assert_not_called()
        st = replay.status()
        self.assertEqual((st["running"], st["phase"]), (False, "stopped"))


class HostilePcap(unittest.TestCase):
    def test_minute_and_mac_tables_are_capped(self):                    # S-I: both grew with every distinct value
        import struct
        import tempfile
        from unittest import mock
        eth = bytearray(b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00") + bytes(40)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "h.pcap")
            with open(path, "wb") as f:
                f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
                for i in range(300):
                    fr = bytearray(eth)
                    fr[6:12] = struct.pack(">Q", 0x020000000000 + i)[2:]
                    f.write(struct.pack("<IIII", 1_700_000_000 + i * 60, 0, len(fr), len(fr)) + bytes(fr))
            with mock.patch.object(pcapprofile, "MAX_MINUTES", 20), mock.patch.object(pcapprofile, "MAX_MACS", 30):
                pr = pcapprofile.profile(path)
        self.assertEqual(len(pr["minute_pkts"]), 20)
        self.assertEqual(len(pr["macs"]), 30)
        self.assertEqual(pr["overflow"]["minutes"], 280)
        self.assertEqual(pr["overflow"]["macs"], 270)
        self.assertEqual(pr["pkts"], 300)                               # totals stay complete


class AgentScope(Base):
    def test_agent_capture_list_ignores_out_dir_but_the_page_may_use_it(self):    # S-L(a)
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as other, tempfile.TemporaryDirectory() as home:
            with open(os.path.join(other, "secret-name.pcap"), "wb") as fh:
                fh.write(b"x")
            with mock.patch.object(self.server, "DEFAULT_OUT", os.path.realpath(home)):
                q = "?out_dir=" + os.path.realpath(other)
                st, body = self.call("GET", "/agent/v1/capture/list" + q, bearer=self.token)
                self.assertEqual(st, 200)
                self.assertNotIn("secret-name", json.dumps(body))
                st, body = self.call("GET", "/api/captures" + q, cookie="og_ui=" + self.server.UI_SECRET)
                self.assertIn("secret-name", json.dumps(body))                      # the page keeps the folder picker

    def test_campaign_scale_is_capped_for_run_and_estimate(self):                  # S-L(b)
        for verb in ("campaign/estimate", "campaign/run"):
            for bad in (1000, 1.5, float("nan")):
                st, _ = self.call("POST", "/agent/v1/" + verb, {"campaign": {}, "scale": bad}, bearer=self.token)
                self.assertEqual(st, 400, (verb, bad))


class PageCsp(Base):
    def headers(self, path):
        import urllib.request
        r = urllib.request.urlopen(self.base + path, timeout=60)
        r.read()
        return r.headers.get_all("Content-Security-Policy") or []

    def test_generated_pages_forbid_script_and_the_app_page_does_not(self):    # S-M
        for path in ("/about", "/report", "/diagram?name=none", "/profile"):
            try:
                csp = self.headers(path)
            except Exception as e:                                          # noqa: BLE001 - an error status still carries the header
                csp = e.headers.get_all("Content-Security-Policy") if hasattr(e, "headers") else []
            if path in ("/about", "/report"):
                self.assertIn("script-src 'none'", csp, path)
            self.assertIn("frame-ancestors 'none'", csp, path)
        self.assertEqual(self.headers("/"), ["frame-ancestors 'none'"])      # the UI needs its own scripts

    def test_campaign_diagram_page_carries_the_meta_policy(self):            # S-M: this page is opened from a Blob URL, with no headers
        import campaign_api
        with open(os.path.join(DEV, "tests", "fixtures", "campaigns", "15-scored.json"), encoding="utf-8") as fh:
            camp = json.load(fh)
        with open(os.path.join(DEV, "tests", "fixtures", "campaigns", "15-scored.summary.json"), encoding="utf-8") as fh:
            summary = json.load(fh)
        st, out = campaign_api.campaign_diagram({"campaign": camp, "summary": summary})
        self.assertEqual(st, 200)
        self.assertIn("http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'\"", out["html"])
        self.assertNotIn("<script", out["html"].lower())

    def test_templates_carry_the_meta_policy_and_no_script(self):           # S-M: also holds for a saved file or a Blob tab
        import page_template
        pg = page_template.page("t", "h", "<p>x</p>")
        self.assertIn("script-src 'none'", pg)
        self.assertNotIn("<script", pg)
        import make_diagram
        src = open(os.path.join(DEV, "make_diagram.py"), encoding="utf-8").read()
        self.assertIn("http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'\"", src)
        self.assertTrue(make_diagram.render_page)


class RootDylibs(unittest.TestCase):
    """S-B: a root-run tcpreplay must not load a library a same-user process could have planted."""
    OTOOL_L = ("/x/tcpreplay:\n\t/opt/homebrew/opt/libdnet/lib/libdnet.1.dylib (compatibility version 2.0.0, current version 2.0.0)\n"
               "\t@rpath/libpcap.A.dylib (compatibility version 1.0.0, current version 1.10.0)\n"
               "\t@loader_path/../lib/libx.dylib (compatibility version 1.0.0)\n"
               "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n\t/System/Library/Frameworks/Foo.framework/Foo (compatibility version 1.0.0)\n")
    OTOOL_R = "Load command 12\n          cmd LC_RPATH\n      cmdsize 32\n         path /opt/homebrew/lib (offset 12)\n"

    def test_refs_skip_system_and_expand_rpath(self):
        got = replay.parse_dylib_refs(self.OTOOL_L, self.OTOOL_R, "/usr/local/bin")
        self.assertEqual(got, ["/opt/homebrew/opt/libdnet/lib/libdnet.1.dylib", "/opt/homebrew/lib/libpcap.A.dylib", "/usr/local/lib/libx.dylib"])

    def test_the_refusal_names_the_library(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            tool = os.path.join(d, "tcpreplay")
            open(tool, "w").close()
            os.chmod(tool, 0o755)
            os.chmod(d, 0o755)
            lib = os.path.join(d, "writable", "libdnet.dylib")
            os.makedirs(os.path.dirname(lib), mode=0o777)
            os.chmod(os.path.dirname(lib), 0o777)
            why = replay.root_check(tool, owners=(0, os.getuid()), deps_of=lambda _r: [lib])
            self.assertIn("libdnet.dylib", why)
            self.assertIn("library", why)

    def test_dependencies_must_resolve_under_root_owned_non_writable_dirs(self):
        import tempfile
        me = (0, os.getuid())
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            tool = os.path.join(d, "tcpreplay")
            open(tool, "w").close()
            os.chmod(tool, 0o755)
            os.chmod(d, 0o755)
            libs = os.path.join(d, "lib")
            os.mkdir(libs, 0o755)
            lib = os.path.join(libs, "libdnet.dylib")
            open(lib, "w").close()
            self.assertTrue(replay.root_safe(tool, owners=me, deps_of=lambda _r: [lib]))
            self.assertTrue(replay.root_safe(tool, owners=me, deps_of=lambda _r: []))
            os.chmod(libs, 0o775)                                   # a library folder others can write (Homebrew's user-owned prefix)
            self.assertFalse(replay.root_safe(tool, owners=me, deps_of=lambda _r: [lib]))
            self.assertFalse(replay.root_safe(tool, owners=me, deps_of=lambda _r: [os.path.join(libs, "missing.dylib")]))   # not yet planted
            self.assertFalse(replay.root_safe(tool, owners=me, deps_of=lambda _r: None))      # cannot tell: refuse
            self.assertFalse(replay.root_safe(tool, owners=(os.getuid() + 12345,), deps_of=lambda _r: []))    # the binary itself, as before


class NotedCheapFixes(unittest.TestCase):
    def test_content_disposition_name_has_no_header_splitting_characters(self):
        import server
        self.assertEqual(server._header_name('a\r\nSet-Cookie: x=1.pcap'), "aSet-Cookie: x=1.pcap")
        self.assertEqual(server._header_name('q"u\\o\x00te'), "quote")

    def test_export_errors_name_files_not_folders(self):
        r = build_manifest.export_error(OSError(13, "Permission denied", "/data/someone/captures/out/a.pcap"))
        self.assertNotIn("/", r)
        self.assertEqual(build_manifest.export_error(ValueError("no space in /data/x/y/z.csv")), "ValueError: no space in z.csv")

    def test_ipfix_export_does_not_follow_a_planted_link(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            victim = os.path.join(d, "victim.txt")
            with open(victim, "w") as fh:
                fh.write("keep")
            pcap, csvp = os.path.join(d, "e.pcap"), os.path.join(d, "e.csv")
            os.symlink(victim, csvp)
            exports_ipfix.write_export([], 10, 2055, pcap, csvp)
            with open(victim) as fh:
                self.assertEqual(fh.read(), "keep")

    def test_pcapng_truncated_inside_the_section_header_reads_as_empty(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.pcapng")
            with open(p, "wb") as fh:
                fh.write(b"\x0a\x0d\x0d\x0a" + b"\x1c\x00\x00\x00")
            self.assertEqual(list(pcapprofile.iter_frames_lt(p)), [])


if __name__ == "__main__":
    unittest.main()

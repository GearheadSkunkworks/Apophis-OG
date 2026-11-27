#!/usr/bin/env python3
"""OpenGenerator self-test harness — the project's regression gate.

Pure standard library (``unittest``); the only third-party import is ``cryptography``, which the
engine already needs. No pytest, so CI needs nothing beyond ``pip install -r requirements.txt``.

Run from this directory::

    python3 selftest.py            # all suites, verbose
    python3 selftest.py -k pin     # just the baseline-pin tests

Exit code is 0 iff everything passes, so it drops straight into CI (see ``.github/workflows``).

What it guards:
  * **The baseline pin** — the no-module build at ``--scale 0.004`` is exactly 466,343 packets,
    and is deterministic across repeated in-process builds (the ``reseed_all`` property).
  * **The capability framework** — every module under ``modules/`` discovers with a usable
    manifest, loads, passes its own ``self_test``, and unloads *cleanly*: the registries it
    touched return to their exact pre-load counts, and a loaded (but unselected) module never
    moves the pin.
  * **The encoder facade** — ``register_encoder`` / ``reset_encoder`` round-trips back to the
    built-in implementation.
  * **The engine checks** — the fast scripts in ``checks/`` (random-stream equivalence, IP
    options, the scenario-proof harness self-test).
"""
import os
import shutil
import sys
import tempfile
import unittest

# Run from this file's directory so the engine imports regardless of the caller's cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import opengenerator_build as OGB          # noqa: E402 - sys.path is set up before the import
from netgen import platform as capmod      # noqa: E402 - sys.path is set up before the import
from netgen import protocols as P          # noqa: E402 - sys.path is set up before the import

PIN = 466343
SCALE = 0.004
_INVENTORY = os.path.join(_HERE, "inventory.json")


def build_baseline(scale=SCALE, modules=None):
    """Build the no-module baseline into a throwaway temp dir (absolute paths, no chdir) and
    return its packet count. ``modules=[]`` is the pinned no-module build."""
    d = tempfile.mkdtemp(prefix="og-selftest-")
    try:
        r = OGB.build(scale=scale, out=os.path.join(d, "s.pcap"),
                      keylog=os.path.join(d, "s.keys"), inventory=_INVENTORY,
                      certs_dir=None, iocs_prefix=None,
                      modules=[] if modules is None else modules, progress=False)
        return r["packets"]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def fresh_kernel():
    """A kernel with the same built-in registries wired under it as the server wires at startup,
    so ``builtins()`` reports live counts and leak checks are meaningful."""
    from netgen import incidents as INC
    from sensorops import providers as PV
    import make_diagram as MD

    k = capmod.Kernel()
    k.discover()
    k.register_source("scenarios", lambda: len(INC.REGISTRY))
    k.register_source("diagrams", lambda: len(MD.DIAGRAMS))
    k.register_source("encoders", lambda: len(P.encoder_names()))
    k.register_source("exporters", lambda: len(OGB.EXPORTERS))
    k.register_source("providers", lambda: PV.available())
    return k


class TestBaselinePin(unittest.TestCase):
    """The core invariant: the default capture is byte-count-stable at 466,343 packets."""

    def test_no_module_baseline_is_466343(self):
        self.assertEqual(build_baseline(), PIN,
                         "no-module --scale %s baseline must stay pinned" % SCALE)

    def test_builds_are_deterministic(self):
        # reseed_all() must make a second in-process build reproduce the first exactly.
        first, second = build_baseline(), build_baseline()
        self.assertEqual(first, PIN)
        self.assertEqual(first, second, "two in-process builds diverged -> reseed_all regressed")


class TestCapabilityModules(unittest.TestCase):
    """Every shipped module discovers, loads, self-tests, and unloads without leaking."""

    @classmethod
    def setUpClass(cls):
        cls.k = fresh_kernel()
        cls.catalog = cls.k.catalog()
        cls.names = [c["name"] for c in cls.catalog]

    def test_at_least_the_known_modules_discovered(self):
        self.assertIn("baseline_pin", self.names)
        self.assertIn("capture_summary", self.names)

    def test_no_manifest_errors(self):
        bad = [c["name"] for c in self.catalog if c.get("error")]
        self.assertEqual(bad, [], "modules with a bad manifest: %s" % bad)

    def test_kinds_are_known(self):
        unknown = [(c["name"], c["kind"]) for c in self.catalog if not c["kind_known"]]
        self.assertEqual(unknown, [], "modules with an unknown kind: %s" % unknown)

    def test_each_module_load_test_unload_clean(self):
        for name in self.names:
            with self.subTest(module=name):
                before = self.k.builtins()
                self.assertTrue(self.k.load(name), "%s failed to load" % name)
                try:
                    res = self.k.self_test(name)
                    self.assertTrue(res.get("ok"),
                                    "%s self_test failed: %s" % (name, res.get("detail")))
                finally:
                    self.assertTrue(self.k.unload(name), "%s failed to unload" % name)
                after = self.k.builtins()
                self.assertEqual(before, after,
                                 "%s leaked registry state: %s -> %s" % (name, before, after))
                self.assertFalse(self.k.is_loaded(name), "%s still loaded after unload" % name)


class TestPinUnderChurn(unittest.TestCase):
    """Loading modules must not move the pin, and a full load/unload cycle must leave it intact."""

    def test_pin_holds_with_all_modules_loaded(self):
        k = fresh_kernel()
        names = [c["name"] for c in k.catalog()]
        for n in names:
            k.load(n)
        try:
            self.assertEqual(build_baseline(), PIN,
                             "a loaded-but-unselected module moved the pin")
        finally:
            for n in names:
                k.unload(n)
        self.assertEqual(build_baseline(), PIN, "pin did not recover after unloading all modules")


class TestEncoderFacade(unittest.TestCase):
    """register_encoder / reset_encoder round-trips to the built-in implementation."""

    def test_override_and_reset(self):
        name = "ftp_line"
        self.assertIn(name, P.encoder_names())
        sentinel = "OVERRIDDEN\r\n"
        builtin = P.register_encoder(name, lambda *_a, **_k: sentinel)
        try:
            self.assertEqual(P.ftp_line("whatever"), sentinel, "override not active")
        finally:
            P.reset_encoder(name)
        # after reset, the public function must behave like the built-in again
        self.assertEqual(P.ftp_line("200 OK"), builtin("200 OK"),
                         "reset_encoder did not restore the built-in")


class TestEngineChecks(unittest.TestCase):
    """The fast scripts under ``checks/`` (added in the engine update) pass.

    check_stream_equivalence  hot helpers keep their bytes AND their random stream (the pin depends on it)
    check_ip_options          default ipv4()/handshake() unchanged; IP options and the Linux SYN-ACK are valid
    check_png                 every image/png body is a real PNG
    check_isolated_rng        the pool helpers survive an imported `secrets`
    scenario_proof --selftest the proof harness's own self-test
    check_rfc791              an independent IPv4/TCP/UDP/ICMP validator passes a fresh baseline build
    The slower checks (company identity, ransomware SMB2, CAPWAP, custom networks) are run by hand."""

    def _run(self, *argv):
        import subprocess
        r = subprocess.run([sys.executable] + list(argv), cwd=_HERE, capture_output=True, text=True, timeout=900)
        self.assertEqual(r.returncode, 0, "%s failed:\n%s%s" % (argv[0], r.stdout[-800:], r.stderr[-800:]))

    def test_stream_equivalence(self):
        self._run("checks/check_stream_equivalence.py")

    def test_ip_options(self):
        self._run("checks/check_ip_options.py")

    def test_png_bodies(self):
        self._run("checks/check_png.py")

    def test_isolated_rng(self):
        self._run("checks/check_isolated_rng.py")

    def test_campaign_unit_suites(self):
        """The fast campaign-builder suites (intel parsers, campaign core, actions). The slower
        end-to-end runner suite is ``python -m unittest tests.test_campaign_runner`` (about 2 minutes)."""
        self._run("-m", "unittest", "tests.test_intel", "tests.test_campaign_core",
                  "tests.test_actions_a", "tests.test_actions_b", "tests.test_actions_host",
                  "tests.test_actions_outside", "tests.test_actions_data", "tests.test_families",
                  "tests.test_feedback", "tests.test_geo", "tests.test_meta_a", "tests.test_meta_b",
                  "tests.test_meta_c", "tests.test_meta_complete", "tests.test_diagram_resolve",
                  "tests.test_diagram_view", "tests.test_diagram_layout", "tests.test_pcap_import")

    def test_sessions(self):
        """Saved sessions: round trip, no secrets or acknowledgements on disk, bounded shape."""
        self._run("-m", "unittest", "tests.test_sessions")

    def test_campaign_api(self):
        """The GUI's HTTP endpoints (real handler on an ephemeral port, no network, no full build)."""
        self._run("-m", "unittest", "tests.test_campaign_api")

    def test_campaign_ui_logic(self):
        """The browser modules' pure logic under node (skipped when node is not installed)."""
        import shutil
        node = shutil.which("node")
        if not node:
            self.skipTest("node not installed")
        major = int(__import__("subprocess").run([node, "-p", "process.versions.node.split('.')[0]"],
                                                   capture_output=True, text=True, timeout=30).stdout.strip() or 0)
        self.assertGreaterEqual(major, 18, "node 18 or newer is required for the JS tests (node:test); found %s" % node)
        for name in ("shell", "editor", "library", "sensor", "board"):
            r = __import__("subprocess").run([node, "--test", "tests/js/%s.test.js" % name], cwd=_HERE,
                                             capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, "%s UI tests failed:\n%s" % (name, r.stdout[-800:]))

    def test_scenario_proof_selftest(self):
        self._run("checks/scenario_proof.py", "--selftest")

    def test_rfc791_clean_baseline(self):
        """The independent IPv4/TCP/UDP/ICMP validator passes a freshly built baseline capture."""
        d = tempfile.mkdtemp(prefix="og-rfc791-")
        try:
            pcap = os.path.join(d, "r.pcap")
            OGB.build(scale=0.001, out=pcap, keylog=os.path.join(d, "r.keys"), inventory=_INVENTORY,
                      certs_dir=None, iocs_prefix=None, modules=[], progress=False)
            self._run("checks/check_rfc791.py", pcap, "--quiet")
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Tests for factory/check_factory.py: each rule fires on a violating snippet, stays quiet on a clean one, and the
repository's own factory files pass. The factory folder is not promoted to releases, so the module skips when absent."""
import importlib.util
import os
import unittest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
_PATH = os.path.join(_ROOT, "factory", "check_factory.py")


@unittest.skipUnless(os.path.isfile(_PATH), "factory/ is not part of this tree")
class FactoryLintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("check_factory", _PATH)
        cls.F = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.F)

    def rules(self, found):
        return sorted({v[0] for v in found})

    def test_repo_factory_files_are_clean(self):
        self.assertEqual(self.F.run(_ROOT), [])

    def test_every_required_rule_is_enforced(self):
        full = "".join("- %s: text\n" % r for r in self.F.REQUIRED_RULES)
        self.assertEqual(self.F.check_rules_text(full), [])
        for r in self.F.REQUIRED_RULES:
            self.assertEqual(self.rules(self.F.check_rules_text(full.replace("- %s: text\n" % r, ""))), ["F001"], r)

    def test_bare_python_is_flagged_but_the_resolver_is_not(self):
        self.assertEqual(self.rules(self.F.check_script_text('PY="$(command -v python3.14 || command -v python3)"\n')), [])
        self.assertIn("F002", self.rules(self.F.check_script_text("python3 tools/x.py\n")))
        self.assertEqual(self.F.check_script_text('"$PY" tools/x.py\n'), [])

    def test_factory_script_must_start_with_set_eu(self):
        self.assertIn("F003", self.rules(self.F.check_script_text("echo hi\n", factory_script=True)))
        self.assertEqual(self.F.check_script_text("#!/bin/sh\nset -eu\necho hi\n", factory_script=True), [])

    def test_ledger_write_needs_a_verdict_first(self):
        bad = 'echo x >> "$HOME/.og-orchestration/ledger.md"\n'
        good = 'if og-gate ci; then V=PASS; fi\nVERDICT=$V\necho x >> "$HOME/.og-orchestration/ledger.md"\n'
        self.assertIn("F004", self.rules(self.F.check_script_text(bad)))
        self.assertEqual(self.F.check_script_text(good), [])

    def test_gate_output_must_not_be_filtered(self):
        self.assertIn("F005", self.rules(self.F.check_script_text('"$ORCH/og-gate" ci | tail -3\n')))
        self.assertIn("F005", self.rules(self.F.check_script_text('"$PY" tools/lint_rules.py | grep OK\n')))

    def test_suppression_needs_a_reason(self):
        self.assertEqual(self.F.check_script_text("python3 x.py  # factory-ok: one-off bootstrap before $PY exists\n"), [])
        self.assertIn("F000", self.rules(self.F.check_script_text("python3 x.py  # factory-ok\n")))

    def test_brief_must_link_the_rules(self):
        self.assertEqual(self.F.check_brief_text("See factory/standing-rules.md\n"), [])
        self.assertEqual(self.rules(self.F.check_brief_text("Never push.\n")), ["F006"])


if __name__ == "__main__":
    unittest.main()

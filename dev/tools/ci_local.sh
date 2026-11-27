#!/bin/sh
# The same gate CI runs, on your own machine. Run it before any push; pushing without it spends CI minutes on failures.
#
#   dev/tools/ci_local.sh          # project lint gate, ruff (if installed), selftest (pin 466,343), release tooling tests, neutrality, redesign mapping, JS tests
#   dev/tools/ci_local.sh --full   # also the whole Python suite (about 5 minutes)
#
# Commit as often as you like; push once per milestone. A pull request builds only when it is not a draft, so keep
# it a draft until this script passes and you are ready for review.
set -e
cd "$(dirname "$0")/.."
PY="$(command -v python3.14 || command -v python3)"
"$PY" tools/lint_rules.py
"$PY" -m unittest tests.test_lint_rules
[ -f ../factory/check_factory.py ] && "$PY" ../factory/check_factory.py
if command -v ruff >/dev/null 2>&1; then ruff check --config ruff.toml .; else echo "ruff not installed: generic lint step skipped (tools/lint_rules.py still ran)"; fi
"$PY" selftest.py
[ -f tests/test_promote.py ] && "$PY" -m unittest tests.test_promote
[ -f tools/promote.py ] && "$PY" tools/promote.py --check
[ -f tools/check_redesign_mapping.py ] && "$PY" tools/check_redesign_mapping.py --quiet
[ -f tools/check_expectations.py ] && "$PY" tools/check_expectations.py
"$PY" tools/contrast_check.py --quiet
[ -f tools/gen_action_table.py ] && "$PY" tools/gen_action_table.py --check
if command -v node >/dev/null 2>&1; then
    # the JS tests use node:test (Node 18+); an older Node would fail with an unreadable error, so say what is wrong
    [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 18 ] || { echo "node 18 or newer is required for the JS tests (found $(node --version))" >&2; exit 1; }
    node --test tests/js/*.test.js
fi
if [ "$1" = "--full" ]; then
    # a test run must not leave files behind: new untracked files after the suite are a failure (they get committed by mistake)
    GITOK=0; git rev-parse --is-inside-work-tree >/dev/null 2>&1 && GITOK=1
    BEFORE=""; [ "$GITOK" = 1 ] && BEFORE="$(git ls-files --others --exclude-standard)"
    "$PY" -m unittest discover -s tests -t .
    if [ "$GITOK" = 1 ]; then
        AFTER="$(git ls-files --others --exclude-standard)"
        if [ "$BEFORE" != "$AFTER" ]; then
            echo "the test run left untracked files; make the test or tool write inside a temp dir:" >&2
            printf '%s\n' "$AFTER" >&2
            exit 1
        fi
    fi
fi
echo "local gate: OK"

#!/bin/sh
# The same gate CI runs, on your own machine. Run it before any push; pushing without it spends CI minutes on failures.
#
#   dev/tools/ci_local.sh          # selftest (pin 466,343), release tooling tests, neutrality, redesign mapping, JS tests
#   dev/tools/ci_local.sh --full   # also the whole Python suite (about 5 minutes)
#
# Commit as often as you like; push once per milestone. A pull request builds only when it is not a draft, so keep
# it a draft until this script passes and you are ready for review.
set -e
cd "$(dirname "$0")/.."
PY="$(command -v python3.14 || command -v python3)"
"$PY" selftest.py
[ -f tests/test_promote.py ] && "$PY" -m unittest tests.test_promote
[ -f tools/promote.py ] && "$PY" tools/promote.py --check
[ -f tools/check_redesign_mapping.py ] && "$PY" tools/check_redesign_mapping.py --quiet
"$PY" tools/contrast_check.py --quiet
[ -f tools/gen_action_table.py ] && "$PY" tools/gen_action_table.py --check
if command -v node >/dev/null 2>&1; then node --test tests/js/*.test.js; fi
if [ "$1" = "--full" ]; then "$PY" -m unittest discover -s tests -t .; fi
echo "local gate: OK"

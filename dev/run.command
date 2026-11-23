#!/bin/bash
# ---------------------------------------------------------------------------------------
# OpenGenerator — double-click launcher (macOS).
#
# Double-click in Finder, or run ./run.command from a terminal. It checks what it needs,
# starts the local web server, and opens the UI in your browser.
#
# It deliberately keeps the Terminal window open on failure: a double-clicked script that
# exits immediately takes its error message with it, which is useless a year from now.
# ---------------------------------------------------------------------------------------
cd "$(dirname "$0")" || exit 1

BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$OFF" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$OFF" "$*"; }

hold() {            # keep the window readable when launched from Finder
  printf '\n%sPress Return to close this window.%s ' "$DIM" "$OFF"
  read -r _ || true
  exit "${1:-1}"
}

say ""
say "${BOLD}OpenGenerator${OFF}"
say "${DIM}$(pwd)${OFF}"
say ""

# --- 1. a Python that can run it -------------------------------------------------------
PY=""
for cand in "$NWTG_PYTHON" python3 /usr/local/bin/python3 /opt/homebrew/bin/python3 \
            /Library/Frameworks/Python.framework/Versions/Current/bin/python3 /usr/bin/python3; do
  [ -n "$cand" ] || continue
  if command -v "$cand" >/dev/null 2>&1; then
    v=$("$cand" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null) || continue
    maj=${v%%.*}; min=${v##*.}
    if [ "$maj" -eq 3 ] && [ "$min" -ge 9 ]; then PY=$cand; break; fi
  fi
done
if [ -z "$PY" ]; then
  bad "No Python 3.9+ found."
  say ""
  say "  Install one from https://www.python.org/downloads/ (or 'brew install python'),"
  say "  then double-click this file again. To use a specific interpreter:"
  say "      NWTG_PYTHON=/path/to/python3 ./run.command"
  hold 1
fi

# --- 2. the one hard dependency --------------------------------------------------------
if ! "$PY" -c 'import cryptography' >/dev/null 2>&1; then
  warn "The 'cryptography' package is missing (needed to build certificates and TLS)."
  say ""
  printf '  Install it now with pip? [y/N] '
  read -r a || a=n
  case "$a" in
    [yY]*)
      say ""
      "$PY" -m pip install --user -r requirements.txt || {
        bad "Install failed. Try a virtual environment instead:"
        say "      $PY -m venv .venv && .venv/bin/pip install -r requirements.txt"
        say "      NWTG_PYTHON=\$(pwd)/.venv/bin/python3 ./run.command"
        hold 1
      };;
    *)
      say ""
      say "  Install it yourself with:  $PY -m pip install -r requirements.txt"
      hold 1;;
  esac
fi

# --- 3. optional extras: absent is fine, the UI says so --------------------------------
# Ask replay.py rather than keeping a second list of install locations here. The two lists
# had already diverged -- this one knew about Homebrew only -- so the launcher could report
# "not installed" on a machine where the app itself finds it, or the reverse.
TP=$("$PY" -c 'import sys; sys.path.insert(0, ".");
import replay
p = replay.find_tool("tcpreplay")
print(p or "")
print(replay.install_hint("tcpreplay"))' 2>/dev/null)
TP_PATH=$(printf '%s\n' "$TP" | sed -n 1p)
TP_HINT=$(printf '%s\n' "$TP" | sed -n 2p)
if [ -n "$TP_PATH" ]; then
  ok "tcpreplay found — the Replay panel will work"
  say "    ${DIM}${TP_PATH}${OFF}"
else
  warn "tcpreplay not installed — generation works, replay is disabled"
  say "    ${DIM}install with: ${TP_HINT:-brew install tcpreplay}${OFF}"
fi

# --- 4. the app itself -----------------------------------------------------------------
for f in server.py opengenerator_build.py ui/index.html inventory.json netgen/__init__.py; do
  [ -e "$f" ] || { bad "Missing $f — is this the complete application folder?"; hold 1; }
done

# Everything else the generator needs, reported by the same checker the GUI calls
# (deps.py / GET /api/deps) so the terminal and the browser can never disagree. It is a
# report, not a gate: the GUI renders the identical list as chips and explains how to fix
# each one, which is more use than refusing to start.
if [ -f deps.py ]; then
  say ""
  say "  ${DIM}Dependencies (the GUI shows this same list):${OFF}"
  "$PY" deps.py --brief || warn "Some requirements are missing — the GUI will show what and why."
fi

say ""
say "${DIM}Starting… the UI opens in your browser. Close this window (or Ctrl-C) to stop.${OFF}"
say "${DIM}If the browser does not open, use the address printed below.${OFF}"
say ""

# -u keeps the startup line (including the actual URL, which may not be port 8765) visible
# even when this script's output is piped or redirected. "$@" forwards flags such as
# --no-browser so the launcher is usable from a terminal as well as from Finder.
"$PY" -u server.py "$@"
status=$?
if [ $status -ne 0 ] && [ $status -ne 130 ]; then   # 130 = Ctrl-C, a normal way to stop
  say ""
  bad "The server exited unexpectedly (status $status). The message above says why."
  hold $status
fi

#!/usr/bin/env python3
"""
OpenGenerator — local web UI (Phase 3 scaffold).

A dependency-free (stdlib-only) local web server that wraps the single-stage generator
`opengenerator_build.py`. It serves a small branded page, runs the generator **in-process** on a
worker thread, streams live progress, and lists the resulting files. It also drives
`tcpreplay` (see replay.py) to play a finished capture onto an interface, with live
played/remaining tracking. Runs entirely on 127.0.0.1 — nothing is exposed off the machine.

Replay needs root, so it is launched through macOS's own administrator prompt; no password
is ever entered into, or handled by, this server. Missing dependencies are reported by
/api/replay/preflight before anything is launched.

    python3 server.py            # opens http://127.0.0.1:8765 in your browser

Packaged as a macOS .app it behaves the same (see BUILD-macos.md). The generator engine
(netgen/, opengenerator_build.py, inventory.py) is bundled alongside this file.
"""
import html
import datetime
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
import signal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def _reexec_under_python_with_cryptography():
    """Guarantee the interpreter running this server has `cryptography`, the engine's one
    third-party dependency (everything else in netgen/ is stdlib). If the Python the shell
    resolved for us lacks it -- common when `python3` points at a freshly installed build with no
    site-packages -- find another Python 3 on the host that has it and re-exec this server under
    that one, before the engine is imported. The app therefore launches with whatever `python3`
    happens to be on PATH instead of failing with ``ModuleNotFoundError: cryptography``.

    No-op when frozen (a PyInstaller .app bundles its own runtime with cryptography) or when
    cryptography already imports here. Guards against a re-exec loop with an env marker, and if no
    suitable interpreter is found, lets the normal import fail after printing how to fix it."""
    import importlib.util
    if getattr(sys, "frozen", False) or hasattr(sys, "_MEIPASS"):
        return                                           # frozen build ships its own deps
    if importlib.util.find_spec("cryptography") is not None:
        return                                           # this interpreter is already fine
    if os.environ.get("OPENGEN_PY_REEXEC") == "1":
        return                                           # already relaunched once -- never loop

    import glob
    names = ["python3", "python3.14", "python3.13", "python3.12", "python3.11",
             "python3.10", "python3.9"]
    candidates = [shutil.which(n) for n in names]
    candidates += sorted(glob.glob(
        "/Library/Frameworks/Python.framework/Versions/*/bin/python3"), reverse=True)
    candidates += ["/usr/local/bin/python3", "/opt/homebrew/bin/python3", "/usr/bin/python3"]

    seen = {os.path.realpath(sys.executable)}            # exclude the interpreter that just failed
    for cand in candidates:
        if not cand:
            continue
        real = os.path.realpath(cand)
        if real in seen or not os.path.exists(real):
            continue
        seen.add(real)
        try:
            probe = subprocess.run([real, "-c", "import cryptography"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0:
            script = os.path.abspath(__file__)
            sys.stderr.write(
                "OpenGenerator: %s has no 'cryptography' package; relaunching under %s\n"
                % (sys.executable, real))
            env = dict(os.environ, OPENGEN_PY_REEXEC="1")
            os.execve(real, [real, script] + sys.argv[1:], env)   # replaces this process

    sys.stderr.write(
        "OpenGenerator: no Python on this host has the 'cryptography' package. Install it with:\n"
        "    %s -m pip install cryptography\n" % sys.executable)


_reexec_under_python_with_cryptography()                 # must run before the engine is imported

# When frozen by PyInstaller the bundled data files live in sys._MEIPASS, not next to a
# source file — __file__ points into the temporary extraction dir and everything built from
# it (ui/, assets/, inventory.json, netgen/) would be looked up in the wrong place.
_BUNDLE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _BUNDLE_DIR)
import overlay                                        # noqa: E402 - patch updates (overlay.py); stdlib only
APP_DIR = overlay.activate(_BUNDLE_DIR)               # the installed patch's tree when one is valid, else the bundle
if APP_DIR != _BUNDLE_DIR and os.path.dirname(os.path.abspath(__file__)) != APP_DIR and __name__ == "__main__":
    import runpy                                      # the patch replaces this entry script too: run its copy instead
    runpy.run_path(os.path.join(APP_DIR, "server.py"), run_name="__main__")
    sys.exit(0)
UI_DIR = os.path.join(APP_DIR, "ui")
sys.path.insert(0, APP_DIR)                       # so the bundled generator imports cleanly
import branding                                       # noqa: E402 — product name, platform, palette, logo
import agent_api                                      # noqa: E402 — /agent/v1/ scope + token + audit, stdlib only
DEFAULT_OUT = os.path.join(os.path.expanduser("~"), branding.CAPTURES_DIRNAME)
PCAP_NAME = "example-all-in-one.pcap"

# macOS application/package bundles are directories that `open` LAUNCHES rather than reveals, so
# /api/reveal rejects any folder whose name ends with one of these. A plain output folder has no
# such extension. (endswith() takes this tuple directly.)
_BUNDLE_EXTS = (".app", ".bundle", ".framework", ".plugin", ".kext", ".pkg", ".mpkg", ".dmg",
                ".xpc", ".appex", ".prefpane", ".qlgenerator", ".component", ".mdimporter",
                ".saver", ".wdgt", ".service", ".action", ".workflow")

import deps                                           # noqa: E402 — stdlib-only, cannot fail
import campaign_api                                   # noqa: E402 — Campaign Builder HTTP API, lazy engine imports
import sessions_api                                   # noqa: E402 — saved sessions (form state), stdlib only
import replay
import captures_store                                   # noqa: E402 — safe delete/restore for captures, stdlib only
import settings_store                                    # noqa: E402 — persistent UI settings, stdlib only
import updater                                           # noqa: E402 — in-app patch updates (GitHub Releases)
import scenario_meta                                   # noqa: E402 — descriptive scenario copy, stdlib only
from sensorops import push_cert, push_ti             # noqa: E402 — stdlib-only, cannot fail

# The engine is imported DEFENSIVELY. It pulls in `cryptography`, and a missing or broken
# wheel there used to kill the server at startup — leaving a traceback in a terminal the user
# may never see and no UI at all to explain it. Nothing below uses these at module scope, so
# the server now always starts, reports the fault through /api/deps as a red chip, and refuses
# the actions that need the engine with a readable error. See deps.py.
try:
    import opengenerator_build                            # noqa: E402 — needs APP_DIR on sys.path
    import make_diagram                               # noqa: E402
    import pcapprofile                                # noqa: E402
    from netgen import platform as capkernel          # noqa: E402 — v5b capability kernel
    from netgen import incidents as _INC              # noqa: E402 — scenario registry
    from sensorops import providers as _providers     # noqa: E402 — provider registry
    from netgen import protocols as _P                # noqa: E402 — encoder registry
    capkernel.kernel.discover()                       # scan /modules once at startup
    # Put the existing built-in registries *under* the kernel so one place sees every capability
    # (built-in + module). Module-provided capabilities register into these same registries, so
    # each count/list is live.
    capkernel.kernel.register_source("scenarios", lambda: len(_INC.REGISTRY))
    capkernel.kernel.register_source("diagrams", lambda: len(make_diagram.DIAGRAMS))
    capkernel.kernel.register_source("providers", lambda: _providers.available())
    capkernel.kernel.register_source("encoders", lambda: len(_P.encoder_names()))
    capkernel.kernel.register_source("exporters", lambda: len(opengenerator_build.EXPORTERS))
    capkernel.kernel.load_enabled()                   # auto-load the persisted enable-on-startup set
    ENGINE_ERROR = ""
except Exception as _e:                               # noqa: BLE001
    opengenerator_build = make_diagram = pcapprofile = capkernel = None
    _INC = _providers = _P = None
    ENGINE_ERROR = f"{type(_e).__name__}: {_e}"

# shared run state (single active run at a time)
STATE = {
    "running": False, "done": False, "error": None, "cancelled": False,
    "packets": 0, "mb": 0.0, "seconds": 0, "clock": "",
    "log": [], "outputs": [], "out_dir": "", "pcap": "", "stix": "", "summary": None, "started": 0.0,
    # path to the stats of the most recent baseline-only run, if there has been one
    "baseline_stats": "",
    # packets-by-protocol for the most recent completed run; empty until one finishes, which is
    # what keeps the GUI's report button disabled
    "protocols": [], "report_scale": 0,
}
LOCK = threading.Lock()

# The engine keeps its build state -- the company identity, every module's RNG, and the capture
# day -- as PROCESS-GLOBAL state (see netgen.reseed_all / identity.set_current). Two builds running
# at once therefore corrupt each other's counts. This server is multi-threaded, and a build can be
# started from more than one path (a capture generation, and a capability module's self_test, which
# builds). BUILD_LOCK serializes every build so only one runs at a time; it is distinct from LOCK,
# which only guards the short STATE updates and must never be held across a build. Diagram rendering
# does NOT build (make_diagram.gather uses a local identity and draws no build RNG), so it is not
# serialized here.
BUILD_LOCK = threading.Lock()
# Browser-session secret: handed to the app's own page as an HttpOnly cookie. Replay and sensor-push routes require it,
# so a client that merely omits the agent token cannot reach them (see agent_api.HUMAN_ONLY).
UI_SECRET = secrets.token_hex(16)


# Preview a campaign for the UI (the board and the capture-size estimate) WITHOUT a full generate:
# run it campaign-only through the engine under BUILD_LOCK — it reseeds the process-global RNG, so
# it must not overlap a real build — and hand back its records plus its exact packet/byte totals.
# campaign_api reaches this through the RUN_CAMPAIGN hook, so that layer needs no engine or lock.
def _preview_campaign(campaign, scale, nets):
    with LOCK:
        if STATE["running"]:
            raise campaign_api.ApiError(
                409, "a capture run is in progress; try the preview when it finishes")
    with BUILD_LOCK:
        return opengenerator_build.preview_campaign(
            campaign, scale=scale, inventory=os.path.join(APP_DIR, "inventory.json"),
            user_net=nets.get("user"), server_net=nets.get("server"), ot_nets=nets.get("ot"))


if opengenerator_build is not None:
    campaign_api.RUN_CAMPAIGN = _preview_campaign

# Set by POST /api/generate/stop, polled by the generator through build(should_cancel=...).
# A thread cannot be killed from outside in Python, so the stop is cooperative: the engine
# checks this every 20,000 packets and raises netgen.core.Cancelled, which unwinds the run and
# deletes the partial capture. Cleared at the start of every run, never left set.
CANCEL = threading.Event()

# ---------------------------------------------------------------------------------------
# Lifecycle: the GUI is a browser tab, so "the user closed the app" is something the server
# has to be TOLD, not something it can observe. Each open tab registers a client id and
# heartbeats; closing one sends a beacon that drops it. When the last client has been gone
# for LIFECYCLE["grace"] seconds the server shuts itself down and releases the port.
#
# Why this is needed at all: before it, closing the tab left server.py running forever
# holding its port, so every restart landed on 8766, 8767, 8768 … and a pile of orphaned
# servers accumulated across a session. Ctrl-C was the only way out, and even that never
# called server_close().
#
# Deliberate guards:
#   * ARMED only after the first client registers, so `--no-browser` (scripted use, the
#     smoke test in CLAUDE.md) never exits before anything connects.
#   * Client ids are per-tab, so closing one of two tabs does not stop the server.
#   * The watchdog refuses to fire while a generation or a replay is in progress — closing
#     a tab must not destroy work that takes minutes. An explicit signal still stops both.
# Presence is a HELD CONNECTION, not a timer. The first implementation heartbeated with
# setInterval(3000) and it was wrong: browsers throttle timers in background tabs (Chrome to
# about once a minute, and frozen tabs stop firing altogether), so merely clicking to another
# tab made the heartbeat stop and the server quit out from under the user. Measured: it exited
# after ~65 s with the tab still open. An EventSource is a socket -- it is not throttled, and
# when the tab closes the socket drops and the server observes it directly.
LIFECYCLE = {"streams": 0, "armed": False, "grace": 6.0, "autoquit": True}
SHUTDOWN = threading.Event()
_HTTPD = None


def _busy():
    """Is there work in flight that a tab-close must not discard?"""
    with LOCK:
        if STATE["running"]:
            return "a capture is being generated"
    try:
        if replay.status().get("running"):
            return "a replay is in progress"
    except Exception:                                  # noqa: BLE001
        pass
    # Both sensor pushes mutate an appliance and must not be cut in half by a tab close. The
    # certificate push is the dangerous one: it deletes every key BEFORE uploading, so a
    # server that exits mid-run leaves the sensor decrypting nothing at all.
    try:
        if push_cert.status().get("running"):
            return "certificates are being pushed to an appliance"
        if push_ti.collection_status().get("running"):
            return "a threat collection is being pushed to an appliance"
    except Exception:                                  # noqa: BLE001
        pass
    return None


def shutdown(reason, stop_work=False):
    """Release the port and exit. `stop_work` also stops a generation and a replay.

    stop_work is True only for an explicit signal (Ctrl-C, SIGTERM from quitting the app,
    SIGHUP from the Terminal window closing) — the user is closing the application itself,
    so leaving a root-owned tcpreplay flooding a sensor with no UI would be worse than
    stopping it. The idle watchdog never passes it, because it never fires while busy.
    """
    if SHUTDOWN.is_set():
        return
    SHUTDOWN.set()
    print(f"\nshutting down: {reason}")
    if stop_work:
        with LOCK:
            running = STATE["running"]
        if running:
            print("  cancelling the generation in progress …")
            CANCEL.set()
        try:
            if replay.status().get("running"):
                print("  stopping the replay in progress …")
                replay.stop()                          # unprivileged: creates the stop-file
        except Exception as e:                         # noqa: BLE001
            print(f"  could not stop the replay ({e}); its monitor window can still stop it.")
    if _HTTPD is not None:
        # shutdown() must not run on the serve_forever thread or it deadlocks.
        threading.Thread(target=_HTTPD.shutdown, daemon=True).start()


def _watchdog():
    """Exit once every tab has been closed for `grace` seconds."""
    gone_since = None
    while not SHUTDOWN.is_set():
        time.sleep(1.0)
        if not LIFECYCLE["autoquit"] or not LIFECYCLE["armed"]:
            continue
        with LOCK:
            live = LIFECYCLE["streams"]
        if live > 0:
            gone_since = None
            continue
        if gone_since is None:
            gone_since = time.time()
        if time.time() - gone_since < LIFECYCLE["grace"]:
            continue
        busy = _busy()
        if busy:
            continue                                   # never discard work in flight
        shutdown("the last browser tab was closed")
        return



def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def list_outputs(out_dir):
    items = []
    for root, _dirs, files in os.walk(out_dir):
        _dirs[:] = [d for d in _dirs if not d.startswith(".")]      # the holding folder and other hidden folders are not results
        for fn in files:
            p = os.path.join(root, fn)
            try:
                items.append({"name": os.path.relpath(p, out_dir), "bytes": os.path.getsize(p),
                              "size": human(os.path.getsize(p))})
            except OSError:
                pass
    items.sort(key=lambda x: x["name"])
    return items


def default_nets():
    """The two emulated /24s as the bundled inventory defines them (UI defaults)."""
    try:
        with open(os.path.join(APP_DIR, "inventory.json")) as f:
            inv = json.load(f)
        fw = [h for h in inv["hosts"] if h["hostname"] == "EXL-FW1"]
        return {"user": fw[0]["subnet"], "server": fw[1]["subnet"]}
    except Exception:                                # noqa: BLE001
        return {"user": "10.10.10.0/24", "server": "10.10.20.0/24"}


def run_generator(scale, out_dir, certs, iocs, modules=None, user_net=None, server_net=None,
                  date=None, ot_nets=None, recipes=None, company=None, industry=None,
                  ot_protocols=None, campaigns=None, address_mode=None,
                  confirm_real_addresses=False):
    """Run the generator in-process (packaging-safe: no reliance on a python interpreter path).
    Everything is written into out_dir; a bundled inventory.json is seeded so no subprocess runs.

    `modules` is the incident selection: None builds every module, a list builds exactly those
    (an empty list is a legitimate choice — the baseline business day with no incidents).

    `campaigns` (a list of validated campaign dicts), `address_mode` ('mapped'|'real') and
    `confirm_real_addresses` are passed to build() only when a campaign is present, so a run
    without them is exactly the run it always was."""
    CANCEL.clear()                               # never start a run holding a stale stop
    with LOCK:
        STATE.update(running=True, done=False, error=None, cancelled=False, packets=0, mb=0.0,
                     seconds=0, clock="", log=[], outputs=[], out_dir=out_dir, pcap="",
                     summary=None, started=time.time())
        STATE.pop("campaign", None)              # present in /api/status only while a campaign result exists
    os.makedirs(out_dir, exist_ok=True)
    # seed the inventory so the generator never needs to spawn inventory.py
    inv_dst = os.path.join(out_dir, "inventory.json")
    if not os.path.exists(inv_dst) and os.path.exists(os.path.join(APP_DIR, "inventory.json")):
        shutil.copy(os.path.join(APP_DIR, "inventory.json"), inv_dst)

    def on_progress(pkts, nbytes, last_ts):
        with LOCK:
            STATE["packets"] = pkts
            STATE["mb"] = nbytes / 1e6
            STATE["clock"] = time.strftime("%H:%M:%S", time.localtime(last_ts)) if last_ts else ""
            STATE["seconds"] = int(time.time() - STATE["started"])

    try:
        n_sel = len(opengenerator_build.select_modules(modules))
        with LOCK:
            STATE["log"].append(f"generating (scale {scale}) into {out_dir} …")
            if company or industry:
                STATE["log"].append(
                    f"emulated company: {(company or 'Example')} {(industry or 'Logistics')}.")
            STATE["log"].append(f"{n_sel} incident module(s) selected, plus the normal day.")
            if user_net or server_net:
                STATE["log"].append(
                    f"emulated networks: user {user_net or 'unchanged'}, "
                    f"server {server_net or 'unchanged'} (host numbering preserved).")
        # A run with no incident modules IS a baseline measurement, so capture the engine's
        # per-tag stats and let the baseline-mix diagram prefer them over the bundled table.
        if campaigns:
            with LOCK:
                STATE["log"].append(f"{len(campaigns)} campaign(s) added to the capture "
                                    f"(address mode {address_mode or 'as saved'}).")
        campaign_kw = ({"campaigns": campaigns, "address_mode": address_mode,
                        "confirm_real_addresses": bool(confirm_real_addresses)}
                       if campaigns else {})
        stats_path = os.path.join(out_dir, "baseline-mix-stats.json") if modules == [] else None
        # out/iocs_prefix default to None/_DERIVE so build() names the files after the emulated
        # company (example-all-in-one.pcap by default, acme-all-in-one.pcap for Acme, etc.). The
        # real paths come back in the summary and drive STATE below.
        # Serialize the build: no other build (another generation, or a module self_test) may run
        # its reseed/identity/RNG against the same process globals at the same time.
        with BUILD_LOCK:
            cwd0 = os.getcwd()
            os.chdir(out_dir)                    # outputs stay together; cwd is process-global, so only inside the lock
            try:
                summary = opengenerator_build.build(
                    scale=scale, out=None, stats=stats_path,
                    certs_dir="certs" if certs else None,
                    date=date,
                    iocs_prefix=opengenerator_build._DERIVE if iocs else None,
                    inventory="inventory.json", progress=False, on_progress=on_progress,
                    modules=modules, user_net=user_net, server_net=server_net, ot_nets=ot_nets,
                    recipes=recipes, company=company, industry=industry, ot_protocols=ot_protocols,
                    should_cancel=CANCEL.is_set, **campaign_kw)
            finally:
                os.chdir(cwd0)
        with LOCK:
            # on_progress fires every N packets, so the last tick it delivered is a ROUND
            # NUMBER below the true total -- the UI was reporting "1,000,000 packets / 517.9 MB"
            # for a capture holding 1,121,146 packets and 580 MB, and the generation report's
            # capture-size KPI inherited the same understatement. build()'s summary carries the
            # writer's real totals, so overwrite the progress figures with them on completion.
            if summary.get("manifest_error"):
                STATE["log"].append("build manifest was not written: " + str(summary["manifest_error"]))
            STATE["packets"] = summary.get("packets", STATE["packets"])
            STATE["mb"] = summary.get("bytes", STATE["mb"] * 1e6) / 1e6
            STATE["protocols"] = summary.get("protocols") or []
            STATE["report_scale"] = scale
            STATE["summary"] = {"nets": summary["nets"],
                                "modules": summary["modules"],
                                "module_names": summary["module_names"],
                                "by_category": summary["by_category"],
                                "all_modules": summary["all_modules"],
                                "date": summary.get("date"),
                                "identity": summary.get("identity"),
                                "iocs": (summary["iocs"] or {}).get("indicators", 0),
                                "by_scenario": summary.get("by_scenario"),
                                "scale": scale,
                                "manifest": summary.get("manifest"),
                                "manifest_error": summary.get("manifest_error")}
            if "campaign" in summary:                # only when a campaign ran: status keeps its old shape otherwise
                STATE["summary"]["campaign"] = json.loads(json.dumps(summary["campaign"], default=str))
                STATE["summary"]["campaign_console"] = [str(x) for x in summary.get("campaign_console") or []]
                STATE["campaign"] = campaign_api.status_extras(STATE["summary"]).get("campaign")
            STATE["running"] = False
            STATE["done"] = True
            STATE["seconds"] = int(time.time() - STATE["started"])
            STATE["outputs"] = list_outputs(out_dir)
            # build() names the pcap (and the threat collection) after the company; point the
            # replay/collection panels at what was actually written, not a fixed name.
            STATE["pcap"] = os.path.join(out_dir, os.path.basename(summary["pcap"]))
            _iocs = summary.get("iocs") or {}
            STATE["stix"] = (os.path.join(out_dir, os.path.basename(_iocs["stix"]))
                             if _iocs.get("stix") else "")
            if stats_path and os.path.exists(stats_path):
                try:                                 # record the scale alongside the counts
                    with open(stats_path) as f:
                        raw = json.load(f)
                    raw["_scale"] = scale
                    with open(stats_path, "w") as f:
                        json.dump(raw, f)
                    STATE["baseline_stats"] = stats_path
                except Exception:                    # noqa: BLE001
                    pass
            if iocs and not STATE["summary"]["iocs"]:
                STATE["log"].append(
                    "note: the selected scenarios emit no external indicators, so the exported "
                    "threat collection is empty.")
            STATE["log"].append("done.")
    except opengenerator_build.Cancelled as e:
        # A stop is not a failure: no error banner, no traceback. build() has already deleted
        # the partial pcap and key log, so the folder is left as it was found.
        with LOCK:
            STATE["running"] = False
            STATE["done"] = True
            STATE["cancelled"] = True
            STATE["seconds"] = int(time.time() - STATE["started"])
            STATE["outputs"] = list_outputs(out_dir)
            STATE["log"].append(f"stopped by request — {e}")
            STATE["log"].append("the partial capture and key log were discarded.")
    except Exception as e:                        # noqa: BLE001
        import traceback
        with LOCK:
            STATE["running"] = False
            STATE["error"] = str(e)
            STATE["log"].append(traceback.format_exc())
    finally:
        CANCEL.clear()


def get_modules():
    """List the registry modules (all are always included in single-stage mode)."""
    try:
        # scenario windows are shown as offsets from the replay start (05:00 capture start),
        # never as a wall-clock time: a replay can start at any moment and the sensor stamps
        # each packet when it is observed, so only the offset is stable.
        def _rel_window(lo, hi, _s=5 * 60):
            def off(m):
                m = int(m) - _s
                if m < 60:
                    return "+%dm" % m
                h, mm = divmod(m, 60)
                return "+%dh" % h if mm == 0 else "+%d:%02d" % (h, mm)
            return "Start %s \u2192 %s" % (off(lo), off(hi))
        from netgen import incidents as INC
        out = []
        for n, i in INC.REGISTRY.items():
            (h1, m1), (h2, m2) = i.window
            out.append({"name": n, "prefix": i.prefix, "title": i.title, "note": i.note,
                        "window": _rel_window(h1 * 60 + m1, h2 * 60 + m2), "pinned": False,
                        # custom-import is not a default scenario: it is built once per imported
                        # recipe file, so the UI keeps it out of the grid and counts and drives the
                        # CUSTOM total from the recipe list instead. 0 recipes = no custom at all. The CAMPAIGN
                        # scenario is likewise built only when a campaign file is supplied.
                        "recipe_driven": i.prefix in ("CUSTOM", "CAMPAIGN"),
                        # OT scenarios are inert without the OT subnet, so the UI hides and disables
                        # them (unselectable) until the OT zone is generated -- like baseline-ot.
                        "ot_only": n in getattr(INC, "OT_SCENARIOS", set()),
                        # an NPM scenario caused by a compromised host auto-selects the NDR scenario
                        # that compromised it; the UI ticks that box too when this one is ticked.
                        "requires": getattr(INC, "SCENARIO_DEPENDENCIES", {}).get(n)})
        # always-on baseline traffic, pinned into its category group by the UI and never
        # sent back in a selection (select_modules refuses it by name)
        out += INC.baseline_modules()
        # additive: descriptive copy per scenario (no key when it has no entry); never touches the engine
        for m in out:
            meta = scenario_meta.get(m["name"])
            if meta is not None:
                m["meta"] = meta
        return out
    except Exception:                            # noqa: BLE001
        return []



def _msg_page(title, heading, msg, q=None, pre=False):
    """A plain message page on the shared template (page_template.page), themed from the query."""
    import page_template
    q = q or {}
    body = "<pre>%s</pre>" % html.escape(msg) if pre else "<p>%s</p>" % html.escape(msg)
    return page_template.page(title, heading, body, (q.get("theme") or [""])[0], (q.get("palette") or [""])[0])


def _themed(page, q):
    """Apply the light/dark mode and palette the app passed in the query string (see make_diagram.themed)."""
    return make_diagram.themed(page, (q.get("theme") or [""])[0], (q.get("palette") or [""])[0])


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):                   # quiet
        pass

    def end_headers(self):
        # Every response: never framed (a hostile page could overlay the app and steer a click), never type-sniffed,
        # no referrer. The app uses no iframes. See docs/design-language.md and SECURITY.md.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def _send(self, code, body, ctype="application/json", headers=None):
        self._status = code                      # read by the agent audit log
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    # ---- same-origin guard (anti-CSRF + anti-DNS-rebinding) -------------------------------
    # This server binds 127.0.0.1 only, but a web page the user visits (or a DNS-rebinding
    # attacker) can still reach it through the browser. So: reject any request whose Host is not
    # a loopback name (defeats DNS rebinding -- the attacker's domain no longer matches), and
    # reject any state-changing POST whose Origin is a foreign site (defeats cross-site request
    # forgery). The GUI is always same-origin on 127.0.0.1/localhost, so legitimate use -- and
    # non-browser clients that send no Host/Origin -- is unaffected.
    _LOCAL_NAMES = ("127.0.0.1", "localhost", "::1")

    _HOST_RE = re.compile(r"^(?:127\.0\.0\.1|localhost|\[::1\])(?::\d{1,5})?$", re.I)
    _ORIGIN_RE = re.compile(r"^https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d{1,5})?$", re.I)
    timeout = 30                       # a client that stalls mid-headers or mid-body is dropped

    def _host_is_local(self):
        host = self.headers.get("Host")
        if host is None:                   # no Host (non-browser); a browser attack always sends one
            return True
        # Exactly host[:port] for the loopback names: no userinfo, path, spaces or look-alike prefix.
        return bool(self._HOST_RE.match(host.strip())) and len(host) <= 64

    def _origin_is_local(self):
        origin = self.headers.get("Origin")
        if origin is None:                 # same-origin GET / non-browser; a cross-site browser POST sends Origin
            return True
        return bool(self._ORIGIN_RE.match(origin.strip())) and len(origin) <= 128

    def _blocked(self, check_origin=False):
        """Send 403 and return True if this request is cross-site or DNS-rebound. Call first."""
        if not self._host_is_local():
            self._send(403, json.dumps({"error": "forbidden: unexpected Host header"}))
            return True
        if check_origin and not self._origin_is_local():
            self._send(403, json.dumps({"error": "forbidden: cross-site request blocked"}))
            return True
        return False

    def _guarded(self, fn):
        """Never drop the socket: a bad body or a handler fault becomes a JSON error reply."""
        try:
            fn()
        except (BrokenPipeError, ConnectionError):
            raise
        except Exception as e:                   # noqa: BLE001
            bad = isinstance(e, (TypeError, ValueError, AttributeError, KeyError, OverflowError))
            try:
                self._send(400 if bad else 500, json.dumps({"error": "the request could not be completed" +
                                                            (": %s" % e if bad else "")}))
            except Exception:                    # noqa: BLE001 — reply already started or socket gone
                pass

    # ---- agent scope (see agent_api) ------------------------------------------------------
    def _ui_session(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "og_ui" and v == UI_SECRET:
                return True
        return False

    def _agent_gate(self, method):
        """Apply the agent rules. Returns (done, verb, target): done=True means a reply was sent. A verb with a
        proxied target is rewritten in place (path, no Authorization header) and falls through to the normal routes."""
        path = urlparse(self.path).path
        bearer = self.headers.get("Authorization")
        if bearer is None:
            if path.startswith(agent_api.PREFIX):
                self._send(401, json.dumps({"error": "a valid agent token is required (create one in Settings)"}))
                return True, None, None
            if method == "POST" and path in agent_api.HUMAN_ONLY and not self._ui_session():
                self._send(403, json.dumps({"error": "forbidden: replay and sensor push are done by a person in the app"}))
                return True, None, None
            return False, None, None
        if not path.startswith(agent_api.PREFIX):
            self._send(403, json.dumps({"error": "forbidden: an agent token only reaches /agent/v1/"}))
            return True, None, None
        if not agent_api.check_bearer(bearer):
            self._send(401, json.dumps({"error": "a valid agent token is required (create one in Settings)"}))
            return True, None, None
        hit = agent_api.resolve(method, path)
        if hit is None:
            self._send(404, json.dumps({"error": "unknown agent verb"}))
            agent_api.audit(path[len(agent_api.PREFIX):][:60], 404)
            return True, None, None
        verb, target = hit
        del self.headers["Authorization"]
        if isinstance(target, str):
            q = urlparse(self.path).query
            self.path = target + ("?" + q if q else "")
        return False, verb, target

    def _agent_done(self, verb, body=None):
        if verb:
            agent_api.audit(verb, getattr(self, "_status", 0), body)

    def do_GET(self):
        self._guarded(self._do_GET)

    def _do_GET(self):
        if self._blocked():
            return
        done, verb, target = self._agent_gate("GET")
        if done:
            return
        if verb:
            try:
                if isinstance(target, tuple):
                    return self._send(*self._run_agent_local(target, {}))
                return self._do_GET_routes()
            finally:
                self._agent_done(verb)
        return self._do_GET_routes()

    def _run_agent_local(self, target, data):
        try:
            status, obj = agent_api.run_local(target[1], data)
            return status, json.dumps(obj)
        except agent_api.AgentError as e:
            return e.status, json.dumps({"error": e.message})

    def _do_GET_routes(self):
        url = urlparse(self.path)
        if url.path.startswith(("/api/intel/", "/api/campaign/", "/ui/")) or url.path == "/campaign/export":
            res = campaign_api.route_get(url.path, url.query, UI_DIR)    # Campaign Builder API + its static files
            if res is not None:
                status, body, ctype, hdrs = res
                return self._send(status, body, ctype, hdrs)
        res = captures_store.route_get(url.path, url.query)          # holding-folder list (/api/captures/trash)
        if res is not None:
            status, body, ctype, hdrs = res
            return self._send(status, body, ctype, hdrs)
        res = updater.route_get(url.path, APP_DIR)                   # update check (/api/update/check)
        if res is not None:
            status, body, ctype, hdrs = res
            return self._send(status, body, ctype, hdrs)
        res = settings_store.route_get(url.path)                     # persistent UI settings (/api/settings)
        if res is not None:
            status, body, ctype, hdrs = res
            return self._send(status, body, ctype, hdrs)
        res = sessions_api.route_get(url.path, url.query)            # saved sessions (/api/session/*)
        if res is not None:
            status, body, ctype, hdrs = res
            return self._send(status, body, ctype, hdrs)
        if url.path == "/api/deps":
            # The generator-side twin of /api/replay/preflight: same report shape, so the UI
            # draws both chip rows with one renderer.
            rep = deps.check()
            if ENGINE_ERROR and rep["ok"]:
                # deps.check() imports the engine itself; if that succeeded but OUR import
                # failed the process is holding a stale failure — say so rather than lie.
                rep["ok"] = False
                rep["errors"].append(
                    "The generator engine failed to load when this server started "
                    f"({ENGINE_ERROR}). Restart the server to pick it up.")
                rep["missing"].append("generator engine")
            return self._send(200, json.dumps(rep))
        if url.path == "/api/diagrams":
            if make_diagram is None:                 # degrade: no diagrams, UI still usable
                return self._send(200, json.dumps({"diagrams": [], "scenarios": {}}))
            # `scenarios` maps module -> diagram name; the GUI uses it to decide which
            # per-scenario Visualize buttons are live.
            return self._send(200, json.dumps({
                "diagrams": make_diagram.catalog(),
                "scenarios": make_diagram.scenario_diagrams()}))
        if url.path == "/about":
            # Same page chrome as the diagrams, and the same "derive, never restate" rule:
            # the counts come from the live registry and inventory, so the About page cannot
            # advertise a scenario count this build does not have.
            if make_diagram is None:
                return self._send(503, self._engine_down_html(), "text/html; charset=utf-8")
            try:
                data = make_diagram.gather(os.path.join(APP_DIR, "inventory.json"), None, None)
                mods, selected = make_diagram.load_modules(None)
                c = make_diagram.DiagramContext(data, mods, selected)
                out = make_diagram.about_page(c)
                d = make_diagram.Diagram(
                    "about", f"About {branding.PRODUCT_TITLE}",
                    "What it is for, what it produces, and what has changed",
                    lambda _c: out, 0, None)
                page = make_diagram.render_page(d, c, make_diagram.load_logo())
            except Exception as e:                   # noqa: BLE001 — never take the server down
                import traceback
                traceback.print_exc()
                return self._send(500, "<pre>%s</pre>" % html.escape(str(e)),
                                  "text/html; charset=utf-8")
            return self._send(200, _themed(page, parse_qs(url.query)), "text/html; charset=utf-8")
        if url.path == "/report":
            with LOCK:
                protos = list(STATE.get("protocols") or [])
                meta = {"bytes": int(STATE.get("mb", 0) * 1e6),
                        "scale": STATE.get("report_scale") or "-",
                        "modules": (STATE.get("summary") or {}).get("modules", "-")}
            if not protos:
                # Same page chrome as every other static page, so it follows ?theme= and ?palette=.
                if make_diagram is None:
                    return self._send(404, _msg_page("No report yet", "Nothing to report yet",
                                      "Generate a capture, then open this again.", parse_qs(url.query)),
                                      "text/html; charset=utf-8")
                try:
                    empty = {"kpis": [], "svg": "", "doc_tag": "Generation report",
                             "h1": "Nothing to report yet",
                             "subtitle": "The report describes a capture that has been built",
                             "sections": [("What to do",
                                           "<p>Generate a capture, then open this page again. It lists the packets "
                                           "by protocol for the capture you just built.</p>")]}
                    d = make_diagram.Diagram("generation-report", "Generation report",
                                             "No capture has been built yet", lambda _c: empty, 0, None)
                    data = make_diagram.gather(os.path.join(APP_DIR, "inventory.json"), None, None)
                    mods, selected = make_diagram.load_modules(None)
                    c = make_diagram.DiagramContext(data, mods, selected)
                    page = make_diagram.render_page(d, c, make_diagram.load_logo())
                except Exception as e:               # noqa: BLE001 — never take the server down
                    import traceback
                    traceback.print_exc()
                    return self._send(500, _msg_page("Report error", "Report error", str(e), parse_qs(url.query), pre=True),
                                      "text/html; charset=utf-8")
                return self._send(404, _themed(page, parse_qs(url.query)), "text/html; charset=utf-8")
            if make_diagram is None:
                return self._send(503, self._engine_down_html(), "text/html; charset=utf-8")
            try:
                out = make_diagram.generation_report(protos, meta)
                d = make_diagram.Diagram(
                    "generation-report", "Generation report",
                    "Packets by protocol for the capture just produced",
                    lambda _c: out, 0, None)
                data = make_diagram.gather(os.path.join(APP_DIR, "inventory.json"), None, None)
                mods, selected = make_diagram.load_modules(None)
                c = make_diagram.DiagramContext(data, mods, selected)
                page = make_diagram.render_page(d, c, make_diagram.load_logo())
            except Exception as e:                   # noqa: BLE001 — never take the server down
                import traceback
                traceback.print_exc()
                return self._send(500, "<pre>%s</pre>" % html.escape(str(e)),
                                  "text/html; charset=utf-8")
            return self._send(200, _themed(page, parse_qs(url.query)), "text/html; charset=utf-8")
        if url.path == "/diagram":
            return self._diagram(parse_qs(url.query))
        if url.path == "/profile":
            return self._profile(parse_qs(url.query))
        if url.path == "/recipe":
            return self._recipe(parse_qs(url.query))
        if url.path == "/profile/export":
            return self._profile_export(parse_qs(url.query))
        if url.path == "/profile/compare":
            return self._profile_compare(parse_qs(url.query))
        if url.path == "/profile/check":
            return self._profile_check(parse_qs(url.query))
        if url.path == "/profile/summary":
            return self._profile_summary(parse_qs(url.query))
        if url.path == "/api/captures":
            return self._captures(parse_qs(url.query))
        if url.path == "/api/manifest":
            return self._manifest(parse_qs(url.query))
        if self.path in ("/", "/index.html"):
            try:
                with open(os.path.join(UI_DIR, "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8",
                                      {"Set-Cookie": "og_ui=%s; Path=/; HttpOnly; SameSite=Strict" % UI_SECRET})
            except OSError:
                return self._send(500, b"UI missing", "text/plain")
        if self.path == "/header-logo.png":
            try:
                with open(os.path.join(UI_DIR, "header-logo.png"), "rb") as f:
                    return self._send(200, f.read(), "image/png")
            except OSError:
                return self._send(404, b"", "image/png")
        if self.path == "/api/modules":
            with LOCK:
                last = STATE.get("pcap") or ""
            default_pcap = last or os.path.join(DEFAULT_OUT, PCAP_NAME)
            industries = list(opengenerator_build.identity.INDUSTRIES) if opengenerator_build else []
            return self._send(200, json.dumps({"modules": get_modules(),
                                                "default_out": DEFAULT_OUT,
                                                "default_pcap": default_pcap,
                                                "pcap_name": PCAP_NAME,
                                                "stix_name": push_ti.STIX_FILENAME,
                                                "default_nets": default_nets(),
                                                "industries": industries,
                                                "version": make_diagram.VERSION if make_diagram else "",
                                                "categories": branding.CATEGORIES,
                                                "scenario_taxonomy": {"families": scenario_meta.taxonomy(),
                                                                      "meta_status": scenario_meta.status()}}))
        if self.path == "/api/capabilities":
            # v5b: the catalog of capability modules under /modules and whether each is loaded.
            if capkernel is None:
                return self._send(503, json.dumps({"error": "capability kernel unavailable"}))
            return self._send(200, json.dumps({"capabilities": capkernel.kernel.catalog(),
                                                "builtins": capkernel.kernel.builtins()}))
        if self.path == "/api/status":
            with LOCK:
                # the protocol table is only needed by /report; shipping it on every 1s poll
                # would be pure waste, so status carries just a readiness flag
                out = {k: v for k, v in STATE.items() if k != "protocols"}
                out["report_ready"] = bool(STATE.get("protocols"))
                return self._send(200, json.dumps(out))
        if self.path == "/api/alive":
            # A presence stream, not a data feed: the browser holds it open for as long as the
            # tab exists and drops it when the tab closes, which is the only signal about tab
            # lifetime that background-tab throttling cannot interfere with. EventSource
            # reconnects by itself after a transient drop, so a brief network blip does not
            # look like a close.
            with LOCK:
                LIFECYCLE["streams"] += 1
                LIFECYCLE["armed"] = True
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(b": open\n\n")
                self.wfile.flush()
                while not SHUTDOWN.is_set():
                    time.sleep(5.0)
                    # The write is the liveness test: once the tab is gone this raises.
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except Exception:                          # noqa: BLE001 - client went away
                pass
            finally:
                with LOCK:
                    LIFECYCLE["streams"] = max(0, LIFECYCLE["streams"] - 1)
            return
        if self.path == "/api/sensor/status":
            # push_cert.status() deliberately carries no credential — the API key is never
            # stored in SSTATE, so it cannot leak through this poll.
            return self._send(200, json.dumps(push_cert.status()))
        if self.path == "/api/sensor/collection/status":
            # Same rule as /api/sensor/status: TSTATE deliberately holds no credential.
            return self._send(200, json.dumps(push_ti.collection_status()))
        if self.path == "/api/replay/status":
            return self._send(200, json.dumps(replay.status()))
        if self.path == "/api/replay/preflight":
            # no-argument form: which tools are present, which interfaces exist
            return self._send(200, json.dumps(replay.preflight()))
        return self._send(404, b"not found", "text/plain")

    def _engine_down_html(self):
        return _msg_page("Engine unavailable", "The generator engine is not loaded",
                         ENGINE_ERROR + " Diagrams are rendered by the engine, so none can be drawn until this is "
                         "resolved. The dependency indicators on the main page say what is missing.")

    def _diagram(self, q):
        """Render a registered diagram live, for the GUI's diagram menu.

        Returns HTML (not JSON) so the button can just open it in a tab. The networks and
        scenario selection come from the query string, so the page always reflects what is
        currently configured in the UI rather than a stale file on disk.
        """
        name = (q.get("name") or ["topology"])[0]
        if make_diagram is None:
            return self._send(503, self._engine_down_html(), "text/html; charset=utf-8")
        try:
            # ot=1 renders the industrial zone. Without it the diagram drops every OT asset
            # before bucketing, so a picture can never claim a zone the capture lacks.
            ot_req = {"ot": (q.get("ot_net") or [None])[0] or None,
                      "ops": None, "idmz": None} if (q.get("ot") or [None])[0] else None
            user_net, server_net, ot_nets = opengenerator_build.validate_nets(
                (q.get("user_net") or [None])[0] or None,
                (q.get("server_net") or [None])[0] or None, ot_req)
            mods = (q.get("modules") or [None])[0]
            modules = None
            if mods is not None:
                modules = opengenerator_build.select_modules(
                    [m for m in mods.split(",") if m.strip()])
            with LOCK:
                measured = STATE.get("baseline_stats") or ""
            company = (q.get("company") or [None])[0] or None
            industry = (q.get("industry") or [None])[0] or None
            page = make_diagram.render(name, user_net=user_net, server_net=server_net,
                                       ot_nets=ot_nets,
                                       modules=modules, measured=measured or None,
                                       company=company, industry=industry)
        except ValueError as e:
            return self._send(400, _msg_page("Diagram error", "Cannot render this diagram", str(e), q),
                              "text/html; charset=utf-8")
        except Exception as e:                       # noqa: BLE001 — never take the server down
            import traceback
            traceback.print_exc()
            return self._send(500, _msg_page("Diagram error", "Diagram error", str(e), q, pre=True),
                              "text/html; charset=utf-8")
        return self._send(200, _themed(page, q), "text/html; charset=utf-8")

    def _profile(self, q):
        """Render the exemplar profile of an imported pcap. Read-only: it reads the file the
        path points at, characterises it at the header level, and returns HTML with the same
        chrome as the diagrams. It never modifies the file or the running state."""
        if make_diagram is None or pcapprofile is None:
            return self._send(503, self._engine_down_html(), "text/html; charset=utf-8")
        path = os.path.expanduser((q.get("path") or [""])[0].strip())

        def _err(code, title, msg):
            return self._send(code, _msg_page(title, title, msg, q), "text/html; charset=utf-8")

        if not path:
            return _err(400, "No file given", "Enter the path to a .pcap or .pcapng file to profile.")
        if not os.path.isfile(path):
            return _err(400, "File not found", "No file at: %s" % path)
        if not pcapprofile.kind(path):
            return _err(400, "Not a capture file", "This is not a pcap or pcapng file (bad magic number): %s" % path)
        try:
            prof = pcapprofile.profile(path)
            why = pcapprofile.unusable_reason(prof)
            if why:
                return _err(422, "Nothing to profile", "%s: %s." % (os.path.basename(path), why))
            data = make_diagram.gather(os.path.join(APP_DIR, "inventory.json"), None, None)
            mods, selected = make_diagram.load_modules(None)
            c = make_diagram.DiagramContext(data, mods, selected)
            out = pcapprofile.content(prof)
            d = make_diagram.Diagram("profile", "Imported pcap", "Imported pcap exemplar",
                                     lambda _c: out, 0, None)
            page = make_diagram.render_page(d, c, make_diagram.load_logo())
        except ValueError as e:                      # too large, etc.: a user-fixable condition
            return _err(413 if "importer accepts" in str(e) else 400, "Cannot import this capture", str(e))
        except Exception as e:                       # noqa: BLE001 — never take the server down
            import traceback
            traceback.print_exc()
            return _err(500, "Could not profile the capture", str(e))
        return self._send(200, _themed(page, q), "text/html; charset=utf-8")

    _SUMMARY_CACHE = {}

    def _profile_summary(self, q):
        """The headline facts about a capture for the Lab import card: flows, protocols, duration, size.
        Read-only; the profile of an unchanged file is kept so choosing it again is instant."""
        def out(d):
            return self._send(200, json.dumps(d))
        if pcapprofile is None:
            return out({"ok": False, "error": "The generator engine is not available."})
        path = os.path.expanduser((q.get("path") or [""])[0].strip())
        if not path or not os.path.isfile(path):
            return out({"ok": False, "error": "No file at %s." % (path or "(empty path)")})
        try:
            st = os.stat(path)
            key = (path, st.st_mtime_ns, st.st_size)
            hit = Handler._SUMMARY_CACHE.get(key)
            if hit is None:
                prof = pcapprofile.profile(path)
                hit = {"ok": True, "flows": len(prof["convos"]), "protocols": len(prof["protocols"]),
                       "duration": round(prof["duration"], 1), "size": st.st_size, "packets": prof["pkts"]}
                if len(Handler._SUMMARY_CACHE) > 16:
                    Handler._SUMMARY_CACHE.clear()
                Handler._SUMMARY_CACHE[key] = hit
            return out(hit)
        except Exception as e:                       # noqa: BLE001 -- an unreadable file is a message, not a crash
            return out({"ok": False, "error": str(e)[:200]})

    def _profile_check(self, q):
        """Cheap pre-flight for the path fields: is this a readable capture (or recipe) file? The page
        asks before opening a report tab, so a typo is an inline message, not a blank error tab."""
        if pcapprofile is None:
            return self._send(200, json.dumps({"ok": False, "error": "The generator engine is not available."}))
        path = os.path.expanduser((q.get("path") or [""])[0].strip())
        want = (q.get("kind") or ["capture"])[0]

        def bad(msg):
            return self._send(200, json.dumps({"ok": False, "error": msg}))
        if not path:
            return bad("Enter a file path.")
        if os.path.isdir(path):
            return bad("That is a folder, not a file.")
        if not os.path.isfile(path):
            return bad("No file at %s. Check the spelling, or choose one from the suggestions." % path)
        try:
            pcapprofile.probe_readable(path)
            if want == "recipe":
                pcapprofile.load_recipe(path)
            else:
                if not pcapprofile.kind(path):
                    return bad("%s is not a pcap or pcapng file (bad magic number)." % os.path.basename(path))
                pcapprofile.check_size(path)
        except ValueError as e:
            return bad(str(e))
        return self._send(200, json.dumps({"ok": True, "size": os.path.getsize(path)}))

    def _manifest(self, q):
        """Read-only: the build manifest for a capture path (or the manifest path itself). Only a plain
        *.manifest.json file directly inside the default output folder or the folder of the last build is served."""
        p = os.path.expanduser((q.get("path") or [""])[0].strip())
        if p.lower().endswith((".pcap", ".pcapng")):
            p = os.path.splitext(p)[0] + ".manifest.json"
        with LOCK:
            roots = [DEFAULT_OUT, STATE.get("out_dir") or ""]
        roots = [os.path.realpath(r) for r in roots if r]
        d, n = os.path.split(p)
        if (not os.path.isabs(p) or not n.endswith(".manifest.json") or n.startswith(".") or "\x00" in p
                or os.path.realpath(d) not in roots or os.path.islink(p) or not os.path.isfile(p)):
            return self._send(400, json.dumps({"error": "not a build manifest: %s" % os.path.basename(p)}))
        try:
            with open(p, encoding="utf-8") as f:
                return self._send(200, f.read())
        except (OSError, UnicodeDecodeError):
            return self._send(400, json.dumps({"error": "cannot read manifest"}))

    def _captures(self, q):
        """Captures and recipes sitting in the output folder, newest first, to fill the path fields'
        suggestion lists. Names only; nothing is opened."""
        d = os.path.expanduser((q.get("out_dir") or [""])[0].strip() or DEFAULT_OUT)
        caps, recs, items = [], [], []
        try:
            entries = [e for e in os.scandir(d) if e.is_file()] if os.path.isdir(d) else []
        except OSError:
            entries = []
        entries.sort(key=lambda e: -e.stat().st_mtime)
        for e in entries:
            low = e.name.lower()
            if low.endswith((".pcap", ".pcapng")):
                caps.append(e.path)
                try:                                     # additive: size and date for the Captures library
                    st = e.stat()
                    items.append({"path": e.path, "name": e.name, "size": st.st_size, "mtime": int(st.st_mtime)})
                except OSError:
                    pass
            elif low.endswith("-recipe.json") or low.endswith(".recipe.json"):
                recs.append(e.path)
        return self._send(200, json.dumps({"dir": d, "captures": caps[:50], "recipes": recs[:50], "items": items[:50]}))

    def _profile_export(self, q):
        """The full tables behind the profile report as a download: format=json (everything) or
        format=csv&table=protocols|hosts|conversations|ports|names. Read-only."""
        if pcapprofile is None:
            return self._send(503, json.dumps({"error": "engine unavailable"}), "application/json")
        path = os.path.expanduser((q.get("path") or [""])[0].strip())
        fmt = (q.get("format") or ["json"])[0]
        if not path or not os.path.isfile(path) or not pcapprofile.kind(path):
            return self._send(400, json.dumps({"error": "not a readable pcap/pcapng file: %s" % path}),
                              "application/json")
        try:
            prof = pcapprofile.profile(path)
            base = os.path.splitext(os.path.basename(path))[0]
            if fmt == "csv":
                table = (q.get("table") or ["hosts"])[0]
                body, ctype, name = pcapprofile.table_csv(prof, table).encode(), "text/csv", "%s-%s.csv" % (base, table)
            else:
                body = json.dumps(pcapprofile.tables_json(prof), indent=1).encode()
                ctype, name = "application/json", "%s-profile.json" % base
        except ValueError as e:
            return self._send(413 if "importer accepts" in str(e) else 400, json.dumps({"error": str(e)}),
                              "application/json")
        except Exception as e:                       # noqa: BLE001
            import traceback
            traceback.print_exc()
            return self._send(500, json.dumps({"error": str(e)}), "application/json")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % name.replace('"', ""))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _profile_compare(self, q):
        """Profile a source capture and a rebuilt capture and show them side by side: per-protocol
        packet counts, hosts, and what the rebuild added or dropped. Read-only."""
        if make_diagram is None or pcapprofile is None:
            return self._send(503, self._engine_down_html(), "text/html; charset=utf-8")
        a = os.path.expanduser((q.get("a") or [""])[0].strip())
        b = os.path.expanduser((q.get("b") or [""])[0].strip())

        def _err(code, msg):
            return self._send(code, _msg_page("Compare", "Cannot compare", msg, q), "text/html; charset=utf-8")
        for pth in (a, b):
            if not pth or not os.path.isfile(pth) or not pcapprofile.kind(pth):
                return _err(400, "Not a readable pcap/pcapng file: %s" % pth)
        try:
            pa, pb = pcapprofile.profile(a), pcapprofile.profile(b)
            out = pcapprofile.compare_content(pa, pb)
            data = make_diagram.gather(os.path.join(APP_DIR, "inventory.json"), None, None)
            mods, selected = make_diagram.load_modules(None)
            c = make_diagram.DiagramContext(data, mods, selected)
            d = make_diagram.Diagram("compare", "Capture comparison", "Source versus rebuilt capture",
                                     lambda _c: out, 0, None)
            page = make_diagram.render_page(d, c, make_diagram.load_logo())
        except ValueError as e:
            return _err(413 if "importer accepts" in str(e) else 400, str(e))
        except Exception as e:                       # noqa: BLE001
            import traceback
            traceback.print_exc()
            return _err(500, str(e))
        return self._send(200, _themed(page, q), "text/html; charset=utf-8")

    def _recipe(self, q):
        """Generate a scenario-recipe JSON from an imported pcap and return it as a download.
        This is the 'output file' that is then re-imported via the recipe field on Generate."""
        if make_diagram is None or pcapprofile is None:
            return self._send(503, self._engine_down_html(), "text/html; charset=utf-8")
        path = os.path.expanduser((q.get("path") or [""])[0].strip())
        if not path or not os.path.isfile(path):
            return self._send(400, json.dumps({"error": "file not found: %s" % path}),
                              "application/json")
        if not pcapprofile.kind(path):
            return self._send(400, json.dumps({"error": "not a pcap/pcapng file"}),
                              "application/json")
        try:
            prof = pcapprofile.profile(path)
            why = pcapprofile.unusable_reason(prof)
            if why:
                return self._send(422, json.dumps({"error": "%s: %s" % (os.path.basename(path), why)}),
                                  "application/json")
            spec = pcapprofile.build_spec(prof, os.path.join(APP_DIR, "inventory.json"))
            body = json.dumps(spec, indent=2).encode()
        except ValueError as e:
            return self._send(413 if "importer accepts" in str(e) else 400,
                              json.dumps({"error": str(e)}), "application/json")
        except Exception as e:                       # noqa: BLE001
            import traceback
            traceback.print_exc()
            return self._send(500, json.dumps({"error": str(e)}), "application/json")
        name = os.path.splitext(os.path.basename(path))[0] + "-recipe.json"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", 'attachment; filename="%s"' % name)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._guarded(self._do_POST)

    def _do_POST(self):
        if self._blocked(check_origin=True):
            return
        done, verb, target = self._agent_gate("POST")
        if done:
            return
        if not verb:
            return self._do_POST_body(None, None)
        self._agent_args = None
        try:
            return self._do_POST_body(verb, target)
        finally:
            self._agent_done(verb, self._agent_args)

    def _do_POST_body(self, verb, target):
        if self.headers.get("Transfer-Encoding"):
            # no chunked bodies: unread chunk data would be parsed as the next request
            self.close_connection = True
            return self._send(411, json.dumps({"error": "a Content-Length is required; chunked bodies are not accepted"}))
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._send(400, json.dumps({"error": "bad Content-Length"}))
        if length < 0:
            return self._send(400, json.dumps({"error": "bad Content-Length"}))
        cap = settings_store.BODY_CAP if self.path in ("/api/settings", "/api/captures/trash", "/api/captures/restore") else campaign_api.BODY_CAP
        if length > cap:
            # Refuse without buffering it: drain a bounded amount so the client can read the reply, then close.
            left = length if length <= 16 * 1024 * 1024 else 0     # an absurd length is refused without waiting for a body
            while left > 0:
                chunk = self.rfile.read(min(65536, left))
                if not chunk:
                    break
                left -= len(chunk)
            self.close_connection = True
            return self._send(413, json.dumps({"error": "the request is larger than %s" % ("4 KB" if cap == settings_store.BODY_CAP else "2 MB")}))
        raw = self.rfile.read(length) if length else b"{}"
        bad_json = False
        try:
            data = json.loads(raw or b"{}")
        except (ValueError, RecursionError):
            data, bad_json = {}, True
        if verb:                                 # an agent call: local verbs are answered here, sensor verbs get the saved key
            self._agent_args = data
            try:
                if isinstance(target, tuple):
                    return self._send(*self._run_agent_local(target, data))
                data = agent_api.prepare(verb, data)
            except agent_api.AgentError as e:
                return self._send(e.status, json.dumps({"error": e.message}))
        if self.path.startswith("/api/agent/"):           # Settings controls; the cookie gate already ran
            status, obj = agent_api.route_ui(self.path, data)
            return self._send(status, json.dumps(obj))
        res = campaign_api.route_post(self.path, data, bad_json)
        if res is not None:                      # Campaign Builder endpoints (/api/intel/*, /api/campaign/*)
            status, body, ctype, hdrs = res
            return self._send(status, body, ctype, hdrs)
        if self.path == "/api/recipe/save":
            # Write the recipe beside the captures (not a browser download into ~/Downloads, which
            # macOS may gate behind a permission prompt) and tell the page where it went.
            if pcapprofile is None:
                return self._send(503, json.dumps({"error": "The generator engine is not available."}))
            if not isinstance(data, dict):
                return self._send(400, json.dumps({"error": "the request body must be a JSON object"}))
            src = os.path.expanduser(str(data.get("path") or "").strip())
            out_dir = os.path.expanduser(str(data.get("out_dir") or "").strip() or DEFAULT_OUT)
            if not src or not os.path.isfile(src):
                return self._send(400, json.dumps({"error": "No file at %s." % (src or "(empty path)")}))
            try:
                pcapprofile.probe_readable(src)
                if not pcapprofile.kind(src):
                    return self._send(400, json.dumps({"error": "Not a pcap or pcapng file."}))
                prof = pcapprofile.profile(src)
                why = pcapprofile.unusable_reason(prof)
                if why:
                    return self._send(422, json.dumps({"error": "%s: %s" % (os.path.basename(src), why)}))
                spec = pcapprofile.build_spec(prof, os.path.join(APP_DIR, "inventory.json"))
                os.makedirs(out_dir, exist_ok=True)
                dest = os.path.join(out_dir, os.path.splitext(os.path.basename(src))[0] + "-recipe.json")
                with open(dest, "w") as fh:
                    json.dump(spec, fh, indent=2)
            except ValueError as e:
                return self._send(413 if "importer accepts" in str(e) else 400, json.dumps({"error": str(e)}))
            except OSError as e:
                return self._send(400, json.dumps({"error": "Could not write the recipe: %s" % (e.strerror or e)}))
            except Exception as e:                   # noqa: BLE001 — never take the server down
                import traceback
                traceback.print_exc()
                return self._send(500, json.dumps({"error": str(e)}))
            return self._send(200, json.dumps({"ok": True, "path": dest, "flows": len(spec.get("flows", []))}))
        res = captures_store.route_post(self.path, data, bad_json, _busy)  # safe delete/restore (/api/captures/{trash,restore})
        if res is not None:
            status, body, ctype, hdrs = res
            return self._send(status, body, ctype, hdrs)
        res = updater.route_post(self.path, APP_DIR, _busy)         # install the patch the last check found
        if res is not None:
            status, body, ctype, hdrs = res
            if status == 200:
                threading.Timer(0.8, _restart).start()               # let the reply reach the page, then restart on the new files
            return self._send(status, body, ctype, hdrs)
        res = settings_store.route_post(self.path, data, bad_json)  # persistent UI settings (/api/settings)
        if res is not None:
            status, body, ctype, hdrs = res
            return self._send(status, body, ctype, hdrs)
        res = sessions_api.route_post(self.path, data, bad_json)    # saved sessions (/api/session/*)
        if res is not None:
            status, body, ctype, hdrs = res
            return self._send(status, body, ctype, hdrs)
        if not isinstance(data, dict):
            return self._send(400, json.dumps({"error": "the request body must be a JSON object"}))
        if self.path == "/api/generate":
            if opengenerator_build is None:
                return self._send(503, json.dumps({
                    "error": "The generator engine is not available on this machine "
                             f"({ENGINE_ERROR}). Check the dependency indicators above."}))
            with LOCK:
                if STATE["running"]:
                    return self._send(409, json.dumps({"error": "a run is already in progress"}))
            # Default matches the GUI field and opengenerator_build.build()'s own default:
            # a full business day. All three agree so an omitted scale never surprises.
            try:
                scale = float(data.get("scale", 1.0))
            except (TypeError, ValueError, OverflowError):
                return self._send(400, json.dumps({"error": "'scale' must be a number"}))
            scale = 0.001 if scale != scale else max(0.001, min(1.0, scale))
            out_dir = data.get("out_dir") or DEFAULT_OUT
            out_dir = os.path.expanduser(out_dir)
            certs = bool(data.get("certs", True))
            iocs = bool(data.get("iocs", True))
            # Emulated company (v5.0). Both blank = the default Example Logistics environment.
            # An industry outside the known set is rejected rather than silently themed.
            company = (data.get("company") or "").strip() or None
            industry = (data.get("industry") or "").strip() or None
            if industry and industry not in opengenerator_build.identity.INDUSTRIES:
                return self._send(400, json.dumps({
                    "error": "unknown industry %r; choose one of: %s"
                             % (industry, ", ".join(opengenerator_build.identity.INDUSTRIES))}))
            # Optional. Absent/blank means today, which is the point of the feature; a bad
            # string is rejected here rather than two minutes into a build.
            cap_date = (data.get("date") or "").strip() or None
            if cap_date:
                try:
                    datetime.datetime.strptime(cap_date, "%Y-%m-%d")
                except ValueError:
                    return self._send(400, json.dumps({
                        "error": "capture date must be YYYY-MM-DD, got %r" % cap_date}))
            # modules: absent/null = every module; a list = exactly those ([] = baseline day only)
            modules = data.get("modules", None)
            if modules is not None:
                if not isinstance(modules, list):
                    return self._send(400, json.dumps({"error": "'modules' must be a list of names"}))
                try:
                    modules = opengenerator_build.select_modules(modules)
                except ValueError as e:
                    return self._send(400, json.dumps({"error": str(e)}))
            try:
                # The OT subnet is opt-in: absent, nothing about it reaches the generator and
                # the capture is packet-identical to one built before the feature existed.
                ot_req = None
                if data.get("ot"):
                    ot_req = {"ot": data.get("ot_net") or None,
                              "ops": data.get("ot_ops_net") or None,
                              "idmz": data.get("ot_idmz_net") or None}
                user_net, server_net, ot_nets = opengenerator_build.validate_nets(
                    data.get("user_net"), data.get("server_net"), ot_req)
            except ValueError as e:
                return self._send(400, json.dumps({"error": str(e)}))
            # Which OT process protocols to emit (the OT-subnet protocol checkboxes). Only meaningful
            # when the OT subnet is on; None = every protocol (back-compat). The energy protocols are
            # additionally gated to the Energy industry by the engine, so passing them without Energy
            # is harmless.
            ot_protocols = None
            if ot_nets and isinstance(data.get("ot_protocols"), list):
                ot_protocols = [str(p) for p in data["ot_protocols"]]
            # recipes: a list of pcap-import recipe JSONs, one CUSTOM scenario each. Back-compat:
            # a single `recipe` string is accepted too. Each must exist on disk.
            raw = data.get("recipes")
            if raw is None:
                raw = [data.get("recipe")] if data.get("recipe") else []
            recipe_paths = []
            for rp in raw:
                rp = os.path.expanduser((rp or "").strip())
                if not rp:
                    continue
                if not os.path.isfile(rp):
                    return self._send(400, json.dumps({"error": "recipe file not found: %s" % rp}))
                if pcapprofile is not None:                # reject a malformed recipe now, not mid-build
                    try:
                        pcapprofile.load_recipe(rp)
                    except ValueError as e:
                        return self._send(400, json.dumps({"error": "bad recipe: %s" % e}))
                recipe_paths.append(rp)
            # Campaign Builder fields (all optional): validated here, before any thread starts.
            try:
                campaigns, address_mode, confirm_real = campaign_api.parse_generate_extras(data)
            except campaign_api.ApiError as e:
                return self._send(e.status, json.dumps(dict(e.extra, error=e.message)))
            gen_args = (scale, out_dir, certs, iocs, modules, user_net, server_net,
                        cap_date, ot_nets, recipe_paths or None, company, industry, ot_protocols)
            if campaigns:
                gen_args += (campaigns, address_mode, confirm_real)
            with LOCK:                               # claim the run here, atomically, so a second POST gets the 409
                if STATE["running"]:
                    return self._send(409, json.dumps({"error": "a run is already in progress"}))
                STATE["running"] = True
            threading.Thread(target=run_generator, args=gen_args, daemon=True).start()
            return self._send(200, json.dumps({"ok": True, "out_dir": out_dir,
                                               "modules": modules,
                                               "user_net": user_net, "server_net": server_net}))
        if self.path == "/api/generate/stop":
            with LOCK:
                if not STATE["running"]:
                    return self._send(409, json.dumps({"error": "no generation is running"}))
                already = CANCEL.is_set()
                if not already:
                    STATE["log"].append("stop requested — finishing the current batch …")
            CANCEL.set()
            # Cooperative: the engine notices within ~20,000 packets. Returning immediately
            # keeps the UI responsive; /api/status reports when it has actually stopped.
            return self._send(200, json.dumps({"ok": True, "already_stopping": already}))
        if self.path == "/api/capabilities/enable":
            # v5c Phase 9: persist (or clear) a module's auto-load-on-startup flag. Does not
            # change the current loaded state -- that's load/unload.
            if capkernel is None:
                return self._send(503, json.dumps({"error": "capability kernel unavailable"}))
            name = (data.get("name") or "").strip()
            if not name:
                return self._send(400, json.dumps({"error": "a module 'name' is required"}))
            capkernel.kernel.set_enabled(name, bool(data.get("on")))
            return self._send(200, json.dumps({"ok": True,
                                                "capabilities": capkernel.kernel.catalog()}))
        if self.path == "/api/capabilities/test-all":
            # v5c Phase 6: run every loaded module's self_test (some, e.g. baseline_pin, build).
            if capkernel is None:
                return self._send(503, json.dumps({"error": "capability kernel unavailable"}))
            with LOCK:
                if STATE["running"]:
                    return self._send(409, json.dumps({
                        "error": "a capture is generating; run self-tests when it finishes"}))
            # self_test_all builds; serialize it so it can't run against a concurrent build.
            with BUILD_LOCK:
                return self._send(200, json.dumps(capkernel.kernel.self_test_all()))
        if self.path in ("/api/capabilities/load", "/api/capabilities/unload",
                         "/api/capabilities/reload", "/api/capabilities/test"):
            # v5b: run-time load/unload/reload/self-test of a capability module.
            if capkernel is None:
                return self._send(503, json.dumps({"error": "capability kernel unavailable"}))
            name = (data.get("name") or "").strip()
            if not name:
                return self._send(400, json.dumps({"error": "a module 'name' is required"}))
            action = self.path.rsplit("/", 1)[1]
            # The capability set is frozen while a capture is building: loading/unloading would
            # pull a registry out from under the engine, and a self_test may itself build.
            if action in ("load", "unload", "reload", "test"):
                with LOCK:
                    if STATE["running"]:
                        return self._send(409, json.dumps({
                            "error": "a capture is generating; try again when it finishes"}))
            try:
                if action == "load":
                    changed = capkernel.kernel.load(name)
                    result = {"ok": True, "changed": changed,
                              "detail": "loaded" if changed else "already loaded"}
                    # A module runs its code with the server's full privileges; flag third-party
                    # ones (added to modules/ after install) so loading one is a conscious act.
                    if name not in capkernel.SHIPPED_MODULES:
                        result["warning"] = ("%r is a third-party module — it ran with this "
                                              "application's privileges. Load only modules you "
                                              "trust." % name)
                elif action == "unload":
                    changed = capkernel.kernel.unload(name)
                    result = {"ok": True, "changed": changed,
                              "detail": "unloaded" if changed else "was not loaded"}
                elif action == "reload":
                    capkernel.kernel.reload(name)
                    result = {"ok": True, "changed": True, "detail": "reloaded"}
                else:  # test -- a self_test may build, so serialize it against other builds
                    with BUILD_LOCK:
                        result = {"ok": True, "test": capkernel.kernel.self_test(name)}
            except capkernel.ModuleError as e:
                return self._send(400, json.dumps({"error": str(e)}))
            result["capabilities"] = capkernel.kernel.catalog()
            return self._send(200, json.dumps(result))
        if self.path == "/api/replay/preflight":
            pcap = os.path.expanduser(data.get("pcap") or "")
            return self._send(200, json.dumps(replay.preflight(pcap or None,
                                                               data.get("iface") or None)))
        if self.path == "/api/replay/start":
            try:
                mode = data.get("speed_mode", "multiplier")
                value = data.get("speed_value", 1.0)
                value = float(value) if mode != "topspeed" else 0.0
                if mode == "multiplier":
                    value = max(0.01, min(1000.0, value))
                loop = max(0, int(data.get("loop", 1) or 1))
                r = replay.start(data.get("pcap") or "", data.get("iface") or "",
                                 speed_mode=mode, speed_value=value, loop=loop,
                                 preload=bool(data.get("preload", False)),
                                 monitor=bool(data.get("monitor", True)))
                return self._send(200, json.dumps(r))
            except RuntimeError as e:
                code = 409 if "already in progress" in str(e) else 400
                return self._send(code, json.dumps({"error": str(e)}))
            except (TypeError, ValueError) as e:
                return self._send(400, json.dumps({"error": f"bad replay parameters: {e}"}))
        if self.path == "/api/bye":
            # sendBeacon from pagehide. The presence stream closing would be noticed anyway
            # within a ping interval; this just makes a deliberate close instant. It carries
            # no client id because it does not need one -- it only nudges the watchdog to
            # re-check, and the stream count is what actually decides.
            return self._send(200, json.dumps({"ok": True}))
        if self.path == "/api/sensor/preflight":
            # Read-only. Runs before the destructive push so the operator is told how many
            # keys are about to be deleted BEFORE confirming, not afterwards.
            try:
                return self._send(200, json.dumps(push_cert.preflight(
                    (data.get("sensor") or "").strip(),
                    data.get("apikey") or "",
                    data.get("certs_dir") or None)))
            except Exception as e:                       # noqa: BLE001
                return self._send(500, json.dumps({"ok": False, "errors": [str(e)]}))
        if self.path == "/api/sensor/push":
            # `confirm` is required and must be the literal string below: this deletes every
            # SSL decryption key on the sensor, so it must not be reachable by an accidental
            # or replayed POST.
            if data.get("confirm") != "DELETE-AND-REPLACE":
                return self._send(400, json.dumps({
                    "error": "confirmation required: this replaces every SSL decryption key "
                             "on the sensor."}))
            certs_dir = os.path.expanduser(data.get("certs_dir") or "")
            if not os.path.isdir(certs_dir):
                # Not "generate a capture first": the folder being absent is usually a typed
                # path, and sending someone off to rebuild an 8 GB capture they already have
                # is the wrong remedy for the wrong diagnosis.
                return self._send(400, json.dumps({
                    "error": "That folder does not exist: %s.%s"
                             % (certs_dir, push_cert.path_hint(certs_dir))}))
            if not push_cert.find_pairs(certs_dir):
                return self._send(400, json.dumps({
                    "error": "%s exists but holds no .crt/.key pairs — generate a capture "
                             "with \u2018Export server certs + keys\u2019 ticked first."
                             % certs_dir}))
            try:
                return self._send(200, json.dumps(push_cert.push_cert(
                    (data.get("sensor") or "").strip(),
                    data.get("apikey") or "",
                    certs_dir,
                    protocol=(data.get("protocol") or "http").lower(),
                    port=int(data.get("port") or 443))))
            except RuntimeError as e:
                return self._send(409, json.dumps({"error": str(e)}))
            except (TypeError, ValueError) as e:
                return self._send(400, json.dumps({"error": "bad parameters: %s" % e}))
        if self.path == "/api/sensor/stop":
            r = push_cert.stop()
            return self._send(200 if r.get("ok") else 409, json.dumps(r))
        if self.path == "/api/sensor/collection/preflight":
            # Read-only, like the certificate preflight: reports what is on the appliance and
            # what is about to be sent, before anything is changed.
            try:
                return self._send(200, json.dumps(push_ti.collection_preflight(
                    (data.get("sensor") or "").strip(),
                    data.get("apikey") or "",
                    data.get("stix") or None,
                    target=(data.get("target") or "sensor"))))
            except Exception as e:                       # noqa: BLE001
                return self._send(500, json.dumps({"ok": False, "errors": [str(e)]}))
        if self.path == "/api/sensor/collection/push":
            # No confirmation token here, unlike the certificate push. This replaces only the
            # collection the tool owns and leaves every other collection alone, so demanding
            # a typed confirmation would train the operator to dismiss one that matters.
            stix = os.path.expanduser(data.get("stix") or "")
            if not stix:
                return self._send(400, json.dumps({
                    "error": "no threat collection file given."}))
            if not os.path.isfile(stix):
                return self._send(400, json.dumps({
                    "error": "threat collection not found: %s — generate a capture with "
                             "\u2018Export threat collection\u2019 ticked first." % stix}))
            try:
                return self._send(200, json.dumps(push_ti.push_ti(
                    (data.get("sensor") or "").strip(),
                    data.get("apikey") or "",
                    stix,
                    target=(data.get("target") or "sensor"),
                    detections=bool(data.get("detections", True)))))
            except RuntimeError as e:
                return self._send(409, json.dumps({"error": str(e)}))
            except (TypeError, ValueError) as e:
                return self._send(400, json.dumps({"error": str(e)}))
        if self.path == "/api/sensor/collection/stop":
            r = push_ti.collection_stop()
            return self._send(200 if r.get("ok") else 409, json.dumps(r))
        if self.path == "/api/replay/stop":
            r = replay.stop()
            return self._send(200 if r.get("ok") else 409, json.dumps(r))
        if self.path == "/api/reveal":
            out_dir = data.get("out_dir") or STATE.get("out_dir") or DEFAULT_OUT
            # Resolve symlinks and require a PLAIN folder. The platform openers (`open`,
            # `xdg-open`, os.startfile) would otherwise launch an application, open a file in its
            # handler, or open a URL — so an arbitrary path here is a launch primitive. A real
            # directory alone is not enough on macOS, where an application/package BUNDLE (.app,
            # …) is itself a directory and `open` LAUNCHES it; so reject bundles too. What is
            # left is "show me the output folder", this endpoint's only purpose.
            out_dir = os.path.realpath(os.path.expanduser(out_dir))
            if not os.path.isdir(out_dir):
                return self._send(400, json.dumps({"error": "not a folder: %s" % out_dir}))
            if os.path.basename(out_dir).lower().endswith(_BUNDLE_EXTS):
                return self._send(400, json.dumps({
                    "error": "refusing to open an application/package bundle: %s" % out_dir}))
            try:
                if sys.platform == "darwin":
                    subprocess.run(["open", out_dir], check=False)
                elif sys.platform.startswith("win"):
                    os.startfile(out_dir)         # noqa: SC200
                else:
                    subprocess.run(["xdg-open", out_dir], check=False)
                return self._send(200, json.dumps({"ok": True}))
            except Exception as e:                # noqa: BLE001
                return self._send(500, json.dumps({"error": str(e)}))
        return self._send(404, b"not found", "text/plain")


def find_port(start=8765):
    """First port we can actually bind.

    Probing with connect() is not enough: a port can refuse connections and still be
    unbindable (TIME_WAIT, or bound-but-not-listening), which would crash the server on
    launch. Binding is the only real test, so try that and keep the socket's verdict.
    """
    import socket
    for port in range(start, start + 40):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            # SO_REUSEADDR matches what ThreadingHTTPServer sets (allow_reuse_address), so the
            # probe's verdict matches the real bind's. Without it a TIME_WAIT socket from a just-
            # restarted server made the probe skip the preferred port (8765) and land on 8766,
            # orphaning a preview pane pinned to 8765. A genuinely in-use port still raises.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise SystemExit(f"No free port in {start}-{start + 39}; is the app already running?")


def _restart():
    """Start a fresh copy of this app a moment from now (it takes over the port once this one has let go), then stop."""
    argv = [sys.executable] + ([] if getattr(sys, "frozen", False) else [os.path.abspath(__file__)]) + [a for a in sys.argv[1:] if a != "--no-browser"]
    subprocess.Popen(["/bin/sh", "-c", 'sleep 1.5; exec "$@"', "sh"] + argv, start_new_session=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutdown("updated; restarting", stop_work=False)


def main():
    # A replay outlives this process: tcpreplay is detached and root-owned. Adopt one that
    # is still running before serving anything, so the UI shows it and Stop reaches it
    # instead of reporting "idle" over a NIC that is still being flooded.
    try:
        adopted = replay.reattach()
        if adopted:
            print(f"reattached to a replay already in progress "
                  f"(pid {adopted['pid']}, {os.path.basename(adopted['pcap'])} "
                  f"-> {adopted['iface'] or 'file'}).")
    except Exception as e:                             # noqa: BLE001 - never block startup
        print(f"note: could not check for a running replay ({e}).")

    global _HTTPD
    LIFECYCLE["autoquit"] = "--no-autoquit" not in sys.argv

    port = find_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    _HTTPD = httpd
    url = f"http://127.0.0.1:{port}/"
    overlay.confirm_boot()                              # a patch, if one is running, started fine
    print(f"{branding.PRODUCT_NAME} UI  ->  {url}")
    if LIFECYCLE["autoquit"]:
        print("Closing the browser tab stops the server. Ctrl-C also works.")
    else:
        print("Close this window (or Ctrl-C) to stop the server.  [--no-autoquit]")

    # SIGTERM: quitting the .app, `kill`, macOS logout. SIGHUP: the Terminal window that
    # launched run.command being closed. Neither was handled, so the process died without
    # closing its socket or stopping anything it had started.
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, lambda n, _f: shutdown(f"received {signal.Signals(n).name}",
                                                      stop_work=True))
        except (ValueError, OSError):                  # not on the main thread, or unsupported
            pass

    threading.Thread(target=_watchdog, daemon=True).start()
    if "--no-browser" not in sys.argv:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        shutdown("interrupted", stop_work=True)
    finally:
        # The point of the whole exercise: actually release the listening socket, so the
        # next start gets the same port instead of walking up to 8766, 8767, 8768 …
        httpd.server_close()
        print("port released. stopped.")


if __name__ == "__main__":
    main()

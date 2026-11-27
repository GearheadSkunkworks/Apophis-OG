#!/usr/bin/env python3
"""
OpenGenerator — application dependency preflight.

The sibling of `replay.preflight()`, for everything the *generator* needs rather than
everything the *replay* needs. It answers one question for the GUI: can this machine build a
capture, and if not, precisely what is absent and how is it installed?

Deliberately stdlib-only and side-effect free — it has to be able to run and report on a
machine where the third-party dependency it is checking for is missing, so it must not import
anything it is testing at module scope.

Two habits worth keeping if you extend it:

* **Import the way the engine imports.** A bare `import cryptography` is pure Python and
  succeeds even when the compiled Rust binding underneath is unusable — which is the exact
  failure a PyInstaller bundle produces (see BUILD-macos.md). `check()` therefore
  imports the same primitives `netgen/tls.py` does and constructs an AESGCM object, so a
  broken wheel is reported here rather than surfacing as a traceback mid-build.
* **Only list things the app actually uses.** `tshark` is not here: captures are validated by
  hand during development and the application never invokes it, so a chip for it would be
  decoration. An indicator nobody can act on is worse than no indicator.

    python3 deps.py            # human-readable report; exit 1 if a requirement is missing
"""
import json
import os
import re
import sys

# When frozen by PyInstaller the bundled data files live in sys._MEIPASS, not next to a
# source file — __file__ points into the temporary extraction dir and everything built from
# it (ui/, assets/, inventory.json, netgen/) would be looked up in the wrong place.
import overlay as _overlay                                # noqa: E402 - the patch overlay's directory when one is active
APP_DIR = _overlay.app_dir(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))))

MIN_PYTHON = (3, 9)

# The business day is built in US/Eastern. zoneinfo reads the system tz database, which a
# stock macOS always has, but a stripped container or a .app built on a machine without it
# does not — and the failure is an import-time exception from netgen.model, not a clear error.
TZ_NAME = "America/New_York"


# Recognises a hint that can be pasted into a terminal, as opposed to advice for a human.
_CMD_WORDS = ("pip", "pip3", "brew", "python", "python3", "sudo", "xcode-select")


def _is_command(hint):
    head = (hint or "").strip().split()
    return bool(head) and head[0] in _CMD_WORDS


def _frozen():
    return bool(getattr(sys, "frozen", False))


# Inside the packaged app nothing is installed by the user: Python, cryptography and the time
# zone data are all in the bundle, so a failure means a damaged build, never a missing install.
REINSTALL_HINT = "this copy of the app is damaged — reinstall OpenGenerator"


def _entry(name, required, found, why, version="", hint="", detail=""):
    return {"name": name, "required": bool(required), "found": bool(found), "why": why,
            "version": version, "hint": hint, "detail": detail}


def _check_python():
    v = sys.version_info
    ok = (v.major, v.minor) >= MIN_PYTHON
    if _frozen():
        return _entry("python", True, ok, "runs the generator engine",
                      version="built in", hint="" if ok else REINSTALL_HINT)
    return _entry(
        "python", True, ok,
        "runs the generator engine",
        version=f"{v.major}.{v.minor}.{v.micro}",
        hint="" if ok else "install Python %d.%d+ from python.org, or: brew install python"
                           % MIN_PYTHON,
        detail=sys.executable)


def _check_cryptography():
    """Import what netgen/tls.py imports, then exercise the native binding."""
    try:
        import cryptography                                             # noqa: F401 - imported only to prove the package is installed
        from cryptography import x509                                   # noqa: F401 - imported only to prove the package is installed
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: F401 - imported only to prove the package is installed
        from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: F401 - imported only to prove the package is installed
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        AESGCM(b"\x00" * 16)                     # touches the compiled backend, ~instant
    except Exception as e:                                              # noqa: BLE001 - import failure is the probe result, reported as a missing dependency
        return _entry("cryptography", True, False,
                      "real RSA certificates and AES-GCM TLS",
                      hint=REINSTALL_HINT if _frozen() else "pip3 install -r requirements.txt",
                      detail=f"{type(e).__name__}: {e}")
    if _frozen():
        return _entry("cryptography", True, True,
                      "real RSA certificates and AES-GCM TLS", version="built in")
    return _entry("cryptography", True, True,
                  "real RSA certificates and AES-GCM TLS",
                  version=getattr(cryptography, "__version__", ""),
                  detail=os.path.dirname(getattr(cryptography, "__file__", "") or ""))


def _check_tzdata():
    try:
        import zoneinfo
        zoneinfo.ZoneInfo(TZ_NAME)
    except Exception as e:                                              # noqa: BLE001 - failure is the probe result, reported as missing time zone data
        return _entry("time zone data", True, False,
                      f"the business day is built in {TZ_NAME}",
                      hint=REINSTALL_HINT if _frozen() else "pip3 install tzdata",
                      detail=f"{type(e).__name__}: {e}")
    return _entry("time zone data", True, True,
                  f"the business day is built in {TZ_NAME}", version=TZ_NAME)


def _check_inventory():
    regen = REINSTALL_HINT if _frozen() else "python3 inventory.py   (regenerates it)"
    path = os.path.join(APP_DIR, "inventory.json")
    if not os.path.isfile(path):
        return _entry("inventory.json", True, False, "the host inventory the capture is built from",
                      hint=regen, detail=path)
    try:
        with open(path) as f:
            hosts = json.load(f)["hosts"]
        addressed = [h for h in hosts if h.get("ip")]
        # The OT assets are only built when the industrial zone is switched on, so reporting one
        # total would claim 238 for a default capture that contains 144. An indicator has to say
        # what THIS run will produce, not what the file happens to hold.
        base = len([h for h in addressed if not h.get("purdue")])
        ot = len(addressed) - base
        version = f"{base} assets" + (f" + {ot} OT (optional)" if ot else "")
        return _entry("inventory.json", True, True, "the host inventory the capture is built from",
                      version=version, detail=path)
    except Exception as e:                                              # noqa: BLE001 - failure is the probe result, reported in the entry detail
        return _entry("inventory.json", True, False, "the host inventory the capture is built from",
                      hint=regen,
                      detail=f"{type(e).__name__}: {e}")


def _check_engine():
    """The bundled generator itself. Imported the way server.py imports it.

    Distinguishes two very different failures that look identical from the outside: files
    genuinely absent from the folder, and files present but unimportable because something
    they depend on is missing. The second must not tell the user to re-copy the folder — the
    fault is the dependency reported above it, and sending someone to re-download a complete
    folder to fix a missing pip package wastes their afternoon.
    """
    # Inside a PyInstaller bundle netgen/ is embedded in the archive as importable modules,
    # NOT extracted as files, so a file-existence check reports a complete app as broken. The
    # import below is the real test either way; the file check only exists to give a better
    # message when running from source.
    if not getattr(sys, "frozen", False):
        parts = ["opengenerator_build.py", os.path.join("netgen", "__init__.py"),
                 os.path.join("netgen", "incidents.py")]
        absent = [p for p in parts if not os.path.isfile(os.path.join(APP_DIR, p))]
        if absent:
            return _entry("generator engine", True, False, "netgen/ + opengenerator_build.py",
                          hint="the application folder is incomplete — re-copy it",
                          detail="missing: " + ", ".join(absent))
    if APP_DIR not in sys.path:
        sys.path.insert(0, APP_DIR)
    try:
        import opengenerator_build                                          # noqa: F401 - imported only to prove the package is installed
        import netgen.incidents as INC
        n = len(INC.REGISTRY)
    except Exception as e:                                              # noqa: BLE001 - import failure is the probe result, reported in the entry
        # ModuleNotFoundError carries .name; a plain ImportError raised from deeper in a
        # package (a broken binding re-raising) may not, so fall back to the message.
        root = ""
        if isinstance(e, ImportError):
            root = (getattr(e, "name", "") or "").split(".")[0]
            if not root:
                m = re.search(r"No module named '([^'.]+)", str(e))
                root = m.group(1) if m else ""
        blocked = root and root not in ("netgen", "opengenerator_build", "inventory")
        return _entry("generator engine", True, False, "netgen/ + opengenerator_build.py",
                      hint=((REINSTALL_HINT if getattr(sys, "frozen", False) else
                             f"resolve the '{root}' dependency above — the engine files are present")
                            if blocked else (REINSTALL_HINT
                                             if getattr(sys, "frozen", False)
                                             else "the application folder may be damaged")),
                      detail=f"{type(e).__name__}: {e}")
    return _entry("generator engine", True, True, "netgen/ + opengenerator_build.py",
                  version=f"{n} modules", detail=APP_DIR)

def _check_logo():
    """Optional: absent only costs the diagrams their wordmark (make_diagram falls back)."""
    path = os.path.join(APP_DIR, "assets", "logo-color.svg")
    found = os.path.isfile(path)
    return _entry("product wordmark", False, found,
                  "branding on generated diagrams",
                  hint="" if found else (REINSTALL_HINT if _frozen()
                                      else "restore assets/logo-color.svg from the snapshot zip"),
                  detail=path if found else "diagrams will render without the logo")


def _check_reveal():
    """Optional: the 'Reveal in folder' button."""
    from shutil import which
    if sys.platform == "darwin":
        path = "/usr/bin/open"
        return _entry("open", False, os.path.exists(path),
                      "the 'Reveal in folder' button", hint="part of macOS", detail=path)
    path = which("xdg-open")
    return _entry("xdg-open", False, bool(path), "the 'Reveal in folder' button",
                  hint="" if path else "optional: install xdg-utils", detail=path or "")


CHECKS = (_check_python, _check_cryptography, _check_tzdata, _check_inventory,
          _check_engine, _check_logo, _check_reveal)


def check():
    """Report on every dependency the generator side of the app relies on.

    Shape matches `replay.preflight()` — {ok, tools, missing, errors, warnings} — so the GUI
    renders both with the same chip and alert code.
    """
    tools = [fn() for fn in CHECKS]
    missing = [t["name"] for t in tools if t["required"] and not t["found"]]
    errors, warnings = [], []
    for t in tools:
        if t["found"]:
            continue
        msg = f"'{t['name']}' is unavailable — {t['why']}"
        if t["detail"] and not os.path.isabs(t["detail"]):
            msg += f" ({t['detail']})"
        msg += "."
        if t["hint"]:
            # Only a hint that really is a shell command gets "Install it with:" — the UI
            # turns that phrase into a <code> span. Prose remedies ("resolve the dependency
            # above") read as nonsense in that frame, so they are appended as a sentence.
            msg += (f" Install it with: {t['hint']}" if _is_command(t["hint"])
                    else " " + t["hint"][0].upper() + t["hint"][1:] + ".")
        (errors if t["required"] else warnings).append(msg)
    return {"ok": not missing, "tools": tools, "missing": missing,
            "errors": errors, "warnings": warnings, "platform": sys.platform,
            # The packaged app carries everything it needs, so a row of green ticks is noise
            # there; the UI uses this to show the row only when something is wrong.
            "frozen": _frozen()}


if __name__ == "__main__":
    rep = check()
    # --brief drops the paths: run.command prints this beside its own checks, where the detail
    # lines would bury the result. The GUI shows the same data as chips with tooltips.
    brief = "--brief" in sys.argv
    if "--json" in sys.argv:
        print(json.dumps(rep, indent=2))
        sys.exit(0 if rep["ok"] else 1)
    for t in rep["tools"]:
        mark = "✓" if t["found"] else ("✗" if t["required"] else "○")
        tag = "" if t["required"] else "  (optional)"
        extra = f" — {t['version']}" if t["version"] else ""
        print(f"  {mark} {t['name']}{extra}{tag}")
        # In brief mode only the interpreter path survives: "which python is this?" is the
        # question a launcher log actually gets asked.
        if t["detail"] and (not brief or t["name"] == "python"):
            print(f"      {t['detail']}")
        if not t["found"] and t["hint"]:
            print(f"      {'install: ' if _is_command(t['hint']) else ''}{t['hint']}")
    if not brief:
        print()
        print("ready to generate" if rep["ok"] else "MISSING: " + ", ".join(rep["missing"]))
    sys.exit(0 if rep["ok"] else 1)

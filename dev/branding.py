"""Central branding seam for the traffic generator.

Single source of truth for the product name, the monitoring platform the capture is
built to demo against, the brand colour palette, and the logo. Phase 0 of the de-brand
introduces this module as an indirection layer only: every value here is identical to
what was previously hard-coded in make_diagram.py / server.py, so the app looks and
behaves the same and the generated capture is unaffected. (Branding changes never touch
the wire; the current pinned baseline is 466,343 packets at ``--scale 0.004 --no-modules``,
moved off the earlier 607,886 by the phase-3 environment rename, not by this module.)

This module is presentation-only and depends on the standard library alone. The netgen
engine and the top-level build script do not import it, so nothing here can change what
goes on the wire.
"""
import base64
import os
import sys

# ---- product -------------------------------------------------------------
PRODUCT_NAME = "OpenGenerator"                         # bare name: identifiers, startup line
PRODUCT_NAME_SHORT = "OpenGenerator"                   # short name: macOS CFBundleName
CAPTURES_DIRNAME = "OpenGenerator-Captures"            # default output folder created under ~
VERSION = "v5"                                         # release line
CODENAME = "Apophis"                                   # v5 code name
# Full display title for page/window titles. PRODUCT_NAME stays the bare name for identifiers
# and anywhere a version should NOT appear (paths, bundle name).
PRODUCT_TITLE = "%s %s (%s)" % (PRODUCT_NAME, VERSION, CODENAME)   # OpenGenerator v5 (Apophis)

# ---- platform (the NDR/NPM platform this capture is built to feed) -------
# Neutral defaults for the open-source upstream. A downstream build overrides these with
# its target platform's identity (vendor name, platform name, and documentation base URL).
VENDOR = ""
PLATFORM = "NDR/NPM platform"
PLATFORM_FULL = "network traffic analysis platform"
DOCS_BASE_URL = ""

# ---- theme palette -------------------------------------------------------
# Neutral theme palette ("Forge": burnt-orange primary, red/green/amber accents, fading to
# near-black). The four scenario-category accents must stay in step with CATS (and the CSS
# variables / gradients) in ui/index.html, and with the raw accent values in
# netgen/incidents.py -- which cannot import this module, because the wire path stays
# independent of branding, so that copy is updated by hand. Keep the accents distinct and
# legible on white. Downstream builds may override with their own brand colours. (The
# constant names are legacy labels, not literal colour names.)
SAPPHIRE = "#C2410C"    # primary: headers, gradients, CUSTOM category (burnt orange)
PLUM = "#DC2626"        # NDR accent (red)
CYAN = "#15803D"        # NPM accent (green)
TANGERINE = "#F59E0B"   # CRP accent (amber)
GRAY = "#4B5563"        # neutral (slate)
MAGENTA = "#1D4ED8"     # OT accent (blue)
VIOLET = "#7C3AED"      # IR accent (violet) -- distinct from the SEC red (PLUM)
FADE = "#0A0A0A"        # gradient fade endpoint: the primary fades to near-black

# scenario category -> accent (NDR Plum, NPM Cyan, CRP Tangerine, OT Magenta)
CATEGORY_COLORS = {"NDR": PLUM, "NPM": CYAN, "CRP": TANGERINE, "OT": MAGENTA}

# The scenario categories, in display order -- the single source for each one's engine `key`,
# short display `tag` (what the chips/pills read), full `label`, and accent `color`. The GUI
# builds its category chips, groups and select-buttons from this (served via /api/modules), so
# relabelling a category (e.g. SEC -> Attacks) or recolouring it is a one-line change here
# instead of edits spread across the UI and this file.
CATEGORIES = [
    {"key": "NDR",    "tag": "SEC",    "label": "Security detections (SEC)",              "color": PLUM},
    {"key": "NPM",    "tag": "PERF",   "label": "Performance faults (PERF)",              "color": CYAN},
    {"key": "CRP",    "tag": "CRYP",   "label": "Crypto posture (CRYP)",                  "color": TANGERINE},
    {"key": "CUSTOM", "tag": "CUSTOM", "label": "Custom (rebuilt from an imported pcap)", "color": SAPPHIRE},
    {"key": "OT",     "tag": "OT",     "label": "OT / ICS (Purdue 0–3.5)",           "color": MAGENTA},
    {"key": "IR",     "tag": "REPLAY", "label": "Incident Replay (real-world reconstruction)", "color": VIOLET},
]

# ---- logo ----------------------------------------------------------------
# When frozen by PyInstaller the bundled data files live in sys._MEIPASS, not next to a
# source file -- __file__ points into the temporary extraction dir and everything built
# from it (ui/, assets/, inventory.json, netgen/) would be looked up in the wrong place.
import overlay as _overlay                                # noqa: E402 - the patch overlay's directory when one is active
APP_DIR = _overlay.app_dir(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))))
# The bundled copy only: the app does not read anything from elsewhere on the machine.
LOGO_CANDIDATES = [
    os.path.join(APP_DIR, "assets", "logo-color.svg"),
]


# The product mark, in black for the light page chrome (About page and every diagram
# masthead). Returned as a self-contained data-URI <img> so a standalone HTML file written
# by the make_diagram CLI carries the logo without a server round-trip.
LOGO_FILE = os.path.join(APP_DIR, "ui", "about-logo.png")


def load_logo():
    """Return a self-contained <img> (base64 data-URI) for the product logo, or "" if the
    file is missing. Used by every page that embeds the masthead mark: the About page, the
    GUI-rendered diagrams, and the standalone diagram HTML the make_diagram CLI writes."""
    try:
        with open(LOGO_FILE, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
    except OSError:
        return ""
    return ('<img src="data:image/png;base64,%s" alt="OpenGenerator logo" '
            'style="height:40px;width:auto;display:block">' % b64)

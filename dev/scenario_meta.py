"""Scenario metadata served additively through /api/modules (stdlib only).

The data lives in scenario_meta.json next to this file (bundled the same way as inventory.json).
It is descriptive copy only: nothing here is read by the traffic engine. A missing or malformed file
yields an empty mapping, so a request can never fail because of it.
"""
import json
import os
import sys
import threading

import overlay as _overlay                                # noqa: E402 - the patch overlay's directory when one is active
APP_DIR = _overlay.app_dir(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))))
PATH = os.path.join(APP_DIR, "scenario_meta.json")

# Ordered categories per family, as the category rail lists them. REPLAY and the recipe-driven
# families each have one fixed bucket.
TAXONOMY = {
    "SEC": ["Initial access", "Credential access", "Discovery", "Lateral movement",
            "Command and control", "Exfiltration", "Impact", "Multi-stage campaign"],
    "PERF": ["Slow applications", "Packet loss and retransmits", "DNS and DHCP faults", "Capacity"],
    "CRYP": ["Weak TLS", "Certificate problems"],
    "REPLAY": ["Incident replay"],
    "CUSTOM": ["Custom recipe"],
    "CAMPAIGN": ["Custom recipe"],
}

# Fields shipped to the UI. Provenance fields (sources, notes) stay in the file only.
PUBLIC_FIELDS = ("category", "category_fit", "also_categories", "expected_observation",
                 "protocols", "protocols_check", "scale", "hosts", "zone_path", "steps", "confidence")
VERIFY_PATH = os.path.join(APP_DIR, "docs", "redesign", "meta-verification.json")
SCALE_PATH = os.path.join(APP_DIR, "scenario_scale.json")      # written by tools/measure_scenario_scale.py

_lock = threading.Lock()
_cache = None            # {"status": str, "by_id": {id: entry}}
_vcache = None           # {id: result} from meta-verification.json
_scache = None           # {id: scale profile} from scenario_scale.json


def _labels(v):
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def protocols_check(entry, result):
    """Verification state of a scenario's declared protocols, from one tool result (or None)."""
    declared = _labels(entry.get("protocols"))
    if not isinstance(result, dict) or result.get("verdict") != "pass":
        return {"status": "unchecked", "checked": [], "carrier_only": [], "unverified": declared}
    checked = _labels(result.get("verified"))
    carrier = _labels(result.get("carrier_only"))
    unverified = _labels(result.get("missing")) + _labels(result.get("unverifiable"))
    return {"status": "partial" if carrier or unverified else "checked",
            "checked": checked, "carrier_only": carrier, "unverified": unverified}


def load_verification(path=None):
    """{id: result}; a missing or corrupt file yields {} (everything reads as unchecked)."""
    try:
        with open(path or VERIFY_PATH, encoding="utf-8") as f:
            res = json.load(f)["results"]
        return {k: v for k, v in res.items() if isinstance(v, dict)}
    except Exception:                                   # noqa: BLE001 - unreadable metadata falls back to an empty dict
        return {}


def load(path=None):
    """Parse the file. Never raises: any fault returns an empty, status-less result."""
    empty = {"status": "", "by_id": {}}
    try:
        with open(path or PATH, encoding="utf-8") as f:
            doc = json.load(f)
        rows = doc["scenarios"]
        by_id = {}
        for r in rows:
            if isinstance(r, dict) and isinstance(r.get("id"), str):
                by_id[r["id"]] = r
        return {"status": str(doc.get("status", "")), "by_id": by_id}
    except Exception:                                   # noqa: BLE001 - malformed or missing: degrade
        return empty


def _data():
    global _cache
    with _lock:
        if _cache is None:
            _cache = load()
        return _cache


def scale_profile(row, anchors, tolerance=1.03):
    """{"behaviour": "fixed"|"scales", "points": [[scale, packets, bytes], ...]} from one measured row, or None.
    A scenario is "fixed" when its own packet count is within `tolerance` of itself at every anchor scale."""
    try:
        pk, by = row["packets"], row["bytes"]
        if row.get("errors") or None in pk or None in by or len(pk) != len(anchors) or not all(pk):
            return None
        return {"behaviour": "fixed" if max(pk) <= min(pk) * tolerance else "scales",
                "points": [[a, p, b] for a, p, b in zip(anchors, pk, by, strict=False)]}
    except (KeyError, TypeError):
        return None


def load_scale(path=None):
    """{scenario id: scale profile}; {} when the file is missing or unreadable."""
    try:
        with open(path or SCALE_PATH, encoding="utf-8") as f:
            d = json.load(f)
        anchors = d["anchors"]
        return {n: p for n, p in ((n, scale_profile(r, anchors)) for n, r in d["scenarios"].items()) if p}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def reset():
    """Drop the cache (tests)."""
    global _cache, _vcache, _scache
    with _lock:
        _cache = _vcache = _scache = None


def get(scenario_id):
    """The public metadata object for a scenario id, or None if it has no entry."""
    e = _data()["by_id"].get(scenario_id)
    if e is None:
        return None
    global _vcache, _scache
    with _lock:
        if _vcache is None:
            _vcache = load_verification()
        if _scache is None:
            _scache = load_scale()
        res = _vcache.get(scenario_id)
        prof = _scache.get(scenario_id)
    out = {k: e[k] for k in PUBLIC_FIELDS if k in e}
    out["protocols_check"] = protocols_check(e, res)
    if prof:
        out["scale"] = prof
    return out


def ids():
    return list(_data()["by_id"])


def status():
    return _data()["status"]


def taxonomy():
    """Ordered category list per family (a fresh copy)."""
    return {k: list(v) for k, v in TAXONOMY.items()}

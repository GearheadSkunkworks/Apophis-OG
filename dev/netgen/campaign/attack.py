"""Bundled MITRE ATT&CK Enterprise catalog (offline).

``attack.json`` is distilled from the official STIX bundle (attack-stix-data, enterprise-attack.json) with
revoked and deprecated objects removed; its ``meta`` block records the ATT&CK version and source. Nothing here
touches the network. Only standard library.
"""
import json
import os
import re
from functools import lru_cache

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack.json")
TID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@lru_cache(maxsize=1)
def _data():
    with open(_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def meta():
    """Catalog metadata: matrix, attack_version, source, counts."""
    return dict(_data()["meta"])


def tactics():
    """Ordered kill-chain tactics: [{"slug","name","id"}]."""
    return [dict(t) for t in _data()["tactics"]]


def _tactic_map():
    return {t["slug"]: t for t in _data()["tactics"]}


def tactic(slug):
    """One tactic by slug (or by id such as TA0002) or None."""
    if not isinstance(slug, str):
        return None
    m = _tactic_map()
    if slug in m:
        return dict(m[slug])
    for t in m.values():
        if t["id"] == slug.upper():
            return dict(t)
    return None


def technique(tid):
    """{"id","name","tactic","tactics"} for a technique/sub-technique id, or None. ``tactic`` is the first one."""
    if not isinstance(tid, str):
        return None
    tid = tid.strip().upper()
    t = _data()["techniques"].get(tid)
    if not t:
        return None
    tac = list(t["tactics"])
    return {"id": tid, "name": t["name"], "tactic": tac[0] if tac else None, "tactics": tac}


def tactic_for(tid, prefer=None):
    """Tactic slug for a technique. ``prefer`` wins when the technique belongs to it; otherwise the first."""
    t = technique(tid)
    if not t:
        return None
    if prefer and prefer in t["tactics"]:
        return prefer
    return t["tactic"]


def validate_ids(ids):
    """List of error strings for unknown or malformed technique ids (empty list = all good)."""
    errs = []
    if not isinstance(ids, (list, tuple)):
        return ["technique ids must be a list"]
    for tid in ids:
        if not isinstance(tid, str) or not TID_RE.match(tid):
            errs.append("malformed technique id %r" % (tid if isinstance(tid, str) and len(tid) < 40 else "<?>"))
        elif technique(tid) is None:
            errs.append("unknown ATT&CK technique %s" % tid)
    return errs


def navigator_layer(techniques, name="OpenGenerator campaign", comment=""):
    """ATT&CK Navigator layer (layer format 4.5) as a dict.

    ``techniques`` is a list of ids or dicts {"id"|"techniqueID", "comment", "score", "tactic"}. Unknown ids are
    skipped. Without a tactic the entry applies to every tactic the technique belongs to.
    """
    out, seen = [], set()
    for item in techniques or []:
        if isinstance(item, str):
            item = {"id": item}
        if not isinstance(item, dict):
            continue
        tid = str(item.get("id") or item.get("techniqueID") or "").upper()
        info = technique(tid)
        key = (tid, item.get("tactic"))
        if not info or key in seen:
            continue
        seen.add(key)
        e = {"techniqueID": tid, "color": "#e8603c", "comment": str(item.get("comment", "")),
             "enabled": True, "score": int(item.get("score", 1))}
        if item.get("tactic"):
            e["tactic"] = item["tactic"]
        out.append(e)
    ver = str(meta().get("attack_version") or "")
    return {
        "name": str(name), "versions": {"attack": ver.split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack", "description": str(comment),
        "filters": {"platforms": ["Linux", "macOS", "Windows", "Network", "PRE", "Containers",
                                  "IaaS", "SaaS", "Office Suite", "Identity Provider"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False, "techniques": out, "gradient": {"colors": ["#ffffff", "#e8603c"], "minValue": 0, "maxValue": 1},
        "legendItems": [], "metadata": [], "links": [], "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd", "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False, "selectVisibleTechniques": False,
    }

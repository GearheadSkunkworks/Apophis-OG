"""Campaign feedback scoring: which of a campaign's actions did the sensor notice?

Pure functions, no I/O. ``score()`` takes the campaign report entries (what ran and when),
the indicator table, the campaign's expectations and the raw detection records a sensor
returned, and says per technique and per action whether a detection matched it.

The detection record shape is documented for the platform's REST API but has not been
checked against a live sensor by this project, so every field is read defensively: a missing
or oddly-typed field never raises, it just contributes nothing to a match.

Matching (see docs/campaign-m4-contracts.md section 2): a detection matches an entry when its
time span overlaps the entry's window (first/last packet widened by ``slack_s`` and shifted
by ``offset_s``) and it shares a technique (equal, parent or sub-technique) with the entry or
a participant address with the entry's hosts or indicators. A technique is ``detected`` when
a matched detection carries it, ``related`` when detections matched the same actions without
carrying it, and ``missed`` otherwise. CVE expectations are not testable and are only counted.
"""
import re

_TID = re.compile(r"T\d{4}(?:\.\d{3})?", re.I)
_SECONDS_BELOW = 1e11            # a time value below this is epoch seconds, not milliseconds


# ---------------------------------------------------------------- small coercions
def _num(v):
    """A float from a number or numeric string; None for anything else (bool included)."""
    if isinstance(v, bool) or v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def _to_ms(v):
    """Epoch milliseconds from a value that may be seconds (below 1e11) or milliseconds."""
    f = _num(v)
    if f is None or f < 0:
        return None
    return f * 1000.0 if f < _SECONDS_BELOW else f


def _to_s(v):
    ms = _to_ms(v)
    return None if ms is None else ms / 1000.0


def _list(v):
    return v if isinstance(v, list) else []


def _tid(v):
    """A normalised technique id (``T1071.001``) from a string or ``{"id": ...}``, else None."""
    if isinstance(v, dict):
        v = v.get("id") or v.get("technique_id") or v.get("name")
    if not isinstance(v, str):
        return None
    m = _TID.search(v)
    return m.group(0).upper() if m else None


def _slug(v):
    """A tactic as a lower-case hyphenated slug ('Command and Control' -> 'command-and-control')."""
    if isinstance(v, dict):
        v = v.get("name") or v.get("id")
    if not isinstance(v, str):
        return None
    s = re.sub(r"[^a-z0-9]+", "-", v.strip().lower()).strip("-")
    return s or None


def _related(a, b):
    """True when two technique ids are equal, or one is the parent of the other."""
    if not a or not b:
        return False
    if a == b:
        return True
    pa, pb = a.split(".")[0], b.split(".")[0]
    return pa == pb and ("." not in a or "." not in b)


def _pct(detected, partial, testable):
    if testable <= 0:
        return 0
    return int((detected + 0.5 * partial) * 100.0 / testable + 0.5)


# ---------------------------------------------------------------- detections
def normalise_detection(d):
    """The neutral form of one raw detection record (never raises; ``None`` if not a dict)."""
    if not isinstance(d, dict):
        return None
    techs, seen = [], set()
    for t in _list(d.get("mitre_techniques")):
        t = _tid(t)
        if t and t not in seen:
            seen.add(t)
            techs.append(t)
    tactics = []
    for t in _list(d.get("mitre_tactics")):
        t = _slug(t)
        if t and t not in tactics:
            tactics.append(t)
    parts = []
    for p in _list(d.get("participants")):
        ip = p.get("ipaddr") if isinstance(p, dict) else p
        if isinstance(ip, str) and ip.strip() and ip.strip() not in parts:
            parts.append(ip.strip())
    start = _to_ms(d.get("start_time"))
    end = _to_ms(d.get("end_time"))
    if start is None:
        start = end if end is not None else _to_ms(d.get("update_time"))
    if end is None:
        end = start
    if start is not None and end is not None and end < start:
        start, end = end, start
    risk = _num(d.get("risk_score"))
    return {
        "id": d.get("id"),
        "title": str(d.get("title") or d.get("type") or "")[:200],
        "type": str(d.get("type") or "")[:100],
        "categories": [str(c) for c in _list(d.get("categories")) if isinstance(c, str)][:20],
        "risk": int(risk) if risk is not None else 0,
        "start_ms": None if start is None else int(start),
        "end_ms": None if end is None else int(end),
        "techniques": techs,
        "tactics": tactics,
        "participants": parts,
        "matched": False,
        "matched_actions": [],
    }


def _technique_names(raw):
    """{technique id: name} for the names the detections themselves carry."""
    out = {}
    for d in raw:
        if isinstance(d, dict):
            for t in _list(d.get("mitre_techniques")):
                if isinstance(t, dict) and isinstance(t.get("name"), str):
                    tid = _tid(t)
                    if tid and tid not in out:
                        out[tid] = t["name"][:120]
    return out


def _catalog(tid):
    """(name, tactic slug) from the bundled ATT&CK table, or (None, None). Local data only."""
    try:
        from netgen.campaign import attack
        t = attack.technique(tid)
        return (t["name"], t["tactic"]) if t else (None, None)
    except Exception:                                                # noqa: BLE001 -- names are optional
        return None, None


# ---------------------------------------------------------------- the window to ask for
def query_window(entries, offset_s=0, slack_s=600, lookahead_s=1800):
    """``(from_ms, until_ms)`` covering every ok entry, or None when no ok entry has a time.

    ``slack_s`` widens both ends; ``lookahead_s`` extends the end further, because the
    platform's machine-learning detections arrive minutes after the traffic."""
    lo = hi = None
    for e in _list(entries):
        if not isinstance(e, dict) or e.get("status") != "ok":
            continue
        a = _to_s(e.get("first_ts") if e.get("first_ts") is not None else e.get("ts"))
        b = _to_s(e.get("last_ts") if e.get("last_ts") is not None else e.get("ts"))
        if a is None and b is None:
            continue
        a = b if a is None else a
        b = a if b is None else b
        lo = a if lo is None else min(lo, a)
        hi = b if hi is None else max(hi, b)
    if lo is None:
        return None
    off = _num(offset_s) or 0.0
    slack = max(0.0, _num(slack_s) or 0.0)
    look = max(0.0, _num(lookahead_s) or 0.0)
    return (int(max(0.0, lo + off - slack) * 1000), int((hi + off + slack + look) * 1000))


# ---------------------------------------------------------------- the score
def _entry_view(i, e, iocs, offset, slack):
    """What matching needs from one entry: window (ms), techniques, addresses."""
    first = _to_s(e.get("first_ts") if e.get("first_ts") is not None else e.get("ts"))
    last = _to_s(e.get("last_ts") if e.get("last_ts") is not None else e.get("ts"))
    if first is None:
        first = last
    if last is None:
        last = first
    win = None
    if first is not None:
        win = ((first + offset - slack) * 1000.0, (last + offset + slack) * 1000.0)
    techs = []
    for t in _list(e.get("techniques")):
        t = _tid(t)
        if t and t not in techs:
            techs.append(t)
    addrs = set()
    for h in (e.get("from_host"), e.get("to_host")):
        ip = h.get("ip") if isinstance(h, dict) else None
        if isinstance(ip, str) and ip.strip():
            addrs.add(ip.strip())
    for ix in _list(e.get("ioc")):
        if isinstance(ix, bool) or not isinstance(ix, int):
            continue
        row = None
        for r in iocs:
            if isinstance(r, dict) and r.get("index") == ix:
                row = r
                break
        if row is None and 0 <= ix < len(iocs) and isinstance(iocs[ix], dict) \
                and iocs[ix].get("index") is None:
            row = iocs[ix]
        a = row.get("address") if isinstance(row, dict) else None
        if isinstance(a, str) and a.strip():
            addrs.add(a.strip())
    return {"i": i, "ok": e.get("status") == "ok", "win": win, "techs": techs, "addrs": addrs,
            "stage": e.get("stage"), "action": e.get("action"), "ts": e.get("ts")}


def _overlaps(win, det):
    if win is None or det["start_ms"] is None:
        return False
    return det["start_ms"] <= win[1] and det["end_ms"] >= win[0]


def _relation(view, det):
    """'technique', 'participant' or None for one detection against one ok entry."""
    if not view["ok"] or not _overlaps(view["win"], det):
        return None
    for a in view["techs"]:
        for b in det["techniques"]:
            if _related(a, b):
                return "technique"
    if view["addrs"] and view["addrs"].intersection(det["participants"]):
        return "participant"
    return None


def score(entries, iocs, expect, stages, detections, offset_s=0, slack_s=600, min_risk=0):
    """Score a campaign report against raw detections; returns the body of the feedback response
    without ``ok`` and ``window`` (the route adds those). Never raises on odd input."""
    entries = [e if isinstance(e, dict) else {} for e in _list(entries)]
    iocs = _list(iocs)
    off = _num(offset_s) or 0.0
    slack = max(0.0, _num(slack_s) or 0.0)
    floor = _num(min_risk) or 0.0

    raw = [d for d in _list(detections) if isinstance(d, dict)]
    names = _technique_names(raw)
    dets = [normalise_detection(d) for d in raw]
    below = [d for d in dets if d["risk"] < floor]
    dets = [d for d in dets if d["risk"] >= floor]

    views = [_entry_view(i, e, iocs, off, slack) for i, e in enumerate(entries)]
    # rel[(entry index, detection index)] -> 'technique' | 'participant'
    rel = {}
    for v in views:
        for j, d in enumerate(dets):
            r = _relation(v, d)
            if r:
                rel[(v["i"], j)] = r
                d["matched"] = True
                d["matched_actions"].append(v["i"])

    # ---- stages and the testable techniques
    stage_info = {}
    for s in _list(stages):
        if isinstance(s, dict) and s.get("id") is not None:
            stage_info[str(s["id"])] = s
    ok_by_stage = {}
    for v in views:
        if v["ok"] and v["stage"] is not None:
            ok_by_stage.setdefault(str(v["stage"]), []).append(v["i"])

    # technique id -> entry indexes that exercise it, in first-seen order
    testable = {}
    for v in views:
        if v["ok"]:
            for t in v["techs"]:
                testable.setdefault(t, [])
                if v["i"] not in testable[t]:
                    testable[t].append(v["i"])
    cves = set()
    for x in _list(expect):
        if not isinstance(x, dict):
            continue
        if x.get("cve"):
            cves.add(str(x["cve"]).strip().upper())
            continue
        t = _tid(x.get("technique"))
        sid = x.get("stage")
        if not t or sid is None or str(sid) not in ok_by_stage:
            continue
        testable.setdefault(t, [])
        for i in ok_by_stage[str(sid)]:
            if i not in testable[t]:
                testable[t].append(i)

    # ---- per technique
    techniques, tally = [], {}
    for t, idxs in testable.items():
        hit, rel_only = set(), set()
        for j, d in enumerate(dets):
            via = [i for i in idxs if (i, j) in rel]
            if not via:
                continue
            if any(_related(t, x) for x in d["techniques"]):
                hit.add(j)
            else:
                rel_only.add(j)
        status = "detected" if hit else ("related" if rel_only else "missed")
        sids, acts = [], []
        for i in idxs:
            sid = views[i]["stage"]
            if sid is not None and str(sid) not in sids:
                sids.append(str(sid))
            a = views[i]["action"]
            if isinstance(a, str) and a not in acts:
                acts.append(a)
        cname, ctac = _catalog(t)
        tactic = None
        for sid in sids:
            tactic = _slug((stage_info.get(sid) or {}).get("tactic"))
            if tactic:
                break
        tactic = tactic or ctac
        if not tactic:
            for j in sorted(hit | rel_only):
                if dets[j]["tactics"]:
                    tactic = dets[j]["tactics"][0]
                    break
        tactic = tactic or "unknown"
        ids = [dets[j]["id"] for j in sorted(hit or rel_only)]
        if status == "detected":
            note = "%d detection(s) carried this technique during the action window." % len(hit)
        elif status == "related":
            note = ("%d detection(s) matched the same action by time and host, but none carried "
                    "this technique." % len(rel_only))
        else:
            note = "no detection matched this technique's action window."
        techniques.append({"technique": t, "name": cname or names.get(t, ""), "tactic": tactic,
                           "status": status, "stages": sids, "actions": acts,
                           "detections": ids, "note": note})
        b = tally.setdefault(tactic, {"testable": 0, "detected": 0, "partial": 0})
        b["testable"] += 1
        if status == "detected":
            b["detected"] += 1
        elif status == "related":
            b["partial"] += 1

    n_det = sum(1 for x in techniques if x["status"] == "detected")
    n_rel = sum(1 for x in techniques if x["status"] == "related")
    n_all = len(techniques)

    # ---- per action
    actions = []
    for v in views:
        if not v["ok"]:
            st, ids = "not_run", []
        else:
            js = [j for j in range(len(dets)) if (v["i"], j) in rel]
            kinds = {rel[(v["i"], j)] for j in js}
            st = "detected" if "technique" in kinds else ("related" if js else "missed")
            ids = [dets[j]["id"] for j in js]
        actions.append({"stage": v["stage"], "action": v["action"], "ts": v["ts"],
                        "status": st, "detections": ids})

    return {
        "count": len(dets),
        "score": {
            "testable": n_all, "detected": n_det, "partial": n_rel, "missed": n_all - n_det - n_rel,
            "percent": _pct(n_det, n_rel, n_all),
            "by_tactic": {k: {"testable": b["testable"], "detected": b["detected"],
                              "partial": b["partial"],
                              "percent": _pct(b["detected"], b["partial"], b["testable"])}
                          for k, b in sorted(tally.items())},
        },
        "techniques": techniques,
        "actions": actions,
        "vulnerabilities": {"count": len(cves),
                            "note": "carried as expectations; no traffic exercises a CVE"},
        "detections": dets,
        "unmatched": sum(1 for d in dets if not d["matched"]),
        "below_min_risk": len(below),
    }

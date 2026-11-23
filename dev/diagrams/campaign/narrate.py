"""Deterministic plain-language sentences for a campaign view (3 to 5, each traced to stages or actions).

`plain(view) -> [{"text": str, "refs": [stage ids]}]`. Templates only: every clause comes from the stage name,
the tactic title, the action's own summary or the totals, so nothing is said that the data does not support.
"""


def _dur(sec):
    sec = float(sec or 0)
    if sec < 90:
        return "%d seconds" % round(sec)
    if sec < 5400:
        return "about %d minutes" % round(sec / 60.0)
    return "about %.1f hours" % (sec / 3600.0)


def _lower(s):
    s = (s or "").strip().rstrip(".")
    return s[:1].lower() + s[1:] if s and not s[:2].isupper() else s


def _first_lower(s):
    return s[:1].lower() + s[1:] if len(s) > 1 and s[1].islower() else s


def _n(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def _node(view, nid):
    return next((n for n in view["nodes"] if n["id"] == nid), None)


def _stage_sentence(view, st):
    acts = [view["actions"][i] for i in st["action_idx"]]
    tactic = st["tactic_title"] or st["tactic"] or "unclassified"
    if not acts:
        return "The %s stage, %s, carries no traffic." % (tactic.lower(), st["name"])
    a = acts[0]
    s, d = _node(view, a["src"]), _node(view, a["dst"])
    where = st["name"] if str(st["name"]).strip().lower() == tactic.lower() else "%s (%s)" % (st["name"], tactic.lower())
    lead = "In %s the %s goes from %s to %s" % (
        where, _first_lower(a["title"]), (s or {}).get("label", a["src"]), (d or {}).get("label", a["dst"]))
    body = _lower(a["plain"] or a["summary"])
    more = len(acts) - 1
    tail = "; %s follow%s" % (_n(more, "more action"), "s" if more == 1 else "") if more else ""
    return "%s: %s%s." % (lead, body, tail) if body else "%s%s." % (lead, tail)


def plain(view):
    t, m = view["totals"], view["meta"]
    stages = view["stages"]
    out = []
    # 1. overview
    if not stages:
        txt = "%s carries no stages." % m["name"]
        if view["vulns"]:
            txt = "%s carries %s as expectations and sends no traffic." % (m["name"], _n(len(view["vulns"]), "vulnerability"))
        return [{"text": txt, "refs": []}]
    who = " attributed to %s" % m["actor"] if m.get("actor") and m["actor"].lower() != "unattributed" else ""
    over = "%s is a %d-stage, %d-action campaign%s" % (m["name"], t["stages"], t["actions"], who)
    if view["mode"] == "plan":
        over += ", planned over %s" % _dur(t["duration_s"])
    else:
        ran = sum(1 for a in view["actions"] if a["status"] == "ok")
        over += "; %d of %d actions emitted %s packets over %s" % (ran, t["actions"], format(t["packets"] or 0, ","), _dur(t["duration_s"]))
    if view["iocs"]:
        over += ", carrying %s" % _n(len(view["iocs"]), "indicator")
    out.append({"text": over + ".", "refs": [s["id"] for s in stages]})
    # 2-4. up to three representative stages: first, busiest middle, last
    pick = [stages[0]]
    if len(stages) > 2:
        mid = max(stages[1:-1], key=lambda s: (len(s["action_idx"]), -stages.index(s)))
        pick.append(mid)
    if len(stages) > 1:
        pick.append(stages[-1])
    for st in pick:
        out.append({"text": _stage_sentence(view, st), "refs": [st["id"]]})
    # 5. coverage
    tech = view["techniques"]
    tactics = sorted({x["tactic"] for x in tech if x["tactic"]})
    if tech:
        txt = "It touches %s across %s." % (_n(len(tech), "ATT&CK technique"), _n(len(tactics), "tactic"))
        if view["mode"] == "scored" and view.get("score"):
            sc = view["score"]
            txt += " The sensor detected %s of %s testable techniques." % (sc.get("detected", 0), sc.get("testable", 0))
        out.append({"text": txt, "refs": sorted({r for x in tech for r in x["stages"]})})
    return out[:5]

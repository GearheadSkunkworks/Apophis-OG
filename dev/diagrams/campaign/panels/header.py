"""Header panel: mode badge, banner text and the KPI strip. Always applies."""
from . import esc, fmt_dur, fmt_int


def render(view, ctx):
    t, mode, opts = view["totals"], view["mode"], view["options"]
    run = mode != "plan"
    kpis = [(fmt_int(t["stages"]), "Stages"), (fmt_int(t["actions"]), "Actions")]
    if run:
        kpis.append((fmt_int(t["packets"]), "Packets"))
    else:
        kpis.append(("~" + fmt_int(t["flows"]) if t.get("flows") is not None else "n/a", "Est. flows"))
    kpis += [(fmt_dur(t["duration_s"]) if t["stages"] else "n/a", "Duration" if run else "Planned duration"),
             (fmt_int(t["indicators_used"]), "Indicators used"), (fmt_int(t["techniques"]), "Techniques")]
    if mode == "scored" and view.get("score") and view["score"].get("percent") is not None:
        kpis.append(("%s%%" % view["score"]["percent"], "Detected"))
    kpis.append((opts.get("address_mode", "mapped").capitalize(), "Addressing"))
    if mode == "plan":
        badge, text = "Plan", "Plan: nothing has been generated yet."
    elif mode == "run":
        badge, text = "Run", "Run: from this capture."
    else:
        badge = "Scored"
        sa = view.get("scored_against") or {}
        bits = [str(sa[k]) for k in ("sensor", "time") if sa.get(k)]
        text = "Scored against %s; read-only." % (", ".join(bits) if bits else "the sensor")
    sub = view["meta"]["description"] or text
    banner = '<div class="cd-banner %s">%s</div>' % (esc(mode), esc(text))
    return {"id": "header", "title": view["meta"]["name"], "sub": sub, "svg": None, "html": banner, "height": 0,
            "alt": [], "kpis": kpis, "badge": badge, "banner": text}

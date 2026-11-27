"""Stage cards: one card per stage with its actions; a summary table above 12 stages."""
from . import (esc, fmt_dur, fmt_int, node_label, tactic_colour, when)

CARD_LIMIT = 12


def _defaults(token):
    try:
        from netgen.campaign import actions as A
        return {k: d.get("default") for k, d in A.get(token).params.items()}
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to None
        return None


def _key_params(a):
    d = _defaults(a["action"])
    items = [(k, v) for k, v in a["params"].items() if not isinstance(v, (dict,)) and
             (d is None or d.get(k) != v) and v not in ("", None)]
    if d is None:
        items = items[:3]
    out = []
    for k, v in items[:4]:
        if isinstance(v, list):
            v = ",".join(str(x) for x in v[:6]) + ("..." if len(v) > 6 else "")
        out.append("%s=%s" % (k, v))
    return ", ".join(out) or "defaults"


def _badge(st):
    return '<span class="cd-badge" style="background:%s">%s</span>' % (
        esc(tactic_colour(st["tactic"])), esc(st["tactic_title"] or st["tactic"] or "stage"))


_STATE = {"planned": "planned", "ok": "ran", "partial": "partly ran", "skipped": "did not run"}


def _summary_table(view):
    run = view["mode"] != "plan"
    rows = ""
    for n, st in enumerate(view["stages"], 1):
        acts = [view["actions"][i] for i in st["action_idx"]]
        pk = ("<td>%s</td>" % fmt_int(sum(a["packets"] or 0 for a in acts))) if run else ""
        rows += ('<tr><td>%d</td><td><b>%s</b></td><td>%s</td><td>%d</td><td class="m">%s</td><td>%s</td>'
                 '<td class="svc">%s</td>%s<td class="svc">%s</td></tr>'
                 % (n, esc(st["name"]), _badge(st), len(acts), esc(when(view, st["start_s"])),
                    esc(fmt_dur(st["end_s"] - st["start_s"])), esc(", ".join(st["techniques"][:4]) or "-"), pk,
                    esc(_STATE.get(st["state"], st["state"]))))
    return ('<table><thead><tr><th>#</th><th>Stage</th><th>Tactic</th><th>Actions</th><th>%s</th><th>Length</th>'
            '<th>Techniques</th>%s<th>State</th></tr></thead><tbody>%s</tbody></table>'
            % ("Clock" if run else "Offset", "<th>Packets</th>" if run else "", rows))


def _card(view, st):
    run = view["mode"] != "plan"
    rows = ""
    for i in st["action_idx"]:
        a = view["actions"][i]
        flag = "" if a["status"] in ("planned", "ok") else '<span class="cd-flag">%s</span>' % esc(a["status"])
        pk = "<td>%s</td>" % ("n/a" if a["packets"] is None else fmt_int(a["packets"])) if run else ""
        wire = a["wire"] or ", ".join(a["protocols"]) or "-"
        rows += ('<tr><td>%s%s</td><td>%s</td><td>%s</td><td class="cd-w">%s</td><td class="cd-w svc">%s</td>%s</tr>'
                 % (esc(a["title"]), flag, esc(node_label(view, a["src"])), esc(node_label(view, a["dst"])),
                    esc(wire), esc(_key_params(a)), pk))
        if a["error"]:
            rows += '<tr><td colspan="%d" class="svc">%s</td></tr>' % (6 if run else 5, esc(a["error"]))
    table = ('<table><thead><tr><th>Action</th><th>From</th><th>To</th><th>On the wire</th><th>Key parameters</th>%s'
             '</tr></thead><tbody>%s</tbody></table>' % ("<th>Packets</th>" if run else "", rows)) if rows else ""
    nar = '<div class="nar">%s</div>' % esc(st["narrative"]) if st["narrative"] else ""
    techs = '<span class="svc" style="font-size:10px">%s</span>' % esc(", ".join(st["techniques"])) if st["techniques"] else ""
    return ('<div class="cd-card"><header>%s<h3>%s</h3>%s<span class="cd-state %s">%s &middot; %s</span></header>%s%s</div>'
            % (_badge(st), esc(st["name"]), techs, esc(st["state"]), esc(_STATE.get(st["state"], st["state"])),
               esc(when(view, st["start_s"])), nar, table))


def render(view, ctx):
    if not view["stages"] or not view["actions"]:
        return None
    if len(view["stages"]) > CARD_LIMIT:
        return {"id": "stages", "title": "Stages", "sub": "%d stages: summary table (cards appear at %d or fewer)"
                % (len(view["stages"]), CARD_LIMIT), "svg": None, "html": _summary_table(view), "height": 0, "alt": []}
    return {"id": "stages", "title": "Stages", "sub": "What each stage does, between which hosts, and what is on the wire",
            "svg": None, "html": "".join(_card(view, s) for s in view["stages"]), "height": 0, "alt": []}

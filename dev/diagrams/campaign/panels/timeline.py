"""Timeline: stage bands on the schedule, action ticks, and beacon cadence strips.

Run and scored pages label the axis with clock time (the start option plus the planned offset); plan pages label
it with offsets only. Above 24 stages the rows group consecutive stages of one tactic. Omitted when the campaign
has no stages with actions."""
import make_diagram as MD
from . import (GRAY, SAPPHIRE, clock, esc, fmt_dur, fmt_off, tactic_colour, trunc)

W = 1180
L, R = 190, 1160
PITCH = 30
MAX_ROWS = 24
_STEPS = [5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400]


def _rows(view):
    stages = view["stages"]
    rows = [{"label": s["name"], "sub": s["tactic_title"] or s["tactic"] or "", "start": s["start_s"], "end": s["end_s"],
             "tactic": s["tactic"], "idx": list(s["action_idx"]), "state": s["state"], "n": 1} for s in stages]
    if len(rows) <= MAX_ROWS:
        return rows
    groups = []
    for r in rows:                                   # merge neighbours that share a tactic
        if groups and groups[-1]["tactic"] == r["tactic"]:
            g = groups[-1]
            g["end"], g["n"] = r["end"], g["n"] + 1
            g["idx"] += r["idx"]
            g["state"] = g["state"] if g["state"] == r["state"] else "partial"
        else:
            groups.append(dict(r))
    while len(groups) > MAX_ROWS:                    # still too many: chunk evenly
        k = -(-len(groups) // MAX_ROWS)
        merged = []
        for i in range(0, len(groups), k):
            ch = groups[i:i + k]
            merged.append({"label": "", "sub": "mixed tactics", "start": ch[0]["start"], "end": ch[-1]["end"],
                           "tactic": ch[0]["tactic"], "idx": [x for c in ch for x in c["idx"]],
                           "state": "partial" if len({c["state"] for c in ch}) > 1 else ch[0]["state"],
                           "n": sum(c["n"] for c in ch)})
        groups = merged
    for g in groups:
        if g["n"] > 1:
            g["label"] = "%d stages" % g["n"] if not g["label"] or g["sub"] != "mixed tactics" else "%d stages" % g["n"]
    return groups


def render(view, ctx):
    if not view["stages"] or not view["actions"]:
        return None
    rows = _rows(view)
    run = view["mode"] != "plan"
    start = view["options"].get("start")
    span = max([r["end"] for r in rows] + [view["actions"][i]["offset_s"] + (view["actions"][i]["dur_s"] or 0)
                                             for r in rows for i in r["idx"]] + [1.0])
    step = next((s for s in _STEPS if span / s <= 10), _STEPS[-1])
    X = lambda sec: L + (R - L) * min(1.0, max(0.0, sec / span))
    H = 66 + len(rows) * PITCH + 8
    P = []
    A = P.append
    A(MD._svg_open(W, H, "Timeline of %d stages over %s" % (len(view["stages"]), fmt_dur(view["totals"]["duration_s"]))))
    MD._panel_title(A, 14, 8, "", ("Clock time from the start option" if run else "Planned offsets from the start")
                    + "; bands are stages, ticks are actions, thin lines are beacon cadence")
    ay = 52
    A('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#d5d6dc" stroke-width="1.4"/>' % (L, ay, R, ay))
    t = 0
    while t <= span + 1e-6:
        x = X(t)
        lab = clock(start, t)[:5] if (run and step >= 60) else (clock(start, t) if run else fmt_off(t))
        A('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="#c9cad0"/>' % (x, ay - 4, x, ay + 4))
        A('<text x="%.1f" y="%d" text-anchor="middle" font-size="9" fill="%s">%s</text>' % (x, ay - 8, GRAY, esc(lab)))
        t += step
    alt = []
    for n, r in enumerate(rows):
        y = 66 + n * PITCH
        col = tactic_colour(r["tactic"])
        x1, x2 = X(r["start"]), X(r["end"])
        if n % 2 == 0:
            A('<rect x="10" y="%d" width="%d" height="%d" fill="#fafafc"/>' % (y - 2, W - 20, PITCH))
        A('<text x="14" y="%d" font-size="10" font-weight="700" fill="%s">%s</text>' % (y + 11, SAPPHIRE, esc(trunc(r["label"], 168, 10))))
        sub = r["sub"] + (" - %s" % r["state"] if r["state"] not in ("planned", "ok") else "")
        A('<text x="14" y="%d" font-size="8.5" fill="%s">%s</text>' % (y + 22, GRAY, esc(trunc(sub, 168, 8.5))))
        dash = ' stroke-dasharray="4 3"' if r["state"] in ("skipped", "partial") else ""
        A('<rect x="%.1f" y="%d" width="%.1f" height="20" rx="4" fill="%s" fill-opacity="0.16" stroke="%s"%s>'
          '<title>%s</title></rect>' % (x1, y, max(4.0, x2 - x1), col, col, dash, esc(r["label"])))
        for i in r["idx"]:
            a = view["actions"][i]
            ok = a["status"] in ("planned", "ok")
            fill, stroke = (col, col) if ok else ("#ffffff", GRAY)
            p = a["params"]
            cnt, iv, jit = p.get("count"), p.get("interval_s"), p.get("jitter")
            ox = X(a["offset_s"])
            if isinstance(cnt, int) and cnt > 1 and isinstance(iv, (int, float)) and iv > 0:
                for k in range(min(cnt, 90)):
                    tx = a["offset_s"] + k * iv
                    if tx > span:
                        break
                    if isinstance(jit, (int, float)) and jit > 0:
                        j1, j2 = X(tx - jit * iv), X(tx + jit * iv)
                        if j2 - j1 > 3:
                            A('<rect x="%.1f" y="%d" width="%.1f" height="12" fill="%s" fill-opacity="0.18"/>'
                              % (j1, y + 4, j2 - j1, stroke))
                    A('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="%s" stroke-width="1.5"/>'
                      % (X(tx), y + 3, X(tx), y + 17, stroke))
            else:
                w = max(3.0, X(a["offset_s"] + (a["dur_s"] or 0)) - ox)
                A('<rect x="%.1f" y="%d" width="%.1f" height="8" rx="2" fill="%s" stroke="%s"><title>%s</title></rect>'
                  % (ox, y + 6, w, fill, stroke, esc(a["title"])))
        alt.append([r["label"], r["sub"], fmt_off(r["start"]), fmt_off(r["end"]), len(r["idx"])])
    A("</svg>")
    return {"id": "timeline", "title": "Timeline", "sub": "", "svg": "".join(P), "html": None, "height": H,
            "alt": alt, "alt_head": ["Stage", "Tactic", "Start", "End", "Actions"]}

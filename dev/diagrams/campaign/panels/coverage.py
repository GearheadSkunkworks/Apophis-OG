"""ATT&CK coverage: tactic columns with technique chips, plus a separate group for CVE expectations.

Plan pages show expected and planned techniques; run pages add emitted; scored pages colour the chips by
detected, related or missed. Omitted when the campaign has neither techniques nor vulnerabilities."""
import make_diagram as MD
from . import CYAN, GRAY, PLUM, SAPPHIRE, TANGERINE, esc, tactic_colour, trunc

W = 1180
PER_ROW = 7
CHIP_H = 34
MAX_PER_COL = 14


def _order():
    try:
        from netgen.campaign import attack
        return [(t["slug"], t["name"]) for t in attack.tactics()]
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to an empty list
        return []


def _style(view, t):
    mode = view["mode"]
    if mode == "scored":
        if t["score"] == "detected":
            return CYAN, CYAN, "#fff", "detected"
        if t["score"] == "related":
            return TANGERINE, TANGERINE, "#1c1830", "related"
        if t["score"] == "missed":
            return PLUM, PLUM, "#fff", "missed"
        return "#f1f1f4", "#c9cad0", "#4a4760", "not testable"
    if mode == "run":
        if t["emitted"]:
            return SAPPHIRE, SAPPHIRE, "#fff", "emitted"
        return "#ffffff", SAPPHIRE, "#4a4760", "expected, not emitted"
    if t["expected"]:
        return "#fdf3ea", SAPPHIRE, "#1c1830", "expected"
    return "#ffffff", GRAY, "#4a4760", "planned by an action"


def render(view, ctx):
    techs, vulns = view["techniques"], view["vulns"]
    if not techs and not vulns:
        return None
    mode = view["mode"]
    names = _order()
    known = [s for s, _ in names]
    title = dict(names)
    cols = {}
    for t in techs:
        cols.setdefault(t["tactic"] or "other", []).append(t)
    keys = [k for k in known if k in cols] + sorted(k for k in cols if k not in known)
    blocks = [keys[i:i + PER_ROW] for i in range(0, len(keys), PER_ROW)]
    ncol = min(PER_ROW, max(1, len(keys)))
    cw = (W - 28) / ncol
    H = 56
    for b in blocks:
        H += 26 + min(MAX_PER_COL + 1, max(len(cols[k]) for k in b)) * (CHIP_H + 4) + 10
    vrows = -(-len(vulns) // 6) if vulns else 0
    if vulns:
        H += 30 + vrows * (CHIP_H + 4) + 8
    P = []
    A = P.append
    A(MD._svg_open(W, H, "ATT&CK coverage: %d techniques" % len(techs)))
    sub = "%d techniques across %d tactics" % (len(techs), len(keys))
    if mode == "scored" and view.get("score") and view["score"].get("percent") is not None:
        sc = view["score"]
        sub = "%s%% coverage: %s detected, %s related, %s missed of %s testable" % (
            sc.get("percent"), sc.get("detected", 0), sc.get("partial", 0), sc.get("missed", 0), sc.get("testable", 0))
    MD._panel_title(A, 14, 14, "", sub)
    # legend
    states = {"plan": [("#fdf3ea", SAPPHIRE, "expected"), ("#ffffff", GRAY, "planned by an action")],
              "run": [(SAPPHIRE, SAPPHIRE, "emitted"), ("#ffffff", SAPPHIRE, "expected, not emitted")],
              "scored": [(CYAN, CYAN, "detected"), (TANGERINE, TANGERINE, "related"), (PLUM, PLUM, "missed"),
                         ("#f1f1f4", "#c9cad0", "not testable")]}[mode]
    lx = 760 if mode == "scored" else 880
    for fill, stroke, word in states:
        A('<rect x="%d" y="14" width="11" height="11" rx="3" fill="%s" stroke="%s"%s/>' % (
            lx, fill, stroke, ' stroke-dasharray="3 2"' if word == "expected, not emitted" else ""))
        A('<text x="%d" y="23" font-size="9" fill="%s">%s</text>' % (lx + 15, GRAY, esc(word)))
        lx += 22 + int(len(word) * 5.2)
    y = 56
    alt = []
    for b in blocks:
        for ci, k in enumerate(b):
            x = 14 + ci * cw
            col = tactic_colour(k)
            A('<text x="%.1f" y="%d" font-size="9" font-weight="700" fill="%s">%s</text>' % (
                x, y + 8, col, esc(trunc(title.get(k, k).upper(), cw - 10, 9))))
            A('<rect x="%.1f" y="%d" width="%.1f" height="2" fill="%s"/>' % (x, y + 13, cw - 8, col))
            items = cols[k]
            for ti, t in enumerate(items[:MAX_PER_COL]):
                cy = y + 20 + ti * (CHIP_H + 4)
                fill, stroke, ink, word = _style(view, t)
                dash = ' stroke-dasharray="3 2"' if word == "expected, not emitted" else ""
                A('<rect x="%.1f" y="%d" width="%.1f" height="%d" rx="5" fill="%s" stroke="%s"%s>'
                  '<title>%s</title></rect>' % (x, cy, cw - 8, CHIP_H, fill, stroke, dash,
                                                 esc("%s %s: %s" % (t["id"], t["name"], word))))
                A('<text x="%.1f" y="%d" font-size="9.5" font-weight="700" fill="%s">%s</text>' % (
                    x + 6, cy + 14, ink, esc(t["id"])))
                A('<text x="%.1f" y="%d" font-size="8.5" fill="%s">%s</text>' % (
                    x + 6, cy + 26, ink, esc(trunc(t["name"], cw - 20, 8.5))))
                alt.append([t["id"], t["name"], title.get(k, k), word])
            if len(items) > MAX_PER_COL:
                A('<text x="%.1f" y="%d" font-size="9" fill="%s">+%d more</text>' % (
                    x, y + 20 + MAX_PER_COL * (CHIP_H + 4) + 10, GRAY, len(items) - MAX_PER_COL))
                alt += [[t["id"], t["name"], title.get(k, k), _style(view, t)[3]] for t in items[MAX_PER_COL:]]
        y += 26 + min(MAX_PER_COL + 1, max(len(cols[k]) for k in b)) * (CHIP_H + 4) + 10
    if vulns:
        A('<line x1="14" y1="%d" x2="%d" y2="%d" stroke="#e4e4e8"/>' % (y - 6, W - 14, y - 6))
        A('<text x="14" y="%d" font-size="9" font-weight="700" fill="%s">EXPECTED, NO TRAFFIC</text>' % (y + 10, GRAY))
        A('<text x="170" y="%d" font-size="9" fill="%s">vulnerability identifiers carried for the coverage view; no packets exercise them</text>'
          % (y + 10, GRAY))
        vw = (W - 28) / 6
        for vi, v in enumerate(vulns):
            cx, cy = 14 + (vi % 6) * vw, y + 20 + (vi // 6) * (CHIP_H + 4)
            A('<rect x="%.1f" y="%d" width="%.1f" height="%d" rx="5" fill="#ffffff" stroke="%s" stroke-dasharray="3 2"/>'
              % (cx, cy, vw - 8, CHIP_H, GRAY))
            A('<text x="%.1f" y="%d" font-size="9.5" font-weight="700" fill="%s" font-family="ui-monospace,Menlo,monospace">%s</text>'
              % (cx + 6, cy + 14, SAPPHIRE, esc(v["cve"])))
            A('<text x="%.1f" y="%d" font-size="8.5" fill="%s">%s</text>' % (
                cx + 6, cy + 26, GRAY, esc(trunc(", ".join(v["techniques"]) or "no technique listed", vw - 20, 8.5))))
            alt.append([v["cve"], ", ".join(v["techniques"]), "expected, no traffic", ""])
    A("</svg>")
    return {"id": "coverage", "title": "ATT&CK coverage", "sub": "", "svg": "".join(P), "html": None, "height": H,
            "alt": alt, "alt_head": ["Id", "Name", "Tactic", "State"]}

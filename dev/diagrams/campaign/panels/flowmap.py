"""Flow map panel: who talks to whom, in zone columns (M4b).

Reads only the view model (contract section 3), lets ``layout.place`` position everything, and draws the result in the
house style of ``make_diagram._netflow_panel`` (white pill labels on the lanes, rounded node boxes). Omitted (None)
when the view has no flows to draw, which is the vulnerability-only form. Every dynamic string goes through ``esc``.
"""
from branding import SAPPHIRE, GRAY, MAGENTA, TANGERINE
import make_diagram as MD

from .. import layout as L

ID = "flowmap"
ZONE_STROKE = {"internet": GRAY, "perimeter": TANGERINE, "user": SAPPHIRE, "server": SAPPHIRE, "ot": MAGENTA}
LEGEND_FS = 9
_STATE_NOTE = {"plan": "Planned flows: nothing has been generated yet.",
               "run": "Flows as generated in this capture.", "scored": "Flows as generated in this capture."}


def _marker_id(color):
    return "fm" + color.lstrip("#").lower()


def _fmt_n(n):
    return "{:,}".format(n) if isinstance(n, int) else ""


def _legend(edges, has_agg):
    items = []
    if any(e["inbound"] and e["state"] not in ("failed", "skipped") for e in edges):
        items.append((L.COLOR_INBOUND, "", "inbound, from the Internet"))
    if any(not e["inbound"] and e["color"] == L.COLOR_OUT for e in edges):
        items.append((L.COLOR_OUT, "", "outbound, to the Internet"))
    if any(e["color"] == L.COLOR_INTERNAL for e in edges):
        items.append((L.COLOR_INTERNAL, "", "inside the network"))
    if any(e["state"] == "failed" for e in edges):
        items.append((L.COLOR_FAILED, "2 3", "failed"))
    if any(e["state"] == "skipped" for e in edges):
        items.append((L.COLOR_SKIPPED, "6 4", "skipped"))
    if any(e["dashed"] and e["state"] != "skipped" for e in edges):
        items.append((GRAY, "6 4", "inferred, upstream of the sensor"))
    return items


def render(view, ctx=None):
    nodes_in, edges_in = view.get("nodes") or [], view.get("edges") or []
    if not nodes_in or not edges_in:
        return None
    lay = L.place(view, width=1180, max_nodes_per_zone=8, internet="auto")
    mode = view.get("mode") or "plan"
    W = lay["width"]
    top_h = lay["height"]
    legend = _legend(lay["edges"], any(n["kind"] == "aggregate" for n in lay["nodes"].values()))
    notes = list(lay["overflow"])
    shown = notes[:3] + (["+%d more notes" % (len(notes) - 3)] if len(notes) > 3 else [])
    H = top_h + 12 + (24 if legend else 0) + 14 * len(shown)

    n_nodes, n_edges = len(lay["nodes"]), len(lay["edges"])
    label = "Flow map: %d hosts and %d flows across %s" % (n_nodes, n_edges, ", ".join(z["label"] for z in lay["zones"]))
    out = []
    A = out.append
    A(MD._svg_open(W, H, label))
    A("<title>%s</title><desc>%s</desc>" % (MD.esc(label), MD.esc(
        "Hosts grouped by network zone with one lane per protocol and port. The text table below the picture lists the same flows.")))
    colors = sorted({e["color"] for e in lay["edges"]})
    A("<defs>" + "".join(
        '<marker id="%s" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto" markerUnits="userSpaceOnUse">'
        '<path d="M0,0 L9,4.5 L0,9 Z" fill="%s"/></marker>' % (_marker_id(c), c) for c in colors) + "</defs>")

    # zone bands and headings
    for z in lay["zones"]:
        x, w = z["x"], z["w"]
        A('<rect x="%.1f" y="26" width="%.1f" height="%d" rx="10" fill="#fafafc" stroke="#e7e7ec"/>' % (
            x - 8, w + 16, top_h - 30))
        A('<text x="%.1f" y="19" font-size="10.5" font-weight="800" fill="%s">%s</text>' % (
            x - 8, SAPPHIRE, MD.esc(z["label"].upper())))

    # lanes first so nodes cover their ends
    for e in lay["edges"]:
        style = ""
        if e["state"] == "failed":
            style = ' stroke-dasharray="2 3"'
        elif e["dashed"]:
            style = ' stroke-dasharray="6 4"'
        op = ".72" if e["state"] == "planned" else ".92"
        tip = "%s to %s: %s" % (lay["nodes"][e["src"]]["title"], lay["nodes"][e["dst"]]["title"], e["text"] or e["proto"])
        A('<path d="%s" fill="none" stroke="%s" stroke-width="1.8" opacity="%s"%s marker-end="url(#%s)">'
          "<title>%s</title></path>" % (e["path"], e["color"], op, style, _marker_id(e["color"]), MD.esc(tip)))

    # nodes
    for _nid, n in lay["nodes"].items():
        stroke = ZONE_STROKE.get(n["zone"], SAPPHIRE)
        dash = ' stroke-dasharray="5 3"' if n["kind"] == "aggregate" else ""
        fill = "#f3f4f6" if n["kind"] == "external" else "#fff"
        A('<rect x="%.1f" y="%.1f" width="%.1f" height="%d" rx="9" fill="%s" stroke="%s" stroke-width="1.6"%s>'
          "<title>%s</title></rect>" % (n["x"], n["y"], n["w"], n["h"], fill, stroke, dash, MD.esc(n["title"])))
        A('<text x="%.1f" y="%.1f" font-size="10.5" font-weight="800" fill="%s">%s</text>' % (
            n["x"] + 9, n["y"] + 17, SAPPHIRE, MD.esc(n["label"])))
        if n["sub"]:
            A('<text x="%.1f" y="%.1f" font-size="8.5" fill="%s" font-family="ui-monospace,Menlo,monospace">%s</text>' % (
                n["x"] + 9, n["y"] + 31, GRAY, MD.esc(n["sub"])))

    # pill labels last
    for e in lay["edges"]:
        if not e["label"]:
            continue
        A('<rect x="%.1f" y="%.1f" width="%.1f" height="15" rx="7.5" fill="#fff" stroke="%s" stroke-opacity=".6"/>' % (
            e["lx"] - e["lw"] / 2, e["ly"] - 7.5, e["lw"], e["color"]))
        A('<text x="%.1f" y="%.1f" text-anchor="middle" font-size="8.5" font-weight="700" fill="%s">%s</text>' % (
            e["lx"], e["ly"] + 3, e["color"], MD.esc(e["label"])))

    # legend and notes
    y = top_h + 14
    if legend:
        x = 8.0
        for color, dash, text in legend:
            d = ' stroke-dasharray="%s"' % dash if dash else ""
            A('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="%s" stroke-width="2"%s/>' % (x, y, x + 24, y, color, d))
            A('<text x="%.1f" y="%d" font-size="%g" fill="%s">%s</text>' % (x + 30, y + 3, LEGEND_FS, GRAY, MD.esc(text)))
            x += 30 + len(text) * LEGEND_FS * 0.5 + 22
        y += 22
    for line in shown:
        A('<text x="8" y="%d" font-size="9" fill="%s">%s</text>' % (y, GRAY, MD.esc(line)))
        y += 14
    A("</svg>")

    alt = []
    for e in lay["edges"]:
        s, d = lay["nodes"][e["src"]], lay["nodes"][e["dst"]]
        alt.append([s["title"], d["title"], (e["text"] or e["proto"]), _fmt_n(len(e["actions"])),
                    _fmt_n(e["packets"]) if e["packets"] is not None else "", e["state"]])
    sub = "Who talks to whom, grouped by network zone. Arrows run from the host that starts the flow to the host that answers. " \
          + _STATE_NOTE.get(mode, "")
    return {"id": ID, "title": "Flow map", "sub": sub, "svg": "".join(out), "html": None, "height": H,
            "alt": alt, "alt_head": ["From", "To", "Protocol and port", "Actions", "Packets", "State"],
            "overflow": lay["overflow"]}

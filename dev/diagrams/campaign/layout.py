"""Zone layout for the campaign flow map (M4b).

``place(view, width=1180, max_nodes_per_zone=8)`` turns the view model's ``nodes`` and ``edges`` (contract section 3)
into coordinates: fixed zone columns, nodes stacked by first use then name, straight or gently curved lanes with
white pill labels. No randomness: the same view gives the same bytes.

Rules that keep it readable
* Zone columns: Internet, perimeter, user, server, OT (OT only when a node needs it). One column each.
* More than ``max_nodes_per_zone`` nodes in a zone: the surplus collapses into one "N more hosts" node (a role name
  is used when all the folded nodes share one), and edges into the folded nodes merge.
* A lane that crosses a column it does not belong to runs through the gap between two node rows, never over a node.
* Lanes between two nodes of one zone bow out into the gutter on the right of the column.
* Lanes attach at spread points along the node side so parallel lanes do not share one point.
* Pill labels are placed near the target end where lanes have fanned apart, then moved along the lane until they
  collide with no node and no other pill; a label that finds no free spot is dropped and reported in ``overflow``.
* ``internet="left"`` (default) keeps the plan's zone order, so inbound lanes run left to right and outbound ones
  right to left. ``"right"`` mirrors the columns so inbound lanes run right to left; ``"auto"`` mirrors when the
  inbound lanes outnumber the others.

Returns ``{"zones","nodes","edges","height","overflow","width"}``; see the contract for the keys of each part.
"""
import math

from branding import SAPPHIRE, PLUM, MAGENTA, GRAY, TANGERINE

ZONE_ORDER = ["internet", "perimeter", "user", "server", "ot"]
ZONE_LABEL = {"internet": "Internet", "perimeter": "Perimeter", "user": "User network",
              "server": "Server network", "ot": "OT network"}

MARGIN = 16
GUTTER = 92               # free space to the right of a column's nodes
NODE_MAX_W = 208
NODE_MIN_W = 56
NODE_H = 42
ROW_GAP = 28
TOP = 46                  # room for the zone headings
PITCH = NODE_H + ROW_GAP
MAX_EDGES = 60
BOW = 26.0                # vertical spread between parallel lanes of one node pair, at mid span
MAX_LABEL_CH = 0.55       # em per character used by the lint and by the truncation below

COLOR_INBOUND, COLOR_OUT, COLOR_INTERNAL = PLUM, SAPPHIRE, MAGENTA
COLOR_FAILED, COLOR_SKIPPED = TANGERINE, GRAY


def _fit(text, px, font):
    """Truncate `text` with an ellipsis so the lint's width estimate stays inside `px`."""
    text = str(text or "")
    n = max(3, int(px / (font * MAX_LABEL_CH)))
    return text if len(text) <= n else text[:n - 1] + "…"


def _state_rank(states):
    for s in ("ok", "failed", "skipped", "planned"):
        if s in states:
            return s
    return "planned"


def _first_use(nodes, edges):
    first = {}
    for pos, e in enumerate(edges):
        acts = e.get("actions") or []
        key = min(acts) if acts else 10 ** 6 + pos
        for end in (e.get("src"), e.get("dst")):
            if end not in first or key < first[end]:
                first[end] = key
    return first


def _aggregate(nodes_by_zone, zone, max_n, order_key, overflow):
    """Fold the surplus of one zone into a single node. Returns ({old_id: new_id}, [nodes])."""
    ordered = sorted(nodes_by_zone, key=order_key)
    if len(ordered) <= max_n:
        return {}, ordered
    keep, rest = ordered[:max_n - 1], ordered[max_n - 1:]
    roles = sorted({n.get("role") or "" for n in rest})
    hosts = sum(max(1, int(n.get("count") or 1)) for n in rest)
    role = roles[0] if len(roles) == 1 and roles[0] else ""
    label = "%d more %shosts" % (hosts, role + " " if role else "")
    agg = {"id": "agg:" + zone, "label": label, "zone": zone, "role": role or "mixed", "address": "",
           "address_kind": "none", "fqdn": "", "ioc": None, "count": hosts, "_agg": True}
    overflow.append("%s: %d nodes folded into one (%d hosts)" % (ZONE_LABEL.get(zone, zone), len(rest), hosts))
    return {n["id"]: agg["id"] for n in rest}, keep + [agg]


_TS = sorted((x / 100.0 for x in range(6, 95, 3)), key=lambda t: (abs(t - 0.72), t))


def _bez(p0, p1, p2, p3, t):
    u = 1 - t
    return (u ** 3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t ** 3 * p3[0],
            u ** 3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t ** 3 * p3[1])


def _cubic(a, b, dy=0.0):
    dx = (b[0] - a[0]) * 0.5
    return (a, (a[0] + dx, a[1] + dy), (b[0] - dx, b[1] + dy), b)


def _hit(r1, r2, pad=0.0):
    return not (r1[2] + pad <= r2[0] or r2[2] + pad <= r1[0] or r1[3] + pad <= r2[1] or r2[3] + pad <= r1[1])


def place(view, width=1180, max_nodes_per_zone=8, internet="left", max_edges=MAX_EDGES):
    overflow = []
    nodes_in = [dict(n) for n in view.get("nodes") or []]
    edges_in = [dict(e) for e in view.get("edges") or []]
    max_n = max(2, int(max_nodes_per_zone))
    ids = {n["id"] for n in nodes_in}
    first = _first_use(nodes_in, edges_in)

    def order_key(n):
        return (first.get(n["id"], 10 ** 9), str(n.get("label") or ""), str(n["id"]))

    # ------------------------------------------------------------ zones and aggregation
    by_zone = {z: [] for z in ZONE_ORDER}
    for n in nodes_in:
        z = n.get("zone") if n.get("zone") in by_zone else "server"
        n["zone"] = z
        by_zone[z].append(n)
    remap, placed = {}, {}
    for z in ZONE_ORDER:
        m, lst = _aggregate(by_zone[z], z, max_n, order_key, overflow)
        remap.update(m)
        placed[z] = lst
    node_info = {n["id"]: n for z in ZONE_ORDER for n in placed[z]}

    # ------------------------------------------------------------ merge edges after aggregation
    merged, order, folded_self = {}, [], 0
    for pos, e in enumerate(edges_in):
        s, d = remap.get(e.get("src"), e.get("src")), remap.get(e.get("dst"), e.get("dst"))
        if s not in node_info or d not in node_info:
            continue
        if s == d:
            folded_self += 1
            continue
        key = (s, d, e.get("proto") or "", e.get("port"))
        m = merged.get(key)
        if m is None:
            m = merged[key] = {"src": s, "dst": d, "proto": e.get("proto") or "", "port": e.get("port"),
                               "actions": [], "packets": None, "bytes": None, "states": set(),
                               "inferred": False, "n": 0, "pos": pos}
            order.append(key)
        m["n"] += 1
        m["actions"] += [a for a in (e.get("actions") or []) if a not in m["actions"]]
        for k in ("packets", "bytes"):
            if e.get(k) is not None:
                m[k] = (m[k] or 0) + e[k]
        m["states"].add(e.get("state") or "planned")
        m["inferred"] = m["inferred"] or bool(e.get("inferred"))
    if folded_self:
        overflow.append("%d lane(s) between hosts folded into the same node are not drawn" % folded_self)
    elist = [merged[k] for k in order]
    if len(elist) > max_edges:
        ranked = sorted(range(len(elist)), key=lambda i: (-len(elist[i]["actions"]), -(elist[i]["packets"] or 0), i))
        keep = set(ranked[:max_edges])
        overflow.append("%d lane(s) not drawn (top %d by action count shown)" % (len(elist) - max_edges, max_edges))
        elist = [e for i, e in enumerate(elist) if i in keep]

    # ------------------------------------------------------------ columns
    zones = [z for z in ZONE_ORDER if z != "ot" or placed["ot"]]
    inbound_n = sum(1 for e in elist if node_info[e["src"]]["zone"] == "internet")
    other_n = len(elist) - inbound_n
    if internet == "right" or (internet == "auto" and inbound_n > other_n):
        zones = list(reversed(zones))
    weights = {z: (1.0 if placed[z] else (0.45 if z == "perimeter" else 0.55)) for z in zones}
    avail = width - 2 * MARGIN
    tot = sum(weights.values())
    cols, x = {}, MARGIN
    for z in zones:
        cw = avail * weights[z] / tot
        w = max(NODE_MIN_W, min(NODE_MAX_W, cw - GUTTER))
        cols[z] = {"x": x, "cw": cw, "w": w, "i": len(cols)}
        x += cw
    nrows = max([len(placed[z]) for z in zones] + [1])
    height = int(TOP + nrows * PITCH + 14)

    pos_xy, out_nodes = {}, {}
    for z in zones:
        c = cols[z]
        for r, n in enumerate(placed[z]):
            ny = TOP + ROW_GAP / 2 + r * PITCH
            cnt = max(1, int(n.get("count") or 1))
            sub = n.get("address") or n.get("fqdn") or ""
            if n.get("_agg"):
                sub = "folded, see stage cards"
            elif cnt > 1:
                sub = "%d hosts" % cnt
            elif sub and n.get("address_kind") == "mapped":
                sub += " (mapped)"
            kind = "aggregate" if n.get("_agg") else ("external" if z == "internet" else "host")
            out_nodes[n["id"]] = {"x": round(c["x"], 1), "y": round(ny, 1), "w": round(c["w"], 1), "h": NODE_H,
                                  "label": _fit(n.get("label"), c["w"] - 16, 10.5),
                                  "sub": _fit(sub, c["w"] - 16, 8.5), "kind": kind, "zone": z,
                                  "title": str(n.get("label") or ""), "role": n.get("role") or "",
                                  "ioc": n.get("ioc"), "count": cnt}
            pos_xy[n["id"]] = (z, r)

    # ------------------------------------------------------------ attachment points
    def rect(nid):
        o = out_nodes[nid]
        return (o["x"], o["y"], o["x"] + o["w"], o["y"] + o["h"])

    for e in elist:
        a, b = cols[pos_xy[e["src"]][0]]["i"], cols[pos_xy[e["dst"]][0]]["i"]
        e["kind"] = "fwd" if a < b else ("back" if a > b else "same")
        e["ss"] = "left" if e["kind"] == "back" else "right"
        e["ds"] = "left" if e["kind"] == "fwd" else "right"
    attach = {}
    for i, e in enumerate(elist):
        attach.setdefault((e["src"], e["ss"]), []).append((i, "s", e["dst"]))
        attach.setdefault((e["dst"], e["ds"]), []).append((i, "d", e["src"]))
    apt = {}
    for (nid, side), lst in sorted(attach.items()):
        r = rect(nid)
        cy = (r[1] + r[3]) / 2
        lst.sort(key=lambda t: ((rect(t[2])[1] + rect(t[2])[3]) / 2, t[0]))
        n = len(lst)
        step = 0 if n == 1 else max(3.0, min(8.0, (NODE_H - 12) / (n - 1)))
        for k, (i, role, _o) in enumerate(lst):
            off = (k - (n - 1) / 2) * step
            off = max(-(NODE_H / 2 - 5), min(NODE_H / 2 - 5, off))
            apt[(i, role)] = (r[2] if side == "right" else r[0], cy + off)

    # corridor choice for lanes that cross columns
    cross = {}
    for i, e in enumerate(elist):
        if e["kind"] == "same":
            continue
        a, b = cols[pos_xy[e["src"]][0]]["i"], cols[pos_xy[e["dst"]][0]]["i"]
        lo, hi = min(a, b), max(a, b)
        ym = (apt[(i, "s")][1] + apt[(i, "d")][1]) / 2
        for k in range(lo + 1, hi):
            z = zones[k]
            nk = len(placed[z])
            if not nk:
                continue                                    # an empty column needs no corridor
            rr = min(range(nk + 1), key=lambda r_: (abs(TOP + r_ * PITCH - ym) + 30 * len(cross.get((k, r_), ())), r_))
            cross.setdefault((k, rr), []).append(i)
    corr = {}
    for (k, rr), lst in cross.items():
        n = len(lst)
        step = 0 if n == 1 else min(4.0, (ROW_GAP - 8) / (n - 1))
        for j, i in enumerate(sorted(lst)):
            corr[(i, k)] = TOP + rr * PITCH + (j - (n - 1) / 2) * step

    # lanes between one pair of nodes that run straight across bow apart so their pill labels never collide
    groups = {}
    for i, e in enumerate(elist):
        if e["kind"] != "same" and not any((i, k) in corr for k in range(len(zones))):
            groups.setdefault(frozenset((e["src"], e["dst"])), []).append(i)
    bow = {}
    for lst in groups.values():
        lst.sort(key=lambda i: (apt[(i, "s")][1] + apt[(i, "d")][1], i))
        for j, i in enumerate(lst):
            bow[i] = (j - (len(lst) - 1) / 2) * BOW

    # ------------------------------------------------------------ paths
    bulge_n = {}
    for i, e in enumerate(elist):
        S, E = apt[(i, "s")], apt[(i, "d")]
        a, b = cols[pos_xy[e["src"]][0]]["i"], cols[pos_xy[e["dst"]][0]]["i"]
        segs = []
        if e["kind"] == "same":
            zi = pos_xy[e["src"]][0]
            j = bulge_n.get(zi, 0)
            bulge_n[zi] = j + 1
            c = cols[zi]
            bmax = max(34.0, c["cw"] - c["w"] - 14)
            bl = min(bmax, 40 + 12 * j)
            segs.append(("C", S, (S[0] + bl, S[1]), (E[0] + bl, E[1]), E))
        else:
            step_dir = 1 if b > a else -1
            cur = S
            for k in range(a + step_dir, b, step_dir):
                z = zones[k]
                if not placed[z]:
                    continue
                cx0, cx1 = cols[z]["x"] - 6, cols[z]["x"] + cols[z]["w"] + 6
                yy = corr[(i, k)]
                enter, leave = ((cx0, yy), (cx1, yy)) if step_dir == 1 else ((cx1, yy), (cx0, yy))
                segs.append(("C",) + _cubic(cur, enter))
                segs.append(("L", enter, leave))
                cur = leave
            segs.append(("C",) + _cubic(cur, E, bow.get(i, 0.0) if len(segs) == 0 else 0.0))
        e["segs"] = segs
        d = "M%.1f,%.1f" % segs[0][1]
        for sg in segs:
            if sg[0] == "C":
                d += " C%.1f,%.1f %.1f,%.1f %.1f,%.1f" % (sg[2] + sg[3] + sg[4])
            else:
                d += " L%.1f,%.1f" % sg[2]
        e["path"] = d

    # ------------------------------------------------------------ labels
    node_rects = [rect(nid) for nid in out_nodes]
    placed_pills = []
    out_edges = []
    hidden = 0
    for i, e in enumerate(elist):
        label = ("%s %s" % (e["proto"], e["port"]) if e["port"] else e["proto"]).strip() or "traffic"
        if e["n"] > 1:
            label += " ×%d" % e["n"]
        st = _state_rank(e["states"])
        if st in ("failed", "skipped"):
            label += " · " + st
        lw = round(len(label) * 8.5 * MAX_LABEL_CH + 14, 1)
        lh = 15
        cand = []
        for sg in reversed(e["segs"]):
            if sg[0] == "C":
                for t in _TS:
                    cand.append(_bez(sg[1], sg[2], sg[3], sg[4], t))
            else:
                for t in (0.5, 0.35, 0.65, 0.2, 0.8):
                    p0, p1 = sg[1], sg[2]
                    cand.append((p0[0] + (p1[0] - p0[0]) * t, p0[1] + (p1[1] - p0[1]) * t))
        chosen = None
        for (px, py) in cand:
            r = (px - lw / 2, py - lh / 2, px + lw / 2, py + lh / 2)
            if r[0] < 2 or r[2] > width - 2:
                continue
            if any(_hit(r, nr, 2) for nr in node_rects) or any(_hit(r, pr, 2) for pr in placed_pills):
                continue
            chosen = (px, py, r)
            break
        src_z, dst_z = out_nodes[e["src"]]["zone"], out_nodes[e["dst"]]["zone"]
        inbound = src_z == "internet"
        if st == "failed":
            color = COLOR_FAILED
        elif st == "skipped":
            color = COLOR_SKIPPED
        elif inbound:
            color = COLOR_INBOUND
        elif dst_z == "internet":
            color = COLOR_OUT
        else:
            color = COLOR_INTERNAL
        if chosen is None:
            hidden += 1
            lx = ly = 0.0
            lw_out, text = 0.0, ""
        else:
            lx, ly = round(chosen[0], 1), round(chosen[1], 1)
            placed_pills.append(chosen[2])
            lw_out, text = lw, label
        out_edges.append({"src": e["src"], "dst": e["dst"], "path": e["path"], "label": text, "lx": lx, "ly": ly,
                          "lw": lw_out, "dashed": bool(e["inferred"] or st == "skipped"), "inbound": inbound,
                          "color": color, "state": st, "proto": e["proto"], "port": e["port"],
                          "actions": list(e["actions"]), "packets": e["packets"], "bytes": e["bytes"],
                          "count": e["n"], "text": label})

    if hidden:
        overflow.append("%d lane label(s) left off for lack of room; every lane is listed in the table below" % hidden)
    zone_out = [{"id": z, "label": ZONE_LABEL[z], "x": round(cols[z]["x"], 1), "w": round(cols[z]["w"], 1)}
                for z in zones]
    return {"zones": zone_out, "nodes": out_nodes, "edges": out_edges, "height": height, "overflow": overflow,
            "width": width}

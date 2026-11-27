"""Tests for the campaign diagram layout, the flow map panel, the lint and the fixture corpus (M4b, worker LAYOUT).
Run from dev/:  python -m unittest tests.test_diagram_layout

Layout and flow map are tested on hand-made view dicts that follow the view contract (section 3), so they do not depend on
view.py; the fixture tests use the real view builder when it is importable.
"""
import copy
import importlib
import json
import os
import re
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
sys.path.insert(0, DEV)

from diagrams.campaign import layout, lint                              # noqa: E402 - sys.path is set up before the import
from diagrams.campaign.panels import flowmap                            # noqa: E402 - sys.path is set up before the import
from netgen.campaign import schema                                      # noqa: E402 - sys.path is set up before the import

FIX = os.path.join(HERE, "fixtures", "campaigns")


# ------------------------------------------------------------------ hand-made views
def N(i, label, zone, role="", addr="", kind="mapped", count=1, fqdn=""):
    return {"id": i, "label": label, "zone": zone, "role": role, "address": addr, "address_kind": kind, "fqdn": fqdn,
            "ioc": None, "count": count}


def E(s, d, proto, port, acts, state="ok", pk=None, by=None):
    return {"src": s, "dst": d, "proto": proto, "port": port, "actions": list(acts), "packets": pk, "bytes": by,
            "state": state, "inbound": s.startswith("x")}


def view(nodes, edges, mode="run"):
    return {"mode": mode, "meta": {"name": "t"}, "nodes": nodes, "edges": edges, "actions": [], "stages": []}


def v_three():
    return view([N("ws", "Workstation EXL-WS-047", "user", "workstation", "10.10.10.147", "real"),
                 N("xc2", "cdn.sync-cdn.net", "internet", "c2", "198.19.30.203"),
                 N("dc", "Domain controller", "server", "domain controller", "10.10.20.10", "real")],
                [E("ws", "xc2", "TLS", 443, [0, 1], pk=120, by=40000), E("ws", "dc", "Kerberos", 88, [2]), E("ws", "dc", "SMB", 445, [3])])


def v_external(n=40):
    nodes = [N("ws", "EXL-WS-047", "user", "workstation", "10.10.10.147", "real")]
    edges = []
    for i in range(n):
        nodes.append(N("x%d" % i, "indicator-%02d.example-feed.net" % i, "internet", "c2", "198.18.%d.%d" % (i, i + 3)))
        edges.append(E("ws", "x%d" % i, "TLS" if i % 3 else "DNS", 443 if i % 3 else 53, [i]))
    return view(nodes, edges)


def v_inbound():
    nodes = [N("xs1", "scanner 45.88.4.21", "internet", "scanner", "198.18.1.2"), N("xs2", "scanner 91.201.14.3", "internet", "scanner", "198.18.1.3"),
             N("xb", "brute 193.32.7.15", "internet", "brute", "198.18.1.4"),
             N("web", "EXL-WEB1", "server", "web server", "10.10.20.21", "real"), N("fs", "EXL-FILE1", "server", "file server", "10.10.20.12", "real")]
    edges = [E("xs1", "web", "TCP", 80, [0]), E("xs2", "fs", "TCP", 445, [1]), E("xb", "web", "TLS", 443, [2]), E("xb", "fs", "RDP", 3389, [3]),
             E("xb", "fs", "SSH", 22, [4])]
    return view(nodes, edges)


def v_mixed():
    v = v_inbound()
    v["nodes"] += [N("ws", "EXL-WS-047", "user", "workstation", "10.10.10.147", "real"), N("xc2", "cdn.sync-cdn.net", "internet", "c2", "198.19.30.203"),
                   N("xe", "drop.exfil.net", "internet", "exfil", "198.19.31.9"), N("dc", "EXL-DC1", "server", "domain controller", "10.10.20.10", "real"),
                   N("fw", "EXL-FW1", "perimeter", "firewall", "10.10.10.1", "real")]
    v["edges"] += [E("ws", "xc2", "TLS", 443, [5, 6]), E("ws", "dc", "LDAP", 389, [7]), E("fs", "xe", "TLS", 443, [8], state="failed"),
                   E("ws", "fw", "ICMP", None, [9], state="skipped"), E("ws", "fs", "SMB", 445, [10], state="planned")]
    return v


def v_ot():
    nodes = [N("ws", "EXL-WS-047", "user", "workstation", "10.10.10.147", "real"), N("fw", "EXL-FW1", "perimeter", "firewall"),
             N("srv", "EXL-FILE1", "server", "file server", "10.10.20.12", "real"), N("xc2", "c2.example.net", "internet", "c2"),
             N("oj", "EXL-OTJUMP1", "ot", "jump host", "10.30.0.5", "real"), N("os", "EXL-SCADA1", "ot", "scada", "10.30.0.20", "real"),
             N("of", "EXL-OTFS1", "ot", "file server", "10.30.0.9", "real")]
    edges = [E("ws", "oj", "RDP", 3389, [0]), E("oj", "of", "SMB", 445, [1]), E("oj", "os", "TCP", None, [2]), E("ws", "xc2", "TLS", 443, [3]),
             E("xc2", "oj", "TLS", 443, [4]), E("ws", "srv", "SMB", 445, [5])]
    return view(nodes, edges)


def v_aggregated(n_ws=30, n_srv=14):
    nodes, edges = [N("xc2", "c2.example.net", "internet", "c2")], []
    for i in range(n_ws):
        nodes.append(N("w%02d" % i, "EXL-WS-%03d" % i, "user", "workstation", "10.10.10.%d" % (100 + i), "real"))
        edges.append(E("w%02d" % i, "xc2", "TLS", 443, [i]))
    for j in range(n_srv):
        nodes.append(N("s%02d" % j, "EXL-SRV-%02d" % j, "server", "server" if j % 2 else "database server", "10.10.20.%d" % (20 + j), "real"))
        edges.append(E("w%02d" % (j % n_ws), "s%02d" % j, "SMB", 445, [100 + j]))
    nodes.append(N("pool", "Workstations", "user", "workstation", count=40))                 # a view-side aggregate
    edges.append(E("pool", "s00", "SMB", 445, [300]))
    return view(nodes, edges)


def v_huge():
    nodes, edges = [], []
    zones = ["internet", "perimeter", "user", "server", "ot"]
    for z_i, z in enumerate(zones):
        for i in range(30 if z != "perimeter" else 3):
            nodes.append(N("%s%d" % (z[0] if z != "internet" else "x", i), "%s-%03d.example" % (z, i), z, "r%d" % (i % 3), "10.%d.0.%d" % (z_i, i + 1)))
    ids = [n["id"] for n in nodes]
    k = 0
    for i, a in enumerate(ids):
        for off in (3, 17, 41):
            b = ids[(i * 7 + off) % len(ids)]
            if a != b:
                edges.append(E(a, b, ["TLS", "SMB", "DNS", "HTTP"][k % 4], [443, 445, 53, 80][k % 4], [k], state=["ok", "failed", "skipped", "planned"][k % 4]))
                k += 1
    return view(nodes, edges)


SHAPES = {"three": v_three, "external40": v_external, "inbound": v_inbound, "mixed": v_mixed, "ot": v_ot, "aggregated": v_aggregated,
          "huge": v_huge}


# ------------------------------------------------------------------ geometry checks
_TOK = re.compile(r"[MCL]|-?\d+\.?\d*")


def sample_path(d, per=24):
    toks, pts, i, cmd, cur = _TOK.findall(d), [], 0, None, None
    while i < len(toks):
        if toks[i] in "MCL":
            cmd = toks[i]
            i += 1
        if cmd == "M":
            cur = (float(toks[i].split(",")[0]) if "," in toks[i] else float(toks[i]), 0)
        x = lambda k: float(toks[i + k])
        if cmd == "M":
            cur = (x(0), x(1))
            pts.append(cur)
            i += 2
        elif cmd == "L":
            n = (x(0), x(1))
            pts += [(cur[0] + (n[0] - cur[0]) * t / per, cur[1] + (n[1] - cur[1]) * t / per) for t in range(1, per + 1)]
            cur = n
            i += 2
        elif cmd == "C":
            p1, p2, p3 = (x(0), x(1)), (x(2), x(3)), (x(4), x(5))
            for t in range(1, per + 1):
                u = t / per
                pts.append(layout._bez(cur, p1, p2, p3, u))
            cur = p3
            i += 6
    return pts


def inside(p, r, shrink):
    return r[0] + shrink < p[0] < r[2] - shrink and r[1] + shrink < p[1] < r[3] - shrink


def rect(n):
    return (n["x"], n["y"], n["x"] + n["w"], n["y"] + n["h"])


class LayoutAssertions:
    def check(self, lay, width=1180):
        nodes = lay["nodes"]
        rects = {k: rect(n) for k, n in nodes.items()}
        keys = sorted(rects)
        for i, a in enumerate(keys):                                         # nodes: in canvas, disjoint
            ra = rects[a]
            self.assertGreaterEqual(ra[0], 0)
            self.assertLessEqual(ra[2], width)
            self.assertGreaterEqual(ra[1], 0)
            self.assertLessEqual(ra[3], lay["height"])
            for b in keys[i + 1:]:
                self.assertFalse(layout._hit(ra, rects[b], 0), "nodes %s and %s overlap" % (a, b))
        pills = []
        for e in lay["edges"]:
            pts = sample_path(e["path"])
            s, d = rects[e["src"]], rects[e["dst"]]
            near = lambda p, r: max(r[0] - p[0], 0, p[0] - r[2]) ** 2 + max(r[1] - p[1], 0, p[1] - r[3]) ** 2
            self.assertLessEqual(near(pts[0], s), 1.0, "lane does not start on its source")
            self.assertLessEqual(near(pts[-1], d), 1.0, "arrow does not land on its target")
            for p in pts[1:-1]:
                for k, r in rects.items():
                    self.assertFalse(inside(p, r, 1.5), "lane %s>%s runs through node %s at %s" % (e["src"], e["dst"], k, p))
            if e["label"]:
                pr = (e["lx"] - e["lw"] / 2, e["ly"] - 7.5, e["lx"] + e["lw"] / 2, e["ly"] + 7.5)
                self.assertGreaterEqual(pr[0], 0)
                self.assertLessEqual(pr[2], width)
                for k, r in rects.items():
                    self.assertFalse(layout._hit(pr, r, 0), "pill %r covers node %s" % (e["label"], k))
                for q in pills:
                    self.assertFalse(layout._hit(pr, q, 0), "pills overlap (%r)" % e["label"])
                pills.append(pr)


class TestLayout(unittest.TestCase, LayoutAssertions):
    def test_all_shapes_collision_free(self):
        for name, fn in SHAPES.items():
            for side in ("left", "right"):
                lay = layout.place(fn(), internet=side)
                self.assertTrue(lay["nodes"], name)
                with self.subTest(shape=name, internet=side):
                    self.check(lay)

    def test_deterministic(self):
        for name, fn in SHAPES.items():
            a = json.dumps(layout.place(fn()), sort_keys=True)
            b = json.dumps(layout.place(copy.deepcopy(fn())), sort_keys=True)
            self.assertEqual(a, b, name)

    def test_zone_columns_and_ot(self):
        lay = layout.place(v_three())
        self.assertEqual([z["id"] for z in lay["zones"]], ["internet", "perimeter", "user", "server"])      # no OT node: no OT column
        lay = layout.place(v_ot())
        self.assertEqual([z["id"] for z in lay["zones"]][-1], "ot")
        xs = [z["x"] for z in lay["zones"]]
        self.assertEqual(xs, sorted(xs))
        for _k, n in lay["nodes"].items():
            z = next(z for z in lay["zones"] if z["id"] == n["zone"])
            self.assertAlmostEqual(n["x"], z["x"], 1)

    def test_three_nodes(self):
        lay = layout.place(v_three())
        self.assertEqual(len(lay["nodes"]), 3)
        self.assertEqual(len(lay["edges"]), 3)
        self.assertEqual(lay["overflow"], [])
        self.assertTrue(all(e["label"] for e in lay["edges"]))
        self.assertIn("TLS 443", [e["label"] for e in lay["edges"]])

    def test_stack_order_is_first_use_then_name(self):
        v = view([N("a", "Zeta", "server"), N("b", "Alpha", "server"), N("c", "Mid", "server"), N("u", "WS", "user")],
                 [E("u", "a", "SMB", 445, [0]), E("u", "c", "SMB", 445, [1]), E("u", "b", "SMB", 445, [2])])
        lay = layout.place(v)
        ys = {k: lay["nodes"][k]["y"] for k in "abc"}
        self.assertLess(ys["a"], ys["c"])
        self.assertLess(ys["c"], ys["b"])
        # unused nodes sort after used ones, by name
        v["nodes"] += [N("z", "Zed", "server"), N("y", "Yak", "server")]
        lay = layout.place(v)
        self.assertLess(lay["nodes"]["b"]["y"], lay["nodes"]["y"]["y"])
        self.assertLess(lay["nodes"]["y"]["y"], lay["nodes"]["z"]["y"])

    def test_forty_external_indicators_aggregate(self):
        lay = layout.place(v_external(40))
        ext = [n for n in lay["nodes"].values() if n["zone"] == "internet"]
        self.assertEqual(len(ext), 8)
        agg = [n for n in ext if n["kind"] == "aggregate"]
        self.assertEqual(len(agg), 1)
        self.assertTrue(agg[0]["label"].startswith("33 more"), agg[0]["label"])
        self.assertTrue(any("folded" in o for o in lay["overflow"]))
        # the 33 folded lanes merge into at most one per protocol/port
        to_agg = [e for e in lay["edges"] if e["dst"] == "agg:internet"]
        self.assertLessEqual(len(to_agg), 2)
        self.assertTrue(any("×" in e["label"] for e in to_agg))
        lay2 = layout.place(v_external(40), max_nodes_per_zone=40)
        self.assertEqual(len([n for n in lay2["nodes"].values() if n["zone"] == "internet"]), 40)
        self.check(lay2)

    def test_aggregation_label_names_a_single_role(self):
        lay = layout.place(v_aggregated(), max_nodes_per_zone=4)
        labels = [n["label"] for n in lay["nodes"].values() if n["kind"] == "aggregate"]
        self.assertTrue(any("more workstation hosts" in x or "more hosts" in x for x in labels), labels)
        for n in lay["nodes"].values():
            if n["kind"] == "aggregate":
                self.assertGreaterEqual(n["count"], 2)
        self.check(lay)

    def test_view_side_aggregate_node_keeps_its_count(self):
        v = view([N("p", "Workstations", "user", "workstation", count=40), N("s", "EXL-FILE1", "server")], [E("p", "s", "SMB", 445, [0])])
        lay = layout.place(v)
        self.assertEqual(lay["nodes"]["p"]["sub"], "40 hosts")

    def test_inbound_direction(self):
        v = v_inbound()
        left = layout.place(v, internet="left")
        right = layout.place(v, internet="right")
        auto = layout.place(v, internet="auto")
        self.assertEqual(auto["zones"][0]["id"], right["zones"][0]["id"])           # inbound-only mirrors in auto mode
        for e in right["edges"]:
            pts = sample_path(e["path"])
            self.assertGreater(pts[0][0], pts[-1][0], "inbound lanes run right to left when the Internet is on the right")
            self.assertTrue(e["inbound"])
        for e in left["edges"]:
            pts = sample_path(e["path"])
            self.assertLess(pts[0][0], pts[-1][0])
        mixed = layout.place(v_mixed(), internet="auto")
        self.assertEqual(mixed["zones"][0]["id"], "internet")                       # mixed keeps the plan's order

    def test_state_styling(self):
        lay = layout.place(v_mixed())
        by = {(e["src"], e["dst"]): e for e in lay["edges"]}
        failed, skipped, planned = by[("fs", "xe")], by[("ws", "fw")], by[("ws", "fs")]
        self.assertEqual(failed["state"], "failed")
        self.assertIn("failed", failed["label"])
        self.assertEqual(skipped["state"], "skipped")
        self.assertTrue(skipped["dashed"])
        self.assertIn("skipped", skipped["label"])
        self.assertFalse(planned["dashed"])
        self.assertEqual(len({failed["color"], skipped["color"], planned["color"]}), 3)

    def test_dashed_inferred_edges(self):
        v = v_three()
        v["edges"][0]["inferred"] = True
        lay = layout.place(v)
        self.assertTrue([e for e in lay["edges"] if e["dst"] == "xc2"][0]["dashed"])
        self.assertFalse([e for e in lay["edges"] if e["dst"] == "dc"][0]["dashed"])

    def test_same_zone_lanes_bow_out(self):
        v = view([N("a", "A", "server"), N("b", "B", "server"), N("c", "C", "server")], [E("a", "b", "SMB", 445, [0]), E("a", "c", "RDP", 3389, [1])])
        lay = layout.place(v)
        self.check(lay)
        for e in lay["edges"]:
            pts = sample_path(e["path"])
            self.assertGreater(max(p[0] for p in pts), lay["nodes"]["a"]["x"] + lay["nodes"]["a"]["w"] + 20)

    def test_self_loops_after_folding_are_dropped_and_reported(self):
        v = v_aggregated()
        v["edges"] += [E("w20", "w25", "SMB", 445, [400]), E("w21", "w26", "RDP", 3389, [401])]
        lay = layout.place(v, max_nodes_per_zone=3)
        self.assertTrue(any("same node" in o for o in lay["overflow"]), lay["overflow"])

    def test_very_large_view(self):
        v = v_huge()
        lay = layout.place(v)
        zones = {}
        for n in lay["nodes"].values():
            zones[n["zone"]] = zones.get(n["zone"], 0) + 1
        self.assertTrue(all(c <= 8 for c in zones.values()), zones)
        self.assertLessEqual(len(lay["edges"]), layout.MAX_EDGES)
        self.assertTrue(any("not drawn" in o for o in lay["overflow"]))
        self.assertLess(lay["height"], 900)
        self.check(lay)

    def test_text_fits_node_boxes(self):
        lay = layout.place(v_three())
        long = view([N("a", "A very long host name that cannot possibly fit in one node box at this size.example.net", "user",
                       addr="10.10.10.147"), N("b", "B", "server")], [E("a", "b", "SMB", 445, [0])])
        n = layout.place(long)["nodes"]["a"]
        self.assertLessEqual(len(n["label"]) * 10.5 * 0.55, n["w"])
        self.assertTrue(n["label"].endswith("…"))
        self.assertTrue(n["title"].startswith("A very long"))
        self.assertTrue(lay)


# ------------------------------------------------------------------ the flow map panel
class TestFlowmap(unittest.TestCase):
    def test_panel_shape(self):
        p = flowmap.render(v_mixed(), None)
        for k in ("id", "title", "sub", "svg", "html", "height", "alt"):
            self.assertIn(k, p)
        self.assertEqual(p["id"], "flowmap")
        self.assertTrue(p["svg"].startswith("<svg"))
        self.assertTrue(p["svg"].rstrip().endswith("</svg>"))
        self.assertGreater(p["height"], 200)
        self.assertEqual(len(p["alt"]), 10)
        self.assertTrue(all(len(r) == len(p["alt_head"]) for r in p["alt"]))

    def test_omitted_without_flows(self):
        self.assertIsNone(flowmap.render(view([N("a", "A", "user")], []), None))
        self.assertIsNone(flowmap.render(view([], []), None))

    def test_no_scripts_no_external_resources_and_escaping(self):
        v = v_three()
        v["nodes"][1]["label"] = '<script>alert(1)</script>&"'
        v["nodes"][1]["address"] = "<img src=x onerror=alert(1)>"
        svg = flowmap.render(v, None)["svg"]
        self.assertNotIn("<script", svg)
        self.assertNotIn("<img", svg)
        self.assertNotIn("http://", svg.replace("http://www.w3.org/2000/svg", ""))
        self.assertNotIn("onerror=alert(1)>", svg)
        self.assertIn("&lt;script&gt;", svg)

    def test_every_shape_lints_clean(self):
        for name, fn in SHAPES.items():
            p = flowmap.render(fn(), None)
            with self.subTest(shape=name):
                bad = lint.lint_svg(p["svg"])
                self.assertEqual(bad, [], [str(b) for b in bad])
                self.assertEqual(p["svg"], flowmap.render(fn(), None)["svg"])

    def test_arrows_land_within_six_px(self):
        for name, fn in SHAPES.items():
            lay = layout.place(fn(), internet="auto")
            for e in lay["edges"]:
                end = sample_path(e["path"])[-1]
                r = rect(lay["nodes"][e["dst"]])
                d = max(r[0] - end[0], 0, end[0] - r[2]) ** 2 + max(r[1] - end[1], 0, end[1] - r[3]) ** 2
                self.assertLessEqual(d ** 0.5, 6.0, name)

    def test_legend_and_labels_follow_the_data(self):
        svg = flowmap.render(v_mixed(), None)["svg"]
        for text in ("failed", "skipped", "inside the network", "TLS 443"):
            self.assertIn(text, svg)
        plain = flowmap.render(v_three(), None)["svg"]
        self.assertNotIn("skipped", plain)
        self.assertNotIn("inbound, from", plain)

    def test_plan_mode_is_labelled(self):
        v = v_three()
        v["mode"] = "plan"
        self.assertIn("nothing has been generated", flowmap.render(v, None)["sub"])

    def test_large_view_summarised(self):
        p = flowmap.render(v_huge(), None)
        self.assertTrue(p["overflow"])
        self.assertIn("folded", p["svg"])
        self.assertLess(p["height"], 1100)


# ------------------------------------------------------------------ lint
def svg(body, w=300, h=200):
    return '<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg">%s</svg>' % (w, h, body)


class TestLint(unittest.TestCase):
    def kinds(self, s):
        return sorted({f.kind for f in lint.lint_svg(s)})

    def test_clean(self):
        s = svg('<rect x="10" y="10" width="100" height="40"/><text x="14" y="30" font-size="10">hello</text>'
                '<text x="14" y="44" font-size="9">world</text>')
        self.assertEqual(lint.lint_svg(s), [])

    def test_overlap(self):
        s = svg('<text x="10" y="30" font-size="12">first label here</text><text x="40" y="32" font-size="12">second label</text>')
        self.assertEqual(self.kinds(s), ["overlap"])
        stacked = svg('<text x="10" y="30" font-size="12">first label here</text><text x="10" y="45" font-size="12">second label</text>')
        self.assertEqual(lint.lint_svg(stacked), [])
        halo = svg('<text x="10" y="30" font-size="12" stroke="#fff">same</text><text x="10" y="30" font-size="12">same</text>')
        self.assertEqual(lint.lint_svg(halo), [])

    def test_clip(self):
        s = svg('<text x="250" y="30" font-size="12" font-weight="700">a long label that runs off the right edge</text>')
        self.assertEqual(self.kinds(s), ["clip"])
        self.assertEqual(self.kinds(svg('<rect x="280" y="10" width="60" height="30"/><text x="5" y="100" font-size="9">ok</text>')), ["clip"])
        self.assertEqual(self.kinds(svg('<text x="-30" y="30" font-size="12">off the left</text>')), ["clip"])

    def test_arrow(self):
        marker = '<defs><marker id="m"><path d="M0,0 L5,2 L0,4"/></marker></defs>'
        good = svg(marker + '<rect x="10" y="10" width="60" height="40"/><rect x="200" y="10" width="60" height="40"/>'
                   '<path d="M70,30 C120,30 150,30 198,30" marker-end="url(#m)" fill="none"/><text x="20" y="25" font-size="9">a</text>')
        self.assertEqual(lint.lint_svg(good), [])
        bad = good.replace("198,30", "150,30").replace("C120,30 150,30", "C100,30 120,30")
        self.assertEqual(self.kinds(bad), ["arrow"])
        life = svg(marker + '<rect x="10" y="10" width="60" height="30"/><line x1="150" y1="40" x2="150" y2="190" stroke="#ccc"/>'
                   '<line x1="70" y1="100" x2="146" y2="100" marker-end="url(#m)"/><text x="12" y="25" font-size="9">c</text>')
        self.assertEqual(lint.lint_svg(life), [])

    def test_tiny_and_empty(self):
        self.assertEqual(self.kinds(svg('<rect x="1" y="1" width="50" height="30"/><text x="3" y="20" font-size="7">x</text>')), ["tiny"])
        self.assertEqual(self.kinds(svg("")), ["empty"])
        self.assertEqual(self.kinds(svg("<defs/>")), ["empty"])

    def test_transform_and_tspan(self):
        s = svg('<g transform="translate(250,0)"><text x="0" y="30" font-size="12" font-weight="700">long label going right</text></g>')
        self.assertEqual(self.kinds(s), ["clip"])
        t = svg('<text x="10" y="30" font-size="10"><tspan x="10" y="30">line one</tspan><tspan x="10" dy="14">line two</tspan></text>')
        self.assertEqual(lint.lint_svg(t), [])

    def test_html_extracts_every_svg_but_the_logo(self):
        page = ('<div class="logo"><svg viewBox="0 0 10 10"><text x="0" y="5" font-size="4">tiny logo</text></svg></div>'
                + svg('<text x="1" y="9" font-size="6">a</text><rect width="5" height="5"/>') + svg('<text x="3" y="30" font-size="9">fine</text>'))
        fs = lint.lint_html(page)
        self.assertEqual([f.kind for f in fs], ["tiny"])
        self.assertIn("svg1", fs[0].element)

    def test_entities_and_garbage(self):
        s = svg('<text x="10" y="20" font-size="10">a &amp; b &nbsp; &lt;c&gt;</text><rect x="1" y="1" width="5" height="5"/>')
        self.assertEqual(lint.lint_svg(s), [])
        self.assertEqual(self.kinds("not an svg"), ["empty"])

    def test_registered_diagrams_stay_clean(self):
        import make_diagram
        for name in ("topology", "ndr-c2-beaconing", "baseline-mcp", "crp-expired-cert", "npm-pqc-posture"):
            with self.subTest(diagram=name):
                self.assertEqual(lint.lint_html(make_diagram.render(name)), [])


# ------------------------------------------------------------------ fixtures
class TestFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(FIX, "forms.json")) as f:
            cls.forms = json.load(f)

    def load(self, name):
        with open(os.path.join(FIX, name)) as f:
            return json.load(f)

    def test_fifteen_forms_present(self):
        self.assertEqual(sorted(v["form"] for v in self.forms.values()), list(range(1, 16)))
        for name, v in self.forms.items():
            self.assertTrue(os.path.exists(os.path.join(FIX, name)), name)
            self.assertEqual(os.path.exists(os.path.join(FIX, name[:-5] + ".summary.json")), v["summary"], name)
            self.assertEqual(os.path.exists(os.path.join(FIX, name[:-5] + ".score.json")), v["score"], name)
            self.assertEqual(set(v["panels"]), {"header", "plain", "timeline", "flowmap", "stages", "trace", "coverage", "filters", "notes"})

    def test_campaigns_validate(self):
        for name, v in self.forms.items():
            data = self.load(name)
            camps = data if isinstance(data, list) else [data]
            errs = [e for c in camps for e in schema.validate(c)]
            if v["valid"]:
                self.assertEqual(errs, [], name)
            else:
                self.assertEqual(v["form"], 9)                                     # the one form with no traffic has no stages
                self.assertEqual(errs, ["stages: required non-empty list"])

    def test_form_shapes(self):
        f = {v["form"]: (n, v) for n, v in self.forms.items()}
        self.assertGreaterEqual(f[1][1]["indicators"], 50)
        self.assertGreaterEqual(f[1][1]["stages"], 7)
        self.assertEqual(f[3][1]["actions"], 1)
        self.assertEqual((f[12][1]["stages"], f[12][1]["actions"]), (60, 400))
        self.assertEqual(f[2][1]["indicators"], 0)
        self.assertEqual(f[10][1]["campaigns"], 2)
        self.assertEqual(f[13][1]["address_mode"], "real")
        self.assertEqual(f[14][1]["mode"], "plan")
        self.assertEqual(f[15][1]["mode"], "scored")
        self.assertTrue(f[15][1]["score"])
        self.assertFalse(f[9][1]["panels"]["flowmap"])
        self.assertTrue(all(c["type"] in schema.IOC_TYPES for c in self.load(f[9][0])["iocs"]))
        # the beacon-only form has only command-and-control actions and carries a family look-alike profile
        c4 = self.load(f[4][0])
        acts = [a for s in c4["stages"] for a in s["actions"]]
        self.assertTrue(all("beacon" in a["action"] for a in acts))
        self.assertTrue(any(a["params"].get("profile") == "cobalt-strike" for a in acts))
        # inbound forms start from external endpoints, form 7 has none at all
        c5 = self.load(f[5][0])
        self.assertTrue(all(a["from"].split(":")[0] in ("scanner", "brute") for s in c5["stages"] for a in s["actions"]))
        c7 = self.load(f[7][0])
        self.assertFalse(any(":" in a["from"] and a["from"].split(":")[0] in ("c2", "exfil", "scanner") for s in c7["stages"] for a in s["actions"]))
        # real mode indicators are public addresses
        c13 = self.load(f[13][0])
        self.assertEqual(c13["options"]["address_mode"], "real")

    def test_summaries_look_like_runner_entries(self):
        for name, v in self.forms.items():
            if not v["summary"]:
                continue
            data = self.load(name[:-5] + ".summary.json")
            for s in (data if isinstance(data, list) else [data]):
                self.assertTrue({"entries", "iocs", "estimate", "errors", "emitted"} <= set(s), name)
                self.assertEqual(s["emitted"], sum(1 for e in s["entries"] if e["status"] == "ok"))
                for e in s["entries"]:
                    self.assertIn(e["status"], ("ok", "skipped", "failed"))
                    for k in ("stage", "action", "from", "to", "params", "protocols", "techniques", "ioc"):
                        self.assertIn(k, e)
                    if e["status"] == "ok":
                        self.assertGreater(e["packets"], 0)
                        self.assertGreater(e["bytes"], 0)
                        self.assertLessEqual(e["first_ts"], e["last_ts"])
                        self.assertIn("name", e["from_host"])
                        self.assertIn("ip", e["to_host"])
                    elif e["status"] == "skipped":
                        self.assertIsNone(e["ts"])
                        self.assertTrue(e["error"])
        s11 = self.load("11-partial.summary.json")
        self.assertEqual(sorted({e["status"] for e in s11["entries"]}), ["failed", "ok", "skipped"])

    def test_score_file_shape(self):
        sc = self.load("15-scored.score.json")
        self.assertEqual({a["status"] for a in sc["actions"]} - {"not_run"}, {"detected", "related", "missed"})
        self.assertTrue({"techniques", "actions", "score"} <= set(sc))

    def test_rebuild_is_identical(self):
        r = subprocess.run([sys.executable, os.path.join(FIX, "make_fixtures.py"), "--check"], capture_output=True, text=True, cwd=DEV)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    # ---- layout and flow map on the real view model (skipped until view.py builds)
    def _build(self, name):
        try:
            V = importlib.import_module("diagrams.campaign.view")
        except Exception as e:                                          # noqa: BLE001 - an import failure skips the test with the reason
            self.skipTest("view.py not importable: %s" % e)
        data = self.load(name)
        camps = data if isinstance(data, list) else [data]
        base = name[:-5]
        summ = self.load(base + ".summary.json") if self.forms[name]["summary"] else None
        summ = summ if isinstance(summ, list) else [summ] * len(camps)
        score = self.load(base + ".score.json") if self.forms[name]["score"] else None
        out = []
        for c, s in zip(camps, summ, strict=False):
            if not c.get("stages"):
                continue
            out.append(V.build(c, s, score))
        return out

    def test_fixture_views_lay_out_cleanly(self):
        helper = LayoutAssertions()
        helper.assertGreaterEqual = self.assertGreaterEqual
        helper.assertLessEqual = self.assertLessEqual
        helper.assertFalse = self.assertFalse
        helper.assertTrue = self.assertTrue
        for name in sorted(self.forms):
            if not self.forms[name]["valid"]:
                continue
            for v in self._build(name):
                with self.subTest(fixture=name, mode=v["mode"]):
                    lay = layout.place(v, internet="auto")
                    helper.check(lay)
                    self.assertEqual(json.dumps(lay, sort_keys=True), json.dumps(layout.place(copy.deepcopy(v), internet="auto"), sort_keys=True))
                    p = flowmap.render(v, None)
                    self.assertIsNotNone(p, name)
                    bad = lint.lint_svg(p["svg"])
                    self.assertEqual(bad, [], [str(b) for b in bad])
                    if self.forms[name]["ot"]:
                        self.assertIn("ot", [z["id"] for z in lay["zones"]]) if any(n["zone"] == "ot" for n in v["nodes"]) else None

    def test_vulnerability_only_has_no_flow_map(self):
        try:
            V = importlib.import_module("diagrams.campaign.view")
        except Exception as e:                                          # noqa: BLE001 - an import failure skips the test with the reason
            self.skipTest("view.py not importable: %s" % e)
        c = self.load("09-vuln-only.json")
        c.setdefault("stages", [])
        self.assertIsNone(flowmap.render(V.build(c, None, None), None))


if __name__ == "__main__":
    unittest.main()

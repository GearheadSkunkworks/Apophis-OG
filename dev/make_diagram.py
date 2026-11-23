#!/usr/bin/env python3
"""
make_diagram.py — branded diagrams of the Example demo environment.

Every diagram is *generated* from `inventory.json`, the configured /24s and the incident
registry rather than drawn by hand, so a diagram can never drift from what the generator
actually emits. Re-run after changing the networks or the scenario selection and the page
follows.

    python3 make_diagram.py --list
    python3 make_diagram.py                                    # default: topology
    python3 make_diagram.py --diagram timeline
    python3 make_diagram.py --user-net 192.168.10.0/24 --server-net 192.168.20.0/24
    python3 make_diagram.py --diagram timeline --module ndr-akira --module npm-voip-quality

--------------------------------------------------------------------------------------------
ADDING A DIAGRAM  (this file is a framework, not a one-off)

Diagrams share the page chrome — masthead, logo, lozenge title, KPI strip, notes, footer — so
they all look like one family. A new diagram is one function:

    @register("attack-path", "Attack path",
              "How the foothold reaches the crown jewels", order=30)
    def attack_path(c):                      # c is a DiagramContext
        return {
            "svg":      "<svg viewBox=...>…</svg>",   # the drawing
            "kpis":     [("7", "Hops"), (c.nets["user"], "User network")],
            "sections": [("Evidence", "<table>…</table>")],
            "notes":    [("", "Heading", "Body text"), ("warn", "Caveat", "…")],
        }

Everything but "svg" is optional. `c` carries the inventory buckets (c.data, incl. c.data["hosts"] and c.host(name) for ANY
host), the live
networks (c.nets / c.gw), the incident registry (c.modules, c.selected) and the palette, so a
builder never hard-codes an address or a scenario name. Register it and it appears in
`--list`, in the GUI's diagram menu and at /api/diagrams automatically.
--------------------------------------------------------------------------------------------

Stdlib only. The product wordmark is inlined from the brand assets when available.
"""
import argparse
import html
import json
import os
import re
import sys

# Branding -- product name, platform, brand palette, logo loader and APP_DIR -- now lives
# in branding.py so the de-brand can swap it in one place. The values are unchanged, so
# diagrams render byte-identically. APP_DIR still resolves the bundled data files (ui/,
# assets/, inventory.json, netgen/), under sys._MEIPASS when frozen by PyInstaller.
from branding import (                                 # noqa: E402
    APP_DIR, LOGO_CANDIDATES, load_logo, PRODUCT_TITLE, CODENAME,
    VERSION as BRANDING_VERSION,
    SAPPHIRE, PLUM, CYAN, TANGERINE, GRAY, MAGENTA, VIOLET, FADE,
)

# device-group labels for the user subnet, in the order they should appear
USER_GROUPS = [
    ("EXL-WS", "Windows workstations", "Windows 11"),
    ("EXL-MAC", "macOS workstations", "macOS 14"),
    ("EXL-AP", "Wireless access points", "CAPWAP to WLC1"),
    ("EXL-PH", "VoIP handsets", "SIP / RTP to PBX1"),
    ("EXL-PRN", "Printers", "IPP / raw 9100"),
    ("EXL-SB", "Smart boards", "mDNS / AirPlay"),
]


# ------------------------------------------------------------------ the framework
class Diagram:
    __slots__ = ("name", "title", "description", "builder", "order", "scenario")

    def __init__(self, name, title, description, builder, order, scenario=None):
        self.name, self.title, self.description = name, title, description
        self.builder, self.order, self.scenario = builder, order, scenario


DIAGRAMS = {}


def register(name, title, description, order=50, scenario=None):
    """Decorator: add a diagram to the registry (see ADDING A DIAGRAM above).

    `scenario="<module-name>"` marks it as belonging to one incident module. Scenario
    diagrams are kept OUT of the top-level picker — otherwise 28 of them would drown the
    two environment diagrams — and are reached from that scenario's Visualize button
    instead. Register it and the button lights up on its own.
    """
    def wrap(fn):
        DIAGRAMS[name] = Diagram(name, title, description, fn, order, scenario)
        return fn
    return wrap


def catalog(include_scenarios=False):
    """Registry entries, display order. By default only the environment-level diagrams —
    what --list, the GUI's diagram menu and /api/diagrams show."""
    ds = sorted(DIAGRAMS.values(), key=lambda d: (d.order, d.name))
    return [{"name": d.name, "title": d.title, "description": d.description,
             "scenario": d.scenario}
            for d in ds if include_scenarios or not d.scenario]


def scenario_diagrams():
    """{module-name: diagram-name} for every scenario that has a diagram. The GUI uses this
    to decide which Visualize buttons are live."""
    return {d.scenario: d.name for d in DIAGRAMS.values() if d.scenario}


class DiagramContext:
    """Everything a diagram builder needs, so builders never hard-code an address or scenario.

    .data      inventory buckets (groups, servers, sensor, switches, counts, org, domain)
    .nets/.gw  the live networks and gateway addresses
    .modules   the incident registry as [{name, prefix, title, note, window}, ...]
    .selected  the subset chosen for this render (all of them unless narrowed)
    """

    def __init__(self, data, modules, selected):
        self.data = data
        self.nets = data["nets"]
        self.gw = data["gw"]
        self.modules = modules
        self.selected = selected
        self.ot_nets = None          # set by render() when the industrial zone is on
        self.palette = {"sapphire": SAPPHIRE, "plum": PLUM, "cyan": CYAN,
                        "tangerine": TANGERINE, "gray": GRAY, "magenta": MAGENTA}

    # convenience so builders stay terse
    esc = staticmethod(lambda x: html.escape(str(x)))

    def cat_color(self, prefix):
        # One colour per category across the whole app: these must match CATS in
        # ui/index.html, or a scenario is one colour in the selector and another in its
        # diagram. CRP is Tangerine, not Gray — Gray is the brand's neutral and read as
        # "disabled" next to the two live categories.
        return {"NDR": PLUM, "NPM": CYAN, "CRP": TANGERINE, "CUSTOM": SAPPHIRE}.get(prefix, SAPPHIRE)

    def host(self, name):
        """Any host in the inventory by name, re-addressed — servers, workstations, boards."""
        return next((h for h in self.data.get("hosts", self.data["servers"])
                     if h["hostname"] == name), None)


def load_modules(selection=None):
    """Read the incident registry. Returns (all_modules, selected_names)."""
    try:
        sys.path.insert(0, APP_DIR)
        from netgen import incidents as INC
        mods = []
        for n, i in INC.REGISTRY.items():
            (h1, m1), (h2, m2) = i.window
            mods.append({"name": n, "prefix": i.prefix, "title": i.title, "note": i.note,
                         "start": h1 * 60 + m1, "end": h2 * 60 + m2,
                         "window": _rel_win(h1 * 60 + m1, h2 * 60 + m2)})
    except Exception:                                # noqa: BLE001 — diagrams still render
        return [], []
    names = [m["name"] for m in mods]
    return mods, (list(selection) if selection is not None else names)


def gather(inventory, user_net=None, server_net=None, ot_nets=None):
    """Load the inventory, optionally re-address it, and bucket it for drawing.

    `ot_nets` is the switch for the industrial zone: without it every OT asset is dropped
    before bucketing, exactly as netgen.model.build_hosts does, so a diagram can never draw a
    zone the capture does not contain.
    """
    with open(inventory) as f:
        inv = json.load(f)
    if not ot_nets:
        inv["hosts"] = [h for h in inv["hosts"] if not h.get("purdue")]
    if user_net or server_net or ot_nets:
        sys.path.insert(0, APP_DIR)
        from netgen.model import remap_inventory
        remap_inventory(inv, user_net, server_net, ot_nets)

    sided = {h["gw_side"]: h for h in inv["hosts"] if h.get("gw_side")}
    if sided:
        # gw_side-tagged inventory: gateway legs may belong to EXL-FW1 or EXL-OTFW1.
        nets = {"user": sided["user"]["subnet"], "server": sided["server"]["subnet"],
                "wan": sided["outside"]["subnet"]}
        gw = {"user": sided["user"]["ip"], "server": sided["server"]["ip"],
              "wan": sided["outside"]["ip"]}
        for side in ("ot", "ops", "idmz"):
            if side in sided:
                nets[side] = sided[side]["subnet"]
                gw[side] = sided[side]["ip"]
    else:
        fw = [h for h in inv["hosts"] if h["hostname"] == "EXL-FW1"]
        nets = {"user": fw[0]["subnet"], "server": fw[1]["subnet"], "wan": fw[2]["subnet"]}
        gw = {"user": fw[0]["ip"], "server": fw[1]["ip"], "wan": fw[2]["ip"]}
        for i, side in enumerate(("ot", "ops", "idmz")):
            if len(fw) > 3 + i:
                nets[side] = fw[3 + i]["subnet"]
                gw[side] = fw[3 + i]["ip"]

    user_hosts = [h for h in inv["hosts"] if h["subnet"] == nets["user"]]
    srv_hosts = [h for h in inv["hosts"] if h["subnet"] == nets["server"]]
    # OT assets, bucketed by Purdue level for the topology and the baseline-ot page
    ot_levels = {}
    for h in inv["hosts"]:
        lvl = h.get("purdue")
        if lvl and lvl != "gw":
            ot_levels.setdefault(lvl, []).append(h)

    groups = []
    for prefix, label, note in USER_GROUPS:
        members = [h for h in user_hosts if h["hostname"].startswith(prefix)]
        if members:
            lo = min(int(h["ip"].rsplit(".", 1)[1]) for h in members)
            hi = max(int(h["ip"].rsplit(".", 1)[1]) for h in members)
            pfx = members[0]["ip"].rsplit(".", 1)[0]
            groups.append({"label": label, "note": note, "count": len(members),
                           "range": f"{pfx}.{lo}–{hi}" if lo != hi else f"{pfx}.{lo}"})

    servers = [h for h in srv_hosts
               if not h["hostname"].startswith(("EXL-SW", "EXL-FW", "EXL-SENSOR"))]
    sensor = next((h for h in srv_hosts if h["hostname"].startswith("EXL-SENSOR")), None)
    switches = [h for h in inv["hosts"] if h["hostname"].startswith("EXL-SW")]
    return {"org": inv.get("org", "Example Logistics"), "domain": inv.get("domain", ""),
            "nets": nets, "gw": gw, "groups": groups, "servers": servers, "sensor": sensor,
            "switches": switches, "n_user": len(user_hosts), "n_server": len(srv_hosts),
            "n_total": len(inv["hosts"]),
            # every host, so a diagram can resolve a user-subnet device (the attacker
            # workstation, a smart board) and not just the servers
            "hosts": inv["hosts"],
            "ot_levels": ot_levels}


def esc(x):
    return html.escape(str(x))


@register("topology", "Network topology",
          "The emulated environment: both class C networks, the firewall, and the SPAN vantage",
          order=10)
def topology(c):
    """The topology itself. Sapphire for primary nodes, cyan/tangerine as categorical accents."""
    d = c.data
    svg = _topology_svg(d)
    rows = "".join(
        f'<tr><td class="m">{esc(h["hostname"])}</td><td class="m ip">{esc(h["ip"])}</td>'
        f'<td>{esc(h["role"])}</td><td class="svc">{esc(h.get("services",""))}</td></tr>'
        for h in d["servers"])
    return {
        "svg": svg,
        "kpis": [(d["n_total"], "Addressed interfaces"),
                 (d["nets"]["user"], "User network", "mono"),
                 (d["nets"]["server"], "Server network", "mono")]
                + ([(d["nets"]["ot"], "OT cell/area", "mono"),
                    (d["nets"]["ops"], "OT operations", "mono"),
                    (d["nets"]["idmz"], "OT IDMZ", "mono")] if d["nets"].get("ot") else [])
                + [(len(d["servers"]), "Servers"),
                   (len(c.modules) or 28, "Incident scenarios"),
                   ("16 h", "Capture window")],
        "sections": [(f'Server inventory — {esc(d["nets"]["server"])}',
                      '<table><thead><tr><th>Host</th><th>Address</th><th>Role</th>'
                      f'<th>Services</th></tr></thead><tbody>{rows}</tbody></table>')],
        "notes": [
            ("", "Every internal network is configurable",
             "Each is a class C (/24). Every host keeps its own last octet when re-addressed, so "
             "host counts, roles, services, MAC addresses and traffic patterns are identical "
             "across any choice of networks — only the network part moves."),
            ("warn", "External addressing is fixed",
             f'The simulated internet (198.51.100.0/24), the WAN {esc(d["nets"]["wan"])} and every '
             "real, publicly documented threat-intel indicator in the built-in scenarios are never "
             "re-addressed, so sensor threat matching behaves identically no matter how the internal "
             "networks are set. A campaign you build moves its indicators into a benchmark range "
             "(198.18.0.0/15) unless you choose real addresses."),
            ("", "Shadow MCP surface (baseline)",
             "All four smart boards poll their vendor's firmware service over HTTPS all day. "
             "EXL-SB-02 takes an update about Start +5:15 and from then on runs an MCP server on port "
             "3000 — advertised over mDNS, driven in plaintext by workstations and the jump "
             "host, with an outbound link to the vendor cloud. This is normal-day traffic, not "
             "an incident module."),
            ("", "Capture vantage",
             "A SPAN of both firewall inside interfaces. Inter-subnet traffic is therefore seen "
             "twice, once per segment, with the TTL decremented across the firewall — which is why "
             "the outside interface never appears in the capture."),
        ],
    }


def _topology_svg(d):
    u_pfx = d["gw"]["user"].rsplit(".", 1)[0]
    s_pfx = d["gw"]["server"].rsplit(".", 1)[0]
    parts = []
    A = parts.append

    # The industrial zone hangs BELOW the enterprise on a third set of firewall legs. That is
    # the only free space on a canvas that is already full at 1180x772, and it is also the right
    # picture: Purdue is a hierarchy and control sits under operations.
    ot = bool(d["nets"].get("ot"))
    height = 772 + (462 if ot else 0)
    A(f'<svg viewBox="0 0 1180 {height}" xmlns="http://www.w3.org/2000/svg" role="img" '
      f'aria-label="Example network topology: user subnet {esc(d["nets"]["user"])} and '
      f'server subnet {esc(d["nets"]["server"])} behind one firewall, SPAN to a sensor'
      + (f', plus the industrial zone {esc(d["nets"]["ot"])} at Purdue levels 0 to 3.5' if ot else '')
      + '">')
    A('<defs>'
      f'<linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
      f'<stop offset="0" stop-color="{SAPPHIRE}"/><stop offset="1" stop-color="{FADE}"/></linearGradient>'
      f'<marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
      f'<path d="M0,0 L10,5 L0,10 z" fill="{GRAY}"/></marker>'
      f'<marker id="arc" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
      f'<path d="M0,0 L10,5 L0,10 z" fill="{TANGERINE}"/></marker>'
      f'<marker id="arm" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
      f'<path d="M0,0 L10,5 L0,10 z" fill="{MAGENTA}"/></marker>'
      '</defs>')

    # ---------------------------------------------------------------- internet
    A(f'<g><rect x="430" y="18" width="320" height="74" rx="37" fill="#f4f4f7" stroke="{GRAY}" stroke-dasharray="5 4"/>'
      f'<text x="590" y="46" text-anchor="middle" font-size="15" font-weight="700" fill="{SAPPHIRE}">Simulated internet</text>'
      f'<text x="590" y="65" text-anchor="middle" font-size="11.5" fill="{GRAY}">15 web hosts + 2 ISP resolvers · 198.51.100.0/24</text>'
      f'<text x="590" y="81" text-anchor="middle" font-size="11.5" font-weight="700" fill="{TANGERINE}">+ real threat-intel indicators (built-in scenarios)</text></g>')

    # WAN link
    A(f'<line x1="590" y1="92" x2="590" y2="132" stroke="{GRAY}" stroke-width="2" marker-end="url(#ar)"/>')
    A(f'<text x="600" y="116" font-size="11" fill="{GRAY}">WAN {esc(d["nets"]["wan"])} · NAT</text>')

    # ---------------------------------------------------------------- firewall
    A(f'<g><rect x="455" y="132" width="270" height="86" rx="12" fill="url(#g)"/>'
      f'<text x="590" y="159" text-anchor="middle" font-size="15.5" font-weight="900" fill="#fff">EXL-FW1</text>'
      f'<text x="590" y="177" text-anchor="middle" font-size="11" fill="#d9d5ea">Firewall · inter-subnet router · NAT · DHCP relay</text>'
      f'<text x="590" y="197" text-anchor="middle" font-size="11" fill="#fff">e1/1 {esc(d["gw"]["user"])} &#160;·&#160; e1/2 {esc(d["gw"]["server"])}</text>'
      f'<text x="590" y="211" text-anchor="middle" font-size="11" fill="#d9d5ea">e1/3 {esc(d["gw"]["wan"])}</text></g>')

    # inside legs
    A(f'<path d="M455,180 L300,180 L300,250" fill="none" stroke="{CYAN}" stroke-width="2.5" marker-end="url(#ar)"/>')
    A(f'<path d="M725,180 L880,180 L880,250" fill="none" stroke="{PLUM}" stroke-width="2.5" marker-end="url(#ar)"/>')
    A(f'<text x="312" y="172" font-size="11" font-weight="700" fill="{CYAN}">inside-A · user side</text>')
    A(f'<text x="838" y="172" font-size="11" font-weight="700" fill="{PLUM}">inside-B · server side</text>')

    # ---------------------------------------------------------------- user subnet
    A(f'<g><rect x="40" y="250" width="520" height="450" rx="14" fill="#fff" stroke="{CYAN}" stroke-width="2"/>'
      f'<rect x="40" y="250" width="520" height="38" rx="14" fill="{CYAN}"/>'
      f'<rect x="40" y="274" width="520" height="14" fill="{CYAN}"/>'
      f'<text x="58" y="276" font-size="14" font-weight="900" fill="#fff">USER NETWORK</text>'
      f'<text x="542" y="276" text-anchor="end" font-size="13" font-weight="700" fill="#fff" '
      f'font-family="ui-monospace,Menlo,monospace">{esc(d["nets"]["user"])}</text></g>')
    A(f'<text x="58" y="308" font-size="11.5" fill="{GRAY}">{d["n_user"]} addressed interfaces · gateway {esc(d["gw"]["user"])} · access switch {esc(d["switches"][0]["ip"]) if d["switches"] else ""}</text>')

    y = 322
    for g in d["groups"]:
        A(f'<g><rect x="58" y="{y}" width="484" height="46" rx="9" fill="#f7fbfe" stroke="#d6ecfa"/>'
          f'<circle cx="84" cy="{y+23}" r="15" fill="{CYAN}"/>'
          f'<text x="84" y="{y+28}" text-anchor="middle" font-size="13" font-weight="900" fill="#fff">{g["count"]}</text>'
          f'<text x="110" y="{y+20}" font-size="13" font-weight="700" fill="{SAPPHIRE}">{esc(g["label"])}</text>'
          f'<text x="110" y="{y+36}" font-size="11" fill="{GRAY}">{esc(g["note"])}</text>'
          f'<text x="528" y="{y+29}" text-anchor="end" font-size="11.5" fill="{SAPPHIRE}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(g["range"])}</text></g>')
        y += 52

    A(f'<rect x="58" y="{y}" width="484" height="30" rx="8" fill="#f7fbfe" stroke="#bfe3f7"/>'
      f'<text x="72" y="{y+19}" font-size="10" fill="{SAPPHIRE}" font-weight="700">'
      f'Baseline: EXL-SB-02 · {esc(u_pfx)}.37 updates at +5:15, then serves MCP :3000 (plaintext)</text>')

    # ---------------------------------------------------------------- server subnet
    A(f'<g><rect x="620" y="250" width="520" height="450" rx="14" fill="#fff" stroke="{PLUM}" stroke-width="2"/>'
      f'<rect x="620" y="250" width="520" height="38" rx="14" fill="{PLUM}"/>'
      f'<rect x="620" y="274" width="520" height="14" fill="{PLUM}"/>'
      f'<text x="638" y="276" font-size="14" font-weight="900" fill="#fff">SERVER NETWORK</text>'
      f'<text x="1122" y="276" text-anchor="end" font-size="13" font-weight="700" fill="#fff" '
      f'font-family="ui-monospace,Menlo,monospace">{esc(d["nets"]["server"])}</text></g>')
    A(f'<text x="638" y="308" font-size="11.5" fill="{GRAY}">{d["n_server"]} addressed interfaces · gateway {esc(d["gw"]["server"])} · {len(d["servers"])} servers</text>')

    y = 320
    for i, h in enumerate(d["servers"]):
        col = i % 2
        row = i // 2
        x = 638 + col * 250
        yy = y + row * 44
        role = h["role"].split("(")[0].strip()
        role = role if len(role) <= 36 else role[:35].rsplit(" ", 1)[0] + "…"
        A(f'<g><rect x="{x}" y="{yy}" width="238" height="38" rx="8" fill="#fbf6f9" stroke="#e9d3de"/>'
          f'<rect x="{x}" y="{yy}" width="4" height="38" rx="2" fill="{PLUM}"/>'
          f'<text x="{x+14}" y="{yy+16}" font-size="11.5" font-weight="700" fill="{SAPPHIRE}">{esc(h["hostname"])}</text>'
          f'<text x="{x+14}" y="{yy+30}" font-size="10" fill="{GRAY}">{esc(role)}</text>'
          f'<text x="{x+228}" y="{yy+23}" text-anchor="end" font-size="10.5" fill="{PLUM}" '
          f'font-family="ui-monospace,Menlo,monospace">.{esc(h["ip"].rsplit(".",1)[1])}</text></g>')

    # sensor
    sy = y + ((len(d["servers"]) + 1) // 2) * 44 + 6
    if d["sensor"]:
        A(f'<g><rect x="638" y="{sy}" width="488" height="42" rx="9" fill="url(#g)"/>'
          f'<text x="652" y="{sy+18}" font-size="12" font-weight="900" fill="#fff">{esc(d["sensor"]["hostname"])} — sensor</text>'
          f'<text x="652" y="{sy+33}" font-size="10.5" fill="#d9d5ea">mgmt NIC {esc(d["sensor"]["ip"])} · monitoring interfaces passive / unaddressed</text></g>')
        # SPAN feeds
        A(f'<path d="M300,700 L300,734 L882,734 L882,{sy+42}" fill="none" stroke="{TANGERINE}" '
          f'stroke-width="2" stroke-dasharray="6 4" marker-end="url(#arc)"/>')
        _span_fw = ("both firewalls&#8217; inside interfaces (EXL-FW1 + EXL-OTFW1)" if ot
                    else "both firewall inside interfaces")
        A(f'<text x="590" y="757" text-anchor="middle" font-size="11.5" font-weight="700" fill="{TANGERINE}">'
          f'SPAN of {_span_fw} &#8594; capture vantage (inter-subnet traffic seen twice)</text>')
    if ot:
        A(_topology_ot(d))
    A('</svg>')
    return "\n".join(parts)


# Purdue level -> (label, note). The counts are derived from the inventory, never written here,
# so the picture cannot claim assets the capture does not contain.
_OT_BANDS = [
    ("3.5", "Industrial DMZ", "idmz", "the only zone the enterprise ever touches"),
    ("3", "Site operations", "ops", "MES, historian, batch, LIMS, OT domain \u2014 speaks IT, not process"),
    ("2", "Supervisory control", "ot", "SCADA and HMI panels"),
    ("1", "Basic control", "ot", "PLCs, RTUs, safety controllers \u2014 Modbus, DNP3"),
]


def _topology_ot(d):
    """The industrial zone, drawn under the enterprise. Everything here is derived from
    d["ot_levels"] and d["nets"], so it stays in step with what was actually built."""
    lv = d.get("ot_levels") or {}
    n = lambda *keys: sum(len(lv.get(k, [])) for k in keys)
    P2, P3, P35 = d["nets"].get("ot", ""), d["nets"].get("ops", ""), d["nets"].get("idmz", "")
    q = []
    B = q.append
    Y0 = 786
    # Server-network -> OT path: EXL-OTJUMP1 is the only host permitted to originate into OT.
    # Draw it as a dotted magenta line from the jump host's right edge, down the clear right
    # margin (outside every host box and the sensor), then into the OT zone's top edge.
    oj_i = next((i for i, h in enumerate(d.get("servers", []))
                 if h.get("hostname") == "EXL-OTJUMP1"), None)
    if oj_i is not None:
        ox = 638 + (oj_i % 2) * 250          # OTJUMP1 box left (matches the server grid)
        oyy = 320 + (oj_i // 2) * 44
        ox_r, oy_mid = ox + 238, oyy + 19    # right edge, vertical middle
        chan = 1158                          # vertical channel right of every box and the sensor
        entry = 1090                         # where the line enters the OT zone top edge
        turn = 740                           # turn left high in the gap, leaving a real down run
        B(f'<path d="M{ox_r},{oy_mid} L{chan},{oy_mid} L{chan},{turn} L{entry},{turn} '
          f'L{entry},{Y0}" fill="none" stroke="{MAGENTA}" stroke-width="2.5" '
          f'stroke-dasharray="2 4" stroke-linecap="round" marker-end="url(#arm)"/>')
        B(f'<text x="{entry - 10}" y="{turn + 26}" text-anchor="end" font-size="11" '
          f'font-weight="700" fill="{MAGENTA}">EXL-OTJUMP1 → OT (only permitted initiator)</text>')
    B(f'<rect x="40" y="{Y0}" width="1100" height="436" rx="14" fill="#fdf2f8" '
      f'stroke="{MAGENTA}" stroke-width="2"/>')
    B(f'<rect x="40" y="{Y0}" width="1100" height="38" rx="14" fill="{MAGENTA}"/>'
      f'<rect x="40" y="{Y0 + 24}" width="1100" height="14" fill="{MAGENTA}"/>')
    B(f'<text x="58" y="{Y0 + 26}" font-size="14" font-weight="900" fill="#fff">'
      f'INDUSTRIAL ZONE \u2014 PURDUE LEVELS 3.5 TO 0</text>')
    B(f'<text x="1122" y="{Y0 + 26}" text-anchor="end" font-size="11.5" fill="#fff">'
      f'{n("3.5", "3", "2", "1", "bms", "iot", "infra")} assets \u00b7 optional</text>')
    counts = {"3.5": n("3.5"), "3": n("3"), "2": n("2"), "1": n("1", "bms", "iot", "infra")}
    subs = {"3.5": P35, "3": P3, "2": P2, "1": P2}
    y = Y0 + 50
    for lvl, label, _key, note in _OT_BANDS:
        B(f'<rect x="58" y="{y}" width="1064" height="72" rx="9" fill="#fff" '
          f'stroke="{MAGENTA}" stroke-width="1.4"/>')
        B(f'<rect x="74" y="{y + 16}" width="64" height="40" rx="8" fill="{MAGENTA}"/>')
        B(f'<text x="106" y="{y + 30}" text-anchor="middle" font-size="8.5" font-weight="700" '
          f'fill="#fff">LEVEL</text>')
        B(f'<text x="106" y="{y + 48}" text-anchor="middle" font-size="15" font-weight="900" '
          f'fill="#fff">{lvl}</text>')
        B(f'<text x="154" y="{y + 28}" font-size="13" font-weight="900" fill="{MAGENTA}">{esc(label)}</text>')
        B(f'<text x="154" y="{y + 46}" font-size="10.5" fill="{GRAY}">{esc(note)}</text>')
        B(f'<text x="154" y="{y + 62}" font-size="10" font-weight="700" fill="{SAPPHIRE}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(subs[lvl])}</text>')
        B(f'<text x="1104" y="{y + 40}" text-anchor="end" font-size="20" font-weight="900" '
          f'fill="{MAGENTA}">{counts[lvl]}</text>')
        B(f'<text x="1104" y="{y + 56}" text-anchor="end" font-size="9" fill="{GRAY}">hosts</text>')
        y += 78
        if lvl == "3.5":
            # The industrial (lower) firewall of the dual-firewall IDMZ sandwich: EXL-FW1
            # (enterprise) sits above the IDMZ, EXL-OTFW1 (industrial) below it. Anything from
            # the enterprise reaching a cell/area device end-to-end crosses BOTH firewalls.
            B(f'<rect x="58" y="{y}" width="1064" height="34" rx="8" fill="{MAGENTA}"/>')
            B(f'<rect x="74" y="{y + 8}" width="26" height="18" rx="4" fill="#fff"/>')
            B(f'<text x="87" y="{y + 21}" text-anchor="middle" font-size="10.5" font-weight="900" '
              f'fill="{MAGENTA}">FW</text>')
            B(f'<text x="112" y="{y + 15}" font-size="11.5" font-weight="900" fill="#fff">'
              f'EXL-OTFW1 \u00b7 INDUSTRIAL FIREWALL</text>')
            B(f'<text x="112" y="{y + 28}" font-size="9.5" fill="#fbdcee">'
              f'IDMZ (L3.5) \u2194 OT (L3\u20131) \u00b7 inside-C / -D / -E \u00b7 '
              f'enterprise\u2192cell crosses EXL-FW1 + EXL-OTFW1 (TTL \u22122, no end-to-end through the IDMZ)</text>')
            B(f'<text x="1104" y="{y + 21}" text-anchor="end" font-size="9.5" fill="#fbdcee">'
              f'the IDMZ sits between the two firewalls</text>')
            y += 42
    B(f'<text x="58" y="{y + 16}" font-size="10.5" fill="{GRAY}">'
      f'Level 0 \u2014 sensors, actuators and drives \u2014 is hardwired to its PLC and deliberately '
      f'never reaches the wire. Levels 4 and 5 are the enterprise above.</text>')
    return "\n".join(q)


# ---------------------------------------------------------------------------------------
# A second diagram, kept deliberately small: it exists to prove the framework seam and to
# be the thing you copy when adding scenario diagrams. It shares every bit of chrome with
# the topology page and hard-codes nothing — the bars come straight from the registry.
# ---------------------------------------------------------------------------------------
DAY_START_MIN, DAY_END_MIN = 5 * 60, 21 * 60          # the 05:00–21:00 capture window


# ============================================================ baseline protocol mix
# Activity groups in a FIXED order. Sorting by share would reshuffle the diagram between builds
# and make two renders impossible to compare; a stable order lets the eye go straight to the
# row it cares about. Each group names the engine tags it folds in, the protocols those put on
# the wire, and a filter that isolates the group in a capture.

# The same measurement, with the OT subnet on. TWO tables rather than one plus a caveat:
# BASELINE_MIX describes a capture with no industrial zone and BASELINE_MIX_OT one with it,
# and baseline_mix() picks by whether the render has an OT network. A single table would
# render perfectly and be wrong, silently, for whichever case it was not measured from.
# Regenerate BOTH together -- any change to baseline traffic invalidates the pair, and the
# OT one is the one nobody will think to re-cut because OT is off by default:
#     python3 opengenerator_build.py --scale 1.0 --no-modules --ot-net --out /tmp/m.pcap \
#             --no-certs --no-iocs --stats /tmp/m.json
# Measured 2026-10-03: 13,992,875 packets / 8,552 MB, of which the OT-tagged industrial zone
# (modbus/dnp3/bacnet and every ot-* tag) is 2,800,340 packets (20.0%) and 1,069 MB (12.5%).
# This build carries the dual-firewall IDMZ sandwich (EXL-FW1 + EXL-OTFW1) and its management
# plane; regenerate with the --stats command above and sum the stats JSON.
BASELINE_MIX_OT = {
    "aborted": (94, 21972),
    "ad-repl": (4245, 1894295),
    "admin-auth": (1005, 194697),
    "arp": (31, 1302),
    "backup": (515928, 527993444),
    "bacnet": (53550, 3346780),
    "capwap": (103146, 6451904),
    "cldap": (190, 39494),
    "cloud": (629688, 533967051),
    "cloud-media": (376451, 374950782),
    "conncheck": (43901, 4034314),
    "dhcp": (708, 151359),
    "dnp3": (140126, 10690946),
    "dns": (24574, 1808357),
    "dns-noise": (25252, 2221376),
    "dns-nx": (1564, 153401),
    "fs-smb": (2480910, 2422299571),
    "genai": (288207, 177096552),
    "http": (60382, 28737496),
    "https": (433909, 351562921),
    "icmp": (426, 28900),
    "intra-http": (77925, 37154439),
    "kerberos": (19559, 3791098),
    "kerberos-fail": (611, 59291),
    "kerberos-lockout": (364, 36776),
    "ldap": (9534, 2114332),
    "ldap-fail": (43, 2793),
    "lob-http": (113580, 54027294),
    "mcp": (4773, 914745),
    "mcp-cloud": (1600, 280305),
    "mdns": (668, 221568),
    "modbus": (1566550, 100124136),
    "name-noise": (1089, 110752),
    "nbns": (450, 63900),
    "ntlm": (648, 72016),
    "ntlm-fail": (63, 6971),
    "ntp": (36224, 2220384),
    "ocsp": (9120, 1257837),
    "os-update": (320857, 324839636),
    "ot-auth": (216, 33497),
    "ot-backup": (348563, 350903273),
    "ot-brokered": (185370, 163477460),
    "ot-egress": (23068, 21677200),
    "ot-files": (74183, 72317583),
    "ot-hist": (46145, 35796010),
    "ot-ingress": (236803, 210716066),
    "ot-mes": (2710, 1415892),
    "ot-mesweb": (5035, 2300716),
    "ot-mgmt": (19448, 4440065),
    "ot-rdp": (98573, 91432485),
    "patch": (641297, 649223232),
    "peer-media": (143730, 30744460),
    "peer-smb": (47536, 43991874),
    "print": (49717, 32049291),
    "prn-job": (134347, 86901619),
    "prn-snmp": (806, 119261),
    "rdp": (73536, 67960638),
    "refused": (2662, 137256),
    "saas": (253632, 230149398),
    "sb-update": (44110, 42762761),
    "sip": (996, 385912),
    "smb": (721689, 683598212),
    "snmp": (8024, 1321910),
    "ssh": (8970, 2228032),
    "svc": (2662, 2031412),
    "syslog": (46292, 14863257),
    "tds": (160, 16200),
    "update": (3990, 3198438),
    "voip": (779000, 166428371),
    "voip-call": (2640748, 564522644),
    "voip-reg": (912, 362144),
}

MIX_GROUPS = [
    ("auth", "Authentication & directory", SAPPHIRE,
     ("kerberos", "kerberos-fail", "kerberos-lockout", "ldap", "ldap-fail", "cldap",
      "ntlm", "ntlm-fail", "admin-auth", "svc", "ad-repl"),
     "Kerberos, LDAP, CLDAP, NTLM, DCE/RPC replication",
     "kerberos || ldap || cldap || ntlmssp"),
    ("discovery", "Name resolution & discovery", GRAY,
     ("dns", "dns-noise", "dns-nx", "mdns", "nbns", "name-noise", "arp", "dhcp",
      "conncheck", "ocsp"),
     "DNS, mDNS, LLMNR, NBNS, ARP, DHCP, OCSP, connectivity probes",
     "dns || mdns || llmnr || nbns || arp || dhcp"),
    ("browse", "Web browsing", CYAN,
     ("https", "http"),
     "TLS 1.2, HTTP/1.1, page fan-out to CDN/font/analytics hosts",
     "tls.handshake.extensions_server_name || http.request"),
    ("intranet", "Internal web apps", CYAN,
     ("intra-http", "lob-http"),
     "Plain HTTP to intranet and line-of-business servers inside the network",
     ""),
    ("cloud", "Consumer cloud & SaaS", CYAN,
     ("cloud", "cloud-media", "saas"),
     "TLS to streaming, social and SaaS platforms; ranged media segments",
     'tls.handshake.extensions_server_name matches "spotify|youtube|googlevideo|apple|'
     'instagram|facebook|fbcdn|netflix|tiktok|reddit|linkedin|slack|dropbox|zoom"'),
    ("genai", "Generative AI", TANGERINE,
     ("genai",),
     "TLS; large POST bodies answered by streamed server-sent events",
     'tls.handshake.extensions_server_name matches "anthropic|claude|openai|chatgpt|gemini|'
     'x\\\\.ai|grok|copilot|perplexity|mistral|huggingface"'),
    ("files", "File & print", PLUM,
     ("smb", "print", "backup", "peer-smb", "fs-smb", "prn-job", "prn-snmp"),
     "SMB2/NBSS, spooler, peer share access",
     "smb2 || nbss"),
    ("voice", "Voice & video", PLUM,
     ("voip", "sip", "peer-media", "voip-call", "voip-reg"),
     "SIP signalling, RTP/RTCP media, peer-to-peer call legs",
     "rtp || rtcp || sip"),
    ("updates", "OS & software updates", SAPPHIRE,
     ("os-update", "patch", "update", "sb-update"),
     "HTTPS metadata scans, cleartext HTTP ranged payload downloads",
     'http.user_agent contains "Update-Agent" || http.user_agent contains "APT-HTTP"'),
    ("iot", "Smart boards & agents", TANGERINE,
     ("mcp", "mcp-cloud"),
     "MCP over HTTP/3000, vendor cloud link",
     "tcp.port == 3000"),
    ("mgmt", "Management & monitoring", GRAY,
     ("snmp", "syslog", "ntp", "ssh", "rdp", "capwap", "icmp", "tds"),
     "SNMP, syslog, NTP, SSH, RDP, CAPWAP, ICMP, TDS",
     "snmp || syslog || ntp || ssh || rdp || capwap || icmp || tds"),
    # Two OT groups, not one, because they are two different kinds of traffic and folding them
    # together hides the point: the cell/area zone averages 77 bytes per packet, the bridge 795.
    # MIX_GROUPS folds engine TAGS, so anything not claimed here lands in "Other" -- check that
    # bucket after adding traffic.
    ("ot-process", "OT process control", MAGENTA,
     ("modbus", "dnp3", "bacnet"),
     "Modbus/TCP, DNP3 and BACnet/IP -- periodic polling, packet-dense and byte-light",
     "modbus || dnp3 || bacapp"),
    ("ot-bridge", "OT operations & bridge", MAGENTA,
     ("ot-mes", "ot-hist", "ot-mesweb", "ot-files", "ot-rdp", "ot-auth", "ot-backup",
      "ot-mgmt", "ot-ingress", "ot-brokered", "ot-egress"),
     "Purdue levels 3 and 3.5: SQL, SMB, RDP, HTTPS, Kerberos -- IT protocols, in the OT zone",
     "ip.addr == 10.10.40.0/24 || ip.addr == 10.10.50.0/24"),
    ("failed", "Failed connections", PLUM,
     ("refused", "aborted"),
     "SYN answered with RST/ACK, mid-stream resets",
     "tcp.flags.reset == 1"),
]

# A measured baseline from a real generated capture — NOT hand-written. Regenerate with:
#     python3 opengenerator_build.py --scale 1.0 --no-modules --out /tmp/m.pcap \
#             --no-certs --no-iocs --stats /tmp/m.json
# then paste the tag table below. The app prefers live stats from your most recent
# baseline-only generation when it has them; this is the fallback so the diagram renders
# instantly, and before anything has been generated at all.
# Measured 2026-10-03 at scale 1.0: 11,148,909 packets / 7,571 MB (OT subnet off).
MEASURED_SCALE = "1.0"
BASELINE_MIX = {
    "aborted": (130, 31476),
    "ad-repl": (4302, 1918952),
    "admin-auth": (849, 165786),
    "arp": (20, 840),
    "backup": (515937, 527995384),
    "capwap": (103200, 6454080),
    "cldap": (190, 39476),
    "cloud": (645564, 551309849),
    "cloud-media": (506917, 503838921),
    "conncheck": (44566, 4088554),
    "dhcp": (838, 177615),
    "dns": (22808, 1672788),
    "dns-noise": (24664, 2180961),
    "dns-nx": (1672, 164748),
    "fs-smb": (2343385, 2286707212),
    "genai": (199743, 123657580),
    "http": (61516, 29237966),
    "https": (447777, 361518579),
    "icmp": (398, 27212),
    "intra-http": (78372, 37397499),
    "kerberos": (20359, 3919507),
    "kerberos-fail": (953, 93532),
    "kerberos-lockout": (274, 27604),
    "ldap": (9729, 2136308),
    "ldap-fail": (43, 2796),
    "lob-http": (101322, 48331613),
    "mcp": (4483, 860480),
    "mcp-cloud": (1644, 283404),
    "mdns": (671, 222626),
    "name-noise": (1078, 110735),
    "nbns": (450, 63900),
    "ntlm": (582, 64789),
    "ntlm-fail": (69, 7223),
    "ntp": (11452, 771576),
    "ocsp": (9240, 1233209),
    "os-update": (395086, 403067187),
    "patch": (731475, 742441359),
    "peer-media": (70974, 15180868),
    "peer-smb": (37766, 35093123),
    "print": (46718, 30140887),
    "prn-job": (142406, 91186275),
    "prn-snmp": (736, 108651),
    "rdp": (52164, 47754620),
    "refused": (2766, 141804),
    "saas": (268412, 244120527),
    "sb-update": (39887, 38520242),
    "sip": (1018, 386836),
    "smb": (707372, 670409522),
    "snmp": (8014, 1321494),
    "ssh": (19355, 4686485),
    "svc": (2674, 2031918),
    "syslog": (45459, 14767897),
    "tds": (160, 16200),
    "update": (5390, 4475640),
    "voip": (877276, 187409373),
    "voip-call": (2527710, 540357779),
    "voip-reg": (894, 363412),
}


def _wrap(text, chars):
    """Greedy word wrap to `chars` per line. SVG has no flow layout, so lines are explicit.

    Companion to _fit(), which truncates a single line; this one keeps all the words and
    spends vertical space instead.
    """
    words, lines, cur = text.split(), [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if len(trial) <= chars or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def _fit(text, px, font_px):
    """Trim `text` to fit `px` at `font_px`, breaking on a word boundary.

    SVG has no text metrics, so this approximates: the brand face averages a little under half
    an em for mixed-case text. Cutting mid-word and appending a full stop looks like a typo, so
    it breaks on a space and uses a real ellipsis.
    """
    limit = int(px / (font_px * 0.47))
    if len(text) <= limit:
        return text
    cut = text[:limit]
    sp = cut.rfind(" ")
    return (cut[:sp] if sp > limit * 0.6 else cut).rstrip(" ,;") + "\u2026"


def _mix_rows(stats):
    """Fold raw engine tag counts into the fixed activity groups."""
    seen, rows = set(), []
    for key, label, accent, tags, protos, filt in MIX_GROUPS:
        pk = sum(stats.get(t, (0, 0))[0] for t in tags)
        by = sum(stats.get(t, (0, 0))[1] for t in tags)
        seen.update(t for t in tags if t in stats)
        rows.append(dict(key=key, label=label, accent=accent, packets=pk, bytes=by,
                         protos=protos, filt=filt))
    op = sum(v[0] for k, v in stats.items() if k not in seen)
    ob = sum(v[1] for k, v in stats.items() if k not in seen)
    if op:
        rows.append(dict(key="other", label="Other", accent=GRAY, packets=op, bytes=ob,
                         protos=", ".join(sorted(k for k in stats if k not in seen)), filt=""))
    return rows


@register("baseline-mix", "Baseline protocol mix",
          "What a normal business day puts on the wire before any scenario is added", order=30)
def baseline_mix(c):
    # Which measured table, chosen by the capture rather than by the reader: a render with an
    # OT network is a different baseline from one without, and plotting the wrong one produces
    # a chart that is entirely plausible and entirely wrong. Live stats from the most recent
    # baseline-only run still beat both.
    ot = bool(getattr(c, "ot_nets", None))
    stats = getattr(c, "measured", None) or (BASELINE_MIX_OT if ot else BASELINE_MIX)
    scale = getattr(c, "measured_scale", None) or MEASURED_SCALE
    which = "with the OT subnet on" if ot else "with no OT subnet"
    rows = _mix_rows(stats)
    tp = sum(r["packets"] for r in rows) or 1
    tb = sum(r["bytes"] for r in rows) or 1
    # Bars run on a FIXED 0-50% scale, not normalised to the largest row. Normalising meant the
    # biggest group always drew full width whatever its real share, so 24.1% of packets and
    # 28.8% of bytes rendered as identical bars and the chart carried no quantitative meaning.
    # A fixed scale shared by both columns makes the two directly comparable and the lengths
    # actually mean something.
    AXIS_MAX = 50.0

    W, rowh = 1180, 42
    H = 146 + rowh * len(rows)
    P = []
    A = P.append
    A(_svg_open(W, H, "Baseline protocol mix"))
    A("</defs>")
    # Geometry. The label column has to hold both the group name and its protocol line; at 250
    # the longest protocol string (66 characters) ran clean under the packets bars. The column
    # is sized to the text rather than the text truncated to the column, with the bars giving
    # up the width — the bars are comparative, so a shorter bar costs nothing.
    lab_w, gap, bar_w = 342, 26, 292
    x_pk = lab_w + gap
    x_by = x_pk + bar_w + 96 + gap
    _panel_title(A, 14, 30, "BASELINE PROTOCOL MIX",
                 "normal business day, no incident modules — measured at scale " + str(scale))
    A('<text x="%d" y="72" font-size="12" font-weight="700" fill="%s" font-style="normal">Share of packets</text>' % (x_pk, SAPPHIRE))
    A('<text x="%d" y="72" font-size="12" font-weight="700" fill="%s" font-style="normal">Share of bytes</text>' % (x_by, PLUM))
    A('<line x1="14" y1="82" x2="%d" y2="82" stroke="#e4e4e8"/>' % (W - 14))

    # a real axis, so the reader can see what a bar length is worth
    def axis(x0, colour):
        for pct in (0, 10, 20, 30, 40, 50):
            gx = x0 + bar_w * pct / AXIS_MAX
            A('<line x1="%.1f" y1="88" x2="%.1f" y2="%d" stroke="#ececf0" stroke-width="1"/>'
              % (gx, gx, 96 + rowh * len(rows)))
            A('<text x="%.1f" y="94" font-size="9" fill="%s" text-anchor="middle">%d%%</text>'
              % (gx, GRAY, pct))
    axis(x_pk, SAPPHIRE)
    axis(x_by, PLUM)
    y = 118
    for r in rows:
        pkp, byp = 100.0 * r["packets"] / tp, 100.0 * r["bytes"] / tb
        A('<rect x="14" y="%d" width="6" height="20" rx="3" fill="%s"/>' % (y - 13, r["accent"]))
        A('<text x="30" y="%d" font-size="14.5" font-weight="700" fill="#1c1830">%s</text>' % (y, esc(r["label"])))
        A('<text x="30" y="%d" font-size="10" fill="%s">%s</text>'
          % (y + 15, GRAY, esc(_fit(r["protos"], lab_w - 42, 10))))
        w1 = max(1.5, bar_w * min(pkp, AXIS_MAX) / AXIS_MAX)
        A('<rect x="%d" y="%d" width="%d" height="18" rx="4" fill="#f1f1f5"/>' % (x_pk, y - 12, bar_w))
        A('<rect x="%d" y="%d" width="%.1f" height="18" rx="%.1f" fill="%s" opacity="0.88"/>' % (x_pk, y - 12, w1, min(4.0, w1 / 2), SAPPHIRE))
        A('<text x="%d" y="%d" font-size="13" font-weight="700" fill="%s">%.1f%%</text>' % (x_pk + bar_w + 10, y + 2, SAPPHIRE, pkp))
        A('<text x="%d" y="%d" font-size="10.5" fill="%s">%.2fM</text>' % (x_pk + bar_w + 58, y + 2, GRAY, r["packets"] / 1e6))
        w2 = max(1.5, bar_w * min(byp, AXIS_MAX) / AXIS_MAX)
        A('<rect x="%d" y="%d" width="%d" height="18" rx="4" fill="#f1f1f5"/>' % (x_by, y - 12, bar_w))
        A('<rect x="%d" y="%d" width="%.1f" height="18" rx="%.1f" fill="%s" opacity="0.88"/>' % (x_by, y - 12, w2, min(4.0, w2 / 2), PLUM))
        A('<text x="%d" y="%d" font-size="13" font-weight="700" fill="%s">%.1f%%</text>' % (x_by + bar_w + 10, y + 2, PLUM, byp))
        A('<text x="%d" y="%d" font-size="10.5" fill="%s">%.2fG</text>' % (x_by + bar_w + 58, y + 2, GRAY, r["bytes"] / 1e9))
        y += rowh
    A("</svg>")

    top_p = max(rows, key=lambda r: r["packets"])
    top_b = max(rows, key=lambda r: r["bytes"])
    trows = "".join(
        '<tr><td>%s</td><td class="svc">%s</td><td class="m">%s</td><td class="m">%.1f%%</td>'
        '<td class="m">%s MB</td><td class="m">%.1f%%</td></tr>'
        % (esc(r["label"]), esc(r["protos"]), format(r["packets"], ","),
           100.0 * r["packets"] / tp, format(int(r["bytes"] / 1e6), ","), 100.0 * r["bytes"] / tb)
        for r in rows)
    return {
        "svg": "".join(P),
        "kpis": [("%.2fM" % (tp / 1e6), "Packets", "mono"),
                 ("%.2f GB" % (tb / 1e9), "Volume", "mono"),
                 ("%d of %d" % (len([r for r in rows if r["packets"]]), len(rows)), "Groups with traffic"),
                 (top_p["label"], "Most packets"),
                 (top_b["label"], "Most bytes"),
                 (str(scale), "Measured at scale", "mono"),
                 (which, "Baseline measured")],
        "sections": [
            ("The mix", '<table><thead><tr><th>Activity</th><th>On the wire</th><th>Packets</th>'
                        '<th>%</th><th>Bytes</th><th>%</th></tr></thead><tbody>' + trows + '</tbody></table>'),
            ("Finding it in a capture",
             _filters_table([(r["label"], r["filt"], r["protos"]) for r in rows if r["filt"]])),
        ],
        "notes": [
            ("", "Baseline only",
             "No incident modules are included. This is what every capture contains regardless of "
             "which scenarios are selected — the floor that deviations stand out against."),
            ("warn", "Packets and bytes disagree, deliberately",
             "File sharing and voice make up most packets, while file sharing, cloud and update "
             "payloads make up most of the volume (voice is many small packets). A mix shown in "
             "one dimension only misleads whoever reads it."),
            ("", "Fixed order, not ranked",
             "Groups stay in the same order between builds so two renders can be compared; sorting "
             "by share would reshuffle the page every time the traffic moves."),
        ],
    }


_TL_COL = {"IR": "#7C3AED", "CAMPAIGN": "#0E7490", "CUSTOM": SAPPHIRE}
_TL_NAMES = [("NDR", "NDR security detections"), ("NPM", "NPM performance faults"),
             ("CRP", "CRP crypto posture"), ("IR", "IR incident replay"),
             ("CAMPAIGN", "CAMPAIGN threat-indicator build"), ("CUSTOM", "CUSTOM imported pcap")]


def _clock(mins):
    return "%02d:%02d" % (mins // 60, mins % 60)


@register("timeline", "Scenario timeline",
          "When each incident scenario fires across the synthetic business day", order=20)
def timeline(c):
    mods = sorted(c.modules, key=lambda m: ({"NDR": 0, "NPM": 1, "CRP": 2, "IR": 3}.get(m["prefix"], 4),
                                            m["start"], m["name"]))
    if not mods:
        return {"svg": '<svg viewBox="0 0 100 20"><text x="4" y="14" font-size="9" '
                       'fill="#4B5563">incident registry unavailable</text></svg>'}

    from netgen import incidents as _INC
    # Only show the OT baseline row when the render actually has an OT network, or the
    # diagram claims traffic the capture does not contain.
    base = _INC.baseline_modules(ot=bool(getattr(c, "ot_nets", None)))
    L, R, TOP, ROW = 300, 1150, 72, 19                # label gutter, right edge, header, row pitch
    BASE_H = (len(base) * ROW + 14) if base else 0
    height = TOP + BASE_H + len(mods) * ROW + 62
    span = DAY_END_MIN - DAY_START_MIN
    x_of = lambda mins: L + (R - L) * (mins - DAY_START_MIN) / span
    col_of = lambda p: _TL_COL.get(p) or c.cat_color(p)
    ot_only = lambda m: "requires the OT subnet" in (m.get("note") or "").lower()
    bot = TOP + BASE_H + len(mods) * ROW           # bottom of the plot area

    P = []
    A = P.append
    A(f'<svg viewBox="0 0 1180 {height}" xmlns="http://www.w3.org/2000/svg" role="img" '
      f'aria-label="Timeline of {len(mods)} incident scenarios across the capture, 05:00 to 21:00 local time (Start +0h to +16h)">')

    # legend: one swatch per category, then the two bar styles
    lx = 8
    A(f'<text x="{lx}" y="14" font-size="10" font-weight="700" fill="{GRAY}">Colour key</text>')
    lx = 84
    for key, label in _TL_NAMES:
        A(f'<rect x="{lx}" y="5" width="22" height="10" rx="5" fill="{col_of(key)}"/>'
          f'<text x="{lx + 28}" y="14" font-size="10" fill="#1c1830">{label}</text>')
        lx += 36 + len(label) * 5.3
    A(f'<rect x="{lx}" y="5" width="22" height="10" rx="5" fill="#15803D" opacity=".55"/>'
      f'<text x="{lx + 28}" y="14" font-size="10" fill="#1c1830">BASE always-on baseline</text>')
    A(f'<rect x="6" y="23" width="26" height="12" rx="6" fill="none" stroke="{MAGENTA}" stroke-width="1.8"/><rect x="8" y="25" width="22" height="8" rx="4" fill="#9ca3af"/>'
      f'<text x="36" y="33" font-size="10" fill="#1c1830">blue outline: needs the optional OT subnet</text>'
      f'<rect x="330" y="24" width="22" height="10" rx="5" fill="#e8e9ed" stroke="#d2d3d9" stroke-dasharray="3 2"/>'
      f'<text x="358" y="33" font-size="10" fill="#1c1830">grey: excluded from this build</text>'
      f'<text x="560" y="33" font-size="10" fill="#1c1830">Bar = scheduled window (hover for detail). Times are the capture clock, America/New_York.</text>')

    # shaded day phases, drawn first so bars sit on top
    for a, b, fill, label in ((7 * 60, 15 * 60, "#eef6fc", "BUSINESS HOURS 07:00–15:00 (Start +2h → +10h)"),
                              (15 * 60, 19 * 60, "#f9f1f6", "ADMIN WINDOW 15:00–19:00 (+10h → +14h)")):
        A(f'<rect x="{x_of(a):.1f}" y="{TOP - 16}" width="{x_of(b) - x_of(a):.1f}" '
          f'height="{BASE_H + len(mods) * ROW + 16}" fill="{fill}"/>')
        A(f'<text x="{(x_of(a) + x_of(b)) / 2:.1f}" y="{TOP - 22}" text-anchor="middle" '
          f'font-size="10" font-weight="700" fill="{GRAY}">{label}</text>')

    # hour grid + two-line axis: relative offset and clock time
    for hh in range(5, 22):
        x = x_of(hh * 60)
        A(f'<line x1="{x:.1f}" y1="{TOP - 16}" x2="{x:.1f}" y2="{bot}" '
          f'stroke="{"#cfd0d8" if hh % 2 else "#eef0f3"}" stroke-width="1"/>')
        if hh % 2 == 1:
            A(f'<text x="{x:.1f}" y="{bot + 14}" text-anchor="middle" font-size="10" font-weight="700" '
              f'fill="{GRAY}">+{hh - 5}h</text>'
              f'<text x="{x:.1f}" y="{bot + 27}" text-anchor="middle" font-size="9.5" fill="{GRAY}">{hh:02d}:00</text>')
    A(f'<text x="{L - 22}" y="{bot + 14}" text-anchor="end" font-size="9.5" fill="{GRAY}">offset from capture start</text>'
      f'<text x="{L - 22}" y="{bot + 27}" text-anchor="end" font-size="9.5" fill="{GRAY}">clock time (local, 24-hour)</text>')
    A(f'<text x="{(L + R) / 2:.0f}" y="{bot + 46}" text-anchor="middle" font-size="10" fill="{GRAY}">'
      f'Every scenario window is fixed in the capture clock; Start = 05:00 on the capture day.</text>')

    # baseline traffic first, in its own style: always present, never selectable
    for i, m in enumerate(base):
        y = TOP + i * ROW
        acc = m.get("accent", CYAN)
        A(f'<text x="8" y="{y + 12}" font-size="9" font-weight="900" fill="{acc}">BASE</text>')
        A(f'<text x="70" y="{y + 12}" font-size="10" fill="{acc}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(m["name"])}</text>')
        x1, x2 = x_of(m["start"]), x_of(m["end"])
        A(f'<rect x="{x1:.1f}" y="{y + 3}" width="{max(3.0, x2 - x1):.1f}" height="11" rx="5.5" '
          f'fill="{acc}" opacity=".55"/>')
        A(f'<rect x="{x1:.1f}" y="{y + 3}" width="{max(3.0, x2 - x1):.1f}" height="11" rx="5.5" '
          f'fill="none" stroke="{acc}" stroke-width="1.2"><title>{esc(m["title"])} — {esc(m["window"])}</title></rect>')
        A(f'<text x="{x1 + 6:.1f}" y="{y + 12}" font-size="8" font-weight="700" fill="#fff">'
          f'baseline from {_clock(m["start"])} · not selectable</text>')
    if base:
        A(f'<line x1="8" y1="{TOP + len(base) * ROW + 5}" x2="{R}" y2="{TOP + len(base) * ROW + 5}" '
          f'stroke="#e4e4e8"/>')

    # one bar per scenario
    prev_cat = None
    for i, m in enumerate(mods):
        y = TOP + BASE_H + i * ROW
        col = col_of(m["prefix"])
        on = m["name"] in c.selected
        if m["prefix"] != prev_cat:
            if prev_cat is not None:
                A(f'<line x1="8" y1="{y - 1}" x2="{R}" y2="{y - 1}" stroke="#e4e4e8"/>')
            A(f'<text x="8" y="{y + 12}" font-size="9" font-weight="900" fill="{col}">{esc(m["prefix"])}</text>')
            prev_cat = m["prefix"]
        A(f'<text x="70" y="{y + 12}" font-size="10" fill="{SAPPHIRE if on else "#9ca3af"}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(m["name"])}</text>')
        x1, x2 = x_of(m["start"]), x_of(m["end"])
        w = max(3.0, x2 - x1)
        A(f'<rect x="{x1:.1f}" y="{y + 3}" width="{w:.1f}" height="11" rx="5.5" '
          f'fill="{col if on else "#e8e9ed"}"><title>{esc(m["title"])} — {_clock(m["start"])}–{_clock(m["end"])} ({esc(m["window"])})</title></rect>')
        if not on:
            A(f'<rect x="{x1:.1f}" y="{y + 3}" width="{w:.1f}" height="11" rx="5.5" fill="none" '
              f'stroke="#d2d3d9" stroke-dasharray="3 2"/>')
        elif ot_only(m):
            A(f'<rect x="{x1 - 2:.1f}" y="{y + 1}" width="{w + 4:.1f}" height="15" rx="7.5" fill="none" '
              f'stroke="{MAGENTA}" stroke-width="1.8"/>')
    A('</svg>')

    n_on = sum(1 for m in mods if m["name"] in c.selected)
    by = {}
    for m in mods:
        if m["name"] in c.selected:
            by[m["prefix"]] = by.get(m["prefix"], 0) + 1
    rows = "".join(
        f'<tr><td class="m nw">{esc(m["name"])}</td><td>{esc(m["prefix"])}</td>'
        f'<td class="m ip nw">{_clock(m["start"])}–{_clock(m["end"])}<br>'
        f'<span style="font-weight:400;color:#4B5563">{esc(m["window"])}</span></td>'
        f'<td>{esc(m["title"])}</td>'
        f'<td class="svc">{esc(m["note"])}</td></tr>'
        for m in mods if m["name"] in c.selected)
    return {
        "svg": "\n".join(P),
        "kpis": [((f'{n_on} + {len(base)}') if base else n_on, "Scenarios + always-on baseline"),
                 (by.get("NDR", 0), "NDR security"),
                 (by.get("NPM", 0), "NPM performance"),
                 (by.get("CRP", 0), "CRP crypto"),
                 (by.get("IR", 0), "IR incident replay"),
                 ("05:00 → 21:00", "Capture window (ET)", "mono"),
                 ("07:00 → 15:00", "Business hours", "mono")],
        "sections": [("Scenarios included",
                      '<table><thead><tr><th>Module</th><th>Cat</th><th>Clock (offset)</th>'
                      f'<th>Scenario</th><th>What it generates</th></tr></thead><tbody>{rows}</tbody></table>')],
        "notes": [
            ("", "Reading the bars",
             "Each bar is the window a module schedules its traffic into, taken live from the incident "
             "registry. Position is the capture clock (05:00–21:00 on the capture day); \"Start +2h\" means "
             "two hours after 05:00. Bars do not show intensity: a module may be quiet for most of its window."),
            ("", "The BASE row is not a module",
             "Baseline traffic is part of the normal day and is always present, so it has no checkbox and "
             "cannot be excluded. It is drawn because the timeline should show everything in the capture."),
            ("", "Why the NDR cluster overlaps",
             "The actor kill chains all run 13:00 → 14:45 (Start +8h → +9:45) and compose the same technique "
             "builders internally, so they deliberately overlap; each is self-contained and can be built on its own."),
            ("warn", "CAMPAIGN and CUSTOM only run when supplied",
             "campaign and custom-import are shown with their default windows but generate nothing unless a "
             "campaign or an imported pcap recipe is provided. Performance (NPM) modules follow healthy, "
             "degrade, recover, so a metric graph shows a step change rather than a flat anomaly."),
        ],
    }


# ---------------------------------------------------------------------------------------
# SCENARIO DIAGRAM: ndr-recon. Registered with scenario="ndr-recon", so it stays out of the
# top-level picker and instead lights up that scenario's Visualize button in the GUI.
# Everything it draws comes from netgen.incidents (RECON_PORTS / RECON_OPEN / RECON_PHASES)
# and the live inventory — nothing about the attack is restated here.
# ---------------------------------------------------------------------------------------
@register("ndr-recon", "Internal reconnaissance",
          "Host sweep, port scan, LDAP dump and share enumeration from one workstation",
          order=100, scenario="ndr-recon")
def ndr_recon_diagram(c):
    from netgen import incidents as INC
    inc = INC.REGISTRY["ndr-recon"]
    (h1, m1), (h2, m2) = inc.window
    w_start, w_end = h1 * 60 + m1, h2 * 60 + m2
    span = (w_end - w_start) * 60                      # window length in seconds
    d = c.data
    atk = c.host(INC.ATTACKER_WS)
    atk_ip = atk["ip"] if atk else "?"
    # Two DIFFERENT host sets, exactly as the builder uses them:
    #   the ICMP sweep hits every server-subnet host except the firewall,
    #   the SYN scan and share enumeration hit only INC.VICTIM_SERVERS.
    swept = [h for h in d["hosts"]
             if h["subnet"] == d["nets"]["server"] and h["hostname"] != "EXL-FW1"]
    scanned = [c.host(n) for n in INC.VICTIM_SERVERS]
    scanned = [h for h in scanned if h]
    scanned_names = {h["hostname"] for h in scanned}
    targets = scanned
    ports = INC.RECON_PORTS

    W, H = 1180, 500
    P, A = [], None
    A = P.append
    A(f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" role="img" '
      f'aria-label="Internal reconnaissance from {esc(INC.ATTACKER_WS)}: ICMP sweep, SYN scan, '
      f'LDAP enumeration and SMB share enumeration, over {_rel_win(h1*60+m1, h2*60+m2)}">')
    A('<defs>'
      f'<marker id="rcarr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{PLUM}"/></marker>'
      f'<linearGradient id="rcg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{SAPPHIRE}"/><stop offset="1" stop-color="{FADE}"/></linearGradient>'
      '</defs>')

    # ---------------- phase timeline across the window ----------------
    A(f'<text x="14" y="20" font-size="11.5" font-weight="900" fill="{SAPPHIRE}">Attack phases</text>')
    A(f'<text x="14" y="34" font-size="9.5" fill="{GRAY}">window {_rel_win(h1*60+m1, h2*60+m2)} '
      f'\u00b7 {span // 60} minutes \u00b7 all four phases from a single source</text>')
    TL, TR, TY = 150, W - 20, 116
    X = lambda sec: TL + (TR - TL) * min(1.0, sec / span)
    A(f'<line x1="{TL}" y1="{TY}" x2="{TR}" y2="{TY}" stroke="#d5d6dc" stroke-width="1.5"/>')
    for mm in range(0, span // 60 + 1, 3):
        xx = X(mm * 60)
        A(f'<line x1="{xx:.1f}" y1="{TY - 4}" x2="{xx:.1f}" y2="{TY + 4}" stroke="#c9cad0"/>')
        A(f'<text x="{xx:.1f}" y="{TY + 17}" text-anchor="middle" font-size="9" fill="{GRAY}">'
          f'{_off(w_start + mm - CAPTURE_START_MIN)}</text>')
    phases = INC.RECON_PHASES
    # All four offsets land in the first third of the window, so positioned callouts collide.
    # A legend above the axis keeps every phase readable; the bars carry the offsets.
    lw = (TR - 150) / len(phases)
    for i, (off, label) in enumerate(phases):
        col = [PLUM, TANGERINE, CYAN, SAPPHIRE][i % 4]
        lx = 150 + i * lw
        A(f'<rect x="{lx:.0f}" y="{TY - 74}" width="11" height="11" rx="3" fill="{col}"/>')
        A(f'<text x="{lx + 16:.0f}" y="{TY - 64}" font-size="9.5" font-weight="700" fill="{col}">'
          f'{i + 1}. {esc(label)}</text>')
        A(f'<text x="{lx + 16:.0f}" y="{TY - 52}" font-size="8.5" fill="{GRAY}" '
          f'font-family="ui-monospace,Menlo,monospace">starts +{off}s</text>')
    for i, (off, label) in enumerate(phases):
        end = phases[i + 1][0] if i + 1 < len(phases) else span
        x1, x2 = X(off), X(end)
        col = [PLUM, TANGERINE, CYAN, SAPPHIRE][i % 4]
        yy = TY - 30
        A(f'<rect x="{x1:.1f}" y="{yy}" width="{max(7, x2 - x1):.1f}" height="17" rx="8" fill="{col}"/>')
        A(f'<text x="{x1 + 5:.1f}" y="{yy + 12.5}" font-size="8.5" font-weight="700" fill="#fff">{i + 1}</text>')
    A(f'<text x="14" y="{TY + 4}" font-size="10" font-weight="700" fill="{PLUM}">{esc(INC.ATTACKER_WS)}</text>')
    A(f'<text x="14" y="{TY + 16}" font-size="9" fill="{GRAY}" font-family="ui-monospace,Menlo,monospace">{esc(atk_ip)}</text>')

    A(f'<line x1="14" y1="150" x2="{W - 14}" y2="150" stroke="#e4e4e8"/>')

    # ---------------- left: the fan-out, which is the signature ----------------
    A(f'<text x="14" y="172" font-size="11.5" font-weight="900" fill="{SAPPHIRE}">The signature: one source, many destinations</text>')
    A(f'<text x="14" y="186" font-size="9.5" fill="{GRAY}">a workstation touching every server on the subnet, on ports it has never used before</text>')
    ax, ay = 108, 330
    A(f'<rect x="{ax - 74}" y="{ay - 26}" width="148" height="52" rx="10" fill="url(#rcg)"/>')
    A(f'<text x="{ax}" y="{ay - 6}" text-anchor="middle" font-size="11.5" font-weight="900" fill="#fff">{esc(INC.ATTACKER_WS)}</text>')
    A(f'<text x="{ax}" y="{ay + 8}" text-anchor="middle" font-size="9.5" fill="#d9d5ea" font-family="ui-monospace,Menlo,monospace">{esc(atk_ip)}</text>')
    A(f'<text x="{ax}" y="{ay + 20}" text-anchor="middle" font-size="8.5" fill="#d9d5ea">compromised foothold</text>')
    n = len(swept)
    top, pitch = 214, min(22, 258 / max(1, n))
    for i, h in enumerate(swept):
        ty = top + i * pitch
        hot = h["hostname"] in scanned_names
        col = PLUM if hot else GRAY
        A(f'<path d="M{ax + 76},{ay} C 200,{ay} 210,{ty + 5} 268,{ty + 5}" fill="none" '
          f'stroke="{col}" stroke-width="{1.2 if hot else 0.7}" opacity="{0.75 if hot else 0.35}"/>')
        A(f'<text x="272" y="{ty + 8}" font-size="9" fill="{SAPPHIRE if hot else "#a9aab2"}" '
          f'font-weight="{700 if hot else 400}" font-family="ui-monospace,Menlo,monospace">{esc(h["hostname"])}</text>')
        A(f'<text x="384" y="{ty + 8}" font-size="8.5" fill="{GRAY if hot else "#c2c3ca"}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(h["ip"])}</text>')
    A(f'<text x="272" y="{top - 18}" font-size="9" font-weight="700" fill="{GRAY}">'
      f'{n} hosts swept on {esc(d["nets"]["server"])}</text>')
    A(f'<text x="272" y="{top - 7}" font-size="9" font-weight="700" fill="{PLUM}">'
      f'red = the {len(scanned)} then scanned</text>')
    A(f'<line x1="470" y1="162" x2="470" y2="{H - 10}" stroke="#e4e4e8"/>')

    # ---------------- right: the port matrix ----------------
    MX, MY = 500, 218
    cw, rh = 40, 25
    A(f'<text x="{MX}" y="172" font-size="11.5" font-weight="900" fill="{SAPPHIRE}">SYN scan result matrix</text>')
    A(f'<text x="{MX}" y="186" font-size="9.5" fill="{GRAY}">every host \u00d7 every port \u00b7 '
      f'SA = SYN/ACK (port open) \u00b7 RST = reset (port closed)</text>')
    for j, p in enumerate(ports):
        A(f'<text x="{MX + 128 + j * cw + cw / 2:.0f}" y="{MY - 6}" text-anchor="middle" '
          f'font-size="9" font-weight="700" fill="{SAPPHIRE}">{p}</text>')
    for i, h in enumerate(targets):
        ry = MY + i * rh
        openset = INC.RECON_OPEN.get(h["hostname"], set())
        A(f'<text x="{MX}" y="{ry + 15}" font-size="9.5" fill="{SAPPHIRE}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(h["hostname"])}</text>')
        if i % 2 == 0:
            A(f'<rect x="{MX + 124}" y="{ry}" width="{len(ports) * cw + 8}" height="{rh}" fill="#fafafc"/>')
        for j, p in enumerate(ports):
            cx = MX + 128 + j * cw + cw / 2
            cy = ry + rh / 2
            if p in openset:
                A(f'<rect x="{cx - 13:.0f}" y="{cy - 8:.0f}" width="26" height="16" rx="5" fill="{PLUM}">'
                  f'<title>{esc(h["hostname"])}:{p} open \u2014 SYN/ACK</title></rect>')
                A(f'<text x="{cx:.0f}" y="{cy + 4:.0f}" text-anchor="middle" font-size="8" font-weight="700" fill="#fff">SA</text>')
            else:
                A(f'<rect x="{cx - 13:.0f}" y="{cy - 8:.0f}" width="26" height="16" rx="5" fill="#fff" stroke="#dfe0e6">'
                  f'<title>{esc(h["hostname"])}:{p} closed \u2014 RST</title></rect>')
                A(f'<text x="{cx:.0f}" y="{cy + 4:.0f}" text-anchor="middle" font-size="8" fill="#c2c3ca">RST</text>')
    A('</svg>')

    n_open = sum(len(INC.RECON_OPEN.get(h["hostname"], set())) for h in scanned)
    n_probe = len(scanned) * len(ports)
    trows = "".join(
        f'<tr><td>{i + 1}</td><td class="m">+{off}s</td><td>{esc(label)}</td><td class="svc">{esc(detail)}</td></tr>'
        for i, ((off, label), detail) in enumerate(zip(INC.RECON_PHASES, [
            f"ICMP echo to all {len(swept)} hosts on {d['nets']['server']} plus 3 unused addresses (no reply) — no prior ICMP from this workstation",
            f"{n_probe} SYN probes ({len(scanned)} hosts \u00d7 {len(ports)} ports) in "
            f"one continuous pass (~4 ms apart); {n_open} answer SYN/ACK, the rest RST",
            f"{INC.RECON_LDAP_SESSIONS} LDAP session, {INC.RECON_LDAP_QUERIES} paged searches against "
            f"EXL-DC1 — users, computers, groups, SPNs, adminCount, OUs",
            "srvsvc NetShareEnumAll over SMB against each server, authenticating as svc_backup",
        ])))
    srvnet = d["nets"]["server"]
    filters = [
        ("Host-discovery sweep", f'icmp.type == 8 && ip.src == {atk_ip}',
         f"clean: {len(swept) + 3} echo requests ({len(swept)} replies; 3 unused addresses stay silent)"),
        ("The port-scan burst", f'tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == {atk_ip} '
                               f'&& ip.dst == {srvnet}', f"{n_probe} probes in one dense burst"),
        ("Ports found open", f'tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.dst == {atk_ip}',
         f"{n_open} in the window"),
        ("Ports found closed", f'tcp.flags.reset == 1 && ip.dst == {atk_ip}',
         f"{n_probe - n_open} in the window"),
        ("Directory enumeration", f'ldap && ip.src == {atk_ip}',
         f"{INC.RECON_LDAP_SESSIONS} session, {INC.RECON_LDAP_QUERIES} searches"),
        ("Share enumeration", 'smb2.filename contains "srvsvc"', "NetShareEnumAll per server"),
    ]
    frows = "".join(f'<tr><td>{esc(a)}</td><td class="m">{esc(b)}</td>'
                    f'<td class="svc">{esc(n)}</td></tr>' for a, b, n in filters)

    return {
        "svg": "".join(P),
        "kpis": [(_rel_start(h1 * 60 + m1), "Window opens", "mono"),
                 (_dur(span // 60), "Duration"),
                 (INC.ATTACKER_WS, "Source", "mono"),
                 (len(swept), "Hosts swept"),
                 (len(scanned), "Servers scanned"),
                 (n_probe, "SYN probes"),
                 (n_open, "Open ports found")],
        "sections": [
            ("Phases", '<table><thead><tr><th>#</th><th>Offset</th><th>Phase</th>'
                       f'<th>What it emits</th></tr></thead><tbody>{trows}</tbody></table>'),
            ("Finding it in a capture",
             '<table><thead><tr><th>What</th><th>Display filter</th><th>Expect</th></tr></thead>'
             f'<tbody>{frows}</tbody></table>'),
        ],
        "notes": [
            ("warn", "Why this is detectable",
             f"One user-subnet workstation pings all {len(swept)} hosts on {d['nets']['server']} "
             f"within seconds, then port-scans the {len(scanned)} that matter, on ports it has no "
             "business using. The fan-out ratio, not any single packet, is the detection."),
            ("", "Open vs closed is real",
             "The matrix is the responses the generator actually emits: SYN/ACK from the service "
             "ports each server genuinely runs, RST everywhere else. An analyst can reconstruct "
             "the attacker's view of the subnet from the capture alone."),
            ("warn", "The source is also a normal workstation",
             f"{INC.ATTACKER_WS} runs an ordinary user day as well, so a bare "
             f"ip.src == {atk_ip} filter returns its legitimate traffic too. Scope broad filters "
             f"to the window above — the scan itself arrives as one dense burst and stands out."),
            ("", "It chains",
             "Recon is also the first phase inside ndr-scattered-spider and every actor kill "
             "chain, which call this same builder under their own tag — so the pattern appears "
             "there too, on their timelines."),
        ],
    }


# =======================================================================================
# SCENARIO DIAGRAM TOOLKIT
# Shared primitives so the NDR scenario diagrams stay a visual family and each builder is
# small. Every one of them reads its facts from netgen.incidents — the module constants
# (RECON_*, CRED_PHASES, LATERAL_PLAN, C2_*, EXFIL_*, RANSOM_*, CHAIN_PHASES, ACTORS) —
# so a picture cannot drift from what the generator emits.
# =======================================================================================
PHASE_COLORS = [PLUM, TANGERINE, CYAN, SAPPHIRE, "#8a5cf0", "#1a8a4a"]


# The capture (and therefore the replay) begins at 05:00. A replay can be started at any wall-clock
# time and the sensor timestamps every packet at the moment it is observed, so an absolute clock
# time on a diagram is meaningless the moment the file is replayed. What IS stable is the offset
# from the first baseline packet: "Start + h:mm". Every scenario window is rendered that way.
CAPTURE_START_MIN = 5 * 60


def _off(mins):
    """A signed offset from the replay start, e.g. +45m, +2h, +2:30."""
    m = int(round(mins))
    if m < 60:
        return "+%dm" % m
    h, mm = divmod(m, 60)
    return "+%dh" % h if mm == 0 else "+%d:%02d" % (h, mm)


def _dur(mins):
    """A duration, e.g. 45m, 2h, 2:30."""
    m = int(round(mins))
    if m < 60:
        return "%dm" % m
    h, mm = divmod(m, 60)
    return "%dh" % h if mm == 0 else "%d:%02d" % (h, mm)


def _rel_start(absmin):
    return "Start " + _off(absmin - CAPTURE_START_MIN)


def _rel_win(lo_absmin, hi_absmin):
    return "Start %s → %s" % (_off(lo_absmin - CAPTURE_START_MIN), _off(hi_absmin - CAPTURE_START_MIN))


def _scn(c, module):
    """Window and actor facts shared by every scenario diagram."""
    from netgen import incidents as INC
    inc = INC.REGISTRY[module]
    (h1, m1), (h2, m2) = inc.window
    start, end = h1 * 60 + m1, h2 * 60 + m2
    atk = c.host(INC.ATTACKER_WS)
    return {"INC": INC, "inc": inc, "start": start, "end": end, "span": (end - start) * 60,
            "from": f"{h1:02d}:{m1:02d}", "to": f"{h2:02d}:{m2:02d}",
            "rstart": _rel_start(start), "rwin": _rel_win(start, end), "dur": _dur(end - start),
            "atk": atk, "atk_ip": atk["ip"] if atk else "?", "who": INC.ATTACKER_WS}


def _phase_bar(A, x0, y0, w, span, marks, legend=True, axis_every=None):
    """A phase strip: colour legend, bars positioned by offset, and a clock axis.

    marks: [(start_sec, end_sec or None, label)]. Returns the y of the axis baseline.
    Offsets in these scenarios cluster early, so labels go in a legend rather than inline.
    """
    L, R = x0 + 92, x0 + w
    X = lambda sec: L + (R - L) * min(1.0, max(0.0, sec / span))
    ly = y0
    if legend:
        lw = (R - x0) / max(1, len(marks))
        for i, (a, b, label) in enumerate(marks):
            col = PHASE_COLORS[i % len(PHASE_COLORS)]
            lx = x0 + i * lw
            A(f'<rect x="{lx:.0f}" y="{ly}" width="10" height="10" rx="3" fill="{col}"/>')
            A(f'<text x="{lx + 15:.0f}" y="{ly + 9}" font-size="9" font-weight="700" fill="{col}">'
              f'{esc(label)}</text>')
        ly += 26
    for i, (a, b, label) in enumerate(marks):
        col = PHASE_COLORS[i % len(PHASE_COLORS)]
        x1, x2 = X(a), X(b if b is not None else span)
        A(f'<rect x="{x1:.1f}" y="{ly}" width="{max(7, x2 - x1):.1f}" height="15" rx="7" '
          f'fill="{col}" opacity="{0.95 if b is not None else 0.6}"><title>{esc(label)}</title></rect>')
    ay = ly + 28
    A(f'<line x1="{L}" y1="{ay}" x2="{R}" y2="{ay}" stroke="#d5d6dc" stroke-width="1.4"/>')
    step = axis_every or max(1, (span // 60) // 6)
    for mm in range(0, span // 60 + 1, step):
        xx = X(mm * 60)
        A(f'<line x1="{xx:.1f}" y1="{ay - 4}" x2="{xx:.1f}" y2="{ay + 4}" stroke="#c9cad0"/>')
        A(f'<text x="{xx:.1f}" y="{ay + 16}" text-anchor="middle" font-size="9" fill="{GRAY}">'
          f'+{mm}m</text>')
    return ay


_ACRONYMS = {"DNS", "SMB", "OT", "C2", "TLS", "VPN", "NDR", "NPM", "IP", "TCP", "UDP", "HTTP", "HTTPS", "RDP", "SPN"}


def sentence_case(title):
    """Sentence case for a panel title written in capitals: first letter capital, the rest lower,
    acronyms kept. Mixed-case titles are left alone."""
    if not title or title != title.upper() or not any(ch.isalpha() for ch in title):
        return title
    words = re.split(r"(\W+)", title)
    out = [w if w in _ACRONYMS else w.lower() for w in words]
    for i, w in enumerate(out):
        if w[:1].isalpha():
            out[i] = w[:1].upper() + w[1:]
            break
    return "".join(out)


def _panel_title(A, x, y, title, sub="", size=11.5, sub_size=9.5, gap=14):
    """Shared panel heading. The defaults are what all 33 diagrams already render, so they
    must not change — pass `size`/`sub_size` to enlarge one page rather than nudging the
    defaults and silently reflowing every other diagram."""
    A(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="900" fill="{SAPPHIRE}">{esc(sentence_case(title))}</text>')
    if sub:
        A(f'<text x="{x}" y="{y + gap}" font-size="{sub_size}" fill="{GRAY}">{esc(sub)}</text>')


def _rows(A, x0, y0, w, rows, pitch=26):
    """rows: [(badge, badge_colour, main, sub, right)] — the workhorse list panel."""
    for i, (badge, col, main, sub, right) in enumerate(rows):
        y = y0 + i * pitch
        if i % 2 == 0:
            A(f'<rect x="{x0 - 4}" y="{y - 13}" width="{w + 8}" height="{pitch}" fill="#fafafc"/>')
        if badge:
            bw = 8 + 7 * len(str(badge))
            A(f'<rect x="{x0}" y="{y - 10}" width="{bw}" height="15" rx="4" fill="{col}"/>')
            A(f'<text x="{x0 + bw / 2:.0f}" y="{y + 1}" text-anchor="middle" font-size="8.5" '
              f'font-weight="700" fill="#fff">{esc(badge)}</text>')
        tx = x0 + (8 + 7 * len(str(badge)) + 8 if badge else 0)
        A(f'<text x="{tx}" y="{y + 1}" font-size="10.5" font-weight="700" fill="{SAPPHIRE}">{esc(main)}</text>')
        if sub:
            A(f'<text x="{tx}" y="{y + 12}" font-size="8.5" fill="{GRAY}">{esc(sub)}</text>')
        if right:
            A(f'<text x="{x0 + w}" y="{y + 1}" text-anchor="end" font-size="9.5" fill="{PLUM}" '
              f'font-family="ui-monospace,Menlo,monospace">{esc(right)}</text>')
    return y0 + len(rows) * pitch


def _beacon_strip(A, x0, y0, w, span, base, jitter, first=None, tunnel=None, colour=PLUM):
    """Jittered beacon cadence — the thing that makes C2 recognisable on a timeline."""
    L, R = x0, x0 + w
    X = lambda sec: L + (R - L) * min(1.0, sec / span)
    A(f'<line x1="{L}" y1="{y0}" x2="{R}" y2="{y0}" stroke="#e4e4e8" stroke-width="1.2"/>')
    import random as _r
    rr = _r.Random(1234)                       # display-only jitter, deterministic
    t = base
    while t < span:
        A(f'<line x1="{X(t):.1f}" y1="{y0 - 9}" x2="{X(t):.1f}" y2="{y0 + 9}" '
          f'stroke="{colour}" stroke-width="1.5" opacity=".8"/>')
        t += base * rr.uniform(*jitter)
    if first is not None:
        A(f'<circle cx="{X(first):.1f}" cy="{y0}" r="6" fill="{TANGERINE}"/>')
        A(f'<text x="{X(first):.1f}" y="{y0 - 14}" text-anchor="middle" font-size="9" '
          f'font-weight="700" fill="{TANGERINE}">first contact +{first}s</text>')
    if tunnel is not None:
        A(f'<rect x="{X(tunnel):.1f}" y="{y0 - 6}" width="{max(8, R - X(tunnel)):.1f}" height="12" '
          f'rx="6" fill="{CYAN}" opacity=".75"/>')
        A(f'<text x="{X(tunnel) + 6:.1f}" y="{y0 + 24}" font-size="9" font-weight="700" fill="{CYAN}">'
          f'persistent tunnel from +{tunnel}s</text>')


def _ext_rows(c, keys):
    """Real external infrastructure for the given EXT_HOSTS keys, straight from the module."""
    from netgen import incidents as INC
    out = []
    for k in keys:
        if k in INC.EXT_HOSTS:
            host, ip, hops = INC.EXT_HOSTS[k]
            label = next((i[2] for i in INC.INDICATORS if i[0] == ip), k)
            out.append((k, host, ip, label))
    return out


def _uuid_str(raw):
    """Render a DCE/RPC interface UUID the way tshark displays it.

    The first three groups go on the wire little-endian, so the display form is not the byte
    order in the source. Deriving it here means a filter printed on a diagram matches what is
    actually in the capture, and keeps matching if the engine changes.
    """
    h = raw.hex()
    return "-".join([
        bytes.fromhex(h[0:8])[::-1].hex(), bytes.fromhex(h[8:12])[::-1].hex(),
        bytes.fromhex(h[12:16])[::-1].hex(), h[16:20], h[20:32]])


def _filters_table(rows):
    body = "".join(f'<tr><td>{esc(a)}</td><td class="m">{esc(b)}</td><td class="svc">{esc(n)}</td></tr>'
                   for a, b, n in rows)
    return ('<table><thead><tr><th>What</th><th>Display filter</th><th>Expect</th></tr></thead>'
            f'<tbody>{body}</tbody></table>')


def _svg_open(w, h, label):
    return (f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" role="img" '
            f'aria-label="{esc(label)}"><defs>'
            f'<linearGradient id="scng" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{SAPPHIRE}"/>'
            f'<stop offset="1" stop-color="{FADE}"/></linearGradient></defs>')


def _actor_box(A, x, y, name, ip, sub="compromised foothold"):
    A(f'<rect x="{x - 76}" y="{y - 24}" width="152" height="48" rx="10" fill="url(#scng)"/>')
    A(f'<text x="{x}" y="{y - 5}" text-anchor="middle" font-size="11" font-weight="900" fill="#fff">{esc(name)}</text>')
    A(f'<text x="{x}" y="{y + 8}" text-anchor="middle" font-size="9" fill="#d9d5ea" '
      f'font-family="ui-monospace,Menlo,monospace">{esc(ip)}</text>')
    A(f'<text x="{x}" y="{y + 19}" text-anchor="middle" font-size="8" fill="#d9d5ea">{esc(sub)}</text>')


@register("ndr-credential-access", "Credential access",
          "Kerberoasting, AS-REP roasting, password spray and DCSync", order=101,
          scenario="ndr-credential-access")
def d_cred(c):
    k = _scn(c, "ndr-credential-access"); INC = k["INC"]
    W, H = 1180, 486
    A = [].append; P = []
    A = P.append
    A(_svg_open(W, H, f'Credential access from {k["who"]} over {k["rwin"]}'))
    _panel_title(A, 14, 20, "ATTACK PHASES",
                 f'window {k["rwin"]} \u00b7 four techniques, all against EXL-DC1')
    marks = [(off, (INC.CRED_PHASES[i + 1][0] if i + 1 < len(INC.CRED_PHASES) else k["span"]), lbl)
             for i, (off, lbl, _d) in enumerate(INC.CRED_PHASES)]
    _phase_bar(A, 14, 42, W - 28, k["span"], marks)
    A(f'<text x="14" y="104" font-size="10" font-weight="700" fill="{PLUM}">{esc(k["who"])}</text>')
    A(f'<text x="14" y="116" font-size="9" fill="{GRAY}" font-family="ui-monospace,Menlo,monospace">{esc(k["atk_ip"])}</text>')
    A(f'<line x1="14" y1="150" x2="{W - 14}" y2="150" stroke="#e4e4e8"/>')

    _panel_title(A, 14, 172, "WHAT EACH PHASE PUTS ON THE WIRE",
                 "every exchange is Kerberos or DRSUAPI to the domain controller")
    counts = [f"{len(INC.KERBEROAST_SPNS)} SPNs, RC4", f"{len(INC.ASREP_ACCOUNTS)} accounts",
              f"{INC.SPRAY_LAST - INC.SPRAY_FIRST} users", "3\u20136 pulls"]
    rows = [(f"+{off}s", PHASE_COLORS[i % len(PHASE_COLORS)], lbl, det, counts[i])
            for i, (off, lbl, det) in enumerate(INC.CRED_PHASES)]
    _rows(A, 14, 210, 430, rows, pitch=34)

    A(f'<line x1="476" y1="162" x2="476" y2="{H - 10}" stroke="#e4e4e8"/>')
    _panel_title(A, 500, 172, "SERVICE PRINCIPAL NAMES REQUESTED",
                 "a TGS-REQ for each, RC4 (etype 23) asked for explicitly \u2014 the roasting tell")
    for i, (svc, host) in enumerate(INC.KERBEROAST_SPNS):
        y = 206 + i * 21
        if i % 2 == 0:
            A(f'<rect x="496" y="{y - 12}" width="{W - 520}" height="21" fill="#fafafc"/>')
        A(f'<rect x="500" y="{y - 9}" width="{8 + 7 * len(svc)}" height="14" rx="4" fill="{PLUM}"/>')
        A(f'<text x="{500 + (8 + 7 * len(svc)) / 2:.0f}" y="{y + 1}" text-anchor="middle" '
          f'font-size="8.5" font-weight="700" fill="#fff">{esc(svc)}</text>')
        A(f'<text x="{500 + 8 + 7 * len(svc) + 10:.0f}" y="{y + 1}" font-size="9.5" fill="{SAPPHIRE}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(host)}</text>')
    A('</svg>')

    prows = "".join(f'<tr><td class="m">+{off}s</td><td>{esc(lbl)}</td><td class="svc">{esc(det)}</td>'
                    f'<td class="m">{esc(counts[i])}</td></tr>'
                    for i, (off, lbl, det) in enumerate(INC.CRED_PHASES))
    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 (k["who"], "Source", "mono"), (len(INC.KERBEROAST_SPNS), "SPNs roasted"),
                 (INC.SPRAY_LAST - INC.SPRAY_FIRST, "Accounts sprayed"), (4, "Techniques")],
        "sections": [("Phases", '<table><thead><tr><th>Offset</th><th>Technique</th>'
                                f'<th>Signature</th><th>Volume</th></tr></thead><tbody>{prows}</tbody></table>'),
                     ("Finding it in a capture", _filters_table([
                         ("Kerberoasting (the RC4 tell)",
                          'kerberos.ENCTYPE == 23 && !(kerberos.ENCTYPE == 18)',
                          f'{len(INC.KERBEROAST_SPNS)} requests offering RC4 and nothing else'),
                         ("The TGS-REQ burst", f'kerberos.msg_type == 12 && ip.src == {k["atk_ip"]}',
                          'includes the user\u2019s own ticket requests'),
                         ("AS-REP roasting", f'kerberos.msg_type == 10 && ip.src == {k["atk_ip"]}',
                          f'AS-REQ incl. {len(INC.ASREP_ACCOUNTS)} preauth-less'),
                         ("Password spray", 'kerberos.error_code == 24',
                          f'PREAUTH_FAILED \u00d7 {INC.SPRAY_LAST - INC.SPRAY_FIRST}'),
                         ("DCSync", f'dcerpc.cn_bind_to_uuid == {_uuid_str(__import__("netgen.protocols", fromlist=["x"]).DRSUAPI_UUID)}',
                          'DRSUAPI bind (GUID unquoted)'),
                         ("All Kerberos from the host", f'kerberos && ip.src == {k["atk_ip"]}',
                          'includes the user\u2019s own logons'),
                     ]))],
        "notes": [
            ("warn", "One host, every technique",
             f'{k["who"]} is a user workstation. Requesting {len(INC.KERBEROAST_SPNS)} service '
             "tickets with RC4 and nothing else, then failing pre-auth against dozens of "
             "accounts, then pulling directory replication, is not something a workstation does."),
            ("", "Why RC4 specifically",
             "Asking for etype 23 when the domain supports AES forces the ticket to be encrypted "
             "under the service account's NTLM hash, which can be cracked offline. The same host "
             "offers 18, 17, 23 in its ordinary traffic \u2014 the downgrade is the tell."),
            ("", "DCSync is the one that matters",
             "DRSUAPI DsGetNCChanges is how a domain controller replicates. From anything that "
             "is not a DC it means credential material is being pulled wholesale."),
            ("", "It chains",
             "This is phase 2 of ndr-scattered-spider and of every actor kill chain, which call "
             "this same builder under their own tag."),
        ],
    }


@register("ndr-lateral-movement", "Lateral movement",
          "RDP, SMB admin-share execution and WMI, spreading to a second workstation",
          order=102, scenario="ndr-lateral-movement")
def d_lateral(c):
    k = _scn(c, "ndr-lateral-movement"); INC = k["INC"]
    plan = sorted(INC.LATERAL_PLAN, key=lambda r: r[0])
    W, H = 1180, 500
    P = []; A = P.append
    A(_svg_open(W, H, f'Lateral movement from {k["who"]} over {k["rwin"]}'))
    _panel_title(A, 14, 20, "MOVEMENT TIMELINE",
                 f'window {k["rwin"]} \u00b7 {len(plan)} remote-execution events from two hosts')
    TECHS = ["RDP", "SMB admin-share exec", "WMI remote exec"]
    tcol = {t: PHASE_COLORS[i] for i, t in enumerate(TECHS)}
    lw = (W - 28) / 3
    for i, t in enumerate(TECHS):
        A(f'<rect x="{14 + i * lw:.0f}" y="42" width="10" height="10" rx="3" fill="{tcol[t]}"/>')
        A(f'<text x="{14 + i * lw + 15:.0f}" y="51" font-size="9" font-weight="700" fill="{tcol[t]}">{esc(t)}</text>')
    L, R = 120, W - 20
    X = lambda sec: L + (R - L) * min(1.0, sec / k["span"])
    for row, src in enumerate((INC.ATTACKER_WS, INC.LATERAL_SECOND_HOST)):
        ry = 82 + row * 36
        A(f'<text x="14" y="{ry + 4}" font-size="9.5" font-weight="700" fill="{SAPPHIRE}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(src)}</text>')
        A(f'<line x1="{L}" y1="{ry}" x2="{R}" y2="{ry}" stroke="#eceded" stroke-width="1.2"/>')
        for off, s_name, tgt, tech, _d in plan:
            if s_name != src:
                continue
            x = X(off)
            A(f'<circle cx="{x:.1f}" cy="{ry}" r="6" fill="{tcol[tech]}"><title>+{off}s {tech} \u2192 {tgt}</title></circle>')
            A(f'<text x="{x:.1f}" y="{ry - 11}" text-anchor="middle" font-size="8.5" fill="{SAPPHIRE}" '
              f'font-family="ui-monospace,Menlo,monospace">{esc(tgt.replace("EXL-", ""))}</text>')
    ay = 154
    A(f'<line x1="{L}" y1="{ay}" x2="{R}" y2="{ay}" stroke="#d5d6dc" stroke-width="1.4"/>')
    for mm in range(0, k["span"] // 60 + 1, 3):
        x = X(mm * 60)
        A(f'<line x1="{x:.1f}" y1="{ay - 4}" x2="{x:.1f}" y2="{ay + 4}" stroke="#c9cad0"/>')
        A(f'<text x="{x:.1f}" y="{ay + 16}" text-anchor="middle" font-size="9" fill="{GRAY}">+{mm}m</text>')
    A(f'<line x1="14" y1="186" x2="{W - 14}" y2="186" stroke="#e4e4e8"/>')

    _panel_title(A, 14, 208, "EVERY REMOTE-EXECUTION EVENT", "in the order the attacker issues them")
    rows = []
    for off, s_name, tgt, tech, dur in plan:
        h = c.host(tgt)
        rows.append((f"+{off}s", tcol[tech], f"{s_name}  \u2192  {tgt}", tech,
                     h["ip"] if h else ""))
    _rows(A, 14, 244, 540, rows, pitch=30)

    A(f'<line x1="596" y1="198" x2="596" y2="{H - 10}" stroke="#e4e4e8"/>')
    _panel_title(A, 620, 208, "THE SPREAD",
                 "a second workstation starts doing the same thing \u2014 that is the escalation")
    a1 = c.host(INC.ATTACKER_WS); a2 = c.host(INC.LATERAL_SECOND_HOST)
    _actor_box(A, 700, 300, INC.ATTACKER_WS, a1["ip"] if a1 else "?")
    _actor_box(A, 700, 392, INC.LATERAL_SECOND_HOST, a2["ip"] if a2 else "?", "popped at +620s")
    seen = []
    for off, s_name, tgt, tech, _d in plan:
        if tgt not in seen:
            seen.append(tgt)
    for i, tgt in enumerate(seen):
        ty = 258 + i * 26
        h = c.host(tgt)
        A(f'<path d="M776,{300 if any(r[1] == INC.ATTACKER_WS and r[2] == tgt for r in plan) else 392} '
          f'C 850,{300} 860,{ty} 906,{ty}" fill="none" stroke="{PLUM}" stroke-width="1" opacity=".45"/>')
        A(f'<text x="912" y="{ty + 4}" font-size="9.5" fill="{SAPPHIRE}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(tgt)}</text>')
        A(f'<text x="{W - 20}" y="{ty + 4}" text-anchor="end" font-size="9" fill="{GRAY}" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(h["ip"] if h else "")}</text>')
    A('</svg>')

    prows = "".join(f'<tr><td class="m">+{off}s</td><td class="m">{esc(sn)}</td>'
                    f'<td class="m">{esc(tg)}</td><td>{esc(te)}</td></tr>'
                    for off, sn, tg, te, _d in plan)
    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 (len(plan), "Exec events"), (len(seen), "Servers touched"),
                 (2, "Source hosts"), (3, "Techniques")],
        "sections": [("Events", '<table><thead><tr><th>Offset</th><th>Source</th><th>Target</th>'
                                f'<th>Technique</th></tr></thead><tbody>{prows}</tbody></table>'),
                     ("Finding it in a capture", _filters_table([
                         ("RDP from a workstation", 'tcp.port == 3389 && ip.src == ' + k["atk_ip"],
                          'workstations do not RDP to servers'),
                         ("Admin-share connect", 'smb2.tree contains "ADMIN$"',
                          'the share is in the tree, not the filename'),
                         ("Dropped binary", 'smb2.filename == "update.exe"', 'PsExec-style drop'),
                         ("Service creation", 'smb2.filename contains "svcctl"', 'CreateService over the pipe'),
                         ("WMI remote exec", f'dcerpc.cn_bind_to_uuid == {_uuid_str(__import__("netgen.protocols", fromlist=["x"]).WMI_UUID)}',
                          'ExecMethod on Win32_Process'),
                         ("The spread", f'ip.src == {(a2 or {}).get("ip", "")} && ip.dst == {c.nets["server"]}',
                          'second host, same techniques'),
                     ]))],
        "notes": [
            ("warn", "Direction is the signal",
             "None of RDP, SMB admin-share writes or WMI is unusual between servers or from the "
             "jump host. From a user workstation into the server subnet, all three are."),
            ("", "Two hosts, not one",
             f'{INC.LATERAL_SECOND_HOST} starts issuing the same techniques at +620s. A detection '
             "keyed only to the original foothold misses half the campaign."),
            ("", "It chains",
             "Phase 3 of ndr-scattered-spider and of every actor kill chain."),
        ],
    }


def _infra_panel(A, c, x0, y0, w, keys, title, sub):
    _panel_title(A, x0, y0, title, sub)
    rows = []
    for key, host, ip, label in _ext_rows(c, keys):
        rows.append((key, PLUM, host, label, ip))
    _rows(A, x0, y0 + 40, w, rows, pitch=30)
    return y0 + 40 + len(rows) * 30


@register("ndr-c2-beaconing", "C2 beaconing",
          "RMM cloud first contact, a low-and-slow HTTPS beacon, and a persistent tunnel",
          order=103, scenario="ndr-c2-beaconing")
def d_c2(c):
    k = _scn(c, "ndr-c2-beaconing"); INC = k["INC"]
    W, H = 1180, 470
    P = []; A = P.append
    A(_svg_open(W, H, f'C2 beaconing from {k["who"]} over {k["rwin"]}'))
    _panel_title(A, 14, 20, "BEACON CADENCE",
                 f'window {k["rwin"]} \u00b7 every ~{INC.C2_BEACON_BASE}s with '
                 f'{int(INC.C2_JITTER[0] * 100)}\u2013{int(INC.C2_JITTER[1] * 100)}% jitter, for {k["span"] // 60} minutes')
    _beacon_strip(A, 120, 92, W - 150, k["span"], INC.C2_BEACON_BASE, INC.C2_JITTER,
                  first=INC.C2_RMM_AT, tunnel=INC.C2_TUNNEL_AT)
    A(f'<text x="14" y="96" font-size="9.5" font-weight="700" fill="{SAPPHIRE}">beacons</text>')
    L, R = 120, W - 30
    X = lambda sec: L + (R - L) * min(1.0, sec / k["span"])
    ay = 140
    A(f'<line x1="{L}" y1="{ay}" x2="{R}" y2="{ay}" stroke="#d5d6dc" stroke-width="1.4"/>')
    for mm in range(0, k["span"] // 60 + 1, 20):
        x = X(mm * 60)
        A(f'<line x1="{x:.1f}" y1="{ay - 4}" x2="{x:.1f}" y2="{ay + 4}" stroke="#c9cad0"/>')
        A(f'<text x="{x:.1f}" y="{ay + 16}" text-anchor="middle" font-size="9" fill="{GRAY}">+{mm}m</text>')
    A(f'<line x1="14" y1="172" x2="{W - 14}" y2="172" stroke="#e4e4e8"/>')

    _actor_box(A, 120, 300, INC.ATTACKER_WS, k["atk_ip"])
    A(f'<text x="120" y="356" text-anchor="middle" font-size="9" fill="{GRAY}">all sessions are outbound TLS through EXL-FW1</text>')
    A(f'<defs><marker id="w2c2" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{PLUM}"/></marker></defs>')
    for _i in range(3):                       # client -> server: workstation to each external destination
        _y = 231 + _i * 30
        A(f'<path d="M198,300 C 245,300 245,{_y} 292,{_y}" fill="none" stroke="{PLUM}" stroke-width="1.3" '
          f'opacity=".7" marker-end="url(#w2c2)"/>')
    _infra_panel(A, c, 300, 194, 430, ["rmm", "c2", "ngrok"],
                 "EXTERNAL INFRASTRUCTURE", "real, publicly documented indicators \u2014 never contacted")
    A(f'<line x1="770" y1="184" x2="770" y2="{H - 10}" stroke="#e4e4e8"/>')
    _panel_title(A, 794, 194, "WHY IT LOOKS LIKE C2",
                 "no single request is remarkable; the pattern is")
    facts = [("1", PLUM, "Regular interval with jitter",
              f'~{INC.C2_BEACON_BASE}s \u00b1 jitter, never exactly periodic', ""),
             ("2", TANGERINE, "Tiny, symmetric payloads", "180\u2013900 byte request and reply", ""),
             ("3", CYAN, "Runs for hours", f'{k["span"] // 60} minutes unbroken', ""),
             ("4", SAPPHIRE, "First-ever destination", "no prior connection from this host", ""),
             ("5", "#8a5cf0", "Persistent tunnel", f'opened at +{INC.C2_TUNNEL_AT}s and held open', "")]
    _rows(A, 794, 234, W - 814, facts, pitch=34)
    A('</svg>')

    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 (f'~{INC.C2_BEACON_BASE}s', "Beacon interval", "mono"),
                 (f'{int(INC.C2_JITTER[0] * 100)}\u2013{int(INC.C2_JITTER[1] * 100)}%', "Jitter", "mono"),
                 (3, "External destinations"), ("TLS", "All encrypted")],
        "sections": [("Finding it in a capture", _filters_table([
            ("All beaconing", f'ip.src == {k["atk_ip"]} && tls.handshake.type == 1',
             'repeated client hellos'),
            ("By destination", 'tls.handshake.extensions_server_name contains "fastcache-cdn"',
             'the C2 SNI'),
            ("RMM first contact", 'tls.handshake.extensions_server_name contains "anydesk"',
             f'at +{INC.C2_RMM_AT}s'),
            ("The tunnel", 'tls.handshake.extensions_server_name contains "ngrok"',
             f'from +{INC.C2_TUNNEL_AT}s, long-lived'),
            ("Decrypted payloads", 'http.request && tcp.port == 443',
             'only with -o tls.keylog_file'),
        ]))],
        "notes": [
            ("warn", "The interval is the detection",
             "Human browsing is bursty and irregular. A session that repeats every minute for "
             "three hours, with small symmetric payloads, is automation."),
            ("", "Indicators are real",
             "The destinations are genuine documented C2 and abused-service addresses so a "
             "sensor's own threat intel matches. Nothing is ever contacted \u2014 they are "
             "destination fields in a synthetic capture."),
            ("", "It chains", "Phase 1 of ndr-scattered-spider; each actor chain runs its own C2 variant."),
        ],
    }



# ---- W3 private layout helper: richer campaign page (timeline with real events, plain-language
# lead, key facts, wrapped tells, collision-free traffic lanes). Used by the NDR campaign + OT pages.
_W3_INV = {}


def _w3_ip(c, name):
    """A host's address from the live context, falling back to the bundled inventory (OT hosts are
    dropped from the context when the OT zone is off, but the page still has to state them)."""
    h = c.host(name)
    if h:
        return h["ip"]
    if not _W3_INV:
        try:
            with open(os.path.join(APP_DIR, "inventory.json")) as f:
                for x in json.load(f)["hosts"]:
                    _W3_INV.setdefault(x["hostname"], x["ip"])
        except Exception:                                   # noqa: BLE001
            _W3_INV["?"] = ""
    return _W3_INV.get(name, "")


def _w3_text(A, x, y, lines, size, fill, weight=400, pitch=None, mono=False):
    pitch = pitch or size + 4
    fam = ' font-family="ui-monospace,Menlo,monospace"' if mono else ""
    for i, ln in enumerate(lines):
        A(f'<text x="{x}" y="{y + i * pitch}" font-size="{size}" font-weight="{weight}" fill="{fill}"{fam}>{esc(ln)}</text>')
    return y + len(lines) * pitch


def _w3_timeline(A, W, y0, span, spec, accent):
    L, R = 130, W - 40
    ay = y0 + 44
    X = lambda s: L + (R - L) * min(1.0, max(0.0, s / span))
    A(f'<line x1="{L}" y1="{ay}" x2="{R}" y2="{ay}" stroke="#c9cad0" stroke-width="1.6"/>')
    mins = span / 60
    step = next(s for s in (5, 10, 15, 20, 30, 60, 120) if mins / s <= 9)
    m = 0
    while m <= mins + 0.01:
        x = X(m * 60)
        A(f'<line x1="{x:.1f}" y1="{ay - 3}" x2="{x:.1f}" y2="{ay + 3}" stroke="#c9cad0"/>')
        A(f'<text x="{x:.1f}" y="{ay + 17}" text-anchor="middle" font-size="9" fill="{GRAY}">+{m}m</text>')
        m += step
    tk = spec.get("ticks")
    if tk:
        t0, gap = tk[0], tk[1]
        t = t0
        while t < min(span, tk[2] if len(tk) > 2 else span):
            A(f'<line x1="{X(t):.1f}" y1="{ay - 7}" x2="{X(t):.1f}" y2="{ay + 7}" stroke="{accent}" stroke-width="1.4" opacity=".55"/>')
            t += gap
    if spec.get("strip_label"):
        _w3_text(A, 14, ay + 3, [spec["strip_label"]], 9.5, SAPPHIRE, 700)
    for i, (sec, label) in enumerate(spec.get("events", [])):
        x = X(sec)
        A(f'<circle cx="{x:.1f}" cy="{ay}" r="5" fill="{TANGERINE}"/>')
        if not label:
            continue
        ly = ay - 14 - (i % 2) * 14
        anchor, lx = "middle", x
        if x < L + 70:
            anchor, lx = "start", x - 4
        elif x > R - 90:
            anchor, lx = "end", x + 4
        A(f'<text x="{lx:.1f}" y="{ly}" text-anchor="{anchor}" font-size="9" font-weight="700" fill="{TANGERINE}">{esc(label)}</text>')


def _w3_flow(A, x0, y0, w, edges, accent, pitch=54):
    """One straight, labelled lane per flow. edges = [(src, src_ip, dst, dst_ip, label, note, dashed)];
    consecutive edges that share an endpoint share its box, so nothing overlaps and no arrow bends."""
    nw = 210
    lx, rx = x0, x0 + w - nw
    A('<defs><marker id="w3ar" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto" markerUnits="userSpaceOnUse">'
      f'<path d="M0,0 L9,4.5 L0,9 Z" fill="{accent}"/></marker></defs>')

    def runs(k):
        out, i = [], 0
        while i < len(edges):
            j = i
            while j + 1 < len(edges) and edges[j + 1][k:k + 2] == edges[i][k:k + 2]:
                j += 1
            out.append((i, j, edges[i][k], edges[i][k + 1]))
            i = j + 1
        return out

    def box(x, i, j, name, ip, col):
        top = y0 + i * pitch + 4
        h = (j - i + 1) * pitch - 8
        cy = top + h / 2
        A(f'<rect x="{x}" y="{top:.0f}" width="{nw}" height="{h:.0f}" rx="9" fill="#fff" stroke="{col}" stroke-width="1.6"/>')
        A(f'<text x="{x + 12}" y="{cy - (2 if ip else -3):.0f}" font-size="10.5" font-weight="800" fill="{SAPPHIRE}">{esc(_fit(name, nw - 22, 10.5))}</text>')
        if ip:
            A(f'<text x="{x + 12}" y="{cy + 11:.0f}" font-size="9" fill="{GRAY}" font-family="ui-monospace,Menlo,monospace">{esc(ip)}</text>')

    for i, j, n, ip in runs(0):
        box(lx, i, j, n, ip, SAPPHIRE)
    for i, j, n, ip in runs(2):
        box(rx, i, j, n, ip, accent)
    mx = (lx + nw + rx) / 2
    for i, (sn, sip, dn, dip, label, note, dashed) in enumerate(edges):
        y = y0 + i * pitch + pitch / 2
        dash = ' stroke-dasharray="6 4"' if dashed else ""
        A(f'<line x1="{lx + nw}" y1="{y:.0f}" x2="{rx - 1}" y2="{y:.0f}" stroke="{accent}" stroke-width="1.8"{dash} marker-end="url(#w3ar)"/>')
        pw = len(label) * 5.3 + 18
        A(f'<rect x="{mx - pw / 2:.0f}" y="{y - 9:.0f}" width="{pw:.0f}" height="18" rx="9" fill="#fff" stroke="{accent}" stroke-opacity=".5"/>')
        A(f'<text x="{mx:.0f}" y="{y + 3.5:.0f}" text-anchor="middle" font-size="9.5" font-weight="700" fill="{accent}">{esc(label)}</text>')
        if note:
            A(f'<text x="{mx:.0f}" y="{y + 21:.0f}" text-anchor="middle" font-size="8.5" fill="{GRAY}">{esc(note)}</text>')
    return y0 + len(edges) * pitch


def _w3_campaign(c, module, spec):
    from netgen import incidents as INC
    inc = INC.REGISTRY[module]
    (h1, m1), (h2, m2) = inc.window
    start, end = h1 * 60 + m1, h2 * 60 + m2
    span = (end - start) * 60
    rstart, rwin, dur = _rel_start(start), _rel_win(start, end), _dur(end - start)
    accent = spec.get("accent", PLUM)
    W = 1180
    B = []; A = B.append
    _panel_title(A, 14, 20, spec["strip_title"], spec["strip_sub"].format(rwin=rwin, span=span // 60))
    _w3_timeline(A, W, 48, span, spec, accent)
    A(f'<line x1="14" y1="134" x2="{W - 14}" y2="134" stroke="#e4e4e8"/>')
    # left: plain-language lead, then key facts
    LX, LW = 14, 410
    y = 158
    _panel_title(A, LX, y, "IN PLAIN TERMS", "")
    y += 18
    y = _w3_text(A, LX, y, _wrap(spec["plain"], int(LW / 5.4)), 11, INK, 500, pitch=16) + 8
    _panel_title(A, LX, y, "KEY FACTS", "")
    y += 18
    for k, v in spec["facts"]:
        vl = _wrap(v, int((LW - 112) / 4.7))
        _w3_text(A, LX, y, [k], 8.5, GRAY, 700)
        y = _w3_text(A, LX + 112, y, vl, 9, SAPPHIRE, 500, pitch=12, mono=spec.get("facts_mono", False) and False) + 5
    left_bot = y
    # right: the tells, wrapped
    TX = 456
    TW = W - TX - 16
    ty = 158
    _panel_title(A, TX, ty, "THE TELLS", spec.get("tells_sub", ""))
    ty += 34
    cols = [accent, PLUM, TANGERINE, CYAN, SAPPHIRE, "#8a5cf0"]
    for i, (main, sub) in enumerate(spec["tells"]):
        sl = _wrap(sub, int((TW - 40) / 4.5))
        h = 18 + 12 * len(sl) + 6
        if i % 2 == 0:
            A(f'<rect x="{TX - 6}" y="{ty - 14}" width="{TW + 12}" height="{h}" fill="#fafafc"/>')
        A(f'<rect x="{TX}" y="{ty - 11}" width="16" height="15" rx="4" fill="{cols[i % 6]}"/>')
        A(f'<text x="{TX + 8}" y="{ty}" text-anchor="middle" font-size="8.5" font-weight="700" fill="#fff">{i + 1}</text>')
        A(f'<text x="{TX + 26}" y="{ty}" font-size="10.5" font-weight="700" fill="{SAPPHIRE}">{esc(main)}</text>')
        _w3_text(A, TX + 26, ty + 13, sl, 8.5, GRAY, 400, pitch=12)
        ty += h
    mid_bot = max(left_bot, ty) + 6
    A(f'<line x1="440" y1="146" x2="440" y2="{mid_bot - 6}" stroke="#e4e4e8"/>')
    A(f'<line x1="14" y1="{mid_bot}" x2="{W - 14}" y2="{mid_bot}" stroke="#e4e4e8"/>')
    fy = mid_bot + 24
    _panel_title(A, 14, fy, spec.get("net_title", "HOW THE TRAFFIC MOVES"), spec.get("net_sub", ""))
    end_y = _w3_flow(A, 14, fy + 18, W - 28, spec["net"], accent)
    if spec.get("legend"):
        _w3_text(A, 14, end_y + 14, [spec["legend"]], 8.5, GRAY)
        end_y += 18
    H = int(end_y + 16)
    svg = _svg_open(W, H, f'{spec["title"]} over {rwin}') + "".join(B) + "</svg>"
    return {
        "svg": svg,
        "kpis": [(rstart, "Window opens", "mono"), (dur, "Duration")] + spec.get("kpis", []),
        "sections": [("Finding it in a capture", _filters_table(spec["filters"]))],
        "notes": spec["notes"],
    }


@register("ndr-needymantis", "NeedyMantis",
          "A second, unrelated implant: fixed-UA HTTPS beacon, WebSocket upgrade, Impacket SMB",
          order=114, scenario="ndr-needymantis")
def d_needymantis(c):
    from netgen import incidents as INC
    ip = lambda n: _w3_ip(c, n)
    lo, hi = INC.NEEDY_CADENCE
    base = (lo + hi) // 2
    ws, wip = INC.NEEDY_WS, ip(INC.NEEDY_WS)
    net = [(ws, wip, "corp.tripswithengine.com", "104.21.81.147", "HTTPS :443 beacon", "every %d–%ds; one URI; WebSocket upgrade on first contact" % (lo, hi), False)]
    for off, t, _ in INC.NEEDY_LATERAL:
        net.append((ws, wip, t, ip(t), "SMB :445 ADMIN$", "+%dm: random 8-letter .exe written, then run as a service" % (off // 60), False))
    return _w3_campaign(c, "ndr-needymantis", {
        "net": net, "title": "NeedyMantis implant", "accent": "#8a5cf0",
        "strip_title": "CHECK-IN CADENCE", "strip_label": "check-ins",
        "strip_sub": "window {rwin} · first contact at +%ds, then a check-in every %d–%ds for {span} min; lateral SMB at +15, +25 and +35 min" % (INC.NEEDY_FIRST_AT, lo, hi),
        "ticks": (INC.NEEDY_FIRST_AT + base, base),
        "events": [(INC.NEEDY_FIRST_AT, "first contact +%ds" % INC.NEEDY_FIRST_AT), (900, "lateral SMB exec +15m / +25m / +35m"), (1500, None), (2100, None)],
        "plain": "One workstation, separate from the other attack chains, quietly phones home over ordinary HTTPS every few minutes, "
                 "then pushes a small program onto three servers over Windows file sharing. Each step looks routine; the combination does not.",
        "facts": [("Foothold", "%s  %s (its own, not %s)" % (ws, wip, INC.ATTACKER_WS)),
                  ("C2 domain", "corp.tripswithengine.com → 104.21.81.147 (CDN edge address; the domain is the indicator)"),
                  ("Beacon", "HTTPS :443, user agent firefox/21.0, one URI /library/zip/, every %d–%ds" % (lo, hi)),
                  ("First contact", "system info base64 in a Cookie, plus a one-time HTTP→WebSocket upgrade"),
                  ("Lateral targets", ", ".join("%s %s" % (t, ip(t)) for _, t, _ in INC.NEEDY_LATERAL) + " (SMB admin share, ADMIN$)")],
        "tells_sub": "benign protocols, used in a way a browser never does",
        "tells": [("Hard-coded ancient user agent", "firefox/21.0 on every request; no real browser sends it today"),
                  ("One fixed URI, forever", "GET /library/zip/ and nothing else, from one host"),
                  ("System info in a Cookie", "base64 metadata, first check-in only"),
                  ("HTTP→WebSocket upgrade", "Upgrade: websocket answered 101 Switching Protocols, once, at first contact"),
                  ("Impacket-style SMB exec", "a public toolkit that runs code over file sharing: an 8-letter .exe is written to ADMIN$ (the hidden admin share), then started through the service-control RPC pipe")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "the implant beacons out, then writes to three servers inside",
        "legend": "Arrows point client → server; replies return on the same connection. All lanes are seen on the sensor SPAN.",
        "kpis": [("~%ds" % base, "Check-in", "mono"), (ws, "Foothold", "mono"), (len(INC.NEEDY_LATERAL), "Lateral targets"), ("TLS", "All encrypted")],
        "filters": [("The implant beacon", 'tls.handshake.extensions_server_name == "corp.tripswithengine.com"', 'the C2 SNI, from one host'),
                    ("The fixed user agent", 'http.user_agent == "firefox/21.0"', 'decrypted; a browser never sends this'),
                    ("The one URI", 'http.request.uri == "/library/zip/"', 'every check-in'),
                    ("System-info cookie", 'http.cookie contains "SESSIONID"', 'first contact, base64 metadata'),
                    ("WebSocket upgrade", 'http.upgrade == "websocket" || http.response.code == 101', 'HTTP promoted to a WebSocket'),
                    ("Admin-share write", 'smb2.tree contains "ADMIN$" && ip.src == %s' % wip, 'an .exe written to ADMIN$ on the implant’s targets'),
                    ("Decrypted payloads", 'http.request && tcp.port == 443', 'only with -o tls.keylog_file')],
        "notes": [("warn", "A separate, unrelated intrusion", "This runs from a different foothold than the other NDR chains, with no lateral path between them and a disjoint set of victim servers. Correlating the two by shared host or target is wrong by construction: a large estate carries more than one intruder at a time."),
                  ("", "Benign protocols, anomalous shape", "Every packet is ordinary HTTPS and SMB. The detection is the combination: an antique user agent on one URI, a Cookie full of base64, an HTTP→WebSocket upgrade to a threat-intel domain, and service-style writes to ADMIN$."),
                  ("", "Indicator is real", "corp.tripswithengine.com is a published NeedyMantis C2, fronted by a CDN. It is a destination field in a synthetic capture and is never contacted; it is exported in the threat collection so a sensor's own intel matches.")]})



# ---- Campaign-C and standalone 4g scenario diagrams -----------------------------------------
# All eight share one renderer driven by a spec, so they read as a family and the per-row
# Visualize button lights for each. Hosts and window come from the registry/inventory; the
# facts and filters are the per-scenario content. Every filter here is validated non-zero.
def _netflow_panel(A, c, x0, y0, w, h, title, sub, edges, accent=PLUM):
    """A 'how the traffic traverses the network' panel, in the style of the lateral-movement SPREAD:
    source hosts on the left, target hosts on the right, a firewall / sensor-SPAN divider between
    them, and one labelled directed edge per flow. edges = [(s_label, s_ip, d_label, d_ip, proto,
    dashed)]; a dashed edge is a flow that is upstream of the SPAN (inferred, not directly seen)."""
    _panel_title(A, x0, y0, title, sub)
    A('<defs><marker id="nfar" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
      f'<path d="M0,0 L8,4 L0,8 Z" fill="{accent}"/></marker></defs>')
    top = y0 + 26
    srcs, dsts = [], []
    for sl, sip, dl, dip, pr, da in edges:
        if (sl, sip) not in srcs:
            srcs.append((sl, sip))
        if (dl, dip) not in dsts:
            dsts.append((dl, dip))
    nw = 172
    lx, rx = x0, x0 + w - nw
    midx = (lx + nw + rx) / 2
    pos = {}

    def node(x, i, n, label, ip, col, side):
        pitch = (h - 34) / max(1, n)
        cy = top + 6 + i * pitch
        A(f'<rect x="{x:.0f}" y="{cy:.0f}" width="{nw}" height="34" rx="8" fill="#fff" stroke="{col}" stroke-width="1.5"/>')
        A(f'<text x="{x+11:.0f}" y="{cy+14:.0f}" font-size="9.5" font-weight="800" fill="{SAPPHIRE}">{esc(label)}</text>')
        A(f'<text x="{x+11:.0f}" y="{cy+27:.0f}" font-size="8.5" fill="{GRAY}" font-family="ui-monospace,Menlo,monospace">{esc(ip)}</text>')
        pos[(side, label, ip)] = (x + (nw if side == "s" else 0), cy + 17)

    A(f'<line x1="{midx:.0f}" y1="{top}" x2="{midx:.0f}" y2="{y0+h-4:.0f}" stroke="#d5d6dc" stroke-dasharray="4 4"/>')
    A(f'<text x="{midx:.0f}" y="{top-3:.0f}" text-anchor="middle" font-size="8" fill="{GRAY}">firewall · sensor SPAN</text>')
    for i, (l, ip) in enumerate(srcs):
        node(lx, i, len(srcs), l, ip, SAPPHIRE, "s")
    for i, (l, ip) in enumerate(dsts):
        node(rx, i, len(dsts), l, ip, accent, "d")
    for sl, sip, dl, dip, pr, da in edges:
        x1, y1 = pos[("s", sl, sip)]
        x2, y2 = pos[("d", dl, dip)]
        dash = ' stroke-dasharray="5 3"' if da else ''
        A(f'<path d="M{x1:.0f},{y1:.0f} C {midx:.0f},{y1:.0f} {midx:.0f},{y2:.0f} {x2:.0f},{y2:.0f}" '
          f'fill="none" stroke="{accent}" stroke-width="1.6" opacity=".7"{dash} marker-end="url(#nfar)"/>')
        # label as a white pill on the curve near the target, where parallel edges have fanned apart
        t = 0.82
        bx = (1-t)**3*x1 + 3*(1-t)**2*t*midx + 3*(1-t)*t**2*midx + t**3*x2
        by = (1-t)**3*y1 + 3*(1-t)**2*t*y1 + 3*(1-t)*t**2*y2 + t**3*y2
        pw = len(pr) * 4.7 + 12
        A(f'<rect x="{bx-pw/2:.0f}" y="{by-7:.0f}" width="{pw:.0f}" height="14" rx="7" fill="#fff" '
          f'stroke="{accent}" stroke-width="0.8" opacity=".95"/>')
        A(f'<text x="{bx:.0f}" y="{by+3:.0f}" text-anchor="middle" font-size="8" fill="{accent}">{esc(pr)}</text>')


# Scenarios are allowed to generate traffic that dominates a device's normal protocol mix. When
# they do, the platform may reclassify that device (or give a workstation a server/scanner role) for the
# duration. That is expected, not a defect, so every attack/fault scenario diagram carries this note.
CLASSIFY_NOTE = ("warn", "Device role may shift in the platform",
                 "This scenario can generate enough traffic to dominate a participating device's "
                 "protocol mix, so the platform may reclassify that device — or a workstation may pick up "
                 "a server, scanner or attacker role — while the scenario runs. The deviation is "
                 "expected: it reflects the scenario, not a generation defect, and the device returns "
                 "to its baseline role once the scenario window passes.")


def _campaign_diagram(c, module, spec):
    from netgen import incidents as INC
    inc = INC.REGISTRY[module]
    (h1, m1), (h2, m2) = inc.window
    frm, to = f"{h1:02d}:{m1:02d}", f"{h2:02d}:{m2:02d}"
    span = ((h2 * 60 + m2) - (h1 * 60 + m1)) * 60
    rstart, rwin, dur = _rel_start(h1 * 60 + m1), _rel_win(h1 * 60 + m1, h2 * 60 + m2), _dur((h2*60+m2)-(h1*60+m1))
    foot = c.host(spec.get("foothold")) if spec.get("foothold") else None
    foot_ip = foot["ip"] if foot else spec.get("foothold_ip", "")
    accent = spec.get("accent", PLUM)
    has_net = bool(spec.get("net"))
    div_bottom = 388 if has_net else None
    W, H = 1180, (600 if has_net else 470)
    if div_bottom is None:
        div_bottom = H - 10
    P = []; A = P.append
    A(_svg_open(W, H, f'{spec["title"]} over {rwin}'))
    _panel_title(A, 14, 20, spec["strip_title"], spec["strip_sub"].format(frm=frm, to=to, span=span // 60, rwin=rwin))
    # a simple time strip with the window marked
    L, R = 120, W - 30
    ay = 96
    A(f'<line x1="{L}" y1="{ay}" x2="{R}" y2="{ay}" stroke="#d5d6dc" stroke-width="1.4"/>')
    for mm in range(0, span // 60 + 1, max(20, (span // 60) // 8 or 20)):
        x = L + (R - L) * min(1.0, mm * 60 / span)
        A(f'<line x1="{x:.1f}" y1="{ay-4}" x2="{x:.1f}" y2="{ay+4}" stroke="#c9cad0"/>')
        A(f'<text x="{x:.1f}" y="{ay+16}" text-anchor="middle" font-size="9" fill="{GRAY}">+{mm}m</text>')
    A(f'<line x1="14" y1="128" x2="{W-14}" y2="128" stroke="#e4e4e8"/>')
    if foot:
        _actor_box(A, 120, 150, spec["foothold"], foot_ip, sub=spec.get("foothold_sub", "campaign-C foothold"))
        A(f'<text x="120" y="206" text-anchor="middle" font-size="9" fill="{GRAY}">{esc(spec.get("foothold_note",""))}</text>')
    if spec.get("infra_keys"):
        _infra_panel(A, c, 300, 142, 430, spec["infra_keys"], spec.get("infra_title","EXTERNAL INFRASTRUCTURE"),
                     spec.get("infra_sub","real, published indicators — never contacted"))
        A(f'<line x1="770" y1="140" x2="770" y2="{div_bottom}" stroke="#e4e4e8"/>')
        tx = 794
    else:
        A(f'<line x1="300" y1="140" x2="300" y2="{div_bottom}" stroke="#e4e4e8"/>')
        tx = 324
    _panel_title(A, tx, 150, "THE TELLS", spec.get("tells_sub",""))
    rows = [(str(i+1), [accent, PLUM, TANGERINE, CYAN, SAPPHIRE, "#8a5cf0"][i % 6], t[0], t[1], "")
            for i, t in enumerate(spec["tells"])]
    _rows(A, tx, 190, W - tx - 20, rows, pitch=32)
    if has_net:
        A(f'<line x1="14" y1="396" x2="{W-14}" y2="396" stroke="#e4e4e8"/>')
        _netflow_panel(A, c, 14, 414, W - 28, H - 426,
                       spec.get("net_title", "HOW THE TRAFFIC MOVES"),
                       spec.get("net_sub", "source hosts → targets, across the firewall / sensor SPAN"),
                       spec["net"], accent)
    A('</svg>')
    return {
        "svg": "".join(P),
        "kpis": [(rstart, "Window opens", "mono"), (dur, "Duration")] + spec.get("kpis", []),
        "sections": [("Finding it in a capture", _filters_table(spec["filters"]))],
        "notes": spec["notes"],
    }


@register("ndr-edge-exploit", "Edge-device exploit", "Inbound VPN exploit, then the edge device pivots inward",
          order=115, scenario="ndr-edge-exploit")
def d_edge(c):
    ip = lambda n: _w3_ip(c, n)
    fw = "10.10.20.1"
    net = [("external attacker", "203.0.113.66", "EXL-FW1 (VPN portal)", fw, "HTTPS :443 exploit", "3 POSTs in the first seconds; crafted SESSID cookie", False)]
    net += [("EXL-FW1 (inside)", fw, "DC1 / FILE1 / MGMT1", "10.10.20.10, .20, .110", "SMB :445 ADMIN$", "one server per pivot, picked at random, every 8–18 min", False),
            ("EXL-WS-009", ip("EXL-WS-009"), "flux C2 node", "91.211.247.42", "HTTPS :443 /gate.php", "beachhead beacons out from +90s", False)]
    return _w3_campaign(c, "ndr-edge-exploit", {
        "net": net, "title": "Edge-device exploitation", "accent": "#b23f0f",
        "strip_title": "ENTRY → PIVOT", "strip_label": "inward pivots",
        "strip_sub": "window {rwin} · exploit burst at the start, then an inward pivot every 8–18 min for {span} min",
        "ticks": (60, 780),
        "events": [(10, "+10s exploit ×3 · +1m first pivot · +90s beachhead C2"), (60, None), (90, None)],
        "plain": "An attacker breaks into the company's VPN gateway from the internet. From then on the gateway itself starts reaching into internal servers, "
                 "which a firewall never does, and a workstation starts calling out to an attacker server.",
        "facts": [("Attacker", "203.0.113.66 (external)"),
                  ("Edge device", "EXL-FW1 inside interface %s, on the monitored server segment" % fw),
                  ("Exploit", "POST /ssl-vpn/hipreport.esp with a path-traversal SESSID cookie; sent framed on the monitored segment, so the sensor sees it"),
                  ("Pivot", "SMB to ADMIN$ with the harvested account svc_backup (NTLM), one of EXL-DC1, EXL-FILE1, EXL-MGMT1 each time"),
                  ("Beachhead", "EXL-WS-009 %s beacons to sync-7f3a.livefeed-cdn.net (91.211.247.42)" % ip("EXL-WS-009"))],
        "tells_sub": "the aftermath is what the sensor sees",
        "tells": [("Inbound VPN exploit", "POST to the portal path /ssl-vpn/hipreport.esp with a traversal string in the SESSID cookie and a 2–6 KB body; the answer is a normal 200"),
                  ("Edge device originates inward", "the gateway's inside interface writes to ADMIN$ on servers; it never does that when healthy"),
                  ("Beachhead C2", "EXL-WS-009 opens HTTPS /gate.php sessions to the fast-flux node"),
                  ("Anomalous origin, ordinary protocol", "SMB from a network appliance is the signal, not SMB itself")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "inbound exploit, inward pivot from the gateway, then the beachhead beacons out",
        "legend": "Arrows point client → server. The VPN exploit is generated on the monitored segment so the sensor can see it.",
        "kpis": [("VPN", "Exploit vector"), ("edge", "Compromised asset"), ("inward", "Pivot direction")],
        "filters": [("Inbound exploit", 'ip.src == 203.0.113.66 && tcp.dstport == 443', 'the three exploit sessions at the start'),
                    ("Edge pivots inward", 'smb2 && ip.src == %s' % fw, "the gateway's inside interface originating SMB"),
                    ("Beachhead C2", 'ip.dst == 91.211.247.42', 'the landed host beaconing out')],
        "notes": [("warn", "The aftermath is the finding", "A healthy edge device does not originate admin protocols toward servers. Seeing it do so, right after an exploit against its own portal, is the signal."),
                  ("", "Dominant entry vector", "Exploiting internet-facing VPN and firewall appliances is a leading initial-access route for ransomware and espionage crews.")]})


@register("ndr-rdp-brute", "Exposed-RDP brute", "Internet brute of the jump host: failures then a success",
          order=116, scenario="ndr-rdp-brute")
def d_rdpbrute(c):
    ip = lambda n: _w3_ip(c, n)
    net = [("brute-force pool", "203.0.113.90", "EXL-MGMT1 (jump host)", ip("EXL-MGMT1"), "RDP :3389, many failures", "~40 attempts at scale 1 (min 6), 1.5–6 s apart, each RST or closed", False),
           ("brute-force pool", "203.0.113.90", "EXL-MGMT1 (jump host)", ip("EXL-MGMT1"), "RDP :3389, one success", "last attempt completes and stays open 20–120 s", False)]
    return _w3_campaign(c, "ndr-rdp-brute", {
        "net": net, "title": "Exposed-RDP brute force", "accent": "#b23f0f",
        "strip_title": "BRUTE → LANDING", "strip_label": "attempts",
        "strip_sub": "window {rwin} · a burst of failed logons in the first few minutes, then one that works",
        "ticks": (20, 4.0, 200),
        "events": [(20, "failures start +20s (~every 4s)"), (220, "success ~3\u20134 min in")],
        "plain": "Someone on the internet repeatedly tries to log on to the company's remote-desktop jump host with guessed accounts. "
                 "Most attempts fail; one finally gets in and stays connected.",
        "facts": [("Source", "203.0.113.90 (external brute-force pool)"),
                  ("Target", "EXL-MGMT1 %s, RDP exposed to the internet" % ip("EXL-MGMT1")),
                  ("Accounts tried", "administrator, admin, backup, svc_admin, user1, support (cycled)"),
                  ("Failure shape", "TCP handshake, X.224 connect, TLS, a short CredSSP exchange (the server rejects the credential), then a reset or close"),
                  ("Success", "same handshake, then a long session with large server-to-client screen updates")],
        "tells_sub": "volume, then a single success",
        "tells": [("Many short 3389 connects", "each ends right after a rejected CredSSP exchange (CredSSP is the network-level logon step), by RST or close"),
                  ("From one external source", "203.0.113.90, a brute-force pool node"),
                  ("Then a full session", "one attempt completes TLS and CredSSP and then stays open for 20–120 s"),
                  ("Success is the pivot point", "the single completing session is the foothold")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "internet → the exposed jump host: failed logons, then one session that stays up",
        "legend": "Arrows point client → server; the server answers on the same connection.",
        "kpis": [("3389", "Port"), ("EXL-MGMT1", "Target"), ("1", "Success among many")],
        "filters": [("All brute attempts", 'ip.src == 203.0.113.90 && tcp.dstport == 3389', 'failures and the success'),
                    ("Failed attempts", 'ip.src == 203.0.113.90 && tcp.flags.reset == 1', 'RST on about 60% of failures; the rest close with a TLS alert'),
                    ("The successful session", 'ip.src == 203.0.113.90 && tls.handshake', 'present on every attempt; the long-lived one is the success')],
        "notes": [("warn", "The exception is the one that works", "Dozens of failures are noise; the single completing session is the intrusion. The pattern is many, then one."),
                  ("", "Exposed RDP", "Internet-reachable RDP on an admin jump host remains a leading ransomware entry vector.")]})


@register("ndr-infostealer", "Infostealer", "Credential archive uploaded to a stealer panel",
          order=117, scenario="ndr-infostealer")
def d_stealer(c):
    ip = lambda n: _w3_ip(c, n)
    net = [("EXL-WS-061", ip("EXL-WS-061"), "stealer panel", "45.139.104.77", "HTTPS :443 POST /c2sock", "one 40–160 KB archive at +1–4 min; 1–3 tiny heartbeats later", False)]
    return _w3_campaign(c, "ndr-infostealer", {
        "net": net, "title": "Infostealer exfiltration", "accent": TANGERINE,
        "strip_title": "ONE-SHOT EXFIL", "strip_label": "uploads",
        "strip_sub": "window {rwin} · one early archive upload, then 1–3 small heartbeats over the next hour",
        "events": [(150, "archive upload (+1–4 min)"), (1800, "heartbeats (+10–50 min)")],
        "plain": "A password-stealing program on one workstation packs up saved browser logins and cookies and uploads them once to its operator's web panel, then goes mostly quiet.",
        "facts": [("Victim", "EXL-WS-061 %s" % ip("EXL-WS-061")),
                  ("Panel", "panel.redtraffic-stats.top (45.139.104.77), published indicator, never contacted"),
                  ("Upload", "HTTPS POST /c2sock, multipart file sys.dat, 40–160 KB, answered by a tiny JSON ack"),
                  ("Heartbeats", "1–3 POSTs of 60–300 bytes (chk.dat) between +10 and +50 min"),
                  ("Client", "truncated Mozilla user agent and its own TLS fingerprint, not the victim's browser")],
        "tells_sub": "commodity eCrime, then quiet",
        "tells": [("Client→server-heavy upload", "the body of the POST is tens of KB; the reply is a few bytes, the reverse of normal browsing"),
                  ("Runs once on infection", "early and one-shot, not a beacon"),
                  ("To a published panel", "panel.redtraffic-stats.top / 45.139.104.77"),
                  ("Stage 0 of the stream", "how the broker got the credentials later sold to the state actor")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "the victim uploads the credential archive out to the panel",
        "legend": "Arrow points client → server; the large payload travels along the arrow.",
        "kpis": [("EXL-WS-061", "Victim", "mono"), ("1-shot", "Cadence"), ("exfil", "Purpose")],
        "filters": [("Exfil to panel", 'ip.dst == 45.139.104.77', 'the credential upload'),
                    ("By SNI", 'tls.handshake.extensions_server_name == "panel.redtraffic-stats.top"', 'the stealer panel'),
                    ("Asymmetric upload", 'ip.dst == 45.139.104.77 && tcp.len > 1000', 'client-heavy, the archive going out')],
        "notes": [("", "Commodity, but the on-ramp", "Infostealers are high-volume eCrime; in this stream it is the broker's stage 0 that enabled the targeted intrusion."),
                  ("", "Indicator is real", "The panel address is a published infostealer indicator; it is a destination field, never contacted.")]})


@register("ndr-fastflux", "Fast-flux / DGA C2", "Algorithmic NXDOMAIN bursts, then a rotating C2",
          order=118, scenario="ndr-fastflux")
def d_fastflux(c):
    ip = lambda n: _w3_ip(c, n)
    w9 = ip("EXL-WS-009")
    net = [("EXL-WS-009", w9, "EXL-DC1 (DNS)", ip("EXL-DC1"), "DNS :53 → NXDOMAIN", "4–8 random names per attempt, all fail", False),
           ("EXL-WS-009", w9, "EXL-DC1 (DNS)", ip("EXL-DC1"), "DNS :53 → answer", "the stable name returns 3–6 rotating node addresses", False),
           ("EXL-WS-009", w9, "flux C2 node", "91.211.247.42", "HTTPS :443 /gate.php", "short check-in to the first node returned", False)]
    return _w3_campaign(c, "ndr-fastflux", {
        "net": net, "title": "Fast-flux / DGA C2", "accent": "#8a5cf0",
        "strip_title": "DGA RESOLUTION", "strip_label": "attempts",
        "strip_sub": "window {rwin} · an attempt every 5–9 min: failing lookups, then one that resolves and a short beacon",
        "ticks": (40, 420),
        "events": [(40, "first attempt +40s")],
        "plain": "A workstation looks up a string of nonsense domain names, hunting for its operator's server (this is how some malware stays reachable when addresses get blocked). "
                 "Most lookups fail; one real name answers with a changing list of servers, and the host connects to one.",
        "facts": [("Host", "EXL-WS-009 %s (beachhead)" % w9),
                  ("Resolver", "EXL-DC1 %s" % ip("EXL-DC1")),
                  ("Per attempt", "4–8 algorithmic names → NXDOMAIN, then the stable name → 3–6 rotating A records (TTL 60–300 s)"),
                  ("C2 name", "sync-7f3a.livefeed-cdn.net (anchor node 91.211.247.42), published indicator"),
                  ("Cadence", "one attempt every 5–9 min, first at +40 s")],
        "tells_sub": "DNS used to FIND the C2, not to hide data",
        "tells": [("Bursts of NXDOMAIN", "4–8 algorithmic names that do not resolve, per attempt"),
                  ("High-entropy labels", "random-looking strings, not words"),
                  ("Then one resolves", "to a rotating set of flux nodes; a brief HTTPS /gate.php check-in follows"),
                  ("Distinct from DNS tunnelling", "here DNS locates the C2; it does not carry the payload")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "lookups fail at the resolver until one answers, then a short HTTPS beacon",
        "legend": "Arrows point client → server; DNS answers return on the same exchange.",
        "kpis": [("DGA", "Domain gen"), ("NXDOMAIN", "The tell"), ("rotating", "A records")],
        "filters": [("NXDOMAIN bursts", 'dns.flags.rcode == 3 && ip.src == %s' % w9, 'algorithmic lookups that fail'),
                    ("The live C2", 'ip.dst == 91.211.247.42', 'anchor flux node (the answer set rotates, so other nodes also appear)'),
                    ("By SNI/domain", 'tls.handshake.extensions_server_name contains "livefeed-cdn"', 'the C2 that answered')],
        "notes": [("warn", "Entropy and NXDOMAIN rate", "A host emitting bursts of high-entropy names that mostly fail is running a domain-generation algorithm. The one that resolves is the live C2."),
                  ("", "Indicator is real", "The flux domain and address are a published fast-flux C2 indicator; they are destination fields, never contacted.")]})


@register("ndr-salt-typhoon", "Salt Typhoon", "Long-slow SNMP espionage against network devices",
          order=119, scenario="ndr-salt-typhoon")
def d_salt(c):
    from netgen import incidents as INC
    ip = lambda n: _w3_ip(c, n)
    w = ip("EXL-WS-061")
    net = [("EXL-WS-061", w, d, ip(d), "SNMP :161 walk", "GetBulk of the interface table, community public" if i == 0 else "", False) for i, d in enumerate(INC.SALT_DEVICES)]
    return _w3_campaign(c, "ndr-salt-typhoon", {
        "net": net, "title": "Salt Typhoon network-device espionage", "accent": CYAN,
        "strip_title": "SLOW SNMP SWEEP", "strip_label": "walks",
        "strip_sub": "window {rwin} · one randomly chosen device walked every 7–15 min for {span} min",
        "ticks": (120, 660),
        "events": [(120, "first walk +2 min")],
        "plain": "A workstation asks the company's network gear (switch, wireless controller, sensor, time and log servers) to list its settings and interfaces over SNMP, a management protocol, "
                 "slowly and for hours. Mapping the plumbing is how espionage crews prepare to live inside it.",
        "facts": [("Collector", "EXL-WS-061 %s" % w),
                  ("Targets", ", ".join("%s %s" % (d.replace("EXL-", ""), ip(d)) for d in INC.SALT_DEVICES)),
                  ("Method", "SNMP v2c GetBulk walks of the interface table, UDP 161, community “public”, ending in endOfMibView"),
                  ("Cadence", "one device (random) every 7–15 min, first at +2 min")],
        "tells_sub": "espionage cadence: quiet, patient, infrastructure-focused",
        "tells": [("SNMP walks of network gear", "switch, wireless controller, sensor, NTP and syslog hosts, not application servers"),
                  ("Default read string", "“public” is the first community a careful operator tries"),
                  ("Long and slow", "spread across hours, never a burst"),
                  ("From a workstation", "SNMP management normally comes from a monitoring server, not an end-user PC")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "the collector walks each network device in turn (one device per visit, chosen at random)",
        "legend": "Arrows point poller → device; each device answers on the same UDP exchange.",
        "kpis": [("SNMP", "Protocol"), ("5 devices", "Targets"), ("espionage", "Intent")],
        "filters": [("SNMP from the collector", 'snmp && ip.src == %s' % w, 'the walks'),
                    ("Against the switch", 'snmp && ip.dst == %s' % ip("EXL-SWB1"), 'the distribution switch'),
                    ("Public community", 'snmp.community == "public"', 'the read string used')],
        "notes": [("warn", "Who is being asked, not just what", "Sustained SNMP against switches, controllers and sensors from a workstation is reconnaissance of the infrastructure itself. This generator models the recon only, not a configuration pull."),
                  ("", "Nation-state espionage", "Salt Typhoon is a state-linked actor reported against telecoms and their network devices.")]})


@register("ndr-webshell", "Web shell", "Decrypted commands POSTed to a planted shell",
          order=120, scenario="ndr-webshell")
def d_webshell(c):
    ip = lambda n: _w3_ip(c, n)
    net = [("EXL-WS-023", ip("EXL-WS-023"), "EXL-WEB2", ip("EXL-WEB2"), "HTTPS POST :443", "/app/uploads/sync.aspx, body cmd=…, output in the reply", False)]
    return _w3_campaign(c, "ndr-webshell", {
        "net": net, "title": "Web shell on an internal server", "accent": PLUM,
        "strip_title": "HANDS-ON-KEYBOARD", "strip_label": "commands",
        "strip_sub": "window {rwin} · clusters of 2–5 commands 8–40 s apart, separated by 3–10 min of quiet",
        "events": [(60, "first command +1 min")],
        "plain": "An attacker uses a hidden web page planted on the company's internal web server as a remote command line: each request carries one command, each reply carries its output.",
        "facts": [("Operator", "EXL-WS-023 %s" % ip("EXL-WS-023")),
                  ("Server", "EXL-WEB2 %s, HTTPS :443" % ip("EXL-WEB2")),
                  ("Shell URI", "POST /app/uploads/sync.aspx, form body cmd=<command>"),
                  ("Commands", "whoami /all, net group \"domain admins\", tasklist /v, ipconfig /all, systeminfo, …"),
                  ("Reply", "200 OK HTML of 0.4–4 KB carrying the command output")],
        "tells_sub": "ordinary HTTPS, extraordinary content",
        "tells": [("POST to one odd URI", "/app/uploads/sync.aspx: an upload folder serving a script that only ever receives POSTs"),
                  ("Command in the body", "cmd=whoami, net group, tasklist, readable once decrypted"),
                  ("Output in the response", "HTML carrying command results"),
                  ("Clustered, then idle", "bursts of commands with human-length gaps")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "decrypted commands POSTed to the planted shell on the line-of-business server",
        "legend": "Arrow points client → server; each reply carries the command output back.",
        "kpis": [("EXL-WEB2", "Host", "mono"), ("POST", "Method"), ("decrypt", "In clear with keys")],
        "filters": [("Web shell POSTs", 'http.request.uri == "/app/uploads/sync.aspx"', 'decrypted; command in the body'),
                    ("Only POSTs to it", 'http.request.method == "POST" && http.request.uri contains "sync.aspx"', 'never a GET'),
                    ("On the LOB app", 'ip.dst == %s && tcp.port == 443' % ip("EXL-WEB2"), 'EXL-WEB2')],
        "notes": [("warn", "Method and path, then content", "An upload path that only ever serves POSTs carrying shell commands is a web shell. The decrypted body removes all doubt."),
                  ("", "Persistence", "A planted shell on an internal app is resilient access that survives a cleaned workstation.")]})


@register("ndr-volt-typhoon", "Volt Typhoon LOTL", "Valid-account admin protocols, no malware",
          order=121, scenario="ndr-volt-typhoon")
def d_volt(c):
    ip = lambda n: _w3_ip(c, n)
    w = ip("EXL-WS-009")
    net = [("EXL-WS-009", w, "EXL-DC1 (directory)", ip("EXL-DC1"), "Kerberos :88 + LDAP :389", "3 directory searches: machines, Domain Admins, SPN accounts", False),
           ("EXL-WS-009", w, "DC1 / FILE1 / SQL1 / MGMT1", "random pick each time", "SMB :445 C$", "browse System32\\config or Users, read 1–2 small files", False),
           ("EXL-WS-009", w, "DC1 / FILE1 / SQL1 / MGMT1", "random pick each time", "RDP :3389", "a 60–150 s interactive session (1 action in 5)", False)]
    return _w3_campaign(c, "ndr-volt-typhoon", {
        "net": net, "title": "Volt Typhoon living-off-the-land", "accent": SAPPHIRE,
        "strip_title": "LOW AND SLOW", "strip_label": "admin touches",
        "strip_sub": "window {rwin} · one quiet admin action every 18–37 min for {span} min, nothing bursty",
        "ticks": (200, 1650),
        "events": [(200, "first action +3 min")],
        "plain": "No malware at all. A workstation uses the company's own admin tools and a valid login to look around the directory and file shares, "
                 "a few times an hour, exactly like an administrator would but from a PC that never does that.",
        "facts": [("Beachhead", "EXL-WS-009 %s with a valid account" % w),
                  ("Actions", "cycle: LDAP, SMB, LDAP, SMB, RDP; one every 18–37 min, first at +200 s"),
                  ("LDAP", "always to the domain controller (Kerberos service ticket, then 3 searches)"),
                  ("SMB / RDP", "to a random one of EXL-DC1, EXL-FILE1, EXL-SQL1, EXL-MGMT1"),
                  ("Malware / C2", "none, by design")],
        "tells_sub": "no malware; the deviation IS the detection",
        "tells": [("Valid-account admin protocols", "LDAP and Kerberos to the domain controller, SMB C$ browsing and occasional RDP to servers"),
                  ("From a host that never does", "a user workstation behaving like a jump host"),
                  ("Low rate, wide gaps", "18–37 minutes apart, all window long"),
                  ("Nothing signature-based fires", "no C2, no payload: only the baseline deviation")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "valid-account admin protocols from a workstation into the server tier",
        "legend": "Arrows point client → server. SMB and RDP targets rotate; each action goes to one server.",
        "kpis": [("none", "Malware"), ("valid", "Accounts"), ("baseline", "The detection")],
        "filters": [("Admin protocols from the beachhead", 'ip.src == %s && (tcp.port == 445 || tcp.port == 3389)' % w, 'SMB/RDP it does not normally originate'),
                    ("Directory touches", 'ip.src == %s && (tcp.port == 88 || tcp.port == 389)' % w, 'Kerberos tickets and LDAP searches'),
                    ("To the servers", 'ip.src == %s && ip.dst == 10.10.20.0/24' % w, 'a workstation reaching the server tier')],
        "notes": [("warn", "There is nothing to signature", "No malware, no C2, no known indicator. The detection is behavioural: a host doing what it has never done, measured against a baseline."),
                  ("", "Pre-positioning", "Volt Typhoon is reported to pre-position inside critical infrastructure for future disruption.")]})


@register("ndr-coercion-adcs", "Coercion → AD CS", "PetitPotam → NTLM relay → AD CS → Domain Admin",
          order=122, scenario="ndr-coercion-adcs")
def d_coercion(c):
    ip = lambda n: _w3_ip(c, n)
    r = ip("EXL-WS-023")
    net = [("EXL-WS-023 (relay)", r, "EXL-FILE1 (victim)", ip("EXL-FILE1"), "1 SMB :445 efsrpc pipe", "PetitPotam: EfsRpcOpenFileRaw makes FILE1 authenticate back", False),
           ("EXL-FILE1 (victim)", ip("EXL-FILE1"), "EXL-WS-023 (relay)", r, "2 SMB :445 NTLM", "the coerced callback: NTLM negotiate, then authenticate", False),
           ("EXL-WS-023 (relay)", r, "EXL-DC2 (AD CS)", ip("EXL-DC2"), "3 HTTPS :443 /certsrv", "the same NTLM relayed; machine certificate issued and fetched", False),
           ("EXL-WS-023 (relay)", r, "EXL-DC1 (KDC)", ip("EXL-DC1"), "4 Kerberos :88 PKINIT", "the certificate buys a ticket as FILE1$", False)]
    return _w3_campaign(c, "ndr-coercion-adcs", {
        "net": net, "title": "Coercion to AD CS (ESC8)", "accent": "#8a5cf0",
        "strip_title": "FOUR HOPS TO DOMAIN ADMIN", "strip_label": "chains",
        "strip_sub": "window {rwin} · the four-hop chain fires up to 6 times in the first ~40 min (retries); the rest of the window is quiet",
        "events": [(200, "first chain +3m20s")],
        "plain": "An attacker tricks a file server into logging on to the attacker's PC, passes that logon on to the company's certificate server to get a certificate in the server's name, "
                 "then swaps the certificate for a Kerberos ticket. A ticket for a powerful machine account can mean control of the whole domain.",
        "facts": [("Relay", "EXL-WS-023 %s" % r),
                  ("Victim machine account", "EXL-FILE1$ %s" % ip("EXL-FILE1")),
                  ("Certificate server", "EXL-DC2 %s (web enrollment /certsrv/certfnsh.asp)" % ip("EXL-DC2")),
                  ("Ticket service", "EXL-DC1 %s (PKINIT)" % ip("EXL-DC1")),
                  ("Repeats", "up to 6 chains, a few minutes apart, first at +200 s")],
        "tells_sub": "each hop in a protocol already on the network",
        "tells": [("MS-EFSR coercion", "EfsRpcOpenFileRaw over the SMB IPC$ pipe \\pipe\\efsrpc; this is PetitPotam"),
                  ("Coerced auth to the relay", "the victim's machine account authenticates to a workstation, where it should not"),
                  ("Relay to the CA web endpoint", "POST /certsrv/certfnsh.asp carrying the relayed NTLM; web enrollment accepts it without signing"),
                  ("A certificate, then a PKINIT TGT", "the issued certificate is exchanged for a Kerberos ticket granting ticket")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "numbered in the order the hops happen within one chain",
        "legend": "Arrows point initiator → responder. Hop 2 runs back toward the relay because the victim is coerced into connecting out.",
        "kpis": [("ESC8", "Technique"), ("EXL-DC2", "The CA", "mono"), ("4 hops", "Per chain")],
        "filters": [("MS-EFSR coercion", 'dcerpc.cn_bind_to_uuid == c681d488-d850-11d0-8c52-00c04fd90f7e', 'the EfsRpcOpenFileRaw interface'),
                    ("Coerced machine auth", 'ntlmssp && ip.src == %s && ip.dst == %s' % (ip("EXL-FILE1"), r), 'the victim authenticating to the relay'),
                    ("CA web enrollment", 'http.request.uri contains "certsrv"', 'the relayed enrollment, decrypted')],
        "notes": [("warn", "The chain still works", "As SMB signing and LDAP channel binding closed older relay paths, AD CS HTTP enrollment, which cannot require signing, kept the coercion-relay-ticket chain alive."),
                  ("", "All four hops are visible", "Coercion RPC, the coerced NTLM, the certsrv POST and the PKINIT ticket are each in a protocol the sensor already sees.")]})



@register("ndr-dns-tunneling", "DNS tunnelling",
          "Encoded subdomains and TXT replies through the internal resolver", order=104,
          scenario="ndr-dns-tunneling")
def d_dnstun(c):
    k = _scn(c, "ndr-dns-tunneling"); INC = k["INC"]
    W, H = 1180, 440
    P = []; A = P.append
    A(_svg_open(W, H, f'DNS tunnelling from {k["who"]} over {k["rwin"]}'))
    _panel_title(A, 14, 20, "THE PATH",
                 "the workstation never talks to the attacker nameserver directly \u2014 the "
                 "internal resolver does it for them")
    dc = c.host("EXL-DC1")
    ns = next((r for r in _ext_rows(c, ["dnsns"])), None)
    y = 110
    _actor_box(A, 130, y, INC.ATTACKER_WS, k["atk_ip"])
    A(f'<rect x="440" y="{y - 24}" width="160" height="48" rx="10" fill="{SAPPHIRE}"/>')
    A(f'<text x="520" y="{y - 5}" text-anchor="middle" font-size="11" font-weight="900" fill="#fff">EXL-DC1</text>')
    A(f'<text x="520" y="{y + 9}" text-anchor="middle" font-size="9" fill="#d9d5ea" '
      f'font-family="ui-monospace,Menlo,monospace">{esc(dc["ip"] if dc else "")}</text>')
    A(f'<text x="520" y="{y + 20}" text-anchor="middle" font-size="8" fill="#d9d5ea">internal resolver</text>')
    A(f'<rect x="830" y="{y - 24}" width="250" height="48" rx="10" fill="{PLUM}"/>')
    A(f'<text x="955" y="{y - 5}" text-anchor="middle" font-size="11" font-weight="900" fill="#fff">'
      f'{esc(ns[1] if ns else "attacker NS")}</text>')
    A(f'<text x="955" y="{y + 9}" text-anchor="middle" font-size="9" fill="#f0d5e0" '
      f'font-family="ui-monospace,Menlo,monospace">{esc(ns[2] if ns else "")}</text>')
    A(f'<text x="955" y="{y + 20}" text-anchor="middle" font-size="8" fill="#f0d5e0">{esc(ns[3] if ns else "")}</text>')
    A(f'<line x1="206" y1="{y}" x2="434" y2="{y}" stroke="{PLUM}" stroke-width="2"/>')
    A(f'<text x="320" y="{y - 8}" text-anchor="middle" font-size="9.5" font-weight="700" fill="{PLUM}">'
      f'TXT query, encoded label</text>')
    A(f'<text x="320" y="{y + 16}" text-anchor="middle" font-size="8.5" fill="{GRAY}">udp/53 \u2014 looks ordinary</text>')
    A(f'<line x1="606" y1="{y}" x2="824" y2="{y}" stroke="{GRAY}" stroke-width="2" stroke-dasharray="5 4"/>')
    A(f'<text x="715" y="{y - 8}" text-anchor="middle" font-size="9.5" font-weight="700" fill="{GRAY}">recursion</text>')
    A(f'<text x="715" y="{y + 16}" text-anchor="middle" font-size="8.5" fill="{GRAY}">resolver \u2192 attacker NS</text>')
    A(f'<line x1="14" y1="172" x2="{W - 14}" y2="172" stroke="#e4e4e8"/>')

    _panel_title(A, 14, 194, "QUERY ANATOMY", "what each tunnelled request actually carries")
    lo, hi = INC.DNSTUN_LABEL_BYTES; tlo, thi = INC.DNSTUN_TXT_BYTES
    thi = min(thi, 160)        # dns_tunnel_burst draws the TXT answer from randint(40, 160); the constant overstates it
    blo, bhi = INC.DNSTUN_BURST; glo, ghi = INC.DNSTUN_GAP
    rows = [("qname", PLUM, "base32-encoded label prefixed to the tunnel domain",
             f'{lo}\u2013{hi} bytes of payload per query', ""),
            ("qtype", TANGERINE, "TXT", "the record type that can carry arbitrary bytes back", ""),
            ("answer", CYAN, "TXT rdata", f'{tlo}\u2013{thi} bytes returned per answer', ""),
            ("burst", SAPPHIRE, f'{blo}\u2013{bhi} queries per burst',
             f'a new burst every {glo}\u2013{ghi}s for {k["span"] // 60} minutes', "")]
    _rows(A, 14, 232, 540, rows, pitch=34)
    A(f'<line x1="596" y1="184" x2="596" y2="{H - 10}" stroke="#e4e4e8"/>')
    _panel_title(A, 620, 194, "WHY IT STANDS OUT", "against the resolver's ordinary traffic")
    facts = [("1", PLUM, "Query volume to one domain",
              "hundreds of names under a single zone, none repeated", ""),
             ("2", TANGERINE, "Label length and entropy",
              f'{lo}\u2013{hi} bytes of base32 where real names are short words', ""),
             ("3", CYAN, "TXT-only", "almost nothing legitimate asks this resolver for TXT at volume", ""),
             ("4", SAPPHIRE, "No caching effect", "every name is unique, so nothing ever hits cache", "")]
    _rows(A, 620, 232, W - 640, facts, pitch=34)
    A('</svg>')

    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 (f'{blo}\u2013{bhi}', "Queries per burst"), (f'{glo}\u2013{ghi}s', "Burst gap", "mono"),
                 ("TXT", "Record type"), (f'{lo}\u2013{hi}B', "Payload per query", "mono")],
        "sections": [("Finding it in a capture", _filters_table([
            ("The tunnel domain", f'dns.qry.name contains "{INC.TUNNEL_DOMAIN.split(".", 1)[1]}"',
             'every tunnelled query'),
            ("TXT queries from the host", f'dns.qry.type == 16 && ip.src == {k["atk_ip"]}',
             'the client side'),
            ("Long encoded labels", 'dns.qry.name.len > 50', 'real names are far shorter'),
            ("The attacker nameserver", f'ip.addr == {ns[2] if ns else ""}',
             'resolver\u2192NS, not client\u2192NS'),
        ]))],
        "notes": [
            ("warn", "It is the resolver that egresses",
             "The workstation only ever talks to EXL-DC1 on udp/53, which is completely normal. "
             "A control that only watches direct egress from endpoints sees nothing."),
            ("", "The nameserver address is a real indicator",
             "The tunnel NS reuses a documented QakBot C2 address, so a sensor's threat intel "
             "matches on the resolver's outbound query."),
            ("", "It chains", "Phase 4 of ndr-scattered-spider."),
        ],
    }


def _vol_bar(A, x, y, w, frac, colour, label, value):
    A(f'<rect x="{x}" y="{y}" width="{w}" height="18" rx="9" fill="#eff0f3"/>')
    A(f'<rect x="{x}" y="{y}" width="{max(6, w * frac):.0f}" height="18" rx="9" fill="{colour}"/>')
    A(f'<text x="{x}" y="{y - 6}" font-size="9.5" font-weight="700" fill="{SAPPHIRE}">{esc(label)}</text>')
    A(f'<text x="{x + w}" y="{y - 6}" text-anchor="end" font-size="9.5" fill="{colour}" '
      f'font-family="ui-monospace,Menlo,monospace">{esc(value)}</text>')


@register("ndr-data-exfil", "Data staging & exfiltration",
          "Bulk SMB reads staged locally, then a sustained outbound upload", order=105,
          scenario="ndr-data-exfil")
def d_exfil(c):
    k = _scn(c, "ndr-data-exfil"); INC = k["INC"]
    stage_total = sum(b for _o, _h, _s, b in INC.EXFIL_STAGING)
    up = INC.EXFIL_UPLOAD_BYTES
    W, H = 1180, 430
    P = []; A = P.append
    A(_svg_open(W, H, f'Data staging and exfiltration from {k["who"]} over {k["rwin"]}'))
    _panel_title(A, 14, 20, "TWO STAGES",
                 f'window {k["rwin"]} \u00b7 pull internally first, then push out once')
    marks = [(INC.EXFIL_STAGING[0][0], INC.EXFIL_UPLOAD_AT, "Staging \u2014 bulk SMB reads"),
             (INC.EXFIL_UPLOAD_AT, k["span"], "Exfiltration \u2014 HTTPS upload")]
    _phase_bar(A, 14, 42, W - 28, k["span"], marks, axis_every=5)
    A(f'<line x1="14" y1="150" x2="{W - 14}" y2="150" stroke="#e4e4e8"/>')

    _panel_title(A, 14, 172, "VOLUME AND DIRECTION", "at scale 1.0; everything scales with --scale")
    mx = max(stage_total, up)
    yy = 216
    for off, host, share, nbytes in INC.EXFIL_STAGING:
        h = c.host(host)
        _vol_bar(A, 14, yy, 500, nbytes / mx, CYAN,
                 f'+{off}s  IN \u2190 {host} \\\\{share}  ({h["ip"] if h else ""})',
                 f'{nbytes / 1e6:.0f} MB')
        yy += 46
    ex = next((r for r in _ext_rows(c, ["exfil"])), None)
    _vol_bar(A, 14, yy, 500, up / mx, PLUM,
             f'+{INC.EXFIL_UPLOAD_AT}s  OUT \u2192 {ex[1] if ex else "external storage"}',
             f'{up / 1e6:.0f} MB')
    yy += 52
    A(f'<rect x="14" y="{yy}" width="500" height="34" rx="8" fill="#fff8f3" stroke="#f6d3bd"/>')
    A(f'<text x="28" y="{yy + 21}" font-size="10" font-weight="700" fill="{TANGERINE}">'
      f'{stage_total / 1e6:.0f} MB pulled in \u2192 {up / 1e6:.0f} MB pushed out, from a workstation</text>')

    A(f'<line x1="556" y1="162" x2="556" y2="{H - 10}" stroke="#e4e4e8"/>')
    _panel_title(A, 580, 172, "WHY IT IS VISIBLE WITHOUT DECRYPTION",
                 "the shape of the transfer gives it away")
    facts = [("1", CYAN, "A workstation reading whole shares",
              "bulk sequential SMB reads, not the odd document", ""),
             ("2", PLUM, "Upload dwarfs download",
              "ordinary browsing is the other way round by an order of magnitude", ""),
             ("3", TANGERINE, "First-ever destination",
              f'{ex[1] if ex else "external storage"} \u2014 never used by this host before', ""),
             ("4", SAPPHIRE, "One sustained session",
              "not the short bursts of interactive use", ""),
             ("5", "#8a5cf0", "Timing follows staging",
              f'the upload starts at +{INC.EXFIL_UPLOAD_AT}s, right after the reads finish', "")]
    _rows(A, 580, 212, W - 600, facts, pitch=34)
    A('</svg>')

    srows = "".join(
        f'<tr><td class="m">+{o}s</td><td>inbound</td><td class="m">{esc(h)}</td>'
        f'<td class="m">\\\\{esc(sh)}</td><td class="m">{b / 1e6:.0f} MB</td></tr>'
        for o, h, sh, b in INC.EXFIL_STAGING)
    srows += (f'<tr><td class="m">+{INC.EXFIL_UPLOAD_AT}s</td><td>outbound</td>'
              f'<td class="m">{esc(ex[1] if ex else "")}</td><td class="m">HTTPS PUT</td>'
              f'<td class="m">{up / 1e6:.0f} MB</td></tr>')
    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 (f'{stage_total / 1e6:.0f} MB', "Staged"), (f'{up / 1e6:.0f} MB', "Exfiltrated"),
                 (len(INC.EXFIL_STAGING), "Shares read"), ("HTTPS", "Egress channel")],
        "sections": [("Transfers", '<table><thead><tr><th>Offset</th><th>Direction</th><th>Peer</th>'
                                   f'<th>Channel</th><th>Volume</th></tr></thead><tbody>{srows}</tbody></table>'),
                     ("Finding it in a capture", _filters_table([
                         ("Bulk staging reads", f'smb2.cmd == 8 && ip.src == {k["atk_ip"]}',
                          'SMB2 READ at volume'),
                         ("The upload", f'ip.addr == {ex[2] if ex else ""}',
                          f'~{up / 1e6:.0f} MB outbound'),
                         ("Upload asymmetry", f'ip.src == {k["atk_ip"]} && tcp.len > 1000',
                          'large client-to-server segments'),
                         ("Destination name", 'tls.handshake.extensions_server_name contains "mega"',
                          'the SNI on the exfil session'),
                     ]))],
        "notes": [
            ("warn", "Asymmetry is the tell",
             "A user workstation sending far more than it receives, sustained, to a destination "
             "it has never used, is the shape of exfiltration regardless of what is inside the TLS."),
            ("", "Staging is the earlier chance",
             "The bulk SMB reads happen minutes before anything leaves the network. That is the "
             "point at which it is still preventable."),
            ("", "It chains", "Final phase of ndr-scattered-spider and of every actor kill chain."),
        ],
    }


@register("ndr-ransomware-encryption", "Ransomware encryption",
          "SMB read plus write-in-place across shares, with renamed files and a ransom note",
          order=106, scenario="ndr-ransomware-encryption")
def d_ransom(c):
    k = _scn(c, "ndr-ransomware-encryption"); INC = k["INC"]
    ext = ".akira"
    note = INC.RANSOM_NOTES.get(ext, "readme.txt")
    lo, hi = INC.RANSOM_FILES
    W, H = 1180, 600
    P = []; A = P.append
    A(_svg_open(W, H, f'Ransomware encryption write-storm over {k["rwin"]}'))
    _panel_title(A, 14, 20, "IMPACT TIMELINE",
                 f'window {k["rwin"]} \u00b7 two shares hit in sequence')
    marks = [(o, o + 120, f'{h} \\\\{sh}') for o, h, sh in INC.RANSOM_TARGETS]
    _phase_bar(A, 14, 42, W - 28, k["span"], marks, axis_every=5)
    A(f'<line x1="14" y1="150" x2="{W - 14}" y2="150" stroke="#e4e4e8"/>')

    _panel_title(A, 14, 172, "WHAT HAPPENS TO EVERY FILE",
                 "the SMB sequence that makes this unmistakable")
    steps = [("1", PLUM, "CREATE + READ the original", "the whole file is pulled", ""),
             ("2", TANGERINE, "WRITE back in place", "same handle, same size class, new content", ""),
             ("3", CYAN, f'CREATE <name>{ext}', "the encrypted artifact appears alongside", ""),
             ("4", SAPPHIRE, f'Drop {note}', "once per directory", "")]
    _rows(A, 14, 210, 520, steps, pitch=34)
    A(f'<rect x="14" y="356" width="520" height="34" rx="8" fill="#fff8f3" stroke="#f6d3bd"/>')
    A(f'<text x="28" y="{377}" font-size="10" font-weight="700" fill="{TANGERINE}">'
      f'{lo}\u2013{hi} files per share at scale 1.0 \u2014 read and rewritten back to back</text>')

    A(f'<line x1="576" y1="162" x2="576" y2="404" stroke="#e4e4e8"/>')
    _panel_title(A, 600, 172, "TARGETS", "the attacker authenticates as svc_backup")
    rows = []
    for o, h, sh in INC.RANSOM_TARGETS:
        host = c.host(h)
        rows.append((f"+{o}s", PLUM, f'{h}  \\\\{sh}', f'read + write-in-place, then {ext} artifacts',
                     host["ip"] if host else ""))
    _rows(A, 600, 212, W - 620, rows, pitch=36)
    _panel_title(A, 600, 300, "READ/WRITE RATIO",
                 "normal file-server use is read-heavy; this is one-to-one")
    _vol_bar(A, 600, 340, W - 620, 0.5, CYAN, "reads", "same count as writes")
    _vol_bar(A, 600, 382, W - 620, 0.5, PLUM, "writes back to the same paths", "30-80 files per share")
    _ipr = lambda n: (c.host(n) or {}).get("ip", "")
    net = [(INC.ATTACKER_WS, k["atk_ip"], h, _ipr(h), "SMB write-storm \\\\" + sh, False) for (o, h, sh) in INC.RANSOM_TARGETS]
    A(f'<line x1="14" y1="414" x2="{W-14}" y2="414" stroke="#e4e4e8"/>')
    _netflow_panel(A, c, 14, 426, W - 28, 168, "HOW THE TRAFFIC TRAVERSES",
                   "the foothold reads and rewrites files on two shares in sequence over SMB", net, PLUM)
    A('</svg>')

    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 (len(INC.RANSOM_TARGETS), "Shares hit"), (f'{lo}\u2013{hi}', "Files per share"),
                 (ext, "Extension", "mono"), ("svc_backup", "Account used", "mono")],
        "sections": [("Finding it in a capture", _filters_table([
            ("The write storm", f'smb2.cmd == 9 && ip.src == {k["atk_ip"]}', 'SMB2 WRITE at volume'),
            ("Encrypted artifacts", f'smb2.filename contains "{ext}"', 'the renamed copies'),
            ("The ransom note", f'smb2.filename contains "{note.split(".")[0][:8]}"', 'one per directory'),
            ("Read-then-write pairs", f'smb2 && ip.addr == {k["atk_ip"]}', 'same paths, both directions'),
            ("The target shares", f'smb2.tree contains "{INC.RANSOM_TARGETS[0][2]}"', 'the share under attack'),
        ]))],
        "notes": [
            ("warn", "Read-then-write in place is the signature",
             "Backup software reads. Users write. Almost nothing legitimately reads a whole "
             "share and writes every file straight back at machine speed."),
            ("", "The artifacts name the actor",
             f'Files gain a {ext} suffix and a {note} note appears. Other actor chains use their '
             "own extensions, which is how you attribute from the capture alone."),
            ("", "Standalone by design",
             "This module is the impact phase on its own, for demonstrating detection without "
             "running a full kill chain first."),
        ],
    }


@register("ndr-cobalt-strike", "Cobalt Strike C2",
          "Jittered HTTP beacon to a team server plus SMB named-pipe peer-to-peer beacons",
          order=107, scenario="ndr-cobalt-strike")
def d_cobalt(c):
    k = _scn(c, "ndr-cobalt-strike"); INC = k["INC"]
    W, H = 1180, 620
    P = []; A = P.append
    A(_svg_open(W, H, f'Cobalt Strike C2 over {k["rwin"]}'))
    _panel_title(A, 14, 20, "BEACON CADENCE",
                 f'window {k["rwin"]} \u00b7 HTTP beacon every ~{INC.COBALT_BEACON_BASE}s '
                 f'with {int(INC.COBALT_JITTER[0] * 100)}\u2013{int(INC.COBALT_JITTER[1] * 100)}% jitter')
    _beacon_strip(A, 120, 86, W - 150, k["span"], INC.COBALT_BEACON_BASE, INC.COBALT_JITTER)
    A(f'<text x="14" y="90" font-size="9.5" font-weight="700" fill="{SAPPHIRE}">HTTP beacon</text>')
    A(f'<text x="14" y="104" font-size="8.5" fill="{GRAY}">one tick per check-in</text>')
    L, R = 120, W - 30
    X = lambda sec: L + (R - L) * min(1.0, sec / k["span"])
    A(f'<text x="14" y="126" font-size="9.5" font-weight="700" fill="{SAPPHIRE}">SMB pipes</text>')
    A(f'<line x1="{L}" y1="122" x2="{R}" y2="122" stroke="#e4e4e8" stroke-width="1.2"/>')
    # engine: 3 child servers, one long-lived pipe session each, opened at +200s/+240s/+280s
    # and held until 60s before the window closes
    for kk in range(3):
        x1 = X(200 + kk * 40)
        A(f'<rect x="{x1:.1f}" y="{117 + kk * 0}" width="{X(k["span"] - 60) - x1:.1f}" height="10" rx="5" '
          f'fill="{CYAN}" opacity=".55"/>')
        A(f'<circle cx="{x1:.1f}" cy="122" r="5" fill="{CYAN}"/>')
    A(f'<text x="{L}" y="140" font-size="8.5" fill="{GRAY}">3 long-lived named-pipe sessions (one per child server), polled every ~{INC.COBALT_PIPE_SLEEP}s</text>')
    ay = 158
    A(f'<line x1="{L}" y1="{ay}" x2="{R}" y2="{ay}" stroke="#d5d6dc" stroke-width="1.4"/>')
    for mm in range(0, k["span"] // 60 + 1, 15):
        x = X(mm * 60)
        A(f'<line x1="{x:.1f}" y1="{ay - 4}" x2="{x:.1f}" y2="{ay + 4}" stroke="#c9cad0"/>')
        A(f'<text x="{x:.1f}" y="{ay + 16}" text-anchor="middle" font-size="9" fill="{GRAY}">+{mm}m</text>')
    A(f'<line x1="14" y1="184" x2="{W - 14}" y2="184" stroke="#e4e4e8"/>')

    _panel_title(A, 14, 206, "TWO CHANNELS, ONE OPERATOR",
                 "egress for tasking, internal pipes so peers never touch the internet")
    rows = [("HTTP", PLUM, "Foothold \u2192 team server",
             f'jittered ~{INC.COBALT_BEACON_BASE}s beacon over TLS', ""),
            ("SMB", CYAN, "Foothold \u2194 servers",
             "named-pipe beacons over 445, peer-to-peer inside the subnet", ""),
            ("PIPE", SAPPHIRE, "\\\\PIPE\\msagent_*",
             "the default Cobalt Strike pipe-name pattern", "")]
    _rows(A, 14, 244, 540, rows, pitch=36)
    A(f'<line x1="596" y1="196" x2="596" y2="426" stroke="#e4e4e8"/>')
    _infra_panel(A, c, 620, 206, W - 640, ["cobaltc2"],
                 "TEAM SERVER", "the address the HTTPS beacon calls (documented Cobalt Strike indicator)")
    _panel_title(A, 620, 300, "PEER TARGETS", "3 of the 7 victim servers are picked at random per run (5 shown)")
    prows = [("", CYAN, n, "", (c.host(n) or {}).get("ip", "")) for n in INC.VICTIM_SERVERS[:5]]
    _rows(A, 620, 330, W - 640, prows, pitch=22)
    _ipc = lambda n: (c.host(n) or {}).get("ip", "")
    _c2 = (_ext_rows(c, ["cobaltc2"]) or [("", "", "?", "")])[0]
    net = [(INC.ATTACKER_WS, k["atk_ip"], "Team server", _c2[2], "HTTPS beacon :443", False)]
    net += [(INC.ATTACKER_WS, k["atk_ip"], v, _ipc(v), "named-pipe / SMB", False) for v in ("EXL-FILE1", "EXL-SQL1")]
    A(f'<line x1="14" y1="434" x2="{W-14}" y2="434" stroke="#e4e4e8"/>')
    _netflow_panel(A, c, 14, 446, W - 28, 168, "HOW THE TRAFFIC TRAVERSES",
                   "one operator: a jittered HTTPS beacon out, and named-pipe beacons onto peer servers", net, CYAN)
    A('</svg>')

    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 (f'~{INC.COBALT_BEACON_BASE}s', "Beacon interval", "mono"),
                 (f'{int(INC.COBALT_JITTER[0] * 100)}\u2013{int(INC.COBALT_JITTER[1] * 100)}%', "Jitter", "mono"),
                 (2, "Channels"), ("msagent_", "Pipe prefix", "mono")],
        "sections": [("Finding it in a capture", _filters_table([
            ("HTTP beacon", 'tls.handshake.extensions_server_name contains "jquery-static"',
             'the team-server SNI'),
            ("Named-pipe beacons", 'smb2.filename contains "msagent_"', 'peer-to-peer tasking'),
            ("Beacon pipe names", 'smb2.filename matches "msagent_[0-9a-f]+"', 'the default naming'),
            ("Beacon regularity", f'ip.src == {k["atk_ip"]} && tls.handshake.type == 1',
             'evenly spaced client hellos'),
        ]))],
        "notes": [
            ("warn", "The SMB channel never egresses",
             "Peer beacons stay inside the subnet over 445, so only the foothold talks to the "
             "internet. Egress-only monitoring sees one compromised host instead of several."),
            ("", "msagent_ is a default",
             "The pipe-name pattern is Cobalt Strike's out-of-the-box default and is widely "
             "signatured; real operators often change it."),
            ("", "It chains", "Black Basta and Play reuse this beacon behaviour inside their kill chains, each with its own team-server address."),
        ],
    }



_C2_EDGE_LABEL = {"rmm": "HTTPS :443 RMM check-in", "cloudflared": "HTTPS tunnel :443", "c2": "HTTPS beacon :443",
                  "ngrok": "TLS tunnel :443", "medusa_c2": "HTTPS beacon :443", "telegram": "HTTPS bot API poll",
                  "ipcheck": "HTTPS IP check"}


def _actor_facts(c, module, INC):
    """Per-actor content for the kill-chain pages, drawn from what the engine's C2 helper and impact phase
    actually do for that actor (c2_rmm_cloud, c2_tunnel, c2_cobalt, handala_c2, _actor_chain), so each page
    says something only that actor does. Returns {} for a module with no entry."""
    ips = lambda n: (c.host(n) or {}).get("ip", "")
    aip = ips(INC.ATTACKER_WS)
    c2_style, impact_ext, _adv = INC.ACTORS.get(module, (None, None, None))
    wipe = module == "ndr-handala"
    own = {"ndr-black-basta": (INC.BLACKBASTA_C2_NAME, INC.BLACKBASTA_C2_IP),
           "ndr-play": (INC.PLAY_C2_NAME, INC.PLAY_C2_IP)}.get(module)
    ext_keys = []
    try:
        ext_keys = [k for k in {"ndr-akira": ["rmm", "cloudflared", "c2", "ngrok"],
                                "ndr-medusa": ["medusa_c2", "cloudflared", "ngrok"],
                                "ndr-handala": ["telegram", "ipcheck"]}.get(module, [])]
    except Exception:                      # noqa: BLE001
        pass
    net = []
    if own:
        net.append((INC.ATTACKER_WS, aip, own[0], own[1], "HTTPS beacon :443", False))
        net.append((INC.ATTACKER_WS, aip, "2\u20133 of the servers", "random pick, once", "SMB named pipe :445", False))
    for key, host, ip, _label in _ext_rows(c, ext_keys):
        net.append((INC.ATTACKER_WS, aip, host, ip, _C2_EDGE_LABEL.get(key, "HTTPS :443"), False))
    imp = "SMB overwrite in place" if wipe else "SMB write + " + str(impact_ext)
    net.append((INC.ATTACKER_WS, aip, "EXL-FILE1", ips("EXL-FILE1"), imp, False))
    net.append((INC.ATTACKER_WS, aip, "EXL-BACKUP1", ips("EXL-BACKUP1"), imp, False))
    f = {"net": net, "filters": [], "plain": "", "tells": []}
    if module == "ndr-akira":
        f["plain"] = ("A ransomware crew that reaches in through a remote-support tool, keeps a second channel open "
                      "through a tunnel service, then encrypts two file shares. Only Akira's chain names its upload "
                      "tool (rclone) and drops its ransom note under the name powerrangers.txt.")
        f["tells"] = ["Two remote-access channels in the first minute (RMM host, tunnel host)",
                      "Beacons about every 45\u201381 s, plus a long-lived TLS tunnel later",
                      "The exfil upload announces rclone/v1.67.0"]
        f["filters"] = [("rclone upload", 'http.user_agent contains "rclone"', 'the exfil names its tool'),
                        ("Ransom note", 'smb2.filename contains "powerrangers"', 'dropped in the share root and Archive'),
                        ("Note text", 'frame contains "akira-recovery"', 'the contact address, in cleartext SMB')]
    elif module == "ndr-medusa":
        f["plain"] = ("A ransomware crew that tunnels out instead of using a remote-support tool: a Cloudflare-style "
                      "tunnel host and a persistent reverse tunnel carry its control traffic before two shares are "
                      "encrypted with a .medusa extension and a note that threatens to publish the stolen data.")
        f["tells"] = ["First contact with the C2 host and the tunnel host within the first minute",
                      "A persistent reverse tunnel opens about two minutes in and stays up",
                      "C2 beacons about every 63\u2013126 s",
                      "Note !!!READ_ME_MEDUSA!!!.txt: Tox chat contact, 10 days before publication"]
        f["filters"] = [("Tunnel sessions", 'tls.handshake.extensions_server_name contains "argo-tunnel"', 'the tunnel host'),
                        ("Ransom note", 'smb2.filename contains "READ_ME_MEDUSA"', 'share root and Archive'),
                        ("Note text", 'frame contains "medusa-support"', 'the contact address, in cleartext SMB')]
    elif module in ("ndr-black-basta", "ndr-play"):
        bb = module == "ndr-black-basta"
        nm = INC.BLACKBASTA_C2_NAME if bb else INC.PLAY_C2_NAME
        f["plain"] = ("A ransomware crew using a Cobalt Strike team server of its own (a throwaway documentation-range "
                      "address). Its control traffic is a jittered HTTPS beacon plus a few long-lived SMB named-pipe "
                      "sessions between servers, followed by " + str(impact_ext) + " encryption of two shares. "
                      + ("Its note points the victim to a TOR leak site and a company id." if bb else
                         "Its note is short, names a webmail contact and sets a 48-hour reply window."))
        f["tells"] = ["HTTPS beacon about every 32\u201363 s (70\u2013140% of 45 s)",
                      "2\u20133 servers each hold one long-lived named-pipe session open for most of the window",
                      "Its own team server (" + str(nm) + "), not the shared Cobalt Strike address",
                      ("Note readme.txt opens \u201cYour data are stolen and encrypted\u201d" if bb else
                       "Note ReadMe.txt opens \u201cYour data has been encrypted. PLAY\u201d"),
                      "Same Cobalt Strike behaviour as " + ("Play" if bb else "Black Basta") + ": tell them apart by team-server name and note"]
        f["filters"] = [("Team-server SNI", 'tls.handshake.extensions_server_name contains "%s"' % str(nm).split(".")[0], 'the C2 name'),
                        ("Named-pipe beacons", 'smb2.filename matches "msagent_[0-9a-f]+"', 'peer-to-peer pipes between servers'),
                        ("Ransom note", 'smb2.filename == "%s"' % ("readme.txt" if bb else "ReadMe.txt"), 'share root and Archive'),
                        ("Note text", 'frame contains "%s"' % ("Your data are stolen" if bb else "pl4y-recovery"), 'the note body, in cleartext SMB')]
    elif module == "ndr-handala":
        f["plain"] = ("A destructive intrusion that talks to its operator through a chat-app bot instead of a conventional "
                      "C2 host, steals data, then overwrites share contents in place and leaves a defacement note "
                      "(HANDALA_README.txt). Nothing is renamed or encrypted, so there are no renamed copies to find: "
                      "the evidence is the write pattern and the note.")
        f["tells"] = ["Long-lived sessions to the chat-app bot API, 2\u20134 polls each, every 5\u201310 minutes",
                      "An IP-address lookup to confirm egress",
                      "Writes to existing files with no renamed copies, then a defacement note"]
        f["filters"] = [("Bot API polling", 'tls.handshake.extensions_server_name contains "telegram"', 'chat-app C2'),
                        ("Defacement note", 'smb2.filename contains "HANDALA_README"', 'one per wiped share')]
    return f



def _chain_diagram(c, module, phases, c2_style, impact_ext, advisory, blurb, net=None):
    """Shared renderer for every kill chain — scattered-spider and the five actor chains.

    They all schedule the same technique builders under their own tag, differing only in the
    C2 style and the impact phase, so one renderer parameterised by ACTORS is honest about
    that rather than pretending they are five unrelated diagrams.
    """
    k = _scn(c, module); INC = k["INC"]
    afacts = _actor_facts(c, module, INC) if module in INC.ACTORS else {}
    if net is None and afacts.get("net"):
        net = afacts["net"]
    noimp = module == "ndr-scattered-spider"      # the engine schedules no impact phase for this chain
    wiper = impact_ext is None and not noimp
    if module == "ndr-play":                      # engine: Cobalt Strike HTTP + SMB pipes only, no SystemBC traffic
        c2_style = "Cobalt Strike HTTP beacon + SMB named pipes"
    ny = 520 if net else 464                      # y of the traffic-flow panel
    ph = max(168, 42 * len({(e[2], e[3]) for e in net}) + 40) if net else 0     # flow panel height grows with its targets
    W, H = 1180, (ny + 12 + ph + 28 if net else 520)
    P = []; A = P.append
    A(_svg_open(W, H, f'{module} kill chain over {k["rwin"]}'))
    _panel_title(A, 14, 20, "KILL CHAIN",
                 f'window {k["rwin"]} \u00b7 {k["span"] // 60} minutes \u00b7 '
                 f'phases overlap by design, as a real intrusion does')
    marks = [(a * 60, (b * 60 if b is not None else None), label) for a, b, label in phases]
    _phase_bar(A, 14, 42, W - 28, k["span"], marks, axis_every=15)
    A(f'<text x="14" y="104" font-size="10" font-weight="700" fill="{PLUM}">{esc(k["who"])}</text>')
    A(f'<text x="14" y="116" font-size="9" fill="{GRAY}" font-family="ui-monospace,Menlo,monospace">{esc(k["atk_ip"])}</text>')
    A(f'<line x1="14" y1="150" x2="{W - 14}" y2="150" stroke="#e4e4e8"/>')

    _panel_title(A, 14, 172, "PHASES AND WHAT THEY REUSE",
                 "each phase calls the standalone module's own builder, under this chain's tag")
    reuse = {"Reconnaissance": "ndr-recon", "Credential access": "ndr-credential-access",
             "Lateral movement": "ndr-lateral-movement", "DNS tunnelling": "ndr-dns-tunneling",
             "Data staging & exfiltration": "ndr-data-exfil", "C2 established": None}
    rows = []
    for i, (a, b, label) in enumerate(phases):
        span_txt = f'+{a}m\u2013{b}m' if b is not None else f'from +{a}m'
        mod = reuse.get(label)
        rows.append((span_txt, PHASE_COLORS[i % len(PHASE_COLORS)], label,
                     (f'same builder as {mod}' if mod else c2_style), ""))
    imp = ("None generated" if noimp else "Share wiper (overwrite in place)" if wiper
           else f'Ransomware encryption ({impact_ext})')
    imp_detail = f"{imp} on EXL-FILE1 at +{INC.CHAIN_PHASES[-1][0]}m, then EXL-BACKUP1 at +92m"
    rows = [(a_, b_, m_, (imp_detail if m_ == "Impact" else d_), r_) for a_, b_, m_, d_, r_ in rows]
    _rows(A, 14, 212, 560, rows, pitch=32)

    A(f'<line x1="616" y1="162" x2="616" y2="{(ny - 8) if net else (H - 10)}" stroke="#e4e4e8"/>')
    _panel_title(A, 640, 172, "WHAT MAKES THIS CHAIN DISTINCT",
                 "the techniques are shared; the C2 and the impact are not")
    ext_keys = {"ndr-akira": ["rmm", "cloudflared", "c2", "ngrok"],
                "ndr-medusa": ["medusa_c2", "cloudflared", "ngrok"],
                "ndr-black-basta": ["cobaltc2"], "ndr-play": ["cobaltc2"],
                "ndr-handala": ["telegram", "ipcheck"],
                "ndr-scattered-spider": ["rmm", "c2", "ngrok", "dnsns", "exfil"]}.get(module, [])
    facts = [("C2", PLUM, c2_style, "the command-and-control style this actor uses", ""),
             ("IMPACT", TANGERINE, imp,
              "the campaign ends with data theft; nothing is encrypted or wiped" if noimp
              else "no files are renamed \u2014 that is the wiper tell" if wiper
              else "renamed copies plus a ransom note", ""),
             ("REF", CYAN, advisory, blurb, "")]
    _rows(A, 640, 212, W - 660, facts, pitch=38)
    own_c2 = {"ndr-black-basta": (INC.BLACKBASTA_C2_NAME, INC.BLACKBASTA_C2_IP),
              "ndr-play": (INC.PLAY_C2_NAME, INC.PLAY_C2_IP)}.get(module)
    if own_c2:
        _panel_title(A, 640, 340, "EXTERNAL INFRASTRUCTURE",
                     "this actor's own team server: a throwaway documentation-range address")
        _rows(A, 640, 372, W - 660, [("c2", SAPPHIRE, own_c2[0], "Cobalt Strike team server (HTTP beacon)", own_c2[1])], pitch=26)
    elif ext_keys:
        _panel_title(A, 640, 340, "EXTERNAL INFRASTRUCTURE", "real documented indicators \u2014 never contacted")
        irows = [(key, SAPPHIRE, host, label, ip) for key, host, ip, label in _ext_rows(c, ext_keys)]
        _rows(A, 640, 372, W - 660, irows, pitch=28)
    if net:
        A(f'<line x1="14" y1="{ny}" x2="{W-14}" y2="{ny}" stroke="#e4e4e8"/>')
        _netflow_panel(A, c, 14, ny + 12, W - 28, ph, "HOW THE TRAFFIC TRAVERSES",
                       "the chained operator: external C2 plus reuse of the internal technique flows", net, PLUM)
    A('</svg>')

    def _span(a, b):                                    # no backslash inside an f-string (py < 3.12)
        return ("+%sm\u2013%sm" % (a, b)) if b is not None else ("from +%sm" % a)

    prows = "".join(
        f'<tr><td class="m">{_span(a, b)}</td>'
        f'<td>{esc(label)}</td><td class="svc">{esc(reuse.get(label) or c2_style)}</td></tr>'
        for a, b, label in phases)
    prows = prows.replace(f'<td>Impact</td><td class="svc">{esc(c2_style)}</td>',
                          f'<td>Impact</td><td class="svc">{esc(imp_detail)}</td>')
    filters = [("The whole chain", f'ip.addr == {k["atk_ip"]}', 'includes the user\u2019s normal day'),
               ("C2 egress", f'tls.handshake.type == 1 && ip.src == {k["atk_ip"]}', 'beacon client hellos')]
    if noimp:
        pass
    elif wiper:
        filters.append(("Impact \u2014 wiper", f'smb2.cmd == 9 && ip.src == {k["atk_ip"]}',
                        'writes with no renamed copies'))
    else:
        filters.append((f'Impact \u2014 {impact_ext} artifacts', f'smb2.filename contains "{impact_ext}"',
                        'the renamed files'))
    filters += afacts.get("filters", [])
    filters += [("Recon phase", f'icmp.type == 8 && ip.src == {k["atk_ip"]}', 'the host sweep'),
                ("Lateral phase", 'smb2.tree contains "ADMIN$"', 'admin-share execution')]
    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 (len(phases), "Phases"), (k["who"], "Origin", "mono"),
                 ("none" if noimp else (impact_ext or "wiper"), "Impact", "mono"),
                 (advisory.split()[-1] if advisory.startswith("CISA") else advisory.split("(")[0].strip(),
                  "Reference", "mono")],
        "sections": [("Phases", '<table><thead><tr><th>Window</th><th>Phase</th>'
                                f'<th>Detail</th></tr></thead><tbody>{prows}</tbody></table>'),
                     ("Finding it in a capture", _filters_table(filters))],
        "notes": ([
            ("warn", "Phases overlap",
             "C2 runs throughout and the technique windows deliberately overlap. A detection that "
             "expects clean sequential stages will not match a real intrusion either."),
            ("", "In plain terms", afacts["plain"]),
            ("", "What sets this actor apart", " \u00b7 ".join(afacts["tells"])),
            ("", "Shared techniques", "Recon, credential access, lateral movement and exfiltration reuse the standalone "
                                      "modules' builders under this chain's tag; the C2 style and impact above are this actor's own."),
        ] if afacts.get("plain") else [
            ("warn", "Phases overlap",
             "C2 runs throughout and the technique windows deliberately overlap. A detection that "
             "expects clean sequential stages will not match a real intrusion either."),
            ("", "Self-contained",
             "This chain calls the technique builders internally under its own tag, so it can be "
             "built on its own \u2014 selecting it alone produces the whole campaign."),
            ("", "Shared techniques, distinct signature",
             "Recon, credential access, lateral movement and exfiltration are the same code as "
             "the standalone modules. What identifies this actor is the C2 style and the impact."),
        ]),
    }


@register("ndr-scattered-spider", "Scattered Spider", "Chained campaign across every NDR technique",
          order=110, scenario="ndr-scattered-spider")
def d_spider(c):
    from netgen import incidents as INC
    _ips = lambda n: (c.host(n) or {}).get("ip", "")
    aip = _ips(INC.ATTACKER_WS)
    net = [(INC.ATTACKER_WS, aip, "RMM cloud / ngrok", "(external)", "HTTPS C2 :443", False),
           (INC.ATTACKER_WS, aip, "EXL-DC1", _ips("EXL-DC1"), "recon \u00b7 lateral", False),
           (INC.ATTACKER_WS, aip, "EXL-FILE1", _ips("EXL-FILE1"), "SMB / RDP", False)]
    return _chain_diagram(c, "ndr-scattered-spider", INC.SPIDER_PHASES,
                          "RMM cloud + low-and-slow HTTPS + ngrok tunnel", None,
                          "Scattered Spider (UNC3944)",
                          "social-engineering-led intrusion; the network-observable subset", net=net)


def _mk_actor(module):
    from netgen import incidents as INC
    c2_style, ext, advisory = INC.ACTORS[module]
    title = INC.REGISTRY[module].title.split("(")[0].strip()

    def builder(c, _m=module, _c2=c2_style, _e=ext, _a=advisory):
        from netgen import incidents as _INC
        return _chain_diagram(c, _m, _INC.CHAIN_PHASES, _c2, _e, _a,
                              "network-observable subset of the published tradecraft")
    builder.__name__ = "d_" + module.replace("-", "_")
    if module == "ndr-play":
        c2_style = "Cobalt Strike HTTP beacon + SMB named pipes"
    register(module, title, f'{c2_style} \u2192 ' + ("share wiper" if ext is None else f'{ext} encryption'),
             order=111, scenario=module)(builder)


for _m in ("ndr-akira", "ndr-medusa", "ndr-black-basta", "ndr-play", "ndr-handala"):
    _mk_actor(_m)


# =======================================================================================
# NPM SCENARIO DIAGRAMS
# Nearly every NPM module is the same machine: healthy pre-roll, then a loop whose severity
# is scaled by incidents.sev(), then healthy post-roll. So they share one renderer, and the
# envelope curve below is drawn by evaluating the real sev() rather than an approximation.
# =======================================================================================
@register("npm-fw-update", "Firewall content update",
          "A firewall content update, and the remote-access outage its commit causes",
          order=201, scenario="npm-fw-update")
def d_fw_update(c):
    """npm-fw-update is an OBSERVABILITY + IMPACT scenario, not a server fault. The jump host
    pulls the PAN-OS content bundle early and the admin commits it mid-morning; because the
    firewall terminates the VPN, the commit's dataplane reload drops the entire remote workforce
    at once -- an easy-to-see cliff in the requests ANSWERED by the auth, database and web servers,
    then a reconnect storm. It answers WHEN the update ran, IF it completed, and what it cost."""
    from netgen import incidents as INC
    inc = INC.REGISTRY["npm-fw-update"]
    mgmt = c.host("EXL-MGMT1"); mgmt_ip = mgmt["ip"] if mgmt else "10.10.20.110"
    dc = c.host("EXL-DC1"); dc_ip = dc["ip"] if dc else "10.10.20.10"
    sql = c.host("EXL-SQL1"); sql_ip = sql["ip"] if sql else "10.10.20.30"
    web = c.host("EXL-WEB2"); web_ip = web["ip"] if web else "10.10.20.41"
    W, H = 1180, 486
    P = []; A = P.append
    A(_svg_open(W, H, 'Firewall content update and the remote-access outage it causes'))
    A('<defs><marker id="fwarrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
      f'<path d="M0,0 L8,4 L0,8 Z" fill="{GRAY}"/></marker></defs>')

    # ---- top: the update timeline -------------------------------------------------------------
    _panel_title(A, 14, 20, "THE UPDATE", "a firewall that also terminates the VPN is updated; its reload cuts every remote worker off for 90\u2013180 s")
    stages = [
        ("Start +1:15", "DOWNLOAD", "EXL-MGMT1 (jump host) ← firewall vendor update servers", "HTTPS: version check, then ~2 MB content bundle", SAPPHIRE),
        ("Start +4:29", "PUSH", "EXL-MGMT1 → EXL-FW1 management API (HTTPS 443)", "upload the bundle, start the install job", PLUM),
        ("Start +4:30", "COMMIT ✓ (~90 s)", "job polled until FIN / OK", "content installed — dataplane reloads", "#1a8a4a"),
    ]
    x0, y = 40, 52
    bw, gap = 356, 20
    for i, (trel, cap, host, detail, col) in enumerate(stages):
        x = x0 + i * (bw + gap)
        A(f'<rect x="{x}" y="{y}" width="{bw}" height="66" rx="10" fill="#fff" stroke="{col}" stroke-width="1.6"/>')
        A(f'<rect x="{x}" y="{y}" width="{bw}" height="19" rx="10" fill="{col}"/>')
        A(f'<rect x="{x}" y="{y+9}" width="{bw}" height="10" fill="{col}"/>')
        A(f'<text x="{x+10}" y="{y+13}" font-size="9.5" font-weight="900" fill="#fff">{esc(cap)}</text>')
        A(f'<text x="{x+bw-10}" y="{y+13}" text-anchor="end" font-size="9.5" font-weight="800" fill="#fff" '
          f'font-family="ui-monospace,Menlo,monospace">{esc(trel)}</text>')
        A(f'<text x="{x+12}" y="{y+40}" font-size="10" font-weight="700" fill="{SAPPHIRE}">{esc(host)}</text>')
        A(f'<text x="{x+12}" y="{y+56}" font-size="9" fill="{GRAY}">{esc(detail)}</text>')
        if i:
            A(f'<line x1="{x-gap}" y1="{y+33}" x2="{x}" y2="{y+33}" stroke="{GRAY}" stroke-width="1.4" marker-end="url(#fwarrow)"/>')
    A(f'<text x="{x0+bw+gap/2}" y="{y-6}" text-anchor="middle" font-size="8.5" fill="{GRAY}">≈ 3 h later</text>')
    A(f'<text x="{x0+2*bw+1.5*gap}" y="{y-6}" text-anchor="middle" font-size="8.5" fill="{GRAY}">≈ 90 s later</text>')

    A(f'<line x1="14" y1="142" x2="{W-14}" y2="142" stroke="#e4e4e8"/>')

    # ---- bottom-left: external traffic dropping at the firewall reboot -----------------------
    _panel_title(A, 14, 166, "EXTERNAL TRAFFIC DROPS AT THE REBOOT",
                 "remote-worker requests answered by the auth / database / web servers per 30 s; bar heights illustrate the shape")
    gx, gy, gw, gh = 44, 206, 600, 150
    base = gy + gh                                  # x-axis baseline (value 0)
    # the profile the generator actually produces: steady, zero through the outage, a reconnect
    # spike, then steady again (illustrative of the measured shape, not a measured table).
    series = [("+4:28", 24, 0), ("", 12, 0), ("+4:29", 15, 0), ("", 15, 0), ("+4:30", 18, 0),
              ("", 0, 1), ("+4:31", 0, 1), ("", 0, 1), ("+4:32", 0, 1), ("", 0, 1),
              ("+4:33", 34, 2), ("", 51, 2), ("+4:34", 23, 0), ("", 12, 0), ("+4:35", 12, 0), ("", 21, 0)]
    vmax = 51.0
    slot = gw / len(series)
    bw = slot * 0.74
    out_i = [i for i, s in enumerate(series) if s[2] == 1]
    # outage band behind the bars
    if out_i:
        bx1 = gx + out_i[0] * slot
        bx2 = gx + (out_i[-1] + 1) * slot
        A(f'<rect x="{bx1:.1f}" y="{gy}" width="{bx2-bx1:.1f}" height="{gh}" fill="{TANGERINE}" opacity=".10"/>')
    A(f'<line x1="{gx}" y1="{base}" x2="{gx+gw}" y2="{base}" stroke="#c9cad0" stroke-width="1.3"/>')
    A(f'<line x1="{gx}" y1="{gy}" x2="{gx}" y2="{base}" stroke="#c9cad0" stroke-width="1.3"/>')
    A(f'<text x="{gx-6}" y="{gy+8}" text-anchor="end" font-size="8.5" fill="{GRAY}">reqs</text>')
    A(f'<text x="{gx-6}" y="{base}" text-anchor="end" font-size="8.5" fill="{GRAY}">0</text>')
    for i, (lab, v, kind) in enumerate(series):
        cx = gx + i * slot + (slot - bw) / 2
        if v > 0:
            bh = (gh - 10) * v / vmax
            col = CYAN if kind != 2 else PLUM           # reconnect-storm bars stand out
            A(f'<rect x="{cx:.1f}" y="{base-bh:.1f}" width="{bw:.1f}" height="{bh:.1f}" rx="1.5" fill="{col}"/>')
        if lab:
            A(f'<text x="{gx + i*slot + slot/2:.1f}" y="{base+13:.0f}" text-anchor="middle" font-size="8" fill="{GRAY}">{lab}</text>')
    # the reboot marker, at the first zero bucket
    if out_i:
        rbx = gx + out_i[0] * slot
        A(f'<line x1="{rbx:.1f}" y1="{gy-4}" x2="{rbx:.1f}" y2="{base}" stroke="{TANGERINE}" stroke-width="2" stroke-dasharray="4 3"/>')
        A(f'<text x="{rbx+4:.1f}" y="{gy+4}" font-size="9" font-weight="800" fill="{TANGERINE}">FIREWALL REBOOT ~Start +4:30</text>')
        A(f'<text x="{(bx1+bx2)/2:.1f}" y="{base-6:.1f}" text-anchor="middle" font-size="8.5" font-weight="700" fill="{TANGERINE}">external traffic → 0</text>')
        A(f'<text x="{(bx1+bx2)/2:.1f}" y="{base-18:.1f}" text-anchor="middle" font-size="8.5" fill="{TANGERINE}">90–180 s</text>')
    sx = gx + 10 * slot + slot / 2
    A(f'<text x="{sx:.1f}" y="{gy-2:.0f}" text-anchor="middle" font-size="8.5" font-weight="700" fill="{PLUM}">reconnect storm</text>')
    A(f'<text x="{gx+gw-4:.0f}" y="{gy+4}" text-anchor="end" font-size="8.5" fill="{GRAY}">steady before · restored after</text>')

    # ---- bottom-right: who and where ---------------------------------------------------------
    A(f'<line x1="664" y1="158" x2="664" y2="{H-10}" stroke="#e4e4e8"/>')
    _panel_title(A, 688, 166, "WHO DROPS, AND OFF WHAT", "24 VPN workers → three server roles")
    rows = [
        ("", SAPPHIRE, "Remote workforce", f"24 VPN users ({INC.RA_IP0}0/24), IPsec tunnels to EXL-FW1", ""),
        ("", PLUM, f"Auth · {dc_ip}", "EXL-DC1 — Kerberos AS (TCP 88)", ""),
        ("", PLUM, f"Database · {sql_ip}", "EXL-SQL1 — TDS (1433)", ""),
        ("", PLUM, f"Web · {web_ip}", "EXL-WEB2 — HTTPS, decryptable (443)", ""),
        ("", TANGERINE, "The cause", "the firewall is the VPN gateway: tunnels drop, then rebuild before the reconnect spike", ""),
    ]
    _rows(A, 688, 206, W - 710, rows, pitch=32)
    A(f'<rect x="688" y="{H-70}" width="{W-710}" height="50" rx="8" fill="#fff6f0" stroke="#f3c6ab"/>')
    A(f'<text x="704" y="{H-50}" font-size="9.5" font-weight="800" fill="{TANGERINE}">Easy to identify</text>')
    A(f'<text x="704" y="{H-36}" font-size="9" fill="{GRAY}">three server roles answer a steady stream, then NOTHING for 90–180 s,</text>')
    A(f'<text x="704" y="{H-23}" font-size="9" fill="{GRAY}">then a synchronized spike — a cliff no single-server fault produces.</text>')
    A('</svg>')
    return {
        "svg": "".join(P),
        "kpis": [("Start +1:15", "Download", "mono"), ("Start +4:29", "Push", "mono"),
                 ("success", "Commit"), ("90–180 s", "Outage"),
                 ("24", "Remote workers"), ("0", "Answered in outage")],
        "sections": [("Finding it in a capture", _filters_table([
            ("Update ran (SNI)", 'tls.handshake.extensions_server_name contains "paloaltonetworks"',
             'when the jump host pulled the update from the vendor\u2019s update hosts'),
            ("Commit completed (keylog)", f'http.response.code == 200 && ip.src == 10.10.20.1',
             "decrypted API replies; the last job poll reports FIN / OK — the IF answer and the outage's start"),
            ("Remote auth requests", f'tcp.port == 88 && ip.src == {INC.RA_IP0}0/24',
             'KDC requests from the VPN pool — steady, then zero through the outage'),
            ("Remote DB requests", f'tcp.port == 1433 && ip.src == {INC.RA_IP0}0/24',
             'TDS to EXL-SQL1 from the VPN pool — same cliff'),
            ("Remote web requests", f'tcp.port == 443 && ip.src == {INC.RA_IP0}0/24',
             'HTTPS to EXL-WEB2 from the VPN pool — same cliff'),
            ("The whole workforce dropping", f'tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == {INC.RA_IP0}0/24',
             'new sessions: steady, zero for 90–180 s, then a reconnect spike'),
        ]))],
        "notes": [
            ("", "Observability and impact, not a server fault",
             "No server degrades. The firewall update is a change event, and its commit reloads the "
             "dataplane that carries the VPN — so the visible cost is every remote worker losing auth, "
             "database and web access at once. Correlating the dip to the commit is the exercise."),
            ("warn", "The cause is the firewall, not the servers",
             "The auth, database and web servers are healthy throughout. A naive read blames three "
             "servers failing together; the real cause is one device — the VPN-terminating firewall — "
             "rebooting. A synchronized cliff across unrelated server roles is the tell."),
            ("", "Legitimate vendor, and baseline-safe",
             "The update hosts are the firewall vendor's real content infrastructure (a destination field only, never "
             "contacted). The whole remote-access workforce exists only when this scenario is selected, so "
             "the pinned --no-modules baseline is unchanged."),
            ("warn", "Replay at original timing",
             "The cliff and the reconnect storm are only legible if the capture is replayed with its "
             "original timing; at top speed the outage collapses into the surrounding traffic."),
        ],
    }

@register("npm-pqc-posture", "Post-quantum readiness",
          "Which hosts can use post-quantum key exchange, which do, and which cannot",
          order=202, scenario="npm-pqc-posture")
def d_pqc(c):
    """A metadata-only TLS 1.3 posture scenario. It reads out as three populations on the
    handshake fields the platform exposes: the client's supported_groups and the server's
    selected key_share group. Scenario-only, so the baseline and the TLS 1.2 RSA
    decryption demo are untouched."""
    k = _scn(c, "npm-pqc-posture"); INC = k["INC"]
    _ip = lambda n: (c.host(n) or {}).get("ip", "")
    W, H = 1180, 500
    P = []; A = P.append
    A(_svg_open(W, H, "Post-quantum key-exchange posture across the estate"))
    A('<defs><marker id="pqar" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">'
      f'<path d="M0,0 L8,4 L0,8 Z" fill="{GRAY}"/></marker></defs>')
    _panel_title(A, 14, 20, "THE QUESTION, DECIDED IN THE HANDSHAKE",
                 f'window {k["rwin"]} · TLS 1.3, X25519MLKEM768 (0x11ec) · the key exchange is in key_share, not the cipher suite')

    # decision flow: offer? -> select?
    def box(x, y, w, h, col, t1, t2):
        A(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="#fff" stroke="{col}" stroke-width="1.7"/>')
        A(f'<text x="{x+w/2:.0f}" y="{y+22:.0f}" text-anchor="middle" font-size="11" font-weight="800" fill="{col}">{esc(t1)}</text>')
        A(f'<text x="{x+w/2:.0f}" y="{y+38:.0f}" text-anchor="middle" font-size="9" fill="{GRAY}">{esc(t2)}</text>')
    box(30, 70, 150, 50, SAPPHIRE, "ClientHello", "supported_groups")
    A(f'<line x1="180" y1="95" x2="236" y2="95" stroke="{GRAY}" stroke-width="1.4" marker-end="url(#pqar)"/>')
    box(236, 70, 160, 50, SAPPHIRE, "Offers 0x11ec?", "the capability tell")
    # no -> not capable
    A(f'<line x1="316" y1="120" x2="316" y2="150" stroke="{GRAY}" stroke-width="1.4" marker-end="url(#pqar)"/>')
    A(f'<text x="324" y="140" font-size="8.5" fill="{GRAY}">no</text>')
    box(236, 152, 160, 46, GRAY, "NOT CAPABLE", "classical groups only")
    # yes -> server select
    A(f'<line x1="396" y1="95" x2="452" y2="95" stroke="{GRAY}" stroke-width="1.4" marker-end="url(#pqar)"/>')
    A(f'<text x="404" y="88" font-size="8.5" fill="{GRAY}">yes</text>')
    box(452, 70, 180, 50, PLUM, "Server key_share", "selects 0x11ec?")
    A(f'<line x1="632" y1="95" x2="688" y2="95" stroke="{GRAY}" stroke-width="1.4" marker-end="url(#pqar)"/>')
    A(f'<text x="696" y="88" font-size="8.5" fill="{GRAY}">yes</text>')
    box(688, 70, 170, 50, "#1a8a4a", "USING PQC", "quantum-safe session")
    A(f'<line x1="542" y1="120" x2="542" y2="150" stroke="{GRAY}" stroke-width="1.4" marker-end="url(#pqar)"/>')
    A(f'<text x="550" y="140" font-size="8.5" fill="{GRAY}">no</text>')
    box(452, 152, 180, 46, TANGERINE, "CAPABLE, NOT USING", "client ready, server is not")

    A(f'<rect x="890" y="64" width="{W-904}" height="136" rx="8" fill="#f7fbfe" stroke="#bfe3f7"/>')
    A(f'<text x="904" y="84" font-size="9.5" font-weight="800" fill="{SAPPHIRE}">Plain-language key</text>')
    for i, t_ in enumerate(("Key exchange: how the two ends agree a secret session key.",
                            "Hybrid group: classic X25519 plus ML-KEM (quantum-resistant),",
                            "so recorded traffic stays safe from quantum computers.",
                            "0x11ec: the number that names that group in the handshake.",
                            "Offering it = capable; the server picking it = using.")):
        A(f'<text x="904" y="{102 + i * 17}" font-size="9" fill="{GRAY}">{esc(t_)}</text>')
    A(f'<line x1="14" y1="214" x2="{W-14}" y2="214" stroke="#e4e4e8"/>')

    # three populations with example hosts
    _panel_title(A, 14, 236, "THE THREE POPULATIONS", "example hosts from this build, and the platform signal each produces")
    rows = [
        ("", "#1a8a4a", "Using — negotiated hybrid",
         f'modern clients → {esc("EXL-WEB1/WEB2")} select 0x11ec', "post-quantum key agreement = yes"),
        ("", TANGERINE, "Capable, not using",
         f'same clients → {esc("EXL-SQL1/FILE1")} fall back to x25519', "offered 0x11ec, negotiated classical"),
        ("", GRAY, "Not capable",
         f'{esc("EXL-SB-01/02/03/04, EXL-OTJUMP1")} — smart boards / OT jump host', "no PQC group ever offered"),
    ]
    _rows(A, 14, 274, 620, rows, pitch=40)
    A(f'<text x="14" y="420" font-size="9.5" font-weight="700" fill="{SAPPHIRE}">Capable clients (offer 0x11ec)</text>')
    cl = "  ".join("%s %s" % (n.replace("EXL-", ""), _ip(n)) for n in INC.PQC_MODERN)
    A(f'<text x="14" y="436" font-size="8.5" fill="{GRAY}" font-family="ui-monospace,Menlo,monospace">{esc(cl)}</text>')

    # right: the dashboard
    A(f'<line x1="664" y1="226" x2="664" y2="{H-10}" stroke="#e4e4e8"/>')
    _panel_title(A, 688, 236, "FEEDING THE DASHBOARD", "metrics and record fields derived from the handshake")
    drows = [
        ("", "#1a8a4a", "PQ sessions", "metric — post-quantum TLS sessions, per client & per server", ""),
        ("", SAPPHIRE, "total sessions", "metric — all TLS sessions, for the denominator", ""),
        ("", TANGERINE, "advertised groups", "handshake field — includes 0x11ec = capable", ""),
        ("", PLUM, "cipher", "metric — sessions by cipher suite", ""),
    ]
    _rows(A, 688, 274, W - 708, drows, pitch=34)
    A(f'<rect x="688" y="{H-80}" width="{W-708}" height="60" rx="8" fill="#f7fbfe" stroke="#bfe3f7"/>')
    A(f'<text x="704" y="{H-60}" font-size="9.5" font-weight="800" fill="{SAPPHIRE}">Observability, not a fault</text>')
    A(f'<text x="704" y="{H-45}" font-size="9" fill="{GRAY}">metadata only — nothing is decrypted; the TLS 1.2 RSA</text>')
    A(f'<text x="704" y="{H-32}" font-size="9" fill="{GRAY}">decryption demo and the pinned baseline are untouched.</text>')
    A('</svg>')
    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 ("X25519MLKEM768", "Hybrid group"), ("0x11ec", "Code point", "mono"),
                 ("3", "Posture states"), ("PQ sessions", "Dashboard metric")],
        "sections": [("Finding it in a capture / dashboard", _filters_table([
            ("Capable (offered PQC)", 'tls.handshake.extensions_supported_group == 0x11ec',
             'client advertises the hybrid group (0x11ec) in supported_groups'),
            ("Using (negotiated PQC)", 'tls.handshake.type == 2 && tls.handshake.extensions_key_share_group == 0x11ec',
             'server selected it — the platform flags post-quantum key agreement and its PQ-session count increments'),
            ("Not capable", 'tls.handshake.type == 1 && not tls.handshake.extensions_supported_group == 0x11ec',
             'client never offers a PQC group'),
            ("Dashboard (platform metric)", 'post-quantum TLS sessions',
             'top-N by client / server / SNI / certificate'),
        ]))],
        "notes": [
            ("", "Three populations, one scenario",
             "Capable clients reach both PQC-ready and legacy servers, so the same client reads as "
             "‘using’ against one server and ‘capable, not using’ against another — which is exactly "
             "the gap a readiness dashboard is meant to surface."),
            ("", "Read from the handshake",
             "The posture is read entirely from the TLS 1.3 handshake — the client's advertised "
             "key-exchange groups and the server's selected group — so a monitor's post-quantum "
             "session metric and related fields populate from this scenario's traffic where they "
             "read empty before."),
            ("warn", "Metadata only, by design",
             "These are TLS 1.3 handshakes with an opaque encrypted tail — the key-exchange posture is "
             "cleartext and is all that is needed. No key schedule, so the decryption demo is unaffected."),
        ],
    }


OT_ACCENT = MAGENTA     # the OT/IoT accent (magenta), to read as the industrial zone

_W3_OT_NOTE = ("", "Requires the OT subnet", "Inert unless the OT zone is enabled in the build; see the OT-visibility note in the GUI.")
_W3_MB = ("Modbus is a decades-old industrial protocol: a master asks a controller to read or write numbered registers. "
          "Function codes (FC) say which: FC 3 reads holding registers; FC 5, 6, 15 and 16 write.")


@register("ndr-ot-modbus-write", "OT: Modbus write tampering",
          "A compromised engineering station writes setpoints to read-only PLCs", order=130, scenario="ndr-ot-modbus-write")
def d_ot_modbus_write(c):
    ip = lambda n: _w3_ip(c, n)
    net = [("EXL-OTENG1", ip("EXL-OTENG1"), "EXL-PLC-01 … -12", "%s … %s" % (ip("EXL-PLC-01"), ip("EXL-PLC-12")), "Modbus/TCP :502", "first a read (FC 3) per PLC, then writes every 20–90 s; one PLC per session", False)]
    return _w3_campaign(c, "ndr-ot-modbus-write", {
        "net": net, "title": "Unauthorized Modbus write", "accent": OT_ACCENT,
        "strip_title": "SETPOINT TAMPERING", "strip_label": "writes",
        "strip_sub": "window {rwin} · {span} min of write commands to controllers that normally only serve reads",
        "ticks": (60, 55), "events": [(60, "first write +1 min")],
        "plain": "An engineer's PC on the plant floor starts changing settings inside the machine controllers (PLCs) that run the production line. "
                 "Controllers are normally only read by the monitoring system, so a write is the alarm. " + _W3_MB,
        "facts": [("Source", "EXL-OTENG1 %s (cell engineering workstation, Purdue level 2)" % ip("EXL-OTENG1")),
                  ("Targets", "PLCs EXL-PLC-01 to -12, %s to %s (level 1), TCP 502" % (ip("EXL-PLC-01"), ip("EXL-PLC-12"))),
                  ("Writes", "mostly FC 6 (write single register), some FC 16 and FC 5, occasionally answered with a Modbus exception"),
                  ("Cadence", "one write session every 20–90 s from +60 s; each PLC gets 2–4 reused registers"),
                  ("Priming", "the first contact with each PLC is a read, as an operator would do")],
        "tells_sub": "what the platform's Modbus metrics break out per peer",
        "tells": [("Writes where there were only reads", "FC 5/6/15/16 appear on PLCs that the baseline only ever read"),
                  ("From the engineering station", "EXL-OTENG1 originates the writes; volume and spread of targets are anomalous"),
                  ("Level-1 control affected", "holding-register changes on the process controllers")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "the engineering station → the PLCs, Modbus write function codes",
        "legend": "Arrow points master → controller; the PLC answers on the same connection. Both ends sit on the OT segment.",
        "kpis": [("Modbus", "Protocol"), ("WRITE", "Function class"), ("12 PLCs", "Possible targets")],
        "filters": [("Modbus writes", 'modbus.func_code in {5 6 15 16}', 'the tampering commands'),
                    ("From the engineering station", 'mbtcp && ip.src == %s' % ip("EXL-OTENG1"), 'writes and the priming reads'),
                    ("Function-code mix", 'mbtcp.func_code', 'the platform breaks these out per peer')],
        "notes": [("warn", "The platform reports Modbus by message type", "Breaking requests out by function code makes a write stand out against a read-only baseline per PLC, with no payload inspection."),
                  _W3_OT_NOTE]})


@register("ndr-ot-sis-tamper", "OT: safety-system tampering",
          "Writes to a safety controller (SIS) that should never be written", order=131, scenario="ndr-ot-sis-tamper")
def d_ot_sis(c):
    ip = lambda n: _w3_ip(c, n)
    net = [("EXL-OTENG1", ip("EXL-OTENG1"), "EXL-SIS-01 / -02", "%s / %s" % (ip("EXL-SIS-01"), ip("EXL-SIS-02")), "Modbus/TCP :502", "a write or a 2–5 read poll every 60–180 s", False)]
    return _w3_campaign(c, "ndr-ot-sis-tamper", {
        "net": net, "title": "Safety-system (SIS) tampering", "accent": OT_ACCENT,
        "strip_title": "SIS TAMPERING (TRITON-STYLE ACTOR BEHAVIOUR)", "strip_label": "contacts",
        "strip_sub": "window {rwin} · {span} min of traffic to a safety controller that should see almost none",
        "ticks": (60, 120), "events": [(60, "first contact +1 min")],
        "plain": "A safety instrumented system (SIS) is the independent last-resort controller that shuts a plant down safely when something goes wrong. "
                 "Here an engineering PC starts talking to it, which almost never happens outside planned maintenance.",
        "facts": [("Source", "EXL-OTENG1 %s" % ip("EXL-OTENG1")),
                  ("Targets", "EXL-SIS-01 %s, EXL-SIS-02 %s, TCP 502" % (ip("EXL-SIS-01"), ip("EXL-SIS-02"))),
                  ("Mix", "half the contacts are a write, half are 2–5 reads of registers from 200 up, outside the normal poll map"),
                  ("Cadence", "one contact every 60–180 s from +60 s"),
                  ("Fidelity", "plain Modbus/TCP; the real TRITON tool used a different protocol (TriStation, UDP 1502), not reproduced here")],
        "tells_sub": "the conversation itself is the signal",
        "tells": [("Any contact with the SIS is notable", "a safety controller is read rarely and written almost never"),
                  ("Engineering protocols to safety", "Modbus writes and out-of-map reads to EXL-SIS-0x outside a maintenance window"),
                  ("The TRITON/TRISIS precedent", "the 2017 attack reprogrammed a safety controller; the network sees the traffic first")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "the engineering station → the safety instrumented system",
        "legend": "Arrow points master → controller; replies return on the same connection.",
        "kpis": [("SIS", "Target"), ("writes + reads", "Contact"), ("safety", "Impact")],
        "filters": [("All traffic to the SIS", 'ip.dst == %s || ip.dst == %s' % (ip("EXL-SIS-01"), ip("EXL-SIS-02")), 'the conversation that should not exist'),
                    ("Modbus writes to the SIS", 'modbus.func_code in {5 6 15 16} && ip.dst == %s' % ip("EXL-SIS-01"), 'reprogramming attempts (repeat for SIS-02)'),
                    ("Who is the source", 'mbtcp && ip.dst == %s' % ip("EXL-SIS-01"), 'the platform names the unexpected peer')],
        "notes": [("warn", "Safety is the highest-consequence zone", "A write to a safety controller can disable the last line of protection; it is the most serious OT finding on the wire."),
                  _W3_OT_NOTE]})


@register("ndr-ot-zone-violation", "OT: cross-Purdue zone violation",
          "An IT host talks straight to a Level-1 PLC, bypassing the jump host", order=132, scenario="ndr-ot-zone-violation")
def d_ot_zone(c):
    ip = lambda n: _w3_ip(c, n)
    net = [("EXL-WS-023 (IT, level 4)", ip("EXL-WS-023"), "EXL-PLC-01 … -12 (level 1)", "%s … %s" % (ip("EXL-PLC-01"), ip("EXL-PLC-12")), "Modbus/TCP :502 (2 firewall hops)", "one read request per session, every 40–120 s, no jump host", False)]
    return _w3_campaign(c, "ndr-ot-zone-violation", {
        "net": net, "title": "Cross-Purdue zone violation", "accent": OT_ACCENT,
        "strip_title": "IT → OT, BYPASSING THE IDMZ", "strip_label": "reads",
        "strip_sub": "window {rwin} · an office PC reaching a Level-1 controller directly, which the Purdue model forbids",
        "ticks": (60, 80), "events": [(60, "first read +1 min")],
        "plain": "Industrial networks are layered (the Purdue model: level 4 offices, level 1 controllers) so office PCs cannot reach machines directly; "
                 "traffic must go through a guarded jump host in the IDMZ, the demilitarised zone between the two. Here an office PC skips all of that and talks Modbus to a controller.",
        "facts": [("Source", "EXL-WS-023 %s, IT subnet (level 4)" % ip("EXL-WS-023")),
                  ("Targets", "any of EXL-PLC-01 to -12, level 1, TCP 502"),
                  ("Request", "Modbus read of registers from 150 up, one request/response per session; not the SCADA pollers' own map"),
                  ("Path", "crosses EXL-FW1 and the industrial firewall EXL-OTFW1; PLC replies arrive at TTL 62"),
                  ("Cadence", "one session every 40–120 s from +60 s")],
        "tells_sub": "a flow that segmentation should make impossible",
        "tells": [("A flow that crosses zones", "an IT-subnet host speaking Modbus to a PLC; policy says this must go through the IDMZ jump host"),
                  ("Two firewall hops on the wire", "PLC replies arrive at TTL 62 (64 minus 2): they crossed EXL-FW1 and EXL-OTFW1, instead of the one hop an IDMZ-brokered path would show"),
                  ("Wrong initiator, no broker", "EXL-OTJUMP1 is the only permitted initiator into OT; this flow is neither it nor brokered")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "a level-4 IT host → level-1 PLCs across both firewalls, never via the IDMZ jump host",
        "legend": "Arrow points client → PLC; the PLC replies on the same connection.",
        "kpis": [("L4→L1", "Zones crossed"), ("2 hops", "Firewalls transited"), ("no broker", "IDMZ jump host")],
        "filters": [("IT host to a PLC", 'mbtcp && ip.src == %s' % ip("EXL-WS-023"), 'the cross-zone source'),
                    ("The two-hop return", 'ip.dst == %s && mbtcp && ip.ttl == 62' % ip("EXL-WS-023"), 'PLC replies at TTL 62 (64 minus 2) crossed both firewalls'),
                    ("Everything to the PLCs", 'mbtcp && ip.src != %s' % ip("EXL-OTJUMP1"), 'peer list: anything but the jump host')],
        "notes": [("warn", "Segmentation is the core OT control", "The platform must classify each subnet into its zone for the cross-zone flow to read correctly; see the OT-visibility note."),
                  ("", "Two L3 devices by design", "EXL-FW1 (enterprise) and EXL-OTFW1 (industrial) sandwich the IDMZ; they are part of the OT baseline, so the extra hop is always there to measure against."),
                  _W3_OT_NOTE]})


@register("ndr-ot-recon", "OT: device enumeration",
          "Modbus unit sweep, BACnet reads and DNP3 probes across the OT segment", order=133, scenario="ndr-ot-recon")
def d_ot_recon(c):
    ip = lambda n: _w3_ip(c, n)
    j = ip("EXL-OTJUMP1")
    net = [("EXL-OTJUMP1", j, "12 PLCs", "%s … %s" % (ip("EXL-PLC-01"), ip("EXL-PLC-12")), "Modbus :502 unit sweep", "3–5 unit IDs, mixed read function codes, some refused", False),
           ("EXL-OTJUMP1", j, "16 BACnet devices", "broadcast + unicast", "BACnet/IP UDP :47808", "Who-Is broadcast, I-Am replies, then ReadProperty to each", False),
           ("EXL-OTJUMP1", j, "6 RTUs", "%s … %s" % (ip("EXL-RTU-01"), ip("EXL-RTU-06")), "DNP3 :20000", "link-status check, then a read", False)]
    return _w3_campaign(c, "ndr-ot-recon", {
        "net": net, "title": "OT device enumeration", "accent": OT_ACCENT,
        "strip_title": "OT RECON", "strip_label": "sweep",
        "strip_sub": "window {rwin} · a single sweep that starts at +30 s and takes a few minutes; the rest of the window is quiet",
        "events": [(30, "sweep starts +30s: PLCs, then BACnet, then RTUs")],
        "plain": "A compromised jump host asks every industrial device on the plant network who it is and what it holds, over three industrial protocols, to build a map before doing anything harmful. "
                 "Modbus talks to PLCs, BACnet to building-control devices, DNP3 to remote terminal units (RTUs) in the field.",
        "facts": [("Source", "EXL-OTJUMP1 %s (IDMZ jump host)" % j),
                  ("Modbus", "12 PLCs in turn, 3–5 unit IDs each over coils, discrete inputs, holding and input registers; ~40% answered with an exception"),
                  ("BACnet", "Who-Is broadcast, I-Am replies, then confirmed ReadProperty to 16 devices"),
                  ("DNP3", "6 RTUs: a link-status request, then a read"),
                  ("Pace", "3–10 s between PLCs/RTUs, 2–8 s per BACnet device; one pass, not repeated")],
        "tells_sub": "breadth is the tell, not any one packet",
        "tells": [("One source, many OT targets", "one host touching PLCs, field devices and RTUs in sequence is building a map"),
                  ("Unit-ID and device sweep", "Modbus to many unit IDs, BACnet reads across devices, DNP3 probes to RTUs"),
                  ("Recon precedes every OT intrusion", "enumeration is step one; catching it here is the earliest warning")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "the jump host sweeps the OT asset set across three protocols",
        "legend": "Arrows point scanner → devices; each device answers on the same exchange.",
        "kpis": [("fan-out", "Pattern"), ("3", "Protocols"), ("34", "Devices probed")],
        "filters": [("From the sweeper", 'ip.src == %s && (mbtcp || bacapp || dnp3)' % j, 'one host across three OT protocols'),
                    ("BACnet reads", 'bacapp.confirmed_service == 12', 'readProperty across devices'),
                    ("Modbus breadth", 'mbtcp && ip.src == %s' % j, 'many PLC and unit targets from one source')],
        "notes": [("warn", "Breadth is the tell, not any one packet", "The platform's per-peer protocol metrics make a single source touching the whole asset set obvious."),
                  _W3_OT_NOTE]})


@register("ndr-ot-rogue-asset", "OT: rogue device",
          "A previously-unseen device appears on the OT segment and polls a PLC", order=134, scenario="ndr-ot-rogue-asset")
def d_ot_rogue(c):
    ip = lambda n: _w3_ip(c, n)
    rip = ".".join(ip("EXL-PLC-01").split(".")[:3] + ["241"])
    net = [("EXL-ROGUE-OT (new)", rip, "up to 4 PLCs", "%s …" % ip("EXL-PLC-01"), "Modbus/TCP :502 polls", "1–3 reads every 20–60 s, sticking to a few PLCs", False)]
    return _w3_campaign(c, "ndr-ot-rogue-asset", {
        "net": net, "title": "Rogue OT asset", "accent": OT_ACCENT,
        "strip_title": "UNKNOWN DEVICE ON THE OT VLAN", "strip_label": "polls",
        "strip_sub": "window {rwin} · a new MAC/IP where the asset set is supposed to be static",
        "ticks": (35, 40), "events": [(30, "device announces itself +30s")],
        "plain": "A device nobody has ever seen on the plant network plugs in, announces itself, and starts asking controllers for data as if it were a legitimate monitoring station. "
                 "Plant networks change rarely, so a newcomer is suspect. " + "Modbus is the industrial read/write protocol.",
        "facts": [("New device", "EXL-ROGUE-OT %s, MAC de:ad:be:ef:30:f1, on the PLC subnet" % rip),
                  ("Arrival", "ARP probe and gratuitous ARP at +30 s, before its first session"),
                  ("Behaviour", "Modbus master: 1–3 reads every 20–60 s from +35 s to a set of up to 4 chosen PLCs"),
                  ("Why it stands out", "no earlier sighting of this MAC or address in the baseline")],
        "tells_sub": "an asset list that should not change, changing",
        "tells": [("A device that was never there", "a fresh MAC/IP on a segment whose inventory should not change"),
                  ("Acting as a Modbus master", "it polls PLCs, an unauthorized supervisory role"),
                  ("Passive discovery", "the platform flags a new device on the OT VLAN the moment it speaks")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "a device the baseline never carried, now polling PLCs",
        "legend": "Arrow points master → controller; the PLC replies on the same connection.",
        "kpis": [("new", "Device"), ("OT VLAN", "Where"), ("Modbus", "Behaviour")],
        "filters": [("The new device's Modbus", 'mbtcp && ip.src == %s' % rip, 'check sources against the known asset list'),
                    ("Everything from the rogue", 'eth.addr == de:ad:be:ef:30:f1', 'ARP announcement and polls'),
                    ("New-device review", 'arp.isgratuitous == 1', "the arrival announcement the platform's new-device detection keys on")],
        "notes": [("warn", "The OT asset set should be static", "An unknown device on an OT VLAN is inherently suspect; subnet-to-zone classification keeps the platform's device list meaningful."),
                  _W3_OT_NOTE]})


@register("ndr-ot-camera-beacon", "OT/IoT: camera beacon",
          "An IP camera beacons to an internet cloud instead of only the NVR", order=135, scenario="ndr-ot-camera-beacon")
def d_ot_camera(c):
    ip = lambda n: _w3_ip(c, n)
    cam = ip("EXL-CAM-01")
    net = [("EXL-CAM-01", cam, "sync.luminaboard-cloud.net", "198.51.100.161", "HTTPS :443 GET /v1/ping", "200–400 B request every 45–120 s; DNS lookup each time", False)]
    return _w3_campaign(c, "ndr-ot-camera-beacon", {
        "net": net, "title": "IP-camera outbound beacon", "accent": OT_ACCENT,
        "strip_title": "IoT EGRESS", "strip_label": "beacons",
        "strip_sub": "window {rwin} · a camera phoning the internet all day, which a field device should never do",
        "ticks": (30, 82), "events": [(30, "first beacon +30s")],
        "plain": "A security camera, which should only ever send video to its recorder (the NVR), starts checking in with a server on the internet every minute or two. "
                 "Hijacked cameras doing this are how IoT botnets such as Mirai operate.",
        "facts": [("Camera", "EXL-CAM-01 %s (OT segment)" % cam),
                  ("Destination", "sync.luminaboard-cloud.net %s, HTTPS :443 (a simulated cloud host this build also uses for the smart-board baseline; a real camera would call its own vendor)" % "198.51.100.161"),
                  ("Request", "GET /v1/ping, user agent IPCam-Agent/2.3.1, 200–400 byte request, short JSON reply"),
                  ("Fingerprint", "the camera's own embedded TLS client, not a browser's"),
                  ("Expected peer", "EXL-NVR1 %s only" % ip("EXL-NVR1"))],
        "tells_sub": "a device that should only talk locally",
        "tells": [("A camera talking to the internet", "an IP camera's only peer should be the NVR; egress is the Mirai-botnet shape"),
                  ("Repeated small beacons", "a periodic outbound HTTPS check-in to one external host"),
                  ("IoT is the soft entry", "cheap devices with default credentials are the common IoT foothold")],
        "net_title": "HOW THE TRAFFIC MOVES", "net_sub": "EXL-CAM-01 → an internet cloud service, past the NVR it should be talking to",
        "legend": "Arrow points client → server; the sensor sees the egress even though the session is encrypted.",
        "kpis": [("camera", "Device"), ("egress", "Direction"), ("HTTPS", "Channel")],
        "filters": [("Camera egress", 'ip.src == %s && ip.dst == 198.51.100.161' % cam, 'the beacon'),
                    ("Any camera to the internet", 'ip.src == %s && !(ip.dst == 10.0.0.0/8)' % cam, 'egress that should not exist'),
                    ("Beacon regularity", 'tls.handshake.type == 1 && ip.src == %s' % cam, 'periodic client hellos')],
        "notes": [("warn", "Field devices should not egress", "A camera reaching the internet is both a performance and a security finding; the platform sees the egress regardless of encryption."),
                  _W3_OT_NOTE]})



NPM_SPEC = {
    "npm-http-errors": dict(
        blurb="Users get \u201csomething went wrong\u201d pages from the shipping app on EXL-WEB2: it answers quickly, but with server errors (HTTP 5xx) instead of data",
        feel=("What a user feels", "pages and API calls fail instantly and retrying sometimes works; nothing hangs,", "which is why the error mix, not latency, is the signal."),
        who="every workstation / API client", targets=["EXL-WEB2"], proto="HTTP / tcp 80",
        metric="HTTP status-code mix (error rate)",
        steps=[("healthy", "API returns 200 with JSON", "replies in about 20-150 ms"),
               ("degraded", "a rising share of requests return 500 / 502 / 503", "up to ~65% of requests at peak, still 10-80 ms"),
               ("degraded", "502/503 have a visible cause: WEB2's own call to SQL1 fails first", "503 = connect to SQL1:1433 refused; 502 = SQL1 login rejected (error 18456)"),
               ("degraded", "every error reply carries Retry-After: 2", "clients are told to back off 2 s"),
               ("recovery", "error rate falls back to zero", "200 again")],
        filters=[("Server errors", 'http.response.code >= 500', 'the 5xx surge'),
                 ("Just the 503s", 'http.response.code == 503', 'backend unavailable'),
                 ("Errors on the LOB app", 'http.response.code >= 500 && ip.src == {EXL-WEB2}', 'scoped to WEB2'),
                 ("The cause behind 502/503", 'tcp.dstport == 1433 && ip.src == {EXL-WEB2}', 'WEB2 failing to use its database'),
                 ("The requests behind them", 'http.request && tcp.dstport == 80', 'client side')]),
    "npm-dhcp-exhaustion": dict(
        blurb="Devices that boot or renew cannot get an IP address, so they sit offline: a compromised workstation (EXL-WS-009) used RDP on DC1 to starve the DHCP scope (auto-selects ndr-volt-typhoon)",
        feel=("What a user feels", "a laptop or phone joins the network but never gets an address,", "so nothing loads until the scope is fixed."),
        who="any device booting or renewing", targets=["EXL-DC1"], proto="DHCP / udp 67",
        metric="lease-acquisition success",
        steps=[("cause", "compromised EXL-WS-009 RDPs into EXL-DC1 on stolen creds and narrows the scope", "RDP from a WORKSTATION to DC1:3389 for 90-200 s, starting 5-25 s into the window"),
               ("healthy", "full DORA: Discover, Offer, Request, Ack", "client gets an address, before the change"),
               ("degraded", "Discover repeated with no Offer", "same transaction id re-sent at about 0, 4, 8, 16, 32 s"),
               ("degraded", "server NAKs a renewing client's Request, then discovery restarts unanswered", "no address in scope; relayed by the firewall, udp 67 to 67"),
               ("recovery", "scope corrected; Offers resume", "DORA completes again")],
        filters=[("The compromised source (cause)", 'rdp && ip.src == {EXL-WS-009} && ip.dst == {EXL-DC1}', 'a workstation driving RDP to the DC -- the platform flags the peer as unusual'),
                 ("No-lease NAKs", 'dhcp.option.dhcp == 6', 'the server refusing'),
                 ("Discovers", 'dhcp.option.dhcp == 1', 'clients asking'),
                 ("All DHCP to the server", 'dhcp && ip.dst == {EXL-DC1}', 'the relayed copies (client broadcasts go to 255.255.255.255)')]),
    "npm-db-pool-exhaustion": dict(
        blurb="The shipping app gets slow and then errors out because its database (EXL-SQL1) has run out of connections: it is up but saturated, not down",
        feel=("What a user feels", "pages hang while the app waits for a database connection,", "then some requests fail with an error."),
        who="the app servers (EXL-WEB1, EXL-WEB2), after a workstation surge", targets=["EXL-SQL1"], proto="TDS / tcp 1433",
        metric="TDS login + query processing time",
        steps=[("cause", "many workstations hit the LOB app on WEB2 at once", "24-40 workstations open connections to WEB2:80 within seconds of the window start"),
               ("healthy", "login and query answered promptly", "tens of ms, before the surge"),
               ("degraded", "app opens more DB connections than the server allows; the connect and login queue", "SYN/ACK up to 1.5 s late, login up to ~0.3 s"),
               ("degraded", "query processing time climbs", "up to ~5 s per query, server busy not down"),
               ("degraded", "up to 30% of logins refused, connection closed", "SQL error 17809: maximum user connections reached")],
        filters=[("The demand surge (cause)", 'tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 80 && ip.dst == {EXL-WEB2}', 'the burst of new connections from many hosts'),
                 ("Resource errors", 'tds.error.number == 17809', 'max user connections reached, login refused'),
                 ("Slow responses", 'tds && tcp.port == 1433 && tcp.time_delta > 1', 'service time over a second'),
                 ("All DB traffic", 'tds && ip.dst == {EXL-SQL1}', 'the pooled conversation')]),
    "npm-radius-storm": dict(
        blurb="Devices cannot get onto the wired or Wi-Fi network: the 802.1X authentication server (NPS on EXL-DC1) rejects, ignores or delays logins",
        feel=("What a user feels", "the port or Wi-Fi stays blocked: either a rejection comes back,", "or nothing does for seconds before the switch or WLC retries."),
        who="every device authenticating by 802.1X (wired via EXL-SWA1, Wi-Fi via EXL-WLC1)", targets=["EXL-DC1"], proto="RADIUS / udp 1812",
        metric="authentication success + latency",
        steps=[("healthy", "Access-Request answered with Access-Accept", "a few ms"),
               ("degraded", "Access-Reject returned instead", "about 60% of attempts at peak"),
               ("degraded", "no response; the switch / WLC retransmits the same request", "about 15% at peak; 1-3 resends, 1-3 s apart"),
               ("degraded", "Access-Accept arrives very late", "inner authentication step takes 1-5 s, not ms")],
        filters=[("Rejects", 'radius.code == 3', 'the auth failures'),
                 ("Accepts", 'radius.code == 2', 'what should happen'),
                 ("Requests", 'radius.code == 1', 'the attempts, from the switch or WLC (the RADIUS client)'),
                 ("Challenges", 'radius.code == 11', 'each EAP round the server answers'),
                 ("All AAA to the NPS", 'radius && ip.dst == {EXL-DC1}', 'the auth conversation')]),
    "npm-nfs-latency": dict(
        blurb="Opening files on the shared drive gets slow: an admin started a heavy job on the NAS (EXL-BACKUP1) and its disks are too busy to answer file reads quickly",
        feel=("What a user feels", "files on the share open slowly or the folder seems to freeze;", "the network is fine, the storage is the slow part."),
        who="hosts reading the NAS share", targets=["EXL-BACKUP1"], proto="NFS / tcp 2049",
        metric="NFS server processing time",
        steps=[("cause", "admin SSHes into the NAS from EXL-MGMT1 and starts a reindex/backup job", "SSH to BACKUP1:22, ~2-4 min"),
               ("healthy", "READ answered immediately", "about 2-10 ms, before the job"),
               ("degraded", "the job's disk I/O makes GETATTR / READ service time rise", "up to ~0.6 s per call at peak"),
               ("degraded", "reads back up behind the slow ones", "transfer time climbs"),
               ("recovery", "service time returns to normal", "fast reads again")],
        filters=[("The administrative cause", 'ssh && ip.dst == {EXL-BACKUP1}', 'the maintenance session that triggered it'),
                 ("Slow NFS calls", 'rpc.time > 0.2', 'reply over 0.2 s (only the worst calls pass 0.5 s)'),
                 ("NFS reads", 'nfs.procedure_v3 == 6', 'the READ operations'),
                 ("All NFS to the NAS", 'nfs && ip.dst == {EXL-BACKUP1}', 'the storage path')]),
    "npm-smtp-backup": dict(
        plain="The mail relay restarts, so mail is slow or told to retry later.",
        blurb="An admin reloads the relay EXL-BACKUP1 over SSH and the mail queue backs up behind it",
        who="any host sending mail", targets=["EXL-BACKUP1"], proto="SMTP / tcp 25",
        metric="SMTP response latency + code mix",
        steps=[("cause", "admin SSHes into the relay from EXL-MGMT1 and reloads Postfix", "SSH to BACKUP1:22, ~90-200 s"),
               ("healthy", "250 Ok after each command", "prompt, before the reload"),
               ("degraded", "the mail service is reloading: reply latency climbs", "seconds per step"),
               ("degraded", "451 try-again greylisting while the queue drains", "clients must queue"),
               ("recovery", "the commit finishes; 250s return promptly", "mail flows")],
        filters=[("The administrative cause", 'ssh && ip.dst == {EXL-BACKUP1}', 'the maintenance session that triggered it'),
                 ("Temporary failures", 'smtp.response.code == 451', 'greylisting / queue full'),
                 ("Slow responses", 'smtp && tcp.time_delta > 1', 'reply over a second'),
                 ("All SMTP to the relay", 'smtp && ip.dst == {EXL-BACKUP1}', 'the mail path')]),
    "npm-mtu-blackhole": dict(
        blurb="Small web requests work but large uploads freeze and then reset: after an admin ACL change on the firewall (FW-A) the sender never learns the path only carries 1400-byte packets",
        fault="FW-A", roles={"EXL-WEB2": "upload destination"},
        feel=("What a user feels", "pages load, but uploading a file hangs for 5-12 s and then fails;", "the 1400-byte limit is never signalled back to the sender."),
        who="hosts doing a bulk upload", targets=["FW-A", "EXL-WEB2"], proto="HTTP / tcp 80 (+ ICMP)",
        metric="large-flow completion",
        steps=[("cause", "admin SSHes into the firewall from EXL-MGMT1 and pushes an ACL that drops ICMP", "SSH from MGMT1 to the firewall :22, 60-150 s"),
               ("healthy", "small request and the bulk body both complete", "200 OK, before the change"),
               ("degraded", "300 KB POST: first flight of 10 full-size DF segments, none acknowledged", "retransmitted at 0.3 s (Windows) / 0.2 s, doubling"),
               ("degraded", "gateway's ICMP fragmentation-needed is now dropped on the path", "type 3 code 4, next-hop MTU 1400, seen by the sensor, never acted on by the sender"),
               ("degraded", "sender keeps the big MSS; the flow stalls", "client gives up after 5-12 s and sends RST")],
        filters=[("The administrative cause", 'ssh && ip.src == {EXL-MGMT1} && tcp.dstport == 22', 'the firewall maintenance session'),
                 ("Fragmentation-needed", 'icmp.type == 3 && icmp.code == 4', 'the blackhole signal'),
                 ("Next-hop MTU", 'icmp.mtu', 'the MTU the gateway advertises'),
                 ("The stalled uploads", 'http.request.method == "POST" && tcp.dstport == 80', 'the bulk flows'),
                 ("Retransmitted segments", 'tcp.analysis.retransmission && tcp.dstport == 80', 'the same segment re-sent at doubling intervals')]),
    "npm-ot-plc-unresponsive": dict(
        blurb="The operators\u2019 SCADA screen loses sight of a controller: the PLC answers slowly, says \u201cbusy\u201d, then goes silent (requires the OT subnet)",
        feel=("What an operator feels", "readings go stale or freeze; after five silent polls in a row", "the master drops the connection and reconnects."),
        who="EXL-SCADA1 polling the PLC", targets=["EXL-PLC-01"], proto="Modbus / tcp 502",
        metric="Modbus response: exceptions, then timeouts",
        steps=[("healthy", "read poll answered promptly", "polled every 1-2 s, answered in about 1-4 ms"),
               ("degraded", "response time climbs first, then PLC returns slave-device-busy exceptions", "up to ~0.35 s slower; exception code 06, reply 0.2-2.2 s late"),
               ("degraded", "polls go unanswered; the master retransmits", "resend after 1-2.5 s; 5 silent polls in a row = reconnect"),
               ("recovery", "the PLC answers again", "reads resume")],
        filters=[("Modbus exceptions", 'modbus.exception_code', 'the PLC refusing a read'),
                 ("Retransmitted polls", 'tcp.analysis.retransmission && tcp.port == 502', 'the master retrying'),
                 ("Slow reads", 'mbtcp && tcp.time_delta > 0.1', 'response time climbing'),
                 ("All Modbus to the PLC", 'mbtcp && ip.dst == {EXL-PLC-01}', 'the poll conversation')]),
    "npm-dns-degradation": dict(
        blurb="Websites and file shares are slow to open or fail to resolve: the main DNS server (EXL-DC1) stops answering reliably, so clients wait, retry, then switch to EXL-DC2",
        feel=("What a user feels", "every name lookup stalls for 1-3 seconds before the page starts,", "or fails outright when DC1 returns an error."),
        who="every workstation", targets=["EXL-DC1", "EXL-DC2"], proto="DNS / udp 53",
        fault="EXL-DC1", roles={"EXL-DC2": "failover server (healthy)"},
        metric="resolution time",
        steps=[("healthy", "query answered by EXL-DC1", "tens of ms"),
               ("degraded", "no reply from DC1, client retransmits", "resend at a fixed 1.0 s"),
               ("degraded", "client falls over to EXL-DC2", "query at 3.0 s, answer 0.2-1.5 s later"),
               ("degraded", "DC1 returns SERVFAIL instead of an answer", "rcode 2, 0.8 s or later; about half then retry on DC2"),
               ("degraded", "or DC1 answers, but late", "0.3 s up to ~4 s at peak")],
        filters=[("Failed resolution", 'dns.flags.rcode == 2', 'SERVFAIL from DC1'),
                 ("Retransmitted queries", 'dns.retransmission', 'the client giving up on DC1'),
                 ("Failover to the secondary", 'dns && ip.dst == {EXL-DC2}', 'queries that skip DC1'),
                 ("Slow answers", 'dns.time > 1', 'resolution over a second')]),
    "npm-smb-slowdown": dict(
        plain="The file server slows down, so opening and saving files hangs for users.",
        blurb="EXL-FILE1 stalls: receive window goes to zero and service time climbs",
        who="every workstation", targets=["EXL-FILE1"], proto="SMB2 / tcp 445",
        metric="read service time",
        steps=[("healthy", "read answered immediately", "a few ms"),
               ("degraded", "SMB2 READ response time climbs", "the server holds each reply longer as severity rises"),
               ("degraded", "on uploads (about half the sessions) the server advertises a zero receive window", "TCP window 0: the client must stop sending"),
               ("degraded", "client sends zero-window probes until the window reopens", "then resumes from the same sequence")],
        filters=[("Zero-window stalls", 'tcp.analysis.zero_window', 'the server telling clients to stop'),
                 ("Window recovery", 'tcp.analysis.window_update', 'each stall ending'),
                 ("Zero-window probes", 'tcp.analysis.zero_window_probe', 'client checking'),
                 ("Slow SMB reads", 'smb2.cmd == 8 && smb2.time > 0.5', 'service time above half a second')]),
    "npm-wan-congestion": dict(
        plain="Internet-bound traffic crawls, so outside sites feel slow for everyone.",
        blurb="The egress path saturates: RTT climbs and segments are retransmitted",
        who="every workstation", targets=["internet"], proto="HTTPS / tcp 443 outbound",
        metric="round-trip time and goodput",
        steps=[("healthy", "normal egress", "RTT 10\u201330 ms, ~80 Mb/s"),
               ("degraded", "queueing delay on the WAN", "RTT up to +100\u2013280 ms at full severity"),
               ("degraded", "available rate collapses", "~8 Mb/s once severity passes 15 %"),
               ("degraded", "segments lost and resent", "timeout resend (200 ms minimum, doubling) or fast retransmit after 3\u20134 duplicate ACKs")],
        filters=[("Retransmissions", 'tcp.analysis.retransmission', 'loss on the egress path'),
                 ("Fast retransmit", 'tcp.analysis.fast_retransmission',
                  'sender reacting to dup-ACKs, not a timeout'),
                 ("Duplicate ACKs", 'tcp.analysis.duplicate_ack', 'the receiver asking again'),
                 ("Slow egress sessions", 'tcp.analysis.ack_rtt > 0.1 && tcp.port == 443', 'elevated RTT')]),
    "npm-auth-latency": dict(
        blurb="Signing in takes seconds instead of a blink: the Kerberos login service (KDC on EXL-DC1) answers slowly, so every logon and file-share ticket drags",
        feel=("What a user feels", "the sign-in spinner and the first file-share open both wait,", "because two ticket requests in a row are slow."),
        who="every workstation", targets=["EXL-DC1"], proto="Kerberos / tcp 88",
        metric="AS-REQ \u2192 AS-REP time",
        steps=[("healthy", "AS-REP returned promptly", "5\u201330 ms"),
               ("degraded", "KDC response time climbs with load", "typically 0.3 s at the start of the ramp, ~2.7 s at peak, long tail capped at 9.5 s"),
               ("degraded", "the follow-up file-server ticket (TGS) is slow in the same way", "a new logon arrives about every 2.5 s"),
               ("recovery", "KDC catches up", "back to milliseconds")],
        filters=[("All Kerberos to the KDC", 'kerberos && tcp.port == 88', 'the whole exchange'),
                 ("Slow AS-REP", 'tcp.time_delta > 0.3 && tcp.srcport == 88', 'the KDC taking its time'),
                 ("AS-REQ volume", 'kerberos.msg_type == 10', 'authentication attempts'),
                 ("AS-REP replies", 'kerberos.msg_type == 11', 'pair them to measure latency'),
                 ("Ticket replies (TGS)", 'kerberos.msg_type == 13', 'the second slow step')]),
    "npm-tcp-loss-storm": dict(
        plain="Packets are dropped on the path to the file server, so transfers crawl.",
        blurb="The Salt Typhoon collector EXL-WS-061 reaches into switch EXL-SWB1 and the path to FILE1 drops segments (auto-selects ndr-salt-typhoon)",
        who="every workstation", targets=["EXL-FILE1"], proto="TCP / tcp 445",
        metric="retransmission rate",
        steps=[("cause", "compromised EXL-WS-061 SSHes into EXL-SWB1 and alters a port's speed/duplex", "SSH from a WORKSTATION to the switch -- anomalous"),
               ("healthy", "clean transfer", "no loss, before the change"),
               ("degraded", "duplex mismatch drops segments: a real hole in the sequence space", "late collisions / FCS errors"),
               ("degraded", "receiver sends duplicate ACKs", "three of them trigger fast retransmit"),
               ("degraded", "sender backs off", "throughput falls")],
        filters=[("The compromised source (cause)", 'ssh && ip.src == {EXL-WS-061} && ip.dst == {EXL-SWB1}', 'a workstation driving SSH to a switch -- the platform flags the peer as unusual'),
                 ("Retransmissions", 'tcp.analysis.retransmission', 'the core signal'),
                 ("Fast retransmit", 'tcp.analysis.fast_retransmission',
                  'dup-ACK triggered, before the RTO'),
                 ("Segments actually missing", 'tcp.analysis.lost_segment',
                  'a real hole in the sequence space')]),
    "npm-ntp-failure": dict(
        blurb="Computer clocks slowly drift because the time server (EXL-NTP1) stops answering, until logons start failing with a clock-skew error from the domain controller (EXL-DC1)",
        feel=("What a user feels", "nothing at first, then sign-in fails on the machines whose clock is", "more than 5 minutes off, starting roughly 17 minutes in for the fastest drifters."),
        who="workstations and five servers (FILE1, WEB1, WEB2, SQL1, DC2)", targets=["EXL-NTP1", "EXL-DC1"], proto="NTP / udp 123",
        metric="time sync, then authentication",
        steps=[("healthy", "NTP poll answered", "clients in sync"),
               ("degraded", "NTP1 stops replying", "polls with no response"),
               ("degraded", "clients keep polling, unanswered", "Linux/ntpd hosts every 60\u2013200 s in 3-6 packet volleys; Windows hosts about every 1024 s"),
               ("impact", "clocks drift more than 5 minutes off", "Kerberos KRB_AP_ERR_SKEW (code 37) from EXL-DC1, TCP 88")],
        filters=[("NTP requests", 'ntp && ip.dst == {EXL-NTP1}', 'the polls'),
                 ("NTP replies", 'ntp && ip.src == {EXL-NTP1}', 'should stop during the window'),
                 ("Clock-skew failures", 'kerberos.error_code == 37', 'KRB_AP_ERR_SKEW'),
                 ("All Kerberos errors", 'kerberos.msg_type == 30', 'includes the skew errors')]),
    "npm-web-degradation": dict(
        plain="The web app is slow or errors out; the real cause is the database behind it.",
        blurb="EXL-WEB2 page time tracks slow TDS to EXL-SQL1 \u2014 the database is the root cause",
        who="every workstation", targets=["EXL-WEB2", "EXL-SQL1"], proto="HTTP + TDS",
        metric="page time, driven by database time",
        steps=[("healthy", "page rendered promptly", "backend responsive"),
               ("degraded", "WEB2\u2192SQL1 query time climbs", "a dedicated slow pool for the window"),
               ("degraded", "the front end waits on the backend", "the cascade"),
               ("impact", "requests give up rather than hang", "HTTP 503 from WEB2, served promptly")],
        filters=[("Server errors", 'http.response.code == 503', 'requests that gave up'),
                 ("Errors from WEB2", 'http.response.code == 503 && ip.src == {EXL-WEB2}',
                  'the front end, not the database'),
                 ("The real cause", 'tds && ip.dst == {EXL-SQL1}', 'database round trips'),
                 ("Slow database", 'tcp.time_delta > 0.5 && tcp.srcport == 1433',
                  'TDS replies taking over half a second')]),
    "npm-web-dns-degradation": dict(
        plain="Ten users cannot open web pages because name lookups fail.",
        blurb="Ten named workstations cannot resolve, so their page loads stall before they start",
        who="10 specific workstations", targets=["EXL-DC1"], proto="DNS then HTTP",
        metric="page load blocked on resolution",
        steps=[("healthy", "name resolved, page loads", "normal"),
               ("degraded", "resolution slow or SERVFAIL", "the page never starts"),
               ("degraded", "browser retries the lookup", "compounding the delay"),
               ("impact", "load fails outright", "no TCP connection is ever attempted")],
        filters=[("Failed resolution", 'dns.flags.rcode == 2', 'SERVFAIL'),
                 ("Slow resolution", 'dns.time > 1', 'over a second to answer'),
                 ("The affected hosts", 'dns && ip.src == {FIRST_WEB_DNS_HOST}', 'one of the ten'),
                 ("Absent page loads", 'dns.flags.rcode == 2 && dns.qry.type == 1', 'lookups with no session after')]),
    "npm-voip-quality": dict(
        plain="Calls sound choppy: voice packets arrive late, out of order or not at all.",
        blurb="Media between handsets degrades: jitter, loss and reordering drag MOS down",
        who="the 10 VoIP handsets", targets=["EXL-PBX1"], proto="SIP / RTP / RTCP",
        metric="jitter, loss and MOS",
        steps=[("healthy", "clean G.711 media", "low jitter, no loss"),
               ("degraded", "inter-arrival jitter climbs", "audible artefacts"),
               ("degraded", "RTP packets lost and reordered", "gaps in the sequence numbers"),
               ("degraded", "RTCP receiver reports carry the damage", "the measurable quality signal")],
        filters=[("Call signalling", 'sip', 'INVITE / BYE around each call'),
                 ("Media streams", 'rtp', 'the audio itself'),
                 ("Reported quality", 'rtcp', 'receiver reports with loss and jitter'),
                 ("Reported loss", 'rtcp.ssrc.fraction > 0', 'receiver reports carrying a loss fraction')]),
    "npm-wireless-degradation": dict(
        plain="Wi-Fi drops: access points lose their controller; two never rejoin.",
        blurb="The WLC control plane falters: APs flap, two never come back, clients lose service",
        who="12 access points and their clients", targets=["EXL-WLC1"], proto="CAPWAP / udp 5246-5247",
        metric="control-plane responsiveness",
        steps=[("healthy", "CAPWAP keepalives answered", "tunnels stable"),
               ("degraded", "echo requests time out", "control latency climbs"),
               ("degraded", "APs drop their tunnel and rejoin", "flapping"),
               ("impact", "two APs never rejoin", "their clients lose service entirely")],
        filters=[("Control plane", 'capwap', 'keepalives, echoes and rejoins'),
                 ("Client-side fallout", 'dhcp || dns', 'renews and lookups that fail'),
                 ("The WLC", 'ip.addr == {EXL-WLC1}', 'everything to and from the controller'),
                 ("Data tunnels", 'udp.port == 5247', 'CAPWAP data versus control')]),
    "npm-sql1-service-failure": dict(
        plain="The database service stops, so web pages that need it fail; the server stays up.",
        blurb="EXL-SQL1 degrades, stops accepting connections, then recovers",
        who="the web tier and its users", targets=["EXL-SQL1", "EXL-WEB1"], proto="TDS / tcp 1433",
        metric="database availability",
        phases=[(600, 605, 0.0, "healthy"), (605, 625, 0.5, "degraded 10:05"), (625, 652, 1.0, "outage 10:25"),
                (652, 665, 0.0, "recovered 10:52")],
        steps=[("healthy", "queries answered", "normal response time (10:00\u201310:05)"),
               ("degraded", "lock timeouts and pool exhaustion", "TDS error 1222 (10:05\u201310:25)"),
               ("outage", "connections refused outright", "TCP RST on 1433 (10:25\u201310:52)"),
               ("recovery", "service restored", "connections accepted again (from 10:52)")],
        filters=[("Database traffic", 'tds', 'all TDS'),
                 ("Refused connections", 'tcp.flags.reset == 1 && tcp.port == 1433', 'the outage'),
                 ("Lock timeouts", 'tds', 'error 1222 in the response stream'),
                 ("Web-tier fallout", 'http.response.code >= 500', 'what users actually saw')]),
}


def _sev_curve(A, x0, y0, w, h, win_sec, colour=CYAN):
    """Draw the real incidents.sev() envelope, sampled from the function itself."""
    from netgen.incidents import sev
    pts = []
    for i in range(0, 201):
        t = win_sec * i / 200.0
        g = sev(t, (0.0, float(win_sec)))
        pts.append(f'{x0 + w * i / 200.0:.1f},{y0 + h - h * g:.1f}')
    A(f'<polyline points="{" ".join(pts)}" fill="none" stroke="{colour}" stroke-width="2.2"/>')
    A(f'<polygon points="{x0},{y0 + h} {" ".join(pts)} {x0 + w},{y0 + h}" fill="{colour}" opacity=".10"/>')
    for frac, label in ((0.15, "ramp"), (0.45, "peak"), (0.72, "recovery starts"), (1.0, "healthy")):
        xx = x0 + w * frac
        A(f'<line x1="{xx:.1f}" y1="{y0}" x2="{xx:.1f}" y2="{y0 + h}" stroke="#d5d6dc" stroke-dasharray="3 3"/>')
        A(f'<text x="{xx:.1f}" y="{y0 - 6}" text-anchor="middle" font-size="8.5" fill="{GRAY}">{label}</text>')
    A(f'<text x="{x0 - 6}" y="{y0 + 8}" text-anchor="end" font-size="8.5" fill="{GRAY}">peak</text>')
    A(f'<text x="{x0 - 6}" y="{y0 + h}" text-anchor="end" font-size="8.5" fill="{GRAY}">healthy</text>')


def _w5_phase_curve(A, x0, y0, w, h, start_min, span_sec, phases):
    """Step-wise envelope for modules that schedule fixed phases instead of incidents.sev().
    phases = [(from_abs_min, to_abs_min, level 0..1, label)]."""
    t0 = start_min * 60.0
    pts = []
    for a, b, lv, lab in phases:
        xa = x0 + w * (a * 60 - t0) / span_sec
        xb = x0 + w * (b * 60 - t0) / span_sec
        pts += [(xa, lv), (xb, lv)]
        A(f'<line x1="{xa:.1f}" y1="{y0}" x2="{xa:.1f}" y2="{y0 + h}" stroke="#d5d6dc" stroke-dasharray="3 3"/>')
        A(f'<text x="{(xa + xb) / 2:.1f}" y="{y0 - 6}" text-anchor="middle" font-size="8.5" fill="{GRAY}">{esc(lab)}</text>')
    ps = " ".join(f"{x:.1f},{y0 + h - h * lv:.1f}" for x, lv in pts)
    A(f'<polyline points="{ps}" fill="none" stroke="{CYAN}" stroke-width="2.2"/>')
    A(f'<polygon points="{pts[0][0]:.1f},{y0 + h} {ps} {pts[-1][0]:.1f},{y0 + h}" fill="{CYAN}" opacity=".10"/>')
    A(f'<text x="{x0 - 6}" y="{y0 + 8}" text-anchor="end" font-size="8.5" fill="{GRAY}">worst</text>')
    A(f'<text x="{x0 - 6}" y="{y0 + h}" text-anchor="end" font-size="8.5" fill="{GRAY}">healthy</text>')


def _npm_diagram(c, module):
    spec = NPM_SPEC[module]
    k = _scn(c, module); INC = k["INC"]

    def resolve(text):
        for name in ("EXL-DC1", "EXL-DC2", "EXL-NTP1", "EXL-WLC1", "EXL-SQL1", "EXL-WEB2", "EXL-FILE1",
                     "EXL-BACKUP1", "EXL-MGMT1", "EXL-SWB1", "FW-A", "EXL-WS-009", "EXL-WS-061", "EXL-PLC-01"):
            if "{" + name + "}" in text:
                h = c.host(name)
                text = text.replace("{" + name + "}", h["ip"] if h else name)
        if "{FIRST_WEB_DNS_HOST}" in text:
            h = c.host("EXL-WS-%03d" % INC.WEB_DNS_HOSTS[0])
            text = text.replace("{FIRST_WEB_DNS_HOST}", h["ip"] if h else "")
        return text

    W, H = 1180, 430
    P = []; A = P.append
    A(_svg_open(W, H, f'{module}: {spec["blurb"]}'))
    _panel_title(A, 14, 20, "SEVERITY ENVELOPE",
                 f'window {k["rwin"]} \u00b7 {k["span"] // 60} minutes \u00b7 '
                 + (f'fixed phases of the fault, as the generator schedules them; healthy traffic runs for up to two minutes before and after the window'
                  if spec.get("phases") else
                  f'ramp up, plateau, recover: how bad the fault is over time (the shape the generator uses); healthy traffic runs for up to two minutes before and after the window'))
    if spec.get("phases"):
        _w5_phase_curve(A, 110, 56, W - 150, 78, k["start"], k["span"], spec["phases"])
    else:
        _sev_curve(A, 110, 56, W - 150, 78, k["span"])
    ay = 140
    A(f'<line x1="110" y1="{ay}" x2="{W - 40}" y2="{ay}" stroke="#d5d6dc" stroke-width="1.4"/>')
    for i in range(0, 5):
        xx = 110 + (W - 150) * i / 4.0
        mm = int(k["span"] / 60 * i / 4.0)
        A(f'<line x1="{xx:.1f}" y1="{ay - 4}" x2="{xx:.1f}" y2="{ay + 4}" stroke="#c9cad0"/>')
        A(f'<text x="{xx:.1f}" y="{ay + 16}" text-anchor="middle" font-size="9" fill="{GRAY}">'
          f'{_off(k["start"] + mm - CAPTURE_START_MIN)}</text>')
    A(f'<text x="14" y="94" font-size="9" fill="{GRAY}">fault severity (0 = healthy, 1 = worst)</text>')
    A(f'<text x="14" y="108" font-size="10" font-weight="700" fill="{CYAN}">drives: {esc(spec["metric"])}</text>')
    A(f'<line x1="14" y1="172" x2="{W - 14}" y2="172" stroke="#e4e4e8"/>')

    _sub = spec.get("plain") or spec["blurb"]
    if len(_sub) > 95:
        _sub = _sub.split(":")[0] if len(_sub.split(":")[0]) <= 95 else _sub[:92].rsplit(" ", 1)[0] + "\u2026"
    _panel_title(A, 14, 194, "WHAT CHANGES, IN ORDER", _sub)
    cols = {"healthy": "#1a8a4a", "degraded": TANGERINE, "impact": PLUM, "outage": PLUM,
            "recovery": CYAN, "cause": SAPPHIRE}
    rows = [(st, cols.get(st, GRAY), what, detail, "") for st, what, detail in spec["steps"]]
    _rows(A, 14, 232, 560, rows, pitch=34)

    A(f'<line x1="616" y1="184" x2="616" y2="{H - 10}" stroke="#e4e4e8"/>')
    _panel_title(A, 640, 194, "WHO AND WHERE", "the fault is one place; the symptom is everywhere")
    trows = []
    for t in spec["targets"]:
        h = c.host(t)
        trows.append(("", SAPPHIRE, t, spec.get("roles", {}).get(t, "fault domain" if h else "external"), (h or {}).get("ip", "")))
    trows.append(("", CYAN, spec["who"], "affected population", ""))
    trows.append(("", GRAY, spec["proto"], "where to look", ""))
    _rows(A, 640, 232, W - 660, trows, pitch=30)
    A(f'<rect x="640" y="{H - 66}" width="{W - 660}" height="46" rx="8" fill="#f7fbfe" stroke="#bfe3f7"/>')
    # three lines centered vertically in the 46px box (baselines centred on the box middle, H-43)
    _feel = spec.get("feel") or ("The step change is the point",
        "healthy traffic before and after means a metric timeline shows a rise and a return,",
        "not a flat band that looks the same as the baseline.")
    A(f'<text x="656" y="{H - 56}" font-size="9.5" font-weight="700" fill="{SAPPHIRE}">'
      f'{esc(_feel[0])}</text>')
    A(f'<text x="656" y="{H - 42}" font-size="9" fill="{GRAY}">{esc(_feel[1])}</text>')
    A(f'<text x="656" y="{H - 30}" font-size="9" fill="{GRAY}">{esc(_feel[2])}</text>')
    A('</svg>')

    srows = "".join(f'<tr><td>{esc(st)}</td><td>{esc(what)}</td><td class="svc">{esc(det)}</td></tr>'
                    for st, what, det in spec["steps"])
    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (k["dur"], "Duration"),
                 (spec.get("fault", spec["targets"][0]), "Fault domain", "mono"), (spec["proto"].split("/")[0].strip(), "Protocol"),
                 ("4", "Envelope stages"), ("yes", "Recovers")],
        "sections": [("Progression", '<table><thead><tr><th>Stage</th><th>What changes</th>'
                                     f'<th>Detail</th></tr></thead><tbody>{srows}</tbody></table>'),
                     ("Finding it in a capture",
                      _filters_table([(a, resolve(b), n) for a, b, n in spec["filters"]]))],
        "notes": [
            ("", "Healthy on both sides",
             "The module schedules healthy traffic before and after the fault window, so the "
             "capture contains the baseline the degradation is measured against."),
            ("warn", "One cause, many symptoms",
             f'The fault lives on {spec.get("fault", spec["targets"][0])}, but what a user reports is {spec["metric"]}. '
             "Following the symptom back to the cause is the exercise."),
            ("", "Replay at original timing",
             "The envelope only survives if the capture is replayed with its original timing. "
             "Top speed flattens it into an undifferentiated burst."),
        ],
    }


def _mk_npm(module):
    inc_title = None

    def builder(c, _m=module):
        return _npm_diagram(c, _m)
    builder.__name__ = "d_" + module.replace("-", "_")
    from netgen import incidents as _I
    t = _I.REGISTRY[module].title.split("(")[0].strip()
    register(module, t, NPM_SPEC[module]["blurb"], order=200, scenario=module)(builder)


for _m in NPM_SPEC:
    _mk_npm(_m)


# =======================================================================================
# CRP SCENARIO DIAGRAMS
# Crypto posture is not a fault: there is no severity envelope and nothing recovers. These
# run at a steady Poisson cadence across the whole business day, because the weakness is a
# property of the configuration rather than an event.
# =======================================================================================
CRP_SPEC = {
    "crp-weak-tls": dict(
        headline="Obsolete TLS on an internal service",
        blurb="clients negotiate TLS 1.0 with RC4 against a legacy intranet host",
        detail=[("Server", "{WEAK_HOST}", "the legacy intranet listener"),
                ("Version", "TLS 1.0", "three versions behind current practice"),
                ("Cipher", "TLS_RSA_WITH_RC4_128_SHA (0x0005)", "RC4 is broken and prohibited"),
                ("Key exchange", "RSA", "no forward secrecy \u2014 one key compromise reads everything"),
                ("Clients", "Windows workstations", "a current macOS client cannot offer RC4, so only Windows clients connect this way")],
        why=[("1", "RC4 is a broken stream cipher", "biases in the keystream are practically exploitable"),
             ("2", "TLS 1.0 predates modern protections", "no AEAD, vulnerable record handling"),
             ("3", "No forward secrecy", "recorded traffic is decryptable if the key ever leaks"),
             ("4", "It is internal, so it is invisible", "external scanners never see this host")],
        filters=[("The weak sessions", 'tls.handshake.ciphersuite == 0x0005', 'every RC4 negotiation'),
                 ("By protocol version", 'tls.handshake.version == 0x0301', 'TLS 1.0 hellos'),
                 ("The host", 'tls.handshake.extensions_server_name contains "legacy-intranet"', 'the SNI'),
                 ("Everything to that server", 'tls && tcp.port == 443', 'all internal TLS')]),
    "crp-expired-cert": dict(
        headline="Invalid certificates on an internal service",
        blurb="backup web pages present an expired or a self-signed certificate, so users cannot tell the real server from an impostor, and click through",
        detail=[("Server 1", "{CERT_HOST}:443", "the backup portal, expired certificate ({EXPIRED_PCT}% of sessions)"),
                ("Server 2", "backup-console.corp.example.local:8443", "the backup console, self-signed certificate (the other {SELF_PCT}%)"),
                ("Cipher", "TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)", "the encryption itself is acceptable; the server identity is not"),
                ("Client behaviour", "warns, then connects anyway", "about 30% of sessions first abort at the warning, then retry and continue")],
        why=[("1", "Identity is unverified", "an expired or self-signed cert proves nothing about who answered"),
             ("2", "Clients are trained to ignore it", "the habit transfers to a real attack"),
             ("3", "Interception is undetectable", "nobody notices a substituted certificate"),
             ("4", "It never expires loudly", "no outage, so it is never prioritised")],
        filters=[("Certificates presented", 'tls.handshake.type == 11', 'every Certificate message'),
                 ("The expired-cert portal", 'tls.handshake.extensions_server_name contains "backup-portal"', 'the SNI (port 443)'),
                 ("The self-signed console", 'tcp.port == 8443 && tls', 'backup-console, self-signed'),
                 ("The cipher in use", 'tls.handshake.ciphersuite == 0x002F', 'AES128-CBC-SHA'),
                 ("Sessions that continued", 'tls.handshake.type == 16', 'key exchange after the bad cert')]),
    "crp-plaintext-creds": dict(
        headline="Credentials sent in clear text",
        blurb="HTTP Basic, FTP and LDAP simple bind carry usernames and passwords readable on the wire",
        detail=[("HTTP Basic", "{PT0}", "401 challenge, then base64 \u2014 encoding, not encryption"),
                ("FTP", "{PT1}", "USER then PASS as literal strings"),
                ("LDAP simple bind", "{PT2}", "the password sits in the bind request"),
                ("Cadence", "one session every ~{CADENCE}s", "all day, across many workstations")],
        why=[("1", "Base64 is not encryption", "anyone on the path recovers the password instantly"),
             ("2", "These are real accounts", "the same identities used elsewhere"),
             ("3", "Passive capture is enough", "no interception or downgrade needed"),
             ("4", "Three protocols, one problem", "fixing one leaves the others")],
        filters=[("HTTP Basic auth", 'http.authbasic', 'the decoded credential'),
                 ("FTP credentials", 'ftp.request.command == "PASS"', 'the password line'),
                 ("FTP logins", 'ftp.request.command == "USER"', 'the username line'),
                 ("LDAP simple bind", 'ldap.bindRequest_element', 'password inside the bind'),
                 ("All three at once", 'http.authbasic || ftp.request.command == "PASS" || ldap.bindRequest_element',
                  'everything leaking a credential')]),
    "crp-anonymous-ftp": dict(
        headline="An anonymous FTP server nobody deployed",
        blurb="a smart board is running FTP, accepts anonymous logins, and the firewall lets the internet reach it",
        detail=[("Host", "{FTP_BOARD}", "a conference-room display, not a file server"),
                ("Service", "FTP/21, clear text", "control and data channels both unencrypted"),
                ("Authentication", "USER anonymous", "no credential is required at all"),
                ("Internal client", "{FTP_WS}", "{FTP_N_INT} sessions from Start +3:17 through the working day"),
                ("Inbound from internet", "{FTP_EXT}", "{FTP_N_EXT} sessions — an explicit firewall pinhole")],
        why=[("1", "The device should not run FTP", "an appliance exposing a file service nobody inventoried"),
             ("2", "Anonymous means unauthenticated", "there is no account to disable or audit"),
             ("3", "It is reachable from the internet", "a deliberate inbound rule, not a misrouted packet"),
             ("4", "Files move both ways", "content can be taken off it and placed onto it")],
        filters=[("Anonymous logins", 'ftp.request.command == "USER" && ftp.request.arg == "anonymous"',
                  '{FTP_TOTAL} sessions, internal and inbound'),
                 ("Inbound from the internet", 'ftp && ip.src == {FTP_EXT}', 'the externally sourced sessions'),
                 ("Downloads", 'ftp.request.command == "RETR"', 'files taken off the board'),
                 ("Uploads", 'ftp.request.command == "STOR"', 'files placed onto the board'),
                 ("The data channels", 'ftp-data', 'the transfers themselves'),
                 ("Any file, by name", 'ftp-data.command contains "exp0101"',
                  'the data frames carrying one file — swap the name for any other'),
                 ("The planted credential file", 'ftp.request.arg == "exp0101.txt"',
                  'the RETR that pulls it off the board'),
                 ("Everything to the board", 'ip.addr == {FTP_BOARD_IP} && tcp.port == 21', 'all FTP control traffic')],
        file_index=True),
}


def _file_index_section():
    """One row per file that crosses the wire: direction, size, type, and the exact filter
    that isolates it.

    Every file in this scenario is carried in full and byte-for-byte, so each of these filters
    selects a complete, openable file — follow the TCP stream, save the payload direction, and
    it opens. A table of names with no filters would leave the reader to work that out.
    """
    from netgen import flows as NF
    kinds = {".csv": "CSV text", ".txt": "plain text", ".xml": "XML text", ".json": "JSON text",
             ".log": "syslog text", ".m3u": "playlist text", ".pdf": "PDF document",
             ".png": "PNG image", ".gz": "gzip tar archive", ".bin": "binary, ASCII header"}

    def kind(n):
        for ext, label in kinds.items():
            if n.endswith(ext):
                return label
        return "file"

    rows = []
    for name, verb, arrow in ([(n, "RETR", "board → client") for n in NF.FTP_DOWNLOADS]
                              + [(n, "STOR", "client → board") for n in NF.FTP_UPLOADS]):
        size = len(NF.ftp_content(name))
        note = f'{arrow} · {size:,} B · {kind(name)}'
        if name == "exp0101.txt":
            note += " · Caesar-shifted credentials"
        rows.append((name, f'ftp-data.command == "{verb} {name}"', note))
    return [("Finding each file in a capture",
             '<p class="hint" style="margin:0 0 10px">Each filter selects the data-channel '
             'frames carrying that one file. Follow the TCP stream and save the payload '
             'direction to recover the file intact — all of them are transferred whole, so '
             'what you save is byte-identical to what the server holds.</p>'
             + _filters_table(rows))]


def _crp_diagram(c, module):
    spec = CRP_SPEC[module]
    k = _scn(c, module); INC = k["INC"]
    cadence = INC.CRP_CADENCE[module]

    def resolve(t):
        t = t.replace("{WEAK_HOST}", INC.CRP_WEAK_TLS_HOST).replace("{CERT_HOST}", INC.CRP_CERT_HOST)
        t = t.replace("{EXPIRED_PCT}", str(int(INC.CRP_CERT_EXPIRED_SHARE * 100)))
        t = t.replace("{SELF_PCT}", str(100 - int(INC.CRP_CERT_EXPIRED_SHARE * 100)))
        t = t.replace("{CADENCE}", str(cadence))
        t = (t.replace("{FTP_BOARD_IP}", c.host(INC.FTP_BOARD)["ip"])
              .replace("{FTP_BOARD}", INC.FTP_BOARD)
              .replace("{FTP_WS}", INC.FTP_CLIENT_WS)
              .replace("{FTP_EXT}", INC.FTP_EXTERNAL_IP)
              .replace("{FTP_N_INT}", str(INC.FTP_INTERNAL_SESSIONS))
              .replace("{FTP_N_EXT}", str(INC.FTP_EXTERNAL_SESSIONS))
              .replace("{FTP_TOTAL}", str(INC.FTP_INTERNAL_SESSIONS + INC.FTP_EXTERNAL_SESSIONS)))
        for i, (kind, host, proto, _d) in enumerate(INC.CRP_PLAINTEXT):
            t = t.replace("{PT%d}" % i, f'{host} \u00b7 {proto}')
        return t

    W, H = 1180, 400
    P = []; A = P.append
    A(_svg_open(W, H, f'{module}: {spec["blurb"]}'))
    _panel_title(A, 14, 20, "PRESENT ALL DAY, NOT AN EVENT",
                 (f'window {k["rwin"]} \u00b7 {INC.FTP_INTERNAL_SESSIONS + INC.FTP_EXTERNAL_SESSIONS} sessions spread over the window '
                  f'(shape illustrative) \u00b7 no ramp, no peak, no recovery \u2014 this is configuration, not a fault')
                 if module == "crp-anonymous-ftp" else
                 f'window {k["rwin"]} \u00b7 a session roughly every {cadence}s \u00b7 '
                 f'no ramp, no peak, no recovery \u2014 this is configuration, not a fault')
    L, R, by = 120, W - 30, 78
    # sessions per 15-minute bucket. Drawing all ~600 ticks over eight hours just makes a
    # solid bar; the point is that the rate never changes, which a density plot shows.
    import random as _r
    rr = _r.Random(99)
    BUCKET = 900
    nb = max(1, k["span"] // BUCKET)
    counts = [0] * nb
    t = 0.0
    if module == "crp-anonymous-ftp":
        # the engine spaces 9 internal and 6 inbound sessions across the window (not a Poisson stream)
        for n_, t0_ in ((INC.FTP_INTERNAL_SESSIONS, 0.0), (INC.FTP_EXTERNAL_SESSIONS, 0.08 * k["span"])):
            for j in range(n_):
                tt = t0_ + j * k["span"] / n_ * rr.uniform(0.75, 1.2)
                counts[min(nb - 1, int(tt // BUCKET))] += 1
    else:
        while t < k["span"]:
            counts[min(nb - 1, int(t // BUCKET))] += 1
            t += rr.expovariate(1.0 / cadence)
    peak = max(1, max(counts))
    bw = (R - L) / nb
    for i, n in enumerate(counts):
        h = 30 * n / peak
        A(f'<rect x="{L + i * bw + 1:.1f}" y="{by + 16 - h:.1f}" width="{bw - 2:.1f}" height="{h:.1f}" '
          f'rx="2" fill="{PLUM}" opacity=".8"><title>{n} sessions in this 15 min</title></rect>')
    A(f'<line x1="{L}" y1="{by + 16}" x2="{R}" y2="{by + 16}" stroke="#d5d6dc"/>')
    A(f'<text x="14" y="{by + 4}" font-size="9.5" font-weight="700" fill="{SAPPHIRE}">sessions</text>')
    A(f'<text x="14" y="{by + 16}" font-size="8.5" fill="{GRAY}">per 15 min</text>')
    A(f'<text x="{R}" y="{by - 20}" text-anchor="end" font-size="9" fill="{GRAY}">'
      + (f'a few sessions at irregular gaps over {k["span"] // 3600} hours \u2014 always available, never an event</text>' if module == "crp-anonymous-ftp" else f'flat for {k["span"] // 3600} hours \u2014 no ramp, no peak, no recovery</text>'))
    ay = by + 40
    A(f'<line x1="{L}" y1="{ay}" x2="{R}" y2="{ay}" stroke="#d5d6dc" stroke-width="1.4"/>')
    for i in range(0, 5):
        xx = L + (R - L) * i / 4.0
        mm = int(k["span"] / 60 * i / 4.0)
        A(f'<line x1="{xx:.1f}" y1="{ay - 4}" x2="{xx:.1f}" y2="{ay + 4}" stroke="#c9cad0"/>')
        A(f'<text x="{xx:.1f}" y="{ay + 16}" text-anchor="middle" font-size="9" fill="{GRAY}">'
          f'{_off(k["start"] + mm - CAPTURE_START_MIN)}</text>')
    A(f'<line x1="14" y1="146" x2="{W - 14}" y2="146" stroke="#e4e4e8"/>')

    _panel_title(A, 14, 168, "THE POSTURE", resolve(spec["blurb"]))
    rows = [("", PLUM, resolve(v), resolve(d), "") for _lbl, v, d in spec["detail"]]
    labels = [r[0] for r in spec["detail"]]
    rows = [(labels[i], PLUM, resolve(spec["detail"][i][1]), resolve(spec["detail"][i][2]), "")
            for i in range(len(spec["detail"]))]
    _rows(A, 14, 206, 560, rows, pitch=36)

    A(f'<line x1="616" y1="158" x2="616" y2="{H - 10}" stroke="#e4e4e8"/>')
    _panel_title(A, 640, 168, "WHY IT MATTERS", "none of this causes an outage, which is why it survives")
    wrows = [(n, TANGERINE, t_, d, "") for n, t_, d in spec["why"]]
    _rows(A, 640, 206, W - 660, wrows, pitch=36)
    A('</svg>')

    drows = "".join(f'<tr><td>{esc(lbl)}</td><td class="m">{esc(resolve(v))}</td>'
                    f'<td class="svc">{esc(resolve(d))}</td></tr>' for lbl, v, d in spec["detail"])
    return {
        "svg": "".join(P),
        "kpis": [(k["rstart"], "Window opens", "mono"), (f'{k["span"] // 60 // 60} h', "Duration"),
                 ((f'{INC.FTP_INTERNAL_SESSIONS + INC.FTP_EXTERNAL_SESSIONS} sessions', "Total", "mono") if module == "crp-anonymous-ftp"
                  else (f'~{cadence}s', "Session cadence", "mono")), ("none", "Recovery"),
                 ("all day", "Exposure"), ("config", "Root cause")],
        "sections": [("Detail", '<table><thead><tr><th>Aspect</th><th>Value</th>'
                                f'<th>Why it matters</th></tr></thead><tbody>{drows}</tbody></table>'),
                     ("Finding it in a capture",
                      # resolve() here too: a filter with an unsubstituted {PLACEHOLDER} is
                      # worse than no filter, because it looks runnable and is not
                      _filters_table([(a, resolve(b), resolve(n)) for a, b, n in spec["filters"]]))]
                    + (_file_index_section() if spec.get("file_index") else []),
        "notes": [
            ("warn", "Nothing breaks, so nothing gets fixed",
             "Unlike an NPM fault there is no outage and no user complaint. The exposure is "
             "continuous and only visible to something watching the traffic."),
            ("", "Internal-only by definition",
             "All of it is workstation-to-server inside the perimeter, so external scanning and "
             "certificate transparency never reveal it.") if module != "crp-anonymous-ftp" else
            ("", "Reachable from outside as well",
             "Besides the internal workstation, six inbound sessions from one internet address reach the board "
             "through a firewall rule, so an external scan would find it."),
            ("", "Constant cadence is deliberate",
             f'Sessions arrive at a steady ~{cadence}s Poisson rate for the whole window, so the '
             "capture shows exposure rather than an incident.") if module != "crp-anonymous-ftp" else
            ("", "Sparse by design",
             "Nine internal and six inbound sessions are spread across the window at irregular gaps, "
             "so the exposure shows as repeated anonymous logins rather than a burst."),
        ],
    }


def _mk_crp(module):
    def builder(c, _m=module):
        return _crp_diagram(c, _m)
    builder.__name__ = "d_" + module.replace("-", "_")
    from netgen import incidents as _I
    t = _I.REGISTRY[module].title.split("(")[0].strip()
    register(module, t, CRP_SPEC[module]["headline"], order=300, scenario=module)(builder)


for _m in CRP_SPEC:
    _mk_crp(_m)


# =======================================================================================
# BASELINE SCENARIO DIAGRAM: the smart board MCP server.
# Registered against "baseline-mcp", which is NOT an incident module — the traffic is part
# of the normal day (Day.smartboards()). It is pinned into the NPM group in the selector,
# always on and not selectable, and this is the diagram its Visualize button opens.
# =======================================================================================
from netgen import flows as F                        # noqa: E402
from netgen import protocols as P                    # noqa: E402

INK = "#1c1830"


def _hm(t):
    return f"{t[0]:02d}:{t[1]:02d}"


# ---------------------------------------------------------------- panel A: the day
def _timeline(x0, y0, w, h):
    """05:00-21:00 strip: periodic vendor polls, the update moment, then the MCP band."""
    L, R = x0 + 92, x0 + w - 14
    D0, D1 = 5 * 60, 21 * 60
    upd = F.MCP_UPDATE_HM[0] * 60 + F.MCP_UPDATE_HM[1]
    X = lambda m: L + (R - L) * (m - D0) / (D1 - D0)
    p = []
    a = p.append

    a(f'<text x="{x0}" y="{y0 + 4}" font-size="11.5" font-weight="900" fill="{SAPPHIRE}">The day</text>')

    # axis
    ay = y0 + 96
    a(f'<line x1="{L}" y1="{ay}" x2="{R}" y2="{ay}" stroke="#d5d6dc" stroke-width="1.5"/>')
    for hh in range(5, 22):
        xx = X(hh * 60)
        a(f'<line x1="{xx:.1f}" y1="{ay - 4}" x2="{xx:.1f}" y2="{ay + 4}" stroke="#c9cad0"/>')
        if hh % 2 == 1:
            a(f'<text x="{xx:.1f}" y="{ay + 17}" text-anchor="middle" font-size="9.5" fill="{GRAY}">+{hh - 5}h</text>')

    # row 1 — all four boards polling the vendor, all day
    r1 = y0 + 26
    a(f'<text x="{x0}" y="{r1 + 4}" font-size="10" fill="{INK}">All 4 boards</text>')
    a(f'<text x="{x0}" y="{r1 + 15}" font-size="9" fill="{GRAY}">firmware poll</text>')
    a(f'<line x1="{L}" y1="{r1}" x2="{R}" y2="{r1}" stroke="#dfe0e6" stroke-dasharray="2 3"/>')
    # the generator polls every 90-150 min; the offer lands in the 25 min before the update
    offer_m = upd - 25
    m = D0 + 40
    while m < D1:
        if abs(m - offer_m) >= 34:                 # leave room for the offer marker
            a(f'<circle cx="{X(m):.1f}" cy="{r1}" r="3" fill="{GRAY}"/>')
        m += 105
    a(f'<circle cx="{X(offer_m):.1f}" cy="{r1}" r="5" fill="{TANGERINE}"/>')
    a(f'<text x="{X(offer_m):.1f}" y="{r1 + 18}" text-anchor="middle" font-size="9" '
      f'font-weight="700" fill="{TANGERINE}" '+'style="paint-order:stroke;stroke:#fff;stroke-width:3.5px;stroke-linejoin:round" '+'>200 manifest \u2192 download</text>')
    a(f'<text x="{R}" y="{r1 - 10}" text-anchor="end" font-size="9" fill="{GRAY}">'
      f'every ~2 h · 204 No Content</text>')

    # row 2 — the updated board's MCP service
    r2 = y0 + 64
    a(f'<text x="{x0}" y="{r2 + 4}" font-size="10" font-weight="700" fill="{SAPPHIRE}">{esc(F.MCP_BOARD)}</text>')
    a(f'<text x="{x0}" y="{r2 + 15}" font-size="9" fill="{GRAY}">MCP server</text>')
    a(f'<line x1="{L}" y1="{r2}" x2="{X(upd):.1f}" y2="{r2}" stroke="#d8d9df" stroke-width="7" stroke-linecap="round"/>')
    a(f'<text x="{(L + X(upd)) / 2:.1f}" y="{r2 - 9}" text-anchor="middle" font-size="9" fill="{GRAY}">no agent · display only</text>')
    a(f'<line x1="{X(upd):.1f}" y1="{r2}" x2="{R}" y2="{r2}" stroke="{CYAN}" stroke-width="7" stroke-linecap="round"/>')
    a(f'<text x="{(X(upd) + R) / 2:.1f}" y="{r2 - 9}" text-anchor="middle" font-size="9.5" font-weight="700" fill="{CYAN}">'
      f'MCP server live on :{P.MCP_PORT} · mDNS advertised · clients connecting</text>')

    # the update moment
    xu = X(upd)
    a(f'<line x1="{xu:.1f}" y1="{y0 + 18}" x2="{xu:.1f}" y2="{ay}" stroke="{TANGERINE}" stroke-width="1.6" stroke-dasharray="4 3"/>')
    a(f'<rect x="{xu - 34:.1f}" y="{y0 + 4}" width="68" height="16" rx="8" fill="{TANGERINE}"/>')
    a(f'<text x="{xu:.1f}" y="{y0 + 15}" text-anchor="middle" font-size="9.5" font-weight="700" fill="#fff">{_hm(F.MCP_UPDATE_HM)} update</text>')
    return "".join(p)


# ------------------------------------------------- panel B: the MCP lifecycle ladder
LADDER = [
    ("c", "POST /mcp", "initialize", "Accept: application/json, text/event-stream", False),
    ("s", "200 OK", "application/json", "Mcp-Session-Id: 1868a90c…  ← session begins", False),
    ("c", "POST /mcp", "notifications/initialized", "Mcp-Session-Id + MCP-Protocol-Version", False),
    ("s", "202 Accepted", "no body", "the signature of a JSON-RPC notification", True),
    ("c", "POST /mcp", "tools/list", "discovery", False),
    ("s", "200 OK", "application/json", "4 tools + inputSchema", False),
    ("c", "POST /mcp", "tools/call", "get_room_status / display_message / …", False),
    ("s", "200 OK", "text/event-stream", "server upgrades to SSE", True),
    ("s", "  event: message", "notifications/progress", "id: 1…3 · streamed before the result", False),
    ("s", "  event: message", "result", "id: 9 · then the stream closes", False),
    ("c", "DELETE /mcp", "session teardown", "Mcp-Session-Id", False),
    ("s", "204 No Content", "", "session ended", False),
]


def _ladder(x0, y0, w):
    cl, sv = x0 + 74, x0 + w - 74
    p = []
    a = p.append
    a(f'<text x="{x0}" y="{y0}" font-size="11.5" font-weight="900" fill="{SAPPHIRE}">MCP session on the wire</text>')
    a(f'<text x="{x0}" y="{y0 + 14}" font-size="9.5" fill="{GRAY}">Streamable HTTP transport, spec {P.MCP_PROTOCOL_VERSION} — plaintext, so every field below is directly readable</text>')

    top = y0 + 34
    a(f'<rect x="{cl - 62}" y="{top}" width="124" height="26" rx="6" fill="{SAPPHIRE}"/>'
      f'<text x="{cl}" y="{top + 17}" text-anchor="middle" font-size="10.5" font-weight="700" fill="#fff">client</text>')
    a(f'<rect x="{sv - 74}" y="{top}" width="148" height="26" rx="6" fill="{CYAN}"/>'
      f'<text x="{sv}" y="{top + 17}" text-anchor="middle" font-size="10.5" font-weight="700" fill="#fff">'
      f'{esc(F.MCP_BOARD)}:{P.MCP_PORT}</text>')

    y = top + 44
    step = 37
    a(f'<line x1="{cl}" y1="{top + 26}" x2="{cl}" y2="{y + step * len(LADDER) - 12}" stroke="#d5d6dc" stroke-dasharray="3 3"/>')
    a(f'<line x1="{sv}" y1="{top + 26}" x2="{sv}" y2="{y + step * len(LADDER) - 12}" stroke="#d5d6dc" stroke-dasharray="3 3"/>')

    for i, (who, head, sub, note, hl) in enumerate(LADDER):
        yy = y + i * step
        c2s = who == "c"
        x1, x2 = (cl, sv) if c2s else (sv, cl)
        col = SAPPHIRE if c2s else CYAN
        if hl:
            a(f'<rect x="{x0 + 4}" y="{yy - 15}" width="{w - 8}" height="30" rx="6" fill="#fff8f3"/>')
        a(f'<line x1="{x1 + (8 if c2s else -8)}" y1="{yy}" x2="{x2 + (-8 if c2s else 8)}" y2="{yy}" '
          f'stroke="{col}" stroke-width="1.6" marker-end="url(#mcparr{"S" if c2s else "C"})"/>')
        mid = (cl + sv) / 2
        a(f'<text x="{mid}" y="{yy - 5}" text-anchor="middle" font-size="10.5" font-weight="700" fill="{col}">'
          f'{esc(head)}{("  " + esc(sub)) if sub else ""}</text>')
        a(f'<text x="{mid}" y="{yy + 12}" text-anchor="middle" font-size="9" fill="{GRAY}">{esc(note)}</text>')
    return "".join(p)


# ------------------------------------------------------- panel C: who talks to whom
def _flowmap(c, x0, y0, w, h):
    p = []
    a = p.append
    bx, by = x0 + w / 2, y0 + 210                # the board, centre
    a(f'<text x="{x0}" y="{y0}" font-size="11.5" font-weight="900" fill="{SAPPHIRE}">Observed flows</text>')
    a(f'<text x="{x0}" y="{y0 + 14}" font-size="9.5" fill="{GRAY}">all of it baseline traffic — no incident module involved</text>')

    def node(cx, cy, ww, hh, title, sub, fill, fg="#fff", stroke=None):
        a(f'<rect x="{cx - ww / 2}" y="{cy - hh / 2}" width="{ww}" height="{hh}" rx="9" fill="{fill}"'
          + (f' stroke="{stroke}"' if stroke else "") + '/>')
        a(f'<text x="{cx}" y="{cy - 2}" text-anchor="middle" font-size="11" font-weight="700" fill="{fg}">{esc(title)}</text>')
        a(f'<text x="{cx}" y="{cy + 12}" text-anchor="middle" font-size="9" fill="{fg}" opacity=".85">{esc(sub)}</text>')

    def arrow(x1, y1, x2, y2, col, label, sub="", dash=None, up=True):
        dash_attr = 'stroke-dasharray="%s" ' % dash if dash else ""      # kept out of the f-string (py < 3.12)
        a(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{col}" stroke-width="1.8" '
          f'{dash_attr}marker-end="url(#mcpflow)"/>')
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        vert = abs(x2 - x1) < 3                    # a vertical arrow: put the label beside it, not on it
        tx, anc = (mx - 8, "end") if vert else (mx, "middle")        # left of a vertical arrow, away from the vendor boxes
        a(f'<text x="{tx}" y="{my - (6 if up else -12)}" text-anchor="{anc}" font-size="9.5" '
          f'font-weight="700" fill="{col}" style="paint-order:stroke;stroke:#fff;stroke-width:3.5px;stroke-linejoin:round" >{esc(label)}</text>')
        if sub:
            a(f'<text x="{tx}" y="{my + (6 if up else -1)}" text-anchor="{anc}" font-size="8.5" fill="{GRAY}" style="paint-order:stroke;stroke:#fff;stroke-width:3.5px;stroke-linejoin:round" >{esc(sub)}</text>')

    # vendor (external, above the firewall)
    node(bx, y0 + 46, 260, 40, F.SB_VENDOR_UPDATES, "firmware manifest + image · HTTPS 443", "#f4f4f7", SAPPHIRE, "#d5d6dc")
    node(bx + 160, y0 + 112, 200, 34, F.SB_VENDOR_CLOUD, "agent heartbeat · HTTPS 443", "#f4f4f7", SAPPHIRE, "#d5d6dc")
    # firewall divider
    a(f'<line x1="{x0}" y1="{y0 + 142}" x2="{x0 + w}" y2="{y0 + 142}" stroke="{PLUM}" stroke-width="1.2" stroke-dasharray="6 4"/>')
    a(f'<text x="{x0 + w - 2}" y="{y0 + 138}" text-anchor="end" font-size="9" font-weight="700" fill="{PLUM}">EXL-FW1 · NAT egress</text>')

    # the board
    node(bx, by, 250, 52, f'{F.MCP_BOARD}  ·  {(c.host(F.MCP_BOARD) or next((h for h in c.data.get("hosts", []) if h["hostname"].endswith(F.MCP_BOARD)), {})).get("ip", "")}',
         f'LuminaBoard {F.SB_FW_NEW} · MCP server :{P.MCP_PORT}', CYAN)

    # clients
    node(x0 + 78, by + 116, 146, 40, "Workstations", "mcp-client / ExampleAssistant", SAPPHIRE)
    node(x0 + w - 74, by + 116, 148, 40, "EXL-MGMT1", "mcp-inspector · admin window", SAPPHIRE)

    arrow(bx - 30, by - 26, bx - 30, y0 + 66, GRAY, "GET /api/v2/firmware/check", "204 → then one 200", up=True)
    arrow(bx + 60, by - 26, bx + 130, y0 + 129, GRAY, "POST /agent/heartbeat", "every ~10 min", up=True)
    arrow(x0 + 78, by + 96, bx - 70, by + 28, CYAN, f"HTTP :{P.MCP_PORT}", "MCP sessions + SSE stream", up=False)
    arrow(x0 + w - 74, by + 96, bx + 70, by + 28, CYAN, f"HTTP :{P.MCP_PORT}", "MCP sessions", up=False)

    # mDNS broadcast
    my_ = by + 176
    a(f'<rect x="{x0 + 10}" y="{my_}" width="{w - 20}" height="34" rx="8" fill="#f7fbfe" stroke="#bfe3f7"/>')
    a(f'<text x="{x0 + 22}" y="{my_ + 14}" font-size="9.5" font-weight="700" fill="{CYAN}">mDNS 224.0.0.251:5353 — _mcp._tcp.local advertised to the whole user subnet</text>')
    a(f'<text x="{x0 + 22}" y="{my_ + 27}" font-size="9" fill="{GRAY}" font-family="ui-monospace,Menlo,monospace">'
      f'TXT  mcp={P.MCP_PROTOCOL_VERSION}  transport=streamable-http  path={P.MCP_ENDPOINT}  ver={F.SB_FW_NEW}</text>')
    return "".join(p)


@register("baseline-mcp", "Smart board MCP",
          "Firmware update and the MCP server that follows", order=150, scenario="baseline-mcp")
def d_baseline_mcp(c):
    W, H = 1180, 762
    svg = [f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" role="img" '
           f'aria-label="Smart board firmware update at {_hm(F.MCP_UPDATE_HM)} and the MCP server traffic that follows">']
    svg.append(
        '<defs>'
        f'<marker id="mcparrS" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{SAPPHIRE}"/></marker>'
        f'<marker id="mcparrC" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{CYAN}"/></marker>'
        f'<marker id="mcpflow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{GRAY}"/></marker>'
        '</defs>')
    svg.append(_timeline(14, 20, W - 28, 130))
    svg.append(f'<line x1="14" y1="172" x2="{W - 14}" y2="172" stroke="#e4e4e8"/>')
    svg.append(_ladder(14, 196, 576))
    svg.append(f'<line x1="606" y1="188" x2="606" y2="{H - 12}" stroke="#e4e4e8"/>')
    svg.append(_flowmap(c, 626, 196, W - 640, 560))
    svg.append('</svg>')

    filters = [
        ("Everything MCP", 'tcp.port == 3000'),
        ("MCP requests only", 'http.request.uri == "/mcp"'),
        ("Session establishment", 'http contains "Mcp-Session-Id"'),
        ("Notifications (no body)", 'http.response.code == 202'),
        ("Server push streams", 'http.content_type contains "text/event-stream"'),
        ("Tool invocations", 'http.file_data contains "tools/call"'),
        ("Service discovery", 'dns.resp.name contains "_mcp._tcp"'),
        ("Vendor firmware poll", 'tls.handshake.extensions_server_name contains "luminaboard"'),
        ("The update itself", 'http.response.code == 200 && ip.addr == 198.51.100.160'),
    ]
    frows = "".join(f'<tr><td>{esc(a)}</td><td class="m">{esc(b)}</td></tr>' for a, b in filters)
    trows = "".join(
        f'<tr><td class="m">{esc(t["name"])}</td><td>{esc(t.get("title",""))}</td>'
        f'<td class="svc">{esc(t["description"])}</td></tr>' for t in P.MCP_TOOLS)

    return {
        "svg": "".join(svg),
        "kpis": [(_hm(F.MCP_UPDATE_HM), "Agent comes up", "mono"),
                 (F.MCP_BOARD, "Board", "mono"),
                 (P.MCP_PORT, "Port (plaintext)"),
                 (P.MCP_PROTOCOL_VERSION, "MCP version", "mono"),
                 (len(P.MCP_TOOLS), "Tools exposed"),
                 ("4", "Boards polling vendor")],
        "sections": [
            ("Tools the board exposes",
             f'<table><thead><tr><th>Tool</th><th>Title</th><th>Description</th></tr></thead><tbody>{trows}</tbody></table>'),
            ("Finding it in a capture",
             f'<table><thead><tr><th>What</th><th>Display filter</th></tr></thead><tbody>{frows}</tbody></table>'),
        ],
        "notes": [
            ("", "Streamable HTTP, not the old SSE transport",
             "MCP's current transport (spec 2025-06-18) uses ONE endpoint for both POST and GET. "
             "The deprecated 2024-11-05 HTTP+SSE transport used a separate /sse endpoint and an "
             "endpoint event; nothing here emits that shape."),
            ("warn", "Why this is worth seeing",
             "An unauthenticated MCP server on a conference-room display, advertised over mDNS and "
             "reachable in plaintext from any workstation, exposes model-callable tools on the "
             "corporate LAN. It arrived through a routine vendor firmware update."),
            ("", "This is baseline, not a scenario",
             "It is scheduled by Day.smartboards() and is present in every capture, including a "
             "build with no incident modules selected. There is nothing to switch on."),
        ],
    }



# ---- Theming -------------------------------------------------------------------------------
# Every diagram is drawn with literal hex colours (the Forge palette) so the SVG stays valid as a
# standalone file. When the page is served by the app, theme.css supplies the colour tokens for the
# palette and light/dark mode the user chose, and the rules below re-point each literal colour at
# a token. CSS beats a presentation attribute, so the drawing code is untouched and a palette
# change needs no diagram change. text/tspan use the readable "-tx" tokens; shapes use the fills.
# Entries: literal hex -> (shape token, text token).
_RAMP = lambda t: "color-mix(in srgb,var(--%s) 55%%,var(--surface))" % t
_FADED = "color-mix(in srgb,var(--gray) 80%,var(--surface))"
THEME_REMAP = {
    # accent
    "#c2410c": ("var(--sapphire)", "var(--sapphire-tx)"),
    "#b23f0f": ("color-mix(in srgb,var(--sapphire) 82%,#000)", "var(--sapphire-tx)"),
    # status
    "#dc2626": ("var(--plum)", "var(--plum-tx)"),
    "#15803d": ("var(--cyan)", "var(--cyan-tx)"),
    "#1a8a4a": ("var(--cyan)", "var(--cyan-tx)"),
    "#1b7f4b": ("var(--cyan)", "var(--cyan-tx)"),
    "#f59e0b": ("var(--tangerine)", "var(--tangerine)"),
    "#1d4ed8": ("var(--magenta)", "var(--magenta-tx)"),
    "#0e7490": ("var(--magenta)", "var(--magenta-tx)"),
    "#7c3aed": ("var(--ir)", "color-mix(in srgb,var(--ir) 70%,var(--ink))"),
    "#8a5cf0": ("var(--ir)", "color-mix(in srgb,var(--ir) 70%,var(--ink))"),
    # text and neutral marks
    "#4b5563": ("var(--gray)", "var(--gray)"),
    "#4a4760": ("var(--gray)", "var(--gray)"),
    # Faded labels ("not involved in this scenario"): readable but quiet. Text uses the theme's gray eased toward
    # the page, so it holds >= 3:1 on white and on the dark page alike (the old literal pale greys were ~1.8:1).
    "#9ca3af": ("var(--gray)", _FADED),
    "#1c1830": ("var(--ink)", "var(--ink)"),
    "#3a2a55": ("var(--ink)", "var(--ink)"),
    "#a9aab2": (_RAMP("gray"), _FADED),
    "#c2c3ca": (_RAMP("gray"), _FADED),
    # paper
    "#fff": ("var(--surface)", None), "#ffffff": ("var(--surface)", None),
    "#fafafc": ("var(--surface-2)", "var(--surface-2)"), "#fbfbfd": ("var(--surface-2)", "var(--surface-2)"),
    "#f7fbfe": ("var(--surface-2)", "var(--surface-2)"), "#fbf6f9": ("var(--surface-2)", "var(--surface-2)"),
    "#fdf2f8": ("var(--surface-2)", "var(--surface-2)"), "#f9f1f6": ("var(--surface-2)", "var(--surface-2)"),
    "#eef6fc": ("var(--surface-2)", "var(--surface-2)"), "#fff8f3": ("var(--surface-2)", "var(--surface-2)"),
    "#fff6f0": ("var(--surface-2)", "var(--surface-2)"), "#fff6f1": ("var(--surface-2)", "var(--surface-2)"),
    "#f1f1f5": ("var(--mist)", "var(--mist)"), "#f4f4f7": ("var(--mist)", "var(--mist)"),
    "#eff0f3": ("var(--mist)", "var(--mist)"), "#e8e9ed": ("var(--mist)", "var(--mist)"),
    "#f0d5e0": ("var(--mist)", "var(--mist)"), "#d9d5ea": ("var(--line)", "var(--line)"),
    # rules and borders
    "#e4e4e8": ("var(--line)", "var(--line)"), "#ececf0": ("var(--line)", "var(--line)"),
    "#eef0f3": ("var(--line)", "var(--line)"), "#eceded": ("var(--line)", "var(--line)"),
    "#dfe0e6": ("var(--line)", "var(--line)"), "#d8d9df": ("var(--line)", "var(--line)"),
    "#e9d3de": ("var(--line)", "var(--line)"), "#d6ecfa": ("var(--line)", "var(--line)"),
    "#bfe3f7": ("var(--line)", "var(--line)"), "#f6d3bd": ("var(--line)", "var(--line)"),
    "#f3c6ab": ("var(--line)", "var(--line)"),
    "#d5d6dc": ("var(--line-2)", "var(--line-2)"), "#cfd0d8": ("var(--line-2)", "var(--line-2)"),
    "#d2d3d9": ("var(--line-2)", "var(--line-2)"), "#c9cad0": ("var(--line-2)", "var(--line-2)"),
}

# A pale colour used as a TEXT fill is light text on a dark node (the firewall and sensor boxes are dark
# gradients in every theme), so text keeps its literal colour; only shapes follow the theme.
for _hx in ("#fafafc", "#fbfbfd", "#f7fbfe", "#fbf6f9", "#fdf2f8", "#f9f1f6", "#eef6fc", "#fff8f3",
            "#fff6f0", "#fff6f1", "#f1f1f5", "#f4f4f7", "#eff0f3", "#e8e9ed", "#f0d5e0", "#d9d5ea"):
    THEME_REMAP[_hx] = (THEME_REMAP[_hx][0], None)


def theme_remap_css():
    """CSS that re-points the SVG's literal colours at theme tokens (see THEME_REMAP)."""
    out = []
    for hx, (shape, text) in THEME_REMAP.items():
        for attr, prop in (("fill", "fill"), ("stroke", "stroke")):
            out.append('svg :not(text):not(tspan)[%s="%s" i]{%s:%s}' % (attr, hx, prop, shape))
            if text:
                out.append('svg text[%s="%s" i],svg tspan[%s="%s" i]{%s:%s}' % (attr, hx, attr, hx, prop, text))
        out.append('svg stop[stop-color="%s" i]{stop-color:%s}' % (hx, shape))
    # the gradient fade end ("near black") follows the palette's header tone
    out.append('svg stop[stop-color="#0a0a0a" i]{stop-color:var(--hdr-a)}')
    # inline style="color:#.." text in tables and notes
    out.append('[style*="#4a4760" i],[style*="#4b5563" i]{color:var(--gray)!important}')
    return "\n  ".join(out)


from page_template import PALETTES, PULSE_MARK, themed  # noqa: E402,F401  (shared page shell)
_PRINT_LIGHT = {"--page": "#fff", "--surface": "#fff", "--surface-2": "#fafafc", "--mist": "#f1f1f5",
                "--line": "#E4E4E8", "--line-2": "#cfd0d8", "--ink": "#1c1830", "--gray": "#4B5563",
                "--code-bg": "rgba(0,0,0,.06)"}


def print_light_css():
    """Paper is white: whatever theme is on screen, print with the light neutrals and the readable
    (non -tx) accents. A custom property set !important in print wins over the theme's own."""
    t = dict(_PRINT_LIGHT)
    t.update({"--sapphire-tx": SAPPHIRE, "--plum-tx": PLUM, "--cyan-tx": CYAN, "--magenta-tx": MAGENTA})
    body = ";".join("%s:%s!important" % kv for kv in t.items())
    return "@media print{:root,:root[data-theme],:root[data-palette]{%s}}" % body


def render_page(diagram, c, logo):
    """Shared chrome for every diagram — masthead, lozenge title, KPI strip, notes, footer.

    A builder supplies only its own content, so diagrams stay a visual family and new ones
    inherit the branding for free.
    """
    out = diagram.builder(c)
    # Attack/fault scenarios (NDR, NPM) may generate traffic that dominates a device's protocol
    # mix and shifts its role in the platform for the scenario window — allowed by design, so the diagram
    # says so. CRP posture scenarios and the environment/baseline diagrams keep their roles and are
    # left out. Done centrally here so every scenario diagram inherits it, builders stay unchanged.
    if diagram.scenario:
        from netgen import incidents as _INC
        _inc = _INC.REGISTRY.get(diagram.scenario)
        if _inc and _inc.prefix.upper() in ("NDR", "NPM"):
            out = dict(out)
            out["notes"] = list(out.get("notes", [])) + [CLASSIFY_NOTE]
    d = c.data

    kpis = "".join(
        f'<div class="kpi"><b class="{k[2] if len(k) > 2 else ""}">{esc(k[0])}</b>'
        f'<span>{esc(k[1])}</span></div>'
        for k in out.get("kpis", []))
    import re as _re
    secs = out.get("sections", [])

    def _slug(h):
        return _re.sub(r"[^a-z0-9]+", "-", _re.sub(r"<[^>]+>", "", h).lower()).strip("-")
    toc = ""
    if len(secs) >= 6:                      # a long report gets a jump list; short ones do not need one
        toc = ('<p class="toc" style="font-size:12px;line-height:1.9">Jump to: ' + " &middot; ".join(
            f'<a href="#{_slug(h)}">{_re.sub(r"<[^>]+>", "", h).title()}</a>' for h, _b in secs) + "</p>")
    sections = toc + "".join(f'<h2 id="{_slug(head)}">{head}</h2>{body}' for head, body in secs)
    notes = "".join(
        f'<div class="note {kind}"><b>{esc(title)}</b>{esc(body)}</div>'
        for kind, title, body in out.get("notes", []))
    notes_block = f'<div class="notes">{notes}</div>' if notes else ""

    # Masthead chrome is the same for every diagram unless a builder says otherwise. The
    # About page is the one caller that does: it describes the TOOL, so leading with the
    # fictional company name and its AD domain would be wrong. Defaults are the historical
    # strings, so no existing diagram changes.
    doc_tag  = out.get("doc_tag") or "Demo environment<br>Synthetic capture topology"
    headline = out.get("h1") or d["org"]
    subtitle = out.get("subtitle") or (diagram.description + " \u00b7 " + d["domain"])

    # When a builder supplies a masthead_title (the About page does), the product title sits in
    # the masthead beside the logo and the big title-block headline is dropped. Every other
    # diagram keeps the logo-only masthead and its own headline.
    mh_title = out.get("masthead_title")
    if mh_title:
        masthead_left = (f'<div class="mh-left"><div class="logo">{PULSE_MARK}</div>'
                         f'<span class="mh-title">{mh_title}</span></div>')
        h1_html = ""
    else:
        masthead_left = f'<div class="logo">{PULSE_MARK}</div>'
        h1_html = f'<h1>{esc(headline)}</h1>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(out.get("h1") or d['org'])} | {esc(diagram.title)}</title>
<style>
  /* Fallback tokens (Forge, light) for a page saved as a standalone file. Served by the app, theme.css
     (linked after this block) replaces them with the palette and light/dark mode the user chose. */
  :root{{--sapphire:{SAPPHIRE};--plum:{PLUM};--cyan:{CYAN};--tangerine:{TANGERINE};--magenta:{MAGENTA};
        --sapphire-tx:{SAPPHIRE};--plum-tx:{PLUM};--cyan-tx:{CYAN};--magenta-tx:{MAGENTA};--ir:{VIOLET};
        --gray:{GRAY};--line:#E4E4E8;--line-2:#cfd0d8;--ink:#1c1830;
        --page:#f5f5f7;--surface:#fff;--surface-2:#fafafc;--mist:#f1f1f5;--code-bg:rgba(0,0,0,.06);
        --hdr-a:{FADE};--hdr-b:{SAPPHIRE};}}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  html,body{{background:var(--page);}}
  body{{font-family:var(--font-ui,'Source Sans 3',Arial,sans-serif);color:var(--ink);line-height:1.4;
       -webkit-font-smoothing:antialiased;}}
  /* 13in, not 11. Every diagram is drawn on a 1180-unit canvas and `.diagram svg` is
     width:100%, so the page width IS the render scale: at 11in the SVGs came out at 0.81x
     their design size and every label with them. 13in puts them at 0.97x -- effectively 1:1
     -- and still fits a 1280px laptop without a horizontal scrollbar. Print is unaffected:
     the @media print block below sets width:auto. */
  .page{{width:13in;max-width:100%;margin:24px auto;background:var(--surface);padding:.45in .55in .4in;
        box-shadow:0 4px 24px rgba(0,0,0,.12);border-radius:var(--r-card,4px);}}
  .masthead{{display:flex;align-items:flex-end;justify-content:space-between;
            padding-bottom:12px;border-bottom:2px solid var(--sapphire);}}
  .logo svg{{height:20px;width:auto;display:block;}}
  .mark{{display:grid;place-items:center;width:30px;height:30px;border-radius:3px;background:var(--mist);
        border:1px solid var(--line-2);color:var(--cyan-tx);}}
  .mark svg{{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;}}
  .mh-left{{display:flex;align-items:center;gap:14px;}}
  .mh-title{{font-size:24px;font-weight:900;color:var(--ink);line-height:1;}}
  .mh-title .mh-open{{color:var(--sapphire-tx);}}
  .doc-tag{{font-size:12px;color:var(--gray);font-weight:500;text-align:right;line-height:1.5;}}
  .title-block{{margin-top:15px;display:flex;align-items:center;gap:15px;}}
  .lozenge{{display:inline-block;background:linear-gradient(135deg,var(--hdr-a),var(--hdr-b));
           color:#fff;font-size:13px;font-weight:700;
           padding:6px 14px;border-radius:3px;white-space:nowrap;}}
  h1{{font-size:33px;font-weight:900;color:var(--sapphire-tx);line-height:1;}}
  .subtitle{{margin-top:5px;font-size:12.5px;color:var(--gray);}}
  .kpi-strip{{display:flex;margin-top:14px;border-top:1px solid var(--line);
             border-bottom:1px solid var(--line);}}
  .kpi{{flex:1;padding:10px 4px;text-align:center;border-right:1px solid var(--line);}}
  .kpi:last-child{{border-right:0;}}
  .kpi b{{display:block;font-size:20px;font-weight:900;color:var(--sapphire-tx);line-height:1.1;}}
  .kpi span{{font-size:12px;color:var(--gray);font-weight:500;}}
  .kpi b.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:15px;}}
  .diagram{{margin:16px 0 4px;}}
  .diagram svg{{width:100%;height:auto;display:block;}}
  h2{{font-size:15px;font-weight:700;color:var(--sapphire-tx);
     margin:20px 0 8px;padding-bottom:5px;border-bottom:1px solid var(--line);}}
  table{{width:100%;border-collapse:collapse;font-size:11px;}}
  th{{text-align:left;font-size:11px;
     color:var(--gray);font-weight:700;padding:5px 8px;border-bottom:1px solid var(--line);}}
  td{{padding:4.5px 8px;border-bottom:1px solid var(--line);vertical-align:top;}}
  td.m{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10.5px;font-weight:600;color:var(--sapphire-tx);}}
  td.ip{{color:var(--plum-tx);}}
  td.svc{{color:var(--gray);font-size:10px;}}
  td.nw{{white-space:nowrap;}}
  .notes{{margin-top:16px;display:flex;gap:14px;flex-wrap:wrap;}}
  .note{{flex:1;min-width:210px;border-left:3px solid var(--cyan);padding:2px 0 2px 11px;
        font-size:11px;color:var(--gray);}}
  .note.warn{{border-left-color:var(--tangerine);}}
  .note b{{display:block;color:var(--sapphire-tx);font-size:11.5px;margin-bottom:2px;}}
  footer{{margin-top:18px;padding-top:9px;border-top:1px solid var(--line);
         font-size:9.5px;color:var(--gray);display:flex;justify-content:space-between;gap:12px;}}
  code{{background:var(--code-bg);padding:0 4px;border-radius:3px;}}
  pre{{background:var(--mist);color:var(--ink);padding:10px 12px;border-radius:5px;overflow:auto;}}
  pre code{{background:none;padding:0;}}
  @media print{{html,body{{background:#fff;}} .page{{margin:0;box-shadow:none;width:auto;}}}}
  {print_light_css()}
  /* the drawn colours follow the chosen palette and light/dark mode (see THEME_REMAP) */
  {theme_remap_css()}
</style>
<link rel="stylesheet" href="/ui/theme.css">
</head>
<body>
<div class="page">
  <div class="masthead">
    {masthead_left}
    <div class="doc-tag">{doc_tag}</div>
  </div>

  <div class="title-block">
    <span class="lozenge">{esc(diagram.title)}</span>
    <div>
      {h1_html}
      <div class="subtitle">{esc(subtitle)}</div>
    </div>
  </div>

  <div class="kpi-strip">{kpis}</div>

  <div class="diagram">{out["svg"]}</div>

  {sections}
  {notes_block}

  <footer>
    <span>{PRODUCT_TITLE} · synthetic demonstration data · no real hosts are contacted</span>
    <span>Generated from inventory.json · user {esc(d['nets']['user'])} · server {esc(d['nets']['server'])}</span>
  </footer>
</div>
</body>
</html>
"""


def generation_report(protocols, meta):
    """The post-generation report: packets by protocol for one capture that was actually built.

    Not a registered diagram — it describes a single run rather than the design of the
    environment, so it never belongs in the diagram dropdown. It reuses the same page chrome so
    it reads as part of the family.

    `protocols` is [(name, packets), ...] counted by `netgen.core.classify()` as the capture was
    written. Percentages are of total packets.
    """
    rows = [(n, c) for n, c in protocols if c]
    rows.sort(key=lambda r: -r[1])
    total = sum(c for _n, c in rows) or 1
    top = rows[0][0] if rows else "-"

    W, rowh = 1180, 30
    H = 96 + rowh * len(rows)
    bar_x, bar_w = 300, 620
    biggest = rows[0][1] if rows else 1
    P = []
    A = P.append
    A(_svg_open(W, H, "Packets by protocol"))
    A("</defs>")
    _panel_title(A, 14, 30, "PACKETS BY PROTOCOL",
                 "counted as the capture was written \u2014 %s packets in %d protocols"
                 % (format(total, ","), len(rows)))
    A('<line x1="14" y1="52" x2="%d" y2="52" stroke="#e4e4e8"/>' % (W - 14))
    y = 74
    for name, count in rows:
        pct = 100.0 * count / total
        A('<text x="14" y="%d" font-size="13" font-weight="700" fill="#1c1830">%s</text>'
          % (y, esc(name)))
        A('<rect x="%d" y="%d" width="%d" height="14" rx="3" fill="#f1f1f5"/>' % (bar_x, y - 11, bar_w))
        w = max(1.5, bar_w * count / biggest)
        A('<rect x="%d" y="%d" width="%.1f" height="14" rx="%.1f" fill="url(#scng)"/>'
          % (bar_x, y - 11, w, min(3.0, w / 2)))
        A('<text x="%d" y="%d" font-size="12.5" font-weight="700" fill="%s" text-anchor="end">%s</text>'
          % (bar_x + bar_w + 92, y, SAPPHIRE, format(count, ",")))
        A('<text x="%d" y="%d" font-size="12.5" font-weight="700" fill="%s" text-anchor="end">%.2f%%</text>'
          % (bar_x + bar_w + 160, y, PLUM, pct))
        y += rowh
    A("</svg>")

    trows = "".join(
        '<tr><td>%s</td><td class="m">%s</td><td class="m">%.2f%%</td></tr>'
        % (esc(n), format(c, ","), 100.0 * c / total) for n, c in rows)
    return {
        "svg": "".join(P),
        "kpis": [(format(total, ","), "Packets", "mono"),
                 ("%.1f GB" % (meta.get("bytes", 0) / 1e9), "Capture size", "mono"),
                 (str(len(rows)), "Protocols"),
                 (top, "Most packets"),
                 (str(meta.get("scale", "-")), "Scale", "mono"),
                 (str(meta.get("modules", "-")), "Scenarios")],
        "sections": [("Packets by protocol",
                      '<table><thead><tr><th>Protocol</th><th>Packets</th><th>% of capture</th>'
                      '</tr></thead><tbody>' + trows + '</tbody></table>')],
        "notes": [
            ("", "Counted at write time",
             "Every frame is classified as it is written to the capture, so these are exact "
             "counts of what was produced \u2014 not a sample, and not a second pass with an "
             "external dissector."),
            ("", "Protocol, not port",
             "Ports are the evidence used to name a protocol, not the unit reported: a reply "
             "from 443 and a request to 443 are both HTTPS. RTP and RTCP carry no port identity "
             "at all and are identified from their headers."),
            ("warn", "Tunnelled traffic counts as its outer protocol",
             "CAPWAP carries wireless client traffic inside UDP, so those frames count as "
             "CAPWAP rather than as whatever is within them."),
        ],
    }


# ---------------------------------------------------------------------------------------
# About page
# ---------------------------------------------------------------------------------------
# REVISIONS is the one hand-maintained table in this file, and it is narrative on purpose:
# "what changed and why it matters to someone using the tool" cannot be derived from the
# registry. Everything factual on the About page IS derived -- module counts, host counts,
# the networks, the diagram list -- so the numbers can never drift from the build even if
# this list falls behind. Add an entry whenever a phase lands; HANDOFF.md carries the
# engineering detail, this carries the user-facing sentence.
# The application's version. The single source of truth is the VERSION file next to this module
# (dev/VERSION; bundled into the packaged app), so the About page, the macOS bundle and the zip
# name can never disagree. _FALLBACK_VERSION is used only when that file is absent or unreadable;
# a test fails if it drifts from dev/VERSION. REVISIONS below is the narrative history and its
# letter-series labels (5d, ...) are history entries, not the current version.
_FALLBACK_VERSION = "5.5.0"


def _read_version(app_dir=None):
    try:
        with open(os.path.join(app_dir or APP_DIR, "VERSION"), encoding="utf-8") as fh:
            v = fh.read().strip()
        return v or _FALLBACK_VERSION
    except (OSError, UnicodeDecodeError):
        return _FALLBACK_VERSION


VERSION = _read_version()
# What the About page shows: product line, code name, then the exact version, e.g.
# "v5 (Apophis) 5.2.0".
VERSION_DISPLAY = "%s (%s) %s" % (BRANDING_VERSION, CODENAME, VERSION)
SERIES_START = "5a"          # first revision of the current series; earlier ones are history

REVISIONS = [
    ("5d", "2026-10-05", "The first real capability module: healthy NFS observability",
     "The platform gains its first real, non-example capability module: nfs_observability. "
     "When selected it introduces seven new systems (six Windows workstations and one Linux "
     "NFS server, named and addressed to match the environment and renaming with a custom "
     "company) and paints a healthy, all-day NFSv3 file-sharing day: workstations upload and "
     "download real files (PNG, PDF, XLSX, CSV, ZIP) over TCP 2049, their names and contents "
     "on the wire so a sensor can identify, name and carve an actual file, alongside the "
     "ordinary working-day traffic those hosts produce (Windows logons, DNS, NTP, DHCP and "
     "SMB). It arrives under a new Standard category for healthy, no-anomaly observability. "
     "The module is the reference for building your own: it ships a README and a from-scratch "
     "tutorial, and demonstrates the pin-safe pattern for a module that adds its own systems: "
     "hosts are injected inside the scenario, after the baseline day is already built, so the "
     "no-module baseline is never altered and still pins at 609,554 packets. NFS traffic now "
     "classifies as NFS (tcp 2049) in the generation report. Under the hood the server now "
     "serializes every build behind a single lock, so a self-test or a second capture can no "
     "longer run concurrently with another build and skew its counts, because the engine's "
     "build state is process-global, and this removes a class of spurious failures. Diagram "
     "rendering is unaffected and stays responsive. This cut also hardens the local web "
     "interface against a browser-borne attacker: the server rejects cross-site (CSRF) and "
     "DNS-rebinding requests, validates the sensor address so an API push can only ever reach "
     "a bare host, restricts the reveal-folder action to a plain folder (never launching an "
     "application bundle), and flags third-party capability modules before they are loaded."),
    ("5c", "2026-10-05", "Capability modules deepen: encoders, self-tests, persistence and a regression gate",
     "The module framework now reaches all the way down to protocol encoders: the 145 wire "
     "encoders resolve through a swappable registry, so a module can change how a protocol is "
     "built on the wire at run time and the original is restored on unload. Scenario "
     "categories (SEC / PERF / CRYP) are data-driven from one table rather than hardcoded in "
     "the interface. Every capability carries a self-test, and the server gains a one-click "
     "\"Test all loaded\" regression check, with the 609,554 baseline pin itself shipped as a "
     "validation module. Onboarding improves: reference modules are badged as examples, the "
     "modules loaded for a build are shown live before Generate, and an authoring guide plus "
     "an in-panel explainer (with a trust note) describe what modules do and how to write "
     "one. The first real, non-example module ships: capture_summary, an exporter that writes "
     "a machine-readable <capture>-summary.json sidecar for automation to ingest. A module "
     "can be marked to auto-load on startup and that choice persists across restarts. The "
     "macOS app now bundles and discovers its capability modules, and a run-time engine scan "
     "that failed inside the frozen bundle is fixed. A standard-library self-test harness "
     "(dev/selftest.py) and GitHub Actions CI guard the pin, build determinism and the whole "
     "load / unload / self-test lifecycle on every change. The no-module baseline is "
     "unchanged and still pins at 609,554 packets."),
    ("5b", "2026-10-05", "A modular capability framework: load, unload and test at run time",
     "The generator gains a capability kernel (netgen/platform). Capability modules live "
     "under /modules, are discovered from their manifests, and can be loaded, unloaded and "
     "self-tested in the running server with no restart. Reference modules ship for all three "
     "kinds (a diagram, an incident scenario and a sensor provider), each appearing live in "
     "the UI (the diagram picker, the scenario grid, the provider list) when loaded. The "
     "existing registries are surfaced under the kernel, and the orchestration core is "
     "decoupled: the reseed and identity fan-out is discovered rather than hardcoded, "
     "post-build exports (certs, threat collection, generation report) are a registry, and "
     "the business day is assembled from ordered baseline contributors, so a new engine "
     "module, export format or baseline service plugs in without editing core. The no-module "
     "baseline is unchanged and still pins at 609,554 packets."),
    ("5a", "2026-10-04", "OpenGenerator v5 (Apophis): the emulated company becomes an input",
     "A Company name and Industry now drive the whole environment: the AD/DNS domain, "
     "Kerberos realm, host prefix, Root CA, organisation and web-app namespace all derive "
     "from a single Identity, so one (name, industry) pair produces one internally consistent "
     "capture. The defaults reproduce the historical Example Logistics environment "
     "byte-for-byte (the no-module baseline still pins at 609,554 packets), while a custom "
     "company re-brands every host, domain, certificate and indicator on the wire and in the "
     "diagrams. Exported filenames follow the company too: the capture, TLS key log, "
     "generation report, threat collection and Root CA cert are all named after it. The GUI "
     "and About page were restyled for the v5 line."),
    ("4h", "2026-10-03", "A second firewall between the enterprise and the OT zone",
     "The IT/OT boundary becomes two L3 devices instead of one. A second firewall, EXL-OTFW1, "
     "is added between the IDMZ and the industrial zone, so the OT cell/area and "
     "site-operations subnets sit behind it rather than behind one more leg of the enterprise "
     "firewall. EXL-FW1 (enterprise) sits above the IDMZ and EXL-OTFW1 (industrial) below it, "
     "the classic dual-firewall sandwich, and enterprise-to-cell traffic now crosses both: a "
     "flow that reaches a PLC from the IT network returns at a TTL two lower than a "
     "single-firewall path would give, which is exactly how the cross-Purdue zone-violation "
     "scenario now proves on the wire that it bypassed the IDMZ broker. EXL-OTFW1 owns the "
     "cell/area and site-operations gateways on its own vendor OUI and carries a management "
     "plane (SNMP, syslog, NTP, SSH) so the platform classifies it as network infrastructure. "
     "The OT baseline re-pins with it: the OT-on business day moves from 657,377 to 645,026 "
     "packets at the regression scale, while the OT-off day stays byte-identical at 607,886. "
     "The single-firewall path is untouched, so a capture without the OT zone is unchanged. "
     "The scenario-selector buttons (Select all / none, and the per-category filters) also "
     "move onto one horizontal line beneath the scenario count."),
    ("4g", "2026-10-02", "Every device generates enough traffic to be classified as its real type",
     "The baseline is re-examined against how the platform actually classifies devices. "
     "Replaying a generated capture to the sensor showed several servers landing on the wrong "
     "role (the database server read as a file server, the primary file server and the "
     "line-of-business web server read as plain PCs, the call manager as a gateway) because "
     "the classifier keys on the dominant protocol a device SERVES to many clients, and those "
     "signals were too thin. A new last pass in the day, classification_enrichment, gives "
     "each server that signal: the file server serves SMB to a broad set of workstations, the "
     "LOB web server serves HTTP to many clients (which also keeps the database server busy "
     "answering TDS), the printers receive print jobs and a printer-MIB SNMP walk, and the "
     "phones register densely so the PBX reads as telephony. The pinned business-day baseline "
     "moves with it, from 574,056 to 607,886 packets (219.8 MB) at the regression scale, and "
     "every current reference to the pin is updated to match. The traffic signatures are "
     "tshark-verified; the resulting platform roles are confirmed by replaying to the sensor. "
     "Also folded in from late 4f: the post-quantum readiness scenario, the pcap-import "
     "profiler and the CUSTOM rebuild path with 25-protocol coverage including the new SMTP, "
     "NFS and RADIUS builders. Seven NPM scenarios also join the library (NPM 13 to 20): an "
     "HTTP 5xx surge, DHCP scope exhaustion, database connection-pool exhaustion, a "
     "RADIUS/NAC auth-failure storm, NFS/NAS storage latency, an SMTP mail-flow backup, and "
     "an MTU/PMTUD blackhole, chosen to show what network observability catches that "
     "endpoints miss."),
    ("4f", "2026-10-02", "More intrusions, a living-off-the-land stream, and a firewall update",
     "The scenario library grows in three ways. First, a second, unrelated intrusion, the "
     "NeedyMantis implant (Microsoft, 2026-09-28). It is a separate compromise from the "
     "existing chains: a different workstation, no lateral path to the other, its own set of "
     "servers, and every observable the implant has without decoding its payload (the DNS and "
     "TLS name of its command channel, a hard-coded antique user agent on one URL, a base64 "
     "system-info cookie, an HTTP-to-WebSocket upgrade, Impacket SMB writes). Its command "
     "domain is a real, published indicator a sensor matches. Second, eight new security "
     "scenarios that are each selectable alone but, chosen together, read as one multi-stage "
     "nation-state intrusion pre-positioning on the network: edge-device exploitation, an "
     "exposed-RDP brute, Salt Typhoon SNMP mapping, a web shell, PetitPotam→AD CS coercion, "
     "Volt Typhoon valid-account living-off-the-land, fast-flux C2, and the infostealer that "
     "sold the access, spread across a small roster of compromised hosts so no one machine "
     "does everything. Third, a firewall content update (NPM): the jump host stages a Palo "
     "Alto update early and the admin commits it mid-morning; because the firewall also "
     "terminates the VPN, the commit's reboot drops the whole remote workforce for a minute "
     "or two, a sharp, easy-to-see drop in the external requests answered by the "
     "authentication, database and web servers, then a reconnect storm. When it runs "
     "alongside the edge-exploit, the update is visibly what stops that intrusion. The "
     "normal-day baseline is unchanged."),
    ("4e", "2026-09-29", "The scenario list moves under what gets built",
     "The scenario chooser sat in a card of its own below the settings; it belongs with the "
     "summary of what the capture will contain, so it now stacks directly under it. Settings "
     "keeps the width its three columns of fields actually need and the scenario list takes "
     "the rest, which leaves fewer scenario names wrapping onto a second line. No change to "
     "the generator, the capture or anything the app produces."),
    ("4d", "2026-09-25", "An OT / ICS subnet, and a layout built for a laptop",
     "The capture can now include an industrial zone: three further class C networks holding "
     "Purdue levels 0 to 3.5: SCADA and HMI panels, twelve PLCs, six RTUs, safety "
     "controllers, a BACnet building-management system and IoT, with site operations and an "
     "industrial DMZ above them. It speaks Modbus, BACnet/IP and DNP3, which are the three OT "
     "protocols the platform actually collects metrics for; each can be switched off "
     "independently, and the level 1 poll interval is adjustable because it is much the "
     "largest influence on how big the capture becomes. The whole thing is optional and off "
     "by default. With it off the capture is identical to one built before the feature "
     "existed. One rule shapes the design: in the baseline exactly one host in the enterprise "
     "opens a session into the industrial zone, a jump host in the server network, so "
     "anything else reaching in is unusual by construction. The window itself is wider: the "
     "app now uses a laptop screen properly rather than a narrow column, the scenario list "
     "scrolls inside its own panel instead of pushing the page down several screens, and the "
     "diagrams render at the size they were drawn."),
    ("4c", "2026-09-18", "Load certificates and threat intelligence into a sensor",
     "The certificates and keys exported alongside a capture can now be pushed straight to a "
     "sensor over its REST API, so the platform can decrypt the replayed HTTPS without "
     "pasting dozens of keys by hand. The sensor address and API key are entered in the app; "
     "the key is held in memory only and forgotten when the page closes. Note that the push "
     "replaces every decryption key already on the sensor. It asks first, and is meant for a "
     "laboratory sensor. The two consequential buttons now stay out of reach until they are "
     "safe to press: pushing certificates and starting a replay each need an acknowledgement "
     "first, and Generate capture waits until the networks, scale and output folder all have "
     "a value. Hovering the ? beside an option explains what it does. The threat collection "
     "exported with a capture can be pushed the same way, to a sensor or to a console, so the "
     "replayed traffic raises threat-intelligence matches without anyone uploading a STIX "
     "file by hand. That push replaces only the collection this tool owns, named "
     "ExampleThreatCollection (built-in collections and anything else you have uploaded are "
     "left alone), and it asks the appliance to raise detections on an indicator match, "
     "saying in its log when that setting has to be made by hand instead."),
    ("4b", "2026-09-17", "FTP file transfers are catalogued correctly",
     "Files moved over FTP now close their data connection from the sending end, which is how "
     "FTP signals end-of-file, and the server's \"opening data connection\" reply now arrives "
     "before the file data rather than racing it. Without both, an analysis platform reads "
     "the transfer as aborted and does not record the file: the capture looked correct in a "
     "packet analyser while no files appeared in the platform."),
    ("4a", "2026-09-17", "Closing the window closes the application",
     "Closing the browser tab now stops the application and releases its port, instead of "
     "leaving a server running in the background. Presence is tracked by a connection the "
     "page holds open rather than a timed check-in, because the browser throttles a timer "
     "once its tab is in the background; an earlier version of the timer shut itself down "
     "after about a minute with the window still open. The application will not quit while a "
     "capture or a replay is in progress, closing one of several tabs leaves the others "
     "working, and quitting the application outright stops a running capture and a running "
     "replay with it."),
    ("3z", "2026-09-17", "Accurate capture totals, and re-measured size guidance",
     "The packet count and size shown when a run finishes are now the capture's true totals "
     "rather than the last progress update, which always rounded down. The scale field's size "
     "estimates have been re-measured against real builds: a full business day is about 8.2 "
     "GB and 10.1 million packets, not the 6.3 GB quoted before the cloud and operating "
     "system update traffic was added."),
    ("3y", "2026-09-17", "One NetBIOS domain name on the wire",
     "Domain controller responses advertised the NetBIOS domain as EXAMPLE while Windows "
     "sign-ins and directory binds used CORP, so an identity view of the capture saw two "
     "names for one domain. Everything now reads CORP, which is what Windows derives from "
     "corp.example.local."),
    ("3x", "2026-09-17", "Renamed, recoloured, and this About page",
     "The application is now OpenGenerator. Crypto-posture scenarios are tangerine instead of "
     "grey, so all three categories are colour-coded in the selector and in their diagrams; "
     "the network settings sit above scale and output folder; and this page describes what "
     "the tool produces and what has changed."),
    ("3w", "2026-09-17", "Replay survives a refresh, a restart and the app closing",
     "The replay panel now reappears after a page reload, a restarted application re-adopts a "
     "replay that is still running, and an optional Terminal monitor window can stop one with "
     "no password even if the application hangs."),
    ("3v", "2026-09-17", "Certificate import guidance",
     "The server certificate export writes a certificate and private key per server, ready to "
     "load onto a sensor for decryption."),
    ("3u", "2026-09-16", "Generation report",
     "Every capture now comes with an exact count of packets by protocol, viewable in the "
     "browser and written beside the capture as CSV."),
    ("3t", "2026-09-16", "Baseline protocol-mix diagram",
     "A third top-level diagram showing the measured protocol mix of the normal day, in "
     "packets and in bytes, with no scenarios added."),
    ("3s", "2026-09-16", "Endpoint diversity, cloud egress, OS patching",
     "Workstations vary by TLS fingerprint and TCP MSS instead of looking identical, reach "
     "consumer cloud and generative-AI services, and browse pages that fan out to several "
     "hosts. Servers patch to vendor update services and do nothing else off-network."),
    ("3r", "2026-09-16", "Reconstructable file transfers",
     "Files carried over FTP are real PNG, PDF, tar.gz and text bytes, so they can be carved "
     "out of the capture and opened, and they populate the platform's Files view."),
    ("3q", "2026-09-16", "Anonymous FTP on a smart board",
     "A hardening scenario: a device that should not run an FTP service does, reachable from "
     "inside and from the internet."),
    ("3p", "2026-09-16", "A real directory in the normal day",
     "Successful and failed logons, expired and disabled accounts, lockouts, service accounts "
     "and tiered privileged accounts, so an identity view of the capture is populated."),
    ("3n", "2026-09-16", "Stoppable generation",
     "A running build can be cancelled; the partial capture is discarded rather than left to "
     "be replayed by accident later."),
    ("3m", "2026-09-16", "Dependency indicators",
     "The Settings card reports everything the generator needs, and the server survives a "
     "broken dependency well enough to explain it."),
    ("3k", "2026-09-15", "Pinned baseline traffic in the selector",
     "Traffic that is always present, such as the shadow MCP server, is shown but not "
     "selectable, so the scenario list matches what is actually built."),
    ("3e-3j", "2026-09-15", "Diagram framework and scenario diagrams",
     "Every scenario has a generated diagram with display filters that are verified against a "
     "real capture before shipping."),
    ("3d", "2026-09-15", "Configurable networks",
     "The two internal /24s are settings. Every host keeps its last octet, so counts, roles "
     "and traffic patterns are unchanged and only the network part moves."),
    ("3c", "2026-09-15", "Scenario selection",
     "Choose which incidents to include. The exported threat collection follows the selection."),
    ("3b", "2026-09-15", "Replay onto a sensor",
     "The application drives tcpreplay itself, with played-versus-remaining progress."),
    ("3a", "2026-09-15", "The GUI",
     "A local web interface around the generator, replacing the command line."),
]


def about_page(c, revisions=None):
    """What this tool is, what it produces, and what has changed.

    Counts come from the live registry and inventory rather than from prose, so the page
    cannot claim a scenario count the build does not have.
    """
    revs = revisions or REVISIONS
    # c.modules is a list of plain dicts from the registry; group by the display prefix
    # (NDR / NPM / CRP) rather than restating the counts here.
    by_cat = {}
    for m in c.modules:
        k = m.get("prefix", "?")
        if k in ("CUSTOM", "CAMPAIGN"):   # recipe/campaign-driven, not default scenarios
            continue
        by_cat[k] = by_cat.get(k, 0) + 1
    # category order the About copy reads in: CRP, NDR, NPM
    _order = {"CRP": 0, "NDR": 1, "NPM": 2}
    cats = ", ".join("%d %s" % (by_cat[k], k) for k in sorted(by_cat, key=lambda x: _order.get(x, 9))) or "none"
    n_mod = sum(by_cat.values())
    try:
        from netgen import incidents as _INC
        n_ot_mod = sum(1 for m in c.modules if m.get("name") in getattr(_INC, "OT_SCENARIOS", set())
                       and m.get("prefix") not in ("CUSTOM", "CAMPAIGN"))
    except Exception:                                  # noqa: BLE001
        n_ot_mod = 0
    n_hosts = c.data["n_total"]
    # OT counts read straight from the inventory (the About context is built OT-off, so c.data holds
    # only the corporate assets). Split on the `purdue` field, exactly as deps.py does, and count
    # only the NEW subnets the OT zone introduces (its jump host sits on the existing server net).
    try:
        import json as _json
        _inv = _json.load(open(os.path.join(APP_DIR, "inventory.json")))["hosts"]
        _ot = [h for h in _inv if h.get("ip") and h.get("purdue")]
        n_ot = len(_ot)
        n_otsubs = len({h.get("subnet") for h in _ot
                        if not str(h.get("ip", "")).startswith(("10.10.10.", "10.10.20."))})
    except Exception:                                  # noqa: BLE001
        n_ot, n_otsubs = 94, 3
    ot_note = (", of which %d appear only when the optional OT environment is on, so the "
               "scenario list shows %d by default" % (n_ot_mod, n_mod - n_ot_mod)) if n_ot_mod else ""
    diagrams = catalog()                               # top-level only
    n_diag = len(catalog(include_scenarios=True))      # + one per scenario

    W, H = 1180, 410
    P = []
    A = P.append
    A(_svg_open(W, H, "About"))
    A("</defs>")
    # Enlarged deliberately: this is the first thing read on the page, and at the shared
    # 11.5/9.5 it was the smallest text on it. Everything below shifts to match.
    _panel_title(A, 14, 34, "What this tool does",
                 "one capture, one business day, and the scenarios you choose; capability modules "
                 "can be loaded and unloaded at run time",
                 size=16, sub_size=12.5, gap=19)
    A('<line x1="14" y1="64" x2="%d" y2="64" stroke="#e4e4e8"/>' % (W - 14))

    steps = [
        ("Model", "A fabricated company you name and classify by industry: the two set the AD/DNS "
                  "domain, host prefix, Root CA and org. By default a logistics and manufacturing "
                  "firm of %d addressed assets across a user and a server network, with their roles, "
                  "OS and services. An optional OT environment adds %d subnets and %d machines."
                  % (n_hosts, n_otsubs, n_ot)),
        ("Generate", "One run writes one time-ordered capture containing a full 16 hour synthetic "
                     "business day plus the incidents you selected. %d are available "
                     "(%s)%s, along with any custom scenarios you have a recipe for." % (n_mod, cats, ot_note)),
        ("Replay", "tcpreplay plays the capture onto a monitoring interface, or over a closed "
                   "network watched by a sensor, so the sensor sees it as live traffic. A "
                   "sensor's offline capture mode will populate devices, threat intelligence, "
                   "IDS hits and records, but it cannot evaluate time based measures in full."),
        ("Demonstrate", "Detections, performance findings, threat intelligence, and posture issues "
                        "appear in the platform, backed by packets and records. Use it as a "
                        "stand alone demonstration or as part of a scripted agentic laboratory "
                        "exercise built on the generated scenarios."),
    ]
    x, bw, gap = 14, (W - 28 - 3 * 18) / 4.0, 18
    for i, (head, body) in enumerate(steps):
        bx = x + i * (bw + gap)
        A('<rect x="%.1f" y="82" width="%.1f" height="208" rx="10" fill="#fbfbfd" '
          'stroke="#e4e4e8"/>' % (bx, bw))
        A('<rect x="%.1f" y="82" width="%.1f" height="4" rx="2" fill="url(#scng)"/>' % (bx, bw))
        A('<text x="%.1f" y="112" font-size="14.5" font-weight="900" fill="%s">%d. %s</text>'
          % (bx + 14, SAPPHIRE, i + 1, esc(head)))
        yy = 134
        # Wider wrap (was 33) so the longest card body — Replay — fits the 208px box instead
        # of overrunning the bottom. 38ch still clears the card's right edge at 12.5px.
        for line in _wrap(body, 38):
            A('<text x="%.1f" y="%d" font-size="12.5" fill="#4a4760">%s</text>'
              % (bx + 14, yy, esc(line)))
            yy += 16
    # An explicit, unmissable statement of scope. Tangerine banner rather than body text,
    # because "this is not for production" is the one sentence on the page that must not be
    # skimmed past.
    A('<rect x="14" y="308" width="%d" height="88" rx="10" fill="#fff6f1" '
      'stroke="%s" stroke-width="1.5"/>' % (W - 28, TANGERINE))
    # Centered both ways within the 88px banner (box y 308..396, so center y = 352).
    _lab_body = _wrap(
            "This application generates synthetic traffic for demonstrations, laboratory "
            "exercises and product development. It is not a production system and must not be "
            "used on one. Every packet is fabricated and every indicator is simulated: "
            "replaying a capture onto a production sensor will raise genuine-looking "
            "detections against hosts that do not exist.", 140)
    _cx = W / 2.0
    _title_step, _body_step = 22, 17          # title->first body, and body line pitch
    _span = _title_step + (len(_lab_body) - 1) * _body_step
    _ty = 362 - (_span + 13) / 2.0            # place the baseline stack so the block centers
    A('<text x="%.1f" y="%.1f" text-anchor="middle" font-size="14" font-weight="900" '
      'fill="#b23f0f">Laboratory and development tool: not for production use</text>'
      % (_cx, _ty))
    for i, line in enumerate(_lab_body):
        A('<text x="%.1f" y="%.1f" text-anchor="middle" font-size="12.5" fill="#4a4760">%s</text>'
          % (_cx, _ty + _title_step + i * _body_step, esc(line)))
    A("</svg>")

    outputs = [
        ("The capture", "<code>&lt;company&gt;-all-in-one.pcap</code>",
         "One time-ordered pcap: the whole business day plus the selected scenarios. There is "
         "no per-scenario file and no merge step. Named after the company "
         "(example-all-in-one.pcap by default)."),
        ("TLS key log", "<code>&lt;name&gt;-tls-keys.log</code>",
         "Session keys for the HTTPS in the capture, so it can be decrypted in Wireshark or by "
         "a sensor without the server keys."),
        ("Server certificates", "<code>certs/</code>",
         "A real certificate and RSA private key per simulated server, plus the issuing CA, in "
         "PEM form. Load a pair onto a sensor to decrypt the capture there."),
        ("Threat collection", "<code>&lt;prefix&gt;.stix.json</code> + <code>.csv</code>",
         "The indicators the build actually emitted, filtered to the scenarios you selected, "
         "ready to import as threat intelligence."),
        ("Generation report", "<code>&lt;name&gt;-generation-report.csv</code>",
         "Exact packet counts by protocol for the capture just produced, also viewable in the "
         "browser."),
        ("Diagrams", "in-browser",
         "%s, and a diagram for every scenario, %d in all. They are generated from the same "
         "inventory and registry as the capture, so they cannot describe something the "
         "capture does not contain."
         % (", ".join(d["title"] for d in diagrams), n_diag)),
    ]
    orows = "".join(
        "<tr><td><b>%s</b></td><td class=\"m\">%s</td><td>%s</td></tr>" % (esc(h), f, esc(b))
        for h, f, b in outputs)

    # A divider where the current series begins, so the table reads as "this version's
    # history, then what came before" rather than one undifferentiated list.
    parts = []
    for ph, date, t, d in revs:
        parts.append(
            "<tr><td class=\"m\">%s</td><td class=\"m\">%s</td><td><b>%s</b><br><span "
            "style=\"color:#4a4760\">%s</span></td></tr>" % (esc(ph), esc(date), esc(t), esc(d)))
    names = [r[0] for r in revs]
    if SERIES_START in names:
        after = names.index(SERIES_START) + 1
        if after < len(parts):
            parts.insert(after,
                         "<tr><td colspan=\"3\" style=\"padding-top:14px;font-size:11px;"
                         "color:%s;"
                         "font-weight:700\">Earlier series: before %s</td></tr>"
                         % (GRAY, esc(SERIES_START)))
    rrows = "".join(parts)

    return {
        "doc_tag": "About this tool<br>Synthetic traffic generator",
        "h1": PRODUCT_TITLE,
        # Title lives in the masthead (beside the logo) rather than the title-block, as a
        # two-tone wordmark: "Open" in the accent, the rest in ink. render_page lays it out.
        "masthead_title": '<span class="mh-open">Open</span>' + esc(PRODUCT_TITLE[len("Open"):]),
        "subtitle": "RFC 791 compliant synthetic network traffic for network sensor testing and demonstration",
        "svg": "".join(P),
        "kpis": [(str(n_mod), "Scenarios"),
                 (str(n_hosts), "Assets"),
                 (str(n_diag), "Diagrams"),
                 (VERSION_DISPLAY, "Version", "mono"),
                 (revs[0][1] if revs else "-", "Updated", "mono")],
        "sections": [
            ("What you get from a run",
             "<table><thead><tr><th>Output</th><th>Where</th><th>What it is</th></tr></thead>"
             "<tbody>" + orows + "</tbody></table>"),
                ("Engineering audit (eng-audit)", '<p>For an engineer taking this over: how the captures are built, what runs underneath, and where the code lives.</p><p><b>One run, one capture.</b> <code>opengenerator_build.build()</code> reseeds the module RNGs, pins the capture day, builds the host model from <code>inventory.json</code>, then runs an event scheduler in-process. It never shells out to a second Python; the GUI calls <code>build()</code> on a worker thread. The result is a single time-ordered <code>example-all-in-one.pcap</code>, with no per-scenario files and no merge step.</p><p><b>Where the packets come from.</b> Each scenario is a builder function in <code>netgen/incidents.py</code>. The scheduler calls it inside its time window, and the builder drives flow helpers in <code>netgen/flows.py</code>. Those assemble frames through <code>netgen/core.py</code> (Ethernet, IP, TCP and UDP, plus the <code>TcpSession</code> state machine that handles sequencing, ACKs, segmentation and loss) and protocol encoders in <code>netgen/protocols.py</code> (DNS, SMB, LDAP, Kerberos, TDS, HTTP, SNMP, RTP, MCP, Modbus, BACnet, DNP3). <code>netgen/model.py</code> holds the business day and the two class C networks; <code>netgen/accounts.py</code> holds the directory. <code>PcapWriter</code> in <code>core.py</code> writes each frame in timestamp order and names its protocol as it writes, so the generation report is exact and needs no second pass over the file.</p><p><b>TLS.</b> <code>netgen/tls.py</code> builds real handshakes. The default is TLS 1.2 with RSA key exchange (<code>TLS_RSA_WITH_AES_128_GCM_SHA256</code>) and a CLIENT_RANDOM key log, so a sensor can decrypt the HTTPS from the exported certificate and key. The post-quantum posture scenario adds a cleartext TLS 1.3 path that carries the key-exchange groups and an opaque encrypted tail, with no key schedule, so it reports posture without touching the decryption path.</p><p><b>Determinism and the baseline.</b> Every <code>netgen</code> module owns a seeded <code>random.Random</code>, and <code>reseed_all()</code> runs before any scheduling, so the same arguments produce the same capture. <code>os.urandom</code> is used only for key material, which is why certificates differ between builds while packet counts and ordering do not. The no-scenario baseline is pinned: <code>--scale 0.004 --no-modules</code> produces 466,343 packets, and every engine change is measured against that number.</p><p><b>Adding a scenario.</b> Write <code>def name(ctx, eng, tag, win)</code>, schedule its events with <code>sched_factory</code> (which passes the timestamp back as a trailing <code>ts</code> keyword), and register it with <code>_reg(name, category, prefix, title, window, fn, note)</code>. Selection happens when the schedule is built, so an unselected module emits nothing and the capture never contains its traffic. The business day is always built. A diagram is one <code>@register(..., scenario=name)</code> function in <code>make_diagram.py</code>; its per-scenario Visualize button turns on by itself.</p><p><b>Tools underneath.</b></p><table><thead><tr><th>Purpose</th><th>Tool</th><th>Notes</th></tr></thead><tbody><tr><td>Engine runtime</td><td class="m">Python 3.11+</td><td>Standard library only, with one exception below.</td></tr><tr><td>Cryptography</td><td class="m">cryptography (PyPI)</td><td>Real RSA certificates and AES-GCM TLS. The only third-party dependency, and the main packaging risk.</td></tr><tr><td>Web UI</td><td class="m">http.server</td><td>Stdlib HTTP server bound to 127.0.0.1. No web framework, no JavaScript build step.</td></tr><tr><td>Validation</td><td class="m">tshark / Wireshark</td><td>Developer tool for checking captures. The application never calls it at runtime.</td></tr><tr><td>Replay</td><td class="m">tcpreplay</td><td>External, from Homebrew or MacPorts. Never bundled. Needs root, which macOS prompts for; the app never handles a password.</td></tr><tr><td>Packaging</td><td class="m">PyInstaller</td><td>Builds the ad-hoc-signed <code>.app</code>. See <code>BUILD-macos.md</code>.</td></tr></tbody></table><p><b>Validating a capture.</b> The bar is a tshark-clean capture: zero bad checksums and no malformed packets except the known CLDAP dissector bug in tshark 4.2.2. The checks are:</p><pre style="background:#f4f4f7;border-radius:8px;padding:12px 14px;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;color:#3a2a55;white-space:pre-wrap;overflow-x:auto">tshark -r out.pcap -q -z expert,error\ntshark -r out.pcap -Y \'(ip.checksum.status=="Bad" or tcp.checksum.status=="Bad")\' | wc -l\ntshark -r out.pcap -o tls.keylog_file:out-tls-keys.log -Y \'http.request and tcp.port==443\' | wc -l</pre><p><b>Running it as a native app.</b> The packaged <code>.app</code> is self-contained. It carries its own Python 3.14, the <code>cryptography</code> wheel and OpenSSL (<code>libcrypto</code> and <code>libssl</code>), so nothing has to be installed to generate captures. What the Mac still has to provide:</p><table><thead><tr><th>Requirement</th><th>Detail</th></tr></thead><tbody><tr><td>Hardware</td><td>Apple Silicon (arm64). The bundle is arm64-only and does not run on Intel Macs; a universal build is blocked by the <code>cryptography</code> wheels (see <code>BUILD-macos.md</code>).</td></tr><tr><td>macOS</td><td>Built and verified on macOS 15 (arm64). The bundle sets no <code>LSMinimumSystemVersion</code>, so there is no hard gate; the practical floor is any macOS that runs the bundled Python 3.14, which on Apple Silicon is macOS 11 or later. Set <code>LSMinimumSystemVersion</code> in the build if you want to enforce a floor.</td></tr><tr><td>First launch</td><td>The app is ad-hoc signed, not notarized, so macOS quarantines a downloaded copy. Open it the first time with right-click then Open, or clear the flag: <code>xattr -dr com.apple.quarantine "OpenGenerator.app"</code>.</td></tr><tr><td>Browser</td><td>The interface is a local page on 127.0.0.1 that opens in the default browser. Any current browser works.</td></tr><tr><td>Replay (optional)</td><td><code>tcpreplay</code>, from Homebrew or MacPorts, not bundled. Replay needs root, which macOS prompts for; the app handles no password. Without it, generation still works and the replay panel shows an install hint.</td></tr><tr><td>Validation (optional)</td><td>Wireshark / <code>tshark</code>, for checking captures by hand during development. Not needed to run the app.</td></tr></tbody></table><p>Running from source instead of the app needs Python 3.11 or later and <code>pip install cryptography</code>; <code>run.command</code> checks both and offers to install the dependency.</p><p><b>The code, and how to get it.</b> The source is the OpenGenerator repository: <code>dev/</code> holds the application, including <code>netgen/</code> (the engine), <code>modules/</code> (capability modules), <code>ui/</code> and <code>tests/</code>. To run without building, double-click <code>run.command</code>, or run <code>python3 server.py</code> from <code>dev/</code>, which imports the engine once at startup, so restart it after editing Python. <code>BUILD-macos.md</code> covers building the <code>.app</code>.</p>'),
        ("Revision history",
             "<table><thead><tr><th>Phase</th><th>Date</th><th>Change</th></tr></thead>"
             "<tbody>" + rrows + "</tbody></table>"),
        ],
        "notes": [
            ("", "Everything runs on this machine",
             "The interface is served on 127.0.0.1 and is never exposed off-box. Generating a "
             "capture needs no privileges. Replay needs root, which macOS prompts for with its "
             "own dialog. You never type a password into this application, and it never handles one."),
            ("warn", "Laboratory and development use only",
             "This is not a production tool and is not supported as one. Point it at "
             "laboratory sensors and isolated networks, and keep everything it produces off "
             "production monitoring paths. No part of it is built to the standards a "
             "production system would need."),
            ("warn", "Simulated indicators, real-looking addresses",
             "The threat collection holds indicators drawn from public reporting so a "
             "sensor matches them. Replaying a capture onto a production sensor will raise "
             "genuine-looking detections, so treat it as lab material."),
        ],
    }


def _relabel_identity(page, company=None, industry=None):
    """Re-brand a rendered diagram to the emulated company. The diagram is display-only, so the
    whole document is built in the template company's tokens (EXL- / corp.example.local /
    Example Logistics) and the identity-bearing strings are swapped here, in one place -- the
    host labels (whether drawn from a literal or from the inventory), the domain, the org and
    the Root CA subject. Only the distinctive multi-token forms are replaced, never the bare
    word "Example", so ordinary prose is left alone. A default (Example Logistics) render is
    returned unchanged."""
    if not (company or industry):
        return page
    sys.path.insert(0, APP_DIR)
    from netgen.identity import Identity, DEFAULT as T
    ident = Identity(company or None, industry or None)
    if ident.name == T.name and ident.industry == T.industry:
        return page
    for a, b in ((T.domain, ident.domain),              # corp.example.local
                 (T.namespace, ident.namespace),        # Example.Web.Data
                 (T.ca, ident.ca),                      # Example Demo Root CA
                 (T.collection, ident.collection),      # ExampleThreatCollection
                 (T.assistant, ident.assistant),        # ExampleAssistant
                 (T.org, ident.org),                    # Example Logistics
                 (T.prefix, ident.prefix),              # EXL-
                 (T.prefix.lower(), ident.prefix.lower())):  # exl-
        if a != b:
            page = page.replace(a, b)
    return page


def render(name="topology", inventory=None, user_net=None, server_net=None, modules=None,
           measured=None, ot_nets=None, company=None, industry=None):
    """Render one registered diagram to an HTML string. The single entry point for the CLI,
    the local server and anything else that wants a diagram. company/industry re-brand the
    diagram to the emulated company (default: Example Logistics)."""
    if name not in DIAGRAMS:
        raise ValueError(f"unknown diagram '{name}'. Known: {', '.join(sorted(DIAGRAMS))}")
    inventory = inventory or os.path.join(APP_DIR, "inventory.json")
    data = gather(inventory, user_net, server_net, ot_nets)
    mods, selected = load_modules(modules)
    c = DiagramContext(data, mods, selected)
    c.ot_nets = ot_nets
    # Live override for baseline-mix: stats written by the most recent baseline-only run. A
    # measurement of this machine's own output beats a table bundled at authoring time, but the
    # bundled one has to exist so the diagram works before anything has been generated.
    if measured:
        try:
            with open(measured) as f:
                raw = json.load(f)
            c.measured = {k: tuple(v) for k, v in raw.items() if isinstance(v, list) and v}
            c.measured_scale = raw.get("_scale") or "your last run"
        except Exception:                            # noqa: BLE001 — never fail a render on it
            pass
    return _relabel_identity(render_page(DIAGRAMS[name], c, load_logo()), company, industry)


def main():
    ap = argparse.ArgumentParser(description="Render a branded Example diagram as single-file HTML.")
    ap.add_argument("--diagram", default="topology",
                    help="which diagram to render (see --list); default: topology")
    ap.add_argument("--list", action="store_true", dest="do_list",
                    help="list the registered diagrams and exit")
    ap.add_argument("--inventory", default=os.path.join(APP_DIR, "inventory.json"))
    ap.add_argument("--user-net", default=None, help="override the user /24, e.g. 192.168.10.0/24")
    ap.add_argument("--server-net", default=None, help="override the server /24")
    ap.add_argument("--module", action="append", metavar="NAME", dest="modules",
                    help="limit scenario-aware diagrams to this module (repeatable)")
    ap.add_argument("--out", default=None,
                    help="output path (default: <diagram>-diagram.html beside this script)")
    ap.add_argument("--company", default=None, help="emulated company name (default: Example)")
    ap.add_argument("--industry", default=None, help="emulated industry (default: Logistics)")
    args = ap.parse_args()

    if args.do_list:
        for d in catalog():
            print(f"  {d['name']:<12} {d['title']:<22} {d['description']}")
        return

    sys.path.insert(0, APP_DIR)
    if args.user_net or args.server_net:
        from opengenerator_build import validate_nets
        try:
            args.user_net, args.server_net = validate_nets(args.user_net, args.server_net)
        except ValueError as e:
            ap.error(str(e))
    if args.modules:
        from opengenerator_build import select_modules
        try:
            args.modules = select_modules(args.modules)
        except ValueError as e:
            ap.error(str(e))

    try:
        page = render(args.diagram, args.inventory, args.user_net, args.server_net, args.modules,
                      company=args.company, industry=args.industry)
    except ValueError as e:
        ap.error(str(e))

    out = args.out or os.path.join(
        APP_DIR, "network-diagram.html" if args.diagram == "topology"
        else f"{args.diagram}-diagram.html")
    with open(out, "w") as f:
        f.write(page)
    d = gather(args.inventory, args.user_net, args.server_net)
    print(f"wrote {out}  [{args.diagram}]")
    print(f"  user   {d['nets']['user']}  ({d['n_user']} interfaces)")
    print(f"  server {d['nets']['server']}  ({d['n_server']} interfaces, {len(d['servers'])} servers)")


if __name__ == "__main__":
    main()


@register("baseline-ot", "OT / ICS zone",
          "Purdue levels 0-3.5: what runs, how often, and the one way in",
          order=160, scenario="baseline-ot")
def d_baseline_ot(c):
    """The industrial zone in detail.

    Every number is derived -- the cadences from netgen.model, the asset counts from the
    inventory, the ports from netgen.protocols. Nothing here is written down twice, so changing
    the poll interval in the UI redraws this page rather than leaving it lying.
    """
    sys.path.insert(0, APP_DIR)
    from netgen import model as _M
    from netgen import protocols as _P
    d = c.data
    lv = d.get("ot_levels") or {}
    # Asked for without the subnet enabled. Say so rather than drawing an empty plant or
    # raising: the diagram describes a zone that this capture does not contain.
    if not d["nets"].get("ot"):
        return {
            "svg": '<svg viewBox="0 0 1180 150" xmlns="http://www.w3.org/2000/svg" role="img" '
                   'aria-label="The OT subnet is not enabled for this capture">'
                   f'<rect x="12" y="12" width="1156" height="126" rx="12" fill="#fdf2f8" '
                   f'stroke="{MAGENTA}" stroke-width="2"/>'
                   f'<text x="590" y="62" text-anchor="middle" font-size="17" font-weight="900" '
                   f'fill="{MAGENTA}">The OT subnet is not enabled</text>'
                   f'<text x="590" y="90" text-anchor="middle" font-size="12.5" fill="{SAPPHIRE}">'
                   f'Tick &#8220;OT network&#8221; in Settings and open this diagram again.</text>'
                   f'<text x="590" y="112" text-anchor="middle" font-size="11" fill="{GRAY}">'
                   f'Without it no OT asset is built at all, so there is nothing here to draw.'
                   f'</text></svg>',
            "h1": "OT / ICS zone",
            "subtitle": "not enabled for this capture",
            "kpis": [("off", "OT subnet"), ("0", "OT assets")],
            "notes": [("", "Nothing is missing",
                       "The industrial zone is opt-in. With it off the capture is byte-identical "
                       "to one built before the feature existed, which is why this page has "
                       "nothing to show rather than showing an empty plant.")],
        }
    n = lambda *keys: sum(len(lv.get(k, [])) for k in keys)
    POLL, DNP, COV = _M.OT_POLL_S, _M.OT_DNP3_POLL_S, _M.OT_BACNET_COV_S
    n_plc, n_rtu = len(lv.get("1", [])), 0
    for h in lv.get("1", []):
        if h["hostname"].startswith("EXL-RTU"):
            n_rtu += 1
    n_plc -= n_rtu

    # ---- sixty seconds of the subnet, one tick per transaction -------------------------
    W, LBL, RGT = 1180, 210, 1120
    lanes = [(f"Modbus · {n_plc} PLCs", POLL, MAGENTA, f"{POLL:g} s — the level 1 poll"),
             (f"DNP3 · {n_rtu} RTUs", DNP, PLUM, f"{DNP:g} s — RTU integrity poll"),
             (f"BACnet COV · {n('bms')} devices", COV, CYAN, f"{COV:g} s — change of value"),
             ("LLDP / SNMP · infrastructure", 30.0, GRAY, "30 s — neighbour advert"),
             ("NTP · all zones", 64.0, GRAY, "64 s — barely inside the window")]
    TOP, ROWH = 56, 30
    H = TOP + len(lanes) * ROWH + 132
    S_ = []
    A = S_.append
    A(f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" role="img" '
      f'aria-label="Sixty seconds of the OT subnet, one tick per transaction, five protocol lanes">')
    A(f'<text x="12" y="22" font-size="13" font-weight="900" fill="{SAPPHIRE}">'
      f'Sixty seconds of the subnet</text>')
    A(f'<text x="12" y="38" font-size="10.5" fill="{GRAY}">one tick = one transaction · '
      f'the process does not keep office hours, so this repeats for the whole 16 h window</text>')
    y = TOP
    for name, per, col, note in lanes:
        A(f'<text x="12" y="{y + 12}" font-size="11" font-weight="700" fill="{SAPPHIRE}">{esc(name)}</text>')
        A(f'<line x1="{LBL}" y1="{y + 8}" x2="{RGT}" y2="{y + 8}" stroke="#e8e8ee" stroke-width="1"/>')
        t = 0.0
        while t <= 60.0001:
            x = LBL + (RGT - LBL) * t / 60.0
            A(f'<rect x="{x - 1.4:.1f}" y="{y}" width="2.8" height="16" rx="1.3" fill="{col}"/>')
            t += per
        A(f'<text x="{RGT + 8}" y="{y + 13}" font-size="9" fill="{GRAY}">{esc(note)}</text>')
        y += ROWH
    A(f'<line x1="{LBL}" y1="{y - 6}" x2="{RGT}" y2="{y - 6}" stroke="{GRAY}" stroke-width="1"/>')
    for sec in range(0, 61, 10):
        x = LBL + (RGT - LBL) * sec / 60.0
        A(f'<line x1="{x:.1f}" y1="{y - 6}" x2="{x:.1f}" y2="{y - 1}" stroke="{GRAY}"/>')
        A(f'<text x="{x:.1f}" y="{y + 10}" text-anchor="middle" font-size="9.5" fill="{GRAY}">{sec}s</text>')
    yb = y + 26
    polls_day = int((_M.T_END - _M.T_START) / POLL)
    A(f'<rect x="12" y="{yb}" width="{W - 24}" height="76" rx="10" fill="#fdf2f8" '
      f'stroke="{MAGENTA}" stroke-width="1.5"/>')
    A(f'<text x="30" y="{yb + 24}" font-size="12.5" font-weight="900" fill="{MAGENTA}">'
      f'Why the level 1 lane is the whole budget</text>')
    A(f'<text x="30" y="{yb + 44}" font-size="11" fill="{SAPPHIRE}">'
      f'{n_plc} PLCs × {polls_day:,} polls × 3 frames — above ~500 ms the client’s '
      f'200 ms delayed-ACK timer fires before the next request, so the ACK is its own frame.</text>')
    A(f'<text x="30" y="{yb + 62}" font-size="11" fill="{SAPPHIRE}">'
      f'Measured at scale 1.0: Modbus is 1,566,492 packets in 100 MB — '
      f'<tspan font-weight="900">64 bytes per packet</tspan>, against 763 for the enterprise.</text>')
    A('</svg>')

    frows = "".join(
        f'<tr><td>{esc(w)}</td><td class="m">{esc(f)}</td></tr>' for w, f in [
            ("All process traffic", "modbus || dnp3 || bacapp"),
            ("Modbus reads", "modbus.func_code == 3 || modbus.func_code == 4"),
            ("Modbus writes — the ones that change the plant",
             "modbus.func_code == 6 || modbus.func_code == 16"),
            ("Modbus exceptions", "modbus.exception_code"),
            ("DNP3 unsolicited reports", "dnp3.al.func == 130"),
            ("BACnet change-of-value", "bacapp.unconfirmed_service == 2"),
            ("BACnet errors, rejects and aborts", "bacapp.type >= 5"),
            ("The one way in", f'ip.src == {esc(_jump_ip(d))} && ip.dst == {esc(d["nets"]["ot"])}'),
            ("Anything else crossing inbound — should be empty",
             f'tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == {esc(d["nets"]["user"])} '
             f'&& ip.dst == {esc(d["nets"]["ot"])}'),
            ("Everything the OT zone does that is NOT process traffic",
             f'ip.addr == {esc(d["nets"]["ot"])} && !modbus && !bacapp && !dnp3'),
        ])
    arows = "".join(
        f'<tr><td>{esc(lbl)}</td><td>{cnt}</td><td class="svc">{esc(note)}</td></tr>'
        for lbl, cnt, note in [
            ("Level 3.5 — IDMZ", n("3.5"), "broker, replicated historian, patch repo, AV relay, proxy, staging"),
            ("Level 3 — site operations", n("3"), "MES + database, historian, batch, LIMS, OT domain, backup"),
            ("Level 2 — supervisory", n("2"), "SCADA servers, HMI panels, cell engineering workstation"),
            ("Level 1 — basic control", n("1"), f"{n_plc} PLCs, {n_rtu} RTUs, safety controllers"),
            ("Building management", n("bms"), "BACnet controller and field devices"),
            ("IoT", n("iot"), "cameras, NVR, badge readers, environmental sensors"),
            ("OT infrastructure", n("infra"), "industrial switches and UPSs"),
            ("Level 0 — process", 0, "hardwired to its PLC — deliberately never on the wire"),
        ])
    return {
        "svg": "\n".join(S_),
        "h1": "OT / ICS zone",
        "subtitle": "Purdue levels 0 to 3.5, and the single path in from the enterprise",
        "kpis": [(f"{POLL:g} s", "Level 1 poll", "mono"),
                 (_P.MODBUS_PORT, "Modbus"),
                 (_P.BACNET_PORT, "BACnet/IP"),
                 (_P.DNP3_PORT, "DNP3"),
                 (n("3.5", "3", "2", "1", "bms", "iot", "infra"), "OT assets"),
                 ("1", "Hosts that may initiate in")],
        "sections": [
            ("What is in each zone",
             '<table><thead><tr><th>Zone</th><th>Hosts</th><th>What it holds</th></tr></thead>'
             f'<tbody>{arows}</tbody></table>'),
            ("Finding it in a capture",
             '<table><thead><tr><th>What</th><th>Display filter</th></tr></thead>'
             f'<tbody>{frows}</tbody></table>'),
        ],
        "notes": [
            ("", "One host initiates into OT, and that is the point",
             "In the baseline exactly one host in the enterprise opens a session into the "
             "industrial zone: the privileged-access jump host in the server subnet. Every other "
             "host contributes zero inbound packets, on every capture day, at every scale. A "
             "scenario that reaches in from anywhere else is therefore anomalous by "
             "construction, with no tuning and no threshold."),
            ("", "The IDMZ terminates, it does not forward",
             "The jump host's session ends at the level 3.5 broker, which opens its own session "
             "down to level 3. Nothing passes through end to end, which is what a DMZ is for. "
             "Egress is the mirror image: the historian replica push, report staging, syslog "
             "forward, patch pull and AV relay all cross the boundary, and every one is opened "
             "from inside OT."),
            ("warn", "This zone speaks IT, not process",
             "Levels 0-2 average 64 bytes per packet. Levels 3 and 3.5 are SQL, SMB, RDP, HTTPS "
             "and backup, and are statistically indistinguishable from the enterprise. An OT "
             "demo that stops at level 2 teaches that OT traffic is always small and periodic, "
             "and skips the zone an intruder actually lands in."),
            ("", "This is baseline, not a scenario",
             "It is scheduled by Day.ot_control() and its four siblings and is present in every "
             "capture built with the OT subnet enabled, including one with no incident modules "
             "selected. There is nothing to switch on beyond the subnet itself."),
        ],
    }


def _jump_ip(d):
    """The one host permitted to initiate into OT, read from the inventory rather than named.

    It carries purdue level 4 because it lives in the enterprise, so it arrives in ot_levels
    under "4" -- it is an OT asset in the sense that it exists only when the subnet does.
    """
    for h in (d.get("ot_levels") or {}).get("4", []):
        if h.get("hostname") == "EXL-OTJUMP1":
            return h["ip"]
    return "<jump host>"


@register("campaign-builder", "Campaign Builder overview",
          "From threat indicators to a sensor score: the pipeline, its safety boundaries and what is verified",
          order=40, scenario=None)
def d_campaign_builder(c):
    """How the Campaign Builder works, drawn from the registries so no count is typed in twice."""
    sys.path.insert(0, APP_DIR)
    from collections import Counter
    from netgen.campaign import actions as _act, attack as _atk, families as _fam
    from intel import sources as _src
    reg = _act.load_all()
    per = Counter(s.tactic for s in reg.values())
    tacs = [t for t in _atk.tactics() if per.get(t["slug"])]
    tacs += [{"slug": k, "name": k.replace("-", " ").title()} for k in sorted(per) if k not in {t["slug"] for t in tacs}]
    n_act, n_tac, n_fam = len(reg), len(tacs), len(_fam.FAMILIES)
    n_feed = len(_src.FEEDS)
    n_key = sum(1 for f in _src.FEEDS.values() if f.needs_key)

    W, H = 1180, 604
    S_ = []
    A = S_.append
    A(_svg_open(W, H, "Campaign Builder pipeline from indicators to sensor score"))
    A(f'<rect x="0" y="0" width="{W}" height="{H}" fill="#ffffff"/>')

    # ---- pipeline row
    steps = [
        ("1", "Indicator sources", [f"{n_feed} feeds ({n_key} need a key)", "pasted list or file", "text, CSV, STIX, MISP"], SAPPHIRE),
        ("2", "Classify and role", ["type, defang, score", "role from nearby words", "c2, payload, scanner..."], SAPPHIRE),
        ("3", "Compile", [f"stages by ATT&CK tactic", f"{n_act} actions to choose from", f"{n_fam} family profiles"], PLUM),
        ("4", "Run", ["each action emits real", "packets into the capture", "inert bodies only"], PLUM),
        ("5", "Exports", ["campaign JSON", "STIX of what is on the wire", "Navigator, reports"], CYAN),
        ("6", "Replay", ["capture sent to the", "sensor's interface", "(tcpreplay, optional)"], TANGERINE),
        ("7", "Sensor check", ["read-only detection query", "score per technique", "detected / related / missed"], TANGERINE),
    ]
    bw, gap, x0, y0, bh = 142, 27, 12, 58, 138
    A(f'<text x="12" y="30" font-size="13" font-weight="900" fill="{SAPPHIRE}">The pipeline</text>')
    A(f'<text x="120" y="30" font-size="10.5" fill="{GRAY}">Left to right, one campaign. Everything up to step 5 is a file on disk; steps 6 and 7 touch your sensor.</text>')
    for i, (num, title, lines, col) in enumerate(steps):
        x = x0 + i * (bw + gap)
        A(f'<rect x="{x}" y="{y0}" width="{bw}" height="{bh}" rx="12" fill="#fff" stroke="{col}" stroke-width="2"/>')
        A(f'<rect x="{x}" y="{y0}" width="{bw}" height="34" rx="12" fill="{col}"/>')
        A(f'<rect x="{x}" y="{y0 + 20}" width="{bw}" height="14" fill="{col}"/>')
        A(f'<text x="{x + 10}" y="{y0 + 22}" font-size="11" font-weight="900" fill="#fff">{num}  {esc(_fit(title, bw - 30, 11))}</text>')
        for j, ln in enumerate(lines):
            A(f'<text x="{x + 10}" y="{y0 + 58 + j * 22}" font-size="9.8" fill="{SAPPHIRE}">{esc(_fit(ln, bw - 16, 9.8))}</text>')
        if i < len(steps) - 1:
            ax = x + bw + 3
            A(f'<path d="M{ax} {y0 + bh / 2} l{gap - 8} 0 m-6 -5 l6 5 l-6 5" fill="none" stroke="{GRAY}" stroke-width="1.8"/>')

    # ---- safety boundaries
    by = y0 + bh + 34
    A(f'<text x="12" y="{by}" font-size="13" font-weight="900" fill="{MAGENTA}">Safety boundaries</text>')
    def cx(i):
        return x0 + i * (bw + gap) + bw / 2
    bounds = [
        (2, 2, "Mapped addresses", "Indicator IPv4 becomes 198.18.0.0/15. Real addresses need --confirm-real-addresses or typing REAL."),
        (3, 3, "No exploit content", "Packets are valid but bodies are inert filler. Nothing is sent to an indicator."),
        (6, 6, "Read-only", "The sensor query only reads detections. It changes nothing on the sensor."),
    ]
    # draw the three boundary cards in one row, each tied to its step by a dashed leader
    cw, cgap = 372, 20
    for k, (a, b, title, body) in enumerate(bounds):
        x = 12 + k * (cw + cgap)
        y = by + 16
        A(f'<rect x="{x}" y="{y}" width="{cw}" height="74" rx="10" fill="#fdf2f8" stroke="{MAGENTA}" stroke-width="1.5"/>')
        A(f'<text x="{x + 12}" y="{y + 22}" font-size="11.5" font-weight="900" fill="{MAGENTA}">{esc(title)}</text>')
        for j, ln in enumerate(_wrap(body, 62)):
            A(f'<text x="{x + 12}" y="{y + 40 + j * 14}" font-size="9.8" fill="{SAPPHIRE}">{esc(ln)}</text>')
        tx = cx(a)
        A(f'<path d="M{x + cw / 2:.0f} {y} L{tx:.0f} {y0 + bh + 6}" fill="none" stroke="{MAGENTA}" stroke-width="1.3" stroke-dasharray="4 3"/>')
        A(f'<circle cx="{tx:.0f}" cy="{y0 + bh + 6}" r="3.5" fill="{MAGENTA}"/>')

    # ---- verified vs not
    vy = by + 16 + 74 + 28
    A(f'<text x="12" y="{vy}" font-size="13" font-weight="900" fill="{SAPPHIRE}">What is verified</text>')
    ver = [
        ("Verified", "#1b7f4b", "Packets: every action has a wire check, and check_rfc791.py validates a whole capture"),
        ("Verified", "#1b7f4b", "Determinism: same indicators, options and date give the same capture"),
        ("Verified", "#1b7f4b", "Feeds: abuse.ch feeds and OTX checked live 2026-11-20, the rest 2026-11-19"),
        ("Not yet", MAGENTA, "Sensor scoring: tested with fixtures only, not yet run against a live sensor"),
    ]
    for k, (tag, col, text) in enumerate(ver):
        y = vy + 20 + k * 24
        A(f'<rect x="12" y="{y - 12}" width="62" height="17" rx="8" fill="{col}"/>')
        A(f'<text x="43" y="{y}" text-anchor="middle" font-size="9" font-weight="900" fill="#fff">{esc(tag)}</text>')
        A(f'<text x="84" y="{y}" font-size="10.2" fill="{SAPPHIRE}">{esc(_fit(text, 520, 10.2))}</text>')

    # ---- tactic coverage (computed)
    px = 640
    A(f'<text x="{px}" y="{vy}" font-size="13" font-weight="900" fill="{SAPPHIRE}">Actions per ATT&amp;CK tactic ({n_act} in {n_tac})</text>')
    mx = max(per.values())
    half = (len(tacs) + 1) // 2
    for k, t in enumerate(tacs):
        col_i, row = divmod(k, half)
        x = px + col_i * 272
        y = vy + 18 + row * 18
        n = per[t["slug"]]
        A(f'<text x="{x}" y="{y + 9}" font-size="9.5" fill="{SAPPHIRE}">{esc(_fit(t["name"], 112, 9.5))}</text>')
        bwid = 120.0 * n / mx
        A(f'<rect x="{x + 116}" y="{y}" width="{bwid:.0f}" height="11" rx="3" fill="{PLUM}"/>')
        A(f'<text x="{x + 120 + bwid:.0f}" y="{y + 9}" font-size="9.5" font-weight="700" fill="{GRAY}">{n}</text>')
    A('</svg>')

    exp_rows = "".join(f"<tr><td class='m'>{esc(a)}</td><td>{esc(b)}</td></tr>" for a, b in [
        ("<prefix>.campaign.json", "The campaign plan; build it again or edit it"),
        ("<prefix>.campaign-iocs.stix.json", "STIX 2.1 of the indicators as they appear in the packets, so a sensor's threat collection matches"),
        ("<prefix>.attack-navigator.json", "ATT&CK Navigator layer of the techniques that ran"),
        ("<prefix>.campaign-report.md / .report.html", "Indicator to stage to action to packets, coverage, anything skipped"),
        ("campaign diagram page", "Timeline, flow map, stage detail, indicator trace and capture filters"),
    ])
    return {
        "svg": "\n".join(S_),
        "h1": "Campaign Builder",
        "subtitle": "From threat indicators to a capture, and from a capture to a sensor score",
        "kpis": [(n_act, "Actions"), (n_tac, "ATT&CK tactics"), (n_fam, "Family profiles"),
                 (n_feed, "Feeds"), ("198.18.0.0/15", "Mapped range", "mono"), (5, "Export files")],
        "sections": [
            ("What each export is for",
             "<table><thead><tr><th>Output</th><th>Use</th></tr></thead>"
             f"<tbody>{exp_rows}</tbody></table>"),
        ],
        "notes": [
            ("", "For a newcomer",
             "Give it a list of bad addresses, domains and URLs. It works out what each would be used for, plans an "
             "attack in stages, and writes that behaviour into a capture of an ordinary business day. Replay the capture "
             "and the sensor should notice. Afterwards you can ask it what it noticed."),
            ("", "For an architect",
             "Compilation and the actions are pure functions of the indicators, options and date, so output is "
             "repeatable. Actions are registered by token with a tactic, techniques, protocols and parameters; the "
             "compiler only chooses tokens and parameters. Exports are derived from the runner's record of what was "
             "emitted, not from the plan, so they describe the packets that exist."),
            ("warn", "Not yet verified",
             "Scoring reads detections in the format the platform documents. It has been exercised with fixtures, "
             "not replayed against a live sensor, so treat a score as provisional."),
        ],
    }

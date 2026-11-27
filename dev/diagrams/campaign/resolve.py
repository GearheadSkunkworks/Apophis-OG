"""Inventory-only endpoint resolver for campaign plan mode.

`resolve_ref(ctx, ref, campaign, options)` answers "which host is this `from`/`to` reference?"
without a built engine context, using the diagram context's inventory (template host names; the
page relabels the identity later). It follows the rules of netgen.campaign.hosts so a plan names
the same host a default build uses:

* the host table is the inventory minus gateway legs (`gw_side`), as netgen.model.build_hosts
  makes it; the firewall resolves to its inside user leg (FW-A), as the real resolver does
* ws is WS-047 when present, else the first workstation; dc/file/sql/web are DC1/FILE1/SQL1/WEB1;
  server is the first of FILE1, WEB1, SQL1, DC1 (or the lateral_target option); host:SUFFIX and
  bare names look up prefix+name
* ws2 and any_ws are random picks in a real build (they depend on the engine's random stream and
  on every earlier draw), so the plan picks the first workstation other than ws, and the result
  carries approx=True
* external refs use hosts.find_ioc and hosts.address_for with the campaign's own address mode and
  mapped table, so the address is the one the packets carry

Result: {"id","label","ip","zone","role","exists","approx"}. exists is False when the reference has
no host (missing role, no OT host, an indicator that cannot be addressed); label and ip are then
best effort. Deterministic, no randomness, no I/O when a ctx is given.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.dirname(os.path.dirname(HERE))
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

from netgen.identity import DEFAULT as _T                     # noqa: E402 - sys.path is set up before the import
from netgen.campaign import hosts as _H                       # noqa: E402 - sys.path is set up before the import

_FIXED = {"dc": "DC1", "file": "FILE1", "sql": "SQL1", "web": "WEB1"}
_SERVER_ORDER = ("FILE1", "WEB1", "SQL1", "DC1")
_ATTACKER_FALLBACK = {"type": "domain", "value": "attacker.invalid-campaign.example"}


def _make_ctx(inventory=None):
    import make_diagram as M
    data = M.gather(inventory or os.path.join(APP_DIR, "inventory.json"))
    return M.DiagramContext(data, [], [])


def _table(ctx):
    """{hostname: inventory row} as the engine's host table sees it (gateway legs dropped)."""
    out = {}
    for h in ctx.data.get("hosts") or ctx.data.get("servers") or []:
        if not h.get("gw_side"):
            out[h["hostname"]] = h
    return out


def _zone(ctx, row):
    if row.get("purdue"):
        return "ot"
    nets = ctx.data.get("nets") or {}
    if row.get("subnet") == nets.get("server"):
        return "server"
    return "user"


def _result(ctx, row, name, approx=False):
    return {"id": name, "label": name, "ip": row["ip"], "zone": _zone(ctx, row),
            "role": row.get("role") or "", "exists": True, "approx": approx}


def _missing(ref, name=None, zone="server"):
    return {"id": "missing:" + ref, "label": name or ref, "ip": "", "zone": zone,
            "role": "", "exists": False, "approx": False}


def _workstations(tbl):
    pre = _T.host("WS-")
    return sorted(n for n in tbl if n.startswith(pre))


def _internal(ctx, ref, options):
    tbl = _table(ctx)
    options = options or {}

    def need(suffix, as_ref=ref):
        name = _T.host(suffix)
        return _result(ctx, tbl[name], name) if name in tbl else _missing(as_ref, name)

    ws = _workstations(tbl)
    pick = _T.host("WS-047")
    if pick not in tbl and ws:
        pick = ws[0]
    if ref == "ws":
        return _result(ctx, tbl[pick], pick) if pick in tbl else _missing(ref, zone="user")
    if ref in ("ws2", "any_ws"):
        others = [n for n in ws if n != pick]
        if ref == "any_ws" and not others and pick in tbl:      # a lone workstation is its own any_ws
            return _result(ctx, tbl[pick], pick, True)
        return _result(ctx, tbl[others[0]], others[0], True) if others else _missing(ref, zone="user")
    if ref == "server":
        tgt = options.get("lateral_target") or "server"
        if tgt != "server":
            return _internal(ctx, tgt, options)
        for suffix in _SERVER_ORDER:
            if _T.host(suffix) in tbl:
                return need(suffix)
        return _missing(ref)
    if ref == "fw":                                              # the firewall's inside user leg, as the real resolver now picks
        for cand in ("FW1", "FW-A"):
            if _T.host(cand) in tbl or cand in tbl:
                row = tbl.get(cand) or tbl[_T.host(cand)]
                r = _result(ctx, row, cand)
                r["zone"] = "perimeter"
                return r
        r = _missing(ref, _T.host("FW-A"), "perimeter")
        fw = next((h for h in ctx.data.get("hosts") or [] if h.get("gw_side") == "user"), None)
        if fw:
            r["ip"] = fw["ip"]
        return r
    if ref in _FIXED:
        return need(_FIXED[ref])
    if ref.startswith("host:"):
        return need(ref[5:])
    if ref in tbl:
        return _result(ctx, tbl[ref], ref)
    if _T.host(ref) in tbl:
        return _result(ctx, tbl[_T.host(ref)], _T.host(ref))
    return _missing(ref)


def _external(ref, campaign):
    try:
        found = _H.find_ioc(campaign, ref)
        ioc = found[1] if found else dict(_ATTACKER_FALLBACK)
        if ioc.get("type") not in _H.ADDRESSABLE:
            raise _H.EndpointError("not addressable")
        ip = _H.address_for(ioc, campaign)
        _, dom = _H.ioc_host_text(ioc)
    except _H.EndpointError:
        return {"id": "missing:" + ref, "label": ref, "ip": "", "zone": "internet", "role": "",
                "exists": False, "approx": False}
    label = (dom.split(".")[0] if dom else "EXT-" + ip.replace(".", "-")).upper()[:30]
    return {"id": "ext:" + ip, "label": label, "ip": ip, "zone": "internet",
            "role": ioc.get("role") or "attacker", "exists": True, "approx": False}


def resolve_ref(ctx, ref, campaign, options=None):
    """Resolve one `from`/`to` reference. `ctx` is a make_diagram.DiagramContext or None (the
    default inventory is loaded). `options` defaults to the campaign's own options."""
    campaign = campaign or {}
    if options is None:
        options = campaign.get("options")
    ref = str(ref)
    if _H.is_external_ref(ref):
        return _external(ref, campaign)
    return _internal(ctx if ctx is not None else _make_ctx(), ref, options)

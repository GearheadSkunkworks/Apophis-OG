"""The campaign view model: the one dict every panel reads (contract section 3).

`build(campaign, summary=None, score=None, ctx=None, company=None) -> dict`

Modes: "scored" when a score is given, else "run" when the summary has entries, else "plan". Plan mode never
carries run data (packets, bytes, ts stay None); a value that is not known is None or absent, never invented.
Deterministic: no clock, no randomness. Standard library only; every collaborator is imported defensively so the
model still builds when one is missing.
"""
import copy
import ipaddress
import re

STAGE_GAP_S = 10.0                       # same quiet gap the runner leaves between stages
OBSERVABLE = ("ipv4", "ipv6", "domain", "url")
PLACED = ("ipv4", "domain", "url")       # observable types the engine can actually place in a capture
_PORT_KEYS = ("port", "dport", "dst_port", "server_port")
_DEFAULT_PORT = {"TLS": 443, "HTTPS": 443, "DNS": 53, "HTTP": 80, "SMB": 445, "SMB2": 445, "SSH": 22,
                 "RDP": 3389, "KERBEROS": 88, "LDAP": 389, "FTP": 21, "SMTP": 25, "WINRM": 5985, "TDS": 1433}
_INTERNAL_LABEL = {
    "ws": ("Compromised workstation", "user", "workstation"),
    "ws2": ("Second workstation", "user", "workstation"),
    "any_ws": ("A workstation", "user", "workstation"),
    "server": ("Application server", "server", "server"),
    "dc": ("Domain controller", "server", "domain controller"),
    "file": ("File server", "server", "file server"),
    "sql": ("SQL server", "server", "database server"),
    "web": ("Web server", "server", "web server"),
    "fw": ("Firewall", "perimeter", "firewall"),
}
_INT_REFS = tuple(_INTERNAL_LABEL)


# ------------------------------------------------------------------ defensive imports
def _imp(name):
    try:
        import importlib
        return importlib.import_module(name, __package__)
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
        return None


def _resolver():
    m = _imp(".resolve")
    return getattr(m, "resolve_ref", None) if m else None


def _meta_get():
    m = _imp("netgen.campaign.actions.meta")
    return getattr(m, "get", None) if m else None


def _actions():
    m = _imp("netgen.campaign.actions")
    if m is None:
        return None
    try:
        m.load_all()
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
        pass
    return m


def _spec(A, token):
    if A is None:
        return None
    try:
        return A.get(token)
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
        return None


# ------------------------------------------------------------------ small helpers
def make_ctx(inventory=None, ot_nets=None):
    """A make_diagram.DiagramContext backed by the inventory (None when it cannot be built)."""
    try:
        import os
        import make_diagram as MD
        data = MD.gather(inventory or os.path.join(MD.APP_DIR, "inventory.json"), ot_nets=ot_nets)
        try:
            mods, selected = MD.load_modules(None)
        except Exception:                                        # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
            mods, selected = [], []
        c = MD.DiagramContext(data, mods, selected)
        c.ot_nets = ot_nets
        return c
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
        return None


def _options(campaign):
    o = dict(campaign.get("options") or {})
    o.setdefault("address_mode", "mapped")
    o.setdefault("start", "10:00")
    o.setdefault("speed", "realistic")
    return o


def _stage_len(st, options):
    full = float(st.get("duration_s") or 60)
    if options.get("speed") == "fast":
        return float(st.get("fast_s") or max(10.0, full / 3)), full
    return full, full


def _num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


_DEFAULT_OT_NETS = ("10.10.30.0/24", "10.10.40.0/24", "10.10.50.0/24")      # the engine's default OT, ops and bridge subnets


def _zone_of_ip(ctx, ip):
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip)
        if ctx is None or not (getattr(ctx, "nets", None) or {}).get("ot"):
            if any(a in ipaddress.ip_network(n) for n in _DEFAULT_OT_NETS):        # OT hosts seen in a run
                return "ot"
        if ctx is None:
            return None
        for key, zone in (("user", "user"), ("server", "server"), ("ot", "ot"), ("ops", "ot"), ("idmz", "ot")):
            net = (ctx.nets or {}).get(key)
            if net and a in ipaddress.ip_network(net, strict=False):
                return zone
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
        return None
    return None


def _tactic_title(slug):
    try:
        from netgen.campaign import attack
        t = attack.tactic(slug)
        return t["name"] if t else (slug or "")
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
        return slug or ""


def _technique(tid):
    try:
        from netgen.campaign import attack
        return attack.technique(tid)
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
        return None


# The protocol that best names a flow: first match in this order wins (a list such as Kerberos/SMB2/DCERPC is an SMB flow).
_FAMILY_ORDER = ("RDP", "WSMAN", "TDS", "SMB2", "SMB", "LDAP", "SSH", "FTP", "SMTP", "HTTPS", "TLS", "HTTP", "DNS", "ICMP", "KERBEROS", "DCERPC")
_FAMILY_LABEL = {"WSMAN": "WinRM", "SMB2": "SMB", "HTTPS": "TLS", "KERBEROS": "Kerberos", "DCERPC": "RPC"}


def _protocol_family(protocols):
    p = [str(x) for x in (protocols or [])]
    up = [x.upper() for x in p]
    for fam in _FAMILY_ORDER:
        if fam in up:
            return _FAMILY_LABEL.get(fam, fam)
    return p[0] if p else "IP"


def _edge_port(spec_protocols, params, family=None):
    for k in _PORT_KEYS:
        v = (params or {}).get(k)
        if isinstance(v, int) and not isinstance(v, bool) and 0 < v < 65536:
            return v
    ports = (params or {}).get("ports")
    if isinstance(ports, list) and len(ports) == 1 and isinstance(ports[0], int):
        return ports[0]
    fam = str(family or _protocol_family(spec_protocols)).upper()
    return _DEFAULT_PORT.get(fam) if fam in ("TLS", "DNS", "SMB", "SMB2", "SSH", "RDP", "LDAP", "WINRM", "TDS", "FTP", "SMTP", "KERBEROS") else None


_PLACE = re.compile(r"\{(src_ip|dst_ip|fqdn|p:[A-Za-z0-9_]+)\}")
_BAD = re.compile(r"[\x00-\x1f\x7f]")


def render_filters(templates, src_addr, dst_addr, fqdn, params):
    """Fill the filter templates; drop one whose placeholders cannot be filled."""
    out = []
    for item in templates or []:
        try:
            what, tpl, expect = item
        except (TypeError, ValueError):
            continue
        ok = [True]

        def sub(m):
            key = m.group(1)
            val = {"src_ip": src_addr, "dst_ip": dst_addr, "fqdn": fqdn}.get(key) if not key.startswith("p:") \
                else (params or {}).get(key[2:])
            if val is None or val == "" or isinstance(val, (list, dict)):
                ok[0] = False  # noqa: B023 closure runs inside the iteration
                return ""
            return _BAD.sub("", str(val))
        text = _PLACE.sub(sub, str(tpl))
        if ok[0] and text.strip():
            out.append({"what": str(what), "filter": text, "expect": str(expect)})
    return out


# ------------------------------------------------------------------ endpoints
class _Nodes:
    def __init__(self, campaign, options, ctx, run_mode):
        self.campaign, self.options, self.ctx, self.run = campaign, options, ctx, run_mode
        self.nodes = {}
        self.resolve = _resolver()
        self.mode = options.get("address_mode", "mapped")
        self.map = {}

    def _put(self, n):
        cur = self.nodes.get(n["id"])
        if cur is None:
            self.nodes[n["id"]] = n
            return n
        for k in ("address", "fqdn"):
            if cur.get(k) is None and n.get(k):
                cur[k] = n[k]
        if cur.get("address") and cur.get("address_kind") == "none":
            cur["address_kind"] = n["address_kind"]
        return cur

    def external(self, ref, host=None):
        from netgen.campaign import hosts as H
        found = None
        try:
            found = H.find_ioc(self.campaign, ref)
        except Exception:                                        # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
            found = None
        if found is None:
            ip = (host or {}).get("ip")
            return self._put({"id": "ext:" + ref, "label": "Attacker host" if ref == "attacker" else ref,
                              "zone": "internet", "role": "attacker", "address": ip,
                              "address_kind": ("real" if self.mode == "real" else "mapped") if ip else "none",
                              "fqdn": None, "ioc": None, "count": 1})
        idx, ioc = found
        ip, dom = H.ioc_host_text(ioc)
        addr = (host or {}).get("ip")
        if not addr:
            try:
                addr = H.address_for(ioc, self.campaign) if not self.run else None
            except Exception:                                    # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
                addr = None
        label = dom or ip or str(ioc.get("value"))
        return self._put({"id": "ioc:%d" % idx, "label": label, "zone": "internet", "role": ioc.get("role") or "unknown",
                          "address": addr, "address_kind": ("real" if self.mode == "real" and ip else "mapped") if addr else "none",
                          "fqdn": dom, "ioc": idx, "count": 1})

    def internal(self, ref, host=None):
        r = None
        if self.resolve and not self.run:
            try:
                r = self.resolve(self.ctx, ref, self.campaign, self.options)
            except Exception:                                    # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
                r = None
        if host and host.get("name"):
            zone = _zone_of_ip(self.ctx, host.get("ip")) or (r or {}).get("zone") or \
                (_INTERNAL_LABEL.get(ref) or (0, "server"))[1]
            return self._put({"id": host["name"], "label": host["name"], "zone": zone,
                              "role": (r or {}).get("role") or (_INTERNAL_LABEL.get(ref) or (0, 0, ref))[2],
                              "address": host.get("ip"), "address_kind": "internal" if host.get("ip") else "none",
                              "fqdn": None, "ioc": None, "count": 1})
        if r:
            return self._put({"id": r.get("id") or "int:" + ref, "label": r.get("label") or ref,
                              "zone": r.get("zone") or "server", "role": r.get("role") or ref,
                              "address": r.get("ip"), "address_kind": "internal" if r.get("ip") else "none",
                              "fqdn": None, "ioc": None, "count": 1, "exists": r.get("exists", True)})
        label, zone, role = _INTERNAL_LABEL.get(ref) or (ref.split(":", 1)[-1], "server", "host")
        return self._put({"id": "int:" + ref, "label": label, "zone": zone, "role": role, "address": None,
                          "address_kind": "none", "fqdn": None, "ioc": None, "count": 1})

    def endpoint(self, ref, host=None):
        try:
            from netgen.campaign import hosts as H
            if H.is_external_ref(ref):
                return self.external(ref, host)
        except Exception:                                        # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
            pass
        return self.internal(ref, host)


# ------------------------------------------------------------------ build
def build(campaign, summary=None, score=None, ctx=None, company=None):
    campaign = copy.deepcopy(campaign) if isinstance(campaign, dict) else {}
    summary = summary if isinstance(summary, dict) else None
    entries_all = list((summary or {}).get("entries") or [])
    mode = "scored" if score else ("run" if entries_all else "plan")
    run = mode != "plan"
    if ctx is None:
        ctx = make_ctx()
    A = _actions()
    metaget = _meta_get()
    options = _options(campaign)
    meta = campaign.get("meta") or {}
    nodes = _Nodes(campaign, options, ctx, run)

    # entries grouped by stage in order; positional fallback when entries carry no stage id
    stages_in = campaign.get("stages") or []
    by_stage, positional = {}, not all(isinstance(e, dict) and e.get("stage") for e in entries_all)
    if not positional:
        for e in entries_all:
            by_stage.setdefault(e["stage"], []).append(e)
    pos_iter = iter(entries_all)

    stages, actions, edges_map = [], [], {}
    t = 0.0
    for st in stages_in:
        length, full = _stage_len(st, options)
        ratio = length / full if full else 1.0
        acts = st.get("actions") or []
        n = max(1, len(acts))
        sid = st.get("id") or "s%d" % (len(stages) + 1)
        idxs = []
        for ai, a in enumerate(acts):
            i = len(actions)
            idxs.append(i)
            ent = None
            if run:
                if positional:
                    ent = next(pos_iter, None)
                else:
                    pool = by_stage.get(sid) or []
                    ent = pool[ai] if ai < len(pool) else None
            token = a.get("action")
            spec = _spec(A, token)
            params = {}
            if spec is not None:
                params = {k: d.get("default") for k, d in (spec.params or {}).items()}
            params.update(a.get("params") or {})
            if ent and isinstance(ent.get("params"), dict):
                params.update(ent["params"])
            md = (metaget(token) if metaget else None) or None
            src_host = (ent or {}).get("from_host") if isinstance((ent or {}).get("from_host"), dict) else None
            dst_host = (ent or {}).get("to_host") if isinstance((ent or {}).get("to_host"), dict) else None
            src = nodes.endpoint(str(a.get("from")), src_host)
            dst = nodes.endpoint(str(a.get("to")), dst_host)
            protos = list((ent or {}).get("protocols") or (spec.protocols if spec else []) or [])
            techs = list((ent or {}).get("techniques") or (spec.techniques if spec else []) or [])
            off = t + (float(a["at"]) * ratio if _num(a.get("at")) else (ai / n) * length * 0.9)
            status = "planned"
            if run:
                s = (ent or {}).get("status")
                status = "ok" if s == "ok" else ("failed" if s == "failed" else "skipped")
            tpl = list((md or {}).get("filters") or [])
            ioc_idx = sorted(set(int(x) for x in ((ent or {}).get("ioc") or a.get("ioc") or []) if _num(x)
                                 ) | {n_["ioc"] for n_ in (src, dst) if n_.get("ioc") is not None})
            act = {
                "i": i, "stage": sid, "action": token, "title": spec.title if spec else str(token),
                "tactic": spec.tactic if spec else st.get("tactic"), "techniques": techs, "protocols": protos,
                "summary": (spec.summary if spec else "") or "",
                "plain": (md or {}).get("plain") or ((spec.summary if spec else "") or ""),
                "tells": list((md or {}).get("tells") or []), "wire": (md or {}).get("wire") or "",
                "filters": render_filters(tpl, src.get("address"), dst.get("address"),
                                          dst.get("fqdn") or src.get("fqdn"), params),
                "src": src["id"], "dst": dst["id"], "inbound": src["zone"] == "internet",
                "params": params, "explain": a.get("explain") or "",
                "status": status, "error": (ent or {}).get("error") if run else None,
                "ts": (ent or {}).get("ts") if run else None,
                "first_ts": (ent or {}).get("first_ts") if run else None,
                "last_ts": (ent or {}).get("last_ts") if run else None,
                "packets": ((ent or {}).get("packets") if ent else None) if run else None,
                "bytes": ((ent or {}).get("bytes") if ent else None) if run else None,
                "ioc": ioc_idx, "score": None, "offset_s": round(off, 1),
                "dur_s": _action_dur(spec, params), "from_ref": a.get("from"), "to_ref": a.get("to"),
            }
            actions.append(act)
            key = (src["id"], dst["id"], _protocol_family(protos), _edge_port(protos, params, _protocol_family(protos)))
            e = edges_map.setdefault(key, {"src": key[0], "dst": key[1], "proto": key[2], "port": key[3],
                                           "actions": [], "packets": None, "bytes": None, "state": "planned",
                                           "inbound": act["inbound"]})
            e["actions"].append(i)
        states = [actions[i]["status"] for i in idxs]
        if not run:
            sstate = "planned"
        elif states and all(s == "ok" for s in states):
            sstate = "ok"
        elif states and not any(s == "ok" for s in states):
            sstate = "skipped"
        else:
            sstate = "partial" if states else "ok"
        stages.append({"id": sid, "name": st.get("name") or sid, "tactic": st.get("tactic"),
                       "tactic_title": _tactic_title(st.get("tactic")),
                       "techniques": list(st.get("techniques") or []), "narrative": st.get("narrative") or "",
                       "action_idx": idxs, "start_s": round(t, 1), "end_s": round(t + length, 1), "state": sstate})
        t += length + STAGE_GAP_S

    # edges: state and run totals
    for e in edges_map.values():
        acts_ = [actions[i] for i in e["actions"]]
        if run:
            ok = [a for a in acts_ if a["status"] == "ok"]
            e["state"] = "ok" if ok else ("failed" if any(a["status"] == "failed" for a in acts_) else "skipped")
            e["packets"] = sum(a["packets"] or 0 for a in ok)
            e["bytes"] = sum(a["bytes"] or 0 for a in ok)
    edges = list(edges_map.values())

    # indicators
    srows = {r.get("index"): r for r in (summary or {}).get("iocs") or [] if isinstance(r, dict)}
    iocs = _iocs(campaign, options, srows, actions, run)
    node_list = sorted(nodes.nodes.values(), key=lambda n: (_ZORDER.get(n["zone"], 9), str(n["id"])))
    for n in node_list:
        n.pop("exists", None)

    techniques = _techniques(campaign, stages, actions, run, score)
    vulns = _vulns(campaign)

    # score onto actions
    score_block = None
    if mode == "scored":
        score_block = dict((score or {}).get("score") or {})
        _apply_action_scores(actions, (score or {}).get("actions") or [])

    est = (summary or {}).get("estimate") if run else None
    if not est:
        try:
            from netgen.campaign import runner
            est = runner.estimate(campaign)
        except Exception:                                        # noqa: BLE001 - estimate failure falls back to counts taken from the stage list
            est = {"stages": len(stages), "actions": len(actions), "flows": len(actions)}
    duration = stages[-1]["end_s"] if stages else 0.0
    packets = sum(a["packets"] or 0 for a in actions) if run else None
    nbytes = sum(a["bytes"] or 0 for a in actions) if run else None
    totals = {"stages": len(stages), "actions": len(actions), "packets": packets, "bytes": nbytes,
              "duration_s": duration, "indicators_used": sum(1 for r in iocs if r["used_by"]),
              "techniques": len(techniques), "flows": est.get("flows")}

    view = {
        "mode": mode,
        "meta": {"name": meta.get("name") or "Campaign", "id": meta.get("id") or "",
                 "description": meta.get("description") or "", "actor": meta.get("actor") or "",
                 "seed": meta.get("seed")},
        "options": options, "stages": stages, "actions": actions, "nodes": node_list, "edges": edges,
        "iocs": iocs, "techniques": techniques, "vulns": vulns, "totals": totals, "notes": [], "errors": [],
        "score": score_block, "estimate": est,
        "scored_against": {k: (score or {}).get(k) for k in ("sensor", "time", "window") if (score or {}).get(k)}
        if mode == "scored" else None,
    }
    view["errors"] = _errors(summary)
    view["notes"] = _notes(view, ctx, campaign)
    return view


_ZORDER = {"internet": 0, "perimeter": 1, "user": 2, "server": 3, "ot": 4}


def _action_dur(spec, params):
    n, iv = params.get("count"), params.get("interval_s")
    if _num(n) and _num(iv) and n > 1 and iv > 0:
        return float(n) * float(iv)
    return float(spec.min_duration_s) if spec is not None else None


def _iocs(campaign, options, srows, actions, run):
    from netgen.campaign import hosts as H
    used = {}
    for a in actions:
        for i in a["ioc"]:
            if not run or a["status"] == "ok":
                used.setdefault(i, []).append(a["i"])
    out = []
    mode = options.get("address_mode", "mapped")
    for i, ioc in enumerate(campaign.get("iocs") or []):
        t = ioc.get("type")
        addr, kind = None, "none"
        row = srows.get(i)
        if t in H.ADDRESSABLE:
            if row and row.get("address"):
                addr = row["address"]
            elif not run:
                try:
                    addr = H.address_for(ioc, dict(campaign, options=options))
                except Exception:                                # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
                    addr = None
            if addr:
                ip, _ = H.ioc_host_text(ioc)
                kind = "real" if (mode == "real" and ip) else "mapped"
        u = sorted(set(used.get(i, [])))
        out.append({"index": i, "type": t, "value": ioc.get("value"), "role": ioc.get("role") or "unknown",
                    "address": addr, "address_kind": kind,
                    "on_wire": bool(t in PLACED and u), "used_by": u})
    return out


def _techniques(campaign, stages, actions, run, score):
    tech = {}

    def get(tid):
        d = tech.get(tid)
        if d is None:
            info = _technique(tid) or {}
            d = tech[tid] = {"id": tid, "name": info.get("name") or tid, "tactic": info.get("tactic"),
                             "_tactics": info.get("tactics") or [], "expected": False, "emitted": False,
                             "planned": False, "score": None, "stages": [], "actions": [], "cves": []}
        return d
    smap = {s["id"]: s for s in stages}
    for s in stages:
        for tid in s["techniques"]:
            d = get(tid)
            d["expected"] = True
            if s["id"] not in d["stages"]:
                d["stages"].append(s["id"])
            if s["tactic"] and s["tactic"] in d["_tactics"]:
                d["tactic"] = s["tactic"]
    for a in actions:
        for tid in a["techniques"]:
            d = get(tid)
            d["planned"] = True
            d["actions"].append(a["i"])
            if a["stage"] not in d["stages"]:
                d["stages"].append(a["stage"])
            if run and a["status"] == "ok":
                d["emitted"] = True
            st = smap.get(a["stage"])
            if st and st["tactic"] and st["tactic"] in d["_tactics"] and not d["expected"]:
                d["tactic"] = st["tactic"]
    for x in campaign.get("expect") or []:
        tid = x.get("technique")
        if not tid:
            continue
        d = get(tid)
        d["expected"] = True
        if x.get("stage") and x["stage"] not in d["stages"]:
            d["stages"].append(x["stage"])
        if x.get("cve") and x["cve"] not in d["cves"]:
            d["cves"].append(x["cve"])
    for r in (score or {}).get("techniques") or []:
        tid = r.get("technique") or r.get("id")
        if not tid:
            continue
        d = get(tid)
        st = r.get("status")
        d["score"] = st if st in ("detected", "related", "missed") else None
        if r.get("name") and d["name"] == tid:
            d["name"] = r["name"]
        if r.get("tactic") and not d["tactic"]:
            d["tactic"] = r["tactic"]
    for d in tech.values():
        d.pop("_tactics", None)
        d["stages"] = sorted(set(d["stages"]))
        d["actions"] = sorted(set(d["actions"]))
        d["cves"] = sorted(d["cves"])
    return [tech[k] for k in sorted(tech)]


def _vulns(campaign):
    by = {}
    for x in campaign.get("expect") or []:
        if x.get("cve"):
            by.setdefault(x["cve"], [])
            if x.get("technique") and x["technique"] not in by[x["cve"]]:
                by[x["cve"]].append(x["technique"])
    for ioc in campaign.get("iocs") or []:
        if ioc.get("type") == "cve" and ioc.get("value"):
            by.setdefault(str(ioc["value"]).upper(), [])
    return [{"cve": k, "techniques": sorted(v)} for k, v in sorted(by.items())]


def _apply_action_scores(actions, rows):
    seen = {}
    for r in rows:
        key = (r.get("stage"), r.get("action"))
        n = seen.get(key, 0)
        seen[key] = n + 1
        pool = [a for a in actions if (a["stage"], a["action"]) == key]
        if n < len(pool):
            st = r.get("status")
            pool[n]["score"] = st if st in ("detected", "related", "missed") else None


def _errors(summary):
    out = []
    for e in (summary or {}).get("errors") or []:
        if isinstance(e, dict):
            where = " / ".join(str(e[k]) for k in ("stage", "action") if e.get(k))
            out.append(("%s: " % where if where else "") + str(e.get("error") or e))
        else:
            out.append(str(e))
    return out


def _notes(view, ctx, campaign):
    notes = []
    mode, opts = view["mode"], view["options"]
    if mode == "plan":
        notes.append({"kind": "info", "title": "Plan: nothing has been generated yet",
                      "body": "Times, flows and addresses are planned from the campaign file. Packet and byte "
                              "counts appear once the capture is built, and detection results once the sensor "
                              "has replayed it."})
    elif mode == "run":
        notes.append({"kind": "info", "title": "The sensor has not been asked yet",
                      "body": "This page describes what the capture contains. It does not say what the sensor "
                              "detected; score the run against a sensor to see that."})
    if view["iocs"] and opts.get("address_mode") != "real":
        notes.append({"kind": "info", "title": "Mapped addressing",
                      "body": "Indicator addresses are remapped into reserved test ranges so a capture never "
                              "points at a live host. The indicator's own value is kept in the trace table."})
    elif opts.get("address_mode") == "real":
        notes.append({"kind": "warn", "title": "Real addressing",
                      "body": "Public indicator addresses are used as written. Replay only on an isolated "
                              "segment that cannot reach those addresses."})
    skipped = [a for a in view["actions"] if a["status"] == "skipped"]
    failed = [a for a in view["actions"] if a["status"] == "failed"]
    if skipped:
        notes.append({"kind": "warn", "title": "%d action(s) skipped" % len(skipped),
                      "body": "; ".join("%s (%s): %s" % (a["title"], a["stage"], a["error"] or "no reason recorded")
                                        for a in skipped[:6]) + (" ..." if len(skipped) > 6 else "")})
    if failed:
        notes.append({"kind": "warn", "title": "%d action(s) failed" % len(failed),
                      "body": "; ".join("%s (%s): %s" % (a["title"], a["stage"], a["error"] or "no reason recorded")
                                        for a in failed[:6]) + (" ..." if len(failed) > 6 else "")})
    ot_ref = any(_is_ot_action(a) for a in view["actions"])
    ot_ran = any(a["status"] == "ok" for a in view["actions"] if _is_ot_action(a))    # a run proves the OT zone was on
    if ot_ref and not ot_ran and (ctx is None or not getattr(ctx, "ot_nets", None)):
        notes.append({"kind": "warn", "title": "OT zone is off",
                      "body": "This campaign touches industrial hosts but the environment has no OT zone, so those "
                              "actions have nothing to run against. Turn the OT zone on to include them."})
    elif ot_ref:
        notes.append({"kind": "info", "title": "OT zone in use",
                      "body": "Some actions run against industrial hosts. Their flows cross the OT firewall."})
    if view["vulns"] and not view["actions"]:
        notes.append({"kind": "info", "title": "No traffic",
                      "body": "This campaign carries vulnerability expectations only. No packets exercise a CVE."})
    elif view["vulns"]:
        notes.append({"kind": "info", "title": "Vulnerabilities are expectations",
                      "body": "CVE identifiers are carried for the coverage view. No traffic exercises them."})
    fams = _families(view)
    if fams:
        notes.append({"kind": "info", "title": "Beacon profile",
                      "body": "Beacons follow the profile for: %s. Cadence and sizes come from that profile."
                              % ", ".join(fams)})
    notes.append({"kind": "warn", "title": "Device role may shift in the platform",
                  "body": "Traffic from a campaign can change how the platform classifies a participating device "
                          "while it runs. The deviation reflects the scenario, not a generation defect."})
    return notes


def _is_ot_action(a):
    try:
        A = _actions()
        s = _spec(A, a["action"])
        return bool(s is not None and getattr(s, "ot", False))
    except Exception:                                            # noqa: BLE001 - a failed check is treated as false
        return False


def _families(view):
    out = []
    try:
        from netgen.campaign import families
        for a in view["actions"]:
            p = a["params"].get("profile")
            if p:
                f = families.lookup(p)
                name = (f or {}).get("name") or (f or {}).get("id")
                if name and name not in out:
                    out.append(str(name))
    except Exception:                                            # noqa: BLE001 - best-effort lookup, falls back to a neutral value so the diagram still renders
        pass
    return out

#!/usr/bin/env python3
"""Rebuild the campaign diagram fixtures (M4b): the 15 forms of campaign-diagram-plan.md section 2.

    cd dev && python3 tests/fixtures/campaigns/make_fixtures.py [--check]

Writes, beside this script, for every form NN-<name>:
    NN-<name>.json            the campaign file (schema v1; form 9 is intentionally without stages, form 10 is a list of two)
    NN-<name>.summary.json    a synthetic run summary (the build summary's `campaign` block): entries, iocs, estimate, errors, emitted
    NN-<name>.score.json      form 15 only: a sensor result of the shape the scoring step returns
    forms.json                form number, title, what the form has, and the expected panel inclusion

No network and no random numbers: indicator lists are synthesised here, campaigns come from the real compiler where a form is
feed-built (forms 1, 4, 9) and are written by hand elsewhere, and the run summaries are made by a small deterministic generator
that imitates the runner's entries (hosts, ts, first and last ts, packets, bytes, status, protocols, techniques, ioc). The
summaries are fabricated, not captured: they exist to exercise layout and panels, never as evidence of what a build emits.
`--check` rebuilds in memory and reports files that differ from the ones on disk (exit status 1).
"""
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, DEV)

from netgen import model                                         # noqa: E402
from netgen.campaign import actions, addressing, compiler, hosts as HOSTS, runner, schema   # noqa: E402

model.set_capture_day("2026-11-20")                              # pinned so the fixture bytes never depend on today's date
REG = actions.load_all()
# first inventory address per host name (the firewall appears three times; the inside user leg comes first)
_first = {}
for _h in json.load(open(os.path.join(DEV, "inventory.json")))["hosts"]:
    _first.setdefault(_h["hostname"], _h["ip"])
INVENTORY = _first
INTERNAL = {"ws": "EXL-WS-047", "ws2": "EXL-WS-012", "any_ws": "EXL-WS-031", "server": "EXL-FILE1", "dc": "EXL-DC1",
            "file": "EXL-FILE1", "sql": "EXL-SQL1", "web": "EXL-WEB1", "fw": "EXL-FW1"}


def _h(*parts):
    return int(hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:12], 16)


# ------------------------------------------------------------------ indicators (synthetic; never contacted)
def _ip(i, base=185):
    return "%d.%d.%d.%d" % (base, 20 + (i * 7) % 200, 1 + (i * 13) % 250, 2 + (i * 29) % 250)


def ioc(t, v, role, **kw):
    d = {"type": t, "value": v, "role": role, "confidence": kw.pop("confidence", 70), "source": kw.pop("source", "fixture-feed"),
         "tags": kw.pop("tags", []), "techniques": kw.pop("techniques", [])}
    d.update(kw)
    return d


def feed_iocs(n_c2=9, n_payload=7, n_exfil=4, n_scan=3, n_brute=3, n_phish=3, n_tor=3, n_cve=4, n_hash=10):
    out = []
    words = ["cdn", "sync", "update", "static", "mail", "api", "docs", "login", "files", "metrics", "edge", "relay"]
    tlds = ["net", "org", "info", "io", "xyz"]
    for i in range(n_c2):
        out.append(ioc("domain", "%s-%d.c2host-%d.%s" % (words[i % 12], i, i % 5, tlds[i % 5]), "c2", tags=["c2"], techniques=["T1071.001"]))
        out.append(ioc("ipv4", _ip(i), "c2", tags=["c2"]))
    for i in range(n_payload):
        out.append(ioc("url", "http://dl%d.payload-%d.%s/%s/file%d.bin" % (i, i % 4, tlds[i % 5], words[i % 12], i), "payload", techniques=["T1105"]))
    for i in range(n_exfil):
        out.append(ioc("domain", "drop%d.exfil-%d.%s" % (i, i, tlds[i % 5]), "exfil", techniques=["T1041"]))
        out.append(ioc("ipv4", _ip(40 + i, 91), "exfil"))
    for i in range(n_scan):
        out.append(ioc("ipv4", _ip(60 + i, 45), "scanner"))
    for i in range(n_brute):
        out.append(ioc("ipv4", _ip(70 + i, 193), "brute"))
    for i in range(n_phish):
        out.append(ioc("domain", "login-portal%d.secure-%d.%s" % (i, i, tlds[i % 5]), "phishing", techniques=["T1566.002"]))
    for i in range(n_tor):
        out.append(ioc("ipv4", _ip(80 + i, 176), "tor", tags=["tor"]))
    for i in range(n_cve):
        out.append(ioc("cve", "CVE-2024-%d" % (21000 + i * 17), "vulnerability", techniques=["T1190"]))
    for i in range(n_hash):
        out.append(ioc("sha256", "%064x" % _h("hash", i), "unknown"))
    out.append(ioc("email", "billing@invoice-help.example", "phishing"))
    out.append(ioc("filename", "invoice_2024.iso", "unknown"))
    return out


# ------------------------------------------------------------------ campaign assembly
def act(token, frm, to, params=None, ioc_idx=None, at=None, explain=""):
    a = {"action": token, "from": frm, "to": to, "params": params or {}, "ioc": list(ioc_idx or []), "explain": explain}
    if at is not None:
        a["at"] = at
    return a


def stage(sid, tactic, name, acts, narrative="", duration=120, techniques=None):
    return {"id": sid, "name": name, "tactic": tactic, "techniques": techniques or [], "narrative": narrative,
            "duration_s": duration, "fast_s": max(10, duration // 4), "actions": acts}


def camp(name, stages, iocs=None, options=None, desc="", seed=7, expect=None, actor="Unattributed"):
    stages = copy.deepcopy(stages)
    for st in stages:
        ts = []
        for a in st["actions"]:
            for t in REG[a["action"]].techniques:
                if t not in ts:
                    ts.append(t)
        st["techniques"] = st["techniques"] or ts
    c = {"schema": schema.SCHEMA_ID,
         "meta": {"name": name, "id": "", "description": desc, "actor": actor, "origin_country": "", "created": "2026-11-20",
                  "seed": seed, "source": {"kind": "hand"} if not iocs else {"kind": "iocs", "feeds": ["fixture-feed"], "ioc_count": len(iocs)}},
         "options": options or {}, "iocs": iocs or [], "stages": stages,
         "expect": expect if expect is not None else [{"technique": t, "stage": s["id"]} for s in stages for t in s["techniques"]],
         "explain": []}
    return schema.normalise(c)


# ------------------------------------------------------------------ the run-summary generator
_COUNT = ("count", "sessions", "bursts", "attempts", "beacons", "queries", "connections", "files", "visits")


def _ext_host(camp_, ref):
    found = HOSTS.find_ioc(camp_, ref)
    if found is None:
        return {"name": "attacker", "ip": "198.18.200.9"}
    _i, ioc_ = found
    ip, dom = HOSTS.ioc_host_text(ioc_)
    addr = HOSTS.address_for(ioc_, camp_)
    return {"name": dom or ip or addr, "ip": addr}


def _int_host(ref):
    if ref in INTERNAL:
        n = INTERNAL[ref]
    elif ref.startswith("host:"):
        n = "EXL-" + ref[5:]
    else:
        n = "EXL-" + ref
    return {"name": n, "ip": INVENTORY.get(n, "10.10.20.250")}


def fake_summary(camp_, overrides=None, label=None):
    """Imitate the runner's campaign report block for `camp_` without building a capture.
    overrides: {entry index: ("skipped"|"failed", message)}."""
    overrides = overrides or {}
    camp_ = dict(camp_)
    opts = dict(camp_.get("options") or {})
    camp_["options"] = opts
    camp_["_map"] = addressing.mapped_table(camp_.get("iocs") or [], HOSTS._seed(camp_))
    options = runner._options(camp_)
    t = runner._start_ts(options)
    entries, errors, stages = [], [], []
    idx = 0
    for st in camp_["stages"]:
        length, full = runner._stage_len(st, options)
        ratio = length / full if full else 1.0
        stages.append({"id": st["id"], "name": st["name"], "tactic": st["tactic"], "techniques": list(st["techniques"]),
                       "narrative": st.get("narrative", ""), "start": t, "length_s": length})
        n = max(1, len(st["actions"]))
        for i, a in enumerate(st["actions"]):
            spec = REG[a["action"]]
            eff = dict({k: d.get("default") for k, d in spec.params.items()}, **(a.get("params") or {}))
            e = {"campaign": label or camp_["meta"]["id"], "stage": st["id"], "stage_name": st["name"], "action": a["action"],
                 "from": a["from"], "to": a["to"], "ioc": [], "explain": a.get("explain", ""), "params": eff, "ts": None,
                 "packets": 0, "bytes": 0, "protocols": list(spec.protocols), "techniques": list(spec.techniques),
                 "status": "skipped", "error": None}
            entries.append(e)
            ov = overrides.get(idx)
            idx += 1
            if ov and ov[0] == "skipped":
                e["error"] = ov[1]
                errors.append({"stage": st["id"], "action": a["action"], "error": ov[1]})
                continue
            fh = _ext_host(camp_, a["from"]) if HOSTS.is_external_ref(a["from"]) else _int_host(a["from"])
            th = _ext_host(camp_, a["to"]) if HOSTS.is_external_ref(a["to"]) else _int_host(a["to"])
            e["from_host"], e["to_host"] = fh, th
            ids = set(a.get("ioc") or [])
            for ref in (a["from"], a["to"]):
                if HOSTS.is_external_ref(ref):
                    f = HOSTS.find_ioc(camp_, ref)
                    if f:
                        ids.add(f[0])
            e["ioc"] = sorted(ids)
            at = a.get("at")
            ts = t + (float(at) * ratio if at is not None else (i / n) * length * 0.9)
            e["ts"] = ts
            if ov and ov[0] == "failed":
                e["status"], e["error"] = "failed", ov[1]
                errors.append({"stage": st["id"], "action": a["action"], "error": ov[1]})
                continue
            reps = 1
            for k in _COUNT:
                if isinstance(eff.get(k), int) and eff[k] > 0:
                    reps = eff[k]
                    break
            reps = min(reps, 400)
            h = _h(a["action"], a["from"], a["to"], idx)
            pk = reps * (6 + h % 9) + 8
            e["status"], e["packets"] = "ok", pk
            e["bytes"] = pk * (110 + (h >> 8) % 700)
            span = float(eff.get("interval_s") or spec.min_duration_s or 1.0) * reps if reps > 1 else spec.min_duration_s
            e["first_ts"] = ts + 0.05
            e["last_ts"] = ts + max(0.3, min(span, length * 0.9))
        t += length + runner.STAGE_GAP_S
    ok = sum(1 for e in entries if e["status"] == "ok")
    return {"id": label or camp_["meta"]["id"], "name": camp_["meta"]["name"], "meta": camp_["meta"], "options": options,
            "stages": stages, "entries": entries, "iocs": runner._ioc_table(camp_), "estimate": runner.estimate(camp_),
            "errors": errors, "emitted": ok}


def fake_score(summary):
    """A sensor result shaped like the scoring step's body, from a fixed pattern over the entries."""
    cycle = ["detected", "related", "missed", "detected", "detected", "missed"]
    acts, techs, seen = [], {}, []
    for i, e in enumerate(summary["entries"]):
        st = "not_run" if e["status"] != "ok" else cycle[i % len(cycle)]
        acts.append({"stage": e["stage"], "action": e["action"], "ts": e["ts"], "status": st, "detections": []})
        if e["status"] == "ok":
            for t in e["techniques"]:
                techs.setdefault(t, {"technique": t, "name": "", "tactic": "", "status": st, "stages": [e["stage"]],
                                     "actions": [e["action"]], "detections": [], "note": "fixture"})
                if t not in seen:
                    seen.append(t)
    n = len(techs)
    nd = sum(1 for x in techs.values() if x["status"] == "detected")
    nr = sum(1 for x in techs.values() if x["status"] == "related")
    return {"sensor": "fixture-sensor", "time": "2026-11-20T10:00:00Z", "count": nd + nr,
            "score": {"testable": n, "detected": nd, "partial": nr, "missed": n - nd - nr,
                      "percent": round(100.0 * (nd + 0.5 * nr) / n, 1) if n else 0, "by_tactic": {}},
            "techniques": [techs[t] for t in seen], "actions": acts,
            "vulnerabilities": {"count": 0, "note": "carried as expectations; no traffic exercises a CVE"},
            "detections": [], "unmatched": 0, "below_min_risk": 0}


# ------------------------------------------------------------------ the forms
def f01():
    c = compiler.compile_campaign(feed_iocs(), {"include": list(schema.ALL_INCLUDES), "beacons_per_c2": 6}, "Feed-built campaign")
    return c


def f02():
    st = [
        stage("s1", "discovery", "Look around", [
            act("ldap_recon", "ws", "dc", {}, explain="Directory lookups from the workstation"),
            act("smb_share_enum", "ws", "file", {}, explain="Share listing"),
            act("port_probe", "ws", "sql", {}, explain="Probe the database port")], "The operator maps the network.", 90),
        stage("s2", "credential-access", "Get tickets", [
            act("kerberoast", "ws", "dc", {}), act("kerberos_spray", "ws", "dc", {})], "Tickets are requested and guessed.", 80),
        stage("s3", "lateral-movement", "Move", [
            act("smb_admin_exec", "ws", "file", {}), act("rdp_session", "ws", "server", {"duration_s": 120})],
            "The operator hops to the file server.", 120)]
    return camp("Hand-built, roles only", st, [], {"include": []}, "No indicators: every actor is a role.", 2)


def f03():
    i = [ioc("domain", "cdn-sync.c2host-1.net", "c2")]
    return camp("Single action", [stage("s1", "command-and-control", "Check in", [
        act("https_beacon", "ws", "c2:0", {"count": 6, "interval_s": 60}, [0], explain="One workstation checks in")], "A single beacon.", 300)],
        i, {"include": []}, "One stage, one action.", 3)


def f04():
    i = [ioc("domain", "updates.sync-cdn.net", "c2", tags=["cobaltstrike"]), ioc("ipv4", "185.44.12.9", "c2", tags=["cobaltstrike"]),
         ioc("domain", "cdn.edge-relay.org", "c2", tags=["sliver c2"])]
    return compiler.compile_campaign(i, {"include": [], "beacons_per_c2": 12, "family": "cobalt-strike"}, "Beacon only, with a family")


def f05():
    i = [ioc("ipv4", "193.32.7.15", "brute"), ioc("ipv4", "45.88.4.21", "scanner"), ioc("ipv4", "91.201.14.3", "scanner"),
         ioc("domain", "probe.scan-net.org", "scanner")]
    st = [stage("s1", "reconnaissance", "Outside scan", [
        act("port_probe", "scanner:0", "web", {}, [1]), act("syn_scan", "scanner:1", "server", {}, [2]),
        act("web_dir_scan", "scanner:2", "web", {"count": 60}, [3])], "Scanners look at the exposed hosts.", 200),
        stage("s2", "initial-access", "Try the doors", [
            act("web_login_spray", "brute:0", "web", {"attempts": 40}, [0]),
            act("exposed_service_login", "brute:0", "server", {"service": "rdp", "attempts": 8}, [0]),
            act("rdp_brute", "brute:0", "server", {"attempts": 30}, [0]),
            act("ssh_brute", "brute:0", "file", {}, [0])], "Passwords are sprayed against exposed services.", 300)]
    return camp("Inbound only", st, i, {"include": []}, "Everything comes from outside.", 5)


def _mixed_stages():
    return [stage("s1", "initial-access", "Probe and spray", [
        act("web_dir_scan", "scanner:0", "web", {"count": 40}, [1]), act("web_login_spray", "brute:0", "web", {"attempts": 30}, [0])],
        "The web server is probed and sprayed.", 180),
        stage("s2", "command-and-control", "Foothold calls home", [
            act("https_beacon", "ws", "c2:0", {"count": 8, "interval_s": 45}, [2]), act("dns_beacon", "ws", "c2:1", {"count": 10}, [3])],
            "The foothold beacons out.", 400),
        stage("s3", "discovery", "Look around", [act("ldap_recon", "ws", "dc"), act("smb_share_enum", "ws", "file")], "Directory and shares.", 100),
        stage("s4", "exfiltration", "Send data out", [
            act("https_upload", "file", "exfil:0", {"total_bytes": 4000000}, [4]), act("dns_exfil", "ws", "exfil:1", {"queries": 60}, [5])],
            "Data leaves over web and DNS.", 240)]


def _mixed_iocs():
    return [ioc("ipv4", "193.32.7.15", "brute"), ioc("ipv4", "45.88.4.21", "scanner"), ioc("domain", "updates.sync-cdn.net", "c2"),
            ioc("domain", "cdn.edge-relay.org", "c2"), ioc("domain", "drop0.exfil-0.net", "exfil"), ioc("domain", "drop1.exfil-1.org", "exfil")]


def f06():
    return camp("Mixed inbound and outbound", _mixed_stages(), _mixed_iocs(), {"include": []}, "Both directions in one picture.", 6)


def f07():
    st = [stage("s1", "lateral-movement", "Spread", [
        act("smb_admin_exec", "ws", "file"), act("rdp_session", "ws", "server", {"duration_s": 90}), act("wmi_exec", "ws", "sql"),
        act("winrm_exec", "ws", "host:WEB2"), act("ssh_remote_exec", "ws", "host:BATCH1"),
        act("smb_admin_exec", "file", "dc"), act("rdp_session", "server", "host:MES1", {"duration_s": 60}),
        act("wmi_exec", "sql", "host:MESDB1"), act("winrm_exec", "ws2", "host:LOG1")], "The operator hops host to host.", 600),
        stage("s2", "persistence", "Dig in", [
            act("remote_schtask", "file", "host:BACKUP1"), act("svcctl_persist", "dc", "host:LIMS1"), act("smb_admin_exec", "dc", "host:WEB3")],
            "Persistence on the new hosts.", 200),
        stage("s3", "credential-access", "Collect keys", [act("dcsync", "dc", "dc"), act("kerberoast", "ws2", "dc")], "Keys from the directory.", 90)]
    return camp("Lateral-heavy", st, [], {"include": []}, "Many internal hops.", 7)


def f08():
    st = [stage("s1", "discovery", "Reach the plant", [
        act("port_probe", "ws", "host:OTJUMP1"), act("rdp_session", "ws", "host:OTJUMP1", {"duration_s": 120}),
        act("smb_share_enum", "host:OTJUMP1", "host:OTFS1"), act("syn_scan", "host:OTJUMP1", "host:SCADA1", {"scope": "targets", "targets": ["10.30.0.20"]}),
        act("winrm_exec", "host:OTJUMP1", "host:OTENG1")], "A foothold reaches the plant network.", 400),
        stage("s2", "command-and-control", "Beacon out", [act("https_beacon", "ws", "c2:0", {"count": 5})], "The foothold calls out.", 300)]
    return camp("Touches the OT zone", st, [ioc("domain", "updates.sync-cdn.net", "c2")], {"include": []}, "Hops through the jump host.", 8)


def f09():
    i = [ioc("cve", "CVE-2024-21001", "vulnerability", techniques=["T1190"]), ioc("cve", "CVE-2023-44487", "vulnerability", techniques=["T1499.002"]),
         ioc("cve", "CVE-2024-3400", "vulnerability", techniques=["T1190", "T1059"])]
    return compiler.compile_campaign(i, {"include": []}, "Vulnerability only")


def f10():
    a = camp("First of two", _mixed_stages()[:2], _mixed_iocs(), {"include": []}, "Campaign A of two in one capture.", 10)
    b = camp("Second of two", f07()["stages"][:2], [], {"include": [], "start": "14:30"}, "Campaign B of two in one capture.", 11)
    b["meta"]["id"] = "second-of-two"
    a["meta"]["id"] = "first-of-two"
    return [a, b]


def f11():
    return camp("Partly failed", _mixed_stages(), _mixed_iocs(), {"include": []}, "Some actions did not run.", 12)


def f12():
    iocs = feed_iocs(n_c2=25, n_payload=15, n_exfil=10, n_scan=8, n_brute=8, n_phish=8, n_tor=6, n_cve=0, n_hash=0)
    byrole = {}
    for i, x in enumerate(iocs):
        if x["type"] in ("ipv4", "domain"):
            byrole.setdefault(x["role"], []).append(i)
    urls = [i for i, x in enumerate(iocs) if x["type"] == "url"]
    ws = ["host:WS-%03d" % n for n in range(1, 76)]
    tgt = ["file", "dc", "sql", "web", "host:WEB2", "host:MES1", "host:BATCH1", "host:LOG1", "host:BACKUP1", "host:LIMS1", "host:NTP1", "host:HIST1"]
    templates = [
        ("command-and-control", "https_beacon", "ws", "c2", {"count": 3, "interval_s": 30}),
        ("command-and-control", "dns_beacon", "ws", "c2", {"count": 6}),
        ("exfiltration", "https_upload", "tgt", "exfil", {"total_bytes": 800000}),
        ("discovery", "smb_share_enum", "ws", "tgt", {}),
        ("discovery", "ldap_recon", "ws", "dc", {}),
        ("lateral-movement", "rdp_session", "ws", "tgt", {"duration_s": 40}),
        ("lateral-movement", "smb_admin_exec", "ws", "tgt", {}),
        ("credential-access", "kerberoast", "ws", "dc", {}),
        ("initial-access", "web_login_spray", "brute", "web", {"attempts": 12}),
        ("reconnaissance", "port_probe", "scanner", "tgt", {}),
        ("initial-access", "phishing_visit", "ws", "phish", {}),
        ("execution", "payload_download", "ws", "payload", {}),
    ]
    stages, k, nact = [], 0, 0
    for s in range(60):
        n = 7 if s < 40 else 6
        acts, tactic_votes = [], {}
        for j in range(n):
            tac, tok, f, t, params = templates[(k * 5 + j) % len(templates)]
            k += 1

            def pick(role):
                if role == "ws":
                    return ws[(k * 3 + j) % len(ws)]
                if role == "tgt":
                    return tgt[(k + j) % len(tgt)]
                if role in ("dc", "web"):
                    return role
                if role == "payload":
                    return "ioc:%d" % urls[(k + j) % len(urls)]
                if role == "phish":
                    return "phish:%d" % ((k + j) % len(byrole["phishing"]))
                return "%s:%d" % (role, (k + j) % len(byrole[role]))
            acts.append(act(tok, pick(f), pick(t), params))
            tactic_votes[tac] = tactic_votes.get(tac, 0) + 1
            nact += 1
        stages.append(stage("s%d" % (s + 1), max(tactic_votes, key=lambda x: (tactic_votes[x], x)), "Wave %d" % (s + 1), acts,
                            "Wave %d of a long campaign." % (s + 1), 60))
    assert nact == 400, nact
    return camp("Very large", stages, iocs, {"include": []}, "60 stages, 400 actions.", 13)


def f13():
    i = [ioc("ipv4", "185.234.72.11", "c2", tags=["c2"]), ioc("domain", "mail.update-service.net", "c2"),
         ioc("ipv4", "91.215.85.40", "exfil"), ioc("url", "http://dl.fast-files.org/stage/pack.bin", "payload")]
    st = [stage("s1", "execution", "Fetch", [act("payload_download", "ws", "ioc:3", {"path": "/stage/pack.bin"}, [3])], "A tool is fetched.", 90),
          stage("s2", "command-and-control", "Beacon", [act("https_beacon", "ws", "c2:0", {"count": 6}, [0]), act("dns_beacon", "ws", "c2:1", {"count": 8}, [1])],
                "Check-ins.", 400),
          stage("s3", "exfiltration", "Out", [act("https_upload", "file", "exfil:0", {"total_bytes": 2000000}, [2])], "Data leaves.", 200)]
    return camp("Real addresses", st, i, {"include": [], "address_mode": "real"}, "Indicators keep their real public addresses.", 14)


def f14():
    return camp("Plan only", _mixed_stages()[1:], _mixed_iocs(), {"include": []}, "Never run; planned offsets only.", 15)


def f15():
    return camp("Scored", _mixed_stages(), _mixed_iocs(), {"include": []}, "Run and scored against a sensor.", 16)


FORMS = [
    # (number, file stem, builder, title, has_summary, overrides, has_score)
    (1, "01-feed-built", f01, "Feed-built, indicator-heavy", True, None, False),
    (2, "02-hand-built", f02, "Hand-built, no indicators", True, None, False),
    (3, "03-single-action", f03, "Single stage, single action", True, None, False),
    (4, "04-beacon-only", f04, "Beacon-only with a family", True, None, False),
    (5, "05-inbound", f05, "Inbound only", True, None, False),
    (6, "06-mixed", f06, "Mixed inbound and outbound", True, None, False),
    (7, "07-lateral-heavy", f07, "Lateral-heavy", True, None, False),
    (8, "08-ot", f08, "Touches the OT zone", True, None, False),
    (9, "09-vuln-only", f09, "Vulnerability only", False, None, False),
    (10, "10-two-campaigns", f10, "Two campaigns in one capture", True, None, False),
    (11, "11-partial", f11, "Partly failed or skipped", True,
     {2: ("skipped", "the built environment has no host EXL-WEB2 (needed by the campaign)"),
      5: ("failed", "ValueError: no route to the target"), 7: ("skipped", "falls after the end of the capture day")}, False),
    (12, "12-very-large", f12, "Very large", True, "large", False),
    (13, "13-real-addresses", f13, "Real address mode", True, None, False),
    (14, "14-plan-only", f14, "Plan only, never run", False, None, False),
    (15, "15-scored", f15, "Scored against a sensor", True, None, True),
]

ALL_PANELS = ["header", "plain", "timeline", "flowmap", "stages", "trace", "coverage", "filters", "notes"]
OMIT = {2: ["trace"], 7: ["trace"], 9: ["timeline", "flowmap", "stages", "filters"]}


def _dump(obj):
    return json.dumps(obj, indent=1, sort_keys=True) + "\n"


def build_all():
    files, forms = {}, {}
    for num, stem, fn, title, has_sum, ov, has_score in FORMS:
        c = fn()
        files[stem + ".json"] = _dump(c)
        camps = c if isinstance(c, list) else [c]
        errs = []
        for x in camps:
            errs += schema.validate(x)
        summary = None
        if has_sum:
            if num == 10:
                summary = [fake_summary(x, label=x["meta"]["id"]) for x in camps]
            else:
                over = ov
                if ov == "large":
                    over = {i: ("skipped", "the built environment has no such host") for i in range(37, 400, 97)}
                summary = fake_summary(c, over)
            files[stem + ".summary.json"] = _dump(summary)
        if has_score:
            files[stem + ".score.json"] = _dump(fake_score(summary))
        stages = sum(len(x["stages"]) for x in camps)
        actions_n = sum(len(s["actions"]) for x in camps for s in x["stages"])
        forms[stem + ".json"] = {
            "form": num, "title": title, "campaigns": len(camps), "stages": stages, "actions": actions_n,
            "valid": not errs, "validation_errors": errs[:3],
            "summary": has_sum, "score": has_score, "mode": "scored" if has_score else ("run" if has_sum else "plan"),
            "panels": {p: (p not in OMIT.get(num, [])) for p in ALL_PANELS},
            "address_mode": camps[0]["options"].get("address_mode", "mapped"),
            "ot": num == 8, "inbound": num in (5, 6, 10, 11, 12, 15), "indicators": sum(len(x["iocs"]) for x in camps)}
    files["forms.json"] = _dump(forms)
    return files


def main(argv):
    files = build_all()
    if "--check" in argv:
        bad = [n for n, t in sorted(files.items()) if not os.path.exists(os.path.join(HERE, n)) or open(os.path.join(HERE, n)).read() != t]
        print("differ: %s" % (", ".join(bad) or "none"))
        return 1 if bad else 0
    for n, t in sorted(files.items()):
        with open(os.path.join(HERE, n), "w") as f:
            f.write(t)
    print("wrote %d files" % len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

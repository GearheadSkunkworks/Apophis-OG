"""
Incident library for the Example demo network.

Every incident is a builder that schedules additive fault traffic onto the
Engine under a tag "incident:<name>" so the side-writer can peel it into its
own pcap. Builders reuse the normal-traffic primitives in flows.py and the
payload builders in protocols.py, so the fault traffic is the same wire-format
(Ethernet II / RFC 791 IPv4, observable ARP, correct checksums) as the day.

Categories and filename prefixes:
    NDR  security detections (attacker = compromised workstation)
    NPM  network-performance faults
    CRP  crypto-posture issues

Registry entries: name -> Incident(prefix, slug, title, window, builder, note).
`--incident <name>` (repeatable) selects them; see model.py.
"""
import base64
import bisect
import math
import os
import random
import string
import struct
import sys
import time

from . import flows as F
from . import protocols as P
from . import tls as TLS
from .core import Host, SYN, ACK, RST, PSH, eth, ipv4, ETH_IP
from .identity import H, get_current, DEFAULT as _TEMPLATE

SEED = 0xA77AC                 # reseeded per build by netgen.reseed_all()
rng = random.Random(SEED)


# --------------------------------------------------------------- infrastructure
# External attacker infrastructure keyed to REAL, publicly-documented malicious
# indicators and real abused services, so a sensor's built-in threat intelligence
# and remote-access/tunnel/cloud-storage detectors match. NOTHING is contacted — the
# generator only writes packets whose destination fields carry these addresses, for
# lab replay/validation. Sources: abuse.ch ThreatFox (Cobalt Strike C2, 2026-09-16),
# abuse.ch Feodo Tracker (QakBot C2), and the real IPs of legitimately-abused services.
# See INDICATORS below and the exported threat collection for provenance.
EXT_HOSTS = {
    #  key            hostname (SNI/DNS)              destination IP      hops
    "c2":         ("cdn-sync.fastcache-cdn.net",   "47.243.191.83",   12),   # Cobalt Strike C2 (ThreatFox)
    "rmm":        ("boot.net.anydesk.com",         "185.229.190.236", 11),   # AnyDesk RMM cloud (real, abused)
    "ngrok":      ("connect.ngrok-agent.com",      "3.12.62.205",     13),   # ngrok tunnel (real, abused)
    "exfil":      ("g.api.mega.co.nz",             "66.203.125.11",   14),   # MEGA cloud storage (real, exfil)
    "dnsns":      ("ns1.telemetry-sync.io",        "27.133.154.218",  10),   # tunneling NS (QakBot C2 IP, Feodo)
    "cloudflared":("edge.argo-tunnel.net",         "144.225.246.14",  12),   # Cobalt Strike C2 (ThreatFox) — Akira
    "cobaltc2":   ("cdn.jquery-static.net",        "5.104.86.108",    12),   # Cobalt Strike C2 (ThreatFox) — Black Basta/Play
    "medusa_c2":  ("api.sync-service.net",         "123.60.142.164",  12),   # Cobalt Strike C2 (ThreatFox) — Medusa
    "telegram":   ("api.telegram.org",             "149.154.166.110", 15),   # Telegram bot API C2 (real, abused) — Handala
    "ipcheck":    ("icanhazip.com",                "104.16.184.241",  14),   # icanhazip IP check (real, abused) — Handala
    "needy_c2":   ("corp.tripswithengine.com",     "104.21.81.147",   12),   # NeedyMantis C2 (Microsoft 2026-09-28); Cloudflare-fronted, so the edge IP is what is on the wire
    "flux_c2":    ("sync-7f3a.livefeed-cdn.net",   "91.211.247.42",   13),   # fast-flux / DGA C2 (abuse.ch ThreatFox 2026); the documented anchor IP -- one of several nodes the name answers to, see FLUX_POOL in incidents.py
    "stealer":    ("panel.redtraffic-stats.top",   "45.139.104.77",   14),   # Lumma-class infostealer exfil panel (abuse.ch ThreatFox 2026)
}
# Full provenance for the exportable threat collection (STIX/CSV). type: ip|domain.
INDICATORS = [
    ("47.243.191.83",   "domain:cdn-sync.fastcache-cdn.net", "Cobalt Strike", "sec.c2",    "abuse.ch ThreatFox 2026-09-16"),
    ("144.225.246.14",  "domain:edge.argo-tunnel.net",       "Cobalt Strike", "sec.c2",    "abuse.ch ThreatFox 2026-09-16"),
    ("5.104.86.108",    "domain:cdn.jquery-static.net",      "Cobalt Strike", "sec.c2",    "abuse.ch ThreatFox 2026-09-16"),
    ("123.60.142.164",  "domain:api.sync-service.net",       "Cobalt Strike", "sec.c2",    "abuse.ch ThreatFox 2026-09-16"),
    ("27.133.154.218",  "domain:ns1.telemetry-sync.io",      "QakBot",        "sec.c2",    "abuse.ch Feodo Tracker"),
    ("185.229.190.236", "domain:boot.net.anydesk.com",       "AnyDesk (RMM)", "sec.remote-access", "abused legitimate service"),
    ("3.12.62.205",     "domain:connect.ngrok-agent.com",    "ngrok (tunnel)","sec.c2",    "abused legitimate service"),
    ("66.203.125.11",   "domain:g.api.mega.co.nz",           "MEGA (exfil)",  "sec.exfil", "abused legitimate service"),
    ("149.154.166.110", "domain:api.telegram.org",           "Telegram (C2)", "sec.c2",    "abused legitimate service"),
    ("104.16.184.241",  "domain:icanhazip.com",              "icanhazip",     "sec.recon", "abused legitimate service"),
    ("104.21.81.147",   "domain:corp.tripswithengine.com",   "NeedyMantis",   "sec.c2",    "Microsoft Threat Intelligence 2026-09-28"),
    ("91.211.247.42",   "domain:sync-7f3a.livefeed-cdn.net",  "FastFlux",      "sec.c2",    "abuse.ch ThreatFox 2026 (fast-flux)"),
    ("45.139.104.77",   "domain:panel.redtraffic-stats.top",  "Lumma",         "sec.exfil", "abuse.ch ThreatFox 2026 (infostealer)"),
]
TUNNEL_DOMAIN = "sync.telemetry-sync.io"
ATTACKER_WS = H("WS-047")          # the compromised foothold on the user subnet
# A second, UNRELATED compromise. NeedyMantis arrives through trojanised legitimate software,
# not the hands-on-keyboard phish that EXL-WS-047 represents, so it is a different host with no
# lateral path to the first. EXL-WS-031 is an IT/engineering workstation -- the kind that
# plausibly has the dev tools the implant sideloads into.
NEEDY_WS = H("WS-031")
# Its own server targets, disjoint from VICTIM_SERVERS, so correlating the two campaigns by
# shared victims is wrong by construction.
NEEDY_TARGETS = (H("WEB2"), H("PRINT1"), H("LOG1"))


def used_indicator_ips(ctx):
    """The external hosts a completed build actually materialized.

    `ext()` is the only way an EXT_HOSTS entry becomes a Host, and it caches into
    `ctx._ext`, so after eng.run() this is exactly the set of indicators present in the
    capture. Deriving it this way means module->indicator attribution cannot drift out of
    sync with the builders, which a hand-maintained table would.
    """
    return {EXT_HOSTS[k][1] for k in getattr(ctx, "_ext", {}) if k in EXT_HOSTS}


def threat_collection(stix_path=None, csv_path=None, only_ips=None):
    """Write the embedded external indicators as an importable threat collection:
    a STIX 2.1 bundle (import into the platform / any TIP) and a flat CSV. Returns counts.

    `only_ips` restricts the export to indicators actually present in the capture (see
    used_indicator_ips). That matters when only some incident modules were selected:
    exporting C2 indicators for modules that were not built would import cleanly and then
    match nothing, which looks like a broken demo. None exports everything.
    """
    import json as _json, uuid as _uuid, datetime as _dt, csv as _csv, os as _os
    # The indicators describe THIS capture, so they are valid from the day it covers. A fixed
    # literal here meant the export claimed validity from a date unrelated to the traffic --
    # already true before the capture day became relative (the capture was the 14th, this
    # said the 16th).
    from .model import capture_day as _cd
    _y, _m, _d = _cd()
    now = _dt.datetime(_y, _m, _d, tzinfo=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objs = []
    rows = []
    for ip, dom, malware, category, source in INDICATORS:
        if only_ips is not None and ip not in only_ips:
            continue
        dom = dom.split(":", 1)[1] if dom.startswith("domain:") else dom
        for kind, value, patt in (("ipv4-addr", ip, f"[ipv4-addr:value = '{ip}']"),
                                   ("domain-name", dom, f"[domain-name:value = '{dom}']")):
            objs.append({
                "type": "indicator", "spec_version": "2.1",
                "id": "indicator--" + str(_uuid.uuid4()),
                "created": now, "modified": now,
                "name": f"{malware} {kind} {value}",
                "description": f"Example demo indicator ({malware}; {category}). Source: {source}.",
                "indicator_types": ["malicious-activity"],
                "pattern": patt, "pattern_type": "stix", "valid_from": now,
                "labels": [malware.lower().split(" ")[0], category],
            })
            rows.append({"indicator": value, "type": kind, "malware": malware,
                         "category": category, "source": source})
    bundle = {"type": "bundle", "id": "bundle--" + str(_uuid.uuid4()), "objects": objs}
    stix_path = stix_path or "example-threat-collection.stix.json"
    csv_path = csv_path or "example-threat-collection.csv"
    for p in (stix_path, csv_path):
        d = _os.path.dirname(p)
        if d:
            _os.makedirs(d, exist_ok=True)
    with open(stix_path, "w") as f:
        _json.dump(bundle, f, indent=1)
    with open(csv_path, "w", newline="") as f:
        w = _csv.DictWriter(f, fieldnames=["indicator", "type", "malware", "category", "source"])
        w.writeheader()
        w.writerows(rows)
    return {"indicators": len(rows), "stix": stix_path, "csv": csv_path}


def ext(ctx, key):
    cache = ctx.__dict__.setdefault("_ext", {})
    if key not in cache:
        name, ip, hops = EXT_HOSTS[key]
        h = Host(name.upper(), ip, "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)),
                 "linux", "external", "198.51.100.0/24", name)
        h.hops = hops
        cache[key] = h
    return cache[key]


def attacker(ctx):
    return ctx.h[ATTACKER_WS]


# the servers an attacker actually goes after, as opposed to every host on the subnet
VICTIM_SERVERS = (H("DC1"), H("DC2"), H("FILE1"), H("SQL1"), H("WEB1"), H("BACKUP1"), H("MGMT1"))


def victims_servers(ctx):
    return [ctx.h[n] for n in VICTIM_SERVERS]


def sched_factory(eng, ctx, tag, win):
    lo, hi = win

    def sched(ts, fn, *a, **kw):
        if lo - 120 <= ts <= hi + 300:
            eng.schedule(ts, lambda: fn(ctx, *a, ts=ts, **kw), tag)
    return sched


def sev(ts, win):
    """Severity envelope in [0,1] across a fault window: a short healthy lead-in, a ramp to a
    peak plateau, then a recovery. Builders scale their degradation by this so every NPM capture
    tells a healthy -> degrade -> recover story instead of a flat band."""
    lo, hi = win
    span = max(1.0, hi - lo)
    x = (ts - lo) / span
    if x <= 0.0:
        return 0.0
    if x < 0.15:
        return (x / 0.15) * 0.4
    if x < 0.45:
        return 0.4 + (x - 0.15) / 0.30 * 0.6
    if x < 0.72:
        return 1.0
    if x < 1.0:
        return max(0.0, 1.0 - (x - 0.72) / 0.28)
    return 0.0


def flanks(lo, hi, n=4):
    """Timestamps for healthy pre-roll (before lo) and post-roll (after hi), within the
    scheduler's -120s / +300s allowance, so a fault-only capture opens and closes healthy."""
    pre = sorted(lo - rng.uniform(15, 110) for _ in range(n))
    post = sorted(hi + rng.uniform(15, 110) for _ in range(n))
    return pre, post


# ============================================================ shared primitives
def syn_scan(ctx, src, targets, ts, per=0.004, complete_open=False):
    """A fast SYN scan: src -> each (host, port). Open -> SYN/ACK; closed -> RST/ACK."""
    out = []
    t = ts
    # ARP the gateway / peers once
    seen = set()
    for host, port, is_open in targets:
        if host.ipb[:3] not in seen:
            out += ctx.arp_for(src, host, t)
            seen.add(host.ipb[:3])
        sport = src.eph()
        s = ctx.tcp(src, host, port, t, sport=sport)
        seq = s.cseq
        copts = struct.pack("!BBH", 2, 4, 1460) + b"\x01\x03\x03\x08\x01\x01\x04\x02"
        s._emit(src, host, sport, port, seq, 0, SYN, 64240, b"", copts)
        s.t += s.rtt * rng.uniform(0.5, 1.5)
        if is_open:
            sopts = struct.pack("!BBH", 2, 4, 1460) + b"\x01\x01\x04\x02"
            s._emit(host, src, port, sport, s.sseq, seq + 1, SYN | ACK, 65535, b"", sopts)
            if complete_open:
                s.t += s.rtt / 2
                s._emit(src, host, sport, port, seq + 1, s.sseq + 1, ACK, 64240)
                s.t += rng.uniform(0.001, 0.01)
                s._emit(src, host, sport, port, seq + 1, s.sseq + 1, RST | ACK, 0)
            else:
                s.t += rng.uniform(0.0005, 0.003)
                s._emit(src, host, sport, port, seq + 1, 0, RST, 0)   # half-open teardown: a bare RST carries ack 0 (RFC 9293)
        else:
            s._emit(host, src, port, sport, 0, seq + 1, RST | ACK, 0)
        out += s.drain()
        t += per * rng.uniform(0.4, 1.8)
    return F.merged(out)


def icmp_sweep(ctx, src, hosts, ts, per=0.01, absent=()):
    """A scanner-style echo sweep (nmap -sn shape): one ICMP identifier for the whole sweep, an incrementing
    sequence, no payload; addresses nobody holds draw no reply. TTLs and MACs come from the link resolver."""
    out = []
    t = ts
    ident = rng.randint(1, 65535)
    seq = 0
    targets = [(h, True) for h in hosts] + [(h, False) for h in absent]
    rng.shuffle(targets)
    for h, answers in targets:
        seq += 1
        out += ctx.arp_for(src, h, t) if answers else []
        dmac, smac, ttl = ctx.link.addr(src, h, src)
        out.append((t, eth(dmac, smac, ETH_IP, ipv4(src, h, 1, P.icmp_echo(ident, seq, True, payload=b""), ttl=ttl))))
        if answers:
            dmac, smac, ttl = ctx.link.addr(h, src, src)
            out.append((t + rng.uniform(0.0004, 0.002), eth(dmac, smac, ETH_IP, ipv4(h, src, 1, P.icmp_echo(ident, seq, False, payload=b""), ttl=ttl))))
        t += per * rng.uniform(0.4, 1.8)
    return F.merged(out)


def smb_admin_exec(ctx, src, target, ts, binary_name="update.exe", size=180_000, dll=False):
    """PsExec-style: one TCP connection, one authenticated SMB session, write a service binary
    to ADMIN$, then re-tree to IPC$ and run svcctl create+start on the same session (real
    PsExec never opens a second session for this)."""
    user = "svc_backup"    # a stolen privileged credential
    s, smb, pre = F._smb_open(ctx, src, target, "ADMIN$", ts, user=user)
    path = binary_name
    s.c2s(smb.create_req(path, write=True), think=rng.uniform(0.002, 0.02))
    r, fid = smb.create_resp(s.t, 0)
    s.s2c(r, think=0.0008)
    data = P.pe_blob(size, dll=dll)        # a real PE (MZ/PE header, section table), not random bytes
    off = 0
    while off < size:
        part = data[off:off + 65536]
        s.c2s(smb.write_req(fid, off, part), think=0.0003)
        s.s2c(smb.write_resp(len(part)), think=0.0005)
        off += len(part)
    s.c2s(smb.close_req(fid), think=0.002)
    s.s2c(smb.close_resp(s.t, size), think=0.0008)
    F._smb_untree(s, smb, think=rng.uniform(0.05, 0.3))
    # svcctl over IPC$, same connection/session, a new tree connect
    F._smb_retree(s, smb, target, "IPC$")
    s.c2s(smb.create_req("svcctl", pipe=True), think=0.003)
    r2, fid2 = smb.create_resp(s.t, 0)
    s.s2c(r2, think=0.0008)
    callid = rng.randint(1, 400)
    auth = (user, "cifs", target.fqdn)
    bind = P.dcerpc_bind(callid, P.SVCCTL_UUID, 2, auth=auth)
    s.c2s(smb.write_req(fid2, 0, bind), think=0.001)
    s.s2c(smb.write_resp(len(bind)), think=0.0006)
    s.c2s(smb.read_req(fid2, 0, 1024), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_bind_ack(callid, "\\PIPE\\svcctl", auth=True)), think=0.0008)
    for opnum, rq, rs in ((15, 260, 40), (12, 320, 60), (19, 120, 24)):  # OpenSCManager, CreateService, StartService
        callid += 1
        req = P.dcerpc_request(callid, opnum, P.blob(rq), sealed=True)
        s.c2s(smb.write_req(fid2, 0, req), think=rng.uniform(0.002, 0.01))
        s.s2c(smb.write_resp(len(req)), think=0.0006)
        s.c2s(smb.read_req(fid2, 0, 1024), think=0.0004)
        s.s2c(smb.read_resp(P.dcerpc_response(callid, P.blob(rs), sealed=True)), think=rng.uniform(0.001, 0.01))
    s.c2s(smb.close_req(fid2), think=0.003)
    s.s2c(smb.close_resp(s.t, 0), think=0.0008)
    pk = F._smb_close(s, smb)
    return F.merged(pre, pk)


def wmi_exec(ctx, src, target, ts):
    """WMI remote execution the way Impacket/wmic do it (MS-DCOM): DCOM activation on tcp/135
    (bind ISystemActivator, RemoteCreateInstance returns the object's string bindings, i.e. the
    dynamic port), then a second connection on that port that binds IWbemLevel1Login, IRemUnknown2
    and IWbemServices and runs Win32_Process.Create. Calls are Kerberos-sealed (packet privacy)."""
    out = ctx.arp_for(src, target, ts)
    dport = rng.randint(49152, 49230)
    s = ctx.tcp(src, target, 135, ts + 0.001).handshake()
    cid = rng.randint(1, 200)
    auth = (src.name + "$", "host", target.fqdn)
    s.c2s(P.dcerpc_bind(cid, P.WMI_ACTIVATOR_UUID, 0, auth=auth), think=0.0006)
    s.s2c(P.dcerpc_bind_ack(cid, "135", auth=True), think=0.001)
    s.c2s(P.dcerpc_request(cid + 1, 4, P.blob(rng.randint(480, 620)), sealed=True), think=0.0008)       # RemoteCreateInstance
    s.s2c(P.dcerpc_response(cid + 1, P.blob(rng.randint(620, 780)), sealed=True), think=0.0035)
    pk = s.close(think=0.002)
    s2 = ctx.tcp(src, target, dport, s.t + 0.003).handshake()
    s2.c2s(P.dcerpc_bind(cid + 2, P.WMI_LOGIN_UUID, 0, auth=auth,
                         extra=((P.IREMUNKNOWN2_UUID, 0), (P.WMI_SERVICES_UUID, 0))), think=0.0006)
    s2.s2c(P.dcerpc_bind_ack(cid + 2, str(dport), auth=True, nctx=3), think=0.001)
    # (context id, opnum, request size, reply size): NTLMLogin, RemQueryInterface2, OpenNamespace-style
    # login, then ExecMethod (Win32_Process Create)
    for i, (cx, op, rq, rs) in enumerate(((0, 6, 300, 200), (1, 6, 220, 120), (2, 3, 1400, 400), (2, 24, 700, 6000))):
        s2.c2s(P.dcerpc_request(cid + 3 + i, op, P.blob(rq), sealed=True, ctx_id=cx), think=rng.uniform(0.002, 0.02))
        s2.s2c(P.dcerpc_response(cid + 3 + i, P.blob(rs), sealed=True), think=rng.uniform(0.002, 0.02))
    pk2 = s2.close(think=rng.uniform(0.05, 0.4))
    return F.merged(out, pk, pk2)


# Implant beacon profiles: a real implant calls ONE configured URI with one user agent and a fixed header
# set, carries its metadata in a cookie, and gets a small opaque reply -- it does not browse. Keyed by the
# EXT_HOSTS entry the beacon calls; any other key is an RMM/cloud call-home and keeps the generic shape.
BEACON_PROFILES = {
    "c2":       dict(path="/api/v1/telemetry/collect", ua="Go-http-client/2.0", tls="go", ctype="application/octet-stream",
                     cookie="session"),
    "cobaltc2": dict(path="/jquery-3.3.1.min.js", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
                     tls="winhttp", ctype="application/javascript", cookie="__cfduid"),
    "cobaltc2_bb": dict(path="/vendor/modernizr-2.8.3.min.js", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
                     tls="winhttp", ctype="application/javascript", cookie="__cfduid"),
    "cobaltc2_play": dict(path="/static/bootstrap.bundle.min.js", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
                     tls="winhttp", ctype="application/javascript", cookie="__cfduid"),
}


# RMM/cloud/tunnel infrastructure that is NOT an HTTP service: AnyDesk's call-home and a
# Cloudflare tunnel exchange opaque application data on a persistent connection, not GETs of
# browsing paths. rmm_beacon opens a short channel burst for these; the long-lived tunnel itself
# is ngrok_tunnel / tls_channel.
OPAQUE_CHANNEL_KEYS = {"rmm", "cloudflared"}


def rmm_beacon(ctx, src, key, requests=1, small=True, ts=None, site=None):
    """A single low-and-slow HTTPS beacon to external infra (C2 / RMM cloud), decryptable. C2 keys
    in BEACON_PROFILES use their pinned profile (one URI, one user agent, metadata in a cookie).
    OPAQUE_CHANNEL_KEYS (AnyDesk, Cloudflare tunnel) are not HTTP at all: a short burst on a
    persistent opaque TLS channel instead of GETs.

    site: override the EXT_HOSTS/`key` lookup with a caller-built (fqdn, Host) pair -- for an
    actor-specific team server that is a throwaway, non-exported host, not a shared indicator."""
    site = site or (ext(ctx, key).fqdn, ext(ctx, key))
    if key in OPAQUE_CHANNEL_KEYS:
        return F.tls_channel(ctx, src, site, ts, duration=rng.uniform(90, 240), period=8.0, tls_profile="winhttp", rate=50e6)
    sizes = [rng.randint(180, 900) for _ in range(requests)] if small else None
    prof = BEACON_PROFILES.get(key)
    if prof:
        meta = base64.b64encode(os.urandom(48)).decode().rstrip("=")
        return F.https_session(ctx, src, site, ts, requests=requests, sizes=sizes, keep_open=0.5, rate=50e6, dns=True,
                               ua=prof["ua"], paths=[prof["path"]] * requests, ctype=prof["ctype"], tls_profile=prof["tls"],
                               req_headers=["Accept: */*", "Cookie: %s=%s" % (prof["cookie"], meta)])
    return F.https_session(ctx, src, site, ts, requests=requests, sizes=sizes, keep_open=0.5, rate=50e6, dns=True)


# ================================================================= NDR builders
# Recon shape, lifted to module level so a diagram can render exactly what the builder emits
# instead of restating it (see make_diagram.py). Changing these changes both.
RECON_PORTS = [445, 3389, 1433, 389, 88, 135, 80, 443, 22, 5985]
RECON_OPEN = {H("DC1"): {445, 389, 88, 135, 80}, H("DC2"): {445, 389, 88, 135},
              H("FILE1"): {445, 135}, H("SQL1"): {1433, 445, 135},
              H("WEB1"): {80, 443, 445, 135}, H("BACKUP1"): {22, 445, 443},
              H("MGMT1"): {3389, 445, 135, 5985}}
# seconds after the window opens: (offset, label)
RECON_PHASES = [(5, "ICMP host-discovery sweep"), (40, "TCP SYN port scan"),
                (120, "LDAP directory enumeration"), (260, "SMB share enumeration")]
RECON_SCAN_BATCH = 70                    # SYN probes in the one continuous pass (7 servers x 10 ports)
RECON_LDAP_SESSIONS, RECON_LDAP_QUERIES = 1, 6   # one tool session, six searches (RECON_LDAP_FILTERS)

RECON_LDAP_PAGE = 50                     # paged-results page size (RFC 2696) for the large result sets


RECON_LDAP_FILTERS = (("objectClass", "user"), ("objectClass", "computer"), ("objectClass", "group"),
                      ("servicePrincipalName", "*"), ("adminCount", "1"), ("objectClass", "organizationalUnit"))


# ---- shapes the scenario diagrams read, so a picture can never drift from the builder ----
# credential access
KERBEROAST_SPNS = [("MSSQLSvc", "exl-sql1.corp.example.local"), ("HTTP", "exl-web1.corp.example.local"),
                   ("CIFS", "exl-file1.corp.example.local"), ("HTTP", "intranet.corp.example.local"),
                   ("MSSQLSvc", "exl-sql1.corp.example.local:1433"), ("HTTP", "exl-mgmt1.corp.example.local"),
                   ("TERMSRV", "exl-mgmt1.corp.example.local"), ("LDAP", "exl-dc2.corp.example.local"),
                   ("HOST", "exl-backup1.corp.example.local"), ("WSMAN", "exl-web1.corp.example.local")]
ASREP_ACCOUNTS = ("svc_scan", "svc_legacy", "helpdesk1", "kiosk", "backupjob")
SPRAY_FIRST, SPRAY_LAST = 1, 40          # EXL-WS-001..039 get one password tried
CRED_PHASES = [(10, "Kerberoasting", "TGS-REQ burst, RC4 (etype 23) requested explicitly"),
               (90, "AS-REP roasting", "AS-REQ with no pre-auth for accounts that allow it"),
               (160, "Password spray", "one password across many users; PREAUTH_FAILED"),
               (300, "DCSync", "DRSUAPI DsGetNCChanges from a host that is not a DC")]

# lateral movement: (offset seconds, source, target, technique, RDP duration range or None).
# Listed in the order the builder issues them, which is what keeps rng consumption stable.
LATERAL_PLAN = [(10, ATTACKER_WS, H("MGMT1"), "RDP", (120, 300)),
                (240, ATTACKER_WS, H("FILE1"), "RDP", (90, 240)),
                (60, ATTACKER_WS, H("DC1"), "SMB admin-share exec", None),
                (360, ATTACKER_WS, H("SQL1"), "SMB admin-share exec", None),
                (150, ATTACKER_WS, H("WEB1"), "WMI remote exec", None),
                (500, ATTACKER_WS, H("BACKUP1"), "WMI remote exec", None),
                (620, H("WS-052"), H("FILE1"), "SMB admin-share exec", None),
                (700, H("WS-052"), H("DC2"), "RDP", (60, 180))]
LATERAL_SECOND_HOST = H("WS-052")       # the spread: a second workstation joins in

# C2 beaconing
C2_RMM_AT, C2_BEACON_BASE, C2_JITTER = 30, 60, (0.75, 1.35)

# NeedyMantis (Storm-3069). A SEPARATE post-compromise implant, built to be distinguishable from
# the hands-on-keyboard chains by WHERE it runs and HOW it looks, not just what it touches:
#   * a different foothold (NEEDY_WS) with no lateral path to EXL-WS-047;
#   * a fixed, atypical user agent on a single fixed request path -- the decryptable tell;
#   * a long cadence, each check-in a fresh TLS session (no kept-open WebSocket -- the 101
#     upgrade is a one-time, decryptable tell on first contact, not a persistent channel),
#     then Impacket-style SMB exec to its OWN target set.
# The C2 is Cloudflare-fronted, so the address on the wire is the edge, and the domain is the
# indicator that matters for threat-intel matching (exported in the STIX/CSV collection).
NEEDY_UA   = "firefox/21.0"                 # hard-coded, years out of date, per Microsoft's writeup
NEEDY_PATH = "/library/zip/"                # the one URI the implant calls
NEEDY_FIRST_AT = 45                         # first check-in, seconds into the window
NEEDY_CADENCE  = (280, 520)                 # seconds between check-ins (slow, jittered)
NEEDY_LATERAL = [(900, H("WEB2"), "SMB admin-share exec"),
                 (1500, H("PRINT1"), "SMB admin-share exec"),
                 (2100, H("LOG1"), "SMB admin-share exec")]


def needy_checkin(ctx, src, ts, first=False):
    """One decryptable C2 check-in, each its own fresh TLS session (no persistent channel).
    first=True is the system-info beacon plus the one-time WebSocket upgrade; otherwise a
    small check-in GET. All observables live in needymantis_beacon."""
    c2 = ext(ctx, "needy_c2")
    return F.needymantis_beacon(ctx, src, (c2.fqdn, c2), ts, first=first)


def ndr_needymantis(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    src = ctx.h[NEEDY_WS]                    # NOT attacker(ctx) -- the whole point
    lo, hi = win
    # First contact carries the system-info cookie and the one-time HTTP->WebSocket upgrade;
    # the slow, jittered cadence runs the rest of the window as separate check-ins.
    first = True
    t = lo + NEEDY_FIRST_AT
    while t < hi:
        s(t, needy_checkin, src, first=first)
        first = False
        t += rng.uniform(*NEEDY_CADENCE)
    # Impacket-style lateral movement (SMB ADMIN$ exec) to its own, disjoint target set.
    for off, target, _tech in NEEDY_LATERAL:
        if lo + off < hi:
            s(lo + off, F_smb_exec, src, target)


def F_smb_exec(ctx, src, target, ts):
    """NeedyMantis' own lateral movement, kept distinct from the campaign-C PsExec helper
    (`smb_admin_exec`) so this scenario's fix stays scoped to its own code path. Real Impacket
    psexec.py drops a random 8-letter .exe (never a DLL -- a DLL cannot be a service image),
    names the service after the file's stem, talks to it over the RemCom named pipe once the
    service starts, then stops/deletes the service and removes the file."""
    stem = "".join(rng.choice(string.ascii_uppercase) for _ in range(8))
    # Known gap, not fixed here: the service name should equal the file's stem (Impacket
    # psexec.py's convention), but this engine's svcctl/WMI calls are all built as sealed,
    # opaque RPC blobs (the same shared convention every other scenario uses), so the real
    # CreateServiceW -- which Impacket actually sends with no DCE auth, name and path in the
    # clear -- is not literally readable on this wire either way. Un-sealing it to carry a
    # real NDR-encoded CreateServiceW stub is a bigger change than this scenario's brief asks
    # for; left for a future pass, noted in the CHANGELOG.
    return needy_psexec(ctx, src, ctx.h[target], ts, stem + ".exe", size=rng.randint(140_000, 220_000))


def needy_psexec(ctx, src, target, ts, binary_name, size):
    user = "svc_backup"    # a stolen privileged credential
    s, smb, pre = F._smb_open(ctx, src, target, "ADMIN$", ts, user=user)
    s.c2s(smb.create_req(binary_name, write=True), think=rng.uniform(0.002, 0.02))
    r, fid = smb.create_resp(s.t, 0)
    s.s2c(r, think=0.0008)
    data = P.pe_blob(size, dll=False)      # a real PE (MZ/PE header, section table): an .exe, not a DLL
    off = 0
    while off < size:
        part = data[off:off + 65536]
        s.c2s(smb.write_req(fid, off, part), think=0.0003)
        s.s2c(smb.write_resp(len(part)), think=0.0005)
        off += len(part)
    s.c2s(smb.close_req(fid), think=0.002)
    s.s2c(smb.close_resp(s.t, size), think=0.0008)
    F._smb_untree(s, smb, think=rng.uniform(0.05, 0.3))
    # svcctl over IPC$, same connection/session, a new tree connect (PsExec never opens a
    # second session for this)
    F._smb_retree(s, smb, target, "IPC$")
    s.c2s(smb.create_req("svcctl", pipe=True), think=0.003)
    r2, fid2 = smb.create_resp(s.t, 0)
    s.s2c(r2, think=0.0008)
    callid = rng.randint(1, 400)
    auth = (user, "cifs", target.fqdn)
    bind = P.dcerpc_bind(callid, P.SVCCTL_UUID, 2, auth=auth)
    s.c2s(smb.write_req(fid2, 0, bind), think=0.001)
    s.s2c(smb.write_resp(len(bind)), think=0.0006)
    s.c2s(smb.read_req(fid2, 0, 1024), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_bind_ack(callid, "\\PIPE\\svcctl", auth=True)), think=0.0008)

    def _rpc(opnum, rq, rs):
        nonlocal callid
        callid += 1
        req = P.dcerpc_request(callid, opnum, P.blob(rq), sealed=True)
        s.c2s(smb.write_req(fid2, 0, req), think=rng.uniform(0.002, 0.01))
        s.s2c(smb.write_resp(len(req)), think=0.0006)
        s.c2s(smb.read_req(fid2, 0, 1024), think=0.0004)
        s.s2c(smb.read_resp(P.dcerpc_response(callid, P.blob(rs), sealed=True)), think=rng.uniform(0.001, 0.01))

    _rpc(15, 260, 40)   # OpenSCManagerW
    _rpc(12, 320, 60)   # CreateServiceW (service name == the dropped file's stem)
    _rpc(19, 120, 24)   # StartServiceW
    # RemCom's command channel: once the service starts, it opens its own named pipe back to
    # the caller and relays stdin ack / stdout / stderr / the exit code.
    s.c2s(smb.create_req("RemCom_communicaton", pipe=True), think=rng.uniform(0.05, 0.2))
    r3, fid3 = smb.create_resp(s.t, 0)
    s.s2c(r3, think=0.0008)
    for n in (64, 512, 96, 4):
        s.c2s(smb.write_req(fid3, 0, P.blob(n)), think=rng.uniform(0.002, 0.02))
        s.s2c(smb.write_resp(n), think=0.0006)
        s.c2s(smb.read_req(fid3, 0, 1024), think=0.0004)
        s.s2c(smb.read_resp(P.blob(n)), think=rng.uniform(0.001, 0.02))
    s.c2s(smb.close_req(fid3), think=0.002)
    s.s2c(smb.close_resp(s.t, 0), think=0.0008)
    _rpc(1, 48, 24)     # ControlService (SERVICE_CONTROL_STOP)
    _rpc(2, 24, 12)     # DeleteService
    s.c2s(smb.close_req(fid2), think=0.003)
    s.s2c(smb.close_resp(s.t, 0), think=0.0008)
    F._smb_untree(s, smb, think=rng.uniform(0.01, 0.05))
    # delete the dropped binary: FILE_OPEN + FILE_DELETE_ON_CLOSE, the CLOSE removes it
    F._smb_retree(s, smb, target, "ADMIN$")
    s.c2s(smb.create_req(binary_name, delete_on_close=True), think=rng.uniform(0.01, 0.05))
    r4, fid4 = smb.create_resp(s.t, 0)
    s.s2c(r4, think=0.0008)
    s.c2s(smb.close_req(fid4), think=0.002)
    s.s2c(smb.close_resp(s.t, 0), think=0.0008)
    pk = F._smb_close(s, smb)
    return F.merged(pre, pk)


# ============================================================ CAMPAIGN C (the LOTL tie-together)
# A single nation-state living-off-the-land operation spread across THREE footholds, so no one
# host does everything. Each of the eight scenarios below is independently selectable and valid
# on its own; selected together they share this roster and plausible timing and read as one
# multi-stage intrusion. The Cowork notes (docs/needymantis-and-campaign-c.md) narrate the
# stream for agentic exercises -- there is deliberately NO combined module.
C_BEACHHEAD = H("WS-009")      # entry: edge-exploit landing, Volt LOTL ops, fast-flux C2
C_PIVOT     = H("WS-023")      # privilege: coercion->relay->ADCS, web shell, RDP-brute success
C_COLLECTOR = H("WS-061")      # discovery: network-device recon, infostealer victim (stage 0)

# Scenario dependencies: an NPM scenario whose CAUSE is post-compromise malicious activity pulls
# in the LOTL NDR scenario that compromised the host, so the capture carries the intrusion context
# and the admin traffic traces back to a workstation the platform already flags as anomalous.
# select_modules() auto-includes the value when the key is selected; the GUI mirrors it.
SCENARIO_DEPENDENCIES = {
    "npm-dhcp-exhaustion": "ndr-volt-typhoon",   # beachhead EXL-WS-009 RDPs the DC to starve DHCP
    "npm-tcp-loss-storm":  "ndr-salt-typhoon",   # collector EXL-WS-061 reaches into the switch
}

# Scenarios that target the OT subnet: inert unless it is generated, so the GUI marks them ot_only
# (hidden, unchecked and unselectable when the OT zone is off), exactly like the pinned OT baseline.
OT_SCENARIOS = {
    "ndr-ot-modbus-write", "ndr-ot-sis-tamper", "ndr-ot-zone-violation", "ndr-ot-recon",
    "ndr-ot-rogue-asset", "ndr-ot-camera-beacon", "npm-ot-plc-unresponsive",
    # 2026-10-23 dashboard add-ons (field devices / supervisory zone are OT-only, so inert
    # without the OT subnet). npm-nightly-backup is enterprise, so it is NOT listed here.
    "ndr-ot-sanctioned-writes", "ndr-ot-new-pair", "ndr-ot-field-egress", "ndr-ot-protocol-sweep",
}

# External, non-exported attacker infrastructure (transient, like the anon-FTP scanner): the
# edge-exploit source and the RDP-brute source. Documentation range, kept OUT of the threat
# collection because they are the attacker's throwaway infra, not durable intel.
EXPLOIT_SRC_IP, EXPLOIT_SRC_NAME = "203.0.113.66", "node66.probe-labs.example"
BRUTE_SRC_IP,   BRUTE_SRC_NAME   = "203.0.113.90", "scan90.bruteforce-pool.example"


def _ext_src(ctx, ip, name, hops=9):
    """An internet-side attacker host, built directly so used_indicator_ips() never sees it
    (same reason as the anon-FTP scanner)."""
    cache = ctx.__dict__.setdefault("_campc_ext", {})
    if ip not in cache:
        h = Host(name.split(".")[0].upper(), ip,
                 "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)),
                 "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", name)
        h.hops = hops
        cache[ip] = h
    return cache[ip]


# ---- #6 Fast-flux / DGA C2 -------------------------------------------------------------------
# Distinct from ndr-dns-tunneling (which hides data IN DNS): here DNS is used to FIND the C2.
# A burst of algorithmic NXDOMAIN lookups, then the one STABLE name the DGA is actually
# converging on; that name answers with a rotating subset of the flux pool (3 to 6 A records,
# a short TTL, a different set on every attempt) -- the rotating A set is the actual fast-flux
# tell, not the DGA names themselves (those only ever NXDOMAIN). A short decryptable HTTPS
# beacon follows, to whichever pool node the lookup handed back first.
DGA_TLD = ["top", "xyz", "info", "net"]


# Throwaway flux nodes behind the stable name, in addition to the one documented ThreatFox
# anchor IP in EXT_HOSTS["flux_c2"]. Documentation range (RFC 5737), same convention as
# EXPLOIT_SRC_IP/BRUTE_SRC_IP: built via _ext_src so used_indicator_ips()/the threat export
# never sees them -- they are not real intelligence, just the rest of the pool.
FLUX_POOL_EXTRA = [
    ("203.0.113.130", "node130.flux-relay.example"),
    ("203.0.113.131", "node131.flux-relay.example"),
    ("203.0.113.132", "node132.flux-relay.example"),
    ("203.0.113.133", "node133.flux-relay.example"),
    ("203.0.113.134", "node134.flux-relay.example"),
]


def _flux_pool(ctx):
    anchor = ext(ctx, "flux_c2")
    return [anchor] + [_ext_src(ctx, ip, name, hops=13) for ip, name in FLUX_POOL_EXTRA]


def _dga_name(seed):
    r = random.Random(seed)
    return "".join(r.choice("bcdfghjklmnpqrstvwxyz0123456789") for _ in range(r.randint(10, 16))) + "." + r.choice(DGA_TLD)


def fastflux_resolve(ctx, src, day_seed, ts=None):
    """A DGA resolution attempt: several NXDOMAIN lookups against algorithmic names, then the
    one stable C2 name, which the resolver answers with a different rotating subset of the
    flux pool every time, then a brief decryptable HTTPS check-in to the first node handed
    back."""
    out = []
    for i in range(rng.randint(4, 8)):
        nm = _dga_name(day_seed * 131 + i)
        out += F.dns_lookup(ctx, src, nm, ts + i * rng.uniform(0.05, 0.3), external=True, rcode=3)  # NXDOMAIN
    stable = ext(ctx, "flux_c2").fqdn
    pool = _flux_pool(ctx)
    nodes = rng.sample(pool, rng.randint(3, min(6, len(pool))))
    ttl = rng.randint(60, 300)
    out += F.dns_lookup(ctx, src, stable, ts + 2.0, external=True,
                        answers=[(P.DNS_A, n.ipb) for n in nodes], ttl=ttl)
    picked = nodes[0]
    out += F.https_session(ctx, src, (stable, picked), ts + 2.3, requests=1, sizes=[rng.randint(140, 520)],
                           keep_open=0.4, rate=50e6, paths=["/gate.php"], dns=False)    # the stable name was resolved just above
    return F.merged(out)


def ndr_fastflux(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    src = ctx.h[C_BEACHHEAD]
    lo, hi = win
    day = int(lo) // 86400
    t = lo + 40
    i = 0
    while t < hi:
        s(t, fastflux_resolve, src, day + i)
        t += rng.uniform(300, 540)
        i += 1


# ---- #7 Infostealer -> access-broker handoff (stage 0 of campaign C) --------------------------
# Commodity eCrime: a browser-credential stealer on the collector host makes a short, one-shot
# HTTPS upload of a credential blob to its panel, then goes quiet. In the tie-together story this
# is how the broker got the creds it later sold to the state actor.
INFOSTEALER_BOUNDARY_PREFIX = "----Boundary"


def infostealer_exfil(ctx, src, ts, first=True):
    """Owner decided 2026-11-06: this is a real upload (Option 1), not a download -- the registry
    title, make_diagram.py's d_stealer and the builder's own comment all said "upload" from the
    start, and a Lumma-class stealer's own exfil call is a POST, not a GET. The credential/cookie
    archive rides as the multipart file part of a single client->server POST /c2sock, answered
    with a tiny JSON ack -- the opposite byte-direction shape from the GET-with-a-huge-response
    this builder had before the fix.
    first=True (the one-shot infection-time call): the full 40-160 KB archive upload. first=False
    (the "few short check-ins" `ndr_infostealer` schedules afterwards): a small heartbeat POST, not
    a second archive -- the diagram and the scheduler's own "runs once on infection" comment both
    say one upload, not 2 to 4.
    non-browser client: a commodity stealer's own HTTP stack, not the victim's browser, so its
    JA3 and UA differ from EXL-WS-061's own browsing on the same wire -- a hand-rolled, truncated
    UA (missing the AppleWebKit/Chrome suffix a real browser would send) is a common commodity
    stealer tell, not a copy of any one named family's exact string."""
    from .tls import TlsSession
    panel = ext(ctx, "stealer")
    host, srv = panel.fqdn, panel
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    boundary = INFOSTEALER_BOUNDARY_PREFIX + "%016x" % rng.getrandbits(64)
    field = b'name="data"; filename="sys.dat"' if first else b'name="data"; filename="chk.dat"'
    payload = P.blob(rng.randint(40_000, 160_000)) if first else P.blob(rng.randint(60, 300))
    body = (_mp_part(boundary.encode(), field, payload,
                     extra_headers=[b"Content-Type: application/octet-stream"])
           + b"--" + boundary.encode() + b"--\r\n")
    hdrs = ["Content-Type: multipart/form-data; boundary=%s" % boundary]
    pre = F.dns_lookup(ctx, src, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)]) if F._wants_dns(ctx, src, host, ts, True) else []
    t = ts + rng.uniform(0.005, 0.05)
    out = ctx.arp_for(src, srv, t)
    s = ctx.tcp(src, srv, 443, t + 0.001, rate=40e6).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile="winhttp")
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.0005, 0.003) if from_c else rng.uniform(0.002, 0.01))
    req = P.http_request("POST", "/c2sock", host, ua, hdrs, body)
    s.c2s(tls.app_data(True, req), think=rng.uniform(0.0008, 0.004))
    ack = b'{"status":"ok","id":"%s"}' % os.urandom(rng.randint(24, 80)).hex().encode()
    resp = P.http_response("200 OK", ack, "application/json", s.t, server=rng.choice(["nginx/1.26.2", "cloudflare"]))
    s.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.12))
    s.c2s(tls.close_notify(True), think=rng.uniform(0.5, 2.0))
    pk = s.close(think=0.002)
    return F.merged(pre, out, pk)


def ndr_infostealer(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    src = ctx.h[C_COLLECTOR]
    lo, hi = win
    # a stealer runs ONCE on infection, early, not on a beacon -- the full archive upload
    s(lo + rng.uniform(60, 240), infostealer_exfil, src, first=True)
    # a couple of short follow-up check-ins over the next hour -- small heartbeats, not a
    # second archive upload (one-shot exfil, per the diagram and this comment)
    for _ in range(rng.randint(1, 3)):
        s(lo + rng.uniform(600, 3000), infostealer_exfil, src, first=False)


# ---- #8 Exposed-RDP brute force -> foothold --------------------------------------------------
# Internet -> the exposed admin jump host: many short, failing RDP connections, then one that
# completes. A top ransomware entry vector. The brute source is external and non-exported.
# Account names the brute-forcer cycles through; the success keeps one fixed account (not
# necessarily the first) so the winning credential reads as a distinct outcome.
BRUTE_ACCOUNTS = ["administrator", "admin", "Administrator", "backup", "svc_admin", "user1", "support"]


def rdp_brute_attempt(ctx, src_ip, src_name, target, succeed=False, ts=None, user="administrator"):
    from .tls import TlsSession
    attacker = _ext_src(ctx, src_ip, src_name)
    tgt = ctx.h[target]
    out = ctx.arp_for(attacker, tgt, ts, vantage=tgt)
    sxn = ctx.tcp(attacker, tgt, 3389, ts + 0.001, vantage=tgt).handshake()
    sxn.c2s(P.rdp_x224_connect(user), think=0.002)
    sxn.s2c(P.rdp_x224_confirm(), think=0.003)
    # Both outcomes negotiate HYBRID (CredSSP) and run the TLS 1.2 handshake underneath it --
    # NLA happens inside TLS, so a failed logon still shows a ClientHello before the server
    # ever gets to see (and reject) the credential. RDP: self-signed, forward-secret, same as
    # the internal admin session (flows.rdp_session) -- its keys are not exported, so CredSSP
    # stays opaque either way, but the cert/cipher must match what this host shows everyone.
    tls = TlsSession(ctx.pki, tgt.fqdn, F._NullLog() if hasattr(F, "_NullLog") else ctx.keylog,
                      alpn=b"", kex="ecdhe", selfsigned=True)
    for from_c, data in tls.handshake():
        (sxn.c2s if from_c else sxn.s2c)(data, think=rng.uniform(0.002, 0.01))
    if not succeed:
        # CredSSP TSRequest exchange: the client's NTLM-wrapped TSRequest, then the server's
        # error TSRequest (bad credential). A fixed 2-leg shape (narrow jitter), within the
        # brief's 1-to-3-record range, so every failed attempt is the same tell and always ends
        # in the server's error record -- not a coin flip on whether that record shows up.
        for sc, from_c in ((420, True), (310, False)):
            size = int(sc * rng.uniform(0.95, 1.05))
            data = tls.app_data(from_c, os.urandom(size))
            (sxn.c2s if from_c else sxn.s2c)(data, think=rng.uniform(0.01, 0.08))
        if rng.random() < 0.6:
            out += sxn.rst_from_server(think=rng.uniform(0.05, 0.2))
        else:
            sxn.s2c(tls.close_notify(False), think=rng.uniform(0.02, 0.1))
            out += sxn.close(by_client=False, think=0.003)
        return F.merged(out)
    # the successful landing: an inbound RDP session, framed like the failed attempts
    # (vantage=tgt). NOT F.rdp_session -- that does Kerberos and internal resolution, which make
    # no sense from the internet and break the inbound framing.
    for sc, ss in ((300, 700), (1200, 400), (500, 3000)):
        sxn.c2s(tls.app_data(True, os.urandom(sc)), think=rng.uniform(0.01, 0.08))
        sxn.s2c(tls.app_data(False, os.urandom(ss)), think=rng.uniform(0.01, 0.08))
    # a session that stays open: periodic bidirectional MCS/graphics bursts for 20 to 120 s, the
    # real foothold rather than a 0.3 s blip. Heavily server -> client, as real RDP is: small
    # keystroke/mouse input up, bitmap update bursts back (same shape as flows.rdp_session).
    t_end = sxn.t + rng.uniform(20, 120)
    while sxn.t < t_end:
        if rng.random() < 0.6:
            sxn.c2s(tls.app_data(True, os.urandom(rng.randint(40, 120))), think=rng.uniform(0.05, 0.6))
            sxn.s2c(tls.app_data(False, os.urandom(rng.randint(200, 6000))), think=rng.uniform(0.01, 0.05))
        else:
            sxn.s2c(tls.app_data(False, os.urandom(rng.randint(4000, 30000))), think=rng.uniform(0.3, 2.0))
    sxn.c2s(tls.close_notify(True), think=0.5)
    return F.merged(out, sxn.close(think=0.003))


def ndr_rdp_brute(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    target = H('MGMT1')                 # the exposed admin jump host
    # a burst of failures across the first few minutes, then one success
    t = lo + 20
    n = int(max(6, 40 * min(1.0, max(0.05, ctx.scale))))
    success_user = rng.choice(BRUTE_ACCOUNTS)
    for i in range(n):
        s(t, rdp_brute_attempt, BRUTE_SRC_IP, BRUTE_SRC_NAME, target, succeed=False,
          user=BRUTE_ACCOUNTS[i % len(BRUTE_ACCOUNTS)])
        t += rng.uniform(1.5, 6.0)
    s(t + rng.uniform(5, 20), rdp_brute_attempt, BRUTE_SRC_IP, BRUTE_SRC_NAME, target, succeed=True,
      user=success_user)


# ---- #4 Salt Typhoon -- network-device espionage ---------------------------------------------
# Targets the NETWORK infrastructure, not servers: real SNMP table walks of switches/APs/
# firewall/sensor over the `public` community. Long-dwell, low-rate -- the espionage, not the
# smash-and-grab. (No config-pull stage on the wire: this generator models the SNMP recon
# only, as the abstraction for device-level espionage -- see brief/validator notes.)
SALT_DEVICES = ("EXL-SWB1", "EXL-WLC1", "EXL-SENSOR1", "EXL-NTP1", "EXL-LOG1")


def salt_recon(ctx, poller, device_name, ts):
    dev = ctx.h[device_name]
    # a real walk: GetBulkRequest PDUs over ifTable, one socket for the whole walk, ending
    # in endOfMibView -- not a run of identical GETs for the same six scalar OIDs.
    return F.snmp_walk(ctx, poller, dev, ts, community=b"public")


def ndr_salt_typhoon(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    src = ctx.h[C_COLLECTOR]
    lo, hi = win
    # slow sweep of the device set, each walked a handful of times across the long window
    t = lo + 120
    while t < hi:
        s(t, salt_recon, src, rng.choice(SALT_DEVICES))
        t += rng.uniform(420, 900)


# ---- #5 Web shell on an internal server ------------------------------------------------------
# After exploiting the internal LOB app, the operator interacts with a planted web shell: POSTs
# to one odd URI, command in the body, output in the response. Decryptable, so it reads in clear.
WEBSHELL_HOST = H("WEB2")
WEBSHELL_PATH = "/app/uploads/sync.aspx"
WEBSHELL_CMDS = [b"whoami /all", b"net group \"domain admins\" /domain", b"tasklist /v",
                 b"ipconfig /all", b"reg query HKLM\\SYSTEM\\CurrentControlSet\\Services",
                 b"dir \\\\EXL-FILE1\\shares", b"systeminfo"]


def webshell_cmd(ctx, operator, ts):
    from .tls import TlsSession
    srv = ctx.h[WEBSHELL_HOST]
    pre = resolve_internal_for(ctx, operator, srv, ts)
    t = ts + rng.uniform(0.005, 0.03)
    out = ctx.arp_for(operator, srv, t)
    sxn = ctx.tcp(operator, srv, 443, t + 0.001).handshake()
    tls = TlsSession(ctx.pki, srv.fqdn, ctx.keylog, profile=getattr(operator, "tls_profile", "winhttp"))
    for from_c, data in tls.handshake():
        (sxn.c2s if from_c else sxn.s2c)(data, think=rng.uniform(0.0008, 0.004))
    cmd = rng.choice(WEBSHELL_CMDS)
    body = b"cmd=" + cmd
    req = P.http_request("POST", WEBSHELL_PATH, srv.fqdn, "Mozilla/5.0", ["Content-Type: application/x-www-form-urlencoded"], body)
    sxn.c2s(tls.app_data(True, req), think=rng.uniform(0.002, 0.02))
    resp = P.http_response("200 OK", P.text_blob(rng.randint(400, 4000)), "text/html; charset=utf-8", sxn.t, server="Microsoft-IIS/10.0")
    sxn.s2c(tls.app_data(False, resp), think=rng.uniform(0.05, 0.3))
    sxn.c2s(tls.close_notify(True), think=rng.uniform(0.3, 1.0))
    return F.merged(pre, out, sxn.close(think=0.002))


def resolve_internal_for(ctx, client, server, ts):
    try:
        return F.resolve_internal(ctx, client, server, ts)
    except Exception:
        return []


def ndr_webshell(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    src = ctx.h[C_PIVOT]
    lo, hi = win
    # interactive hands-on-keyboard: clustered commands, with gaps
    t = lo + 60
    while t < hi:
        for _ in range(rng.randint(2, 5)):
            s(t, webshell_cmd, src)
            t += rng.uniform(8, 40)
        t += rng.uniform(200, 600)


# ---- #3 Volt Typhoon -- living-off-the-land pre-positioning ----------------------------------
# No malware, no C2. Valid-account use of ordinary admin protocols from a host that normally does
# not, at a low rate across the whole window. The detection IS the baseline deviation -- which is
# the entire point of this generator.
VOLT_TARGETS = (H("DC1"), H("FILE1"), H("SQL1"), H("MGMT1"))


# a handful of LOTL-style directory searches -- not the collector's full enumeration -- typical of
# living-off-the-land recon: who runs where, who's a domain admin, which accounts hold an SPN.
VOLT_LDAP_PLAN = (("computer", None, ["cn", "dNSHostName", "operatingSystem"]),
                   ("admin", "CN=Domain Admins,OU=Groups,%s" % P.BASE_DN, ["sAMAccountName", "cn", "memberOf"]),
                   ("spn", None, ["sAMAccountName", "cn", "servicePrincipalName"]))


VOLT_CONFIG_FILES = ["SAM", "SYSTEM", "SECURITY"]


def volt_ldap_recon(ctx, src, ts, dc=None):
    """3 LDAP searches over a Kerberos-bound session: which machines exist, who is in Domain
    Admins, which accounts hold an SPN -- the TGS request reuses the host's own logged-on TGT
    (force=True still means TGS-REQ/TGS-REP only, no AS-REQ), so no fresh TGT is ever drawn."""
    dc = dc or ctx.h[H('DC1')]
    user = P.username_for(src.name)
    pre, t = F.kerberos_tgs(ctx, src, "ldap", dc, ts, force=True)
    out = ctx.arp_for(src, dc, t)
    s = ctx.tcp(src, dc, 389, t + 0.001).handshake()
    mid = 1
    s.c2s(P.ldap_bind_request(mid, P.krb_ap_req_token(user, "ldap", dc.fqdn)), think=0.0005)
    s.s2c(P.ldap_bind_response(mid), think=rng.uniform(0.001, 0.004))
    d = _enum_directory(ctx)
    for key, member_of, attrs in VOLT_LDAP_PLAN:
        objs = d[key]
        if member_of is not None:
            objs = [o for o in objs if member_of in "".join(o[1].get("memberOf", []))]
            filt = P._filter_eq("memberOf", member_of)
        elif key == "spn":
            filt = P._filter_present("servicePrincipalName")
        else:
            filt = P._filter_eq("objectCategory", "computer")
        mid += 1
        cookie, first, i = b"\x00", True, 0
        paged = key == "spn"
        while True:
            chunk = objs[i:i + RECON_LDAP_PAGE] if paged else objs
            i += RECON_LDAP_PAGE
            more = paged and i < len(objs)
            s.c2s(P.ldap_search_request(mid, P.BASE_DN, 2, filt, attrs,
                  controls=P.ldap_paged_control(RECON_LDAP_PAGE, b"" if first else cookie) if paged else b""),
                  think=rng.uniform(0.01, 0.06))
            first = False
            cookie = os.urandom(8) if more else b""
            resp = b"".join(P.ldap_search_entry(mid, dn, at) for dn, at in chunk)
            resp += P.ldap_search_done(mid, controls=P.ldap_paged_control(0 if not more else len(objs), cookie) if paged else b"")
            s.s2c(resp, think=rng.uniform(0.004, 0.02))
            if not more:
                break
            mid += 1
    mid += 1
    s.c2s(P.ldap_unbind(mid), think=rng.uniform(0.01, 0.2))
    pk = s.close(think=0.0005)
    return F.merged(pre, out, pk)


def volt_c_dollar_touch(ctx, src, server, ts):
    """Low-volume C$ recon: browse into Windows\\System32\\config or Users, list what's there,
    read one or two small items -- a directory peek, not a bulk transfer."""
    s, smb, pre = F._smb_open(ctx, src, server, "C$", ts)
    path = rng.choice(["Windows\\System32\\config", "Users"])
    s.c2s(smb.create_req(path, write=False), think=rng.uniform(0.002, 0.02))
    r, dfid = smb.create_resp(s.t, 0, directory=True)
    s.s2c(r, think=0.0008)
    s.c2s(smb.query_dir_req(dfid), think=0.0006)
    if path.endswith("config"):
        listing = [(n, rng.randint(256_000, 40_000_000), False) for n in VOLT_CONFIG_FILES]
    else:
        listing = [(P.username_for((H('WS-') + "%03d") % i), 0, True) for i in rng.sample(range(1, 76), rng.randint(3, 6))]
    s.s2c(smb.query_dir_resp(listing, s.t), think=rng.uniform(0.001, 0.004))
    s.c2s(smb.close_req(dfid), think=0.0006)
    s.s2c(smb.close_resp(s.t, 0), think=0.0006)
    readable = [x for x in listing if not x[2]]
    for name, size, _ in rng.sample(readable, min(2, len(readable))):
        read_len = min(size, 65536)
        s.c2s(smb.create_req("%s\\%s" % (path, name), write=False), think=rng.uniform(0.3, 2.0))
        r, fid = smb.create_resp(s.t, read_len)
        s.s2c(r, think=rng.uniform(0.0008, 0.004))
        s.c2s(smb.read_req(fid, 0, read_len), think=0.0006)
        s.s2c(smb.read_resp(P.blob(read_len)), think=rng.uniform(0.0008, 0.004))
        s.c2s(smb.close_req(fid), think=0.0006)
        s.s2c(smb.close_resp(s.t, read_len), think=0.0006)
    pk = F._smb_close(s, smb)
    return F.merged(pre, pk)


def volt_action(ctx, src, kind, target_name, ts):
    tgt = ctx.h[target_name]
    if kind == "rdp":
        return F.rdp_session(ctx, src, tgt, ts, rng.uniform(60, 150))
    if kind == "smb":
        return volt_c_dollar_touch(ctx, src, tgt, ts)
    # ldap: directory recon always goes to a domain controller, regardless of the rotated target
    return volt_ldap_recon(ctx, src, ts)


def ndr_volt_typhoon(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    src = ctx.h[C_BEACHHEAD]
    lo, hi = win
    # low and slow: a handful of quiet admin touches, spread wide, nothing bursty
    t = lo + 200
    kinds = ["ldap", "smb", "ldap", "smb", "rdp"]  # rdp only 1 in 5, it is the heavy one
    i = 0
    while t < hi:
        s(t, volt_action, src, kinds[i % len(kinds)], rng.choice(VOLT_TARGETS))
        t += rng.uniform(1100, 2200)   # low and slow: wide gaps
        i += 1


# ---- #2 Coercion -> NTLM relay -> AD CS -> Domain Admin (ESC8) --------------------------------
# The marquee AD attack. Observable in four hops, all in protocols that already exist:
#   coerce (MS-EFSR RPC) -> the victim auths to the relay (SMB/NTLM) -> relay to the CA web
#   enrollment endpoint (HTTP certsrv) -> a PKINIT TGT obtained with the issued cert.
ADCS_CA   = H("DC2")            # the CA with web enrollment (certsrv)
ESC8_VICTIM = H("FILE1")       # the machine account coerced to authenticate


def esc8_coerce(ctx, relay, victim, ts):
    """MS-EFSR coercion over the IPC$ named pipe (PetitPotam): an authenticated SMB session from
    the relay to the victim, then EfsRpcOpenFileRaw over \\pipe\\efsrpc -- tcp/135 hosts only the
    endpoint mapper, never a direct EFSR bind."""
    s, smb, pre = F._smb_open(ctx, relay, victim, "IPC$", ts)
    s.c2s(smb.create_req("efsrpc", pipe=True), think=rng.uniform(0.002, 0.02))
    r, fid = smb.create_resp(s.t, 0)
    s.s2c(r, think=0.0008)
    callid = rng.randint(1, 400)
    bind = P.dcerpc_bind(callid, P.EFSR_UUID, 1)
    s.c2s(smb.write_req(fid, 0, bind), think=0.001)
    s.s2c(smb.write_resp(len(bind)), think=0.0006)
    s.c2s(smb.read_req(fid, 0, 1024), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_bind_ack(callid, "\\PIPE\\efsrpc")), think=0.0012)
    callid += 1
    req = P.dcerpc_request(callid, 0, P.efs_open_file_raw_req("\\\\" + relay.ip + "\\share\\x"))
    s.c2s(smb.write_req(fid, 0, req), think=0.001)
    s.s2c(smb.write_resp(len(req)), think=0.0006)
    s.c2s(smb.read_req(fid, 0, 1024), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_response(callid, P.efs_open_file_raw_resp())), think=0.0015)
    s.c2s(smb.close_req(fid), think=0.002)
    s.s2c(smb.close_resp(s.t, 0), think=0.0008)
    pk = F._smb_close(s, smb)
    return F.merged(pre, pk)


def esc8_chain(ctx, relay, ts):
    victim = ctx.h[ESC8_VICTIM]
    ca = ctx.h[ADCS_CA]
    victim_user = victim.name + "$"
    # 1) coercion: EFSR over the authenticated IPC$ pipe, not a bare tcp/135 bind
    out = esc8_coerce(ctx, relay, victim, ts)
    # 2) the coerced callback: victim -> relay SMB, NEGOTIATE (type 1) so far
    oa = ctx.arp_for(victim, relay, ts + 0.3)
    sa = ctx.tcp(victim, relay, 445, ts + 0.31).handshake()
    smb = P.Smb2()
    sa.c2s(smb.negotiate_req(os.urandom(16)), think=0.0006)
    sa.s2c(smb.negotiate_resp(os.urandom(16), sa.t), think=0.001)
    sa.c2s(smb.session_setup_req(P.spnego_ntlm_init(P.ntlm_negotiate("CORP", victim.name))), think=0.001)
    # 3) the relay, acting as client, gets the CA's real challenge before it can answer the victim
    from .tls import TlsSession
    from urllib.parse import quote
    oe = ctx.arp_for(relay, ca, ts + 0.5)
    se = ctx.tcp(relay, ca, 443, ts + 0.51).handshake()
    tls = TlsSession(ctx.pki, ca.fqdn, ctx.keylog, profile="winhttp")
    for from_c, data in tls.handshake():
        (se.c2s if from_c else se.s2c)(data, think=rng.uniform(0.001, 0.005))
    ua = "Microsoft-CryptoAPI/10.0"
    probe = P.http_request("POST", "/certsrv/certfnsh.asp", ca.fqdn, ua)
    se.c2s(tls.app_data(True, probe), think=0.002)
    se.s2c(tls.app_data(False, P.http_response("401 Unauthorized", b"", "text/html", se.t,
          headers=["WWW-Authenticate: NTLM"])), think=0.004)
    type1_b64 = base64.b64encode(P.ntlm_negotiate("CORP", relay.name)).decode()
    req1 = P.http_request("POST", "/certsrv/certfnsh.asp", ca.fqdn, ua, ["Authorization: NTLM " + type1_b64])
    se.c2s(tls.app_data(True, req1), think=0.003)
    challenge = P.ntlm_challenge(ca.name, dns_domain=ca.fqdn)
    type2_b64 = base64.b64encode(challenge).decode()
    se.s2c(tls.app_data(False, P.http_response("401 Unauthorized", b"", "text/html", se.t,
          headers=["WWW-Authenticate: NTLM " + type2_b64])), think=0.004)
    # 4) the relay hands the victim that SAME challenge, then forwards the resulting type 3
    sa.s2c(smb.session_setup_challenge(P.spnego_ntlm_challenge(challenge)), think=rng.uniform(0.001, 0.004))
    sa.c2s(smb.session_setup_req(P.spnego_ntlm_auth(P.ntlm_authenticate(victim_user, "CORP", victim.name))),
          think=rng.uniform(0.002, 0.01))
    sa.s2c(smb.session_setup_resp(), think=rng.uniform(0.001, 0.005))
    oa_pk = sa.close(think=0.002)
    type3_b64 = base64.b64encode(P.ntlm_authenticate(victim_user, "CORP", victim.name)).decode()
    csr_b64 = base64.b64encode(P.blob(900)).decode()
    body = ("Mode=newreq&CertAttrib=" + quote("CertificateTemplate:Machine") + "&CertRequest=" + quote(csr_b64)).encode()
    req3 = P.http_request("POST", "/certsrv/certfnsh.asp", ca.fqdn, ua,
                          ["Content-Type: application/x-www-form-urlencoded", "Authorization: NTLM " + type3_b64], body)
    se.c2s(tls.app_data(True, req3), think=0.004)
    reqid = rng.randint(1000, 9999)
    html = (f"<html><body>Certificate Issued.<br>Your Request Id is {reqid}.<br>"
            f"<a href=\"certnew.cer?ReqID={reqid}&amp;Enc=b64\">Download certificate</a></body></html>").encode()
    se.s2c(tls.app_data(False, P.http_response("200 OK", html, "text/html", se.t)), think=0.01)
    # 5) fetch the issued certificate (same authenticated connection, no Authorization needed again)
    get_cer = P.http_request("GET", f"/certsrv/certnew.cer?ReqID={reqid}&Enc=b64", ca.fqdn, ua)
    se.c2s(tls.app_data(True, get_cer), think=0.005)
    pem = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(P.blob(1200)) + b"\n-----END CERTIFICATE-----\n"
    # Enc=b64 means the body is base64 text, not binary DER -- application/pkix-cert would send
    # tshark's X.509 dissector after it and it would fail to parse PEM text as DER.
    se.s2c(tls.app_data(False, P.http_response("200 OK", pem, "application/x-x509-user-cert", se.t)), think=0.01)
    oe_pk = se.close(think=0.002)
    # 6) the issued cert buys a PKINIT TGT for the machine account, from the relay host
    pk_out = F.kerberos_pkinit(ctx, relay, ts + 1.3, victim_user, dc=ctx.h[H('DC1')])
    return F.merged(out, oa, oa_pk, oe, oe_pk, pk_out)


def ndr_coercion_adcs(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    relay = ctx.h[C_PIVOT]
    lo, hi = win
    # the chain fires a few times (retries / multiple machine accounts coerced)
    for k in range(int(max(2, 4 * min(1.0, max(0.1, ctx.scale)) + 2))):
        s(lo + 200 + k * rng.uniform(120, 400), esc8_chain, relay)


# ---- #1 Edge-device exploitation -> inward pivot ---------------------------------------------
# The sensor sits inside, so the inbound VPN exploit itself is upstream of the SPAN. What IS
# visible, and is the finding, is the AFTERMATH: the compromised edge device (the firewall's
# inside interface) suddenly originating admin protocols inward that it never normally does,
# and the beachhead workstation establishing outbound C2. Modelled as that visible aftermath.
EDGE_INWARD = (H("DC1"), H("FILE1"), H("MGMT1"))


EDGE_HARVESTED_ACCOUNT = "svc_backup"    # a stolen privileged credential, not a device identity


def edge_pivot(ctx, ts):
    # the firewall's inside interface (FW-B, on the monitored server segment) reaching inward,
    # authenticated with a harvested account over NTLM -- the appliance itself has no domain
    # computer account to request a Kerberos ticket with.
    fw = ctx.h.get("FW-B")
    out = []
    if fw is not None:
        tgt = ctx.h[rng.choice(EDGE_INWARD)]
        out += F.smb_file_activity(ctx, fw, tgt, ts, n_files=rng.randint(1, 2), write_ratio=0.5, share="ADMIN$",
                                   ntlm_user=EDGE_HARVESTED_ACCOUNT)
    return F.merged(out)


def ndr_edge_exploit(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    # a short inbound exploitation burst from the attacker to the firewall, framed so it is on
    # the monitored segment, then the inward pivot and the beachhead C2.
    attacker = _ext_src(ctx, EXPLOIT_SRC_IP, EXPLOIT_SRC_NAME)
    fwb = ctx.h.get("FW-B")
    if fwb is not None:
        for i in range(3):
            s(lo + 10 + i * rng.uniform(0.3, 1.2), _edge_exploit_probe, attacker, fwb)
    # inward pivot from the edge device
    t = lo + 60
    while t < hi:
        s(t, edge_pivot)
        t += rng.uniform(500, 1100)
    # the beachhead establishes outbound C2 (reuse the fast-flux channel narrative)
    s(lo + 90, _edge_beachhead_c2, ctx.h[C_BEACHHEAD])


def _edge_exploit_probe(ctx, attacker, fwb, ts):
    # CVE-2024-3400-style GlobalProtect exploitation: a crafted SESSID cookie carrying a path
    # traversal, posted to the save-config endpoint -- not a generic oversized body to a CSS path.
    from .tls import TlsSession
    out = ctx.arp_for(attacker, fwb, ts, vantage=fwb)
    sxn = ctx.tcp(attacker, fwb, 443, ts + 0.001, vantage=fwb).handshake()
    tls = TlsSession(ctx.pki, ("vpn." + get_current().domain), ctx.keylog, profile="openssl")
    for from_c, data in tls.handshake():
        (sxn.c2s if from_c else sxn.s2c)(data, think=rng.uniform(0.001, 0.006))
    sessid = "../../../../opt/pancfg/mgmt/save-config/%s" % os.urandom(6).hex()
    req = P.http_request("POST", "/ssl-vpn/hipreport.esp", ("vpn." + get_current().domain), "curl/8.4.0",
                         ["Content-Type: application/x-www-form-urlencoded", "Cookie: SESSID=" + sessid],
                         P.blob(rng.randint(2000, 6000)))
    sxn.c2s(tls.app_data(True, req), think=0.003)
    sxn.s2c(tls.app_data(False, P.http_response("200 OK", P.blob(300), "text/css", sxn.t, server="PanWeb")), think=0.02)
    return F.merged(out, sxn.close(think=0.002))


def _edge_beachhead_c2(ctx, src, ts):
    c2 = ext(ctx, "flux_c2")
    return F.https_session(ctx, src, (c2.fqdn, c2), ts, requests=2, sizes=[220, 180], keep_open=0.5, rate=50e6, paths=["/gate.php", "/gate.php"], dns=True)

C2_TUNNEL_AT = 900
COBALT_BEACON_BASE, COBALT_JITTER = 45, (0.7, 1.4)

COBALT_PIPE_SLEEP = 60       # base interval between a pipe session's write/read polls, seconds


# DNS tunnelling
DNSTUN_BURST, DNSTUN_GAP = (3, 8), (1.5, 5.0)
DNSTUN_LABEL_BYTES, DNSTUN_TXT_BYTES = (20, 45), (40, 200)

# data exfiltration: (offset, host, share, bytes at scale 1, direction)
EXFIL_STAGING = [(10, H("FILE1"), "Dept", 60_000_000), (20, H("BACKUP1"), "Users", 30_000_000)]
EXFIL_UPLOAD_AT, EXFIL_UPLOAD_BYTES = 600, 90_000_000

# impact
RANSOM_TARGETS = [(60, H("FILE1"), "Dept"), (480, H("BACKUP1"), "Users")]
RANSOM_FILES, WIPER_FILES = (30, 80), (25, 60)

# kill chains: (start minute, end minute, phase) relative to the window
CHAIN_PHASES = [(3, None, "C2 established"), (8, 22, "Reconnaissance"), (20, 40, "Credential access"),
                (40, 62, "Lateral movement"), (60, 80, "Data staging & exfiltration"),
                (85, None, "Impact")]
SPIDER_PHASES = [(5, None, "C2 established"), (10, 25, "Reconnaissance"), (25, 45, "Credential access"),
                 (45, 75, "Lateral movement"), (60, 90, "DNS tunnelling"),
                 (80, 105, "Data staging & exfiltration")]
# per-actor: C2 style, impact extension (None = wiper), CISA advisory
ACTORS = {
    "ndr-akira": ("AnyDesk RMM + Cloudflare tunnel + ngrok", ".akira", "CISA AA24-109A"),
    "ndr-medusa": ("Cloudflared + Ligolo reverse tunnel", ".medusa", "CISA AA25-071A"),
    "ndr-black-basta": ("Cobalt Strike HTTP + SMB named pipes", ".basta", "CISA AA24-131A"),
    "ndr-play": ("Cobalt Strike / SystemBC", ".play", "CISA AA23-352A"),
    "ndr-handala": ("Telegram bot API + icanhazip", None, "Void Manticore (no public advisory)"),
}


def _free_server_addrs(ctx, n):
    pfx = ctx.link.server_prefix
    taken = {h.ipb[3] for h in ctx.h.values() if h.ipb[:3] == pfx}
    out = []
    for last in rng.sample([x for x in range(20, 250) if x not in taken], n):
        ip = ".".join(str(b) for b in pfx) + "." + str(last)
        out.append(Host("UNUSED-%d" % last, ip, "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)),
                        "linux", "unused", "", ""))
    return out


def _enum_directory(ctx):
    """The objects the recon reads, as (dn, attributes) lists per object class."""
    from .accounts import SERVICE_ACCOUNTS, PRIVILEGED_ACCOUNTS, PRIV_GROUPS
    dom = P.BASE_DN
    sid = b"\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00" + os.urandom(12)
    ldap_ts = lambda days: "%d" % (132_000_000_000_000_000 + days * 864_000_000_000)
    users, seen = [], set()
    for i in range(1, 76):
        u = P.username_for((H('WS-') + "%03d") % i)
        if u in seen:
            u = "%s%d" % (u, i)
        seen.add(u)
        users.append((f"CN={u},OU=Staff,OU=Users,{dom}", {
            "sAMAccountName": [u], "displayName": [u.title()], "userPrincipalName": [f"{u}@{P.DOMAIN}"],
            "memberOf": [f"CN=Logistics-Staff,OU=Groups,{dom}", f"CN=Intranet-Users,OU=Groups,{dom}"],
            "department": [rng.choice(["Operations", "Dispatch", "Finance", "IT"])],
            "userAccountControl": ["512"], "pwdLastSet": [ldap_ts(rng.randint(1, 900))],
            "lastLogonTimestamp": [ldap_ts(rng.randint(900, 1000))], "objectSid": [sid + struct.pack("<I", 1100 + i)]}))
    spn_objs = []
    for name, host, svc, why in SERVICE_ACCOUNTS:
        d = (f"CN={name},OU=Service Accounts,{dom}", {
            "sAMAccountName": [name], "description": [why], "userAccountControl": ["66048"],
            "memberOf": [f"CN=Service-Accounts,OU=Groups,{dom}"], "pwdLastSet": [ldap_ts(rng.randint(300, 1500))],
            "servicePrincipalName": [f"{svc}/{host.lower()}.{P.DOMAIN}"], "objectSid": [sid + struct.pack("<I", 1500 + len(users))]})
        users.append(d)
        spn_objs.append(d)
    admins = []
    for name, tier, why in PRIVILEGED_ACCOUNTS:
        d = (f"CN={name},OU=Admins,{dom}", {
            "sAMAccountName": [name], "description": [why], "adminCount": ["1"], "userAccountControl": ["512"],
            "memberOf": [f"CN={'Domain Admins' if tier == 0 else 'Help Desk'},OU=Groups,{dom}"],
            "pwdLastSet": [ldap_ts(rng.randint(10, 200))], "objectSid": [sid + struct.pack("<I", 1800 + len(users))]})
        users.append(d)
        admins.append(d)
    comps, comp_spn = [], []
    wins = sorted((h for h in ctx.h.values() if "windows" in h.os.lower() and h.fqdn), key=lambda h: h.name)
    for h in wins:
        ou = "Domain Controllers" if h.name.startswith(H('DC')) else ("Servers" if h.role.lower().find("server") >= 0 else "Workstations")
        spns = [f"HOST/{h.fqdn}", f"HOST/{h.name}", f"RestrictedKrbHost/{h.fqdn}", f"TERMSRV/{h.name}"]
        if h.name.startswith(H('DC')):
            spns += [f"ldap/{h.fqdn}", f"GC/{h.fqdn}/{P.DOMAIN}", f"E3514235-4B06-11D1-AB04-00C04FC2DCD2/{h.fqdn}/{P.DOMAIN}"]
        d = (f"CN={h.name},OU={ou},{dom}", {
            "cn": [h.name], "dNSHostName": [h.fqdn], "operatingSystem": [h.os],
            "operatingSystemVersion": ["10.0 (20348)" if "server" in h.os.lower() else "10.0 (19045)"],
            "servicePrincipalName": spns, "userAccountControl": ["4096" if ou != "Domain Controllers" else "532480"],
            "lastLogonTimestamp": [ldap_ts(rng.randint(990, 1000))], "objectSid": [sid + struct.pack("<I", 2000 + len(comps))]})
        comps.append(d)
        comp_spn.append(d)
    groups = []
    for g in PRIV_GROUPS + ["Logistics-Staff", "Intranet-Users", "Service-Accounts", "IT-Operations", "VPN-Users", "Finance-Share"]:
        members = [u[0] for u in users if f"CN={g}," in "".join(u[1].get("memberOf", []))] or [users[-1][0]]
        a = {"cn": [g], "member": members[:120], "groupType": ["-2147483646"], "objectSid": [sid + struct.pack("<I", 2500 + len(groups))]}
        if g in ("Domain Admins", "Enterprise Admins", "Server Operators", "Backup Operators"):
            a["adminCount"] = ["1"]
        groups.append((f"CN={g},OU=Groups,{dom}", a))
    ous = [(f"OU={o},{dom}", {"ou": [o], "distinguishedName": [f"OU={o},{dom}"], "gPLink": [f"[LDAP://CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{dom};0]"]})
           for o in ("Staff", "Service Accounts", "Admins", "Workstations", "Servers", "Domain Controllers", "Groups")]
    return {"user": users, "computer": comps, "group": groups, "spn": spn_objs + comp_spn,
            "admin": admins + [g for g in groups if "adminCount" in g[1]], "organizationalUnit": ous}


def recon_ldap_session(ctx, src, ts, dc=None):
    """LDAP enumeration the way a collector does it: Kerberos bind, then subtree searches from the domain
    base for users, computers, groups, SPN holders, adminCount=1 and OUs, the large ones with the RFC 2696
    paged-results control (page size RECON_LDAP_PAGE, cookie round trips)."""
    dc = dc or ctx.h[H('DC1')]
    user = P.username_for(src.name)
    pre, t = F.kerberos_tgs(ctx, src, "ldap", dc, ts)
    out = ctx.arp_for(src, dc, t)
    s = ctx.tcp(src, dc, 389, t + 0.001).handshake()
    mid = 1
    s.c2s(P.ldap_bind_request(mid, P.krb_ap_req_token(user, "ldap", dc.fqdn)), think=0.0005)
    s.s2c(P.ldap_bind_response(mid), think=rng.uniform(0.001, 0.004))
    d = _enum_directory(ctx)
    plan = [("user", "user", ["sAMAccountName", "displayName", "memberOf", "userAccountControl", "pwdLastSet", "description", "servicePrincipalName", "adminCount", "objectSid", "lastLogonTimestamp"]),
            ("computer", "computer", ["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion", "servicePrincipalName", "userAccountControl", "lastLogonTimestamp", "objectSid"]),
            ("group", "group", ["cn", "member", "groupType", "adminCount", "objectSid"]),
            ("spn", None, ["sAMAccountName", "cn", "servicePrincipalName", "dNSHostName"]),
            ("admin", None, ["sAMAccountName", "cn", "memberOf", "adminCount", "description"]),
            ("organizationalUnit", "organizationalUnit", ["ou", "distinguishedName", "gPLink"])]
    for (key, _cls, attrs), (fattr, fval) in zip(plan, RECON_LDAP_FILTERS, strict=False):
        filt = P._filter_present(fattr) if fval == "*" else P._filter_eq(fattr, fval)
        objs = d[key]
        cookie, first = b"\x00", True
        mid += 1
        i = 0
        while True:
            chunk = objs[i:i + RECON_LDAP_PAGE]
            i += RECON_LDAP_PAGE
            s.c2s(P.ldap_search_request(mid, P.BASE_DN, 2, filt, attrs, controls=P.ldap_paged_control(RECON_LDAP_PAGE, b"" if first else cookie)),
                  think=rng.uniform(0.01, 0.06))
            first = False
            more = i < len(objs)
            cookie = os.urandom(8) if more else b""
            resp = b"".join(P.ldap_search_entry(mid, dn, at) for dn, at in chunk)
            resp += P.ldap_search_done(mid, controls=P.ldap_paged_control(0 if not more else len(objs), cookie))
            s.s2c(resp, think=rng.uniform(0.004, 0.02))
            if not more:
                break
            mid += 1
    mid += 1
    s.c2s(P.ldap_unbind(mid), think=rng.uniform(0.01, 0.2))
    pk = s.close(think=0.0005)
    return F.merged(pre, out, pk)


def ndr_recon(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    srv = victims_servers(ctx)
    L0 = win[0]
    # 1) ICMP host-discovery sweep across the server subnet (one scanner, one identifier; a few addresses are unused)
    srv_pfx = ctx.link.server_prefix              # configurable subnets: never hard-code this
    hosts = [ctx.h[n] for n in ctx.h if ctx.h[n].ipb[:3] == srv_pfx and n not in ("FW-A", "FW-B", "FW-OUT")]
    s(L0 + RECON_PHASES[0][0], icmp_sweep, atk, hosts, absent=_free_server_addrs(ctx, 3))
    # 2) TCP SYN port scan of the victim servers, one continuous pass at scanner speed (4 ms probe spacing)
    tgts = []
    for h in srv:
        for p in RECON_PORTS:
            tgts.append((h, p, p in RECON_OPEN.get(h.name, set())))
    rng.shuffle(tgts)
    s(L0 + RECON_PHASES[1][0], syn_scan, atk, tgts)
    # 3) LDAP enumeration of the whole directory (users, computers, groups, SPNs, adminCount, OUs)
    for k in range(RECON_LDAP_SESSIONS):
        s(L0 + RECON_PHASES[2][0] + k * 30, recon_ldap_session, atk, dc=ctx.h[H('DC1')])
    # 4) SMB share enumeration (srvsvc NetShareEnumAll) against each server
    for i, h in enumerate(srv):
        s(L0 + RECON_PHASES[3][0] + i * 8, smb_share_enum, atk, h)


def smb_share_enum(ctx, src, target, ts):
    s, smb, pre = F._smb_open(ctx, src, target, "IPC$", ts, user="svc_backup")
    s.c2s(smb.create_req("srvsvc", pipe=True), think=0.003)
    r, fid = smb.create_resp(s.t, 0)
    s.s2c(r, think=0.0008)
    cid = rng.randint(1, 300)
    bind = P.dcerpc_bind(cid, P.SRVSVC_UUID, 3, auth=("svc_backup", "cifs", target.fqdn))
    s.c2s(smb.write_req(fid, 0, bind), think=0.001)
    s.s2c(smb.write_resp(len(bind)), think=0.0006)
    s.c2s(smb.read_req(fid, 0, 1024), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_bind_ack(cid, "\\PIPE\\srvsvc", auth=True)), think=0.0008)
    # NetShareEnumAll (opnum 15)
    s.c2s(smb.write_req(fid, 0, P.dcerpc_request(cid + 1, 15, P.blob(120), sealed=True)), think=0.002)
    s.s2c(smb.write_resp(200), think=0.0006)
    s.c2s(smb.read_req(fid, 0, 4096), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_response(cid + 1, P.blob(rng.randint(400, 1400)), sealed=True)), think=rng.uniform(0.002, 0.02))
    s.c2s(smb.close_req(fid), think=0.003)
    s.s2c(smb.close_resp(s.t, 0), think=0.0008)
    return F.merged(pre, F._smb_close(s, smb))


def ndr_lateral_movement(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    L0 = win[0]
    # RDP from a workstation to servers (abnormal: workstations don't normally RDP to servers),
    # PsExec-style SMB admin-share execution, WMI remote exec, and a second popped workstation
    # spreading the same techniques. Driven from LATERAL_PLAN so the diagram cannot drift.
    for off, src_name, tgt, tech, dur in LATERAL_PLAN:
        src = atk if src_name == ATTACKER_WS else ctx.h[src_name]
        if tech == "RDP":
            s(L0 + off, F.rdp_session, src, ctx.h[tgt], duration=rng.uniform(*dur))
        elif tech.startswith("SMB"):
            s(L0 + off, smb_admin_exec, src, ctx.h[tgt])
        else:
            s(L0 + off, wmi_exec, src, ctx.h[tgt])


def ndr_credential_access(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    L0 = win[0]
    # Kerberoasting: a burst of TGS-REQ for many SPNs, each asking for RC4
    s(L0 + CRED_PHASES[0][0], kerberoast, atk)
    # AS-REP roasting: AS-REQ without pre-auth for several accounts
    s(L0 + CRED_PHASES[1][0], asrep_roast, atk)
    # Password spray: Kerberos AS-REQ pre-auth failures across many users, one password
    s(L0 + CRED_PHASES[2][0], password_spray, atk)
    # DCSync: DRSUAPI DsGetNCChanges from a non-DC host
    s(L0 + CRED_PHASES[3][0], dcsync, atk, ctx.h[H("DC1")])


def kerberoast(ctx, src, ts):
    dc = ctx.h[H('DC1')]
    spns = KERBEROAST_SPNS
    out = ctx.arp_for(src, dc, ts)
    user = P.username_for(src.name)
    t = ts
    for svc, host in spns:
        s = ctx.tcp(src, dc, 88, t + 0.001).handshake()
        # ask for RC4 only (etype 23) so the ticket comes back encrypted under the service
        # account's NTLM hash — the Kerberoasting tell
        req = P.krb_tgs_req(user, svc, host, t, rng.getrandbits(31),
                            etypes=P.KRB_ETYPES_RC4_ONLY)
        s.c2s(_krb_tcp(req), think=0.0006)
        rep = P.krb_tgs_rep(user, svc, host, etype=23)   # RC4 ticket + enc-part: the Kerberoast tell
        s.s2c(_krb_tcp(rep), think=rng.uniform(0.001, 0.01))
        out += s.close(think=0.001)
        t += rng.uniform(0.2, 1.2) * rng.uniform(0.7, 1.4)   # jittered cadence
    return F.merged(out)


def asrep_roast(ctx, src, ts):
    dc = ctx.h[H('DC1')]
    out = ctx.arp_for(src, dc, ts)
    t = ts
    for u in ASREP_ACCOUNTS:
        s = ctx.tcp(src, dc, 88, t + 0.001).handshake()
        s.c2s(_krb_tcp(P.krb_as_req(u, t, rng.getrandbits(31), False)), think=0.0006)
        rep = P.krb_as_rep(u, etype=23)   # AS-REP returned WITHOUT pre-auth, RC4 (Rubeus-style roast)
        s.s2c(_krb_tcp(rep), think=rng.uniform(0.001, 0.008))
        out += s.close(think=0.001)
        t += rng.uniform(0.3, 1.5)
    return F.merged(out)


def password_spray(ctx, src, ts):
    dc = ctx.h[H("DC1")]
    out = ctx.arp_for(src, dc, ts)
    t = ts
    users = [P.username_for(H("WS-%03d" % i)) for i in range(SPRAY_FIRST, SPRAY_LAST)]
    for u in users:
        s = ctx.tcp(src, dc, 88, t + 0.001).handshake()
        s.c2s(_krb_tcp(P.krb_as_req(u, t, rng.getrandbits(31), True)), think=0.0006)
        s.s2c(_krb_tcp(P.krb_error_preauth(u, t, code=24)), think=rng.uniform(0.001, 0.006))  # KDC_ERR_PREAUTH_FAILED
        out += s.close(think=0.001)
        t += rng.uniform(0.4, 1.6)
    return F.merged(out)


def _krb_tcp(b):
    return struct.pack("!I", len(b)) + b


def dcsync(ctx, src, target, ts):
    """DRSUAPI replication pull from a host that is NOT a domain controller. A real DCSync first
    gets an ldap/ service ticket to the target DC (that is how the tool authenticates at all);
    the DRSUAPI call ids then increase per request, as a real client's do."""
    pre, ts = F.kerberos_tgs(ctx, src, "ldap", target, ts, force=True)
    out = ctx.arp_for(src, target, ts)
    dport = rng.randint(49152, 49230)
    s = ctx.tcp(src, target, 135, ts + 0.001).handshake()
    cid = rng.randint(1, 200)
    s.c2s(P.dcerpc_bind(cid, P.EPM_UUID, 3), think=0.0006)
    s.s2c(P.dcerpc_bind_ack(cid, "135"), think=0.001)
    s.c2s(P.dcerpc_request(cid + 1, 3, P.epm_map_request(P.DRSUAPI_UUID, 4, target.ipb)), think=0.0008)
    s.s2c(P.dcerpc_response(cid + 1, P.epm_map_response(P.DRSUAPI_UUID, 4, dport, target.ipb)), think=0.0015)
    pk = s.close(think=0.002)
    s2 = ctx.tcp(src, target, dport, s.t + 0.003).handshake()
    auth = (P.username_for(src.name), "E3514235-4B06-11D1-AB04-00C04FC2DCD2", target.fqdn)
    s2.c2s(P.dcerpc_bind(cid + 2, P.DRSUAPI_UUID, 4, auth=auth), think=0.0006)
    s2.s2c(P.dcerpc_bind_ack(cid + 2, str(dport), auth=True), think=0.001)
    # DsBind then several DsGetNCChanges pulling secrets, each with its own increasing call id
    call = cid + 3
    s2.c2s(P.dcerpc_request(call, 0, P.blob(80), sealed=True), think=0.002)
    s2.s2c(P.dcerpc_response(call, P.blob(60), sealed=True), think=0.003)
    for _ in range(rng.randint(3, 6)):
        call += 1
        s2.c2s(P.dcerpc_request(call, 3, P.blob(220), sealed=True), think=rng.uniform(0.01, 0.05))
        s2.s2c(P.dcerpc_response(call, P.blob(rng.randint(3000, 20000)), sealed=True), think=rng.uniform(0.02, 0.1))
    pk2 = s2.close(think=rng.uniform(0.05, 0.3))
    return F.merged(pre, out, pk, pk2)


def ndr_c2_beaconing(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    lo, hi = win
    # RMM cloud first-time connection (the platform's RMM detector signal)
    s(lo + C2_RMM_AT, rmm_beacon, atk, "rmm", 2)
    # low-and-slow HTTPS beacon to C2 every ~60 s with jitter, all window long
    t = lo + 60
    while t < hi:
        s(t, rmm_beacon, atk, "c2", 1)
        t += C2_BEACON_BASE * rng.uniform(*C2_JITTER)     # jittered interval
    # a persistent ngrok-style tunnel opened mid-window and held open (long-lived TLS)
    s(lo + C2_TUNNEL_AT, ngrok_tunnel, atk, until=hi)


def ngrok_tunnel(ctx, src, ts, until=None):
    """A real ngrok/reverse-tunnel connection: opaque application data on one persistent TLS
    session, held open at least an hour (or to the end of the window), not a 110 s HTTP browse."""
    site = (ext(ctx, "ngrok").fqdn, ext(ctx, "ngrok"))
    duration = max(3600.0, (until - ts)) if until else 3600.0
    return F.tls_channel(ctx, src, site, ts, duration=duration, period=30.0, tls_profile="winhttp", rate=40e6)


def ndr_dns_tunneling(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    lo, hi = win
    t = lo + 10
    while t < hi:
        s(t, dns_tunnel_burst, atk, rng.randint(*DNSTUN_BURST))
        t += rng.uniform(*DNSTUN_GAP)


def _public_host(ctx, key, name, ip, hops=9):
    cache = ctx.__dict__.setdefault("_pubhosts", {})
    if key not in cache:
        h = Host(name.upper(), ip, "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)),
                 "linux", "external", "198.51.100.0/24", name)
        h.hops = hops
        cache[key] = h
    return cache[key]


def dns_tunnel_burst(ctx, src, count, ts):
    """Many long encoded TXT queries to the corporate resolver, which recurses to the attacker NS.
    The resolver sends its own transaction id upstream (RD clear, EDNS0), the NS answers with that id,
    and the resolver relays the same answer bytes to the client with AA clear. The first burst walks the
    delegation (root, TLD) before the NS is asked; about 1 in 150 upstream queries times out (SERVFAIL)."""
    dc = ctx.h[H('DC1')]
    ns = ext(ctx, "dnsns")
    out = ctx.arp_for(src, dc, ts)
    t = ts
    if not ctx.__dict__.get("_dnstun_delegated"):
        ctx.__dict__["_dnstun_delegated"] = True
        root = _public_host(ctx, "root-a", "a.root-servers.net", "198.41.0.4", 7)
        tld = _public_host(ctx, "tld-io", "a0.nic.io", "194.0.1.1", 8)
        tldn = TUNNEL_DOMAIN.rsplit(".", 1)[-1]
        zone = ".".join(TUNNEL_DOMAIN.split(".")[-2:])
        for host, qn, ref_zone, ref_ns in ((root, tldn, tldn, [f"a0.nic.{tldn}"]), (tld, zone, zone, [ns.fqdn])):
            x = ctx.next_txid()
            dsp = dc.eph()
            out += ctx.arp_for(dc, host, t)
            out.append(ctx.udp(dc, host, dsp, 53, P.dns_query(x, qn, 2, rd=False, edns=True), t))
            out.append(ctx.udp(host, dc, 53, dsp, P.dns_referral(x, qn, 2, ref_zone, ref_ns), t + rng.uniform(0.012, 0.04), vantage=dc))
            t += 0.06
    for _ in range(count):
        txid = ctx.next_txid()
        sport = src.eph()
        payload = os.urandom(rng.randint(20, 45))
        q = P.dns_tunnel_query(txid, payload, TUNNEL_DOMAIN, qtype=P.DNS_TXT)
        out.append(ctx.udp(src, dc, sport, 53, q, t))
        qname = _qname_of(q)
        dtx = ctx.next_txid()
        dsport = dc.eph()
        out += ctx.arp_for(dc, ns, t + 0.0005)
        uq = P.dns_tunnel_query(dtx, payload, TUNNEL_DOMAIN, qtype=P.DNS_TXT, rd=False, edns=True)
        out.append(ctx.udp(dc, ns, dsport, 53, uq, t + 0.0007))
        if rng.random() < 0.007:
            # the NS does not answer: one resolver retry, then SERVFAIL to the client
            out.append(ctx.udp(dc, ns, dsport, 53, uq, t + 1.5))
            out.append(ctx.udp(dc, src, 53, sport, P.dns_response(txid, qname, P.DNS_TXT, [], rcode=2, aa=False), t + rng.uniform(3.0, 3.6), vantage=src))
            t += rng.uniform(0.05, 0.2)
            continue
        data = os.urandom(rng.randint(40, 160))
        resp = P.dns_tunnel_response(dtx, qname, data, qtype=P.DNS_TXT)
        out.append(ctx.udp(ns, dc, 53, dsport, resp, t + rng.uniform(0.02, 0.08), vantage=dc))
        out.append(ctx.udp(dc, src, 53, sport, P.dns_tunnel_response(txid, qname, data, aa=False), t + rng.uniform(0.09, 0.12), vantage=src))
        t += rng.uniform(0.05, 0.2)
    return F.merged(out)


def _qname_of(query_bytes):
    """Extract the QNAME string from a raw DNS query for building the response."""
    i = 12
    labels = []
    while query_bytes[i]:
        n = query_bytes[i]
        labels.append(query_bytes[i + 1:i + 1 + n].decode("latin1"))
        i += 1 + n
    return ".".join(labels)


def ndr_data_exfil(ctx, eng, tag, win, exfil_ua=None):
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    lo, hi = win
    # 1) staging: bulk SMB reads from FILE1 (pulling shares to the attacker host)
    s(lo + 10, F.smb_bulk_transfer, atk, ctx.h[H('FILE1')], "Dept", int(60e6 * ctx.scale), direction="read")
    # 2) pull a big result set from SQL1 via the intranet path is normal; here attacker reads a DB backup share
    s(lo + 20, F.smb_bulk_transfer, atk, ctx.h[H('BACKUP1')], "Users", int(30e6 * ctx.scale), direction="read")
    # 3) exfil: large sustained HTTPS upload to external storage (asymmetric, client->server heavy)
    s(lo + 600, exfil_upload, atk, int(90e6 * ctx.scale), ua=exfil_ua)


def exfil_upload(ctx, src, total, ts, ua=None):
    """Sustained outbound upload to generic S3-compatible object storage over TLS (PUT per part,
    the real semantics of that style of API). Non-flat: a short ramp of smaller parts, per-part
    size and rate jitter, and one short pause partway through, instead of a constant stream.

    ua: a specific exfil tool's user agent (e.g. an rclone build), for a chain whose own registry
    text names the tool; left None, every other caller keeps the generic browser UA unchanged."""
    from .tls import TlsSession
    site = ext(ctx, "exfil")
    ua = ua or P.UAS[0]
    pre = F.dns_lookup(ctx, src, site.fqdn, ts, external=True, answers=[(1, site.ipb)])
    t = ts + rng.uniform(0.01, 0.05)
    out = ctx.arp_for(src, site, t)
    s = ctx.tcp(src, site, 443, t + 0.001, rate=80e6).handshake()
    tls = TlsSession(ctx.pki, site.fqdn, ctx.keylog)
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.001, 0.01))
    base_chunk = 4_000_000
    sent = 0
    part = 0
    paused = False
    while sent < total:
        ramp = min(1.0, 0.25 + part * 0.15)            # the first few parts are smaller (ramp-up)
        n = min(total - sent, max(256_000, int(base_chunk * ramp * rng.uniform(0.6, 1.4))))
        body = P.blob(n)
        req = P.http_request("PUT", f"/upload/part-{part:04d}", site.fqdn, ua,
                             ["Content-Type: application/octet-stream", f"Content-Length: {n}"])
        s.c2s(tls.app_data(True, req + body), think=rng.uniform(0.03, 0.6))
        s.s2c(tls.app_data(False, P.http_response("201 Created", b'{"ok":true}', "application/json", s.t)), think=rng.uniform(0.02, 0.15))
        sent += n
        part += 1
        if not paused and 0.4 < sent / total < 0.6:    # one short pause partway through
            paused = True
            s.idle(rng.uniform(3.0, 8.0))
    s.c2s(tls.close_notify(True), think=0.5)
    return F.merged(pre, out, s.close(think=0.01))


def ndr_scattered_spider(ctx, eng, tag, win):
    """Chained kill chain: recon -> creds -> lateral -> (C2 throughout) -> staging -> exfil."""
    lo = win[0]

    def W(a, b):
        return (lo + a * 60, lo + b * 60)
    # C2 established early and runs low-and-slow across the whole campaign
    ndr_c2_beaconing(ctx, eng, tag, (lo + 5 * 60, win[1]))
    ndr_recon(ctx, eng, tag, W(10, 25))
    ndr_credential_access(ctx, eng, tag, W(25, 45))
    ndr_lateral_movement(ctx, eng, tag, W(45, 75))
    ndr_dns_tunneling(ctx, eng, tag, W(60, 90))
    ndr_data_exfil(ctx, eng, tag, W(80, 105))


# ============================================== ransomware / actor impact prims
RANSOM_NOTES = {".akira": "akira_readme.txt", ".medusa": "!!!READ_ME_MEDUSA!!!.txt",
                ".basta": "readme.txt", ".play": "ReadMe.txt"}


# Ransom note of the standalone ndr-ransomware-encryption module (hidden reference of the NDR-08 lab:
# the chat code the victim is told to log in with, as in real Akira notes). Written in its own short
# SMB session per share, so a sensor that keeps only part of a long session still holds the packets.
AKIRA_CHAT_CODE = "wB7k9QxT3mZp5Rj2Vn"


AKIRA_NOTE_TEXT = (
    "Hi friends,\r\n\r\n"
    "Whatever who you are and what your title is if you're reading this it means the internal "
    "infrastructure of your company is fully or partially dead, all your backups - virtual, physical "
    "- everything that we managed to reach - are completely removed. Moreover, we have taken a great "
    "amount of your corporate data prior to encryption.\r\n\r\n"
    "Well, for now let's keep all the tears and resentment to ourselves and try to build a constructive "
    "dialogue. We're fully aware of what damage we caused by locking your internal sources. At the "
    "moment, you have to know:\r\n\r\n"
    "1. Dealing with us you will save your company from huge dangers.\r\n"
    "2. We are not interested in destroying your business, we want to get a payment for our work.\r\n\r\n"
    "Contact us via TOR browser:\r\n"
    "1. Download and install TOR Browser from this site: https://torproject.org/\r\n"
    "2. Paste this link - https://k7vq3xwz2hn5dmpyb4r6tjlf8cgouea2s9ixkn4wvhd3qmrp5zyb7lad.onion/\r\n"
    "3. Use this code - {code} - to log into our chat.\r\n\r\n"
    "Keep in mind that the faster you will get in touch, the less damage we cause.\r\n")


# The Akira chain's own note file is not the standalone NDR-08 scenario's akira_readme.txt: the two are told
# apart by name and by text (the chain's note has no chat line).
CHAIN_NOTE_NAMES = {".akira": "powerrangers.txt"}


NOTE_SESSION_DELAY = (1.0, 3.0)    # the note session opens this long after the encrypting session


# Notes of the actor chains. Each family has its own wording and contact channel; the {code} slot is a
# victim id generated per run (it is NOT a lab flag: a chain's hidden reference is the owner's to place).
CHAIN_NOTES = {
    ".akira": (
        "Your corporate network has been breached and the files on your servers are encrypted. A copy of "
        "your internal data is in our hands.\r\n\r\n"
        "Do not rename the encrypted files and do not run recovery tools; they can damage the data for good.\r\n\r\n"
        "To get the decryptor and the deletion proof, write to akira-recovery@onionmail.example and quote "
        "your victim id: {code}\r\n"
        "Replies are sent within 72 hours.\r\n"),
    ".medusa": (
        "Medusa Locker has encrypted your files. All your important data has been exfiltrated and will be "
        "published on our blog if you do not contact us.\r\n\r\n"
        "What guarantees do you have? We value our reputation: after payment we delete the data and give you "
        "the decryptor, and you may test-decrypt three small files.\r\n\r\n"
        "Contact: medusa-support@onionmail.example, Tox chat 7E1C0F3A9B2D44C6A8E5F0B1D2C3A49687758695A4B3C2D1E0F9\r\n"
        "Your victim id: {code}\r\n"
        "You have 10 days before the data is published and the price doubles.\r\n"),
    ".basta": (
        "Your data are stolen and encrypted.\r\n\r\n"
        "The data will be published on TOR website if you do not pay the ransom.\r\n\r\n"
        "You can contact us and decrypt one file for free on this TOR site (you should download and install "
        "TOR browser first https://torproject.org): http://b4sta7kq2vnxw3zjfhm5r6tdlpyc8guoea9sbi4kn2wvhd3.onion\r\n\r\n"
        "Your company id for log in: {code}\r\n"),
    ".play": (
        "Your data has been encrypted. PLAY\r\n\r\n"
        "Do not rename or modify the encrypted files; do not use third-party decryption tools, they can damage "
        "the data permanently.\r\n\r\n"
        "To recover, contact us: pl4y-recovery@proton.example\r\n"
        "Reference: {code}\r\n"
        "Use a different mail provider if you receive no answer within 48 hours.\r\n"),
}


def _chain_reseed(tag):
    """Give an actor chain its own random streams. Every module owns a generator that is seeded the same
    way at the start of a build, so two chains built alone drew identical sequences and produced the same
    recon, credential, lateral and exfil traffic; salting each generator with the chain's tag separates them."""
    from . import core as _core, protocols as _p
    for m in (sys.modules[__name__], F, _p, _core):
        m.rng.seed("%s|%s|%d" % (tag, m.__name__, m.rng.getrandbits(32)))


def ransom_note_session(ctx, src, server, share, name, text, ts):
    """The encryptor drops its note over a short SMB session of its own (a separate thread):
    negotiate, session setup, tree connect, CREATE (new file), one WRITE of the note, CLOSE, logoff."""
    s, smb, pre = F._smb_open(ctx, src, server, share, ts, user="svc_backup")
    data = text.encode("ascii")
    s.c2s(smb.create_req(name, write=True), think=rng.uniform(0.001, 0.004))
    rn, nfid = smb.create_resp(s.t, 0, action=2)
    s.s2c(rn, think=0.0004)
    s.c2s(smb.write_req(nfid, 0, data), think=0.0004)
    s.s2c(smb.write_resp(len(data)), think=0.0004)
    s.c2s(smb.close_req(nfid), think=0.0004)
    s.s2c(smb.close_resp(s.t, len(data)), think=0.0003)
    return F.merged(pre, F._smb_close(s, smb))


RANSOM_BLOCK = 1 << 20      # 1 MiB per READ/WRITE (CreditCharge 16)


def ransom_encrypt(ctx, src, server, ext, ts, share="Dept", note_text=None, note_dirs=("",), note_name=None):
    """Encryption/impact phase: an SMB read+write-in-place storm over a file share. Each file is
    opened (FILE_OPEN, read+write+DELETE), read and rewritten block by block, then renamed to
    <name><ext> with a SET_INFO FileRenameInformation on the same handle, as the Windows encryptors do.
    The ransom note follows: with `note_text`, in a short SMB session of its own (one per
    `note_dirs` entry, since a real encryptor drops a note in every directory it touched);
    without it, as one write in the encrypting session."""
    s, smb, pre = F._smb_open(ctx, src, server, share, ts, user="svc_backup")
    s.streaming = True      # bulk read/write at LAN speed: ACKs do not hold the sender back
    # enumerate the share: one directory entry per file (a name exists once in a folder, so each
    # is opened and renamed once)
    s.c2s(smb.create_req("", write=False), think=rng.uniform(0.002, 0.02))
    r, dfid = smb.create_resp(s.t, 0, directory=True)
    s.s2c(r, think=0.0008)
    nfiles = int(rng.randint(30, 80) * max(0.15, min(1.0, ctx.scale)))
    names = set()
    while len(names) < nfiles:
        name = rng.choice(F.FILE_NAMES).replace("{n}", str(rng.randint(10000, 99999)))
        if name in names:
            stem, dot, suffix = name.rpartition(".")
            name = f"{stem}-{rng.randint(2, 9)}{dot}{suffix}"
        names.add(name)
    cap = int(800_000 * max(0.15, min(1.0, ctx.scale)))
    listing = [(name, min(rng.randint(20_000, 800_000), cap), False) for name in sorted(names)]
    rng.shuffle(listing)
    s.s2c(smb.query_dir_resp(listing + [("Archive", 0, True)], s.t), think=rng.uniform(0.001, 0.004))
    s.c2s(smb.close_req(dfid), think=0.0006)
    s.s2c(smb.close_resp(s.t, 0), think=0.0006)
    t_first = s.t
    for name, size, _ in listing:
        # open the original, read it, write the ciphertext back in place
        s.c2s(smb.open_existing_req(name), think=rng.uniform(0.0008, 0.006))
        rr, fid = smb.create_resp(s.t, size, action=1)
        s.s2c(rr, think=0.0006)
        off = 0
        while off < size:
            nrd = min(RANSOM_BLOCK, size - off)     # large blocks, multi-credit, as the encryptors issue them
            s.c2s(smb.read_req(fid, off, nrd), think=0.0002)
            s.s2c(smb.read_resp(P.blob(nrd)), think=0.0003)
            s.c2s(smb.write_req(fid, off, P.blob(nrd)), think=0.0002)   # high-entropy ciphertext, same length
            s.s2c(smb.write_resp(nrd), think=0.0003)
            off += nrd
        # the encrypted file takes its new name: rename on the open handle, then close it
        s.c2s(smb.set_info_rename_req(fid, name + ext), think=0.0004)
        s.s2c(smb.set_info_resp(), think=0.0004)
        s.c2s(smb.close_req(fid), think=0.0004)
        s.s2c(smb.close_resp(s.t, size), think=0.0004)
    out = [pre]
    note = note_name or RANSOM_NOTES.get(ext, "readme.txt")
    if note_text is None:
        s.c2s(smb.create_req(note, write=True), think=0.001)
        rn, nfid = smb.create_resp(s.t, 0)
        s.s2c(rn, think=0.0004)
        brief = b"Your network has been encrypted. Contact us via the onion link in this note.\r\n"
        s.c2s(smb.write_req(nfid, 0, brief), think=0.0004)
        s.s2c(smb.write_resp(len(brief)), think=0.0004)    # the reply counts what was written (78), not a round 80
        s.c2s(smb.close_req(nfid), think=0.0004)
        s.s2c(smb.close_resp(s.t, len(brief)), think=0.0004)
    else:
        t_note = t_first + rng.uniform(*NOTE_SESSION_DELAY)
        for d in note_dirs:      # one note in every directory the encryptor touched
            out.append(ransom_note_session(ctx, src, server, share, (d + "\\" if d else "") + note, note_text, t_note))
            t_note += rng.uniform(1.0, 3.0)
    out.append(F._smb_close(s, smb))
    return F.merged(*out)


def share_wiper(ctx, src, server, ts, share="Dept"):
    """Void Manticore / Handala style: enumerate the share, then open existing files and
    overwrite them in place with random data (no rename, no <ext> artifact), then drop a
    defacement note. Same listing/paging convention as `ransom_encrypt`, so every opened name
    was first seen in a directory listing."""
    s, smb, pre = F._smb_open(ctx, src, server, share, ts, user="svc_backup")
    nfiles = int(rng.randint(25, 60) * max(0.15, min(1.0, ctx.scale)))
    s.c2s(smb.create_req("", write=False), think=rng.uniform(0.002, 0.02))
    r, dfid = smb.create_resp(s.t, 0, directory=True)
    s.s2c(r, think=0.0008)
    seen = set()
    listing = []
    while len(listing) < nfiles:
        name = rng.choice(F.FILE_NAMES).replace("{n}", str(rng.randint(10000, 99999)))
        if name in seen:
            continue
        seen.add(name)
        listing.append((name, rng.randint(20_000, 500_000), False))
    page = 40
    for off in range(0, len(listing), page):
        batch = listing[off:off + page]
        s.c2s(smb.query_dir_req(dfid), think=0.0006)
        tail = [("Archive", 0, True)] if off + page >= len(listing) else []
        s.s2c(smb.query_dir_resp(batch + tail, s.t), think=rng.uniform(0.001, 0.004))
    s.c2s(smb.close_req(dfid), think=0.0006)
    s.s2c(smb.close_resp(s.t, 0), think=0.0006)
    for name, size, _ in listing:
        size = int(size * max(0.15, min(1.0, ctx.scale)))
        s.c2s(smb.open_existing_req(name), think=rng.uniform(0.0008, 0.005))
        rr, fid = smb.create_resp(s.t, size, action=1)
        s.s2c(rr, think=0.0005)
        off = 0
        while off < size:
            nw = min(65536, size - off)
            s.c2s(smb.write_req(fid, off, P.blob(nw)), think=0.0002)   # random overwrite
            s.s2c(smb.write_resp(nw), think=0.0003)
            off += nw
        s.c2s(smb.close_req(fid), think=0.0004)
        s.s2c(smb.close_resp(s.t, size), think=0.0004)
    s.c2s(smb.create_req("HANDALA_README.txt", write=True), think=0.001)
    rn, nfid = smb.create_resp(s.t, 0)
    s.s2c(rn, think=0.0004)
    s.c2s(smb.write_req(nfid, 0, b"#FreePalestine - Handala. Your data has been wiped.\r\n"), think=0.0004)
    s.s2c(smb.write_resp(52), think=0.0004)
    s.c2s(smb.close_req(nfid), think=0.0004)
    s.s2c(smb.close_resp(s.t, 52), think=0.0004)
    return F.merged(pre, F._smb_close(s, smb))


BLACKBASTA_C2_IP, BLACKBASTA_C2_NAME = "203.0.113.77", "relay77.sync-edge.example"


PLAY_C2_IP, PLAY_C2_NAME = "203.0.113.88", "node88.cdn-relay.example"


# throwaway team servers (documentation range, built via _ext_src so neither reaches
# used_indicator_ips()/the threat export): one per actor chain that needs to differ from the
# shared, real `cobaltc2` ThreatFox indicator.
_COBALT_ACTOR_SITES = {"cobaltc2_bb": (BLACKBASTA_C2_NAME, BLACKBASTA_C2_IP), "cobaltc2_play": (PLAY_C2_NAME, PLAY_C2_IP)}


def cobalt_http_beacon(ctx, src, ts, key="cobaltc2"):
    """A single Cobalt Strike HTTP(S) beacon check-in to the team server (decryptable).

    key in _COBALT_ACTOR_SITES: that actor's own team server -- a throwaway documentation-range
    host (not the real, already-exported `cobaltc2` ThreatFox indicator), so two actor chains
    sharing this builder are not indistinguishable by infrastructure."""
    actor = _COBALT_ACTOR_SITES.get(key)
    site = (actor[0], _ext_src(ctx, actor[1], actor[0])) if actor else None
    return rmm_beacon(ctx, src, key, requests=1, ts=ts, site=site)


def cobalt_smb_pipe(ctx, a, b, ts, pipe=None, until=None):
    """Cobalt Strike SMB (named-pipe) beacon: ONE session and ONE pipe (same name) held open
    for the whole stretch, polled on a jittered sleep timer with small framed write/read pairs
    (a 4-byte little-endian length prefix, the External C2 framing, plus data) -- not a fresh
    session and random pipe name every call."""
    pipe = pipe or ("msagent_%02x" % rng.randint(0, 255))
    s, smb, pre = F._smb_open(ctx, a, b, "IPC$", ts, user="svc_backup")
    s.c2s(smb.create_req(pipe, pipe=True), think=rng.uniform(0.002, 0.02))
    r, fid = smb.create_resp(s.t, 0)
    s.s2c(r, think=0.0008)
    end = until if until else ts + rng.uniform(60, 240)
    while s.t < end:
        tasking = P.blob(rng.randint(36, 256))
        s.c2s(smb.write_req(fid, 0, struct.pack("<I", len(tasking)) + tasking), think=0.0)
        s.s2c(smb.write_resp(4 + len(tasking)), think=0.001)
        output = P.blob(rng.randint(56, 1396))
        s.c2s(smb.read_req(fid, 0, 4096), think=rng.uniform(0.1, 0.5))
        s.s2c(smb.read_resp(struct.pack("<I", len(output)) + output), think=0.002)
        s.idle(COBALT_PIPE_SLEEP * rng.uniform(*COBALT_JITTER))   # jittered sleep timer
    s.c2s(smb.close_req(fid), think=0.01)
    s.s2c(smb.close_resp(s.t, 0), think=0.001)
    return F.merged(pre, F._smb_close(s, smb))


TELEGRAM_BOT_TOKEN = "8234567123:AAFwJ3-xK9pL7nQ2vR4tY6uI8oP0aS3dEf"


def telegram_poll_session(ctx, src, ts, polls=None):
    """Telegram Bot API long polling: repeated GET /bot<token>/getUpdates on one persistent TLS
    connection, each held about 25-30 s (the real getUpdates timeout) before its reply, instead
    of a fresh TLS session and browser UA per check-in."""
    from .tls import TlsSession
    site = ext(ctx, "telegram")
    pre = F.dns_lookup(ctx, src, site.fqdn, ts, external=True, answers=[(P.DNS_A, site.ipb)])
    t = ts + rng.uniform(0.01, 0.05)
    out = ctx.arp_for(src, site, t)
    s = ctx.tcp(src, site, 443, t + 0.001, rate=40e6).handshake()
    tls = TlsSession(ctx.pki, site.fqdn, ctx.keylog, profile="go")
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.001, 0.006))
    for i in range(polls or rng.randint(2, 4)):
        req = P.http_request("GET", "/bot%s/getUpdates?timeout=30&offset=%d" % (TELEGRAM_BOT_TOKEN, rng.randint(1, 999)),
                             site.fqdn, "python-requests/2.31.0")
        s.c2s(tls.app_data(True, req), think=rng.uniform(0.5, 3.0) if i else rng.uniform(0.0008, 0.004))
        s.idle(rng.uniform(25.0, 30.0))      # the long-poll wait itself
        s.s2c(tls.app_data(False, P.http_response("200 OK", b'{"ok":true,"result":[]}', "application/json", s.t)),
              think=rng.uniform(0.01, 0.1))
    s.c2s(tls.close_notify(True), think=rng.uniform(0.5, 5.0))
    return F.merged(pre, out, s.close(think=0.01))


def handala_c2(ctx, eng, tag, win):
    """Handala's network-observable C2: icanhazip-style IP check + Telegram Bot API long polling."""
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    lo, hi = win
    s(lo + 5, ipcheck_call, atk)
    t = lo + 30
    while t < hi:
        s(t, telegram_poll_session, atk, polls=rng.randint(2, 4))
        t += rng.uniform(300, 600)   # fewer, longer-lived sessions, not a fresh one every beacon


def ipcheck_call(ctx, src, ts):
    site = (ext(ctx, "ipcheck").fqdn, ext(ctx, "ipcheck"))
    return F.https_session(ctx, src, site, ts, requests=1, sizes=[40], keep_open=0.2, rate=40e6, dns=True)


# ---- C2 style helpers for the actor chains ----------------------------------
def c2_rmm_cloud(ctx, eng, tag, win):        # Akira: AnyDesk/RMM + Cloudflare tunnel + ngrok
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    lo, hi = win
    s(lo + 20, rmm_beacon, atk, "rmm", requests=2)
    s(lo + 40, rmm_beacon, atk, "cloudflared", requests=2)
    t = lo + 90
    while t < hi:
        s(t, rmm_beacon, atk, "c2", requests=1)
        t += 60 * rng.uniform(0.75, 1.35)
    s(lo + 700, ngrok_tunnel, atk, until=hi)


def c2_tunnel(ctx, eng, tag, win):           # Medusa: Cloudflared + Ligolo reverse tunnel
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    lo, hi = win
    s(lo + 20, rmm_beacon, atk, "medusa_c2", requests=2)
    s(lo + 40, rmm_beacon, atk, "cloudflared", requests=2)   # real Cloudflared tunnel, a sustained opaque channel
    s(lo + 120, ngrok_tunnel, atk, until=hi)           # Ligolo-style persistent reverse tunnel (TLS)
    t = lo + 60
    while t < hi:
        s(t, rmm_beacon, atk, "medusa_c2", requests=1)
        t += 90 * rng.uniform(0.7, 1.4)


def c2_cobalt(ctx, eng, tag, win, key="cobaltc2"):           # Black Basta / Play: Cobalt Strike
    s = sched_factory(eng, ctx, tag, win)
    atk = attacker(ctx)
    servers = victims_servers(ctx)
    lo, hi = win
    t = lo + 20
    while t < hi:
        s(t, cobalt_http_beacon, atk, key=key)
        t += COBALT_BEACON_BASE * rng.uniform(*COBALT_JITTER)   # jittered HTTP beacon
    # SMB named-pipe peer-to-peer beacons: a small fixed set of child servers (distinct, picked
    # once), each with one long-lived pipe session held open for most of the window and polled
    # on a jittered sleep timer -- not a fresh session and random server/pipe every 220s.
    n_children = max(2, min(3, len(servers)))
    children = rng.sample(servers, n_children)
    for i, child in enumerate(children):
        pipe = "msagent_%02x" % rng.randint(0, 255)
        start = lo + 200 + i * 40
        s(start, cobalt_smb_pipe, atk, child, pipe=pipe, until=hi - 60)


# ---- the actor kill chains --------------------------------------------------
def _actor_chain(ctx, eng, tag, win, c2, ext=None, wiper=False):
    lo, hi = win
    _chain_reseed(tag)
    note_text = (CHAIN_NOTES.get(ext) or "").format(code=os.urandom(9).hex()) or None

    def W(a, b):
        return (lo + a * 60, lo + b * 60)
    # only Akira's own registry text names a specific exfil tool (rclone); every other chain
    # keeps the generic browser UA on the same shared exfil upload.
    exfil_ua = "rclone/v1.67.0" if ext == ".akira" else None
    c2(ctx, eng, tag, (lo + 3 * 60, hi))
    ndr_recon(ctx, eng, tag, W(8, 22))
    ndr_credential_access(ctx, eng, tag, W(20, 40))
    ndr_lateral_movement(ctx, eng, tag, W(40, 62))
    ndr_data_exfil(ctx, eng, tag, W(60, 80), exfil_ua=exfil_ua)
    # impact phase near the end
    atk = attacker(ctx)
    eng.schedule(lo + 85 * 60, lambda: (share_wiper if wiper else ransom_encrypt)(
        ctx, atk, ctx.h[H('FILE1')], *( () if wiper else (ext,) ), ts=lo + 85 * 60,
        **({} if wiper else {"note_text": note_text, "note_dirs": ("", "Archive"), "note_name": CHAIN_NOTE_NAMES.get(ext)})), tag)
    # also hit a second share/server for spread, the same as every ransomware chain
    if wiper:
        eng.schedule(lo + 92 * 60, lambda: share_wiper(ctx, atk, ctx.h[H('BACKUP1')], ts=lo + 92 * 60, share="Users"), tag)
    else:
        eng.schedule(lo + 92 * 60, lambda: ransom_encrypt(
            ctx, atk, ctx.h[H('BACKUP1')], ext, ts=lo + 92 * 60, share="Users", note_text=note_text, note_dirs=("", "Archive"),
            note_name=CHAIN_NOTE_NAMES.get(ext)), tag)


def ndr_akira(ctx, eng, tag, win):
    _actor_chain(ctx, eng, tag, win, c2_rmm_cloud, ext=".akira")


def ndr_medusa(ctx, eng, tag, win):
    _actor_chain(ctx, eng, tag, win, c2_tunnel, ext=".medusa")


def ndr_black_basta(ctx, eng, tag, win):
    # its own team server (cobaltc2_bb), not Play's shared cobaltc2 identity
    _actor_chain(ctx, eng, tag, win, lambda c, e, t, w: c2_cobalt(c, e, t, w, key="cobaltc2_bb"), ext=".basta")


def ndr_play(ctx, eng, tag, win):
    # its own team server (cobaltc2_play), distinct from Black Basta's and the shared cobaltc2
    _actor_chain(ctx, eng, tag, win, lambda c, e, t, w: c2_cobalt(c, e, t, w, key="cobaltc2_play"), ext=".play")


def ndr_handala(ctx, eng, tag, win):
    """Network-observable subset of Handala / Void Manticore: recon + lateral (to reach the
    file server) + large data theft + Telegram/HTTPS C2, then a shared-drive WIPER (overwrite,
    no rename). Phishing delivery and single-host local wiping are endpoint-only and omitted."""
    _actor_chain(ctx, eng, tag, win, handala_c2, wiper=True)


# ---- atomic impact modules (usable on their own) ----------------------------
def ndr_ransomware_encryption(ctx, eng, tag, win):
    atk = attacker(ctx)
    eng.schedule(win[0] + 60, lambda: ransom_encrypt(ctx, atk, ctx.h[H('FILE1')], ".akira", ts=win[0] + 60,
                                                         note_text=AKIRA_NOTE_TEXT.format(code=AKIRA_CHAT_CODE)), tag)
    eng.schedule(win[0] + 8 * 60, lambda: ransom_encrypt(ctx, atk, ctx.h[H('BACKUP1')], ".akira", ts=win[0] + 8 * 60, share="Users",
                                                         note_text=AKIRA_NOTE_TEXT.format(code=AKIRA_CHAT_CODE)), tag)


def ndr_cobalt_strike(ctx, eng, tag, win):
    c2_cobalt(ctx, eng, tag, win)


# ================================================================= NPM builders
# ===================================================== SQL1 service-failure (NPM)
# Inlined 2026-10-04 from the former netgen/incident.py (which was imported only here).
# A dedicated RNG, reseeded at the top of npm_sql1(), reproduces that module's output exactly.
_sql1_rng = random.Random(31337)


# ---------------------------------------------------------------- backend TDS
def _sql1_pool_conn(ctx, t0, web=None):
    """A fresh WEB1(or WEB2)->SQL1 pooled connection, healthy handshake. Returns open session."""
    web, sql = web or ctx.h[H('WEB1')], ctx.h[H('SQL1')]
    s = ctx.tcp(web, sql, 1433, t0).handshake()
    s.c2s(P.tds_prelogin(True), think=0.0004)
    s.s2c(P.tds_prelogin(False), think=_sql1_rng.uniform(0.0005, 0.002))
    s.c2s(P.tds_login7("svc_intranet"), think=0.0006)
    s.s2c(P.tds_login_ack(), think=_sql1_rng.uniform(0.001, 0.004))
    return s


def _sql1_backend_degrade(ctx, ts, web=None):
    """One slow/errored backend query cycle during the DEGRADE phase."""
    web, sql = web or ctx.h[H('WEB1')], ctx.h[H('SQL1')]
    out = ctx.arp_for(web, sql, ts)
    s = _sql1_pool_conn(ctx, ts + 0.001, web)
    q = _sql1_rng.choice(P.SQL_QUERIES).replace("{n}", str(_sql1_rng.randint(100000, 999999))).replace("{user}", "svc_intranet")
    s.c2s(P.tds_sql_batch(q), think=0.001)
    r = _sql1_rng.random()
    if r < 0.45:
        # very slow success: server ACKs the request late, then a slow result
        s.idle(_sql1_rng.uniform(3.0, 12.0))
        s._emit(sql, web, s.dport, s.sport, s.sseq, s.cseq, ACK, s.swin)   # late ACK
        cols = [("ShipmentId", "int"), ("Status", "nvarchar")]
        data = [(_sql1_rng.randint(100000, 999999), _sql1_rng.choice(["IN_TRANSIT", "AT_HUB"])) for _ in range(_sql1_rng.randint(1, 20))]
        s.s2c(P.tds_split(0x04, P.tds_result(cols, data), s.dport), think=_sql1_rng.uniform(2.0, 8.0))
        pk = s.close(by_client=True, think=_sql1_rng.uniform(0.05, 0.4))
    elif r < 0.80:
        # lock request time-out (error 1222) after a long wait
        s.idle(_sql1_rng.uniform(8.0, 20.0))
        s.s2c(P.tds_split(0x04, P.tds_error(1222, "Lock request time out period exceeded.", severity=16, spid=s.dport % 200), s.dport), think=0.02)
        pk = s.close(by_client=True, think=_sql1_rng.uniform(0.05, 0.3))
    else:
        # client-side command timeout: WEB1 sends an Attention (0x06) then tears the socket down.
        # c2s() advances cseq by the packet's own length -- the raw _emit() this replaced left
        # cseq unmoved, so the following ACK/FIN,ACK reused the Attention's own sequence number
        # (NPM-01 brief fix 2).
        s.idle(_sql1_rng.uniform(25.0, 31.0))
        s.c2s(P.tds_packet(0x06, b""), think=0.0)
        s.s2c(P.tds_packet(0x04, b"\xfd" + struct.pack("<HHQ", 0x0020, 0, 0)), think=_sql1_rng.uniform(0.2, 2.0))  # DONE, Acknowledge ATTN
        pk = s.close(by_client=True, think=0.1)
    return F.merged(out, pk)


def _sql1_backend_outage(ctx, ts, web=None):
    """OUTAGE: WEB1(or WEB2) tries to open new connections; all are refused outright -- a
    stopped listener never accepts a SYN, so the earlier handshake-then-RST variant (which
    implied the listener was still up) is gone (NPM-01 brief fix 1)."""
    web, sql = web or ctx.h[H('WEB1')], ctx.h[H('SQL1')]
    out = ctx.arp_for(web, sql, ts)
    s = ctx.tcp(web, sql, 1433, ts + 0.001)
    pk = s.refused(attempts=_sql1_rng.randint(2, 3))
    return F.merged(out, pk)


def _sql1_backend_recover(ctx, ts, web=None):
    """RECOVERY: connections succeed again, first queries a bit slow."""
    web, sql = web or ctx.h[H('WEB1')], ctx.h[H('SQL1')]
    out = ctx.arp_for(web, sql, ts)
    s = _sql1_pool_conn(ctx, ts + 0.001, web)
    q = _sql1_rng.choice(P.SQL_QUERIES).replace("{n}", str(_sql1_rng.randint(100000, 999999))).replace("{user}", "svc_intranet")
    s.c2s(P.tds_sql_batch(q), think=0.001)
    cols = [("ShipmentId", "int"), ("TrackingNo", "nvarchar"), ("Status", "nvarchar")]
    data = [(_sql1_rng.randint(100000, 999999), f"{get_current().prefix}{_sql1_rng.randint(100000, 999999)}", _sql1_rng.choice(["IN_TRANSIT", "AT_HUB", "DELIVERED"])) for _ in range(_sql1_rng.randint(1, 40))]
    s.s2c(P.tds_split(0x04, P.tds_result(cols, data), s.dport), think=_sql1_rng.uniform(0.3, 1.5))
    pk = s.close(by_client=True, think=_sql1_rng.uniform(0.05, 0.5))
    return F.merged(out, pk)


# ------------------------------------------------------------------ user HTTP
_SQL1_ASP_ERROR = (b"<!DOCTYPE html><html><head><title>Server Error</title></head><body>"
             b"<h1>Server Error in '/' Application.</h1>"
             b"<h2>A network-related or instance-specific error occurred while establishing a connection to SQL Server.</h2>"
             b"<p>The server was not found or was not accessible. (provider: TCP Provider, error: 0 - "
             b"No connection could be made because the target machine actively refused it.)</p>"
             b"<pre>System.Data.SqlClient.SqlException (0x80131904): A network-related or instance-specific error "
             b"occurred while establishing a connection to SQL Server.\n"
             b"   at System.Data.SqlClient.SqlInternalConnectionTds..ctor(...)\n"
             b"   at Example.Web.Data.ShipmentRepository.GetOpenShipments()\n</pre></body></html>")

_SQL1_ASP_TIMEOUT = (b"<!DOCTYPE html><html><head><title>Server Error</title></head><body>"
               b"<h1>Server Error in '/' Application.</h1>"
               b"<h2>Timeout expired.</h2>"
               b"<p>The timeout period elapsed prior to completion of the operation or the server is not responding.</p>"
               b"<pre>System.Data.SqlClient.SqlException (0x80131904): Timeout expired.  The timeout period elapsed "
               b"prior to completion of the operation or the server is not responding.\n"
               b"   at System.Data.SqlClient.SqlCommand.ExecuteReader(...)\n</pre></body></html>")


def _sql1_user_http_fault(ctx, client, ts, phase):
    """A user browsing the intranet during the incident: slow pages / 500s / retries."""
    web = ctx.h[H("WEB1")]
    user = P.username_for(client.name)
    ua = P.UAS[0] if ctx.is_windows(client) else P.UAS[2]
    tgs, t = F.kerberos_tgs(ctx, client, "HTTP", web, ts + 0.005)
    out = ctx.arp_for(client, web, t)
    host = f"intranet.{get_current().domain}"
    s = ctx.tcp(client, web, 80, t + 0.001).handshake()
    token = base64.b64encode(P.krb_ap_req_token(user, "HTTP", web.fqdn)).decode()
    s.c2s(P.http_request("GET", "/", host, ua), think=_sql1_rng.uniform(0.001, 0.01))
    s.s2c(P.http_response("401 Unauthorized", b"", "text/html", s.t, headers=["WWW-Authenticate: Negotiate"]), think=_sql1_rng.uniform(0.001, 0.004))
    # number of page views + retries depends on phase
    if phase == "degrade":
        views = _sql1_rng.randint(1, 3)
    elif phase == "outage":
        views = _sql1_rng.randint(2, 6)   # users hit reload repeatedly
    else:
        views = _sql1_rng.randint(1, 2)
    first = True
    for _i in range(views):
        path = _sql1_rng.choice(["/shipments", "/reports", "/api/shipments?page=1&size=50", "/carriers", "/shipments?page=%d" % _sql1_rng.randint(2, 6)])
        think = _sql1_rng.uniform(0.001, 0.004) if first else _sql1_rng.uniform(1.5, 8.0)   # short = impatient reloads
        hdrs = ["Authorization: Negotiate " + token] if first else ["Cookie: ASP.NET_SessionId=" + os.urandom(12).hex()]
        if path.startswith("/api/"):
            hdrs.append("Accept: application/json")
        s.c2s(P.http_request("GET", path, host, ua, hdrs), think=think)
        if phase == "degrade":
            if _sql1_rng.random() < 0.5:
                body = P.intranet_page("Shipments", _sql1_rng.randint(15, 40), s.t)
                s.s2c(P.http_response("200 OK", body, "text/html; charset=utf-8", s.t, headers=["X-Powered-By: ASP.NET"], gzip=True), think=_sql1_rng.uniform(4.0, 18.0))
            else:
                s.s2c(P.http_response("500 Internal Server Error", _SQL1_ASP_TIMEOUT, "text/html; charset=utf-8", s.t, headers=["X-Powered-By: ASP.NET"]), think=_sql1_rng.uniform(20.0, 32.0))
        elif phase == "outage":
            s.s2c(P.http_response("500 Internal Server Error", _SQL1_ASP_ERROR, "text/html; charset=utf-8", s.t, headers=["X-Powered-By: ASP.NET"]), think=_sql1_rng.uniform(0.05, 0.6))
        else:
            body = P.intranet_page("Shipments", _sql1_rng.randint(15, 40), s.t)
            s.s2c(P.http_response("200 OK", body, "text/html; charset=utf-8", s.t, headers=["X-Powered-By: ASP.NET"], gzip=True), think=_sql1_rng.uniform(0.3, 2.0))
        first = False
    pk = s.close(by_client=_sql1_rng.random() < 0.5, think=_sql1_rng.uniform(1, 10))
    return F.merged(tgs, out, pk)


# ------------------------------------------------------------- admin response
def _sql1_admin_diagnose(ctx, ts):
    """MGMT1 admin: ping SQL1 (box is up), a refused telnet-style TCP probe to 1433, then RDP in."""
    mgmt, sql = ctx.h[H("MGMT1")], ctx.h[H("SQL1")]
    out = F.icmp_ping(ctx, mgmt, sql, ts, count=4)                     # ICMP succeeds: host is up
    probe = ctx.tcp(mgmt, sql, 1433, ts + 5.0)
    out += probe.refused(attempts=1)                                   # admin confirms 1433 refused
    out += F.rdp_session(ctx, mgmt, sql, ts + 8.0, duration=_sql1_rng.uniform(180, 360))   # remote in to fix it
    return F.merged(out)


def _sql1_health_probe(ctx, ts, phase):
    """WEB1 application health monitor pinging SQL1's port every ~15 s. TDS requires prelogin
    and login before a batch (NPM-01 brief fix 4) -- the probe is a full connection, not a bare
    SQL batch on a fresh handshake."""
    web, sql = ctx.h[H('WEB1')], ctx.h[H('SQL1')]
    out = ctx.arp_for(web, sql, ts)
    if phase == "outage":
        s = ctx.tcp(web, sql, 1433, ts + 0.001)
        out += s.refused(attempts=1)
    else:
        s = _sql1_pool_conn(ctx, ts + 0.001, web)
        s.c2s(P.tds_sql_batch("SELECT 1"), think=0.001)
        if phase == "degrade":
            s.s2c(P.tds_split(0x04, P.tds_result([("c", "int")], [(1,)]), s.dport), think=_sql1_rng.uniform(1.0, 6.0))
        else:
            s.s2c(P.tds_split(0x04, P.tds_result([("c", "int")], [(1,)]), s.dport), think=_sql1_rng.uniform(0.002, 0.05))
        out += s.close(think=0.05)
    return F.merged(out)


# ------------------------------------------------------------------- syslog
def _sql1_syslog_event(ctx, sender, ts, text, pri=27):
    log = ctx.h[H("LOG1")]
    out = ctx.arp_for(sender, log, ts)
    out.append(ctx.udp(sender, log, sender.eph() if sender.ttl == 128 else 514, 514, P.syslog(pri, ts, sender.name.lower(), text), ts))
    return F.merged(out)


_SQL1_WEB_MSGS_DEGRADE = [
    "W3SVC-WP[intranet]: WARN Example.Web.Data.ShipmentRepository - SqlException 1222 Lock request time out period exceeded",
    # NPM-01 brief fix 6: the modelled pool is 4 persistent connections plus one new connection
    # per slow query -- not the "100/100, 32 queued" exhaustion the old text claimed.
    "W3SVC-WP[intranet]: WARN ADO.NET connection pool for exl-sql1.corp.example.local: 4 pooled connections healthy, new-connection latency elevated",
    "W3SVC-WP[intranet]: ERROR ExecuteReader timeout expired after 30000 ms querying dbo.Shipments",
]
_SQL1_WEB_MSGS_OUTAGE = [
    "W3SVC-WP[intranet]: ERROR System.Data.SqlClient.SqlException 0x80131904 - target machine actively refused {sql1}:1433",
    # fix 6: no /health HTTP endpoint is ever requested on the wire, so drop that claim.
    "W3SVC-WP[intranet]: ERROR HealthCheck DB=UNHEALTHY exl-sql1:1433 connection refused",
    "W3SVC-WP[intranet]: ERROR Unhandled SqlException in GetOpenShipments; returning 500 to client",
]
_SQL1_SQL_MSGS = [
    # fix 6: completed the sentence a real SQL Server 17053 message finishes with.
    "MSSQLSERVER: Error: 17053, Severity: 16, State: 1. The operating system returned error 21 to SQL Server during a read at offset 0x00000003a2c000 in file 'E:\\SQLData\\Logistics.mdf'.",
    "MSSQLSERVER: SQL Server has encountered 128 occurrences of I/O requests taking longer than 15 seconds to complete on file [Logistics.mdf]",
]


def npm_sql1(ctx, eng, tag, win):
    """NPM: EXL-SQL1 (Microsoft SQL Server) service failure -- degrade 10:05, outage 10:25,
    recover 10:52. Only the SQL service fails; the host stays up (ICMP/RDP keep working) so the
    admin can log in to restart it. Inlined from the former netgen/incident.py; the dedicated
    _sql1_rng reseeded here reproduces that module's stream byte-for-byte."""
    _sql1_rng.seed(31337)
    from .model import local as L0
    D = win[0] - L0(10, 0)                       # a shift moves its whole timeline; 0 in the default day

    def L(h, m=0, s=0):
        return L0(h, m, s) + D
    win = (L(10, 0), L(11, 5))

    def sched(ts, fn, *a, **kw):
        if win[0] - 60 <= ts <= win[1] + 120:
            eng.schedule(ts, lambda: fn(ctx, *a, **kw), tag)

    users = [ctx.h[n] for n in ctx.h if n.startswith((H('WS'), H('MAC')))]

    # ---- DEGRADE 10:05-10:25 : backend slow, some users see it
    t = L(10, 5)
    while t < L(10, 25):
        sched(t, _sql1_backend_degrade, t)
        t += _sql1_rng.expovariate(1 / 6.0)
    t = L(10, 8)
    while t < L(10, 26):
        sched(t, _sql1_user_http_fault, _sql1_rng.choice(users), t, "degrade")
        t += _sql1_rng.expovariate(1 / 25.0)

    # ---- OUTAGE 10:25-10:52 : refused connects, resets, 500s, retries
    t = L(10, 25)
    while t < L(10, 52):
        sched(t, _sql1_backend_outage, t)
        t += _sql1_rng.expovariate(1 / 3.5)
    t = L(10, 25, 30)
    while t < L(10, 53):
        sched(t, _sql1_user_http_fault, _sql1_rng.choice(users), t, "outage")
        t += _sql1_rng.expovariate(1 / 12.0)

    # ---- WEB1 health monitor throughout (phase "degrade" only from 10:05, not the window start;
    # anything before that is a healthy probe, same fast-reply branch as "recover" -- fix 4)
    t = win[0]
    while t < win[1]:
        phase = ("healthy" if t < L(10, 5) else "degrade") if t < L(10, 25) else \
                ("outage" if t < L(10, 52) else "recover")
        sched(t, _sql1_health_probe, t, phase)
        t += 15 + _sql1_rng.uniform(-1, 1)

    # ---- WEB2: a second SQL1 client, equally affected (real failure: every client sees it --
    # NPM-01 brief fix 3). Kept inside this window only; NPM-06's own window is untouched.
    web2 = ctx.h.get(H('WEB2'))
    if web2 is not None:
        t = L(10, 5)
        while t < L(10, 25):
            sched(t, _sql1_backend_degrade, t, web2)
            t += _sql1_rng.expovariate(1 / 6.0)
        t = L(10, 25)
        while t < L(10, 52):
            sched(t, _sql1_backend_outage, t, web2)
            t += _sql1_rng.expovariate(1 / 3.5)
        t = L(10, 52)
        while t < L(11, 5):
            sched(t, _sql1_backend_recover, t, web2)
            t += _sql1_rng.expovariate(1 / 4.0)

    # ---- RECOVERY 10:52-11:05
    t = L(10, 52)
    while t < L(11, 5):
        sched(t, _sql1_backend_recover, t)
        t += _sql1_rng.expovariate(1 / 4.0)
    t = L(10, 53)
    while t < L(11, 6):
        sched(t, _sql1_user_http_fault, _sql1_rng.choice(users), t, "recover")
        t += _sql1_rng.expovariate(1 / 20.0)

    # ---- admin response: notices ~10:30, diagnoses, RDPs, restarts service ~10:50, then a
    # second short RDP session for the actual restart (NPM-01 brief fix 7 -- the page says the
    # service comes back at 10:50 but the admin's one session ends at 10:36, so nobody is
    # visibly there to restart it)
    sched(L(10, 31), _sql1_admin_diagnose, L(10, 31))
    sched(L(10, 48), F.rdp_session, ctx.h[H('MGMT1')], ctx.h[H('SQL1')], L(10, 48), rng.uniform(90, 150))

    # ---- syslog narrative
    def burst(t0, t1, sender_name, msgs, rate, pri):
        t = t0
        while t < t1:
            sched(t, _sql1_syslog_event, ctx.h[sender_name], t, _sql1_rng.choice(msgs), pri)
            t += _sql1_rng.expovariate(rate)
    burst(L(10, 4), L(10, 25), H('WEB1'), _SQL1_WEB_MSGS_DEGRADE, 1 / 8.0, 27)
    # {sql1} is filled in here so the log body matches the configured server subnet
    burst(L(10, 25), L(10, 52), H('WEB1'),
          [m.format(sql1=ctx.h[H('SQL1')].ip) for m in _SQL1_WEB_MSGS_OUTAGE], 1 / 4.0, 27)
    burst(L(10, 2), L(10, 26), H('SQL1'), _SQL1_SQL_MSGS, 1 / 20.0, 27)
    sched(L(10, 25), _sql1_syslog_event, ctx.h[H('SQL1')], L(10, 25), "MSSQLSERVER: SQL Server service terminated unexpectedly (exit code 255)", 27)
    sched(L(10, 50), _sql1_syslog_event, ctx.h[H('SQL1')], L(10, 50), "Service Control Manager: The SQL Server (MSSQLSERVER) service entered the running state.", 30)
    sched(L(10, 52), _sql1_syslog_event, ctx.h[H('WEB1')], L(10, 52), ("W3SVC-WP[intranet]: INFO HealthCheck DB=HEALTHY " + get_current().prefix.lower() + "sql1:1433 recovered; connection pool re-established"), 30)


def npm_dns_degradation(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    dc1, dc2 = ctx.h[H("DC1")], ctx.h[H("DC2")]
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    pre, post = flanks(lo, hi)
    for t in pre + post:                     # healthy DNS before and after the fault
        s(t, dns_slow_or_fail, rng.choice(users), dc1, dc2, g=0.0)
    t = lo
    while t < hi:
        s(t, dns_slow_or_fail, rng.choice(users), dc1, dc2, g=sev(t, win))
        t += rng.expovariate(1 / 2.0)


def dns_slow_or_fail(ctx, client, dc1, dc2, ts, g=1.0):
    out = ctx.arp_for(client, dc1, ts)
    sport = client.eph()
    txid = ctx.next_txid()
    name = rng.choice([("intranet." + get_current().domain), get_current().fqdn('FILE1'), "www.example.com", "api.example.net"])
    # Public names answered by an internal DC should read as a recursive lookup, not an
    # authoritative one, and keep the TTL a real resolver would carry (NPM-02 brief fix 2).
    aa, ttl = (True, 1200) if name.endswith("example.local") else (False, 300)
    ans = DNS_A_ans(name, ctx)
    q = P.dns_query(txid, name)
    out.append(ctx.udp(client, dc1, sport, 53, q, ts))
    r = rng.random()
    if g < 0.15:
        # healthy: crisp answer in a few ms
        out.append(ctx.udp(dc1, client, 53, sport, P.dns_response(txid, name, P.DNS_A, ans, aa=aa, ttl=ttl), ts + rng.uniform(0.002, 0.012), vantage=client))
    elif r < 0.4 * g + 0.05:
        # Timeout on DC1: a Windows client retransmits at a fixed 1.0 s, then asks the
        # secondary at a fixed 3.0 s if the primary still hasn't answered -- not a uniform
        # spread (NPM-02 brief fix 4; "Done when": retransmit histogram spiked at 1.0 s).
        out.append(ctx.udp(client, dc1, sport, 53, q, ts + 1.0))                           # retransmit
        out += ctx.arp_for(client, dc2, ts + 2.8)
        out.append(ctx.udp(client, dc2, sport, 53, q, ts + 3.0))
        out.append(ctx.udp(dc2, client, 53, sport, P.dns_response(txid, name, P.DNS_A, ans, aa=aa, ttl=ttl), ts + 3.0 + rng.uniform(0.2, 1.5), vantage=client))
    elif r < 0.7:
        # SERVFAIL from DC1. A real stub resolver that gets a hard failure from the
        # preferred server asks the alternate for the same name rather than giving up
        # outright -- the page's T4 ("make the client retry elsewhere") needs this to be
        # true some of the time, not almost never (NPM-02 brief fix 3).
        sf_t = ts + rng.uniform(0.8, 0.8 + 2.0 * g)
        if sf_t > ts + 1.0:
            # a reply later than 1 s is preceded by the client's fixed 1.0 s resend (same txid/port)
            out.append(ctx.udp(client, dc1, sport, 53, q, ts + 1.0))
        out.append(ctx.udp(dc1, client, 53, sport, P.dns_response(txid, name, P.DNS_A, [], rcode=2, aa=False), sf_t, vantage=client))
        if rng.random() < 0.5:
            q2 = min(sf_t + 0.4, ts + 3.0)      # failover rides the fixed 3.0 s timer at the latest
            out += ctx.arp_for(client, dc2, q2 - 0.1)
            out.append(ctx.udp(client, dc2, sport, 53, q, q2))
            out.append(ctx.udp(dc2, client, 53, sport, P.dns_response(txid, name, P.DNS_A, ans, aa=aa, ttl=ttl), q2 + rng.uniform(0.002, 0.012), vantage=client))
    else:
        # Slow success, worsening with severity -- but a client waiting past 1 s without
        # anything back still retransmits (same txid/port) even though the one answer that
        # eventually arrives satisfies both (NPM-02 brief fix 3).
        delay = rng.uniform(0.3, 0.3 + 3.7 * g)
        if delay > 1.0:
            out.append(ctx.udp(client, dc1, sport, 53, q, ts + 1.0))
        out.append(ctx.udp(dc1, client, 53, sport, P.dns_response(txid, name, P.DNS_A, ans, aa=aa, ttl=ttl), ts + delay, vantage=client))
    return F.merged(out)


def DNS_A_ans(name, ctx):
    if name.endswith("example.local"):
        h = {("intranet." + get_current().domain): ctx.h[H('WEB1')], get_current().fqdn('FILE1'): ctx.h[H('FILE1')]}.get(name)
        if h:
            return [(P.DNS_A, h.ipb)]
    # A public name gets its one real, stable address (model.py's INTERNET table) every time,
    # not a fresh random one per lookup (NPM-02 brief fix 2).
    site = ctx.sites.get(name)
    if site:
        return [(P.DNS_A, site[1].ipb)]
    return [(P.DNS_A, bytes([198, 51, 100, rng.randint(10, 200)]))]


def npm_smb_slowdown(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    file1 = ctx.h[H("FILE1")]
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    pre, post = flanks(lo, hi)
    for t in pre + post:                     # healthy fast reads flanking the fault
        s(t, smb_slow_read, rng.choice(users), file1, g=0.0)
    t = lo
    while t < hi:
        s(t, smb_slow_read, rng.choice(users), file1, g=sev(t, win))
        t += rng.expovariate(max(0.05, min(1.0, ctx.scale)) / 3.0)


def smb_slow_read(ctx, client, server, ts, g=1.0):
    """A slow file server. Reads: the server holds each response for a service time that rises
    continuously with severity (log-normal, no zero window, because a reader that cannot absorb
    data would be the client). Writes: the server is the receiver of the bulk data, so it
    advertises Win=0, the client probes with the next real byte of its own pending data, and
    after the window update sends that data from the same sequence (NPM-03 brief fixes 1-4)."""
    s, smb, pre = F._smb_open(ctx, client, server, "Dept", ts)
    size = int(rng.randint(120_000, 900_000) * max(0.1, min(1.0, ctx.scale)))
    name = rng.choice(F.FILE_NAMES).replace("{n}", str(rng.randint(10000, 99999)))
    meta = rng.uniform(0.002, 0.01) + 0.5 * g * rng.uniform(0.4, 1.0)
    chunk = 65536
    writing = g > 0 and rng.random() < 0.5
    s.c2s(smb.create_req(name, write=writing), think=rng.uniform(0.005, 0.03) + 0.1 * g)
    r, fid = smb.create_resp(s.t, size)
    s.s2c(r, think=meta)
    off = 0
    while off < size:
        n = min(chunk, size - off)
        if writing:
            req = smb.write_req(fid, off, P.blob(n))
            if rng.random() < SMB_ZEROWIN_P * g:
                s.zero_window(req, reopen=rng.uniform(0.2, 0.2 + SMB_ZEROWIN_EXTRA * g), first_wait=0.5)
            s.c2s(req, think=rng.uniform(0.002, 0.02))
            s.s2c(smb.write_resp(n), think=rng.uniform(0.002, 0.01) + g * rng.lognormvariate(-3.0, 0.8))
        else:
            s.c2s(smb.read_req(fid, off, n), think=rng.uniform(0.002, 0.02))
            # service time rises for every read with severity, long-tailed (median ~0.15 s * g)
            svc = rng.uniform(0.002, 0.01) + g * rng.lognormvariate(-1.9, 0.9)
            s.s2c(smb.read_resp(P.blob(n)), think=svc)
        off += n
    s.c2s(smb.close_req(fid), think=0.01)
    s.s2c(smb.close_resp(s.t, size), think=0.01)
    return F.merged(pre, F._smb_close(s, smb))


def _wan_cdn(ctx):
    """A benign CDN egress target for the WAN-congestion module (NOT attacker infra)."""
    for name in ("cdn.jsdelivr.net", "objects.githubusercontent.com", "www.cloudflare.com"):
        if name in ctx.sites:
            return name, ctx.sites[name][1]
    n, srv = next(iter(ctx.sites.items()))
    return n, srv[1]


def npm_wan_congestion(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    pre, post = flanks(lo, hi)
    for t in pre + post:                     # healthy fast egress flanking the fault
        s(t, wan_slow_session, rng.choice(users), g=0.0)
    t = lo
    while t < hi:
        s(t, wan_slow_session, rng.choice(users), g=sev(t, win))
        t += rng.expovariate(1 / 4.0)


def wan_slow_session(ctx, client, ts, g=1.0):
    """Egress HTTPS to a legitimate CDN with high RTT and retransmissions when the WAN is
    congested; healthy and fast when severity is low. (Uses a real CDN, not attacker infra.)"""
    from .tls import TlsSession
    host, srv = _wan_cdn(ctx)
    rtt = rng.uniform(0.01, 0.03) + g * rng.uniform(*WAN_RTT_ADD)    # RTT climbs with congestion
    rate = WAN_RATE_BAD if g > 0.15 else WAN_RATE_OK
    out = ctx.arp_for(client, srv, ts)
    s = ctx.tcp(client, srv, 443, ts + 0.001, rtt=rtt, rate=rate).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile=getattr(client, "tls_profile", "chrome"))
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.01, 0.03) + 0.18 * g)
    for _ in range(rng.randint(2, 5)):
        req = P.http_request("GET", "/asset/%s.bin" % os.urandom(3).hex(), host, P.UAS[0])
        treq = tls.app_data(True, req)
        s.c2s(treq, think=rng.uniform(0.02, 0.1) + 0.4 * g)
        if rng.random() < 0.08 * g:
            # the request isn't promptly ACKed/answered -- the client's own RTO fires and it
            # retransmits (RFC 6298: max(200ms, SRTT + 4*RTTVAR), doubling on a second loss),
            # before any response has arrived (NPM-04 brief fix 1).
            rto = max(0.2, 4 * rtt)
            s.retransmit_last_client_segment(treq, delays=(rto, rto * 2))
        body = P.blob(int(rng.randint(20000, 120000) * max(0.1, min(1.0, ctx.scale))))
        resp = tls.app_data(False, P.http_response("200 OK", body, "application/octet-stream", s.t))
        if rng.random() < 0.6 * g:
            # loss on the download itself: real duplicate ACKs and a sender fast retransmit,
            # about one RTT after the last duplicate (see TcpSession.fast_retransmit) -- not a
            # spurious resend of a request the server already answered.
            s.fast_retransmit(resp, dup_acks=rng.randint(3, 4), lost_index=rng.randint(0, 2),
                              think=rng.uniform(0.05, 0.2) + 0.4 * g)
        else:
            s.s2c(resp, think=rng.uniform(0.05, 0.2) + 0.4 * g)
    return F.merged(out, s.close(think=0.1))


def npm_auth_latency(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    pre, post = flanks(lo, hi)
    for t in pre + post:                     # healthy fast logons flanking the fault
        s(t, slow_kerberos, rng.choice(users), g=0.0)
    t = lo
    while t < hi:
        s(t, slow_kerberos, rng.choice(users), g=sev(t, win))
        t += rng.expovariate(1 / 2.5)


def slow_kerberos(ctx, client, ts, g=1.0):
    """A user logon against a saturated KDC: AS-REQ without pre-authentication, KDC_ERR_PREAUTH_REQUIRED
    (25), then the pre-authenticated AS-REQ whose AS-REP is slow, then a TGS exchange for a file-server
    ticket that is slow in the same way (NPM-05 brief fixes 1-3). A computer account renewing its TGT
    stays a rare event (about 1 in 12). Only this scenario's own exchanges are slowed; the
    ordinary day's Kerberos is untouched."""
    dc = ctx.h[H('DC1')]
    machine = rng.random() < 0.08
    who = client.name + "$" if machine else P.username_for(client.name)
    out = ctx.arp_for(client, dc, ts)

    def slow():
        if g < 0.15:
            return rng.uniform(0.005, 0.03)
        # long-tailed: the envelope sets the scale, not a uniform band
        return min(9.5, rng.lognormvariate(math.log(0.3 + 2.4 * g), 0.55))

    s = ctx.tcp(client, dc, 88, ts + 0.001).handshake()
    s.c2s(_krb_tcp(P.krb_as_req(who, ts, rng.getrandbits(31), False)), think=0.001)
    s.s2c(_krb_tcp(P.krb_error_preauth(who, ts)), think=rng.uniform(0.0008, 0.003) if g < 0.15 else slow() * 0.1)
    pk = s.close(think=0.0006)
    s2 = ctx.tcp(client, dc, 88, s.t + rng.uniform(0.002, 0.008)).handshake()
    s2.c2s(_krb_tcp(P.krb_as_req(who, ts, rng.getrandbits(31), True)), think=0.0004)
    s2.s2c(_krb_tcp(P.krb_as_rep(who)), think=slow())
    pk2 = s2.close(think=0.01)
    out += pk + pk2
    if not machine:
        file1 = ctx.h[H('FILE1')]
        s3 = ctx.tcp(client, dc, 88, s2.t + rng.uniform(0.01, 0.05)).handshake()
        s3.c2s(_krb_tcp(P.krb_tgs_req(who, "cifs", file1.fqdn, s3.t, rng.getrandbits(31))), think=0.0004)
        s3.s2c(_krb_tcp(P.krb_tgs_rep(who, "cifs", file1.fqdn)), think=slow() if g >= 0.15 else rng.uniform(0.0015, 0.005))
        out += s3.close(think=0.0006)
    return F.merged(out)


# ---- web-server degradation (WEB2 cascade from a slow SQL1 backend) ----------
def npm_web_degradation(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H('WS'), H('MAC')))]
    lo, hi = win
    # a dedicated slow WEB2->SQL1 pool for the incident window (open before pre-roll, close after post-roll)
    eng.schedule(lo - 120, lambda: _web2_pool_open(ctx, lo - 120), tag)
    warm = random.Random(6)                  # own generator: the shared stream is not touched
    for dt in sorted(warm.uniform(1.0, 110.0) for _ in range(WEB2_POOL_SIZE - 4)):
        eng.schedule(lo - 120 + dt, lambda dt=dt: _web2_pool_extra_open(ctx, lo - 120 + dt), tag)
    pre, post = flanks(lo, hi)
    for t in pre + post:                     # healthy fast pages flanking the cascade
        s(t, web2_slow_page, rng.choice(users), g=0.0)
    t = lo + 20
    while t < hi:
        s(t, web2_slow_page, rng.choice(users), g=sev(t, win))
        t += rng.expovariate(1 / 6.0)
    eng.schedule(hi + 200, lambda: _web2_pool_close(ctx, hi + 200), tag)
    for dt in sorted(warm.uniform(30.0, 330.0) for _ in range(WEB2_POOL_SIZE - 4)):
        eng.schedule(hi + 200 + dt, lambda dt=dt: _web2_pool_extra_close(ctx, hi + 200 + dt), tag)


def _isolated_rng():
    """Every random generator in the process; the larger pool's extra connections draw from them
    and the state is put back afterwards so the rest of the capture is byte-for-byte unchanged."""
    gens = {id(v): v for m in list(sys.modules.values()) for v in list(getattr(m, "__dict__", {}).values())
            if isinstance(v, random.Random) and not isinstance(v, random.SystemRandom)}   # SystemRandom (secrets) has no state
    gens = list(gens.values()) + [random]
    return gens, [g.getstate() for g in gens]


def _web2_pool_open(ctx, ts):
    """The IIS app pool's first 4 connections. ADO.NET grows the pool as concurrent queries need it
    (up to 100), so a slow DB queues no query behind a busy connection; the rest open one by one
    (`_web2_pool_extra_open`) over the next two minutes."""
    return F.sql_pool_open(ctx, ts, web=H('WEB2'), svc="svc_shipping", pool=_web2_pool(ctx))


def _web2_pool_extra_open(ctx, ts):
    gens, saved = _isolated_rng()
    out = F.sql_pool_open(ctx, ts, n=1, web=H('WEB2'), svc="svc_shipping", pool=_web2_pool(ctx))
    for g, st in zip(gens, saved, strict=False):
        g.setstate(st)
    return out


def _web2_pool_close(ctx, ts):
    """The original connections close with the app pool; the extras were already pruned as they idled."""
    pool = _web2_pool(ctx)
    out = F.sql_pool_close(ctx, ts, pool=pool[:4])
    del pool[:4]
    return out


def _web2_pool_extra_close(ctx, ts):
    """ADO.NET prunes idle pooled connections a few at a time, not all at once."""
    pool = _web2_pool(ctx)
    if len(pool) <= 4:
        return []
    gens, saved = _isolated_rng()
    out = F.sql_pool_close(ctx, ts, pool=[pool.pop()])
    for g, st in zip(gens, saved, strict=False):
        g.setstate(st)
    return out


def _web2_pool(ctx):
    return ctx.__dict__.setdefault("_npm_web2_pool", [])


WEB2_POOL_SIZE = 64                  # the IIS app pool's TDS connections to SQL1 (ADO.NET allows 100)


WEB2_DB_HEALTHY = (0.03, 0.12)       # SQL1 reply time before and after the fault, seconds


WEB2_DB_FAULT = (0.2, 8.8)           # at severity g the reply takes 0.2 .. 0.2 + 8.8 * g seconds (about 9 s at the peak)


WEB2_FLAG_REF = "INC0047192"         # NPM-06 Extra Challenge: the ticket named in the held orders' notes during the incident


def _web2_order_note(oid, status, g):
    """Free-text order note, deterministic from the order (no random draw). While the incident
    is active, held orders carry the ops note that names the ticket for the DB-side cause; this
    lives only in the TDS result rows, which ~db records do not keep, so the packets hold it."""
    if status == "HOLD":
        if g >= 0.15:
            return f"Held: dock 7 scanner offline, see {WEB2_FLAG_REF}"
        return "Held: awaiting carrier pickup window"
    return ("", "Signature required", "Fragile", "Dock 3 staging")[oid % 4]


def web2_slow_page(ctx, client, ts, g=1.0):
    """Client browses the WEB2 LOB app; each page's backend TDS query to SQL1 is slow,
    so the HTTP response time tracks the DB service time (multi-tier cascade). Under load the
    backend returns SQL timeout error tokens and the front end serves 503s."""
    web = ctx.h[H('WEB2')]
    pool = _web2_pool(ctx)
    user = P.username_for(client.name)
    ua = P.UAS[0] if ctx.is_windows(client) else P.UAS[2]
    host = ("shipping." + get_current().domain)
    tgs, t = F.kerberos_tgs(ctx, client, "HTTP", web, ts + 0.005)
    out = ctx.arp_for(client, web, t)
    s = ctx.tcp(client, web, 80, t + 0.001).handshake()
    token = base64.b64encode(P.krb_ap_req_token(user, "HTTP", web.fqdn)).decode()
    s.c2s(P.http_request("GET", "/", host, ua), think=rng.uniform(0.001, 0.01))
    s.s2c(P.http_response("401 Unauthorized", b"", "text/html", s.t, headers=["WWW-Authenticate: Negotiate"]), think=rng.uniform(0.001, 0.004))
    sql_pkts = []
    db_lo, db_hi = WEB2_DB_HEALTHY if g < 0.15 else (WEB2_DB_FAULT[0], WEB2_DB_FAULT[0] + WEB2_DB_FAULT[1] * g)   # DB service time tracks severity
    for i in range(rng.randint(2, 5)):
        path = rng.choice(["/orders", "/orders?page=%d" % rng.randint(2, 9), "/api/orders?size=50", "/dispatch", "/labels"])
        hdrs = ["Authorization: Negotiate " + token] if i == 0 else ["Cookie: ASP.NET_SessionId=" + os.urandom(12).hex()]
        s.c2s(P.http_request("GET", path, host, ua, hdrs), think=rng.uniform(0.001, 0.005) if i == 0 else rng.uniform(1, 6) + 14 * g)
        db_error = False
        if pool:
            sp = rng.choice(pool[:4])        # same draw as before the pool was widened, so the capture's random stream is unchanged
            if sp.t > s.t:                   # one batch at a time per TDS connection: the app pool hands out an idle one,
                idle = [c for c in pool if c.t <= s.t]
                sp = max(idle, key=lambda c: c.t) if idle else min(pool, key=lambda c: c.t)   # the most recently released (a few hot connections, a long tail)
            sp.at(s.t + rng.uniform(0.0005, 0.002))
            q = rng.choice(P.SQL_QUERIES).replace("{n}", str(rng.randint(100000, 999999))).replace("{user}", user)
            sp.c2s(P.tds_sql_batch(q), think=0.0)
            if rng.random() < 0.25 * g:
                # SQL Server lock-request timeout error token (Msg 1222) — backend failing under load
                sp.s2c(P.tds_split(0x04, P.tds_error(1222, "Lock request time out period exceeded.", severity=16, spid=sp.dport), sp.dport), think=rng.uniform(db_lo, db_hi))
                db_error = True
            else:
                cols = [("OrderId", "int"), ("Tracking", "nvarchar"), ("Status", "nvarchar"), ("Notes", "nvarchar")]
                data = [(oid, trk, st, _web2_order_note(oid, st, g)) for oid, trk, st in
                        [(rng.randint(100000, 999999), f"{get_current().prefix}{rng.randint(100000, 999999)}", rng.choice(["PICKED", "SHIPPED", "HOLD"])) for _ in range(rng.randint(1, 30))]]
                sp.s2c(P.tds_split(0x04, P.tds_result(cols, data), sp.dport), think=rng.uniform(db_lo, db_hi))
            sql_pkts += sp.drain()
            s.at(sp.t + 0.002)               # the web tier answers only after the DB reply arrives
        # web response only after the slow/failed backend returns -> long HTTP service time
        if db_error:                          # the front end gives up only when SQL answered with the lock-timeout error
            s.s2c(P.http_response("503 Service Unavailable", b"<h1>Backend timeout</h1>", "text/html", s.t, server="Microsoft-IIS/10.0", headers=["Retry-After: 5"]), think=rng.uniform(0.05, 0.3))
        else:
            body = P.intranet_page("Orders", rng.randint(15, 50), s.t)
            s.s2c(P.http_response("200 OK", body, "text/html; charset=utf-8", s.t, headers=["X-Powered-By: ASP.NET"], gzip=True), think=rng.uniform(0.02, 0.2))
    pk = s.close(by_client=rng.random() < 0.6, think=rng.uniform(2, 12))
    return F.merged(tgs, out, pk, sql_pkts)


# ---- wireless degradation (WLC control issue) -------------------------------
# Two access points hard-fail during this incident (power/crash): their CAPWAP tunnel drops
# and never rejoins, the controller closes its end and logs the missed heartbeat, and nothing more
# is heard from them or from the clients homed on them. The rest of the fleet only flaps.
DEAD_APS = ("EXL-AP-03", "EXL-AP-08")

# ---- NPM / CRP shapes the scenario diagrams read (see make_diagram.py) ----
AUTH_SLOW_PEAK = (0.3, 6.0)          # unused since NPM-05: slow_kerberos draws log-normal, median 0.3 + 2.4 g s, cap 9.5 s
WAN_RTT_ADD = (0.10, 0.28)           # extra RTT at full severity
WAN_RATE_OK, WAN_RATE_BAD = 80e6, 8e6
DNS_RETRY_AT, DNS_FAILOVER_AT = (1.0, 2.0), (2.5, 3.0)
SMB_ZEROWIN_EXTRA = 1.2              # extra zero-window stall seconds at full severity (reopen time 0.2 .. 1.4 s)
SMB_ZEROWIN_P = 0.3                  # chance a 64 KB write chunk meets a closed window at full severity


WEB_DNS_HOSTS = (3, 9, 14, 22, 27, 31, 38, 44, 51, 60)   # the 10 workstations that stall
# CRP posture
CRP_WEAK_TLS_HOST, CRP_WEAK_TLS_CIPHER = "legacy-intranet.corp.example.local", 0x0005
CRP_CERT_HOST, CRP_CERT_CIPHER = "backup-portal.corp.example.local", 0x002F
# One identity per server (CRP-02 brief fix 1): the expired cert lives on the portal (443),
# a second, unrelated service -- a backup console on a different port and SNI -- always
# presents the self-signed one. Neither server's identity varies session to session.
CRP_CERT_HOST2, CRP_CERT_PORT2 = "backup-console.corp.example.local", 8443


CRP_CERT_EXPIRED_SHARE = 0.6         # share of sessions that go to the expired-cert portal
CRP_CADENCE = {"crp-weak-tls": 60, "crp-expired-cert": 90, "crp-plaintext-creds": 45,
               # anonymous FTP is session-based rather than a steady poll: the cadence is
               # the average gap between the 9 internal sessions across the working day.
               "crp-anonymous-ftp": 3260}
CRP_PLAINTEXT = [("http-basic", "exl-print1.corp.example.local", "HTTP/80",
                  "401 then Authorization: Basic \u2014 base64, not encryption"),
                 ("ftp", "exl-backup1.corp.example.local", "FTP/21", "USER then PASS in clear text"),
                 ("ldap-simple", "exl-dc1.corp.example.local", "LDAP/389", "simple bind carrying the password")]
DEAD_AP_CLIENTS = {H("AP-03"): [3, 10, 11, 12, 13], H("AP-08"): [50, 51, 52, 53]}


def _wlc_stalls(win):
    """Intervals in which the controller's control plane does not answer. Short ones make Echo Responses late,
    long ones (past the 66 s the AP waits) tear the tunnels down, and every AP sees the same stall, so the
    rejoins come in waves. They grow toward the plateau of the severity envelope and are gone before the
    window closes."""
    r = random.Random("npm07-stalls")
    lo, hi = win
    out, t = [], lo + r.uniform(25, 70)
    while t < hi - 90:
        x = sev(t, win)
        k = r.random()
        dur = r.uniform(2, 14) if k < 0.40 else (r.uniform(18, 60) if k < 0.75 else r.uniform(70, 140))
        dur *= 0.5 + 0.5 * x
        out.append((t, min(t + dur, hi - 30)))
        t += dur + r.uniform(25, 110) * (1.4 - 0.9 * x)
    return out


def _ap_homes(ctx):
    """Which wireless workstations are homed on which AP: the clients of the two hard-failed APs are fixed,
    the rest are spread over the other ten."""
    aps = sorted(n for n in ctx.h if n.startswith(H('AP')))
    live = [n for n in aps if n not in DEAD_APS]
    homes = {n: [] for n in aps}
    homes.update({n: list(v) for n, v in DEAD_AP_CLIENTS.items()})
    fixed = {i for v in DEAD_AP_CLIENTS.values() for i in v}
    for k, i in enumerate(i for i in range(1, 76) if i not in fixed):
        homes[live[k % len(live)]].append(i)
    return homes


def _wlc_syslog(ctx, ts, msg, pri=11):
    wlc, log = ctx.h[H('WLC1')], ctx.h[H('LOG1')]
    out = ctx.arp_for(wlc, log, ts)
    out.append(ctx.udp(wlc, log, 514, 514, P.syslog(pri, ts, (get_current().prefix.lower() + "wlc1"), msg), ts))
    return F.merged(out)


def _aireos_ts(ts):
    return time.strftime("%b %d %H:%M:%S", time.localtime(ts)) + ".%03d" % int((ts % 1) * 1000)


def _echo_lost(ctx, t, ap):
    """The controller notes that an AP's tunnel went quiet (AireOS layout: *task: timestamp: %FACILITY-SEV-MNEMONIC)."""
    mac = ":".join("%02x" % b for b in ap.mac)
    return _wlc_syslog(ctx, t, f"*capwapPingSocketTask: {_aireos_ts(t)}: %CAPWAP-3-ECHO_ERR: capwap_ac_sm.c:7623 "
                               f"Did not receive heartbeat reply from AP {mac}", pri=11)


def npm_wireless_degradation(ctx, eng, tag, win):
    """EXL-WLC1's control plane stalls. APs see Echo Responses arrive late or not at all, the ones that wait out
    the retransmissions rejoin (Discovery, DTLS, Join, Configuration), and the clients homed on an AP drop for
    the minute and a half it takes and then renew their address and re-resolve their names in a burst."""
    from .capwap import get_plane
    lo, hi = win
    plane = get_plane(ctx)
    homes = _ap_homes(ctx)
    plane.set_fault(_wlc_stalls(win), win, {n: len(v) for n, v in homes.items()}, DEAD_APS)
    aps = [ctx.h[n] for n in sorted(homes)]
    day_end = plane.t_end
    for ap in aps:
        life = plane.life(ap)
        life.plan()
        for tc, k in life.reconnects:
            if tc < day_end:
                cl = ctx.h.get(f"{H('WS-')}{homes[ap.name][k]:03d}")
                if cl:
                    eng.schedule(tc, lambda cl=cl, tc=tc: wireless_client_reconnect(ctx, cl, tc), tag)
        for fail_t, _run_t in life.rejoins:      # the controller's own watchdog notices once it is answering again
            t = fail_t + 2.0 + rng.uniform(0, 3)
            eng.schedule(t, lambda t=t, ap=ap: _echo_lost(ctx, t, ap), tag)
        if life.dead_from is not None:
            t = life.dead_from + 62.0 + rng.uniform(0, 4)
            eng.schedule(t, lambda t=t, ap=ap: _echo_lost(ctx, t, ap), tag)
    # Normally the baseline day carries the tunnels and this only perturbs them. Built without it, the scenario
    # puts its own tunnels (Echo, retransmits, Discovery, DTLS, Join, data resume) on the wire for the window.
    t_on = max(lo - 120, plane.t_start)
    eng.schedule(t_on, lambda: iter(()) if plane.live else plane.stream_all(aps, t_on, min(hi + 900, day_end)), tag)
    # the change that preceded it, in the controller's own log: where the exercise's hidden reference lives
    t = lo - 19 * 60 - rng.uniform(0, 240)
    mgmt = ctx.h[H('MGMT1')]
    eng.schedule(t, lambda t=t: _wlc_syslog(
        ctx, t, f"*emWeb: {_aireos_ts(t)}: Configuration saved by user admin ({mgmt.ip}), change record {WLC_CHANGE_REF}",
        pri=14), tag)












WLC_CHANGE_REF = "CHG0031877"      # the hidden reference of NPM-07: the change record named in EXL-WLC1's configuration-saved log line


def wireless_client_reconnect(ctx, client, ts):
    """A Wi-Fi client whose AP just came back: it re-associates, renews its address (RFC 2131 4.3.2 INIT-REBOOT
    most of the time, a full DORA when it does not trust its lease), checks the address with ARP (RFC 5227)
    and re-resolves the names it uses. The first lookups can be lost while the data path comes up."""
    from .core import udp_bcast, udp_frame, eth, arp as arp_pkt, BCAST, ETH_ARP
    dc1, dc2 = ctx.h[H('DC1')], ctx.h[H('DC2')]
    windows = ctx.is_windows(client)
    fw = ctx.link.gateway_for(client)
    xid = rng.getrandbits(32)
    sopts = P.dhcp_server_opts(dc1.ipb, fw.ipb, [dc1.ipb, dc2.ipb])
    bflag = 0x8000 if windows else 0                         # Windows asks for broadcast replies; the relay then broadcasts (RFC 2131 4.1)

    def to_client(msg):
        if bflag:
            return udp_bcast(fw, 67, 68, msg, dst_ip=b"\xff\xff\xff\xff", dst_mac=BCAST, src_ip=fw.ipb)
        return udp_frame(ctx.link, fw, client, 67, 68, msg, client)

    out, t = [], ts

    def exchange(t, mk_client, mk_server):
        """Client broadcast -> relay (the firewall) -> DHCP server and back (RFC 2131 4.1, RFC 1542): the relay sets
        giaddr and hops, forwards udp 67 to 67 to the server, which replies to giaddr; the relay answers the client."""
        out.append((t, udp_bcast(client, 68, 67, mk_client(), src_ip=b"\x00\x00\x00\x00")))
        tf = t + rng.uniform(0.0002, 0.001)
        out.append(ctx.udp(fw, dc1, 67, 67, mk_client(giaddr=fw.ipb, hops=1), tf))
        ts_ = tf + rng.uniform(0.003, 0.015)                  # the server's processing time
        out.append(ctx.udp(dc1, fw, 67, 67, mk_server(), ts_))
        tc = ts_ + rng.uniform(0.0002, 0.001)
        out.append((tc, to_client(mk_server())))
        return tc

    if rng.random() >= 0.7:                                  # DISCOVER / OFFER first
        t = exchange(t, lambda giaddr=b"\x00" * 4, hops=0: P.dhcp(1, xid, client.mac, 1, giaddr=giaddr, hops=hops,
                                                                   options=P.dhcp_client_opts(client.name, client.mac, windows), flags=bflag),
                     lambda: P.dhcp(2, xid, client.mac, 2, yiaddr=client.ipb, siaddr=dc1.ipb, giaddr=fw.ipb, options=sopts, flags=bflag))
        t += rng.uniform(0.001, 0.01)
        copts = P.dhcp_client_opts(client.name, client.mac, windows, req_ip=client.ipb, server_id=dc1.ipb)
    else:                                                    # INIT-REBOOT: REQUEST with the old address, no server id (RFC 2131 4.3.2)
        copts = P.dhcp_client_opts(client.name, client.mac, windows, req_ip=client.ipb)
    t = exchange(t, lambda giaddr=b"\x00" * 4, hops=0: P.dhcp(1, xid, client.mac, 3, giaddr=giaddr, hops=hops, options=copts, flags=bflag),
                 lambda: P.dhcp(2, xid, client.mac, 5, yiaddr=client.ipb, siaddr=dc1.ipb, giaddr=fw.ipb, options=sopts, flags=bflag))
    # RFC 5227: PROBE_WAIT 0-1 s, three probes 1-2 s apart, then two announcements ANNOUNCE_WAIT / ANNOUNCE_INTERVAL = 2 s apart
    probe = eth(BCAST, client.mac, ETH_ARP, arp_pkt(1, client.mac, b"\x00" * 4, b"\x00" * 6, client.ipb))
    tp = t + rng.uniform(0.0, 1.0)
    for i in range(3):
        out.append((tp, probe))
        if i < 2:
            tp += rng.uniform(1.0, 2.0)
    out += ctx.arp.gratuitous(client, tp + 2.0) + ctx.arp.gratuitous(client, tp + 4.0)
    tp += 2.0                                                # the address is usable once ANNOUNCE_WAIT has passed
    t = tp + rng.uniform(0.1, 0.6)
    pool = [("intranet." + get_current().domain), ("shipping." + get_current().domain), "outlook.office365.com",
            "login.microsoftonline.com", "teams.microsoft.com", "ocsp.digicert.com", "www.example.com"]
    names = ["www.msftconnecttest.com"] if windows else ["captive.apple.com"]
    names += rng.sample(pool, rng.randint(3, 5))
    internal = {("intranet." + get_current().domain): ctx.h[H('WEB1')], ("shipping." + get_current().domain): ctx.h[H('WEB2')]}
    for name in names:
        host = internal.get(name)
        ans = [(P.DNS_A, host.ipb)] if host else DNS_A_ans(name, ctx)
        dc, alt = (dc1, dc2) if rng.random() < 0.85 else (dc2, dc1)
        r = rng.random()
        if r < 0.22:      # the query is lost while the data path comes up; the resolver retries on the other server after 1 s
            sport, txid = client.eph(), ctx.next_txid()
            out += ctx.arp_for(client, dc, t)
            out.append(ctx.udp(client, dc, sport, 53, P.dns_query(txid, name), t))
            out += F.dns_lookup(ctx, client, name, t + 1.0, answers=ans, external=host is None, dc=alt)
        elif r < 0.27:    # lost twice: the third try, 3 s in, gets through
            sport, txid = client.eph(), ctx.next_txid()
            out += ctx.arp_for(client, dc, t)
            out.append(ctx.udp(client, dc, sport, 53, P.dns_query(txid, name), t))
            out += ctx.arp_for(client, alt, t + 1.0)
            out.append(ctx.udp(client, alt, sport, 53, P.dns_query(ctx.next_txid(), name), t + 1.0))
            out += F.dns_lookup(ctx, client, name, t + 3.0, answers=ans, external=host is None, dc=dc)
        else:
            out += F.dns_lookup(ctx, client, name, t, answers=ans, external=host is None, dc=dc)
        t += rng.uniform(0.05, 1.2)
    return F.merged(out)


# ---- web-traffic degradation for many hosts due to DNS ----------------------
def npm_web_dns_degradation(ctx, eng, tag, win):
    """>=10 named user hosts whose web browsing is slow because DNS resolution is failing."""
    s = sched_factory(eng, ctx, tag, win)
    hosts = [ctx.h[H("WS-%03d" % i)] for i in WEB_DNS_HOSTS]       # the 10 stalling workstations
    lo, hi = win
    pre, post = flanks(lo, hi)
    for hst in hosts:
        for t in pre + post:                 # each host loads pages cleanly before/after the DNS fault
            s(t, web_load_blocked_by_dns, hst, g=0.0)
        t = lo + rng.uniform(0, 60)
        while t < hi:
            s(t, web_load_blocked_by_dns, hst, g=sev(t, win))
            t += rng.expovariate(1 / float(CRP_CADENCE["crp-plaintext-creds"]))


def web_load_blocked_by_dns(ctx, client, ts, g=1.0):
    """A page load stalled by slow/failed DNS: the DNS round-trip dominates; the HTTP/HTTPS
    connection only starts after resolution (or the page fails when DNS SERVFAILs). Healthy
    when severity is low."""
    dc1, dc2 = ctx.h[H('DC1')], ctx.h[H('DC2')]
    ua = P.UAS[0] if ctx.is_windows(client) else P.UAS[2]
    site_name = rng.choice([("shipping." + get_current().domain), ("intranet." + get_current().domain),
                            "www.example.com", "cdn.example.net", "api.example.net"])
    internal = site_name.endswith("example.local")
    target = {("shipping." + get_current().domain): ctx.h[H('WEB2')], ("intranet." + get_current().domain): ctx.h[H('WEB1')]}.get(site_name)
    if not internal:
        target = ctx.sites[site_name][1] if site_name in ctx.sites else ctx.sites["www.example.com"][1]  # benign internet site
    out = ctx.arp_for(client, dc1, ts)
    sport = client.eph()
    txid = ctx.next_txid()
    q = P.dns_query(txid, site_name)
    out.append(ctx.udp(client, dc1, sport, 53, q, ts))
    r = rng.random()
    if g < 0.15:
        # healthy: fast resolution, then a real page load (same request/TLS exchange as in the window)
        ipb = target.ipb
        out.append(ctx.udp(dc1, client, 53, sport, P.dns_response(txid, site_name, P.DNS_A, [(P.DNS_A, ipb)], aa=internal, ttl=300), ts + rng.uniform(0.002, 0.012), vantage=client))
        return _dns_page_load(ctx, client, target, site_name, internal, ua, ts + rng.uniform(0.02, 0.06), out)
    if r < 0.4 * g + 0.05:
        # DNS SERVFAIL -> the stub resolver asks the next server straight away (within ms), which
        # is also failing; the page never loads (NPM-08 brief fix 4)
        t1 = ts + rng.uniform(1.0, 3.0)
        out.append(ctx.udp(dc1, client, 53, sport, P.dns_response(txid, site_name, P.DNS_A, [], rcode=2, aa=False), t1, vantage=client))
        t2 = t1 + rng.uniform(0.002, 0.01)
        out += ctx.arp_for(client, dc2, t2)
        out.append(ctx.udp(client, dc2, sport, 53, q, t2 + 0.0005))
        out.append(ctx.udp(dc2, client, 53, sport, P.dns_response(txid, site_name, P.DNS_A, [], rcode=2, aa=False), t2 + rng.uniform(1.0, 3.0), vantage=client))
        return F.merged(out)   # no web connection at all -- the visible symptom is DNS-only, page never loads
    # slow resolution, then a normal (but delayed) page load
    resolve_at = ts + rng.uniform(2.0, 5.0)
    # Windows resolver timers: resend at 1 s and again at 3 s while no answer has come (same txid and port)
    for dt in (1.0, 3.0):
        if ts + dt < resolve_at:
            out.append(ctx.udp(client, dc1, sport, 53, q, ts + dt + rng.uniform(0, 0.004)))
    out.append(ctx.udp(dc1, client, 53, sport, P.dns_response(txid, site_name, P.DNS_A, [(P.DNS_A, target.ipb)], aa=internal, ttl=60), resolve_at, vantage=client))
    return _dns_page_load(ctx, client, target, site_name, internal, ua, resolve_at + rng.uniform(0.02, 0.1), out)


def _dns_page_load(ctx, client, target, site_name, internal, ua, at, out):
    """The web transaction after a successful lookup: HTTP GET to the intranet, or TLS plus GET to a public site."""
    if internal:
        s = ctx.tcp(client, target, 80, at).handshake()
        s.c2s(P.http_request("GET", "/", site_name, ua), think=rng.uniform(0.002, 0.02))
        s.s2c(P.http_response("200 OK", P.intranet_page("Home", rng.randint(10, 30), s.t), "text/html; charset=utf-8", s.t, gzip=True), think=rng.uniform(0.02, 0.2))
        return F.merged(out, s.close(think=rng.uniform(1, 6)))
    from .tls import TlsSession
    s = ctx.tcp(client, target, 443, at).handshake()
    tls = TlsSession(ctx.pki, site_name, ctx.keylog)
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.002, 0.02))
    s.c2s(tls.app_data(True, P.http_request("GET", "/", site_name, ua)), think=rng.uniform(0.002, 0.02))
    s.s2c(tls.app_data(False, P.http_response("200 OK", P.blob(rng.randint(4000, 40000)), "text/html", s.t)), think=rng.uniform(0.02, 0.2))
    return F.merged(out, s.close(think=rng.uniform(1, 6)))


# ---- VoIP call-quality degradation ------------------------------------------
def npm_voip_quality(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    phones = [ctx.h[n] for n in ctx.h if n.startswith(H("PH"))]
    lo, hi = win
    pre, post = flanks(lo, hi, n=2)
    for t in pre + post:                     # a clean call before and after the degradation
        a, b = rng.sample(phones, 2)
        s(t, degraded_call, a, b, min(120, max(20, rng.lognormvariate(4.2, 0.5))), g=0.0)
    t = lo + 10
    while t < hi:
        a, b = rng.sample(phones, 2)
        s(t, degraded_call, a, b, min(300, max(30, rng.lognormvariate(4.6, 0.6))), g=sev(t, win))
        t += rng.expovariate(max(0.1, min(1.0, ctx.scale)) / 90.0)


def _ge_loss_mask(n, mean_loss, burst=3.3):
    """Gilbert-Elliott loss: the good state delivers, the bad state drops, mean burst `burst`
    packets, and the stationary loss equals `mean_loss` (congestion loss comes in bursts)."""
    p_bg = 1.0 / burst
    p_gb = min(0.9, mean_loss * p_bg / max(1e-9, 1.0 - mean_loss))
    bad = rng.random() < mean_loss
    out = []
    for _ in range(n):
        out.append(bad)
        bad = (rng.random() >= p_bg) if bad else (rng.random() < p_gb)
    return out


def _stream_view(base_seq, rows):
    """rows: [(index, send_time, arrival or None)]. Returns arrival-ordered snapshots so an RTCP
    report at time T can read the highest sequence received, packets received and RFC 3550
    interarrival jitter at that moment."""
    got = sorted((arr, i, st) for i, st, arr in rows if arr is not None)
    times, hi, cnt, jit = [], [], [], []
    h, c, j, prev = -1, 0, 0.0, None
    for arr, i, st in got:
        transit = (arr - st) * 8000.0
        if prev is not None:
            j += (abs(transit - prev) - j) / 16.0
        prev = transit
        h = max(h, i)
        c += 1
        times.append(arr); hi.append(h); cnt.append(c); jit.append(int(j))
    return times, hi, cnt, jit


def degraded_call(ctx, a, b, duration, ts, g=1.0):
    """A SIP call whose RTP media suffers bursty loss and queue-correlated delay (poor MOS) under
    load, or is clean when severity is low. Signalling is the ordinary call's two-leg dialog through
    the PBX; RTCP is RFC 3550 compound SR + reception report + SDES from both ends (NPM-09 fixes 1-3)."""
    pbx = ctx.h[H('PBX1')]
    ea, eb = 2000 + int(a.name[-2:]), 2000 + int(b.name[-2:])
    pa, pb = rng.randrange(16384, 32766, 2), rng.randrange(16384, 32766, 2)
    out = ctx.arp_for(a, pbx, ts) + ctx.arp_for(pbx, b, ts + 0.05, vantage=b)
    cid1, cid2 = os.urandom(8).hex() + "@" + a.ip, os.urandom(8).hex() + "@" + pbx.ip
    ta, tb, tp = os.urandom(4).hex(), os.urandom(4).hex(), "as" + os.urandom(4).hex()

    def leg(frm, to, via_ip, cid, cseq, extra=None):
        return [f"Via: SIP/2.0/UDP {via_ip}:5060;branch=z9hG4bK{os.urandom(6).hex()}", frm, to, f"Call-ID: {cid}", f"CSeq: {cseq}", "Max-Forwards: 70"] + (extra or [])
    fa = f"From: \"{P.username_for(a.name).title()}\" <sip:{ea}@{get_current().fqdn('PBX1')}>;tag={ta}"
    toB = f"To: <sip:{eb}@{get_current().fqdn('PBX1')}>"
    sdp_a = P.sdp(a.ip, pa, rng.randint(1000, 99999))
    sdp_b = P.sdp(b.ip, pb, rng.randint(1000, 99999))
    fp = f"From: \"{P.username_for(a.name).title()}\" <sip:{ea}@{pbx.ip}>;tag={tp}"
    toB2 = f"To: <sip:{eb}@{b.ip}:5060>"
    t = ts
    out.append(ctx.udp(a, pbx, 5060, 5060, P.sip_msg(f"INVITE sip:{eb}@{get_current().fqdn('PBX1')} SIP/2.0", leg(fa, toB, a.ip, cid1, "101 INVITE", [f"Contact: <sip:{ea}@{a.ip}:5060>", "User-Agent: Cisco-CP8841/14.2.1"]), sdp_a), t))
    out.append(ctx.udp(pbx, a, 5060, 5060, P.sip_msg("SIP/2.0 100 Trying", leg(fa, toB, a.ip, cid1, "101 INVITE", ["Server: Asterisk PBX 20.9.2"])), t + 0.004, vantage=a))
    out.append(ctx.udp(pbx, b, 5060, 5060, P.sip_msg(f"INVITE sip:{eb}@{b.ip}:5060 SIP/2.0", leg(fp, toB2, pbx.ip, cid2, "102 INVITE", [f"Contact: <sip:{ea}@{pbx.ip}:5060>", "User-Agent: Asterisk PBX 20.9.2"]), sdp_a), t + 0.02, vantage=b))
    out.append(ctx.udp(b, pbx, 5060, 5060, P.sip_msg("SIP/2.0 100 Trying", leg(fp, toB2, pbx.ip, cid2, "102 INVITE")), t + 0.03, vantage=b))
    out.append(ctx.udp(b, pbx, 5060, 5060, P.sip_msg("SIP/2.0 180 Ringing", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "102 INVITE", [f"Contact: <sip:{eb}@{b.ip}:5060>"])), t + 0.09, vantage=b))
    out.append(ctx.udp(pbx, a, 5060, 5060, P.sip_msg("SIP/2.0 180 Ringing", leg(fa, toB + f";tag={tp}", a.ip, cid1, "101 INVITE")), t + 0.1, vantage=a))
    t += rng.uniform(1.5, 4.0)
    out.append(ctx.udp(b, pbx, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "102 INVITE", [f"Contact: <sip:{eb}@{b.ip}:5060>", "User-Agent: Cisco-CP8841/14.2.1"]), sdp_b), t, vantage=b))
    out.append(ctx.udp(pbx, b, 5060, 5060, P.sip_msg(f"ACK sip:{eb}@{b.ip}:5060 SIP/2.0", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "102 ACK")), t + 0.006, vantage=b))
    out.append(ctx.udp(pbx, a, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", leg(fa, toB + f";tag={tp}", a.ip, cid1, "101 INVITE", [f"Contact: <sip:{eb}@{pbx.ip}:5060>", "User-Agent: Asterisk PBX 20.9.2"]), sdp_b), t + 0.008, vantage=a))
    out.append(ctx.udp(a, pbx, 5060, 5060, P.sip_msg(f"ACK sip:{eb}@{get_current().fqdn('PBX1')} SIP/2.0", leg(fa, toB + f";tag={tp}", a.ip, cid1, "101 ACK")), t + 0.03))
    out += ctx.arp_for(a, b, t + 0.02)
    # RTP: 20 ms cadence both directions; bursty loss (Gilbert-Elliott) and queue-correlated delay
    ssa, ssb = rng.getrandbits(32), rng.getrandbits(32)
    sa, sb = rng.randint(0, 40000), rng.randint(0, 40000)
    rta, rtb = rng.getrandbits(32), rng.getrandbits(32)
    loss_fwd, loss_rev = 0.002 + 0.12 * g, 0.001 + 0.06 * g
    jit_fwd, jit_rev = 0.001 + 0.02 * g, 0.0008 + 0.012 * g
    n = int(duration / 0.02)
    t0 = t + 0.04
    rho = 0.95
    dirs = []                                   # per direction: rows, view
    for src, dst, sp, dp, ssrc, seq0, rts0, off, loss, jit in (
            (a, b, pa, pb, ssa, sa, rta, 0.0, loss_fwd, jit_fwd), (b, a, pb, pa, ssb, sb, rtb, 0.01, loss_rev, jit_rev)):
        lost = _ge_loss_mask(n, loss)
        q, rows = 0.0, []
        for i in range(n):
            q = rho * q + math.sqrt(1 - rho * rho) * rng.gauss(0, jit)       # queue delay wanders, not i.i.d.
            send = t0 + i * 0.02 + off
            arr = None if lost[i] else send + 0.0005 + abs(q) * 1.0
            rows.append((i, send, arr))
            if arr is not None:
                out.append(ctx.udp(src, dst, sp, dp, P.rtp_packet(seq0 + i, rts0 + i * 160, ssrc, marker=(i == 0)), arr, tos=0xB8))
        dirs.append((rows, _stream_view(seq0, rows), seq0, ssrc, rts0))
    # RTCP (RTP port + 1): each end sends SR + report block about the peer's stream + SDES,
    # every 0.5..1.5 x 5 s, with LSR/DLSR from the peer's last SR
    sr_log = [[], []]                           # per sender: (send time, ntp middle32) of its SRs
    tend_media = t0 + n * 0.02
    nxt = [t0 + 5.0 * rng.uniform(0.5, 1.5), t0 + 5.0 * rng.uniform(0.5, 1.5)]
    last_rep = [(0, 0), (0, 0)]                 # per reporter: (expected, received) at its previous report
    events = []
    while min(nxt) < tend_media:
        w = 0 if nxt[0] <= nxt[1] else 1
        events.append((nxt[w], w))
        nxt[w] += 5.0 * rng.uniform(0.5, 1.5)
        if nxt[w] >= tend_media:
            nxt[w] = float("inf") if w == 0 else float("inf")
    for T, w in sorted(events):
        me, peer = (a, b) if w == 0 else (b, a)
        sp, dp = (pa + 1, pb + 1) if w == 0 else (pb + 1, pa + 1)
        rows_me, _v, seq_me, ssrc_me, rts_me = dirs[w]
        rows_pe, view_pe, seq_pe, ssrc_pe, _r = dirs[1 - w]
        times, hi, cnt, jit = view_pe
        k = bisect.bisect_right(times, T) - 1
        sent = int((T - (t0 + (0.01 if w else 0.0))) / 0.02) + 1
        sent = max(1, min(n, sent))
        ext = (seq_pe + hi[k]) if k >= 0 else seq_pe
        got = cnt[k] if k >= 0 else 0
        expected = (hi[k] + 1) if k >= 0 else 0
        pe, pr = last_rep[w]
        d_exp, d_got = expected - pe, got - pr
        frac = min(255, max(0, int(256 * (d_exp - d_got) / d_exp))) if d_exp > 0 else 0
        last_rep[w] = (expected, got)
        lsr = dlsr = 0
        peer_srs = [x for x in sr_log[1 - w] if x[0] + 0.001 <= T]
        if peer_srs:
            lsr = peer_srs[-1][1]
            dlsr = int((T - peer_srs[-1][0] - 0.001) * 65536)
        sr_log[w].append((T, P.ntp_middle32(T)))
        out.append(ctx.udp(me, peer, sp, dp, P.rtcp_sr_report(ssrc_me, T, rts_me + sent * 160, sent, sent * 160, ssrc_pe,
                                                                frac, max(0, expected - got), ext, jit[k] if k >= 0 else 0, lsr, dlsr), T, tos=0xB8))
    tend = t0 + n * 0.02 + 0.05
    out.append(ctx.udp(a, pbx, 5060, 5060, P.sip_msg(f"BYE sip:{eb}@{get_current().fqdn('PBX1')} SIP/2.0", leg(fa, toB + f";tag={tp}", a.ip, cid1, "102 BYE")), tend))
    out.append(ctx.udp(pbx, a, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", leg(fa, toB + f";tag={tp}", a.ip, cid1, "102 BYE")), tend + 0.005, vantage=a))
    out.append(ctx.udp(pbx, b, 5060, 5060, P.sip_msg(f"BYE sip:{eb}@{b.ip}:5060 SIP/2.0", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "103 BYE")), tend + 0.01, vantage=b))
    out.append(ctx.udp(b, pbx, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "103 BYE")), tend + 0.016, vantage=b))
    return F.merged(out)


# ---- TCP retransmission / packet-loss storm ---------------------------------
def npm_tcp_loss_storm(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H('WS'), H('MAC')))]
    lo, hi = win
    # THE CAUSE (post-compromise, not an admin): the Salt Typhoon collector EXL-WS-061 SSHes into
    # the server-distribution switch EXL-SWB1 and alters a port's speed/duplex, creating a duplex
    # mismatch on the path to FILE1 whose late collisions / FCS errors drop segments. The anomaly
    # the platform surfaces is the SOURCE -- a user workstation originating SSH to network infrastructure.
    # ndr-salt-typhoon is auto-selected with this scenario (SCENARIO_DEPENDENCIES).
    coll, sw = ctx.h.get(C_COLLECTOR), ctx.h.get(H('SWB1'))
    if coll is not None and sw is not None:
        t_admin = lo + rng.uniform(5, 25)
        eng.schedule(t_admin, (lambda a=coll, r=sw, t=t_admin, d=rng.uniform(60, 150): F.ssh_session(ctx, a, r, t, d, server_banner="SSH-2.0-Cisco-1.25")), tag)  # noqa: B008 draw order is pinned
    pre, post = flanks(lo, hi)
    for t in pre + post:                     # clean downloads flanking the loss storm
        s(t, lossy_download, rng.choice(users), g=0.0)
    t = lo
    while t < hi:
        s(t, lossy_download, rng.choice(users), g=sev(t, win))
        t += rng.expovariate(max(0.1, min(1.0, ctx.scale)) / 2.0)


def lossy_download(ctx, client, ts, g=1.0):
    """A file read from FILE1 over a lossy path: real segment loss, duplicate ACKs and a
    sender fast-retransmit. Loss rate scales with severity; clean at low g."""
    server = ctx.h[H('FILE1')]
    s, smb, pre = F._smb_open(ctx, client, server, "Dept", ts)
    size = int(rng.randint(200_000, 900_000) * max(0.1, min(1.0, ctx.scale)))
    name = rng.choice(F.FILE_NAMES).replace("{n}", str(rng.randint(10000, 99999)))
    s.c2s(smb.create_req(name), think=rng.uniform(0.005, 0.03))
    r, fid = smb.create_resp(s.t, size)
    s.s2c(r, think=rng.uniform(0.002, 0.02))
    off = 0
    chunk = 65536
    loss_p = 0.35 * g
    cwnd_full = max(2, chunk // s.mss)       # segments in a whole read: an unconstrained sender
    cwnd = cwnd_full
    while off < size:
        n = min(chunk, size - off)
        s.c2s(smb.read_req(fid, off, n), think=rng.uniform(0.002, 0.02))
        data = smb.read_resp(P.blob(n))
        if rng.random() < loss_p:
            # a response segment is genuinely dropped. Mostly the client dup-ACKs the hole (with
            # SACK) and the server fast-retransmits; sometimes a burst of 2-4 adjacent segments;
            # now and then the tail is lost and only the RTO repairs it (no dup ACKs possible).
            kind = rng.random()
            if kind < 0.08:
                s.tail_loss_rto(data, rto=0.3, think=rng.uniform(0.02, 0.08))
                cwnd = 1                         # RTO: back to slow start
            else:
                s.fast_retransmit(data, dup_acks=rng.randint(3, 4),
                                  lost_index=rng.randint(0, 2), think=rng.uniform(0.02, 0.08),
                                  lost_count=rng.randint(2, 4) if kind < 0.35 else 1)
                cwnd = max(2, cwnd // 2)         # multiplicative decrease (RFC 5681)
        elif cwnd < cwnd_full:
            # recovering sender: the response goes out in flights of `cwnd` segments with a round
            # trip (plus path queueing) between flights; the window grows back one segment per
            # flight, so throughput visibly dips after each loss and recovers.
            s.t += rng.uniform(0.01, 0.05)
            fo = 0
            while fo < len(data):
                step = cwnd * s.mss
                s.s2c(data[fo:fo + step])
                fo += step
                if fo < len(data):
                    s.t += s.rtt * rng.uniform(1.0, 1.5) + rng.uniform(0.001, 0.004)
                    cwnd = min(cwnd_full, cwnd + 1)
        else:
            s.s2c(data, think=rng.uniform(0.01, 0.05))
        off += n
    s.c2s(smb.close_req(fid), think=0.01)
    s.s2c(smb.close_resp(s.t, size), think=0.01)
    return F.merged(pre, F._smb_close(s, smb))


# ---- NTP time-sync failure --------------------------------------------------
def npm_ntp_failure(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H('WS'), H('MAC')))]
    hosts = users + [ctx.h[n] for n in (H('FILE1'), H('WEB1'), H('WEB2'), H('SQL1'), H('DC2'))]
    lo, hi = win
    pre, post = flanks(lo, hi)
    # Unsynchronised clocks drift (NPM-11 brief fix 4). Most hosts slip a few ms per minute; about
    # a third of the user machines (laptops resumed from sleep, VMs) slip several seconds per
    # minute, so the first one crosses the 5-minute Kerberos limit about 17 minutes in and more
    # follow as the window goes on.
    rate = {}
    for hst in hosts:
        fast = hst in users and rng.random() < 0.3
        rate[hst.name] = (rng.uniform(6.0, 18.0) if fast else rng.uniform(0.002, 0.06)) / 60.0   # s per s
    for hst in hosts:
        for k, t in enumerate(pre + post):   # healthy NTP sync (NTP1 answers) before and after
            # the first poll answered after recovery still carries the accumulated offset; the
            # clock is stepped back by the reply, so later polls are clean
            off = rate[hst.name] * (hi - lo) if k == len(pre) else 0.0
            s(t, ntp_healthy, hst, offset=off)
    # failure: NTP1 stops answering the scenario's polls (the ordinary day's own polls to NTP1 are
    # the baseline and are untouched). Windows w32time hosts poll once per ~1024 s; ntpd/chrony
    # hosts send an iburst-style volley every 1 to 3 minutes.
    for hst in hosts:
        win_host = ctx.is_windows(hst)
        t = lo + (rng.uniform(0, 1024) if win_host else rng.uniform(0, 120))
        while t < hi:
            s(t, ntp_unreachable, hst, offset=rate[hst.name] * (t - lo), single=win_host)
            t += rng.uniform(990, 1060) if win_host else rng.uniform(60, 200)
    # auth impact: Kerberos fails with clock-skew errors from the moment a host's clock is more
    # than 5 minutes off, so the error rate ramps with the number of hosts past the limit
    for hst in users:
        cross = lo + 300.0 / rate[hst.name]
        t = cross + rng.uniform(0, 60)
        while t < hi:
            s(t, kerberos_skew_fail, hst)
            t += rng.expovariate(1 / 45.0)


def ntp_healthy(ctx, client, ts, offset=0.0):
    """Normal NTP: client polls NTP1 and gets a prompt reply (synced)."""
    ntp = ctx.h[H('NTP1')]
    out = ctx.arp_for(client, ntp, ts)
    sport = 123 if not ctx.is_windows(client) else client.eph()
    req = P.ntp_request(ts + offset, ctx.is_windows(client))
    out.append(ctx.udp(client, ntp, sport, 123, req, ts))
    out.append(ctx.udp(ntp, client, 123, sport, P.ntp_response(req[40:48], ts + 0.001, ts + 0.001, vn=(req[0] >> 3) & 7), ts + rng.uniform(0.001, 0.01), vantage=client))
    return F.merged(out)


def ntp_unreachable(ctx, client, ts, offset=0.0, single=False):
    """NTP1 stops answering: the client's transmit timestamp is its own (drifted) clock."""
    ntp = ctx.h[H('NTP1')]
    out = ctx.arp_for(client, ntp, ts)
    sport = 123 if not ctx.is_windows(client) else client.eph()
    for k in range(1 if single else rng.randint(3, 6)):
        out.append(ctx.udp(client, ntp, sport, 123, P.ntp_request(ts + k + offset, ctx.is_windows(client)), ts + k * rng.uniform(1, 3)))
        # no reply from NTP1 (service unreachable)
    return F.merged(out)


def kerberos_skew_fail(ctx, client, ts):
    """A host whose clock has drifted: Kerberos AS-REQ is rejected with KRB_AP_ERR_SKEW (37)."""
    dc = ctx.h[H("DC1")]
    out = ctx.arp_for(client, dc, ts)
    s = ctx.tcp(client, dc, 88, ts + 0.001).handshake()
    s.c2s(_krb_tcp(P.krb_as_req(client.name + "$", ts, rng.getrandbits(31), True)), think=0.001)
    s.s2c(_krb_tcp(P.krb_error(37, client.name + "$", ts)), think=rng.uniform(0.005, 0.03))
    out += s.close(think=0.01)
    return F.merged(out)


# ================================================================= CRP builders
def crp_weak_tls(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    # Windows-only (CRP-01 brief fix 4): a modern macOS client cannot offer RC4 at all, so a
    # single legacy ClientHello shape for both platforms is not a real client's hello.
    users = [ctx.h[n] for n in ctx.h if n.startswith(H('WS'))]
    lo, hi = win
    t = lo
    while t < hi:
        s(t, weak_tls_session, rng.choice(users), ctx.h[H('WEB1')])
        t += rng.expovariate(1 / float(CRP_CADENCE["crp-weak-tls"]))


def weak_tls_session(ctx, client, server, ts):
    from .tls import weak_handshake, weak_app_data
    pre = F.dns_lookup(ctx, client, CRP_WEAK_TLS_HOST, ts, answers=[(P.DNS_A, server.ipb)]) \
        if F._wants_dns(ctx, client, CRP_WEAK_TLS_HOST, ts, True) else []
    out = ctx.arp_for(client, server, ts) + pre
    s = ctx.tcp(client, server, 443, ts + 0.001).handshake()
    for from_c, data in weak_handshake(ctx.pki, CRP_WEAK_TLS_HOST, cipher=0x0005):
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.001, 0.01))
    s.c2s(weak_app_data(True, rng.randint(200, 600)), think=rng.uniform(0.01, 0.1))
    s.s2c(weak_app_data(False, rng.randint(400, 4000)), think=rng.uniform(0.02, 0.2))
    return F.merged(out, s.close(think=0.05))


CRP_CERT_ABORT_SHARE = 0.3    # share of sessions whose first attempt aborts at the cert warning


def crp_expired_cert(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    # Windows-only, same reasoning as crp_weak_tls (CRP-01 brief fix 4, shared with CRP-02).
    users = [ctx.h[n] for n in ctx.h if n.startswith(H('WS'))]
    lo, hi = win
    t = lo
    while t < hi:
        target = "portal" if rng.random() < CRP_CERT_EXPIRED_SHARE else "console"
        client = rng.choice(users)
        if rng.random() < CRP_CERT_ABORT_SHARE:
            # The cert-warning dialog: the first attempt closes right after the server's
            # Certificate, before key exchange; the user clicks through a few seconds later
            # and the retry completes (CRP-02 brief fix 3).
            s(t, expired_cert_abort, client, target)
            s(t + rng.uniform(2.0, 8.0), expired_cert_session, client, target)
        else:
            s(t, expired_cert_session, client, target)
        t += rng.expovariate(1 / float(CRP_CADENCE["crp-expired-cert"]))


def _expired_cert_target(target):
    if target == "portal":
        return CRP_CERT_HOST, 443, "expired"
    return CRP_CERT_HOST2, CRP_CERT_PORT2, "selfsigned"


def expired_cert_abort(ctx, client, target, ts):
    from .tls import weak_handshake, weak_alert
    server = ctx.h[H('BACKUP1')]
    host, port, mode = _expired_cert_target(target)
    pre = F.dns_lookup(ctx, client, host, ts, answers=[(P.DNS_A, server.ipb)]) \
        if F._wants_dns(ctx, client, host, ts, True) else []
    out = ctx.arp_for(client, server, ts) + pre
    s = ctx.tcp(client, server, port, ts + 0.001).handshake()
    for from_c, data in weak_handshake(ctx.pki, host, cipher=0x002F, cert_mode=mode):
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.001, 0.01))
        if not from_c:
            break   # stop right after the server's Certificate/ServerHelloDone flight
    if rng.random() < 0.6:
        desc = rng.choice([42, 46, 48])
        s.c2s(weak_alert(desc), think=rng.uniform(1.0, 4.0))
        pk = s.close(by_client=True, think=0.05)
    else:
        pk = s.close(by_client=True, think=rng.uniform(1.0, 4.0))   # the user just closes the tab
    return F.merged(out, pk)


def expired_cert_session(ctx, client, target, ts):
    from .tls import weak_handshake, weak_app_data
    server = ctx.h[H('BACKUP1')]
    host, port, mode = _expired_cert_target(target)
    pre = F.dns_lookup(ctx, client, host, ts, answers=[(P.DNS_A, server.ipb)]) \
        if F._wants_dns(ctx, client, host, ts, True) else []
    out = ctx.arp_for(client, server, ts) + pre
    s = ctx.tcp(client, server, port, ts + 0.001).handshake()
    for from_c, data in weak_handshake(ctx.pki, host, cipher=0x002F, cert_mode=mode):  # AES128_SHA but bad cert
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.001, 0.01))
    s.c2s(weak_app_data(True, rng.randint(200, 500)), think=rng.uniform(0.01, 0.1))
    s.s2c(weak_app_data(False, rng.randint(400, 3000)), think=rng.uniform(0.02, 0.2))
    return F.merged(out, s.close(think=0.05))


# --- anonymous FTP on a device that should not be running one ----------------------------
# Deliberately NOT the MCP board: one posture story per host keeps both legible, and a
# reviewer can tell at a glance whether they are looking at the rogue MCP server or the rogue
# FTP server.
FTP_BOARD = H("SB-03")
FTP_CLIENT_WS = H("WS-018")
# TEST-NET-3 (RFC 5737). Deliberately NOT an EXT_HOSTS indicator and not created through
# ext(), so it never reaches the exported threat collection: this is a hardening finding about
# an exposed service, not a threat-intel hit, and conflating the two makes the demo argue two
# things at once.
FTP_EXTERNAL_IP = "203.0.113.47"
FTP_EXTERNAL_NAME = "scanner-node-7.probe-labs.example"
FTP_FIRST = (8, 17)                  # the first session lands exactly here
FTP_INTERNAL_SESSIONS = 9
FTP_EXTERNAL_SESSIONS = 6
# What each session does. A plausible mix: some browse, some pull, some push — an FTP server
# that only ever serves LIST is not a file server anyone is using.
# How many transfers each session performs, as (downloads, uploads). The catalogue is dealt
# out across these in order so every file in it appears on the wire exactly once — the point of
# the scenario is a countable set of observable files, and random sampling repeats itself and
# leaves gaps (the first pass produced only 8 distinct files from 16 transfers). Sums to 12
# downloads now that the external scanner (fix 3, below) no longer continues this same cursor
# into the catalogue's tail -- without the internal total covering all 12, the last two files
# (support-bundle.tar.gz, firmware-backup.bin) would never be fetched by anyone.
FTP_INTERNAL_SHAPE = [(1, 0), (1, 1), (2, 0), (1, 1), (0, 2), (2, 1), (1, 1), (1, 1), (3, 0)]


# The internet client is a scanner probing an open anonymous FTP server, not a second user of
# the board (CRP-04 brief fix 3) -- it never uploads and never pulls the firmware image or the
# support bundle (both much too large for a probe, and the page never credits it with write
# access). `exp0101.txt` stays exclusive to the internal workstation, per the page.
FTP_SCANNER_RETR_POOL = [n for n in F.FTP_DOWNLOADS if n not in ("firmware-backup.bin", "support-bundle.tar.gz", "exp0101.txt")]


def _ftp_external_host(ctx):
    """The internet-side client. Built directly rather than through ext() precisely so that
    used_indicator_ips() never sees it."""
    cache = ctx.__dict__.setdefault("_anonftp", {})
    if "h" not in cache:
        h = Host("SCANNER-NODE-7", FTP_EXTERNAL_IP,
                 "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)),
                 "linux", "external", "203.0.113.0/24", FTP_EXTERNAL_NAME)
        h.hops = 9
        cache["h"] = h
    return cache["h"]


def crp_anonymous_ftp(ctx, eng, tag, win):
    """A smart board quietly running an anonymous FTP server, reachable from inside and out.

    The posture finding has three parts and all three are readable on the wire without keys:
    the service exists on a device that has no business running one, it accepts `USER
    anonymous`, and the firewall has an inbound pinhole so the internet can reach it too.
    """
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    board = ctx.h[FTP_BOARD]
    ws = ctx.h.get(FTP_CLIENT_WS) or ctx.h[ATTACKER_WS]
    outside = _ftp_external_host(ctx)
    sc = max(0.02, min(1.0, ctx.scale))       # keep transfers visible even in small captures

    # Deal the catalogue out across the sessions. Downloads and uploads are each walked in
    # order (wrapping if the shapes ask for more than the catalogue holds), so the set of
    # distinct files on the wire is exactly the catalogue on every build.
    dl, ul = list(F.FTP_DOWNLOADS), list(F.FTP_UPLOADS)
    cursor = {"d": 0, "u": 0}

    def plan(n_get, n_put, want_list):
        items = ["LIST"] if want_list else []
        for _ in range(n_get):
            items.append(("RETR", dl[cursor["d"] % len(dl)])); cursor["d"] += 1
        for _ in range(n_put):
            items.append(("STOR", ul[cursor["u"] % len(ul)])); cursor["u"] += 1
        return tuple(items)

    # Internal: the first session is pinned to the window start (08:17 by default), the rest spread over the day.
    from . import ftpfiles as FF
    FF.set_first_login(lo)                    # the board's syslog shows that same first login
    t = lo
    for i, (ng, npu) in enumerate(FTP_INTERNAL_SHAPE[:FTP_INTERNAL_SESSIONS]):
        s(t, F.anon_ftp_session, ws, board, ops=plan(ng, npu, i % 2 == 0),
          scale=sc, passwd="anonymous@")
        t += (hi - lo) / FTP_INTERNAL_SESSIONS * rng.uniform(0.75, 1.2)

    # Inbound from the internet, offset so the two sources interleave rather than pair up.
    # Each session is a scanner's probe: login, LIST, at most one RETR of a small, already
    # -catalogued file -- never an upload, never the firmware image or the support bundle.
    def scanner_plan():
        items = ["LIST"]
        if rng.random() < 0.5:
            items.append(("RETR", rng.choice(FTP_SCANNER_RETR_POOL)))
        return tuple(items)

    t = lo + (hi - lo) * 0.08
    for _ in range(FTP_EXTERNAL_SESSIONS):
        s(t, F.anon_ftp_session, outside, board, ops=scanner_plan(), scale=sc, passwd="IEUser@")
        t += (hi - lo) / FTP_EXTERNAL_SESSIONS * rng.uniform(0.7, 1.25)


def crp_plaintext_creds(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    t = lo
    while t < hi:
        kind = rng.choice([x[0] for x in CRP_PLAINTEXT])
        s(t, plaintext_cred_session, rng.choice(users), kind)
        t += rng.expovariate(1 / float(CRP_CADENCE["crp-plaintext-creds"]))


def plaintext_cred_session(ctx, client, kind, ts):
    if kind == "http-basic":
        server = ctx.h[H('PRINT1')]     # a printer/appliance admin page over HTTP
        host = get_current().fqdn('PRINT1')
        pre = F.dns_lookup(ctx, client, host, ts, answers=[(P.DNS_A, server.ipb)]) \
            if F._wants_dns(ctx, client, host, ts, True) else []
        out = ctx.arp_for(client, server, ts) + pre
        s = ctx.tcp(client, server, 80, ts + 0.001).handshake()
        user = P.username_for(client.name)
        pw = P.password_for(user)
        ua = rng.choice(P.UAS[:7])       # a browser identity, not one of the system/update agents
        body401 = b"<html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1></body></html>"
        s.c2s(P.http_request("GET", "/admin/status", host, ua), think=rng.uniform(0.005, 0.05))
        s.s2c(P.http_response("401 Unauthorized", body401, "text/html", s.t, server="HP-ChaiSOE/1.0", headers=['WWW-Authenticate: Basic realm="Printer Admin"']), think=0.003)
        # the authenticated retry is the SAME client re-sending its own headers plus Authorization,
        # not a different tool -- a real browser never swaps identity mid-challenge
        s.c2s(P.http_basic_request("GET", "/admin/status", host, user, pw, ua=ua), think=rng.uniform(0.01, 0.1))
        s.s2c(P.http_response("200 OK", P.blob(1200), "text/html", s.t, server="HP-ChaiSOE/1.0"), think=rng.uniform(0.005, 0.03))
        return F.merged(out, s.close(think=0.05))
    if kind == "ftp":
        server = ctx.h[H('BACKUP1')]
        ftp_host = get_current().fqdn('BACKUP1')
        pre = F.dns_lookup(ctx, client, ftp_host, ts, answers=[(P.DNS_A, server.ipb)]) \
            if F._wants_dns(ctx, client, ftp_host, ts, True) else []
        out = ctx.arp_for(client, server, ts) + pre
        s = ctx.tcp(client, server, 21, ts + 0.001).handshake()
        user = P.username_for(client.name)
        pw = P.password_for(user)
        s.s2c(P.ftp_line(("220 " + H('BACKUP1') + " FTP service ready")), think=0.02)
        s.c2s(P.ftp_line(f"USER {user}"), think=rng.uniform(0.05, 0.3))
        s.s2c(P.ftp_line("331 Password required"), think=0.02)
        s.c2s(P.ftp_line(f"PASS {pw}"), think=rng.uniform(0.05, 0.3))   # cleartext password on the wire
        s.s2c(P.ftp_line("230 Login successful"), think=0.02)
        s.c2s(P.ftp_line("SYST"), think=0.1)
        s.s2c(P.ftp_line("215 UNIX Type: L8"), think=0.02)
        s.c2s(P.ftp_line("PWD"), think=rng.uniform(0.05, 0.2))
        s.s2c(P.ftp_line('257 "/" is current directory.'), think=0.02)
        s.c2s(P.ftp_line("TYPE I"), think=rng.uniform(0.05, 0.2))
        s.s2c(P.ftp_line("200 Type set to I."), think=0.02)
        pk = []
        dp = rng.randrange(49152, 65500)
        h = server.ipb
        s.c2s(P.ftp_line("PASV"), think=rng.uniform(0.05, 0.3))
        s.s2c(P.ftp_line("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)."
                         % (h[0], h[1], h[2], h[3], dp >> 8, dp & 0xFF)),
              think=rng.uniform(0.01, 0.05))
        if rng.random() < 0.7:
            s.c2s(P.ftp_line("LIST"), think=rng.uniform(0.02, 0.15))
            d = ctx.tcp(client, server, dp, s.t + rng.uniform(0.004, 0.02)).handshake()
            s.s2c(P.ftp_line("150 Opening BINARY mode data connection for file list."), think=0.02)
            d.t = max(d.t, s.t + 0.0005)
            d.s2c(("\r\n".join(F.ftp_listing(ctx.link)) + "\r\n").encode(), think=rng.uniform(0.05, 0.3))
            pk += d.close(by_client=False, think=rng.uniform(0.01, 0.05))
        else:
            name = rng.choice(F.FTP_DOWNLOADS)
            body = F.ftp_content(name, ctx.link)
            size = len(body)
            s.c2s(P.ftp_line(f"RETR {name}"), think=rng.uniform(0.05, 0.4))
            d = ctx.tcp(client, server, dp, s.t + rng.uniform(0.004, 0.02)).handshake()
            s.s2c(P.ftp_line(f"150 Opening BINARY mode data connection for {name} ({size} bytes)."), think=0.02)
            d.t = max(d.t, s.t + 0.0005)
            for off in range(0, size, 8192):
                d.s2c(body[off:off + 8192], think=rng.uniform(0.0008, 0.006))
            pk += d.close(by_client=False, think=rng.uniform(0.01, 0.06))
        s.s2c(P.ftp_line("226 Transfer complete."), think=rng.uniform(0.01, 0.05))
        s.c2s(P.ftp_line("QUIT"), think=rng.uniform(1, 45))   # seconds to under a minute, not a login probe
        s.s2c(P.ftp_line("221 Goodbye"), think=0.02)
        return F.merged(out, pk, s.close(think=0.05))
    # ldap-simple: cleartext simple bind with password on 389
    dc = ctx.h[H('DC1')]
    ldap_host = get_current().fqdn('DC1')
    pre = F.dns_lookup(ctx, client, ldap_host, ts, answers=[(P.DNS_A, dc.ipb)]) \
        if F._wants_dns(ctx, client, ldap_host, ts, True) else []
    out = ctx.arp_for(client, dc, ts) + pre
    s = ctx.tcp(client, dc, 389, ts + 0.001).handshake()
    user = P.username_for(client.name)
    pw = P.password_for(user)
    upn = f"{user}@{P.DOMAIN}"           # a UPN bind name, not the logon name as a literal CN
    import netgen.asn1 as A
    mid = 1
    simple = A.tlv(0x60, A.integer(3) + A.octets(upn.encode()) + A.tlv(0x80, pw.encode()))
    s.c2s(A.seq(A.integer(mid), simple), think=rng.uniform(0.005, 0.05))
    s.s2c(A.seq(A.integer(mid), A.tlv(0x61, A.enum(0) + A.octets(b"") + A.octets(b""))), think=rng.uniform(0.002, 0.02))
    # a real client searches after it binds -- rootDSE, the cheapest query every LDAP tool issues
    mid += 1
    s.c2s(P.ldap_search_request(mid, "", 0, P._filter_present("objectClass"),
                                 ["defaultNamingContext", "dnsHostName", "supportedLDAPVersion"]),
          think=rng.uniform(0.01, 0.1))
    resp = P.ldap_search_entry(mid, "", {"defaultNamingContext": [P.BASE_DN], "dnsHostName": [dc.fqdn],
                                          "supportedLDAPVersion": ["3", "2"]}) + P.ldap_search_done(mid)
    s.s2c(resp, think=rng.uniform(0.002, 0.02))
    mid += 1
    s.c2s(P.ldap_unbind(mid), think=rng.uniform(0.05, 0.3))
    return F.merged(out, s.close(think=0.02))


# ==================================================================== registry
# ---- php2shell: CVE-2026-109618 + CVE-2026-109619 (PHP core RCE) ------------------------------
# An internet host attacks an internet-facing PHP server (EXL-WEB3) over HTTPS. The sensor sits
# inside, so every flow here is framed INBOUND (vantage=the web server) and on the monitored
# segment -- internet -> internal web server, exactly the direction this is exploited in the wild.
# The TLS is the generator's ordinary RSA 1.2 keyed into the key log, so a sensor given the
# exported certs+keys decrypts and dissects the HTTP inside. Nothing here is a working exploit:
# the bodies are high-entropy filler SHAPED like the public exploit so the structural tells are
# on the wire, not a payload that does anything.
#
# What the public reporting (PHP advisories GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp, Calif,
# Wiz, Datadog, Imperva, Cloudflare, watchTowr; Oct 2026) says is observable, and is modelled:
#   * CVE-2026-109618 (OOM corruption): a multipart/form-data POST that exhausts PHP memory
#     while still under post_max_size -- empty filename="" file controls, deeply nested field
#     names, and many headers per part. PHP parses it BEFORE application code runs. mod_php runs
#     request shutdown over the half-built request state -> RCE; a worker that crashes answers
#     the next data with a bare RST (Apache AH00052 segfault on the host side).
#   * CVE-2026-109619 (stale global state / use-after-free): session upload progress, which is
#     ON by default and runs without session_start(). A field named PHP_SESSION_UPLOAD_PROGRESS
#     plus a file part; the attack needs two requests to hit the SAME worker, so these come in
#     tight pairs to one server.
#   * Memory disclosure (Heartbleed-shape): a dangling session-id pointer leaks ~67 KB of worker
#     memory back to the client in an oversized binary Set-Cookie: PHPSESSID response header.
#   * Early in-the-wild attempts (watchTowr/Patchstack/Cloudflare, 2026-10-21) used boundary
#     strings naming the CVEs -- B7kQpoc618 / B7kQpoc619 -- included here because they appear in the published reports.
#     They are a weak indicator (trivially changed), so the structural tells above carry the
#     scenario; a success returns HTTP 200, so status code alone is NOT the signal.
# Aftermath (the most direct evidence a sensor sees): the PHP worker on EXL-WEB3 originates an
# OUTBOUND reverse connection it never normally makes, then an operator drives a planted PHP web
# shell -- command in a POST, output in the response.
PHP2SHELL_HOST = "EXL-WEB3"
PHP2SHELL_VHOST = "portal.example.example"        # template value; resolved per build by _php2shell_vhost()
PHP2SHELL_SRC_IP, PHP2SHELL_SRC_NAME = "203.0.113.182", "scan182.probe-labs.example"
PHP2SHELL_C2_IP, PHP2SHELL_C2_NAME = "203.0.113.182", "scan182.probe-labs.example"
PHP2SHELL_BOUNDARY_618 = "B7kQpoc618"
PHP2SHELL_BOUNDARY_619 = "B7kQpoc619"
PHP2SHELL_SHELL_PATH = "/portal/uploads/.sess_cache.php"
PHP2SHELL_UAS = ("python-requests/2.32.3", "curl/8.9.1", "Go-http-client/1.1", "python-urllib3/2.2.2")
PHP2SHELL_PROBE_PATHS = ("/", "/index.php", "/info.php", "/portal/", "/portal/login.php",
                         "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/?phpinfo=1")
PHP2SHELL_CMDS = [b"id", b"uname -a", b"cat /etc/passwd", b"ls -la /var/www/portal",
                  b"crontab -l", b"cat /var/www/portal/config/db.php", b"ps aux | grep php"]
# Real command output per PHP2SHELL_CMDS entry, not shipping-vocabulary filler -- what a planted
# web shell's `system()`/`shell_exec()` call actually returns. Credentials are placeholders.
PHP2SHELL_CMD_OUTPUTS = {
    b"id": b"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
    b"uname -a": b"Linux exl-web3 5.15.0-134-generic #144-Ubuntu SMP x86_64 GNU/Linux\n",
    b"cat /etc/passwd": (b"root:x:0:0:root:/root:/bin/bash\n"
                         b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                         b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                         b"mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false\n"),
    b"ls -la /var/www/portal": (b"total 48\n"
                                b"drwxr-xr-x  6 www-data www-data 4096 Nov  5 09:12 .\n"
                                b"drwxr-xr-x  3 root     root     4096 Oct  2 14:05 ..\n"
                                b"-rw-r--r--  1 www-data www-data  612 Nov  5 09:10 .sess_cache.php\n"
                                b"drwxr-xr-x  2 www-data www-data 4096 Oct  2 14:05 config\n"
                                b"-rw-r--r--  1 www-data www-data 2214 Oct  2 14:05 upload.php\n"
                                b"drwxr-xr-x  2 www-data www-data 4096 Oct  2 14:05 uploads\n"),
    b"crontab -l": (b"# m h  dom mon dow   command\n"
                   b"*/5 * * * * /usr/bin/php /var/www/portal/cron/sync.php >/dev/null 2>&1\n"),
    b"cat /var/www/portal/config/db.php": (b"<?php\nreturn [\n"
                                           b"    'host' => '127.0.0.1',\n"
                                           b"    'database' => 'portal',\n"
                                           b"    'username' => 'portal_app',\n"
                                           b"    'password' => 'REDACTED-PLACEHOLDER',\n"
                                           b"];\n"),
    b"ps aux | grep php": (b"www-data   1821  0.0  0.4  98344 16452 ?        S    09:01   0:00 php-fpm: pool www\n"
                           b"www-data   1822  0.0  0.4  98344 16388 ?        S    09:01   0:00 php-fpm: pool www\n"),
}
# CVE-2026-109618 response-side signature (parse-stage OOM). When display_errors is on the OOM
# surfaces as this exact PHP fatal line; "in Unknown on line 0" is the 109618 startup tell a
# sensor matches on. (Fidelity: the response string, not the status code, carries the signal.)
PHP2SHELL_OOM_FATAL = (b"<br />\n<b>Fatal error</b>:  Allowed memory size of 134217728 bytes "
                       b"exhausted (tried to allocate 4096 bytes) in <b>Unknown</b> on line <b>0</b><br />\n")


def _mp_part(boundary, disposition, value, extra_headers=()):
    lines = [b"--" + boundary, b"Content-Disposition: form-data; " + disposition]
    lines += list(extra_headers)
    lines += [b"", value]
    return b"\r\n".join(lines) + b"\r\n"


def _php2shell_mp_oom(boundary):
    """CVE-2026-109618 shape: nested names, an empty filename="" control, many headers/part."""
    b = boundary.encode()
    nested = b"x" + b"".join(b"[%d]" % i for i in range(40))          # deeply nested field name
    pad = [b"X-Part-Pad-%d: %s" % (i, b"a" * 24) for i in range(24)]   # unbounded headers per part
    parts = [
        _mp_part(b, b'name="' + nested + b'"', P.blob(rng.randint(1500, 4000))),
        _mp_part(b, b'name="upload[]"; filename=""', P.blob(600),      # empty file control
                 extra_headers=[b"Content-Type: application/octet-stream"] + pad),
        _mp_part(b, b'name="d[a][b][c][d][e][f][g]"', P.blob(rng.randint(3000, 8000))),
    ]
    return b"".join(parts) + b"--" + b + b"--\r\n"


def _php2shell_mp_uap(boundary):
    """CVE-2026-109619 shape: the session-upload-progress field plus a file part."""
    b = boundary.encode()
    parts = [
        _mp_part(b, b'name="PHP_SESSION_UPLOAD_PROGRESS"', P.blob(rng.randint(200, 700))),
        _mp_part(b, b'name="file"; filename="u.bin"', P.blob(rng.randint(2000, 6000)),
                 extra_headers=[b"Content-Type: application/octet-stream"]),
    ]
    return b"".join(parts) + b"--" + b + b"--\r\n"


def _php2shell_inbound(ctx, attacker, srv, ts, *, method, path, ua, req_headers=None, body=b"",
                       status="500 Internal Server Error", server="Apache/2.4.58 (Ubuntu)",
                       resp_body=None, resp_headers=None, resp_ctype="text/html; charset=utf-8", crash=False):
    """One inbound HTTPS request to the PHP server, framed on the SPAN (internet -> internal).
    crash=True models a worker dying: the server answers the request data with a bare RST."""
    from .tls import TlsSession
    out = ctx.arp_for(attacker, srv, ts, vantage=srv)
    sxn = ctx.tcp(attacker, srv, 443, ts + 0.001, vantage=srv).handshake()
    tls = TlsSession(ctx.pki, srv.fqdn, ctx.keylog, profile="openssl")
    for from_c, data in tls.handshake():
        (sxn.c2s if from_c else sxn.s2c)(data, think=rng.uniform(0.001, 0.006))
    req = P.http_request(method, path, _php2shell_vhost(), ua, req_headers, body)
    sxn.c2s(tls.app_data(True, req), think=rng.uniform(0.002, 0.02))
    if crash:                                            # worker segfaults on the half-built request
        return F.merged(out, sxn.rst_from_server(think=rng.uniform(0.01, 0.08)))
    rb = resp_body if resp_body is not None else P.text_blob(rng.randint(200, 600))
    resp = P.http_response(status, rb, resp_ctype, sxn.t, server=server, headers=resp_headers)
    sxn.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.1))
    return F.merged(out, sxn.close(think=0.002))


def php2shell_probe(ctx, attacker, srv, ts, ua=None):
    """Recon: an unauthenticated GET for a PHP fingerprint / known path."""
    path = rng.choice(PHP2SHELL_PROBE_PATHS)
    hdrs = ["X-Forwarded-For: %s" % PHP2SHELL_SRC_IP]
    return _php2shell_inbound(ctx, attacker, srv, ts, method="GET", path=path,
                              ua=ua or rng.choice(PHP2SHELL_UAS), req_headers=hdrs,
                              status="200 OK", resp_headers=["X-Powered-By: PHP/8.3.14"])


def php2shell_oom(ctx, attacker, srv, ts, crash=True, ua=None):
    """CVE-2026-109618 attempt: a multipart POST that exhausts memory before app code runs.
    Status is CONFIG-dependent, not exploit-dependent: a crashed worker answers with a bare RST;
    a surviving worker returns 500 + empty body (display_errors off) or 200 + the PHP OOM fatal
    string (display_errors on). So the response side -- the fatal string -- is the signal, not the
    status code (see detector-fidelity lesson)."""
    boundary = PHP2SHELL_BOUNDARY_618
    ua = ua or rng.choice(PHP2SHELL_UAS)
    hdrs = ["Content-Type: multipart/form-data; boundary=%s" % boundary,
            "X-Forwarded-For: %s" % PHP2SHELL_SRC_IP]
    body = _php2shell_mp_oom(boundary)
    if crash:                                            # worker segfaults on the half-built request
        return _php2shell_inbound(ctx, attacker, srv, ts, method="POST", path="/portal/upload.php",
                                  ua=ua, req_headers=hdrs, body=body, crash=True)
    if rng.random() < 0.5:                               # display_errors Off: 500 + empty body
        return _php2shell_inbound(ctx, attacker, srv, ts, method="POST", path="/portal/upload.php",
                                  ua=ua, req_headers=hdrs, body=body,
                                  status="500 Internal Server Error", resp_body=b"")
    return _php2shell_inbound(ctx, attacker, srv, ts, method="POST", path="/portal/upload.php",
                              ua=ua, req_headers=hdrs, body=body,
                              status="200 OK", resp_body=PHP2SHELL_OOM_FATAL)      # display_errors On


def php2shell_uap(ctx, attacker, srv, ts, ua=None):
    """CVE-2026-109619 attempt: the producer+consumer pair of session-upload-progress POSTs must
    land on the SAME prefork worker -- which only happens when both ride ONE keep-alive connection
    (Apache pins a connection to one child). So this sends BOTH requests on a single TCP+TLS
    session (equal source port on the wire), not two separate connections -- the precondition is
    the tell, and modelling it on one connection is what makes the 109619 shape faithful. One
    client socket cannot change identity mid-connection, so the UA is drawn once and reused for
    both requests, not redrawn per request."""
    from .tls import TlsSession
    boundary = PHP2SHELL_BOUNDARY_619
    ua = ua or rng.choice(PHP2SHELL_UAS)
    sid = "%032x" % rng.getrandbits(128)
    hdrs = ["Content-Type: multipart/form-data; boundary=%s" % boundary,
            "Cookie: PHPSESSID=%s" % sid, "X-Forwarded-For: %s" % PHP2SHELL_SRC_IP,
            "Connection: keep-alive"]
    out = ctx.arp_for(attacker, srv, ts, vantage=srv)
    sxn = ctx.tcp(attacker, srv, 443, ts + 0.001, vantage=srv).handshake()
    tls = TlsSession(ctx.pki, srv.fqdn, ctx.keylog, profile="openssl")
    for from_c, data in tls.handshake():
        (sxn.c2s if from_c else sxn.s2c)(data, think=rng.uniform(0.001, 0.006))
    for i in range(2):                                   # producer then consumer, same worker
        think = rng.uniform(0.2, 0.9) if i == 1 else rng.uniform(0.002, 0.02)   # pace the consumer
        req = P.http_request("POST", "/portal/upload.php", _php2shell_vhost(),
                             ua, hdrs, _php2shell_mp_uap(boundary))
        sxn.c2s(tls.app_data(True, req), think=think)
        resp = P.http_response("200 OK", P.text_blob(rng.randint(200, 600)),
                               "text/html; charset=utf-8", sxn.t, server="Apache/2.4.58 (Ubuntu)")
        sxn.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.1))
    return F.merged(out, sxn.close(think=0.002))


def php2shell_leak(ctx, attacker, srv, ts, ua=None):
    """Memory disclosure: the server returns ~67 KB of worker memory in the response body
    (application/octet-stream) behind a short, ordinary-looking PHPSESSID cookie -- the
    Heartbleed-shape response-side tell, without an unrealistically huge header line (a real
    server/intermediary rejects a single header line in the tens of KB)."""
    leaked = P.blob(int(min(67000, 67000 * min(1.0, max(0.05, ctx.scale)))))
    sid = "%032x" % rng.getrandbits(128)
    return _php2shell_inbound(ctx, attacker, srv, ts, method="POST", path="/portal/upload.php",
                              ua=ua or rng.choice(PHP2SHELL_UAS),
                              req_headers=["Content-Type: multipart/form-data; boundary=%s" % PHP2SHELL_BOUNDARY_619,
                                           "X-Forwarded-For: %s" % PHP2SHELL_SRC_IP],
                              body=_php2shell_mp_uap(PHP2SHELL_BOUNDARY_619), status="200 OK",
                              resp_body=leaked, resp_ctype="application/octet-stream",
                              resp_headers=["Set-Cookie: PHPSESSID=%s; path=/" % sid])


def php2shell_success(ctx, attacker, srv, ts, ua=None):
    """A successful attempt returns HTTP 200 and the worker keeps serving -- so the status code
    alone is NOT the signal; the structural request tells and the aftermath are."""
    hdrs = ["Content-Type: multipart/form-data; boundary=%s" % PHP2SHELL_BOUNDARY_618,
            "X-Forwarded-For: %s" % PHP2SHELL_SRC_IP]
    return _php2shell_inbound(ctx, attacker, srv, ts, method="POST", path="/portal/upload.php",
                              ua=ua or rng.choice(PHP2SHELL_UAS), req_headers=hdrs,
                              body=_php2shell_mp_oom(PHP2SHELL_BOUNDARY_618), status="200 OK")


def php2shell_callback(ctx, ts):
    """Aftermath: the PHP server (EXL-WEB3) ORIGINATES an outbound connection it never normally
    makes -- the most direct evidence on the wire. Anomalous origin, ordinary protocol."""
    srv = ctx.h.get(PHP2SHELL_HOST)
    c2 = _ext_src(ctx, PHP2SHELL_C2_IP, PHP2SHELL_C2_NAME)
    if srv is None:
        return []
    return F.https_session(ctx, srv, (c2.fqdn, c2), ts, requests=rng.randint(2, 4),
                           sizes=[180, 240, 160, 200], keep_open=1.0, rate=20e6,
                           ua="curl/8.9.1", paths=["/p.php", "/p.php", "/p.php", "/p.php"], dns=True)


def php2shell_webshell(ctx, attacker, srv, ts, ua=None):
    """Hands-on-keyboard on a planted PHP web shell: command in the POST, real command output
    (not shipping-vocabulary filler) in the response."""
    cmd = rng.choice(PHP2SHELL_CMDS)
    b64_cmd = base64.b64encode(cmd).decode().replace("=", "%3D")   # percent-encode padding in a form body
    body = ("c=" + b64_cmd).encode()
    out = base64.b64encode(PHP2SHELL_CMD_OUTPUTS.get(cmd, b""))
    return _php2shell_inbound(ctx, attacker, srv, ts, method="POST", path=PHP2SHELL_SHELL_PATH,
                              ua=ua or rng.choice(PHP2SHELL_UAS),
                              req_headers=["Content-Type: application/x-www-form-urlencoded",
                                           "X-Forwarded-For: %s" % PHP2SHELL_SRC_IP],
                              body=body, status="200 OK", resp_body=out)


def _php2shell_vhost():
    return "portal.%s.example" % get_current().slug


def _php2shell_server(ctx):
    """The internet-facing PHP portal server. It is created here, when the scenario is built,
    rather than carried in the inventory, so adding it never moves the no-module baseline
    (a new inventory host shifts the day's random stream and its packet count)."""
    name = PHP2SHELL_HOST
    srv = ctx.h.get(name)
    if srv is None:
        link = ctx.link
        ip = link.place("10.10.20.42") if hasattr(link, "place") else "10.10.20.42"
        srv = Host(name, ip, "00:50:56:b2:70:1c", "Linux (Ubuntu) / Apache 2.4 / PHP 8.3-FPM",
                   "Public customer portal (Apache / PHP-FPM)", ip.rsplit(".", 1)[0] + ".0/24",
                   get_current().fqdn("WEB3"))
        ctx.h[name] = srv
    return srv


def php2shell(ctx, eng, tag, win):
    """Internet -> internal PHP server. Recon, then interleaved CVE-2026-109618 (OOM, mostly
    worker-crash RSTs) and CVE-2026-109619 (session-upload-progress pairs) with memory-disclosure
    responses, then a 200 breakthrough, the server's outbound callback, and web-shell commands."""
    s = sched_factory(eng, ctx, tag, win)
    srv = _php2shell_server(ctx)
    attacker = _ext_src(ctx, PHP2SHELL_SRC_IP, PHP2SHELL_SRC_NAME)
    ua = rng.choice(PHP2SHELL_UAS)    # one scanning tool for the whole incident, not a fresh draw per request
    lo, hi = win
    # 1) recon: a short burst of PHP fingerprinting GETs
    t = lo + 20
    for _ in range(rng.randint(5, 9)):
        s(t, php2shell_probe, attacker, srv, ua=ua)
        t += rng.uniform(2, 8)
    # 2) exploitation attempts, to about 60% through the window
    t = lo + 90
    while t < lo + (hi - lo) * 0.6:
        r = rng.random()
        if r < 0.55:
            s(t, php2shell_oom, attacker, srv, crash=(rng.random() < 0.8), ua=ua)
        elif r < 0.85:
            s(t, php2shell_uap, attacker, srv, ua=ua)
        else:
            s(t, php2shell_leak, attacker, srv, ua=ua)
        t += rng.uniform(5, 20)
    # 3) the breakthrough (HTTP 200) and the aftermath: the server calls out
    brk = lo + (hi - lo) * 0.62
    s(brk, php2shell_success, attacker, srv, ua=ua)
    s(brk + rng.uniform(3, 8), php2shell_callback)
    # 4) hands-on-keyboard on the planted web shell
    t = brk + rng.uniform(20, 60)
    while t < hi:
        for _ in range(rng.randint(2, 5)):
            s(t, php2shell_webshell, attacker, srv, ua=ua)
            t += rng.uniform(6, 30)
        t += rng.uniform(120, 400)


# ============================================================================================
# OT dashboard add-ons + nightly backup (added in the 2026-11 engine update).
# Each is a SELECTABLE, pin-safe scenario that layers on top of the baseline; inert unless
# selected and (for the OT ones) unless the OT subnet is generated.
# ============================================================================================

MB_MAX_TIMEOUTS = 5                  # consecutive unanswered polls before the master drops and reopens the connection


def ot_plc_session(ctx, master, plc, t0, t_end, win):
    """SCADA master polling one PLC over a persistent Modbus/TCP connection. Healthy = prompt
    reads. As load rises the response time grows first (before any exception), then the PLC
    answers some polls with slave-busy and stops answering others: the master's TCP retransmits
    the unanswered request (same sequence number), the next poll uses a new TID, and after
    MB_MAX_TIMEOUTS silent polls in a row it closes the connection and reconnects. Recovery
    mirrors the ramp (latency falls back, then normal)."""
    out = ctx.arp_for(master, plc, t0)
    sx = ctx.tcp(master, plc, P.MODBUS_PORT, t0 + 0.0008).handshake()
    tid = rng.randrange(1, 4096)
    nxt = t0 + 0.5
    silent = 0
    while nxt < t_end:
        nxt = max(nxt, sx.t)                  # a master blocked on timeouts falls behind its schedule, it does not queue polls
        g = sev(nxt, win)
        cyc = nxt
        nxt += rng.uniform(1.0, 2.0)
        for k in range(rng.randint(2, 4)):
            tid = (tid + 1) & 0xFFFF
            req = P.modbus_read_req(tid, 1, P.MB_READ_HOLDING, 0, 10)
            sx.c2s(req, think=max(0.0002, (cyc - sx.t) if k == 0 else rng.uniform(0.004, 0.03)))
            r = rng.random()
            if g >= 0.25 and r < 0.6 * g:
                if r < 0.3 * g:
                    sx.retransmit_last_client_segment(req, delays=(rng.uniform(1.0, 1.0 + 1.5 * g),))
                    silent += 1
                else:
                    sx.s2c(P.modbus_exception(tid, 1, P.MB_READ_HOLDING, P.MB_EX_BUSY), think=rng.uniform(0.2, 0.2 + 2.0 * g))
                    silent = 0
            else:
                lat = rng.uniform(0.0006, 0.004) + (rng.uniform(0.0, 0.35 * g) if g > 0.03 else 0.0)
                sx.s2c(P.modbus_read_rsp(tid, 1, P.MB_READ_HOLDING, 10), think=lat)
                silent = 0
            if silent >= MB_MAX_TIMEOUTS:
                out = F.merged(out, sx.close(think=rng.uniform(0.01, 0.1)))
                silent = 0
                sx = ctx.tcp(master, plc, P.MODBUS_PORT, sx.t + rng.uniform(1.0, 3.0)).handshake()
                break
    return F.merged(out, sx.close(think=0.002))


def ndr_ot_sanctioned_writes(ctx, eng, tag, win):
    """BENIGN OT baseline add-on (feeds the control-writes + logon tables as the NORMAL case).

    Not an attack. It gives the dashboards a sanctioned baseline so ndr-ot-modbus-write /
    ndr-ot-sis-tamper stand out against real operator activity rather than against nothing:
      * a run of sanctioned operator setpoint WRITEs, always from one dedicated writer
        (EXL-HMI4) to a small, reused register range -- separable from the wider SCADA/HMI
        baseline (which also writes setpoints) by source and register alone, not just by being
        benign;
      * a couple of benign OT NTLM logons, reached by the file server's IP literal (not its
        FQDN -- that is the whole reason Kerberos is skipped) and authenticating against the OT
        forest's own NetBIOS domain, not the enterprise one;
      * a handful of failed Kerberos pre-auths (KDC_ERR_PREAUTH_FAILED) at the 06:00 / 14:00
        shift change -- a mistyped password, the everyday benign look-alike of a spray --
        each followed by the same user's successful retry a few seconds later;
      * one after-hours engineer logon.
    MITRE: n/a (benign). Purdue: writers in Zone 2 (L2 supervisory), PLCs in Zone 1 (L1 field).
    Dashboard: control-writes table (benign baseline), Purdue-zone user / logon tables."""
    from .model import ot_account_at
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    # Window opens 05:45; express every time as an offset from lo so the scenario registers in the
    # metadata dry-run (which fabricates a 0-based window) as well as in a real build (lo=05:45).
    shift0, shift1 = lo + 4500, lo + 33300          # 07:00 .. 15:00 production shift
    change_am, change_pm = lo + 900, lo + 29700     # 06:00 / 14:00 shift change
    after_hours = lo + 47700                        # 19:00
    plcs = _ot_hosts(ctx, H("PLC"))
    writers = [h for h in (ctx.h.get(n) for n in
               (H("SCADA1"), H("SCADA2"), H("HMI1"), H("HMI2"), H("HMI3"), H("HMI4"))) if h]
    sanctioned_writer = writers[-1] if writers else None       # EXL-HMI4, always this one host
    sanctioned_targets = [90, 91, 92]                          # outside the baseline's own 40-80 range
    otdc = ctx.h.get(H("OTDC1"))
    otfs = ctx.h.get(H("OTFS1"))
    realm = P.OT_REALM
    if plcs and sanctioned_writer:
        for _ in range(16):
            s(rng.uniform(shift0, shift1), F.modbus_setpoint_write,
              sanctioned_writer, rng.choice(plcs), targets=sanctioned_targets)
    if otfs and writers:
        for host in writers[:2]:
            s(rng.uniform(shift0, shift1), F.ntlm_smb_logon, host, otfs,
              user=ot_account_at(host.name, shift0), share="Recipes",
              domain=P.OT_NETBIOS, share_host=otfs.ip)
    if otdc and writers:
        for change in (change_am, change_pm):
            host = rng.choice(writers)
            fail_ts = change + rng.uniform(-120, 120)
            user = ot_account_at(host.name, change)
            s(fail_ts, F.kerberos_as_outcome, host, user=user, outcome="bad_password", dc=otdc, realm=realm)
            s(fail_ts + rng.uniform(5, 20), F.kerberos_as_outcome, host, user=user, outcome="ok", dc=otdc, realm=realm)
    eng_ws = ctx.h.get(H("OTENG1")) or ctx.h.get(H("ENGWS1"))
    if otdc and eng_ws:
        t = after_hours + rng.uniform(600, 2400)
        s(t, F.kerberos_as_outcome, eng_ws, user=ot_account_at(eng_ws.name, t),
          outcome="ok", dc=otdc, realm=realm)


def _ot_arp_arrival(ctx, host, ts=None):
    """A new host announcing itself on its segment: RFC 5227 probe + gratuitous announcement."""
    return ctx.arp.probe(host, ts)


def _ot_new_laptop(ctx):
    """Mint a previously-unseen engineering laptop in the Zone-2 supervisory range (a fresh MAC/IP
    the baseline never carried, in .17-.29 -- .10-.16 are the SCADA/HMI/eng hosts). Memoized."""
    cached = getattr(ctx, "_ot_newlaptop", None)
    if cached is not None:
        return cached
    scada = ctx.h.get(H("SCADA1"))
    if scada is None:
        return None
    ip = ".".join(scada.ip.split(".")[:3]) + ".23"
    h = Host(H("ENG-LAPTOP"), ip, "de:ad:be:ef:30:5a", "windows",
             "unknown engineering laptop", scada.subnet, H("ENG-LAPTOP").lower())
    h.hops = scada.hops
    ctx._ot_newlaptop = h
    return h


def _ot_new_pair_settle_arp(ctx, lap, plc, hi, ts=None):
    """Once the laptop's first Modbus session has resolved the PLC's MAC (and the PLC the
    laptop's), keep both neighbour-cache entries fresh for the rest of the incident: a
    dedicated point-to-point OT link is the only traffic either side sees on that pair, so
    neither entry goes stale between polls the way a busy enterprise host's would."""
    far = hi + 300
    ctx.arp.cache[(lap.mac, plc.ipb)] = far
    ctx.arp.cache[(plc.mac, lap.ipb)] = far
    return []


def ndr_ot_new_pair(ctx, eng, tag, win):
    """Newly-seen pair INSIDE OT: an engineering laptop appears in Zone 2 (new MAC/IP in the
    supervisory /24), announces itself by ARP, then polls a PLC it has never talked to (Modbus
    reads, learning the register map low-and-slow) and finally writes a register. The signal is a
    client->PLC pair the baseline never carried, plus the escalation from read to write.
    MITRE: T0842 (new device) / T0855 (unauthorized command). Purdue: laptop Zone 2, PLC Zone 1.
    Dashboard: newly-seen-pairs table, control-writes table."""
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    plcs = _ot_hosts(ctx, H("PLC"))
    lap = _ot_new_laptop(ctx)
    if not plcs or lap is None:
        return
    target = plcs[0]
    s(lo + 20, _ot_arp_arrival, lap)
    # A host joining the segment is not ARP-only: a static-IP engineering laptop still
    # registers its NetBIOS name and sends the usual LLMNR/NBNS chatter.
    s(lo + 23, F.nbns_register, lap)
    s(lo + 30, F.name_noise, lap)
    t = lo + 60
    s(t, F.modbus_poll_block, lap, target, n_polls=rng.randint(2, 5), period=2.0, unit=1)
    s(t + 15, _ot_new_pair_settle_arp, lap, target, hi)
    t += rng.uniform(40, 110)
    while t < hi - 300:
        s(t, F.modbus_poll_block, lap, target, n_polls=rng.randint(2, 5), period=2.0, unit=1)
        t += rng.uniform(40, 110)
    s(hi - 180, F.modbus_setpoint_write, lap, target)


def _ot_egress_beacon(ctx, dev, c2, resolver, resolve_now, ts=None):
    """One low-and-slow egress beacon from a field device: when the previous answer's TTL has
    expired, a DNS A lookup of the (first-seen) C2 domain to the local resolver, then a small
    cleartext HTTP GET to the C2 on :80 with a tiny octet-stream response. A control-zone asset
    resolving or reaching the internet at all is the tell -- the shape is deliberately tiny so a
    bytes view keeps it low-and-slow."""
    out = []
    host = c2.fqdn
    if resolve_now and resolver is not None:
        out += ctx.arp_for(dev, resolver, ts)
        txid = ctx.next_txid()
        sport = dev.eph()
        out.append(ctx.udp(dev, resolver, sport, 53, P.dns_query(txid, host, P.DNS_A), ts))
        out.append(ctx.udp(resolver, dev, 53, sport,
                           P.dns_response(txid, host, P.DNS_A, [(P.DNS_A, c2.ipb)], aa=False, ttl=120),
                           ts + rng.uniform(0.01, 0.05), vantage=dev))
    t = ts + (0.08 if (resolve_now and resolver is not None) else 0.0)
    s = ctx.tcp(dev, c2, 80, t + 0.001).handshake()
    ua = "SyncAgent/1.1 (embedded)"
    s.c2s(P.http_request("GET", "/u/%s" % os.urandom(4).hex(), host, ua, ["Accept: */*"]),
          think=rng.uniform(0.01, 0.1))
    s.s2c(P.http_response("200 OK", P.blob(rng.randint(80, 400)), "application/octet-stream",
                          s.t, server="nginx"), think=rng.uniform(0.05, 0.3))
    return F.merged(ctx.arp_for(dev, c2, t), out, s.close(by_client=True, think=rng.uniform(0.2, 1.0)))


def ndr_ot_field_egress(ctx, eng, tag, win):
    """Egress from a field device: a Zone-1 RTU (or PLC) resolves a first-seen internet domain and
    makes low-and-slow cleartext HTTP requests out to an internet address -- a rogue-firmware /
    implant tell. A control-zone asset has no reason to resolve or reach the internet.
    MITRE: T0883 (internet accessible device) / T1071 (C2). Purdue: device Zone 1 (L1 field).
    Dashboard: egress / allow-list-violation table, bytes-to-external (low-and-slow)."""
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    devs = _ot_hosts(ctx, H("RTU")) or _ot_hosts(ctx, H("PLC"))
    if not devs:
        return
    dev = devs[0]
    c2 = _ext_src(ctx, "203.0.113.70", "fw-sync.rtu-telemetry.example", hops=14)
    resolver = ctx.h.get(H("IDMZ-DNS")) or ctx.h.get(H("OTDC1"))
    answer_ttl = 120    # matches the DNS response's own ttl=120 below
    t = lo + 45
    last_resolve = None
    while t < hi:
        resolve_now = last_resolve is None or (t - last_resolve) >= answer_ttl
        s(t, _ot_egress_beacon, dev, c2, resolver, resolve_now)
        if resolve_now:
            last_resolve = t
        t += rng.uniform(120, 300)


def _ot_sweep_modbus_probe(ctx, src, plc, unit, ts=None, configured_unit=1):
    """One connection, one probe, in a unit-id sweep: the PLC answers normally only for its own
    configured unit id; every other unit id gets a real exception (gateway target device failed
    to respond) -- a device-level difference a sweep can actually learn from, not twelve
    identical reads. Function code varies across probes instead of always FC4."""
    out = ctx.arp_for(src, plc, ts)
    s = ctx.tcp(src, plc, P.MODBUS_PORT, ts + 0.0008).handshake()
    tid = rng.randrange(1, 4096)
    func = rng.choice((P.MB_READ_COILS, P.MB_READ_HOLDING, P.MB_READ_INPUT))
    count = 8 if func == P.MB_READ_COILS else 10
    s.c2s(P.modbus_read_req(tid, unit, func, 0, count), think=rng.uniform(0.001, 0.003))
    if unit == configured_unit:
        s.s2c(P.modbus_read_rsp(tid, unit, func, count), think=rng.uniform(0.001, 0.004))
    else:
        s.s2c(P.modbus_exception(tid, unit, func, P.MB_EX_GATEWAY_FAILED), think=rng.uniform(0.001, 0.004))
    pk = s.close(think=0.001)
    return F.merged(out, pk)


def ndr_ot_protocol_sweep(ctx, eng, tag, win):
    """Short burst / scan inside OT: a Level-3 operations host sweeps Level-1 assets with
    sub-second connections -- Modbus cycling unit IDs across every PLC, then DNP3 probes across the
    RTUs. Each probe is its OWN short-lived connection, so the signal is connection fan-out / churn
    (counted on FLOW_CLASSIFY), not sustained polling -- exactly the traffic a flow-tick headline
    under-counts. Each PLC only answers for its own configured unit id (1); every other id draws
    an exception, so the sweep actually discloses which units exist, not twelve identical polls.
    MITRE: T0842 / T0846 (remote system / information discovery). Purdue: actor Zone 3 (L3 ops)
    -> targets Zone 1 (L1 field). Dashboard: connections / short-burst table."""
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    plcs = _ot_hosts(ctx, H("PLC"))
    rtus = _ot_hosts(ctx, H("RTU"))
    actor = ctx.h.get(H("ENGWS1")) or ctx.h.get(H("OTMON1"))
    if actor is None or not (plcs or rtus):
        return
    t = lo + 30
    for plc in plcs:
        for unit in range(1, 13):
            if t > hi - 90:
                break
            s(t, _ot_sweep_modbus_probe, actor, plc, unit)
            t += rng.uniform(0.05, 0.4)
        if t > hi - 90:
            break
    for rtu in rtus:
        if t > hi - 30:
            break
        s(t, F.dnp3_poll_block, actor, rtu, n_polls=1)
        t += rng.uniform(0.1, 0.5)


def npm_nightly_backup(ctx, eng, tag, win):
    """Opt-in diurnal-shape add-on (NOT a baseline change): a nightly backup window. Several
    Windows servers push bulk SMB backups to EXL-BACKUP1 in a late-evening window, so a by-hour
    bytes view shows the expected nightly spike. Implemented as a scenario because the baseline is
    pinned; a lunch dip cannot be a scenario (a scenario only ADDs), so the additive nightly backup
    is the shape that models cleanly. Dashboard: bytes-by-hour / backup-window view."""
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    bkp = ctx.h.get(H("BACKUP1"))
    if bkp is None:
        return
    srv_pfx = ctx.link.server_prefix
    servers = [h for h in ctx.h.values()
               if h.ipb[:3] == srv_pfx and getattr(h, "ttl", 64) == 128
               and h.name not in (H("SENSOR1"), H("SWB1"), "FW-B", H("BACKUP1"))][:5]
    scale = max(0.02, min(1.0, getattr(ctx, "scale", 1.0)))
    # A backup window: every server starts its job at a staggered time in the first half hour and
    # streams (throttled, one long SMB session) until shortly before the window closes, the rate
    # ramping down to 40 percent; 250 to 400 MB per server at scale 1.0 (about 1.5 GB in all), well
    # above the ordinary day's single 150 MB backup at 18:06. Then a catalog read and a small write.
    for i, srv in enumerate(servers):
        t = lo + i * 1200.0 / max(1, len(servers)) + rng.uniform(0, 240)      # staggered over the first 20 minutes
        end = hi - rng.uniform(120, 1200)
        total = int(rng.uniform(250_000_000, 400_000_000) * scale)
        ramp = 0.4
        avg = total / max(60.0, end - t)
        s(t, F.smb_bulk_transfer, srv, bkp, "Backup", total, direction="write", pace=2 * avg / (1 + ramp), pace_end=ramp)
        s(end + rng.uniform(20, 60), F.smb_bulk_transfer, srv, bkp, "Backup", int(rng.uniform(2e6, 6e6) * scale) + 65536,
          direction="read", files=4)                      # catalog / verify read
        s(end + rng.uniform(90, 150), F.smb_bulk_transfer, srv, bkp, "Backup", int(rng.uniform(2e5, 8e5) * scale) + 65536,
          direction="write", files=1)                     # small catalog write


class Incident:
    def __init__(self, prefix, slug, title, window, builder, note=""):
        self.prefix, self.slug, self.title = prefix, slug, title
        self.window, self.builder, self.note = window, builder, note

    def fault_name(self):
        return f"example-{self.prefix}-{self.slug}.pcap"


def _w(a, b):
    """Window tuple as (hour,min) pairs, resolved at build time via model.local."""
    return (a, b)


REGISTRY = {}


def _reg(name, prefix, slug, title, win_hm, builder, note=""):
    REGISTRY[name] = Incident(prefix, slug, title, win_hm, builder, note)


# NDR — security (attacker = compromised workstation EXL-WS-047)
_reg("ndr-recon", "NDR", "recon", "Internal reconnaissance (host/port sweep, LDAP & share enumeration)",
     ((13, 5), (13, 20)), ndr_recon, "ICMP sweep, SYN scan, LDAP dump, srvsvc share enum from one host")
_reg("ndr-lateral-movement", "NDR", "lateral-movement", "Lateral movement (RDP, SMB admin-share PsExec, WMI)",
     ((13, 30), (13, 55)), ndr_lateral_movement, "workstation->server RDP, ADMIN$ write + svcctl, WMI exec")
_reg("ndr-credential-access", "NDR", "credential-access", "Credential access (Kerberoasting, AS-REP roast, spray, DCSync)",
     ((13, 15), (13, 45)), ndr_credential_access, "RC4-only TGS burst, preauth-less AS-REP, PREAUTH_FAILED spray, DRSUAPI from non-DC")
_reg("ndr-c2-beaconing", "NDR", "c2-beaconing", "C2 beaconing (RMM cloud + low-and-slow HTTPS + ngrok tunnel)",
     ((12, 30), (15, 30)), ndr_c2_beaconing, "first-time RMM connection, jittered 60s beacon, persistent tunnel")
_reg("ndr-dns-tunneling", "NDR", "dns-tunneling", "DNS tunneling (long encoded TXT queries via the resolver)",
     ((13, 40), (14, 20)), ndr_dns_tunneling, "base32 subdomains to an attacker NS, high query volume, TXT payloads")
_reg("ndr-data-exfil", "NDR", "data-exfil", "Data staging & exfiltration (SMB staging then HTTPS upload)",
     ((14, 10), (14, 45)), ndr_data_exfil, "bulk SMB reads then large asymmetric TLS PUT to external storage")
_reg("ndr-scattered-spider", "NDR", "scattered-spider", "Scattered Spider kill chain (recon->creds->lateral->C2->exfil)",
     ((13, 0), (14, 45)), ndr_scattered_spider, "chained campaign correlating every NDR technique")
_reg("ndr-ransomware-encryption", "NDR", "ransomware-encryption", "Ransomware encryption write-storm (SMB in-place encrypt + .ext)",
     ((14, 30), (15, 0)), ndr_ransomware_encryption, "mass SMB read+write-in-place + <name>.akira artifacts + ransom note")
_reg("ndr-cobalt-strike", "NDR", "cobalt-strike", "Cobalt Strike C2 (HTTP jittered beacon + SMB named-pipe P2P)",
     ((13, 0), (15, 0)), ndr_cobalt_strike, "team-server HTTPS beacon with jitter + internal \\PIPE\\msagent_ beacons")
_reg("ndr-akira", "NDR", "akira", "Akira ransomware kill chain (CISA AA24-109A)",
     ((13, 0), (14, 45)), ndr_akira, "RMM/Cloudflare/ngrok C2, Kerberoast/DCSync, RDP/SMB lateral, rclone exfil, .akira encryption")
_reg("ndr-medusa", "NDR", "medusa", "Medusa ransomware kill chain (CISA AA25-071A)",
     ((13, 0), (14, 45)), ndr_medusa, "scan + PsExec/WMI/RDP lateral, Cloudflared/Ligolo tunnel C2, exfil, .medusa encryption")
_reg("ndr-black-basta", "NDR", "black-basta", "Black Basta ransomware kill chain (CISA AA24-131A)",
     ((13, 0), (14, 45)), ndr_black_basta, "Cobalt Strike HTTP+SMB-pipe C2, lateral, exfil, .basta encryption")
_reg("ndr-play", "NDR", "play", "Play ransomware kill chain (CISA AA23-352A)",
     ((13, 0), (14, 45)), ndr_play, "Cobalt Strike C2 (the advisory also documents SystemBC; not generated here), SMB/RDP lateral, exfil, .play encryption")
_reg("ndr-handala", "NDR", "handala", "Handala / Void Manticore (network-observable subset: theft + share wiper)",
     ((13, 0), (14, 45)), ndr_handala, "Telegram/HTTPS C2 + icanhazip, data theft, SMB share overwrite-wiper (no encryption)")

_reg("ndr-needymantis", "NDR", "needymantis", "NeedyMantis implant (separate foothold: fixed-UA HTTPS beacon + Impacket SMB exec)",
     ((9, 10), (17, 30)), ndr_needymantis, "second, unrelated compromise; firefox/21.0 agent on /library/zip/, disjoint targets")
_reg("ndr-fastflux", "NDR", "fastflux", "Fast-flux / DGA C2 (algorithmic NXDOMAIN bursts, rotating A records)",
     ((8, 30), (18, 0)), ndr_fastflux, "beachhead EXL-WS-009 resolves DGA domains to rotating flux nodes, then beacons")
_reg("ndr-infostealer", "NDR", "infostealer", "Infostealer exfiltration (Lumma-class credential upload to a panel)",
     ((8, 5), (10, 0)), ndr_infostealer, "commodity stealer on EXL-WS-061 uploads a credential archive; stage 0 of the LOTL stream")
_reg("ndr-rdp-brute", "NDR", "rdp-brute", "Exposed-RDP brute force (internet \u2192 jump host, failures then a success)",
     ((7, 50), (9, 0)), ndr_rdp_brute, "external brute of EXL-MGMT1 over 3389; many RST'd attempts then one full session")
_reg("ndr-salt-typhoon", "NDR", "salt-typhoon", "Salt Typhoon network-device espionage (SNMP walks of switches/APs/sensor)",
     ((8, 40), (16, 40)), ndr_salt_typhoon, "collector EXL-WS-061 walks network infrastructure via SNMP, long and slow")
_reg("ndr-webshell", "NDR", "webshell", "Web shell on an internal server (POSTs to an odd URI, decrypted commands)",
     ((9, 30), (16, 0)), ndr_webshell, "operator EXL-WS-023 drives a web shell on EXL-WEB2; command in POST, output in response")
_reg("ndr-volt-typhoon", "NDR", "volt-typhoon", "Volt Typhoon living-off-the-land (valid-account admin protocols, no malware)",
     ((7, 40), (20, 30)), ndr_volt_typhoon, "beachhead EXL-WS-009 quietly uses LDAP/SMB/RDP to servers; the detection is the baseline deviation")
_reg("ndr-coercion-adcs", "NDR", "coercion-adcs", "Coercion \u2192 NTLM relay \u2192 AD CS \u2192 DA (ESC8)",
     ((10, 0), (14, 0)), ndr_coercion_adcs, "relay EXL-WS-023 coerces a machine account (MS-EFSR), relays to the CA, gets a cert, then a TGT")
_reg("ndr-edge-exploit", "NDR", "edge-exploit", "Edge-device exploitation \u2192 inward pivot (compromised VPN/firewall)",
     ((7, 30), (9, 30)), ndr_edge_exploit, "inbound VPN exploit, then the edge device originates admin protocols inward and the beachhead beacons out")
# ---- NPM: firewall content-update event (Palo Alto) -----------------------------------------
# NPM is about network PERFORMANCE, and being able to see WHEN and IF a firewall updated is a
# valid performance-monitoring use case: change correlation (did metrics move after the update?)
# and maintenance verification (did the scheduled update actually complete?). This emits ONE
# fully observable, timestamped update event that completes with a commit. It also identifies
# the firewall as a Palo Alto device, since the traffic goes to paloaltonetworks.com.
FW_UPDATE_VENDOR = "updates.paloaltonetworks.com"
FW_UPDATE_DL     = "downloads.paloaltonetworks.com"
# Two separated legs, aligned to the ndr-edge-exploit clock so the capture reads as "the update
# stopped the compromise" with NO code dependency between the two modules:
#   06:15  jump host pre-positions the content bundle (before the business day)
#   07:30  firewall compromised (ndr-edge-exploit, unchanged) -> inward pivot observed until ~09:30
#   09:29  admin pushes, AFTER the pivot has been plainly visible for ~2 h
#   ~09:30:30  commit completes + brief dataplane-reload blip. The push is at 09:29 (not later)
#          precisely so the ~90 s commit lands just PAST edge-exploit's 09:30 pivot hard-stop:
#          the last inward touch always precedes the commit, so the capture reads as "the update
#          stopped it" with no inward pivot after the commit -- emergent, not enforced in code.
FW_DOWNLOAD_AT   = (6, 15)          # leg 1: pull the bundle early
FW_PUSH_AT       = (9, 29)          # leg 2: push (commit completes ~09:30:30, just past the pivot)
FW_COMMIT_SECS   = (80, 100)        # PAN-OS commit duration; the dataplane reloads near the end
# Vendor IPs (GCP-fronted content infrastructure). The SNI is what names Palo Alto on the wire;
# the server IP/OS is incidental. These are NOT in model.UPDATE_HOSTS on purpose: adding hosts
# there feeds model.INTERNET and the per-host MAC/hops draws reseed the whole day, moving the
# pinned --no-modules baseline (A/B proven: ~124k-packet drop, 574,056 -> 450,356 at the
# pre-2026-10-02 pin; the pin is now 609,554). Minting them here keeps the
# baseline byte-for-byte, because this builder only runs when the scenario is selected.
_FW_VENDOR_IPS = {FW_UPDATE_VENDOR: "34.107.151.202", FW_UPDATE_DL: "34.120.160.131"}


def _fw_vendor_site(ctx, name):
    """An ad-hoc internet site for the vendor host, built with fixed MAC/hops so nothing is
    drawn from the shared RNG at baseline-construction time. Memoized per run so the host keeps
    a single ipid/port stream. Returns the (name, Host) tuple F.https_session expects."""
    from .core import Host
    cache = getattr(ctx, "_fw_vendor_sites", None)
    if cache is None:
        cache = ctx._fw_vendor_sites = {}
    if name not in cache:
        ip = _FW_VENDOR_IPS[name]
        # fixed MAC derived from the IP (deterministic, no rng), internet-host profile
        octets = [int(x) for x in ip.split(".")]
        mac = "02:00:00:%02x:%02x:%02x" % (octets[1], octets[2], octets[3])
        h = Host(name.upper(), ip, mac, "linux", "internet host", "198.51.100.0/24", name)
        h.hops = 13
        cache[name] = (name, h)
    return cache[name]


def _split3(total):
    """Three download objects that sum to `total` bytes (about 0.5 to 0.8 MB each)."""
    a = int(total * rng.uniform(0.28, 0.38))
    b = int(total * rng.uniform(0.28, 0.38))
    return [a, b, total - a - b]


def fw_update_download(ctx, mgmt, ts):
    """Leg 1 (early, pre-business): the jump host checks the vendor for a new content version and
    pulls the PAN-OS bundle. Pre-positioned long before it is applied -- WHEN the content arrived."""
    ua = "PanOS-ContentUpdate/10.2"
    out = []
    # metadata: is there a new content version? (HTTPS to the vendor update service)
    out += F.https_session(ctx, mgmt, _fw_vendor_site(ctx, FW_UPDATE_VENDOR), ts, requests=2, sizes=[600, 1400],
                           keep_open=0.5, rate=50e6, ua=ua,
                           paths=["/api/content/version", "/api/content/manifest"])
    # download the content bundle from the delivery host (sizable, the performance leg)
    out += F.https_session(ctx, mgmt, _fw_vendor_site(ctx, FW_UPDATE_DL), ts + 8, requests=3,
                           sizes=_split3(rng.randint(1_800_000, 2_000_000)),
                           keep_open=1.0, rate=30e6, ua=ua,
                           paths=["/content/panupv2-all-contents"] * 3)
    return F.merged(out)


def fw_update_push(ctx, mgmt, ts):
    """Leg 2 (late, after the inward pivot is visible): the admin pushes the pre-staged bundle to
    the firewall mgmt API and commits. The commit takes ~90 s (PAN-OS), and the success response
    is the IF-completed signal. The dataplane reload near the end of the commit is the blip."""
    from .tls import TlsSession
    fw = ctx.h.get("FW-B")
    if fw is None:
        return []
    o2 = ctx.arp_for(mgmt, fw, ts)
    sx = ctx.tcp(mgmt, fw, 443, ts + 0.001).handshake()
    tls = TlsSession(ctx.pki, ("fw." + get_current().domain), ctx.keylog, profile="winhttp")
    for from_c, data in tls.handshake():
        (sx.c2s if from_c else sx.s2c)(data, think=rng.uniform(0.001, 0.005))
    bnd = "------------------------%016x" % rng.getrandbits(64)
    mp = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"panupv2-all-contents-8812-9000\"\r\n"
          "Content-Type: application/octet-stream\r\n\r\n" % bnd).encode() + P.blob(rng.randint(300_000, 800_000)) + ("\r\n--%s--\r\n" % bnd).encode()
    up = P.http_request("POST", "/api/?type=import&category=content", ("fw." + get_current().domain),
                        "curl/8.4.0", ["Content-Type: multipart/form-data; boundary=%s" % bnd], mp)
    sx.c2s(tls.app_data(True, up), think=0.01)
    sx.s2c(tls.app_data(False, P.http_response("200 OK", b"<response status='success'><result>content imported</result></response>",
           "application/xml", sx.t, server="PanWeb")), think=0.05)
    from urllib.parse import quote
    # the install is a job: the API answers at once with a job id, then the client polls `show jobs`
    # every 5 to 10 s until the job is FIN (the dataplane reload sits near the end of the job)
    api = lambda cmd: "/api/?type=op&cmd=" + quote(cmd, safe="")
    job = rng.randint(2000, 9000)
    sx.c2s(tls.app_data(True, P.http_request("GET", api("<request><content><upgrade><install><version>latest</version></install></upgrade></content></request>"),
                                             ("fw." + get_current().domain), "curl/8.4.0")), think=0.02)
    sx.s2c(tls.app_data(False, P.http_response("200 OK",
           b"<response status='success' code='19'><result><msg><line>Content install job enqueued with jobid %d</line></msg><job>%d</job></result></response>" % (job, job),
           "application/xml", sx.t, server="PanWeb")), think=0.08)
    total = rng.uniform(86, 91)
    t_end = sx.t + total
    poll = api("<show><jobs><id>%d</id></jobs></show>" % job)
    while True:
        wait = rng.uniform(5, 10)
        last = sx.t + wait + 0.1 >= t_end - 0.01 or (t_end - sx.t - wait) < 5
        if last:
            wait = max(1.0, t_end - sx.t - 0.1)
        sx.c2s(tls.app_data(True, P.http_request("GET", poll, ("fw." + get_current().domain), "curl/8.4.0")), think=wait)
        pct = min(99, int(100 * (1 - (t_end - sx.t) / total)))
        if last:
            res = (b"<response status='success'><result><job><id>%d</id><type>ContentInstall</type><status>FIN</status><result>OK</result>"
                   b"<progress>100</progress><details><line>content version 8812-9000 installed</line></details></job></result></response>" % job)
        else:
            res = (b"<response status='success'><result><job><id>%d</id><type>ContentInstall</type><status>ACT</status><result>PEND</result>"
                   b"<progress>%d</progress></job></result></response>" % (job, pct))
        sx.s2c(tls.app_data(False, P.http_response("200 OK", res, "application/xml", sx.t, server="PanWeb")), think=rng.uniform(0.02, 0.08))
        if last:
            break
    return F.merged(o2, sx.close(think=0.01))


# ---- Remote-access workforce (VPN users terminating on the Palo Alto gateway) ----------------
# The REAL blip is here, and it is EXTERNAL, not internal. The firewall IS the VPN concentrator,
# so when its dataplane reloads after the commit every remote worker drops at once. On the wire
# that is a clean, easy-to-see cliff: the number of requests ANSWERED by the server-subnet auth
# (KDC), database (TDS) and web (HTTPS) servers falls to the remote-worker floor for the whole
# outage, then a reconnect storm spikes it as everyone re-authenticates and re-establishes.
# This traffic exists ONLY when npm-fw-update is selected, so the pinned --no-modules baseline is
# untouched. Workers are external hosts built directly (never ext()), so they are not indicators.
RA_IP0   = "192.0.2."            # TEST-NET-1: distinct from the internet range AND the attackers
RA_COUNT = 24                    # remote workforce size (drives how big the cliff is)
RA_AUTH, RA_DB, RA_WEB = H("DC1"), H("SQL1"), H("WEB2")
RA_OUTAGE_SECS = (90, 180)       # the firmware commit reloads the dataplane; the VPN is down this long
RA_WAN_RTT = (0.020, 0.080)      # remote workers are many hops out: a realistic WAN round-trip


def _ra_worker(ctx, i):
    """One remote worker as an external host, built directly (deterministic MAC from the IP, no
    rng) so used_indicator_ips() never sees it and the baseline construction is never perturbed."""
    cache = ctx.__dict__.setdefault("_ra_pool", {})
    if i not in cache:
        ip = RA_IP0 + str(149 + i)
        o = [int(x) for x in ip.split(".")]
        h = Host("RA-USER-%02d" % i, ip, "02:00:5e:%02x:%02x:%02x" % (o[1], o[2], o[3]),
                 "windows", "external", RA_IP0 + "0/24", "ra-user-%02d.vpn.%s.local" % (i, get_current().slug))
        h.hops = 7
        cache[i] = h
    return cache[i]


def _ra_tcp(ctx, worker, server, dport, ts):
    """An inbound TCP session from a remote worker to an internal server: framed vantage=server
    and transiting the firewall (like every other inbound-from-internet flow in this engine), with
    a realistic WAN RTT so the remote clients also read as higher-latency than the LAN."""
    return ctx.tcp(worker, server, dport, ts, vantage=server, rtt=rng.uniform(*RA_WAN_RTT))


def _ra_kerberos(ctx, worker, i, ts):
    dc = ctx.h.get(RA_AUTH)
    if dc is None:
        return []
    out = ctx.arp_for(worker, dc, ts, vantage=dc)
    s = _ra_tcp(ctx, worker, dc, 88, ts + 0.001).handshake()
    u = "rwkr%02d" % i
    s.c2s(F._tcp_len(P.krb_as_req(u, ts, rng.getrandbits(31), True)), think=0.002)
    s.s2c(F._tcp_len(P.krb_as_rep(u)), think=rng.uniform(0.003, 0.02))
    return F.merged(out, s.close(think=0.002))


def _ra_tds(ctx, worker, ts):
    sql = ctx.h.get(RA_DB)
    if sql is None:
        return []
    out = ctx.arp_for(worker, sql, ts, vantage=sql)
    s = _ra_tcp(ctx, worker, sql, 1433, ts + 0.001).handshake()
    s.c2s(P.tds_prelogin(True), think=0.0004)
    s.s2c(P.tds_prelogin(False), think=rng.uniform(0.0005, 0.002))
    s.c2s(P.tds_login7("rwkr"), think=0.0006)
    s.s2c(P.tds_login_ack(), think=rng.uniform(0.001, 0.004))
    s.c2s(P.tds_sql_batch("SELECT TOP 20 ref, status FROM dbo.Shipments WHERE status='open'"), think=0.001)
    rows = [(rng.randint(1000, 9999), "SH%03d" % rng.randint(1, 999)) for _ in range(3)]
    s.s2c(P.tds_split(0x04, P.tds_result([("ref", "int"), ("status", "nvarchar")], rows), 60),
          think=rng.uniform(0.002, 0.02))
    return F.merged(out, s.close(think=0.001))


def _ra_https(ctx, worker, ts):
    web = ctx.h.get(RA_WEB)
    if web is None:
        return []
    from .tls import TlsSession
    out = ctx.arp_for(worker, web, ts, vantage=web)
    s = _ra_tcp(ctx, worker, web, 443, ts + 0.001).handshake()
    tls = TlsSession(ctx.pki, web.fqdn, ctx.keylog, profile="chrome")
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.002, 0.01))
    login = P.http_request("POST", "/sso/login", web.fqdn, P.UAS[0],
                           ["Content-Type: application/x-www-form-urlencoded"], b"user=rwkr&sso=saml")
    s.c2s(tls.app_data(True, login), think=0.01)
    s.s2c(tls.app_data(False, P.http_response("200 OK", P.blob(1200), "text/html", s.t, server="nginx/1.26.2")),
          think=rng.uniform(0.02, 0.1))
    for path in ("/app/dashboard", "/app/api/orders"):
        s.c2s(tls.app_data(True, P.http_request("GET", path, web.fqdn, P.UAS[0])), think=rng.uniform(0.2, 1.0))
        s.s2c(tls.app_data(False, P.http_response("200 OK", P.blob(rng.randint(2000, 9000)),
              "application/json", s.t, server="nginx/1.26.2")), think=rng.uniform(0.02, 0.1))
    return F.merged(out, s.close(think=0.01))


def _ra_tun(ctx, i):
    return ctx.__dict__.setdefault("_ra_tun", {}).setdefault(i, {})


def ra_tunnel_up(ctx, i, ts):
    """IKEv2 NAT-T tunnel from remote worker i to the firewall (the VPN gateway): IKE_SA_INIT on
    udp/500, IKE_AUTH on udp/4500, then ESP-in-UDP. New SPIs on every (re-)establishment."""
    fw = ctx.h.get("FW-B")
    if fw is None:
        return []
    w = _ra_worker(ctx, i)
    st = _ra_tun(ctx, i)
    st.update(ispi=bytes(rng.getrandbits(8) for _ in range(8)), rspi=bytes(rng.getrandbits(8) for _ in range(8)),
              spi_out=bytes(rng.getrandbits(8) for _ in range(4)), spi_in=bytes(rng.getrandbits(8) for _ in range(4)),
              seq_out=0, seq_in=0, msgid=2, sport=w.eph())
    out = ctx.arp_for(w, fw, ts, vantage=fw)
    rtt = rng.uniform(*RA_WAN_RTT)
    u = lambda a, b, sp, dp, pl, t: ctx.udp(a, b, sp, dp, pl, t, vantage=fw)
    zero = b"\x00\x00\x00\x00"
    _sport = st["sport"]
    out.append(u(w, fw, 500, 500, P.ike_sa_init(st["ispi"], b"\x00" * 8, True), ts))
    out.append(u(fw, w, 500, 500, P.ike_sa_init(st["ispi"], st["rspi"], False), ts + rtt))
    t = ts + rtt + rng.uniform(0.004, 0.02)
    out.append(u(w, fw, 4500, 4500, zero + P.ike_encrypted(st["ispi"], st["rspi"], 35, 1, True, rng.randint(180, 260)), t))
    out.append(u(fw, w, 4500, 4500, zero + P.ike_encrypted(st["ispi"], st["rspi"], 35, 1, False, rng.randint(120, 200)), t + rtt + rng.uniform(0.01, 0.06)))
    return F.merged(out)


def ra_tunnel_esp(ctx, i, ts, n=None):
    """A burst of ESP-in-UDP data both ways (inner traffic of the worker's activity)."""
    fw = ctx.h.get("FW-B")
    st = _ra_tun(ctx, i)
    if fw is None or not st:
        return []
    w = _ra_worker(ctx, i)
    out = []
    t = ts
    for _ in range(n or rng.randint(14, 40)):
        t += rng.uniform(0.002, 0.04)
        if rng.random() < 0.45:
            st["seq_out"] += 1
            out.append(ctx.udp(w, fw, 4500, 4500, P.esp_in_udp(st["spi_out"], st["seq_out"], rng.choice((84, 132, 276, 612, 1148))), t, vantage=fw))
        else:
            st["seq_in"] += 1
            out.append(ctx.udp(fw, w, 4500, 4500, P.esp_in_udp(st["spi_in"], st["seq_in"], rng.choice((84, 132, 276, 1148, 1348))), t, vantage=fw))
    return F.merged(out)


def ra_nat_keepalive(ctx, i, ts):
    fw = ctx.h.get("FW-B")
    if fw is None or not _ra_tun(ctx, i):
        return []
    return F.merged([ctx.udp(_ra_worker(ctx, i), fw, 4500, 4500, b"\xff", ts, vantage=fw)])


def ra_tunnel_dpd(ctx, i, ts):
    """Dead-peer detection against a gateway that no longer answers: an empty INFORMATIONAL
    request, retransmitted with backoff (4, 7, 13, 25 s) and never answered."""
    fw = ctx.h.get("FW-B")
    st = _ra_tun(ctx, i)
    if fw is None or not st:
        return []
    w = _ra_worker(ctx, i)
    msg = b"\x00\x00\x00\x00" + P.ike_encrypted(st["ispi"], st["rspi"], 37, st["msgid"], True, 0, inner_first=0)
    out, t = [], ts
    for gap in (0, 4, 7, 13, 25):
        t += gap
        out.append(ctx.udp(w, fw, 4500, 4500, msg, t, vantage=fw))
    st["msgid"] += 1
    return F.merged(out)


def ra_activity(ctx, i, ts):
    """One remote worker's unit of work: authenticate at the KDC, query the database, use the web
    app. The three internal servers each answer a request -- which is exactly what stops during
    the outage and resumes in the reconnect storm."""
    worker = _ra_worker(ctx, i)
    out = []
    out += _ra_kerberos(ctx, worker, i, ts)
    out += _ra_tds(ctx, worker, ts + rng.uniform(0.2, 0.6))
    out += _ra_https(ctx, worker, ts + rng.uniform(0.6, 1.4))
    out += ra_tunnel_esp(ctx, i, ts)
    return F.merged(out)


def npm_fw_update(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    mgmt = ctx.h.get(H('MGMT1'))
    if mgmt is None:
        return
    from .model import local
    lo, hi = win
    # leg 1: download early, pre-positioned before the business day
    D = lo - local(*REGISTRY["npm-fw-update"].window[0])      # the legs move with the window
    dl = local(*FW_DOWNLOAD_AT) + D
    if not (lo <= dl <= hi):
        dl = lo + 900
    s(dl, fw_update_download, mgmt)
    # leg 2: push; the ~90 s commit lands just past edge-exploit's 09:30 pivot hard-stop
    pu = local(*FW_PUSH_AT) + D
    if not (lo <= pu <= hi):
        pu = hi - 3600
    s(pu, fw_update_push, mgmt)
    # ---- the blip: the remote-access workforce outage, aligned to the commit ----
    commit_done = pu + 91                       # when the dataplane reload completes (see FW_COMMIT_SECS)
    outage = rng.uniform(*RA_OUTAGE_SECS)
    reboot_start, reboot_end = commit_done, commit_done + outage
    online = lo + 300                           # the workforce is online shortly after the window opens
    for i in range(1, RA_COUNT + 1):
        # steady state BEFORE the outage
        t = online + rng.uniform(0, 240)        # stagger the morning logins
        s(t - 2, ra_tunnel_up, i)               # the IPsec tunnel to the firewall comes up first
        k = t
        while k < reboot_start:                 # NAT keepalive every 20 s while the gateway is there
            s(k, ra_nat_keepalive, i)
            k += 20 + rng.uniform(-1, 1)
        s(reboot_start + rng.uniform(3, 15), ra_tunnel_dpd, i)     # then dead-peer detection gets no answer
        s(reboot_end + rng.uniform(0.0, 0.4), ra_tunnel_up, i)     # the tunnel is rebuilt before the storm
        k = reboot_end + 1
        while k < hi - 60:
            s(k, ra_nat_keepalive, i)
            k += 20 + rng.uniform(-1, 1)
        while t < reboot_start - 5:
            s(t, ra_activity, i)
            t += rng.uniform(90, 210)
        # NOTHING is scheduled in [reboot_start, reboot_end): the VPN is down, every request stops
        # the reconnect STORM: everyone re-establishes within ~20 s of the firewall returning
        s(reboot_end + rng.uniform(0.5, 20), ra_activity, i)
        # steady state resumes after recovery
        t = reboot_end + rng.uniform(25, 150)
        while t < hi - 60:
            s(t, ra_activity, i)
            t += rng.uniform(90, 210)


# ---- NPM: post-quantum key-exchange posture ------------------------------------------------
# A metadata-only TLS 1.3 posture scenario, scenario-only so the pinned baseline is untouched and
# the TLS 1.2 RSA decryption demo is unaffected. It emits handshakes whose cleartext key-exchange
# fields populate exactly what the platform reads (confirmed against a reference sensor): the client's
# supported_groups are the per-client "capable" signal, and the server's selected key_share
# group is the per-session "using" signal. Three populations, so a dashboard shows capable /
# using / not-capable per host:
PQC_GROUP       = 0x11ec                       # X25519MLKEM768 (the deployed hybrid)
PQC_OFFER       = [0x11ec, 0x001d, 0x0017]     # capable client: PQC first, classical fallback
PQC_CLASSIC     = [0x001d, 0x0017]             # not-capable client: no PQC group offered
PQC_MODERN      = [H("WS-003"), H("WS-014"), H("WS-025"), H("WS-036"), H("MAC-001")]  # capable
PQC_LEGACY      = ["EXL-SB-01", "EXL-SB-02", "EXL-SB-03", "EXL-SB-04", "EXL-OTJUMP1"]      # not capable
PQC_READY_SRV   = [H("WEB1"), H("WEB2")]     # servers configured for PQC (will select 0x11ec)
PQC_LEGACY_SRV  = [H("SQL1"), H("FILE1")]    # servers not yet PQC (always classical)


def pqc_session(ctx, client, server, offer, select, ts=None, profile=None):
    """One TLS 1.3 posture handshake, framed client -> internal server over 443. `offer` is the
    client's supported_groups; `select` is the group the server echoes (PQC iff hybrid)."""
    from .tls import tls13_posture, tls13_app_data
    out = ctx.arp_for(client, server, ts)
    sx = ctx.tcp(client, server, 443, ts + 0.001).handshake()
    for from_c, data in tls13_posture(server.fqdn, offer, select, profile=profile):
        (sx.c2s if from_c else sx.s2c)(data, think=rng.uniform(0.002, 0.01))
    # a little opaque application data each way, then close
    sx.c2s(tls13_app_data(True, rng.randint(200, 500)), think=rng.uniform(0.01, 0.05))
    sx.s2c(tls13_app_data(False, rng.randint(800, 4000)), think=rng.uniform(0.02, 0.08))
    return F.merged(out, sx.close(think=0.01))


PQC_PROFILE = {"EXL-WS-003": "chrome", "EXL-WS-014": "firefox", "EXL-WS-025": "chrome", "EXL-WS-036": "chrome",
               "EXL-MAC-001": "safari", "EXL-SB-01": "appliance", "EXL-SB-02": "agent", "EXL-SB-03": "appliance",
               "EXL-SB-04": "agent", "EXL-OTJUMP1": "agent"}


def npm_pqc(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    modern = [ctx.h[n] for n in PQC_MODERN if n in ctx.h]
    legacy = [ctx.h[n] for n in PQC_LEGACY if n in ctx.h]
    pqcsrv = [ctx.h[n] for n in PQC_READY_SRV if n in ctx.h]
    oldsrv = [ctx.h[n] for n in PQC_LEGACY_SRV if n in ctx.h]
    jobs = []
    for _ in range(3):                             # three sessions per client and server across the hour
        for cl in modern:
            for sv in pqcsrv:                      # capable client + PQC server = USING
                jobs.append((cl, sv, PQC_OFFER, PQC_GROUP))
            for sv in oldsrv:                      # capable client + legacy server = CAPABLE, not using
                jobs.append((cl, sv, PQC_OFFER, 0x001d))
        for cl in legacy:
            for sv in (pqcsrv + oldsrv):           # not-capable client: never offers PQC
                jobs.append((cl, sv, PQC_CLASSIC, 0x001d))
    for cl, sv, offer, sel in jobs:
        s(rng.uniform(lo + 60, hi - 60), pqc_session, cl, sv, offer, sel, profile=PQC_PROFILE.get(cl.name))


# ============================================================================================
# Additional NPM scenarios (built 2026-10-02): richer network-observability demos. Each is
# scenario-only and follows the sev()-scaled healthy->degrade->recover shape. Several exercise the
# Phase-3 SMTP / NFS / RADIUS builders so those protocols get first-class NPM scenarios.
# ============================================================================================

def npm_http_errors(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    pre, post = flanks(lo, hi)
    for t in pre + post:
        s(t, http_err_page, rng.choice(users), g=0.0)
    t = lo
    while t < hi:
        s(t, http_err_page, rng.choice(users), g=sev(t, win))
        t += rng.expovariate(1 / 4.0)


def http_err_page(ctx, client, ts, g=1.0):
    """The LOB API on EXL-WEB2 starts returning 5xx. Server processing time stays low (it fails
    fast), so the signal is the status-code mix, not latency -- the easiest NPM read there is."""
    web = ctx.h[H('WEB2')]
    host = ("shipping." + get_current().domain)
    ua = P.UAS[0] if ctx.is_windows(client) else P.UAS[2]
    out = ctx.arp_for(client, web, ts)
    dep = []
    sx = ctx.tcp(client, web, 80, ts + 0.001).handshake()
    for _i in range(rng.randint(2, 5)):
        path = rng.choice(["/api/orders", "/api/track", "/api/rate", "/dispatch", "/labels"])
        sx.c2s(P.http_request("GET", path, host, ua), think=rng.uniform(0.01, 0.2))
        if rng.random() < 0.65 * g:
            code = rng.choice(["500 Internal Server Error", "503 Service Unavailable", "502 Bad Gateway"])
            if not code.startswith("500"):
                # the 502/503 has a visible cause (NPM-12 brief fix 1): the app's own call to its
                # database fails first -- 503 when the connect is refused, 502 when SQL1 accepts the
                # connection but rejects the login. A 500 is an application fault and stays local.
                sql1 = ctx.h[H('SQL1')]
                tb = sx.t + rng.uniform(0.001, 0.004)
                dep.extend(ctx.arp_for(web, sql1, tb))
                sd = ctx.tcp(web, sql1, 1433, tb + 0.001)
                if code.startswith("503"):
                    dep.extend(sd.refused())
                else:
                    sd.handshake()
                    sd.c2s(P.tds_prelogin(True), think=0.0004)
                    sd.s2c(P.tds_prelogin(False), think=rng.uniform(0.0005, 0.002))
                    sd.c2s(P.tds_login7("svc_shipping", app="ShippingApi", host=web.name), think=rng.uniform(0.0006, 0.002))
                    spid = rng.randint(50, 120)
                    sd.s2c(P.tds_split(0x04, P.tds_error(18456, "Login failed for user 'svc_shipping'. Reason: Failed to open the explicitly specified database.", severity=14, state=38, spid=spid), spid),
                           think=rng.uniform(0.001, 0.004))
                    dep.extend(sd.close(by_client=False, think=rng.uniform(0.001, 0.01)))
                sx.t = max(sx.t, sd.t)
            sx.s2c(P.http_response(code, b"<h1>Backend error</h1>", "text/html", sx.t,
                                   server="Microsoft-IIS/10.0", headers=["Retry-After: 2"]),
                   think=rng.uniform(0.01, 0.08))
        else:
            sx.s2c(P.http_response("200 OK", P.blob(rng.randint(800, 6000)), "application/json", sx.t,
                                   server="Microsoft-IIS/10.0"), think=rng.uniform(0.02, 0.15))
    return F.merged(out, dep, sx.close(think=rng.uniform(0.2, 2.0)))


def npm_dhcp_exhaustion(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    # THE CAUSE (post-compromise, not an admin): the Volt Typhoon beachhead EXL-WS-009 RDPs into
    # EXL-DC1 using valid stolen credentials and narrows the DHCP scope, starving the pool. The
    # anomaly the platform surfaces is the SOURCE -- a user workstation originating RDP to the domain
    # controller, an admin protocol it never uses normally. ndr-volt-typhoon is auto-selected with
    # this scenario (SCENARIO_DEPENDENCIES) so the beachhead's wider LOTL activity is in the capture.
    beach, dc1 = ctx.h.get(C_BEACHHEAD), ctx.h.get(H("DC1"))
    if beach is not None and dc1 is not None:
        t_admin = lo + rng.uniform(5, 25)
        eng.schedule(t_admin, (lambda a=beach, r=dc1, t=t_admin, d=rng.uniform(90, 200): F.rdp_session(ctx, a, r, t, d)), tag)  # noqa: B008 draw order is pinned
    pre, post = flanks(lo, hi)
    for t in pre + post:
        s(t, dhcp_lease_attempt, rng.choice(users), g=0.0)
    t = lo
    while t < hi:
        s(t, dhcp_lease_attempt, rng.choice(users), g=sev(t, win))
        t += rng.expovariate(1 / 3.0)


def dhcp_lease_attempt(ctx, client, ts, g=1.0):
    """DHCP scope exhaustion on EXL-DC1, dissecting as RFC 2131: the client broadcasts (0.0.0.0 to
    255.255.255.255, B flag as its OS sets it), the firewall relays to the server (giaddr set, udp
    67 to 67) and relays the reply back. Healthy: a normal DORA. Pool empty: DISCOVERs get no OFFER
    (a server with no free address sends none) and the client retries with a growing `secs`, same
    xid, at roughly 0, 4, 8, 16, 32 s. Changed scope: an INIT-REBOOT REQUEST for the old address is
    answered with a NAK (message type, server id and a text only, RFC 2131 4.3.1), after which the
    client starts discovery again and gets no OFFER."""
    from .core import udp_bcast, udp_frame, BCAST
    dc1, dc2 = ctx.h[H('DC1')], ctx.h[H('DC2')]
    fw = ctx.link.gateway_for(client)
    win_os = ctx.is_windows(client)
    bflag = 0x8000 if win_os else 0
    sopts = P.dhcp_server_opts(dc1.ipb, fw.ipb, [dc1.ipb, dc2.ipb])
    out = []

    def to_client(msg, broadcast):
        if broadcast:
            return udp_bcast(fw, 67, 68, msg, dst_ip=b"\xff\xff\xff\xff", dst_mac=BCAST, src_ip=fw.ipb)
        return udp_frame(ctx.link, fw, client, 67, 68, msg, client)

    def exchange(t, mk_client, mk_server=None, nak=False):
        """client broadcast -> relay -> server (-> relay -> client). Returns the time after the last frame."""
        out.append((t, udp_bcast(client, 68, 67, mk_client(), src_ip=b"\x00\x00\x00\x00")))
        tf = t + rng.uniform(0.0002, 0.001)
        out.append(ctx.udp(fw, dc1, 67, 67, mk_client(giaddr=fw.ipb, hops=1), tf))
        if mk_server is None:
            return tf
        ts_ = tf + rng.uniform(0.003, 0.015)
        out.append(ctx.udp(dc1, fw, 67, 67, mk_server(), ts_))
        tc = ts_ + rng.uniform(0.0002, 0.001)
        out.append((tc, to_client(mk_server(), broadcast=nak or bool(bflag))))
        return tc

    def discover(xid, secs=0):
        return lambda giaddr=b"\x00" * 4, hops=0: P.dhcp(1, xid, client.mac, 1, giaddr=giaddr, hops=hops, secs=secs, flags=bflag,
                                                         options=P.dhcp_client_opts(client.name, client.mac, win_os))

    def silent_discovers(t0, xid, n):
        """the same DISCOVER (same xid) at 0, 4, 8, 16, 32 s, each +/-1 s, secs counting up"""
        base = (0, 4, 8, 16, 32)
        for k in range(n):
            tk = t0 + (0 if k == 0 else base[k] + rng.uniform(-1.0, 1.0))
            exchange(tk, discover(xid, secs=int(tk - t0)))

    xid = rng.getrandbits(32)
    r = rng.random()
    if g < 0.15:
        t = exchange(ts, discover(xid), lambda: P.dhcp(2, xid, client.mac, 2, yiaddr=client.ipb, siaddr=dc1.ipb, giaddr=fw.ipb, options=sopts, flags=bflag))
        copts = P.dhcp_client_opts(client.name, client.mac, win_os, req_ip=client.ipb, server_id=dc1.ipb)
        t += rng.uniform(0.001, 0.01)
        exchange(t, lambda giaddr=b"\x00" * 4, hops=0: P.dhcp(1, xid, client.mac, 3, giaddr=giaddr, hops=hops, options=copts, flags=bflag),
                 lambda: P.dhcp(2, xid, client.mac, 5, yiaddr=client.ipb, siaddr=dc1.ipb, giaddr=fw.ipb, options=sopts, flags=bflag))
    elif r < 0.5 * g + 0.1:
        silent_discovers(ts, xid, rng.randint(3, 5))                 # pool empty: no OFFER ever comes back
    else:
        # lease renewal after the scope was narrowed: INIT-REBOOT REQUEST (no server id), refused with a NAK
        copts = P.dhcp_client_opts(client.name, client.mac, win_os, req_ip=client.ipb)
        text = rng.choice([b"wrong network", b"requested address not available"])
        nak_opts = P.opt(54, dc1.ipb) + P.opt(56, text) + P.opt(61, b"\x01" + client.mac)
        t = exchange(ts, lambda giaddr=b"\x00" * 4, hops=0: P.dhcp(1, xid, client.mac, 3, giaddr=giaddr, hops=hops, options=copts, flags=bflag),
                     lambda: P.dhcp(2, xid, client.mac, 6, giaddr=fw.ipb, options=nak_opts, flags=0x8000), nak=True)
        silent_discovers(t + rng.uniform(0.05, 1.0), rng.getrandbits(32), rng.randint(1, 4))   # discovery restarts, no OFFER
    return F.merged(out)


def npm_db_pool_exhaustion(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    # the application tier is the two IIS servers; the OT application server is not a consumer
    # here (NPM-13 brief fix 1), so the scenario does not need the OT zone
    apps = [ctx.h[n] for n in (H('WEB1'), H('WEB2')) if n in ctx.h]
    users = [ctx.h[n] for n in ctx.h if n.startswith((H('WS'), H('MAC')))]
    lo, hi = win
    # THE CAUSE: a demand surge -- many workstations hit the LOB app on WEB2 at once, so the app
    # tier opens more back-end DB connections than the pool allows. Observable as a burst of new
    # connections (a SYN spike) to WEB2 from many distinct hosts right at the onset.
    web2 = ctx.h.get(H('WEB2'))
    if web2 is not None and users:
        burst = rng.sample(users, min(len(users), rng.randint(24, 40)))
        for i, u in enumerate(burst):
            s(lo + 2 + i * rng.uniform(0.05, 0.4), web2_hit, u)
    pre, post = flanks(lo, hi)
    for t in pre + post:
        s(t, tds_pool_query, rng.choice(apps), g=0.0)
    t = lo
    while t < hi:
        s(t, tds_pool_query, rng.choice(apps), g=sev(t, win))
        t += rng.expovariate(1 / 2.5)


def web2_hit(ctx, client, ts):
    """One lightweight workstation hit on the LOB app -- used as the demand-surge cause that
    exhausts the DB pool. A plain new connection, so the surge is a visible SYN spike to WEB2."""
    web = ctx.h[H("WEB2")]
    ua = P.UAS[0] if ctx.is_windows(client) else P.UAS[2]
    out = ctx.arp_for(client, web, ts)
    sx = ctx.tcp(client, web, 80, ts + 0.001).handshake()
    sx.c2s(P.http_request("GET", "/dispatch", f"shipping.{get_current().domain}", ua), think=rng.uniform(0.01, 0.1))
    sx.s2c(P.http_response("200 OK", P.blob(rng.randint(500, 3000)), "text/html", sx.t, server="Microsoft-IIS/10.0"), think=rng.uniform(0.02, 0.2))
    return F.merged(out, sx.close(think=rng.uniform(0.1, 1.0)))


def tds_pool_query(ctx, app, ts, g=1.0):
    """EXL-SQL1 is UP but out of user connections: under load a new connection waits in the accept
    queue (late SYN/ACK), the login and the first query follow late, and part of the logins are
    refused with SQL error 17809 (maximum number of user connections reached; the server then
    closes the connection). Healthy flanks use one pooled connection for several queries.
    Distinct from npm-sql1-service-failure, where the service is actually down."""
    sql1 = ctx.h[H('SQL1')]
    out = ctx.arp_for(app, sql1, ts)
    sx = ctx.tcp(app, sql1, 1433, ts + 0.001).handshake(syn_delay=rng.uniform(0, 1.5 * g) if g > 0 else 0.0)
    spid = rng.randint(50, 120)
    sx.c2s(P.tds_prelogin(True), think=0.0004)
    sx.s2c(P.tds_prelogin(False), think=rng.uniform(0.0005, 0.002))
    sx.c2s(P.tds_login7("svc_app"), think=rng.uniform(0.0006, 0.0006 + 0.3 * g))
    if rng.random() < 0.3 * g:
        sx.s2c(P.tds_split(0x04, P.tds_error(17809, "Could not connect because the maximum number of '200' user connections has already been reached. The system administrator can use sp_configure to increase the maximum value. The connection has been closed.", severity=20, state=1, spid=spid), spid),
               think=rng.uniform(0.01, 0.01 + 0.5 * g))
        return F.merged(out, sx.close(by_client=False, think=rng.uniform(0.001, 0.01)))
    sx.s2c(P.tds_login_ack(), think=rng.uniform(0.001, 0.004) + 0.2 * g)
    queries = ["SELECT TOP 50 OrderId, Status FROM dbo.Shipments WITH (NOLOCK)",
               "SELECT TOP 20 OrderId, Carrier, Status FROM dbo.Shipments WHERE Status = 'HOLD' ORDER BY OrderId DESC",
               "SELECT COUNT(*) AS Open FROM dbo.Shipments WHERE Status <> 'DELIVERED'"]
    for q in range(1 if g > 0 else rng.randint(2, 6)):      # a healthy pooled connection is reused
        gap = rng.uniform(0.001, 0.001 + 2.5 * g) if g > 0 else (0.001 if q == 0 else rng.uniform(0.02, 0.4))
        sx.c2s(P.tds_sql_batch(rng.choice(queries)), think=gap)
        rows = [(rng.randint(1000, 999999), rng.choice(["PICKED", "SHIPPED", "HOLD"])) for _ in range(rng.randint(1, 40))]
        sx.s2c(P.tds_split(0x04, P.tds_result([("OrderId", "int"), ("Status", "nvarchar")], rows), spid),
               think=rng.uniform(0.05, 0.05 + 5.0 * g) if g > 0 else rng.uniform(0.008, 0.02))
    return F.merged(out, sx.close(think=rng.uniform(0.01, 0.2)))


def npm_radius_storm(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    pre, post = flanks(lo, hi)
    for t in pre + post:
        s(t, radius_attempt, rng.choice(users), g=0.0)
    t = lo
    while t < hi:
        s(t, radius_attempt, rng.choice(users), g=sev(t, win))
        t += rng.expovariate(1 / 3.0)


def radius_attempt(ctx, client, ts, g=1.0):
    """802.1X through the NPS on EXL-DC1 (UDP 1812), as a real NAS sends it: the access switch
    (wired, NAS-Port-Type 15) or the WLC (wireless, 19) is the RADIUS client and relays the
    supplicant's EAP-PEAP conversation: Identity, PEAP start, the TLS handshake in EAP-Message
    fragments, the tunnel rounds, then Access-Accept (EAP-Success + MS-MPPE keys) or Access-Reject
    (EAP-Failure), every packet with a valid Message-Authenticator. Under load: Rejects surge,
    some requests get no answer at some round and the NAS retransmits the same packet, and the
    inner-authentication round (the directory lookup) answers slowly. Outcome mix as before."""
    srv = ctx.h[H('DC1')]
    wireless = "mac" in client.os.lower() or int("".join(c for c in client.name if c.isdigit()) or "0") % 2 == 0
    nas = ctx.h[H('WLC1') if wireless else H('SWA1')]
    ap = rng.choice([h for n, h in ctx.h.items() if n.startswith(H('AP'))] or [nas])
    mac = "-".join("%02X" % b for b in client.mac)
    called = ("-".join("%02X" % b for b in ap.mac) + ":Example-Corp") if wireless else "-".join("%02X" % b for b in nas.mac)
    nas_port = 1 if wireless else 50100 + rng.randint(1, 48)
    ptype = 19 if wireless else 15
    cinfo = "CONNECT 144Mbps 802.11n" if wireless else "CONNECT 1000Mbps Full duplex"
    user = P.username_for(client.name)
    out = ctx.arp_for(nas, srv, ts)
    sport = nas.eph()
    r = rng.random()
    if g < 0.15:
        outcome = "accept"
    elif r < 0.5 * g + 0.1:
        outcome = "reject"
    elif r < 0.75:
        outcome = "none"
    else:
        outcome = "accept"
    slow = outcome == "accept" and g >= 0.15

    # the conversation as (client EAP response, server EAP request) per round; a client response
    # echoes the identifier of the server request it answers
    cur = [rng.randint(1, 100)]

    def cresp(etype_data=None, flags=0, tls=b"", ident_only=False):
        if etype_data is not None:
            return P.eap_packet(2, cur[0], 1, etype_data)
        return P.peap_packet(2, cur[0], flags, tls)

    def sreq(flags=0, tls=b"", total=None):
        cur[0] = (cur[0] + 1) & 0xFF
        return P.peap_packet(1, cur[0], flags, tls, total=total)
    flights = TLS.peap_handshake(ctx.pki, srv.fqdn)
    rounds = [(cresp(user.encode()), sreq(0x20))]                                  # identity -> PEAP start
    rounds.append((cresp(tls=flights[0][1]), None))                              # ClientHello
    srv_flight = flights[1][1]
    frags = [srv_flight[k:k + 1000] for k in range(0, len(srv_flight), 1000)]
    for k, fr in enumerate(frags):                                               # server flight, fragmented
        last = k == len(frags) - 1
        rounds[-1] = (rounds[-1][0], sreq((0x80 if k == 0 else 0) | (0 if last else 0x40), fr, len(srv_flight)))
        if not last:
            rounds.append((cresp(), None))                                       # empty ack of a fragment
    rounds.append((cresp(tls=flights[2][1]), sreq(0, flights[3][1])))            # client finish -> server finish
    rounds.append((cresp(), sreq(0, TLS.tunnel_record(rng.randint(24, 34)))))    # tunnel: inner identity request
    rounds.append((cresp(tls=TLS.tunnel_record(rng.randint(40, 60))), sreq(0, TLS.tunnel_record(rng.randint(60, 70)))))
    rounds.append((cresp(tls=TLS.tunnel_record(rng.randint(100, 120))), sreq(0, TLS.tunnel_record(rng.randint(60, 90)))))
    rounds.append((cresp(tls=TLS.tunnel_record(rng.randint(20, 30))), None))     # final tunnel ack
    stall = rng.randrange(len(rounds)) if outcome == "none" else -1
    t = ts
    state = b""
    for k, (creq, crep) in enumerate(rounds):
        ident = (rng.randint(0, 255) + k) & 0xFF
        req, auth = P.radius_eap_request(ident, user, nas.ipb, nas.name, creq, state=state, calling_id=mac, called_id=called,
                                         nas_port=nas_port, nas_port_type=ptype, connect_info=cinfo)
        out.append(ctx.udp(nas, srv, sport, 1812, req, t))
        if k == stall:
            for c in range(1, rng.randint(2, 4)):          # same packet again: the NAS retransmits
                out.append(ctx.udp(nas, srv, sport, 1812, req, t + c * rng.uniform(1.0, 3.0)))
            break
        last_round = k == len(rounds) - 1
        # healthy rounds answer in a few ms; the inner authentication (round before the last) is the slow one
        lat = rng.uniform(0.003, 0.02)
        if g >= 0.15 and k == len(rounds) - 2:
            lat = rng.uniform(1.0, 1.0 + 4.0 * g) if slow else rng.uniform(0.05, 0.3 + 1.0 * g)
        t += lat
        if last_round:
            if outcome == "reject":
                reply = P.radius_eap_reply(3, ident, auth, P.eap_packet(4, (cur[0] + 1) & 0xFF), extra=P.radius_attr(18, b"Authentication failed"))
            else:
                reply = P.radius_eap_reply(2, ident, auth, P.eap_packet(3, (cur[0] + 1) & 0xFF),
                                           extra=P.radius_attr(1, user.encode()) + P.ms_mppe_keys())
            out.append(ctx.udp(srv, nas, 1812, sport, reply, t))
            break
        state = bytes(rng.getrandbits(8) for _ in range(24))
        if crep is None:
            crep = sreq()
        out.append(ctx.udp(srv, nas, 1812, sport, P.radius_eap_reply(11, ident, auth, crep, state=state), t))
        t += rng.uniform(0.002, 0.01)
    return F.merged(out)


def npm_nfs_latency(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    # THE CAUSE (same admin host as npm-smtp-backup): the admin SSHes into the NAS from the jump
    # host and kicks off a reindex/backup job, whose disk I/O is what makes every NFS read drag.
    mgmt, nas = ctx.h.get(H("MGMT1")), ctx.h.get(H("BACKUP1"))
    if mgmt is not None and nas is not None:
        t_admin = lo + rng.uniform(5, 25)
        eng.schedule(t_admin, (lambda a=mgmt, r=nas, t=t_admin, d=rng.uniform(120, 240): F.ssh_session(ctx, a, r, t, d)), tag)  # noqa: B008 draw order is pinned
    pre, post = flanks(lo, hi)
    for t in pre + post:
        s(t, nfs_slow_read, rng.choice(users), g=0.0)
    t = lo
    while t < hi:
        s(t, nfs_slow_read, rng.choice(users), g=sev(t, win))
        t += rng.expovariate(1 / 3.0)


_NFS_FILES = ["report.xlsx", "budget-fy27.xlsx", "roadmap.pptx", "handbook.pdf", "q3-forecast.xlsx", "design-notes.docx",
              "site-plan.vsdx", "training.mp4.idx", "customers.csv", "minutes-nov.docx", "pricing.pdf", "archive-index.db"]


def _nfs_file(i):
    """Stable per-file facts derived from the file id: handle, fileid, size in 8 KiB reads."""
    import hashlib
    h = hashlib.sha1((get_current().prefix.lower().encode() + b"backup1:/export/shared:%d") % i).digest()
    reads = 2 + h[0] % 4
    return {"name": _NFS_FILES[i], "fh": h + h[:8], "fileid": 4096 + i * 17,
            "size": 8192 * (reads - 1) + 1024 + (h[1] << 5) % 7000, "reads": reads}


def nfs_slow_read(ctx, client, ts, g=1.0):
    """NAS latency on EXL-BACKUP1 (NFSv3 / tcp 2049): a real read session -- MOUNT once per client
    (portmap GETPORT, MNT), then LOOKUP -> GETATTR(regular file) -> ACCESS -> READ with advancing
    offsets and eof on the last. GETATTR/READ server time climbs with severity. One TCP connection
    per burst (sessions are bursts, not accesses)."""
    import hashlib
    srv = ctx.h.get(H('BACKUP1'))
    if srv is None:
        return []
    out = ctx.arp_for(client, srv, ts)
    OK = b"\x00\x00\x00\x00"
    FALSE = OK
    TRUE = b"\x00\x00\x00\x01"
    u32 = lambda v: v.to_bytes(4, "big")
    n = int("".join(ch for ch in client.name if ch.isdigit()) or "0")
    uid = 10000 + n
    gid = 100
    cred = P.rpc_auth_unix(client.name.lower(), uid=uid, gid=gid, gids=(1000 + n % 7,) if n % 3 == 0 else ())
    root_fh = hashlib.sha1((get_current().prefix.lower().encode() + b"backup1:/export/shared")).digest() + b"\x00" * 8
    mounted = ctx.__dict__.setdefault("_nfs_mounted", set())
    t_nfs = ts + 0.001
    if client.name not in mounted:
        mounted.add(client.name)
        tm = ts
        # portmap GETPORT(mountd, v3, tcp) on 111, then MNT on the port it returned (20048)
        sp = ctx.tcp(client, srv, 111, tm).handshake()
        xp = rng.getrandbits(32)
        sp.c2s(P.rpc_call(xp, 100000, 2, 3, args=u32(100005) + u32(3) + u32(6) + u32(0)), think=0.002)
        sp.s2c(P.rpc_reply(xp, u32(20048)), think=rng.uniform(0.0004, 0.002))
        out = F.merged(out, sp.close(think=0.01))
        sm = ctx.tcp(client, srv, 20048, sp.t + rng.uniform(0.004, 0.02)).handshake()
        xm = rng.getrandbits(32)
        sm.c2s(P.rpc_call(xm, 100005, 3, 1, cred=cred, args=P.xdr_str("/export/shared")), think=0.002)
        sm.s2c(P.rpc_reply(xm, OK + P.xdr_opaque(root_fh) + u32(1) + u32(1)), think=rng.uniform(0.001, 0.006))
        out = F.merged(out, sm.close(think=0.01))
        t_nfs = sm.t + rng.uniform(0.005, 0.03)
    sx = ctx.tcp(client, srv, 2049, t_nfs).handshake()
    xid = [rng.getrandbits(32)]

    def exch(proc, args, results, svc):
        xid[0] = (xid[0] + 1) & 0xFFFFFFFF
        sx.c2s(P.rpc_call(xid[0], 100003, 3, proc, cred=cred, args=args), think=rng.uniform(0.002, 0.01))
        sx.s2c(P.rpc_reply(xid[0], results), think=svc)

    svc_lo, svc_hi = 0.002 + 0.03 * g, 0.01 + 0.6 * g
    f = _nfs_file(rng.randrange(len(_NFS_FILES)))
    fa = lambda: P.nfs3_fattr3(is_dir=False, size=f["size"], fileid=f["fileid"], uid=uid, gid=gid)
    exch(3, P.xdr_opaque(root_fh) + P.xdr_str(f["name"]),
         OK + P.xdr_opaque(f["fh"]) + TRUE + fa() + FALSE, rng.uniform(0.002, 0.01 + 0.1 * g))      # LOOKUP
    exch(1, P.xdr_opaque(f["fh"]), OK + fa(), rng.uniform(svc_lo, svc_hi))                           # GETATTR (regular file)
    exch(4, P.xdr_opaque(f["fh"]) + u32(0x1F), OK + TRUE + fa() + u32(0x0D), rng.uniform(0.002, 0.01 + 0.1 * g))  # ACCESS
    off = 0
    while off < f["size"]:
        cnt = min(8192, f["size"] - off)
        eof = off + cnt >= f["size"]
        res = OK + FALSE + u32(cnt) + (u32(1) if eof else FALSE) + P.xdr_opaque(P.blob(cnt))
        exch(6, P.xdr_opaque(f["fh"]) + off.to_bytes(8, "big") + u32(8192), res, rng.uniform(svc_lo, svc_hi))
        off += cnt
    return F.merged(out, sx.close(think=rng.uniform(0.01, 0.2)))


def npm_smtp_backup(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H('WS'), H('MAC')))]
    lo, hi = win
    # THE CAUSE, on the wire: an admin SSHes into the relay from the jump host and reloads Postfix.
    # The mail service is unavailable/slow while the config commits, which is what backs the queue
    # up -- so the degradation has a visible administrative trigger, not an unexplained slump. The
    # SSH maintenance session brackets the ramp, exactly as the fw-update commit does for its blip.
    mgmt, relay = ctx.h.get(H('MGMT1')), ctx.h.get(H('BACKUP1'))
    if mgmt is not None and relay is not None:
        t_admin = lo + rng.uniform(5, 25)
        dur = rng.uniform(90, 200)
        eng.schedule(t_admin, (lambda a=mgmt, r=relay, t=t_admin, d=dur: F.ssh_session(ctx, a, r, t, d)), tag)
    pre, post = flanks(lo, hi)
    for t in pre + post:
        s(t, smtp_slow_send, rng.choice(users), g=0.0)
    t = lo
    pending = []                                 # (due, client, attempt): a deferred message is re-sent by the same host
    while t < hi:
        g = sev(t, win)
        due = [p for p in pending if p[0] <= t]
        if due:                                  # this arrival slot is a queued retry, so the session count is unchanged
            pending.remove(due[0])
            _, client, attempt = due[0]
        else:
            client, attempt = rng.choice(users), 0
        r = rng.random()
        if r < 0.35 * g:
            kind = "421" if r < 0.012 * g else ("450" if r < 0.35 * g * 0.25 else "451")
            pending.append((t + (rng.uniform(300, 600) if attempt == 0 else rng.uniform(600, 1800)), client, attempt + 1))
        else:
            kind = None
        s(t, smtp_slow_send, client, g=g, defer=kind, attempt=attempt)
        t += rng.expovariate(1 / 5.0)


def smtp_slow_send(ctx, client, ts, g=1.0, defer=None, attempt=0):
    """Mail relay EXL-BACKUP1 (SMTP / tcp 25) backs up: reply latency climbs and, under load, it
    defers with a 4xx so clients queue and retry (the scheduler re-sends the same message from the
    same host 5 to 10 min later, then every 10 to 30 min). defer: None, "451" (MAIL FROM, local
    problem), "450" (RCPT TO, greylisting) or "421" (service not available, server closes)."""
    srv = ctx.h.get(H('BACKUP1'))
    if srv is None:
        return []
    out = ctx.arp_for(client, srv, ts)
    sx = ctx.tcp(client, srv, 25, ts + 0.001).handshake()
    fq = "%s.%s" % (client.name.lower(), P.DOMAIN)
    host = (get_current().prefix.lower() + "backup1.%s") % P.DOMAIN
    user = P.username_for(client.name)
    sender = "%s@%s" % (user, P.DOMAIN)
    rcpt = "helpdesk@%s" % P.DOMAIN

    def slow(base):
        return rng.uniform(base, base + 6.0 * g)

    sx.s2c(b"220 %s ESMTP Postfix\r\n" % host.encode(), think=slow(0.05))
    sx.c2s(b"EHLO %s\r\n" % fq.encode(), think=rng.uniform(0.03, 0.12))
    sx.s2c(b"250-%s\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-ETRN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN\r\n"
           % host.encode(), think=slow(0.02))
    sx.c2s(b"MAIL FROM:<%s>\r\n" % sender.encode(), think=rng.uniform(0.02, 0.1))
    if defer == "451":
        sx.s2c(b"451 4.3.0 Temporary system problem, try again later\r\n", think=slow(0.1))
        sx.c2s(b"QUIT\r\n", think=rng.uniform(0.05, 0.3))
        sx.s2c(b"221 2.0.0 Bye\r\n", think=0.02)
        return F.merged(out, sx.close(think=0.02))
    if defer == "421":
        sx.s2c(b"421 4.3.2 %s Service not available, closing transmission channel\r\n" % host.encode(), think=slow(0.1))
        return F.merged(out, sx.close(by_client=False, think=0.02))
    sx.s2c(b"250 2.1.0 Ok\r\n", think=slow(0.02))
    sx.c2s(b"RCPT TO:<%s>\r\n" % rcpt.encode(), think=rng.uniform(0.02, 0.08))
    if defer == "450":
        sx.s2c(b"450 4.2.0 <%s>: Recipient address rejected: Greylisted, see http://postgrey.schweikert.ch/help/%s.html\r\n"
               % (rcpt.encode(), P.DOMAIN.encode()), think=slow(0.1))
        sx.c2s(b"QUIT\r\n", think=rng.uniform(0.05, 0.3))
        sx.s2c(b"221 2.0.0 Bye\r\n", think=0.02)
        return F.merged(out, sx.close(think=0.02))
    sx.s2c(b"250 2.1.5 Ok\r\n", think=slow(0.02))
    sx.c2s(b"DATA\r\n", think=0.03)
    sx.s2c(b"354 End data with <CR><LF>.<CR><LF>\r\n", think=slow(0.02))
    when = time.strftime("%a, %d %b %Y %H:%M:%S -0500", time.gmtime(ts - 18000))
    hdr = ("From: %s <%s>\r\nTo: Help Desk <%s>\r\nDate: %s\r\nMessage-ID: <%08x.%04x@%s>\r\nSubject: daily status\r\n"
           "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n"
           % (user, sender, rcpt, when, rng.getrandbits(32), rng.getrandbits(16), fq))
    body = hdr.encode() + P.blob(300).hex().encode()[:500] + b"\r\n.\r\n"
    sx.c2s(body, think=rng.uniform(0.05, 0.2))
    sx.s2c(b"250 2.0.0 Ok: queued as %s\r\n" % ("%010X" % rng.getrandbits(40)).encode(), think=slow(0.05))
    sx.c2s(b"QUIT\r\n", think=0.05)
    sx.s2c(b"221 2.0.0 Bye\r\n", think=0.02)
    return F.merged(out, sx.close(think=0.02))


def npm_mtu_blackhole(ctx, eng, tag, win):
    s = sched_factory(eng, ctx, tag, win)
    users = [ctx.h[n] for n in ctx.h if n.startswith((H("WS"), H("MAC")))]
    lo, hi = win
    # THE CAUSE: an admin SSHes into the firewall from the jump host and pushes an ACL change that
    # starts dropping ICMP (poor/misconfigured ICMP routing). After that commit the gateway's
    # fragmentation-needed messages no longer get the sender to lower its MSS, so bulk flows stall.
    mgmt, fw = ctx.h.get(H("MGMT1")), ctx.h.get("FW-A")
    if mgmt is not None and fw is not None:
        t_admin = lo + rng.uniform(5, 25)
        eng.schedule(t_admin, (lambda a=mgmt, r=fw, t=t_admin, d=rng.uniform(60, 150): F.ssh_session(ctx, a, r, t, d)), tag)  # noqa: B008 draw order is pinned
    pre, post = flanks(lo, hi)
    for t in pre + post:
        s(t, mtu_stall_flow, rng.choice(users), g=0.0)
    t = lo
    while t < hi:
        s(t, mtu_stall_flow, rng.choice(users), g=sev(t, win))
        t += rng.expovariate(1 / 6.0)


ICMP_UNREACH_MIN_GAP = 0.5           # a router rate-limits ICMP unreachables (typically one per 0.5-1 s)


MTU_PATH = 1400                      # the link behind the firewall's user-side interface


MTU_BURST_SEGS = 10                  # initial congestion window (RFC 6928): the upload's first flight


MTU_RTO = (0.3, 0.2)                 # first retransmission timeout, seconds: Windows clients, others (doubles each time)


MTU_GIVE_UP = (5.0, 12.0)            # the application's own timeout, seconds


MTU_STALL_SEVERITY = 0.15            # above this severity an upload stalls; at or below it the upload completes


def mtu_stall_flow(ctx, client, ts, g=1.0):
    """A PMTUD blackhole on the path to EXL-WEB2: small requests succeed, but a bulk upload's
    full-size DF segments cannot cross a 1400-byte link. The firewall answers each drop with ICMP
    type 3 code 4 (next-hop MTU 1400) quoting the dropped datagram, but a filter between the
    firewall and the sender (the pushed ACL / a host rule) keeps the sender from lowering its MSS,
    so it retransmits the same segment at its RTO until the application gives up. The sensor sits
    upstream of that filter and sees the ICMP, the retransmissions, and a server that never
    acknowledges the body. The ICMP is the smoking gun only the network sees."""
    srv = ctx.h[H('WEB2')]
    host = ("shipping." + get_current().domain)
    ua = P.UAS[0] if ctx.is_windows(client) else P.UAS[2]
    out = ctx.arp_for(client, srv, ts)
    sx = ctx.tcp(client, srv, 80, ts + 0.001).handshake()
    cont = b"HTTP/1.1 100 Continue\r\n\r\n"            # an interim response has no headers and no body
    if g < MTU_STALL_SEVERITY:
        sx.c2s(P.http_request("POST", "/api/upload", host, ua, ["Content-Length: 300000", "Expect: 100-continue"]), think=rng.uniform(0.005, 0.02))
        sx.s2c(cont, think=rng.uniform(0.002, 0.01))
        sx.c2s(P.blob(300000), think=rng.uniform(0.05, 0.2))
        sx.s2c(P.http_response("200 OK", b"{\"ok\":true}", "application/json", sx.t), think=rng.uniform(0.02, 0.1))
        return F.merged(out, sx.close(think=rng.uniform(0.1, 0.5)))
    # small requests still work on this very connection: they fit under the path MTU
    sx.c2s(P.http_request("GET", "/api/queue", host, ua), think=rng.uniform(0.005, 0.02))
    sx.s2c(P.http_response("200 OK", b"{\"pending\":%d}" % rng.randint(0, 40), "application/json", sx.t), think=rng.uniform(0.004, 0.03))
    sx.c2s(P.http_request("POST", "/api/upload", host, ua, ["Content-Length: 300000", "Expect: 100-continue"]), think=rng.uniform(0.4, 2.0))
    sx.s2c(cont, think=rng.uniform(0.002, 0.01))
    sx._s_unacked = 0
    sx._c_unacked = 0
    fw = ctx.link.gateway_for(client)
    dmac, smac, ttl = ctx.link.addr(fw, client, client)
    sent = ctx.__dict__.setdefault("_mtu_icmp_times", [])   # the firewall's rate limit is shared by every flow

    def segment(t, seq, payload, flags):
        sx.t = t
        sx._emit(sx.c, sx.s, sx.sport, sx.dport, seq, sx.sseq, flags, sx.cwin, payload)
        return sx.pkts[-1][1]

    def dropped(t, frame):
        """The firewall cannot forward the DF datagram and answers with frag-needed, subject to its rate limit."""
        ti = t + rng.uniform(0.0003, 0.002)
        i = bisect.bisect_left(sent, ti)
        if (i > 0 and ti - sent[i - 1] < ICMP_UNREACH_MIN_GAP) or (i < len(sent) and sent[i] - ti < ICMP_UNREACH_MIN_GAP):
            return
        sent.insert(i, ti)
        quoted = frame[14:14 + 20 + 8]                    # the datagram's own IP header + first 8 bytes (RFC 792)
        out.append((ti, eth(dmac, smac, ETH_IP, ipv4(fw, client, 1, P.icmp_frag_needed(MTU_PATH, quoted), ttl=ttl))))

    t = sx.t + rng.uniform(0.001, 0.005)
    seq0 = sx.cseq
    seq = seq0
    for i in range(MTU_BURST_SEGS):                        # the first flight, back to back
        payload = P.blob(sx.mss)
        frame = segment(t, seq, payload, ACK | (PSH if i == MTU_BURST_SEGS - 1 else 0))
        if i == 0:
            _, first_payload, t_first = frame, payload, t
            dropped(t, frame)
        seq += len(payload)
        t += rng.uniform(0.00002, 0.00006)
    # RTO retransmissions of the first unacknowledged segment: same sequence number, new IP id, RTO doubling
    rto = MTU_RTO[0] if ctx.is_windows(client) else MTU_RTO[1]
    give_up = rng.uniform(*MTU_GIVE_UP)                       # the application's own timeout
    tr, delay = t_first, rto
    while tr + delay - t_first <= give_up:
        tr += delay
        frame = segment(tr, seq0, first_payload, ACK)
        dropped(tr, frame)
        delay *= 2
    sx.cseq = seq
    t_end = t_first + give_up
    sx.t = t_end
    sx._emit(sx.c, sx.s, sx.sport, sx.dport, seq, sx.sseq, RST | ACK, 0)
    return F.merged(out, sx.drain())


# ============================================================================================
# OT / IoT scenarios (built 2026-10-02). They target the OT subnet, so each is INERT unless the OT
# zone is enabled (the PLC/RTU/SIS/camera hosts are not in ctx.h otherwise). Most reuse the existing
# OT flow builders -- the finding is WHO is talking and WHICH function code, which is exactly what
# the platform's Modbus/BACnet/DNP3 metrics break out, plus cross-Purdue-zone flow and new-device sight.
# ============================================================================================

def _ot_hosts(ctx, *prefixes):
    return [h for h in ctx.h.values() if h.name.startswith(prefixes)]


def ndr_ot_modbus_write(ctx, eng, tag, win):
    """A compromised engineering workstation writes setpoints to PLCs that normally only serve
    READs -- Modbus write function codes appearing where there were none. FC6 is the majority,
    with FC16/FC5 and an occasional exception in a minority of sessions (`mix=True`); each PLC
    gets its own small, reused register pool, and the first write to a PLC follows a read."""
    s = sched_factory(eng, ctx, tag, win)
    plcs = _ot_hosts(ctx, H('PLC'))
    actor = ctx.h.get(H('OTENG1'))
    if not plcs or actor is None:
        return
    lo, hi = win
    targets = {p.name: rng.sample(range(40, 80), rng.randint(2, 4)) for p in plcs}
    primed = set()
    t = lo + 60
    while t < hi:
        plc = rng.choice(plcs)
        if plc.name not in primed:
            primed.add(plc.name)
            s(t, F.modbus_poll_block, actor, plc, n_polls=1)
            t += rng.uniform(1.0, 3.0)
        s(t, F.modbus_setpoint_write, actor, plc, mix=True, targets=targets[plc.name])
        t += rng.uniform(20, 90)


def ndr_ot_sis_tamper(ctx, eng, tag, win):
    """Plain Modbus/TCP contact with the Safety Instrumented System that should essentially never
    happen at all -- not the real TriStation (UDP/1502) shape TRITON/TRISIS used, which this
    builder does not reproduce. A conversation to EXL-SIS-0x is the signal regardless; the reads
    probe registers outside the baseline poll's own map, so even the request itself (not just
    the source) differs from a legitimate SCADA poll."""
    s = sched_factory(eng, ctx, tag, win)
    sis = _ot_hosts(ctx, H('SIS'))
    actor = ctx.h.get(H('OTENG1'))
    if not sis or actor is None:
        return
    lo, hi = win
    t = lo + 60
    while t < hi:
        tgt = rng.choice(sis)
        if rng.random() < 0.5:
            s(t, F.modbus_setpoint_write, actor, tgt)
        else:
            s(t, F.modbus_poll_block, actor, tgt, n_polls=rng.randint(2, 5), start=200)
        t += rng.uniform(60, 180)


def ndr_ot_zone_violation(ctx, eng, tag, win):
    """A compromised IT host (Level 4) speaks Modbus straight to a Level-1 PLC, bypassing the
    jump host that is the only permitted initiator into OT -- a cross-Purdue-zone flow. One
    request/response per session (the page's own "shape of a poll" claim), reading a register
    range the baseline SCADA pollers never touch, not a copy of their own map."""
    s = sched_factory(eng, ctx, tag, win)
    plcs = _ot_hosts(ctx, H('PLC'))
    it = ctx.h.get(C_PIVOT) or ctx.h.get(H('WS-023'))
    if not plcs or it is None:
        return
    lo, hi = win
    t = lo + 60
    while t < hi:
        s(t, F.modbus_poll_block, it, rng.choice(plcs), n_polls=1, start=150)
        t += rng.uniform(40, 120)


def _ot_recon_modbus_probe(ctx, src, plc, ts):
    """Real enumeration on one PLC: several unit ids across several function codes (coils,
    discrete inputs, holding/input registers), with an occasional exception -- not a single
    random read with one unit id."""
    out = ctx.arp_for(src, plc, ts)
    s = ctx.tcp(src, plc, P.MODBUS_PORT, ts + 0.0008).handshake()
    tid = rng.randrange(1, 4096)
    funcs = (P.MB_READ_COILS, P.MB_READ_DISCRETE, P.MB_READ_HOLDING, P.MB_READ_INPUT)
    for unit in rng.sample(range(1, 9), rng.randint(3, 5)):
        func = rng.choice(funcs)
        tid = (tid + 1) & 0xFFFF
        count = 8 if func in (P.MB_READ_COILS, P.MB_READ_DISCRETE) else 10
        s.c2s(P.modbus_read_req(tid, unit, func, 0, count), think=rng.uniform(0.01, 0.05))
        if rng.random() < 0.4:
            code = P.MB_EX_ILLEGAL_FUNC if rng.random() < 0.6 else P.MB_EX_GATEWAY_FAILED
            s.s2c(P.modbus_exception(tid, unit, func, code), think=rng.uniform(0.002, 0.01))
        else:
            s.s2c(P.modbus_read_rsp(tid, unit, func, count), think=rng.uniform(0.002, 0.01))
    pk = s.close(think=0.002)
    return F.merged(out, pk)


def _ot_recon_bacnet_sweep(ctx, src, devices, ts):
    """A real discovery sweep: a broadcast Who-Is, I-Am replies from the devices present, then
    a confirmed ReadProperty with each -- not a cold ReadProperty to a hard-coded device list."""
    from .core import udp_bcast
    out = [(ts, udp_bcast(src, P.BACNET_PORT, P.BACNET_PORT, P.bacnet_who_is_req(), dst_ip=src.ipb[:3] + b"\xff"))]
    t = ts + 0.05
    for d in devices:
        out.append(ctx.udp(d, src, P.BACNET_PORT, P.BACNET_PORT, P.bacnet_i_am_rsp(rng.randint(1, 4000)), t, vantage=d))
        t += rng.uniform(0.01, 0.08)
    pk = F.merged(out)
    t += rng.uniform(0.3, 1.0)
    for d in devices:
        pk = F.merged(pk, F.bacnet_read_exchange(ctx, src, d, t))
        t += rng.uniform(2, 8)
    return pk


def _ot_recon_dnp3_probe(ctx, src, rtu, ts):
    """A link-status check before the read -- not a cold READ with no link-layer probe."""
    out = ctx.arp_for(src, rtu, ts)
    s = ctx.tcp(src, rtu, P.DNP3_PORT, ts + 0.0008).handshake()
    s.c2s(P.dnp3_link_status_req(4, 3), think=0.0003)
    s.s2c(P.dnp3_link_status_rsp(3, 4), think=rng.uniform(0.002, 0.01))
    pk = s.close(think=0.002)
    poll = F.dnp3_poll_block(ctx, src, rtu, ts + rng.uniform(0.1, 0.3), n_polls=1)
    return F.merged(out, pk, poll)


def ndr_ot_recon(ctx, eng, tag, win):
    """OT device enumeration from the (compromised) jump host: a Modbus unit/function-code
    sweep of the PLCs, a BACnet Who-Is discovery sweep of the field devices, and DNP3
    link-status checks plus reads of the RTUs."""
    s = sched_factory(eng, ctx, tag, win)
    plcs = _ot_hosts(ctx, H('PLC'))
    bac = _ot_hosts(ctx, H('BAC-'), H('ENV-'))
    rtus = _ot_hosts(ctx, H('RTU'))
    actor = ctx.h.get(H('OTJUMP1'))
    if actor is None or not (plcs or bac or rtus):
        return
    lo, hi = win
    t = lo + 30
    for p in plcs:
        s(t, _ot_recon_modbus_probe, actor, p)
        t += rng.uniform(3, 10)
    if bac:
        devices = bac[:16]
        s(t, _ot_recon_bacnet_sweep, actor, devices)
        t += rng.uniform(2, 8) * len(devices)
    for r in rtus:
        s(t, _ot_recon_dnp3_probe, actor, r)
        t += rng.uniform(3, 10)


def _ot_rogue_host(ctx):
    """Mint a previously-unseen device on the OT (Level-1) segment: a fresh MAC/IP the baseline
    never carried. Memoized so it keeps one identity across the window."""
    cached = getattr(ctx, "_ot_rogue", None)
    if cached is not None:
        return cached
    plcs = _ot_hosts(ctx, H("PLC"))
    if not plcs:
        return None
    ref = plcs[0]
    ip = ".".join(ref.ip.split(".")[:3]) + ".241"
    h = Host(H("ROGUE-OT"), ip, "de:ad:be:ef:30:f1", "linux", "unknown device", ref.subnet, get_current().host("ROGUE-OT").lower())
    h.hops = ref.hops
    ctx._ot_rogue = h
    return h


def ndr_ot_rogue_asset(ctx, eng, tag, win):
    """A device that was never in the baseline appears on the OT segment and starts polling a PLC
    as a Modbus master -- a new MAC/IP where the asset set is supposed to be static. Announces
    itself (ARP probe + gratuitous) before its first session, then sticks to a small recurring
    set of targets -- not a fresh uniform-random PLC every time -- so the ARP cache actually
    gets to keep an entry past the end of its lifetime."""
    s = sched_factory(eng, ctx, tag, win)
    plcs = _ot_hosts(ctx, H('PLC'))
    rogue = _ot_rogue_host(ctx)
    if not plcs or rogue is None:
        return
    lo, hi = win
    targets = rng.sample(plcs, min(4, len(plcs)))
    s(lo + 30, _ot_arp_arrival, rogue)
    t = lo + 35
    while t < hi:
        s(t, F.modbus_poll_block, rogue, rng.choice(targets), n_polls=rng.randint(1, 3))
        t += rng.uniform(20, 60)


def ndr_ot_camera_beacon(ctx, eng, tag, win):
    """An IP camera that should only talk to the NVR starts beaconing to an internet cloud --
    the IoT-botnet shape, and an egress no field device should ever make. A fixed small
    check-in to one path, a device user agent, a short JSON reply and the camera's own
    embedded TLS fingerprint -- not a desktop browser's random browsing."""
    s = sched_factory(eng, ctx, tag, win)
    cams = _ot_hosts(ctx, H('CAM'))
    site = ctx.sites.get("sync.luminaboard-cloud.net")
    if not cams or site is None:
        return
    cam = cams[0]
    lo, hi = win
    t = lo + 30
    while t < hi:
        s(t, F.https_session, cam, site, requests=1, sizes=[rng.randint(200, 400)],
          ua="IPCam-Agent/2.3.1", paths=["/v1/ping"], ctype="application/json",
          tls_profile="embedded", dns=True)
        t += rng.uniform(45, 120) / max(0.2, min(1.0, ctx.scale))


# ---- NPM: a PLC goes unresponsive to supervisory polls -----------------------
def npm_ot_plc_unresponsive(ctx, eng, tag, win):
    plcs = _ot_hosts(ctx, H('PLC'))
    scada = ctx.h.get(H('SCADA1'))
    if not plcs or scada is None:
        return
    plc = plcs[0]
    lo, hi = win
    # one long-lived Modbus/TCP connection from the master to the controller, polled every 1 to 2 s;
    # it is only closed and reopened after repeated timeouts (healthy lead-in and recovery included)
    t0 = lo - 300
    eng.schedule(t0, (lambda: ot_plc_session(ctx, scada, plc, t0, hi + 300, win)), tag)




# ---- CUSTOM: a scenario rebuilt from an imported pcap recipe -------------------------------
# `pcapprofile.build_spec` turns an imported capture into a recipe JSON; this reads it back and
# recreates the exemplar's flows in the simulated environment, with as much Layer-7 fidelity as
# the engine's builders allow. Mapped onto real Example hosts, the corp domain, the engine's
# users and PKI -- nothing from the import is reused, it is recreated. Protocols the engine cannot
# build are skipped and reported. Scenario-only and seeded, so the pinned baseline is untouched.
# Everything the engine can actually build, reachable from an imported recipe. One token per
# adapter below; build_spec emits these same tokens. Protocols the engine cannot emit (SMTP,
# NFS, RADIUS, QUIC, the platform long-tail) are not here and are reported, not faked.
CI_SUPPORTED = {"HTTPS", "HTTP", "SMB2", "Kerberos", "LDAP", "TDS", "RDP", "SNMP", "DNS",
                "SSH", "FTP", "NTP", "DHCP", "Syslog", "SIP", "Print", "MCP", "NameRes",
                "ICMP", "Modbus", "BACnet", "DNP3", "SMTP", "NFS", "RADIUS"}
# Only these target the recipe's mapped server; the rest resolve their own canonical
# infrastructure (NTP1, LOG1, PBX1, PRINT1, a smart board, the DCs) or need no server.
CI_NEEDS_SERVER = {"HTTPS", "HTTP", "SMB2", "TDS", "RDP", "SNMP", "SSH", "FTP", "SMTP", "NFS"}
# OT flows only exist when the OT subnet is switched on for this build.
CI_OT = {"Modbus", "BACnet", "DNP3"}


def _ci_https(ctx, client, server, ts, paths, ua):
    from .tls import TlsSession
    out = ctx.arp_for(client, server, ts)
    sx = ctx.tcp(client, server, 443, ts + 0.001).handshake()
    tls = TlsSession(ctx.pki, server.fqdn, ctx.keylog, profile=getattr(client, "tls_profile", "chrome"))
    for from_c, data in tls.handshake():
        (sx.c2s if from_c else sx.s2c)(data, think=rng.uniform(0.002, 0.01))
    for pth in (paths or ["/"])[:5]:
        sx.c2s(tls.app_data(True, P.http_request("GET", pth, server.fqdn, ua or P.UAS[0])), think=rng.uniform(0.05, 0.6))
        sx.s2c(tls.app_data(False, P.http_response("200 OK", P.blob(rng.randint(1200, 9000)),
               "text/html", sx.t, server="nginx/1.26.2")), think=rng.uniform(0.02, 0.1))
    return F.merged(out, sx.close(think=0.01))


def _ci_http(ctx, client, server, ts, paths, ua):
    out = ctx.arp_for(client, server, ts)
    sx = ctx.tcp(client, server, 80, ts + 0.001).handshake()
    for pth in (paths or ["/"])[:5]:
        sx.c2s(P.http_request("GET", pth, server.fqdn, ua or P.UAS[0]), think=rng.uniform(0.05, 0.6))
        sx.s2c(P.http_response("200 OK", P.blob(rng.randint(800, 6000)), "text/html", sx.t), think=rng.uniform(0.02, 0.1))
    return F.merged(out, sx.close(think=0.01))


def _ci_tds(ctx, client, server, ts):
    out = ctx.arp_for(client, server, ts)
    sx = ctx.tcp(client, server, 1433, ts + 0.001).handshake()
    sx.c2s(P.tds_prelogin(True), think=0.0004)
    sx.s2c(P.tds_prelogin(False), think=rng.uniform(0.0005, 0.002))
    sx.c2s(P.tds_login7("svc_app"), think=0.0006)
    sx.s2c(P.tds_login_ack(), think=rng.uniform(0.001, 0.004))
    sx.c2s(P.tds_sql_batch("SELECT TOP 20 ref, status FROM dbo.Shipments"), think=0.001)
    rows = [(rng.randint(1000, 9999), "SH%03d" % rng.randint(1, 999)) for _ in range(3)]
    sx.s2c(P.tds_split(0x04, P.tds_result([("ref", "int"), ("status", "nvarchar")], rows), 60),
           think=rng.uniform(0.002, 0.02))
    return F.merged(out, sx.close(think=0.001))


def _ci_pick(ctx, prefixes, exclude=None):
    """A deterministic host whose name starts with one of `prefixes`, or None."""
    pool = [h for h in ctx.h.values()
            if h.name.startswith(prefixes) and h is not exclude]
    return rng.choice(pool) if pool else None


def _ci_sip(ctx, client, ts):
    # sip_call derives each extension from the last two digits of the host name, so both ends
    # need a numeric tail; mapped workstations have one. The PBX, RTP and RTCP come for free.
    if not client.name[-2:].isdigit():
        client = _ci_pick(ctx, (H("WS"),)) or client
    peer = _ci_pick(ctx, (H("WS"), H("MAC")), exclude=client)
    if peer is None or not client.name[-2:].isdigit() or not peer.name[-2:].isdigit():
        return []
    return F.sip_call(ctx, client, peer, ts, rng.uniform(30, 240))


def _ci_mcp(ctx, client, ts):
    sb = _ci_pick(ctx, (H("SB-"),))
    return F.mcp_session(ctx, client, sb, ts) if sb else []


def _ci_ot(ctx, proto, client, ts):
    if proto == "Modbus":
        plc = _ci_pick(ctx, (H("PLC"),))
        master = _ci_pick(ctx, (H("HMI"),)) or client
        return F.modbus_poll_block(ctx, master, plc, ts, n_polls=rng.randint(2, 6)) if plc else []
    if proto == "BACnet":
        dev = _ci_pick(ctx, (H("PLC"), H("RTU"), H("HMI")))
        ctrl = _ci_pick(ctx, (H("HMI"),)) or client
        return F.bacnet_read_exchange(ctx, ctrl, dev, ts) if dev else []
    if proto == "DNP3":
        rtu = _ci_pick(ctx, (H("RTU"),))
        master = _ci_pick(ctx, (H("HMI"),)) or client
        return F.dnp3_poll_block(ctx, master, rtu, ts, n_polls=rng.randint(2, 4)) if rtu else []
    return []


def _ci_flow(ctx, flow, client, ts=None):
    """Execute one recipe flow in the simulated environment. Returns the packet list.

    Server-targeted protocols use the recipe's mapped Example server; the rest resolve their
    own canonical infrastructure (the DCs, NTP1, LOG1, PBX1, a printer, a smart board) exactly
    as the baseline builders do. Any missing endpoint yields an empty list, never an exception,
    so one unbuildable flow cannot abort the scenario.
    """
    proto = flow.get("protocol")
    server = ctx.h.get(flow.get("server"))
    ua = (flow.get("user_agents") or [None])[0]
    # ---- server-targeted ----
    if proto == "HTTPS":
        return _ci_https(ctx, client, server, ts, flow.get("paths"), ua) if server else []
    if proto == "HTTP":
        return _ci_http(ctx, client, server, ts, flow.get("paths"), ua) if server else []
    if proto == "SMB2":
        if not server:
            return []
        share = ((flow.get("shares") or ["Dept"])[0]).rstrip("\\").split("\\")[-1] or "Dept"
        return F.smb_file_activity(ctx, client, server, ts, n_files=rng.randint(1, 3), share=share)
    if proto == "TDS":
        return _ci_tds(ctx, client, server, ts) if server else []
    if proto == "RDP":
        return F.rdp_session(ctx, client, server, ts, rng.uniform(30, 150)) if server else []
    if proto == "SNMP":
        return F.snmp_poll(ctx, client, server, ts) if server else []
    if proto == "SSH":
        return F.ssh_session(ctx, client, server, ts, rng.uniform(20, 180)) if server else []
    if proto == "FTP":
        return F.anon_ftp_session(ctx, client, server, ts, ops=("LIST",)) if server else []
    if proto == "SMTP":
        return F.smtp_session(ctx, client, server, ts) if server else []
    if proto == "NFS":
        return F.nfs_session(ctx, client, server, ts) if server else []
    # ---- resolve their own infrastructure ----
    if proto == "RADIUS":
        return F.radius_auth(ctx, client, ts)
    if proto == "Kerberos":
        return F.kerberos_as(ctx, client, ts, user=P.username_for(client.name))
    if proto == "LDAP":
        return F.ldap_session(ctx, client, ts, dc=server)
    if proto == "DNS":
        return F.dns_lookup(ctx, client, "intranet.%s" % P.DOMAIN, ts)
    if proto == "NTP":
        return F.ntp_exchange(ctx, client, ts)
    if proto == "DHCP":
        return F.dhcp_acquire(ctx, client, ts)
    if proto == "Syslog":
        return F.syslog_msg(ctx, client, ts)
    if proto == "Print":
        return F.print_job(ctx, client, ts)
    if proto == "NameRes":
        return F.name_noise(ctx, client, ts)
    if proto == "ICMP":
        return F.icmp_ping(ctx, client, server or ctx.link.gateway_for(client), ts)
    if proto == "SIP":
        return _ci_sip(ctx, client, ts)
    if proto == "MCP":
        return _ci_mcp(ctx, client, ts)
    if proto in CI_OT:
        return _ci_ot(ctx, proto, client, ts)
    return []


def _build_one_recipe(ctx, s, recipe, lo, hi, span, ot_on):
    """Recreate one recipe's flows in the window. Returns its reconstruction report."""
    clients = [ctx.h[hm["example"]] for hm in recipe.get("host_map", []) if hm.get("example") in ctx.h]
    if not clients:
        clients = [ctx.h[n] for n in ctx.h if n.startswith(H("WS"))][:20]
    report = {"source": recipe.get("source", {}), "built": [], "skipped": []}
    for flow in recipe.get("flows", []):
        proto = flow.get("protocol")
        if proto not in CI_SUPPORTED:
            report["skipped"].append({"protocol": proto, "server": flow.get("server"),
                                      "reason": "no builder for this protocol"})
            continue
        if proto in CI_NEEDS_SERVER and ctx.h.get(flow.get("server")) is None:
            report["skipped"].append({"protocol": proto, "server": flow.get("server"),
                                      "reason": "server not in inventory"})
            continue
        if proto in CI_OT and not ot_on:
            report["skipped"].append({"protocol": proto, "server": flow.get("server"),
                                      "reason": "OT subnet not enabled in this build"})
            continue
        n = min(400, max(1, int(flow.get("sessions", 10) * min(1.0, ctx.scale))))
        for i in range(n):
            t = lo + 60 + span * i / n + rng.uniform(0, span / max(1, n))
            s(t, _ci_flow, flow, clients[i % len(clients)])
        report["built"].append({"protocol": proto, "builder": flow.get("builder"),
                                 "server": flow.get("server"), "sessions": n})
    rep = recipe.get("reproducible", {})
    built_names = {b["protocol"] for b in report["built"]}
    for nm in rep.get("approximate_only", []) + rep.get("not_reproduced", []):
        if nm in built_names:
            continue
        report["skipped"].append({"protocol": nm, "reason": "no builder in the engine (reported, not built)"})
    return report


def custom_import_scenario(ctx, eng, tag, win):
    """One CUSTOM scenario per imported recipe. `ctx.recipes` is a list of recipe dicts (the GUI
    and CLI can supply several); `ctx.recipe` is accepted as a single-recipe fallback. With none,
    the scenario is inert and contributes nothing — custom is never present unless a recipe is."""
    recipes = getattr(ctx, "recipes", None)
    if not recipes:
        one = getattr(ctx, "recipe", None)
        recipes = [one] if one else []
    recipes = [r for r in recipes if r]
    if not recipes:
        ctx.custom_report = None
        return
    s = sched_factory(eng, ctx, tag, win)
    lo, hi = win
    span = max(1.0, hi - lo - 120)
    ot_on = any(h.name.startswith((H("PLC"), H("RTU"), H("HMI"))) for h in ctx.h.values())
    reports = [_build_one_recipe(ctx, s, r, lo, hi, span, ot_on) for r in recipes]
    # one report per recipe, plus the combined view older readers expect
    ctx.custom_report = {"recipes": reports, "count": len(reports),
                         "built": [b for r in reports for b in r["built"]],
                         "skipped": [sk for r in reports for sk in r["skipped"]]}


def campaign_scenario(ctx, eng, tag, win):
    """Campaign built from threat indicators (netgen.campaign). The import is guarded so a missing
    or broken campaign package can never break a normal build; with no campaign supplied the
    scenario is inert."""
    if not getattr(ctx, "campaigns", None):
        ctx.campaign_report = None
        return
    from .campaign import runner as _campaign_runner
    _campaign_runner.campaign_scenario(ctx, eng, tag, win)


_reg("campaign", "CAMPAIGN", "campaign", "Campaign built from threat indicators",
     ((9, 0), (16, 0)), campaign_scenario,
     "an ATT&CK-mapped attack campaign compiled from threat indicators (or a campaign file); stages "
     "are placed from the campaign's own start time and each action is real protocol traffic. "
     "Inert unless a campaign is supplied.")
# NPM — performance
_reg("custom-import", "CUSTOM", "custom", "Custom scenario rebuilt from an imported pcap recipe",
     ((9, 0), (11, 0)), custom_import_scenario,
     "reads a recipe JSON produced by the pcap importer and recreates its flows in the simulated "
     "environment (mapped hosts, corp domain, engine users and PKI); skips and reports protocols "
     "the engine cannot build. Inert unless a recipe is loaded.")
_reg("npm-fw-update", "NPM", "fw-update", "Firewall content update (Palo Alto): WHEN it ran, IF it completed, and the remote-access outage it caused",
     ((6, 0), (10, 30)), npm_fw_update, "jump host pulls the PAN-OS bundle early (06:15), admin pushes after the inward pivot is visible (09:29); the ~90s commit reloads the dataplane and drops the entire VPN workforce -- auth/DB/web requests crater for 90-180s then a reconnect storm; aligns with ndr-edge-exploit")
_reg("npm-pqc-posture", "NPM", "pqc-posture", "Post-quantum readiness: which hosts can use PQC key exchange, which do, and which cannot",
     ((11, 0), (12, 0)), npm_pqc, "TLS 1.3 handshakes across capable/using/not-capable hosts; populates the platform's post-quantum key-exchange fields and metric for a readiness dashboard")
_reg("npm-sql1-service-failure", "NPM", "sql1-service-failure", "SQL Server service failure (degrade/outage/recover)",
     ((10, 0), (11, 5)), npm_sql1, "EXL-SQL1 MSSQL outage; see incident.py")
_reg("npm-dns-degradation", "NPM", "dns-degradation", "DNS degradation on EXL-DC1 (timeouts, SERVFAIL, failover)",
     ((9, 15), (9, 50)), npm_dns_degradation, "slow/failed resolution, retry + failover to DC2")
_reg("npm-smb-slowdown", "NPM", "smb-slowdown", "SMB file-server slowdown (zero-window, high service time)",
     ((13, 0), (13, 40)), npm_smb_slowdown, "EXL-FILE1 slow reads, zero-window stalls")
_reg("npm-wan-congestion", "NPM", "wan-congestion", "WAN congestion (high RTT, retransmissions on egress)",
     ((16, 0), (16, 40)), npm_wan_congestion, "egress HTTPS with loss/retransmit and elevated RTT")
_reg("npm-auth-latency", "NPM", "auth-latency", "Authentication latency (slow Kerberos on EXL-DC1)",
     ((8, 0), (8, 40)), npm_auth_latency, "slow AS-REP from the KDC during logon")
_reg("npm-web-degradation", "NPM", "web-degradation", "Web-server degradation (EXL-WEB2 cascade from slow SQL1)",
     ((13, 30), (14, 15)), npm_web_degradation, "WEB2 page time tracks slow TDS to SQL1; some 503s; DB is the root cause")
_reg("npm-wireless-degradation", "NPM", "wireless-degradation", "Wireless degradation (EXL-WLC1 control-plane issue)",
     ((14, 0), (14, 45)), npm_wireless_degradation, "controller stalls: late/lost CAPWAP Echo, AP rejoin waves (Discovery, DTLS, Join), client DHCP/DNS storm after each rejoin")
_reg("npm-web-dns-degradation", "NPM", "web-dns-degradation", "Web degradation from DNS (10 hosts, slow/failed resolution)",
     ((11, 0), (11, 45)), npm_web_dns_degradation, "10 named hosts: DNS SERVFAIL/slow resolution stalls or fails page loads")
_reg("npm-voip-quality", "NPM", "voip-quality", "VoIP call-quality degradation (RTP jitter, loss, reorder)",
     ((9, 30), (10, 30)), npm_voip_quality, "degraded G.711 media between handsets; poor MOS")
_reg("npm-tcp-loss-storm", "NPM", "tcp-loss-storm", "TCP retransmission / packet-loss storm on a segment",
     ((15, 0), (15, 40)), npm_tcp_loss_storm, "the compromised Salt Typhoon collector EXL-WS-061 SSHes into switch EXL-SWB1 (anomalous admin from a workstation) and induces a duplex mismatch on the FILE1 path: retransmits, dup-ACKs, fast retransmit. Auto-selects ndr-salt-typhoon")
_reg("npm-ntp-failure", "NPM", "ntp-failure", "NTP time-sync failure (EXL-NTP1 unreachable)",
     ((12, 0), (12, 40)), npm_ntp_failure, "clients poll NTP1 with no reply; clock drift / unsynced")
_reg("npm-http-errors", "NPM", "http-errors", "HTTP 5xx error-rate surge (LOB API on EXL-WEB2)",
     ((10, 0), (10, 40)), npm_http_errors, "WEB2 API returns 500/502/503 at volume; the status-code mix spikes while service time stays low")
_reg("npm-dhcp-exhaustion", "NPM", "dhcp-exhaustion", "DHCP scope exhaustion (clients cannot get a lease)",
     ((6, 30), (7, 15)), npm_dhcp_exhaustion, "the compromised Volt Typhoon beachhead EXL-WS-009 RDPs the DC (anomalous admin from a workstation) and starves the scope: DISCOVERs get no OFFER and REQUESTs are NAKed. Auto-selects ndr-volt-typhoon")
_reg("npm-db-pool-exhaustion", "NPM", "db-pool-exhaustion", "Database connection-pool exhaustion (EXL-SQL1 saturated, not down)",
     ((14, 30), (15, 15)), npm_db_pool_exhaustion, "TDS login queues and query processing time climbs; some requests get a resource error and abort")
_reg("npm-radius-storm", "NPM", "radius-storm", "RADIUS / 802.1X NAC auth-failure storm (NPS on EXL-DC1)",
     ((7, 30), (8, 10)), npm_radius_storm, "Access-Reject surge, dropped requests with retransmits, and slow Access-Accepts; network onboarding fails")
_reg("npm-nfs-latency", "NPM", "nfs-latency", "NFS / NAS storage latency (EXL-BACKUP1)",
     ((12, 15), (12, 55)), npm_nfs_latency, "NFSv3 GETATTR/READ server processing time climbs on tcp 2049; reads from the share stall")
_reg("npm-smtp-backup", "NPM", "smtp-backup", "SMTP mail-flow backup / delivery latency (relay EXL-BACKUP1)",
     ((16, 30), (17, 10)), npm_smtp_backup, "an admin SSHes into the relay (EXL-MGMT1 -> BACKUP1:22) and reloads Postfix; while it commits, SMTP reply latency climbs and 451 greylisting backs the queue up -- the SSH session is the visible cause")
_reg("npm-mtu-blackhole", "NPM", "mtu-blackhole", "MTU blackhole / PMTUD failure (bulk flows stall to EXL-WEB2)",
     ((11, 30), (12, 10)), npm_mtu_blackhole, "small requests fine, but oversized DF segments are dropped and ICMP fragmentation-needed never lowers the MSS")

# OT / IoT — require the OT subnet enabled (inert otherwise); see the OT-visibility note in the GUI
_reg("ndr-ot-modbus-write", "NDR", "ot-modbus-write", "OT: unauthorized Modbus write / setpoint tampering (writes to a read-only PLC)",
     ((10, 0), (10, 40)), ndr_ot_modbus_write, "compromised EXL-OTENG1 issues Modbus WRITE function codes to PLCs that normally only serve READs. Requires the OT subnet")
_reg("ndr-ot-sis-tamper", "NDR", "ot-sis-tamper", "OT: safety-system (SIS) tampering (TRITON-shape writes to a safety controller)",
     ((11, 0), (11, 40)), ndr_ot_sis_tamper, "traffic to EXL-SIS-0x, which should essentially never be written to. Requires the OT subnet")
_reg("ndr-ot-zone-violation", "NDR", "ot-zone-violation", "OT: cross-Purdue zone violation (IT host talks straight to a Level-1 PLC)",
     ((9, 0), (9, 45)), ndr_ot_zone_violation, "a compromised IT host speaks Modbus directly to a PLC, bypassing the jump host that is the only permitted initiator into OT. Requires the OT subnet")
_reg("ndr-ot-recon", "NDR", "ot-recon", "OT: device enumeration (Modbus unit sweep, BACnet reads, DNP3 probes)",
     ((8, 30), (9, 15)), ndr_ot_recon, "the compromised jump host enumerates the OT asset set across Modbus/BACnet/DNP3. Requires the OT subnet")
_reg("ndr-ot-rogue-asset", "NDR", "ot-rogue-asset", "OT: rogue / previously-unseen device on the OT segment",
     ((13, 0), (13, 45)), ndr_ot_rogue_asset, "a new MAC/IP appears on the OT VLAN and polls a PLC as a Modbus master, where the asset set is supposed to be static. Requires the OT subnet")
_reg("ndr-ot-camera-beacon", "NDR", "ot-camera-beacon", "OT/IoT: IP camera outbound beacon (Mirai-shape egress)",
     ((8, 0), (17, 0)), ndr_ot_camera_beacon, "an IP camera that should only talk to the NVR beacons to an internet cloud. Requires the OT subnet")
_reg("npm-ot-plc-unresponsive", "NPM", "ot-plc-unresponsive", "OT: PLC unresponsive to supervisory polls (Modbus exceptions, then timeouts)",
     ((14, 0), (14, 40)), npm_ot_plc_unresponsive, "a PLC stops answering SCADA polls -- slave-busy exceptions then no reply and retransmits; loss of view. Requires the OT subnet")
# The healthy OT protocols parsed since 2026-10 (EtherNet/IP, S7comm, OPC UA, synchrophasor,
# ICCP/TASE.2) are NOT scenarios: they are OT-subnet protocol options emitted by the baseline OT
# day -- see netgen/model.py (Day.ot_ethernetip/ot_s7comm/ot_opcua/ot_synchrophasor/ot_iccp), gated
# by the OT protocol checkboxes, with synchrophasor/ICCP additionally gated to the Energy industry.

_reg("ndr-php2shell", "NDR", "php2shell", "php2shell PHP core RCE (CVE-2026-109618 / -109619): internet \u2192 internal PHP server",
     ((10, 20), (11, 15)), php2shell, "inbound HTTPS multipart POSTs to the portal web server (WEB3) (empty filename, nested names, PHP_SESSION_UPLOAD_PROGRESS), worker-crash RSTs and an oversized PHPSESSID memory leak, then a 200, the server's outbound callback and web-shell commands. Decrypts with the exported keys")
_reg("ndr-ot-sanctioned-writes", "NDR", "ot-sanctioned-writes",
     "OT: sanctioned operator setpoint writes + logons (BENIGN baseline for the control-writes table)",
     ((5, 45), (20, 0)), ndr_ot_sanctioned_writes,
     "BENIGN: sanctioned Modbus setpoint writes from SCADA/HMI to PLCs across the shift, a couple of "
     "benign OT NTLM logons, failed Kerberos pre-auths at shift change (mistyped password), and one "
     "after-hours engineer logon -- the normal baseline ndr-ot-modbus-write / ndr-ot-sis-tamper stand "
     "out against. Not a detection. Requires the OT subnet")
_reg("ndr-ot-new-pair", "NDR", "ot-new-pair",
     "OT: newly-seen pair (unknown engineering laptop appears in Zone 2 and polls+writes a PLC)",
     ((11, 0), (11, 45)), ndr_ot_new_pair,
     "a previously-unseen engineering laptop (new MAC/IP in the Zone-2 supervisory /24) announces "
     "itself by ARP, then reads a PLC it has never touched (Modbus) and finally writes a register -- "
     "a client->PLC pair the baseline never carried, escalating read->write. Requires the OT subnet")
_reg("ndr-ot-field-egress", "NDR", "ot-field-egress",
     "OT: egress from a field device (Zone-1 RTU resolves + beacons to the internet, rogue firmware)",
     ((15, 30), (17, 30)), ndr_ot_field_egress,
     "a Zone-1 field device resolves a first-seen internet domain and makes low-and-slow cleartext "
     "HTTP requests to an internet address (203.0.113.70) -- a rogue-firmware / implant tell; a "
     "control-zone asset has no reason to reach the internet. Requires the OT subnet")
_reg("ndr-ot-protocol-sweep", "NDR", "ot-protocol-sweep",
     "OT: short-burst protocol sweep (Level-3 host sweeps Level-1 with sub-second connections)",
     ((16, 15), (16, 20)), ndr_ot_protocol_sweep,
     "a Level-3 operations host sweeps Level-1 assets with sub-second connections -- Modbus cycling "
     "unit IDs across every PLC, then DNP3 probes across the RTUs; each probe is its own short-lived "
     "connection, so the signal is connection fan-out / churn (FLOW_CLASSIFY), which a flow-tick "
     "headline under-counts. Requires the OT subnet")
_reg("npm-nightly-backup", "NPM", "nightly-backup",
     "Diurnal shape: nightly backup window (bulk SMB from servers to the backup server)",
     ((19, 0), (20, 45)), npm_nightly_backup,
     "opt-in diurnal-shape add-on (never a baseline change): several Windows servers push bulk SMB "
     "backups to the backup server in a late-evening window, so a by-hour bytes view shows the expected "
     "nightly spike. Additive by design (a lunch dip cannot be a scenario)")

# CRP — crypto posture
_reg("crp-weak-tls", "CRP", "weak-tls", "Weak TLS (TLS 1.0 / RC4) on an internal service",
     ((7, 0), (15, 0)), crp_weak_tls, "clients negotiating TLS 1.0 RC4_SHA to legacy-intranet")
_reg("crp-expired-cert", "CRP", "expired-cert", "Expired / self-signed certificates on an internal service",
     ((7, 0), (15, 0)), crp_expired_cert, "backup-portal presents an expired or self-signed cert")
_reg("crp-plaintext-creds", "CRP", "plaintext-creds", "Plaintext credentials (HTTP Basic, FTP, LDAP simple bind)",
     ((7, 0), (15, 0)), crp_plaintext_creds, "credentials sent in the clear over HTTP/FTP/LDAP")
_reg("crp-anonymous-ftp", "CRP", "anon-ftp", "Anonymous FTP on a smart board (internal and inbound from the internet)",
     ((8, 17), (17, 30)), crp_anonymous_ftp,
     f"{FTP_BOARD} runs an unmanaged FTP server; {FTP_INTERNAL_SESSIONS} internal and "
     f"{FTP_EXTERNAL_SESSIONS} inbound anonymous sessions, all in clear text")

# IR -- Incident Replay: faithful real-world reconstructions. The builder lives in netgen.netscaler
# (imported here, after this module is otherwise defined, so its lazy `from netgen import incidents`
# inside build() never cycles). Pin-safe: hosts are injected in the builder, so an unselected build
# is unchanged (609,554).
from .netscaler import build as _netscaler_build       # noqa: E402
_reg("ir-netscaler-compromise", "IR", "netscaler-compromise",
     "NetScaler Compromise (webshell → beacon → DTLS → replay → exfil → LDAP SPN scan → SMB → reverse SSH)",
     ((14, 0), (16, 30)), _netscaler_build,
     "Faithful replay of a Citrix NetScaler/Gateway compromise: a gateway (VIP+SNIP), external "
     "attacker/workforce/C2/exfil hosts and nine attack phases over a benign portal day. Exactly one "
     "detection is designed to fire (LDAP SPN scan). Achievable fingerprint fidelity "
     "(HASSH/JA4S/workforce-JA4 hash-exact). Adds on top of the baseline, never alters the pin.")


# IR -- a SECOND NetScaler/Gateway incident (CVE-2026-88771), its own sibling package. A different
# offender exploits the same class of appliance, drops a webshell, beacons to its own C2, and pivots
# inward to the DC and the SQL server. Same lazy-import discipline; same pin-safe runtime injection.
from .netscaler88771 import build as _netscaler88771_build    # noqa: E402
_reg("ir-netscaler-cve88771", "IR", "netscaler-cve88771",
     "NetScaler CVE-2026-88771 (exploit → webshell → C2 beacon → LDAP SPN scan → SMB → TDS/MSSQL pivot)",
     ((11, 0), (13, 0)), _netscaler88771_build,
     "Pin-safe replay of a second Citrix NetScaler/Gateway compromise (CVE-2026-88771): an "
     "unauthenticated RCE drops a webshell on the Gateway, the SNIP beacons out on :8443 with "
     "first-seen C2 DNS (NXDOMAIN) and exfils the stolen ns.conf, then pivots inward -- a cleartext "
     "LDAP SPN scan to the DC, SMB session-setup fails, and a real TDS/MSSQL login to SQL1 "
     "(db + identity enumeration, blocked xp_cmdshell). Its own offender (203.0.113.88) and C2/exfil "
     "sinks, distinct from the first NetScaler replay; reuses the gateway identity and emitter toolkit. "
     "Decrypts with the exported keys; LDAP/SMB/TDS are cleartext and fully decodable")

# IR -- BeyondTrust Remote Support / PRA zero-day (CVE-2026-102764). A new internet-published
# appliance host is exploited via the origin-spoofed file-read/write bypass, then -- as a
# privileged-access broker -- originates admin protocols inward. Same lazy-import, pin-safe pattern.
from .beyondtrust102764 import build as _beyondtrust102764_build    # noqa: E402
_reg("ir-beyondtrust-cve102764", "IR", "beyondtrust-cve102764",
     "BeyondTrust CVE-2026-102764 (origin-spoofed file ops → webshell → C2 → inward RDP/SMB/LDAP pivot)",
     ((9, 0), (11, 0)), _beyondtrust102764_build,
     "Pin-safe replay of the BeyondTrust Remote Support / Privileged Remote Access zero-day "
     "(CVE-2026-102764, CVSS 9.3, ARMORY CASTLE / UNC5221, CISA KEV): an unauthenticated "
     "origin-spoofed request reads a secret off the published appliance (BTRS1) and writes a "
     "webshell, which beacons out on :8443 with first-seen C2 DNS (NXDOMAIN) and exfils the session "
     "store, then the appliance -- a privileged-access broker -- reaches INWARD: a cleartext LDAP "
     "SPN scan to the DC, SMB session-setup fails, RDP to the jump host MGMT1, and SSH to a "
     "server. A DMZ edge device originating admin protocols is the tell. Own offender (203.0.113.102) "
     "and C2/exfil sinks; reuses the NetScaler emitter toolkit. Decrypts with the exported keys")

# IR -- Metabase unauthenticated SQL-injection zero-day (CVE-2026-72898). A new published Metabase
# host is taken over via /reset_password SQLi, then exfils data from its connected backend SQL1.
from .metabase72898 import build as _metabase72898_build    # noqa: E402
_reg("ir-metabase-cve72898", "IR", "metabase-cve72898",
     "Metabase CVE-2026-72898 (unauth /reset_password SQLi → admin takeover → bulk TDS exfil from SQL1)",
     ((12, 0), (13, 30)), _metabase72898_build,
     "Pin-safe replay of the Metabase unauthenticated SQL-injection zero-day (CVE-2026-72898, "
     "CVSS 10.0, CISA KEV, exploited in the wild): an origin-observable SQLi POST to /reset_password "
     "takes over the published Metabase host (BI1) as admin, the admin API reads the stored "
     "connected-database credentials, then Metabase originates anomalous BULK TDS queries against "
     "its backend SQL1 and exports the pulled data to the attacker. Own offender (203.0.113.72); "
     "reuses the emitter toolkit and the TDS builders. Cleartext-in-TLS HTTP; cleartext, decodable TDS")

# IR -- SharePoint "ToolShell" deserialization RCE (CVE-2026-58644). A new published SharePoint host
# is taken via the ToolPane.aspx exploit (spinstall0.aspx webshell + MachineKey theft), then pivots
# to its content DB (SQL1) and the DC. Same lazy-import, pin-safe pattern.
from .sharepoint58644 import build as _sharepoint58644_build    # noqa: E402
_reg("ir-sharepoint-cve58644", "IR", "sharepoint-cve58644",
     "SharePoint ToolShell CVE-2026-58644 (ToolPane RCE → spinstall0 webshell + MachineKey theft → DB/DC pivot)",
     ((16, 30), (18, 0)), _sharepoint58644_build,
     "Pin-safe replay of the on-prem SharePoint Server deserialization RCE (CVE-2026-58644, CVSS 9.8, "
     "CISA KEV, 'ToolShell'): a POST to ToolPane.aspx with the tell-tale SignOut referer drops the "
     "spinstall0.aspx webshell on the published host (SP1), the farm MachineKey "
     "(ValidationKey/DecryptionKey) is stolen for forged-__VIEWSTATE RCE, the box beacons out on "
     ":8443 and exfils keys+documents, then pivots -- a content-DB TDS pull from SQL1, a "
     "cleartext LDAP SPN scan, and SMB to the DC. Own offender (203.0.113.58) and C2/exfil sinks; "
     "reuses the emitter + TDS/LDAP/SMB toolkit. Decrypts with the exported keys")

# IR -- PAN-OS GlobalProtect authentication bypass (CVE-2026-0257). A forged auth-override cookie on
# a new published gateway stands up an unauthorized VPN session; the attacker's VPN-assigned internal
# IP then does RDP/SMB/LDAP lateral movement. Same lazy-import, pin-safe pattern.
from .panos0257 import build as _panos0257_build    # noqa: E402
_reg("ir-panos-globalprotect-cve0257", "IR", "panos-globalprotect-cve0257",
     "PAN-OS GlobalProtect CVE-2026-0257 (forged auth-override cookie → unauthorized VPN → RDP/SMB/LDAP lateral)",
     ((7, 30), (9, 30)), _panos0257_build,
     "Pin-safe replay of the PAN-OS GlobalProtect authentication-bypass (CVE-2026-0257, CVSS 7.8, "
     "CISA KEV, ransomware: Qilin / Inc): the attacker forges an auth-override cookie on the published "
     "gateway (GPGW1) to stand up an UNAUTHORIZED VPN session and is assigned an internal VPN IP "
     "(VPN-7731). The twist is the pivot originates from that internal VPN IP, not the edge box: "
     "internal recon, a cleartext LDAP SPN scan, SMB probes of the DC and file server, and RDP into "
     "the jump host MGMT1 -- the ransomware precursor. Own offender (203.0.113.57); reuses the "
     "emitter toolkit and RDP/SMB/LDAP. Cleartext-in-TLS portal legs; observable internal movement")

# IR -- VMware vCenter Syslog-service traversal -> root RCE (CVE-2026-59310). A new vCenter host is
# taken via /etc/cron.d, dials reverse SSH out, and deploys ransomware to the ESXi hosts it manages.
from .vcenter59310 import build as _vcenter59310_build    # noqa: E402
_reg("ir-vcenter-cve59310", "IR", "vcenter-cve59310",
     "VMware vCenter CVE-2026-59310 (syslog traversal → cron RCE → reverse SSH → ESXi ransomware push)",
     ((18, 0), (19, 30)), _vcenter59310_build,
     "Pin-safe replay of the VMware vCenter Syslog-service directory-traversal → root RCE "
     "(CVE-2026-59310, CVSS 9.8, CISA KEV, Babuk-derived ESXi ransomware): a traversal writes a cron "
     "file into /etc/cron.d on the vCenter appliance (VC1), which dials reverse SSH out to the "
     "attacker, beacons on :8443 with first-seen C2 DNS, exfils the VM inventory, then drives every "
     "managed ESXi host (ESXI1/2) on the vSphere API (:443) and the agent port (:902) to deploy "
     "the ransomware. Own offender (203.0.113.59) and C2/exfil sinks; reuses the emitter toolkit and "
     "the OpenSSH HASSH flow. Cleartext-in-TLS HTTP; observable reverse-SSH and :902 control")

# IR -- WordPress Core upgrade-window race (CVE-2026-119977, CISA KEV 3 Nov 2026, fixed 7.1.4). A
# new WordPress site (WEB4) is updated; for a few seconds the staged installer is web-reachable
# under wp-content/upgrade/, and a scanner that lands inside the window completes setup-config.php
# with database settings pointing at an attacker-run MySQL server. Same lazy-import, pin-safe pattern.
from .wordpress_upgrade_race import build as _wordpress_upgrade_race_build    # noqa: E402
_reg("ir-wordpress-upgrade-race", "IR", "wordpress-upgrade-race",
     "WordPress upgrade-window race (CVE-2026-119977): staged setup-config.php -> rogue MySQL takeover",
     ((8, 0), (11, 0)), _wordpress_upgrade_race_build,
     "Pin-safe replay of the WordPress Core upgrade-window race (CVE-2026-119977, CISA KEV, fixed "
     "7.1.4): hours of background scanning for the staged installer under wp-content/upgrade/ "
     "(mostly 404), an admin-triggered core update and package download, then a short window (a "
     "few seconds, measured at build time) where the SAME polling GET returns 200 -- one scanner "
     "completes setup-config.php?step=2 with database settings pointing at an attacker-run MySQL "
     "server (WEB4 connects out on :3306 with a real MySQL handshake/login/query), the site is "
     "now wired to the attacker's database, and WEB4 keeps talking to it. Own offender/sinks "
     "(203.0.113.119-121, 198.51.100.119); a legitimate WEB4->DB4 MySQL leg and ordinary site "
     "visits are shipped as look-alikes. Cleartext HTTP; decodable MySQL wire protocol")


# IR -- Linux IPv4 TCP use-after-free race (CVE-2026-98432, Akamai / Red Hat RHSB-2026-016). Two internet
# sources spray one Linux host each with SYNs that carry IPv4 options and are retransmitted; the plain TCP
# listener never completes a handshake, the MPTCP listener loses one race (leak, payload, callback).
from .ipopt_tcp_uaf import build as _ipopt_tcp_uaf_build    # noqa: E402
_reg("ir-ipopt-tcp-uaf", "IR", "ipopt-tcp-uaf",
     "Linux IPv4 TCP use-after-free race (CVE-2026-98432): IP-options SYN retry spray -> MPTCP listener leak and callback",
     ((18, 0), (19, 30)), _ipopt_tcp_uaf_build,
     "Pin-safe replay of the Linux IPv4 TCP use-after-free race (CVE-2026-98432): two internet sources spray one "
     "Linux host each for about 50 minutes with SYNs that carry IPv4 options (Record Route, Timestamp, DF set) and "
     "are retransmitted with the same source port and sequence number. LNX1 (plain TCP listener, tcp/8443) never "
     "completes a handshake with its attacker; LNX2 (Go MPTCP listener, tcp/9000, MP_CAPABLE) loses one race: the "
     "winning SYN-ACK carries extra bytes in its IP options (ASSUMED), the attacker sends one small payload, and "
     "LNX2 calls back out to the attacker on a high port (ASSUMED). Own offenders (203.0.113.140-141); option-free "
     "clients, plain SYN retransmits, a partner MPTCP client and a one-off option-bearing scanner ship as look-alikes. "
     "The retransmit gap, the attacker's RSTs, the rate and the leak are modelling choices, not documented signatures")


# Baseline traffic that is ALWAYS in the capture and is NOT selectable. These are display-only
# descriptors: they are deliberately not in REGISTRY, because the builders already run
# unconditionally (Day.smartboards()). Putting one in REGISTRY would build it a second time.
# The GUI pins them into their category group; select_modules() refuses them by name.
BASELINE_MODULES = {
    "baseline-mcp": {
        "prefix": "NPM", "title": "Smart board MCP server (vendor update, then agent traffic)",
        "note": "all 4 boards poll the vendor; EXL-SB-02 updates at 10:15 and serves MCP on :3000",
        "window": ((10, 15), (21, 0)),
        "why": "part of the normal business day \u2014 scheduled by Day.smartboards()",
        "accent": "#15803D",
    },
    # Shown only when the OT subnet is enabled -- `ot_only` is what the selector and the
    # timeline filter on. Its window is the WHOLE capture, unlike every scenario and unlike
    # baseline-mcp, because a process does not keep office hours.
    "baseline-ot": {
        "prefix": "OT", "title": "OT / IoT baseline \u2014 Purdue levels 0\u20133.5",
        "note": "Modbus 2 s, DNP3 10 s, BACnet 45 s; level 3 operations and the IDMZ; "
                "one jump host crosses in",
        "window": ((5, 0), (21, 0)),
        "why": "part of the normal day for a plant \u2014 scheduled by Day.ot_control() and its "
               "four siblings; present whenever the OT subnet is on",
        "accent": "#1D4ED8",
        "ot_only": True,
    },
}


def baseline_modules(ot=None):
    """Display descriptors for always-on baseline traffic, shaped like REGISTRY entries.

    `ot` selects what the caller wants back: True includes the OT row, False excludes it, and
    None (the default) returns everything with `ot_only` on the row so the caller can decide.
    The selector in the GUI takes the third form -- it renders the row hidden and reveals it
    when the OT checkbox is ticked, because the page is built once and the checkbox moves.
    """
    out = []
    for name, m in BASELINE_MODULES.items():
        if ot is False and m.get("ot_only"):
            continue
        (h1, m1), (h2, m2) = m["window"]
        out.append({"name": name, "prefix": m["prefix"], "title": m["title"], "note": m["note"],
                    "window": f"{h1:02d}:{m1:02d}\u2013{h2:02d}:{m2:02d}",
                    "start": h1 * 60 + m1, "end": h2 * 60 + m2,
                    "pinned": True, "why": m["why"],
                    "accent": m.get("accent", "#15803D"), "ot_only": bool(m.get("ot_only"))})
    return out


def resolve_window(win_hm):
    from .model import local
    (h1, m1), (h2, m2) = win_hm
    return (local(h1, m1), local(h2, m2))


# --------------------------------------------------------------- timing shifts
# The owner can slide a scenario along the capture day. A shift is whole minutes added to the
# scenario's window; every builder takes its times from `win`, so the scenario moves as a block and
# its content is unchanged. SHIFTS is set for the duration of one build (opengenerator_build) and
# is empty otherwise, which keeps the default build byte-for-byte what it was.
SHIFTS = {}
CAPTURE_MIN = (5 * 60, 21 * 60)            # the 16 hours of traffic, minutes after midnight
SHIFT_LEAD_MIN, SHIFT_TAIL_MIN = 2, 5      # a scenario's lead-in events and tail flows stay inside the capture
SHIFT_LOCKED = {                           # meaning tied to the baseline clock, or no window of its own
    "ndr-ot-sanctioned-writes": "tied to the baseline's shift changes",
    "custom-import": "driven by its recipe, not a window",
    "campaign": "its start time is set in the campaign's own Start option",
}
SHIFT_LIMITS = {                           # tighter than the capture bounds: these only read right near their hours
    "npm-nightly-backup": (-90, 10),
    "crp-weak-tls": (-30, 60),
    "crp-expired-cert": (-30, 60),
    "crp-plaintext-creds": (-30, 60),
}
SHIFT_PAIRS = (                            # one story across two scenarios: they always move together
    ("npm-fw-update", "ndr-edge-exploit"),
    ("npm-tcp-loss-storm", "ndr-salt-typhoon"),
)


def _window_min(name):
    (h1, m1), (h2, m2) = REGISTRY[name].window
    return h1 * 60 + m1, h2 * 60 + m2


def shift_limits(name):
    """(min, max) whole minutes a scenario may move, or None when it is locked."""
    if name in SHIFT_LOCKED:
        return None
    lo, hi = _window_min(name)
    dmin = CAPTURE_MIN[0] + SHIFT_LEAD_MIN - lo
    dmax = CAPTURE_MIN[1] - SHIFT_TAIL_MIN - hi
    if name in SHIFT_LIMITS:
        dmin, dmax = max(dmin, SHIFT_LIMITS[name][0]), min(dmax, SHIFT_LIMITS[name][1])
    return min(dmin, 0), max(dmax, 0)


def shift_partner(name):
    for a, b in SHIFT_PAIRS:
        if name == a:
            return b
        if name == b:
            return a
    return None


def normalize_shifts(raw, selected):
    """Validate a {scenario: minutes} request against the selected scenarios and return the
    effective shifts (zeros dropped, partners of a linked pair filled in). Raises ValueError with
    a message fit to show the owner; nothing is silently clamped."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("'shifts' must be an object of scenario name to whole minutes")
    sel = set(selected)
    out = {}
    for name, d in raw.items():
        if isinstance(d, bool) or not isinstance(d, int):
            raise ValueError("shift for %r must be a whole number of minutes" % name)
        if name not in REGISTRY or name not in sel:
            raise ValueError("cannot shift %r: it is not a selected scenario" % name)
        if name in SHIFT_LOCKED:
            raise ValueError("%r cannot be moved: %s" % (name, SHIFT_LOCKED[name]))
        if d:
            out[name] = d
    for name in list(out):
        partner = shift_partner(name)
        if partner and partner in sel and partner not in SHIFT_LOCKED:
            if out.get(partner, out[name]) != out[name]:
                raise ValueError("%r and %r always move together; give them the same shift" % (name, partner))
            out[partner] = out[name]
    for name, d in out.items():
        lim = shift_limits(name)
        if not lim[0] <= d <= lim[1]:
            raise ValueError("%r can move between %+d and %+d minutes, not %+d" % (name, lim[0], lim[1], d))
    return out


def set_shifts(shifts):
    """Install the effective shifts for the build in progress ({} restores the default day)."""
    SHIFTS.clear()
    SHIFTS.update(shifts or {})


def window_for(name, shifts=None):
    """The scenario's absolute (lo, hi) with its shift applied."""
    lo, hi = resolve_window(REGISTRY[name].window)
    d = (SHIFTS if shifts is None else shifts).get(name, 0) * 60
    return lo + d, hi + d


def _isolate_scheduling(eng, name):
    """While a shifted build is scheduling `name`, run each of its flows on its own random
    streams (seeded from the scenario and the flow's position) and put the shared streams back
    afterwards. Without this a scenario moved in time changes the draws every later flow sees,
    so the rest of the day would shift in content too. Returns the undo."""
    import zlib
    gens = _isolated_rng()[0]
    seed0, count, orig = zlib.crc32(name.encode()), [0], eng.schedule

    def schedule(ts, factory, tag="misc"):
        count[0] += 1
        k = count[0]

        def run():
            saved = [g.getstate() for g in gens]
            for i, g in enumerate(gens):
                g.seed(zlib.crc32(("%d:%d:%d" % (seed0, k, i)).encode()))
            try:
                return list(factory())             # draw now, while the streams are ours
            finally:
                for g, st in zip(gens, saved, strict=False):
                    g.setstate(st)
        orig(ts, run, tag)
    eng.schedule = schedule
    return lambda: eng.__dict__.pop("schedule", None)


def build(name, day, ctx, eng, tag=None):
    inc = REGISTRY[name]
    tag = tag or f"incident:{name}"
    win = window_for(name)
    undo = _isolate_scheduling(eng, name) if SHIFTS else None
    try:
        inc.builder(ctx, eng, tag, win)      # npm-sql1 derives its own timeline from the window start
    finally:
        if undo:
            undo()


# --------------------------------------------------------------- identity relabel
# Every module-level constant above that embeds a company token (host prefix, DNS domain,
# web-app namespace, org) is written in the TEMPLATE identity's tokens (Example Logistics /
# EXL- / corp.example.local). For a non-default company these are re-derived from a one-time
# template snapshot: apply_identity() rewrites each constant's tokens to the build's identity,
# so the incident scenarios speak the same company's names as the rest of the capture. Inline
# host references resolve live through H()/get_current() and need no snapshot.
_IDENTITY_CONSTANTS = [
    "ADCS_CA", "ATTACKER_WS", "BASELINE_MODULES", "CRP_CERT_HOST", "CRP_PLAINTEXT",
    "CRP_WEAK_TLS_HOST", "C_BEACHHEAD", "C_COLLECTOR", "C_PIVOT", "DEAD_APS", "DEAD_AP_CLIENTS",
    "EDGE_INWARD", "ESC8_VICTIM", "EXFIL_STAGING", "FTP_BOARD", "FTP_CLIENT_WS",
    "KERBEROAST_SPNS", "LATERAL_PLAN", "LATERAL_SECOND_HOST", "NEEDY_LATERAL", "NEEDY_TARGETS",
    "NEEDY_WS", "PQC_LEGACY", "PQC_LEGACY_SRV", "PQC_MODERN", "PQC_READY_SRV", "RANSOM_TARGETS",
    "RA_AUTH", "RA_DB", "RA_WEB", "RECON_OPEN", "SALT_DEVICES", "VICTIM_SERVERS", "VOLT_TARGETS",
    "PHP2SHELL_CMD_OUTPUTS", "PHP2SHELL_HOST", "PQC_PROFILE", "CRP_CERT_HOST2", "WEBSHELL_CMDS", "WEBSHELL_HOST", "_SQL1_ASP_ERROR", "_SQL1_WEB_MSGS_DEGRADE",
    "_SQL1_WEB_MSGS_OUTAGE",
]
_TEMPLATES = {}


def _token_pairs(ident):
    # Longest / most-specific first; each maps a TEMPLATE token to the build identity's.
    return [(_TEMPLATE.domain, ident.domain),
            (_TEMPLATE.namespace, ident.namespace),
            (_TEMPLATE.org, ident.org),
            (_TEMPLATE.prefix, ident.prefix),
            (_TEMPLATE.prefix.lower(), ident.prefix.lower())]


def _relabel(obj, ident):
    if isinstance(obj, str):
        for a, b in _token_pairs(ident):
            if a != b:
                obj = obj.replace(a, b)
        return obj
    if isinstance(obj, bytes):
        for a, b in _token_pairs(ident):
            if a != b:
                obj = obj.replace(a.encode(), b.encode())
        return obj
    if isinstance(obj, tuple):
        return tuple(_relabel(x, ident) for x in obj)
    if isinstance(obj, list):
        return [_relabel(x, ident) for x in obj]
    if isinstance(obj, set):
        return {_relabel(x, ident) for x in obj}
    if isinstance(obj, dict):
        return {_relabel(k, ident): _relabel(v, ident) for k, v in obj.items()}
    return obj


def _capture_templates():
    if _TEMPLATES:
        return
    g = globals()
    for n in _IDENTITY_CONSTANTS:
        _TEMPLATES[n] = g[n]


def apply_identity(identity=None):
    """Re-derive the module-level identity-bearing constants for the build's identity (called
    from netgen.reseed_all). A no-op for the default (template) identity."""
    ident = identity or get_current()
    _capture_templates()
    g = globals()
    for n in _IDENTITY_CONSTANTS:
        g[n] = _relabel(_TEMPLATES[n], ident)


_capture_templates()

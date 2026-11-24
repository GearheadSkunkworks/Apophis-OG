"""netgen.netscaler -- the "NetScaler Compromise" incident-replay scenario.

A built-in selectable scenario (``ir-netscaler-compromise``, category "Incident Replay"),
registered in netgen.incidents like every other scenario. It was first built as a capability
module and moved in-tree so it is selectable from the scenario grid without loading anything.

A faithful, selectable reconstruction of the Citrix NetScaler/Gateway compromise described in the
companion spec (INCIDENT_REPLAY_SPEC.md): webshell C2, an outbound TCP beacon, a DTLS probe/burst,
a stolen-session replay, first-seen C2 DNS (NXDOMAIN), cleartext config exfiltration, cleartext
LDAP enumeration ending in an SPN scan (the ONE detection the capture is built to fire), failed SMB
session-setups, and an SSH test + reverse-SSH persistence -- interleaved with benign portal traffic.

DESIGN DECISIONS:
  * Addressing is REMAPPED into the OpenGenerator framework: the gateway lives on the monitored
    server segment (VIP/SNIP share one MAC), DCs/app reuse the baseline estate, and the attacker /
    workforce / C2 / exfil hosts are external documentation-range IPs. The attack *content* (UAs,
    URIs, C2 domains, the SPN filter, enumerated accounts, OpenSSH/curl versions, the one detection)
    is kept verbatim so every record reads true. the documented counts reproduce; the literal source 5-tuples
    do not (that was the accepted trade for staying in-framework).
  * ACHIEVABLE fingerprint fidelity (see ja4.py). Hash-exact and asserted in self_test: client &
    server HASSH, JA4S, the workforce JA4 (a+b), and every JA4/JA4H readable prefix. NOT hash-exact
    (one-way hashes whose preimages the spec never gives): the implant JA4 cipher-hash, the JA4_c
    component, cert SHA-1/SHA-256 & literal JA4X509, and the literal stolen-cookie JA4H hashes --
    those are reproduced structurally, and the decisive *same-cookie-two-clients* signal relationally.

PIN-SAFE (the hard rule -- a scenario may only ADD, never ALTER the baseline): every host is injected
into ``ctx.h`` INSIDE the scenario builder, which runs only when the scenario is selected and only
after ``day.build()`` has scheduled the normal day over the original inventory. A build that does not
select this scenario still pins at 466,343.
"""
from netgen import identity as ID
from netgen import protocols as P
from netgen.core import Host

from . import phases
from . import nsconf

def _host(ctx, suffix):
    """The build identity's hostname for a role suffix, e.g. 'DC1' -> 'EXL-DC1' (or 'ACM-DC1')."""
    return ID.get_current().host(suffix)


# ---- remapped topology --------------------------------------------------------------------
_GW_MAC = "00:50:56:bb:02:3d"                       # one device, two interfaces share a MAC
_VIP_SUFFIX, _VIP_IP = "CAG1-VIP", "10.10.20.51"    # gateway external face (portal VIP), monitored
_SNIP_SUFFIX, _SNIP_IP = "CAG1", "10.10.20.52"      # gateway internal face (NetScaler SNIP)
# external hosts: (fqdn, ip, hops)
_EXTERNAL = {
    "attacker": ("node74.probe-pool.example", "198.51.100.74", 10),   # offender / webshell op / DTLS / replay
    "beacon":   ("sync.beacon-cloud.example", "192.0.2.21", 12),      # TCP 8443 heartbeat sink
    "exfil":    ("cdn-acme-updates.com",      "192.0.2.22", 14),      # HTTP PUT exfil sink (IOC domain kept)
    "ndrapi":   ("eh-lab.securityintersect.com", "192.0.2.23", 11),   # pre-window curl probe target
    "wfA":      ("host-a.remote.example",     "198.51.100.31", 7),    # owns the hijacked session
    "wfB":      ("host-b.remote.example",     "198.51.100.32", 7),
    "wfC":      ("host-c.remote.example",     "198.51.100.33", 7),
    "wfD":      ("host-d.remote.example",     "198.51.100.34", 7),
}


def _inject_hosts(ctx):
    """Add the gateway's two faces (shared MAC) and the external actors. Pin-safe: runs in the
    builder, so the baseline day (built from the inventory before this) never sees them."""
    domain = P.DOMAIN
    snip_name, vip_name = _host(ctx, _SNIP_SUFFIX), _host(ctx, _VIP_SUFFIX)
    if snip_name not in ctx.h:
        ctx.h[snip_name] = Host(snip_name, ctx.link.place(_SNIP_IP), _GW_MAC, "freebsd netscaler",
                                "NetScaler SNIP (gateway mgmt)", ctx.link.server_net,
                                "netscaler." + domain)
        ctx.h[vip_name] = Host(vip_name, ctx.link.place(_VIP_IP), _GW_MAC, "freebsd netscaler",
                               "Citrix Gateway VIP (portal)", ctx.link.server_net,
                               "vpn." + domain)
    cache = ctx.__dict__.setdefault("_ns_ext", {})
    for key, (fqdn, ip, hops) in _EXTERNAL.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip,
                     "02:00:5e:%02x:%02x:%02x" % (phases.rng.randrange(256), phases.rng.randrange(256), phases.rng.randrange(256)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    return cache


# ---- the incident schedule ------------------------------------------------------------
# Webshell observed request log : (h, m, s, asset_key, command)
_WEBSHELL_LOG = [
    (14, 0, 41, "logo", "ls /var/vpn/scripts/"), (14, 4, 31, "theme", "whoami"),
    (14, 9, 51, "whip", "ls /var/vpn/scripts/"), (14, 15, 35, "theme", "netstat -tlnp"),
    (14, 21, 3, "boot", "cat /netscaler/ns.conf"), (14, 26, 13, "boot", "netstat -tlnp"),
    (14, 41, 52, "theme", "netstat -tlnp"), (14, 52, 4, "boot", "ls /var/vpn/scripts/"),
    (14, 57, 32, "theme", "uname -a"), (15, 7, 1, "logo", "uname -a"),
    (15, 10, 54, "logo", "uname -a"), (15, 16, 15, "theme", "whoami"),
    (15, 21, 36, "whip", "cat /netscaler/ns.conf"), (15, 27, 17, "theme", "whoami"),
    (15, 32, 32, "theme", "id"), (15, 42, 39, "whip", "id"),
    (15, 56, 1, "logo", "netstat -tlnp"), (16, 10, 19, "whip", "ls /var/vpn/scripts/"),
    (16, 14, 41, "whip", "ls /var/vpn/scripts/"), (16, 20, 21, "whip", "id"),
    (16, 24, 55, "logo", "whoami"),
]
# LDAP enumeration schedule: (h, m, s) aligned to phases._ENUM order
_LDAP_TIMES = [(16, 0, 34), (16, 0, 38), (16, 0, 40), (16, 0, 42), (16, 0, 46), (16, 0, 49),
               (16, 0, 52), (16, 0, 55), (16, 0, 59), (16, 1, 2), (16, 1, 3), (16, 1, 7),
               (16, 1, 10), (16, 1, 13)]


def build(ctx, eng, tag, win):
    """Schedule the full incident at the exact relative offsets of the source incident, rebased into the capture
    day. Signature-critical records (DTLS, the 14 LDAP searches + SPN scan, the exfil PUT, the SMB
    fails, SSH, the 6 replay GETs, 2 C2 DNS) are always emitted; beacon cadence and benign portal
    volume scale with ctx.scale. Registered as the ``ir-netscaler-compromise`` scenario in
    netgen.incidents (incidents imports this lazily to avoid a cycle)."""
    from netgen import incidents as INC
    ext = _inject_hosts(ctx)
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    day0 = lo - 14 * 3600                              # midnight of the capture day (window opens 14:00)
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))
    ident = ID.get_current()

    def at(h, m, sec=0.0):
        return day0 + h * 3600 + m * 60 + sec

    vip = ctx.h[ident.host(_VIP_SUFFIX)]
    snip = ctx.h[ident.host(_SNIP_SUFFIX)]
    dc1 = ctx.h.get(ident.host("DC1"))
    dc2 = ctx.h.get(ident.host("DC2"))
    app = ctx.h.get(ident.host("WEB1"))
    atk, beacon, exfil = ext["attacker"], ext["beacon"], ext["exfil"]
    ndrapi = ext["ndrapi"]
    wf = [ext["wfA"], ext["wfB"], ext["wfC"], ext["wfD"]]

    # ---- Phase 1: webshell (implant) -- the observed log -----------------------------------
    for h, m, sec, asset, cmd in _WEBSHELL_LOG:
        s(at(h, m, sec), phases.webshell_beacon, atk, vip, cmd, asset)

    # ---- pre-window NDR-API probe (context) ------------------------------------------------
    s(at(14, 53, 28), phases.ndr_api_probe, vip, ndrapi)

    # ---- Phase 2: outbound C2 beacon (15:44:38 onward, every ~60-100s) ---------------------
    t, counter = at(15, 44, 38), 1
    while t < hi:
        s(t, phases.c2_beacon, snip, beacon, counter)
        counter += 1
        t += phases.rng.uniform(60, 100)

    # ---- Phase 3: DTLS probe + burst -------------------------------------------------------
    s(at(15, 49, 27.798), phases.dtls_probe, atk, vip)
    s(at(15, 55, 8.569), phases.dtls_burst, atk, vip)

    # ---- Phase 5: first-seen C2 DNS (NXDOMAIN) ---------------------------------------------
    if dc1 is not None:
        s(at(15, 56, 25.769), phases.c2_dns, snip, dc1, "c2-acme-updates.com")
        s(at(16, 0, 6.158), phases.c2_dns, snip, dc1, "cdn-acme-updates.com")

    # ---- Phase 4: portal session replay (two-network cookie overlap) -----------------------
    s(at(15, 56, 51), phases.portal_legit, wf[0], vip)       # legit owner, same cookie
    s(at(15, 58, 33), phases.portal_replay, atk, vip)        # attacker replays it

    # ---- Phase 6: config exfiltration (cleartext HTTP PUT, ~200KB) -------------------------
    body = nsconf.ns_conf(vip=vip.ip, snip=snip.ip, domain=P.DOMAIN,
                       server_pfx=".".join(str(b) for b in ctx.link.fw_b.ipb[:3]))
    s(at(16, 0, 6.176), phases.config_exfil, snip, exfil, body)

    # ---- Phase 7: LDAP enum + SPN scan (389) + routine LDAPS 636 contrast ------------------
    if dc1 is not None:
        s(at(15, 45, 1), phases.ldaps_routine, snip, dc1)    # routine baseline bind (contrast)
        t0 = at(*_LDAP_TIMES[0])
        s(t0, phases.ldap_enum_run, snip, dc1, phases._ENUM, [at(*t) - t0 for t in _LDAP_TIMES])

    # ---- Phase 8: SMB session-setup fails to both DCs --------------------------------------
    if dc1 is not None:
        s(at(16, 1, 20.714), phases.smb_fail, snip, dc1)
    if dc2 is not None:
        s(at(16, 1, 21.586), phases.smb_fail, snip, dc2)

    # ---- Phase 9: SSH test + reverse SSH persistence ---------------------------------------
    if app is not None:
        s(at(16, 1, 39.882), phases.ssh_test, snip, app)
        s(at(16, 3, 16.291), phases.ssh_reverse, app, snip)

    # ---- benign interleave: workforce portal traffic across the window ----------
    labels = ["A", "B", "C", "D"]
    for client, label in zip(wf, labels, strict=False):
        visits = max(2, int(round(14 * scale)))
        for _ in range(visits):
            s(lo + phases.rng.uniform(0, max(1.0, hi - lo - 60)), phases.portal_browse, client, vip, label)

"""Discovery actions: scans and enumeration (ATT&CK tactic "discovery").

Every action here is network *behaviour* for exercising a network sensor: probes, handshakes and
directory/share queries with dummy data. Nothing here carries an exploit, a payload or a working tool.

Shared helpers used by access.py and lateral.py live in this module too (``deterministic``,
``is_external``, ``vantage_for``, ``arp_between``, ``own_user``, ``account_names``).
"""
import struct

from . import ActionSpec, register
from ... import flows as F
from ... import protocols as P
from ...core import Host, TcpSession, SYN, ACK, RST, eth, ipv4, arp, ETH_IP, rng

# --------------------------------------------------------------------------- shared helpers


from . import deterministic  # noqa: E402,F401  (shared; register() also applies it)


def is_external(ctx, h):
    """True for an internet-side host (no gateway on the enterprise link model)."""
    return getattr(h, "role", "") == "external" or ctx.link.gateway_for(h) is None


def vantage_for(ctx, src, dst):
    """The host whose segment the frames are captured on: the internal side of the flow."""
    return dst if is_external(ctx, src) else src


def arp_between(ctx, src, dst, ts):
    """ARP resolution only when both ends sit on the enterprise link model."""
    if is_external(ctx, src) or is_external(ctx, dst):
        return []
    return ctx.arp_for(src, dst, ts)


def own_user(src):
    return P.username_for(src.name)


def account_names(ctx, n, kind="users"):
    """Up to n account names from the build's account directory (deterministic order)."""
    d = getattr(ctx, "dir", None)
    names = []
    if d is not None:
        names = [a.name for a in getattr(d, kind, [])]
    if not names:
        names = sorted({P.username_for(h.name) for h in ctx.h.values()
                        if "workstation" in getattr(h, "role", "").lower()})
    return names[:n]


# --------------------------------------------------------------------------- scan plumbing
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 636, 1433, 3306, 3389, 5985, 8080]
SERVICE_PORTS = [22, 80, 135, 139, 443, 445, 3389]


def _is_open(h, port):
    """Which ports a host answers on, from its OS and role (stable, no randomness)."""
    os_, role = h.os.lower(), h.role.lower()
    if "windows" in os_:
        ports = {135, 139, 445}
        if "workstation" not in role:
            ports |= {3389, 5985}
        if "domain" in role or "controller" in role or h.name.endswith("DC1") or h.name.endswith("DC2"):
            ports |= {53, 88, 389, 636}
    elif "linux" in os_ or "unix" in os_:
        ports = {22}
    else:
        ports = set()
    if "web" in role or "server" in role:
        ports |= {80, 443}
    if "sql" in role or "database" in role:
        ports |= {1433}
    return port in ports


def _scan_hosts(ctx, dst, scope, max_hosts, targets):
    """Hosts a scan covers. targets (list of IPv4 strings) wins; scope 'host' = only dst; 'subnet' =
    dst plus the build's hosts in its /24, dst first."""
    pool = list(ctx.h.values())
    if targets:
        want = [str(t) for t in targets]
        out = [h for h in pool if h.ip in want]
        return out[:max_hosts] or [dst]
    if scope == "host":
        return [dst]
    same = sorted((h for h in pool if h.ipb[:3] == dst.ipb[:3] and h.ip != dst.ip), key=lambda h: h.ipb)
    return ([dst] + same)[:max_hosts]


def _absent_hosts(ctx, anchor, n):
    """n unoccupied addresses in anchor's /24, as throwaway Host objects (they never answer)."""
    taken = {h.ip for h in ctx.h.values()}
    pre = anchor.ip.rsplit(".", 1)[0]
    out = []
    last = 200
    while len(out) < n and last > 1:
        ip = "%s.%d" % (pre, last)
        last -= 3
        if ip in taken:
            continue
        mac = "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3))
        h = Host("ABSENT%d" % len(out), ip, mac, "linux", "absent", anchor.subnet, "")
        out.append(h)
    return out


def _syn_probe(ctx, src, host, port, t, sport, vant, is_open, complete_open=False):
    """One SYN probe: SYN -> SYN/ACK + RST (open, half-open) or RST/ACK (closed)."""
    s = TcpSession(ctx.link, src, host, port, t, sport=sport, vantage=vant)
    seq = s.cseq
    copts = struct.pack("!BBH", 2, 4, 1460) + b"\x01\x03\x03\x08\x01\x01\x04\x02"
    s._emit(src, host, sport, port, seq, 0, SYN, 64240, b"", copts)
    s.t += s.rtt * rng.uniform(0.5, 1.5)
    if is_open:
        sopts = struct.pack("!BBH", 2, 4, 1460) + b"\x01\x01\x04\x02"
        s._emit(host, src, port, sport, s.sseq, seq + 1, SYN | ACK, 65535, b"", sopts)
        s.t += rng.uniform(0.0005, 0.003)
        if complete_open:
            s._emit(src, host, sport, port, seq + 1, s.sseq + 1, ACK, 64240)
            s.t += rng.uniform(0.001, 0.01)
            s._emit(src, host, sport, port, seq + 1, s.sseq + 1, RST | ACK, 0)
        else:
            s._emit(src, host, sport, port, seq + 1, 0, RST, 0)
    else:
        s._emit(host, src, port, sport, 0, seq + 1, RST | ACK, 0)
    return s.drain()


# --------------------------------------------------------------------------- syn_scan
@deterministic
def syn_scan(ctx, src, dst, *, ts, ports=None, scope="subnet", max_hosts=12, targets=None, rate=250.0,
             complete_open=False):
    """TCP SYN sweep. On the wire: for every (host, port) one SYN from a single scanner source port;
    closed ports answer RST/ACK, open ports answer SYN/ACK and the scanner sends a bare RST."""
    ports = [int(p) for p in (ports or SERVICE_PORTS)]
    hosts = _scan_hosts(ctx, dst, scope, int(max_hosts), targets)
    vant = vantage_for(ctx, src, dst)
    out, t = [], ts
    sport = src.eph()
    per = 1.0 / max(1.0, float(rate))
    pairs = [(h, p) for h in hosts for p in ports]
    arped = set()
    for h, port in pairs:
        if h.ip not in arped:
            arped.add(h.ip)
            out += arp_between(ctx, src, h, t)
        out += _syn_probe(ctx, src, h, port, t, sport, vant, _is_open(h, port), bool(complete_open))
        t += per * rng.uniform(0.4, 1.8)
    return F.merged(out)


# --------------------------------------------------------------------------- icmp_sweep
def _icmp_frame(ctx, a, b, vant, t, ident, seq, request):
    dmac, smac, ttl = ctx.link.addr(a, b, vant)
    return (t, eth(dmac, smac, ETH_IP, ipv4(a, b, 1, P.icmp_echo(ident, seq, request, payload=b""), ttl=ttl)))


@deterministic
def icmp_sweep(ctx, src, dst, *, ts, scope="subnet", max_hosts=16, targets=None, absent=3, rate=100.0):
    """ICMP echo sweep. On the wire: one echo request per address (single identifier, rising sequence,
    empty payload); live hosts reply, absent addresses stay silent (an unanswered ARP on the local segment)."""
    hosts = [h for h in _scan_hosts(ctx, dst, scope, int(max_hosts), targets)]
    vant = vantage_for(ctx, src, dst)
    ghosts = _absent_hosts(ctx, dst, int(absent)) if int(absent) > 0 else []
    order = [(h, True) for h in hosts] + [(h, False) for h in ghosts]
    rng.shuffle(order)
    out, t = [], ts
    ident = rng.randint(1, 65535)
    per = 1.0 / max(1.0, float(rate))
    for n, (h, live) in enumerate(order, 1):
        if live:
            out += arp_between(ctx, src, h, t)
        elif not is_external(ctx, src) and h.ipb[:3] == src.ipb[:3]:
            # nobody holds the address: the ARP request goes unanswered (three tries), no echo is ever sent
            for k in range(3):
                out.append((t + k * 1.0, eth(b"\xff" * 6, src.mac, 0x0806,
                                             arp(1, src.mac, src.ipb, b"\x00" * 6, h.ipb))))
            t += 0.05
            continue
        out.append(_icmp_frame(ctx, src, h, vant, t, ident, n, True))
        if live:
            out.append(_icmp_frame(ctx, h, src, vant, t + rng.uniform(0.0004, 0.002), ident, n, False))
        t += per * rng.uniform(0.4, 1.8)
    return F.merged(out)


# --------------------------------------------------------------------------- port_probe
@deterministic
def port_probe(ctx, src, dst, *, ts, ports=None, gap_s=0.8):
    """A handful of connect() probes to one host's service ports. On the wire: a full three-way
    handshake then an immediate FIN for open ports; SYN then RST/ACK for closed ones."""
    ports = [int(p) for p in (ports or SERVICE_PORTS)]
    vant = vantage_for(ctx, src, dst)
    out, t = arp_between(ctx, src, dst, ts), ts
    for port in ports:
        if _is_open(dst, port):
            s = TcpSession(ctx.link, src, dst, port, t + 0.001, vantage=vant).handshake()
            out += s.close(think=rng.uniform(0.001, 0.02))
        else:
            out += _syn_probe(ctx, src, dst, port, t, src.eph(), vant, False)
        t += float(gap_s) * rng.uniform(0.3, 1.6)
    return F.merged(out)


# --------------------------------------------------------------------------- ldap_recon
_GROUPS = ["Domain Admins", "Domain Users", "Enterprise Admins", "Backup Operators", "Server Operators",
           "IT-Support", "Finance-Users", "Remote Desktop Users"]


def _paged(s, mid, base, filt, attrs, entries, page, scope=2):
    """One paged search (RFC 2696): request with the paged control, then one response per page."""
    cookie = b""
    pages = [entries[i:i + page] for i in range(0, len(entries), page)] or [[]]
    for i, chunk in enumerate(pages):
        s.c2s(P.ldap_search_request(mid, base, scope, filt, attrs, controls=P.ldap_paged_control(page, cookie)),
              think=rng.uniform(0.002, 0.04))
        cookie = b"" if i == len(pages) - 1 else struct.pack("!I", rng.getrandbits(32)) + b"\x00\x00\x00\x00"
        body = b"".join(P.ldap_search_entry(mid, dn, at) for dn, at in chunk)
        s.s2c(body + P.ldap_search_done(mid, controls=P.ldap_paged_control(0, cookie)),
              think=rng.uniform(0.002, 0.02))
        mid += 1
    return mid


@deterministic
def ldap_recon(ctx, src, dst, *, ts, max_entries=40, page_size=20):
    """LDAP enumeration of the directory. On the wire: Kerberos service ticket for ldap/, GSS-SPNEGO
    bind, a rootDSE search, then paged searches for users, groups and computers."""
    pre, t = F.kerberos_tgs(ctx, src, "ldap", dst, ts)
    out = arp_between(ctx, src, dst, t)
    user = own_user(src)
    s = TcpSession(ctx.link, src, dst, 389, t + 0.001, vantage=vantage_for(ctx, src, dst)).handshake()
    mid = 1
    s.c2s(P.ldap_bind_request(mid, P.krb_ap_req_token(user, "ldap", dst.fqdn)), think=0.0005)
    s.s2c(P.ldap_bind_response(mid), think=rng.uniform(0.001, 0.004))
    mid += 1
    s.c2s(P.ldap_search_request(mid, "", 0, P._filter_present("objectClass"),
                                ["defaultNamingContext", "dnsHostName", "supportedLDAPVersion", "domainFunctionality",
                                 "namingContexts"]), think=rng.uniform(0.002, 0.02))
    s.s2c(P.ldap_search_entry(mid, "", {"defaultNamingContext": [P.BASE_DN], "dnsHostName": [dst.fqdn],
                                        "supportedLDAPVersion": ["3", "2"], "domainFunctionality": ["7"],
                                        "namingContexts": [P.BASE_DN, "CN=Configuration," + P.BASE_DN]})
          + P.ldap_search_done(mid), think=rng.uniform(0.001, 0.006))
    mid += 1
    n, page = int(max_entries), max(1, int(page_size))
    users = [("CN=%s,OU=Staff,OU=Users,%s" % (u, P.BASE_DN),
              {"sAMAccountName": [u], "displayName": [u.title()], "memberOf": ["CN=Domain Users,CN=Users," + P.BASE_DN],
               "userPrincipalName": ["%s@%s" % (u, P.DOMAIN)]}) for u in account_names(ctx, n)]
    mid = _paged(s, mid, P.BASE_DN, P._filter_and(P._filter_eq("objectCategory", "person"), P._filter_eq("objectClass", "user")),
                 ["sAMAccountName", "displayName", "memberOf", "userPrincipalName"], users, page)
    groups = [("CN=%s,CN=Users,%s" % (g, P.BASE_DN), {"cn": [g], "member": ["CN=%s,OU=Staff,OU=Users,%s" % (own_user(src), P.BASE_DN)]})
              for g in _GROUPS]
    mid = _paged(s, mid, P.BASE_DN, P._filter_eq("objectClass", "group"), ["cn", "member"], groups, page)
    comps = [("CN=%s,OU=Workstations,%s" % (h.name, P.BASE_DN),
              {"cn": [h.name], "dNSHostName": [h.fqdn], "operatingSystem": [h.os]})
             for h in sorted(ctx.h.values(), key=lambda x: x.name) if h.fqdn and "windows" in h.os.lower()][:n]
    mid = _paged(s, mid, P.BASE_DN, P._filter_eq("objectClass", "computer"), ["cn", "dNSHostName", "operatingSystem"], comps, page)
    s.c2s(P.ldap_unbind(mid), think=rng.uniform(0.01, 0.2))
    return F.merged(pre, out, s.close(think=0.0005))


# --------------------------------------------------------------------------- smb_share_enum
@deterministic
def smb_share_enum(ctx, src, dst, *, ts, user=None, share="Dept"):
    """SMB2 share enumeration. On the wire: negotiate and Kerberos session setup, tree connect to IPC$,
    srvsvc bind and NetShareEnumAll, then a tree connect to one share and a directory listing."""
    acct = user or own_user(src)
    s, smb, pre = F._smb_open(ctx, src, dst, "IPC$", ts, user=acct)
    s.c2s(smb.create_req("srvsvc", pipe=True), think=0.003)
    r, fid = smb.create_resp(s.t, 0)
    s.s2c(r, think=0.0008)
    cid = rng.randint(1, 300)
    bind = P.dcerpc_bind(cid, P.SRVSVC_UUID, 3, auth=(acct, "cifs", dst.fqdn))
    s.c2s(smb.write_req(fid, 0, bind), think=0.001)
    s.s2c(smb.write_resp(len(bind)), think=0.0006)
    s.c2s(smb.read_req(fid, 0, 1024), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_bind_ack(cid, "\\PIPE\\srvsvc", auth=True)), think=0.0008)
    req = P.dcerpc_request(cid + 1, 15, P.blob(120), sealed=True)       # NetShareEnumAll
    s.c2s(smb.write_req(fid, 0, req), think=0.002)
    s.s2c(smb.write_resp(len(req)), think=0.0006)
    s.c2s(smb.read_req(fid, 0, 4096), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_response(cid + 1, P.blob(rng.randint(400, 1400)), sealed=True)),
          think=rng.uniform(0.002, 0.02))
    s.c2s(smb.close_req(fid), think=0.003)
    s.s2c(smb.close_resp(s.t, 0), think=0.0008)
    F._smb_untree(s, smb, think=rng.uniform(0.05, 0.3))
    F._smb_retree(s, smb, dst, share)                                       # list one of the shares found
    s.c2s(smb.create_req("", write=False), think=rng.uniform(0.002, 0.02))
    r, dfid = smb.create_resp(s.t, 0, directory=True)
    s.s2c(r, think=0.0008)
    names = [(n.replace("{n}", str(rng.randint(10000, 99999))), rng.randint(20_000, 800_000), False)
             for n in rng.sample(F.FILE_NAMES, 6)] + [("Archive", 0, True)]
    s.c2s(smb.query_dir_req(dfid), think=0.0006)
    s.s2c(smb.query_dir_resp(names, s.t), think=rng.uniform(0.001, 0.004))
    s.c2s(smb.close_req(dfid), think=0.0006)
    s.s2c(smb.close_resp(s.t, 0), think=0.0006)
    return F.merged(pre, F._smb_close(s, smb))


# --------------------------------------------------------------------------- registration
register(ActionSpec(
    token="syn_scan", fn=syn_scan, title="TCP SYN scan", tactic="discovery", techniques=["T1046"],
    protocols=["TCP"], summary="SYN probes across a port list on a subnet or host list; closed ports answer RST/ACK, "
    "open ports SYN/ACK followed by a bare RST.",
    params={"ports": {"type": "list", "default": SERVICE_PORTS, "help": "TCP ports to probe"},
            "scope": {"type": "str", "default": "subnet", "help": "subnet (dst's /24) or host (dst only)"},
            "max_hosts": {"type": "int", "default": 12, "help": "cap on hosts probed"},
            "targets": {"type": "list", "default": None, "help": "explicit IPv4 list; overrides scope"},
            "rate": {"type": "float", "default": 250.0, "help": "probes per second"},
            "complete_open": {"type": "bool", "default": False, "help": "finish the handshake on open ports (connect scan)"}},
    src="any", dst="internal", min_duration_s=5.0))

register(ActionSpec(
    token="icmp_sweep", fn=icmp_sweep, title="ICMP echo sweep", tactic="discovery", techniques=["T1018"],
    protocols=["ICMP", "ARP"], summary="Echo requests with one identifier and rising sequence across a subnet; "
    "live hosts reply, absent addresses stay silent.",
    params={"scope": {"type": "str", "default": "subnet", "help": "subnet or host"},
            "max_hosts": {"type": "int", "default": 16, "help": "cap on live hosts swept"},
            "targets": {"type": "list", "default": None, "help": "explicit IPv4 list"},
            "absent": {"type": "int", "default": 3, "help": "unoccupied addresses that draw no reply"},
            "rate": {"type": "float", "default": 100.0, "help": "requests per second"}},
    src="any", dst="internal", min_duration_s=3.0))

register(ActionSpec(
    token="port_probe", fn=port_probe, title="Service port probe", tactic="discovery", techniques=["T1046"],
    protocols=["TCP"], summary="A few connect probes to one host's common service ports: handshake then FIN when open, "
    "RST/ACK when closed.",
    params={"ports": {"type": "list", "default": SERVICE_PORTS, "help": "TCP ports to probe"},
            "gap_s": {"type": "float", "default": 0.8, "help": "mean seconds between probes"}},
    src="any", dst="internal", min_duration_s=5.0))

register(ActionSpec(
    token="ldap_recon", fn=ldap_recon, title="LDAP directory enumeration", tactic="discovery",
    techniques=["T1087.002", "T1069.002", "T1018"], protocols=["Kerberos", "LDAP"],
    summary="Ticket for ldap/, GSS-SPNEGO bind, a rootDSE search, then paged searches for users, groups and computers.",
    params={"max_entries": {"type": "int", "default": 40, "help": "directory entries returned per object type"},
            "page_size": {"type": "int", "default": 20, "help": "paged-results page size"}},
    src="internal", dst="internal", needs=("DC1",), min_duration_s=3.0))

register(ActionSpec(
    token="smb_share_enum", fn=smb_share_enum, title="SMB share enumeration", tactic="discovery",
    techniques=["T1135"], protocols=["Kerberos", "SMB2", "DCERPC"],
    summary="SMB2 session to IPC$, srvsvc NetShareEnumAll, then a tree connect and directory listing of one share.",
    params={"user": {"type": "str", "default": None, "help": "account used (default: the source's own account)"},
            "share": {"type": "str", "default": "Dept", "help": "share listed after the enumeration"}},
    src="internal", dst="internal", needs=("FILE1",), min_duration_s=2.0))

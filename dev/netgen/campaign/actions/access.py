"""Credential-access actions: failed and roasting-style authentication traffic (ATT&CK tactic
"credential-access").

Every account name here is a dummy or an account from the build's own directory, and every outcome is
the protocol's ordinary failure (or, for the roasting actions, the ordinary reply a domain controller
gives). There is no working credential, no exploit and no tool output on the wire: this is the shape
of the traffic so a network sensor can be tested.
"""
import struct

from . import ActionSpec, register
from .recon import (deterministic, vantage_for, arp_between, own_user, account_names)
from ... import flows as F
from ... import protocols as P
from ...core import TcpSession, rng

DUMMY_USERS = ["root", "admin", "test", "ubuntu", "oracle", "postgres", "pi", "deploy", "support", "guest"]


def _tcp_len(b):
    return struct.pack("!I", len(b)) + b


# --------------------------------------------------------------------------- ssh_brute
@deterministic
def ssh_brute(ctx, src, dst, *, ts, connections=10, tries=3, users=None, gap_s=2.0):
    """SSH password guessing. On the wire: a series of TCP/22 connections, each with the identification
    banners, key exchange, encrypted auth requests that all fail, and a server disconnect."""
    users = list(users or DUMMY_USERS)
    vant = vantage_for(ctx, src, dst)
    out, t = arp_between(ctx, src, dst, ts), ts
    client_banner = rng.choice([b"SSH-2.0-libssh_0.10.5", b"SSH-2.0-paramiko_3.4.0", b"SSH-2.0-OpenSSH_9.2"])
    for i in range(int(connections)):
        s = TcpSession(ctx.link, src, dst, 22, t + 0.001, vantage=vant).handshake()
        s.c2s(client_banner + b"\r\n", think=0.002)
        s.s2c(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", think=0.003)
        s.c2s(P.ssh_kexinit(True), think=0.002)
        s.s2c(P.ssh_kexinit(False), think=0.002)
        s.c2s(P.ssh_ecdh_init(), think=0.003)
        s.s2c(P.ssh_ecdh_reply() + P.ssh_newkeys(), think=0.004)
        s.c2s(P.ssh_newkeys(), think=0.002)
        s.c2s(P.ssh_encrypted(44), think=0.003)            # service request ssh-userauth
        s.s2c(P.ssh_encrypted(60), think=0.002)            # service accept
        for k in range(int(tries)):
            u = users[(i * int(tries) + k) % len(users)]
            s.c2s(P.ssh_encrypted(92 + 4 * len(u)), think=rng.uniform(0.05, 0.4))      # userauth request (password)
            s.s2c(P.ssh_encrypted(76), think=rng.uniform(0.9, 2.2))                    # userauth failure after the KDF delay
        s.s2c(P.ssh_encrypted(84), think=rng.uniform(0.01, 0.05))                      # disconnect: too many failures
        out += s.close(by_client=False, think=0.02)
        t = s.t + float(gap_s) * rng.uniform(0.4, 1.8)
    return F.merged(out)


# --------------------------------------------------------------------------- rdp_brute
@deterministic
def rdp_brute(ctx, src, dst, *, ts, attempts=8, users=None, gap_s=3.0):
    """RDP logon attempts. On the wire: repeated TCP/3389 connections, X.224 negotiation selecting CredSSP,
    a TLS handshake, a failed CredSSP exchange, then the connection ends (reset or close)."""
    from ...tls import TlsSession
    users = list(users or ["administrator", "admin", "backup", "svc_admin", "user1", "support"])
    vant = vantage_for(ctx, src, dst)
    out, t = arp_between(ctx, src, dst, ts), ts
    for i in range(int(attempts)):
        s = TcpSession(ctx.link, src, dst, 3389, t + 0.001, vantage=vant).handshake()
        s.c2s(P.rdp_x224_connect(users[i % len(users)]), think=0.002)
        s.s2c(P.rdp_x224_confirm(), think=0.003)
        tls = TlsSession(ctx.pki, dst.fqdn, F._NullLog(), alpn=b"", kex="ecdhe", selfsigned=True)
        for from_c, data in tls.handshake():
            (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.002, 0.01))
        for size, from_c in ((420, True), (310, False)):       # CredSSP TSRequest, then the server's error
            data = tls.app_data(from_c, P.blob(int(size * rng.uniform(0.95, 1.05))))
            (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.01, 0.08))
        if rng.random() < 0.6:
            pk = s.rst_from_server(think=rng.uniform(0.05, 0.2))
        else:
            s.s2c(tls.close_notify(False), think=rng.uniform(0.02, 0.1))
            pk = s.close(by_client=False, think=0.003)
        out += pk
        t = s.t + float(gap_s) * rng.uniform(0.4, 1.8)
    return F.merged(out)


# --------------------------------------------------------------------------- kerberos_spray
@deterministic
def kerberos_spray(ctx, src, dst, *, ts, accounts=25, unknown_ratio=0.15, gap_s=0.8):
    """Kerberos password spray. On the wire: one TCP/88 connection per account with an AS-REQ carrying
    pre-authentication, answered KDC_ERR_PREAUTH_FAILED (24), or KDC_ERR_C_PRINCIPAL_UNKNOWN (6) for a
    share of names that do not exist."""
    names = account_names(ctx, int(accounts))
    out, t = arp_between(ctx, src, dst, ts), ts
    vant = vantage_for(ctx, src, dst)
    for _i, u in enumerate(names):
        s = TcpSession(ctx.link, src, dst, 88, t + 0.001, vantage=vant).handshake()
        unknown = rng.random() < float(unknown_ratio)
        if unknown:
            u = "%s%d" % (u, rng.randint(2, 9))
        s.c2s(_tcp_len(P.krb_as_req(u, t, rng.getrandbits(31), True)), think=0.0006)
        if unknown:
            s.s2c(_tcp_len(P.krb_error(6, u, t)), think=rng.uniform(0.001, 0.006))
        else:
            s.s2c(_tcp_len(P.krb_error_preauth(u, t, code=24)), think=rng.uniform(0.001, 0.006))
        out += s.close(think=0.001)
        t += float(gap_s) * rng.uniform(0.5, 1.5)
    return F.merged(out)


# --------------------------------------------------------------------------- kerberoast
def _spn_list(ctx, n):
    """(service, fqdn) pairs: the directory's service accounts first, then server hosts."""
    pairs = []
    d = getattr(ctx, "dir", None)
    for a in getattr(d, "services", []) or []:
        spn = getattr(a, "spn", None)
        if spn and "/" in spn:
            svc, host = spn.split("/", 1)
            pairs.append((svc, host))
    for h in sorted(ctx.h.values(), key=lambda x: x.name):
        if h.fqdn and "server" in h.role.lower() and "windows" in h.os.lower():
            pairs.append(("HOST", h.fqdn))
            pairs.append(("CIFS", h.fqdn))
    seen, out = set(), []
    for p in pairs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out[:n]


@deterministic
def kerberoast(ctx, src, dst, *, ts, count=10, gap_s=0.7):
    """Kerberoasting. On the wire: a burst of TGS-REQs over TCP/88 for different service principals, each
    offering only RC4 (etype 23); the domain controller answers with a ticket encrypted the same way."""
    user = own_user(src)
    out, t = arp_between(ctx, src, dst, ts), ts
    vant = vantage_for(ctx, src, dst)
    for svc, host in _spn_list(ctx, int(count)):
        s = TcpSession(ctx.link, src, dst, 88, t + 0.001, vantage=vant).handshake()
        s.c2s(_tcp_len(P.krb_tgs_req(user, svc, host, t, rng.getrandbits(31), etypes=P.KRB_ETYPES_RC4_ONLY)), think=0.0006)
        s.s2c(_tcp_len(P.krb_tgs_rep(user, svc, host, etype=23)), think=rng.uniform(0.001, 0.01))
        out += s.close(think=0.001)
        t += float(gap_s) * rng.uniform(0.3, 1.7)
    return F.merged(out)


# --------------------------------------------------------------------------- asrep_roast
@deterministic
def asrep_roast(ctx, src, dst, *, ts, accounts=6, vulnerable=3, gap_s=0.9):
    """AS-REP roasting. On the wire: AS-REQs without pre-authentication over TCP/88; accounts that do not
    require pre-auth get an RC4 AS-REP, the rest get KDC_ERR_PREAUTH_REQUIRED (25)."""
    names = account_names(ctx, int(accounts))
    out, t = arp_between(ctx, src, dst, ts), ts
    vant = vantage_for(ctx, src, dst)
    for i, u in enumerate(names):
        s = TcpSession(ctx.link, src, dst, 88, t + 0.001, vantage=vant).handshake()
        s.c2s(_tcp_len(P.krb_as_req(u, t, rng.getrandbits(31), False)), think=0.0006)
        if i < int(vulnerable):
            s.s2c(_tcp_len(P.krb_as_rep(u, etype=23)), think=rng.uniform(0.001, 0.008))
        else:
            s.s2c(_tcp_len(P.krb_error_preauth(u, t, code=25)), think=rng.uniform(0.001, 0.006))
        out += s.close(think=0.001)
        t += float(gap_s) * rng.uniform(0.4, 1.6)
    return F.merged(out)


# --------------------------------------------------------------------------- registration
register(ActionSpec(
    token="ssh_brute", fn=ssh_brute, title="SSH password guessing", tactic="credential-access",
    techniques=["T1110.001"], protocols=["TCP", "SSH"],
    summary="A series of SSH connections with banners, key exchange and encrypted password attempts that all fail.",
    params={"connections": {"type": "int", "default": 10, "help": "number of connections"},
            "tries": {"type": "int", "default": 3, "help": "auth attempts per connection"},
            "users": {"type": "list", "default": None, "help": "dummy account names tried"},
            "gap_s": {"type": "float", "default": 2.0, "help": "mean seconds between connections"}},
    src="any", dst="internal", min_duration_s=20.0))

register(ActionSpec(
    token="rdp_brute", fn=rdp_brute, title="RDP logon attempts", tactic="credential-access",
    techniques=["T1110.001"], protocols=["TCP", "RDP", "TLS"],
    summary="Repeated RDP connections that negotiate CredSSP, complete TLS and end in a failed credential exchange.",
    params={"attempts": {"type": "int", "default": 8, "help": "number of connection attempts"},
            "users": {"type": "list", "default": None, "help": "dummy account names in the X.224 cookie"},
            "gap_s": {"type": "float", "default": 3.0, "help": "mean seconds between attempts"}},
    src="any", dst="internal", min_duration_s=20.0))

register(ActionSpec(
    token="kerberos_spray", fn=kerberos_spray, title="Kerberos password spray", tactic="credential-access",
    techniques=["T1110.003"], protocols=["Kerberos"],
    summary="One AS-REQ with pre-auth per account over TCP/88, answered KDC_ERR_PREAUTH_FAILED (or unknown principal).",
    params={"accounts": {"type": "int", "default": 25, "help": "accounts attempted"},
            "unknown_ratio": {"type": "float", "default": 0.15, "help": "share of names that do not exist"},
            "gap_s": {"type": "float", "default": 0.8, "help": "mean seconds between attempts"}},
    src="any", dst="internal", needs=("DC1",), min_duration_s=15.0))

register(ActionSpec(
    token="kerberoast", fn=kerberoast, title="Kerberoasting", tactic="credential-access",
    techniques=["T1558.003"], protocols=["Kerberos"],
    summary="A burst of TGS-REQs for service principals offering only RC4 (etype 23), answered with RC4 tickets.",
    params={"count": {"type": "int", "default": 10, "help": "service principals requested"},
            "gap_s": {"type": "float", "default": 0.7, "help": "mean seconds between requests"}},
    src="internal", dst="internal", needs=("DC1",), min_duration_s=7.0))

register(ActionSpec(
    token="asrep_roast", fn=asrep_roast, title="AS-REP roasting", tactic="credential-access",
    techniques=["T1558.004"], protocols=["Kerberos"],
    summary="AS-REQs without pre-authentication; accounts that allow it get an RC4 AS-REP, others a pre-auth-required error.",
    params={"accounts": {"type": "int", "default": 6, "help": "accounts asked about"},
            "vulnerable": {"type": "int", "default": 3, "help": "how many accounts do not require pre-auth"},
            "gap_s": {"type": "float", "default": 0.9, "help": "mean seconds between requests"}},
    src="internal", dst="internal", needs=("DC1",), min_duration_s=6.0))

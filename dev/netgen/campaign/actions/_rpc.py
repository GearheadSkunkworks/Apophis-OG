"""Private wire helpers for the host-side campaign actions (host.py).

Two small toolkits, both built from the engine's own builders:

* a DCERPC-over-SMB named-pipe session (SMB2 negotiate and Kerberos session setup, IPC$ tree connect,
  pipe open, DCERPC bind with Kerberos packet privacy, then sealed request/response pairs). The RPC
  interface UUID, version, pipe name and operation numbers are correct, so a sensor sees the right
  interface and call; the stub bodies are sealed filler of a plausible size (a real client seals them
  too, so a sensor never reads them).
* LDAP write operations (modifyRequest / modifyResponse) on top of ``protocols._ldap_msg`` and a
  Kerberos-bound LDAP session open/close.

Nothing here carries working content: dummy account names, inert filler, benign attribute values.
"""
from ... import flows as F
from ... import protocols as P
from ... import asn1 as A
from .recon import arp_between, own_user, vantage_for

rng = F.rng

# Interface UUIDs (MS-TSCH ITaskSchedulerService v1.0, MS-EVEN legacy eventlog v0.0) and their pipes.
ATSVC_UUID = P._dce_uuid("86d35949-83c9-4044-b424-db363231fd0c")
EVEN_UUID = P._dce_uuid("82273fdc-e32a-18c3-3f78-827929dc23ea")
ATSVC_PIPE = "\\PIPE\\atsvc"
EVEN_PIPE = "\\PIPE\\eventlog"
SVCCTL_PIPE = "\\PIPE\\svcctl"


# ---------------------------------------------------------------------------- DCERPC over an SMB pipe
class PipeSession:
    """One authenticated SMB2 session with a bound DCERPC pipe. Build with ``open_pipe``."""

    def __init__(self, s, smb, pre, fid, callid, acct, server):
        self.s, self.smb, self.pre, self.fid, self.callid = s, smb, pre, fid, callid
        self.acct, self.server = acct, server
        self.closed = False

    def call(self, opnum, req_len, resp_len, think=None):
        """One sealed request and its sealed response (filler of the given sizes) on the pipe."""
        s, smb = self.s, self.smb
        self.callid += 1
        req = P.dcerpc_request(self.callid, opnum, P.blob(int(req_len)), sealed=True)
        s.c2s(smb.write_req(self.fid, 0, req), think=think if think is not None else rng.uniform(0.002, 0.012))
        s.s2c(smb.write_resp(len(req)), think=0.0006)
        s.c2s(smb.read_req(self.fid, 0, 4096), think=0.0004)
        s.s2c(smb.read_resp(P.dcerpc_response(self.callid, P.blob(int(resp_len)), sealed=True)),
              think=rng.uniform(0.001, 0.01))

    def finish(self):
        """Close the pipe, tree-disconnect, log off, close TCP. Returns the packet list."""
        s, smb = self.s, self.smb
        s.c2s(smb.close_req(self.fid), think=0.003)
        s.s2c(smb.close_resp(s.t, 0), think=0.0008)
        return F.merged(self.pre, F._smb_close(s, smb))


def open_pipe(ctx, src, dst, ts, pipe_name, uuid, ver, sec_addr, user=None):
    """SMB2 session to ``dst`` (Kerberos), IPC$ tree connect, open ``pipe_name`` and bind ``uuid``."""
    acct = user or own_user(src)
    s, smb, pre = F._smb_open(ctx, src, dst, "IPC$", ts, user=acct)
    s.c2s(smb.create_req(pipe_name.rsplit("\\", 1)[-1], pipe=True), think=rng.uniform(0.002, 0.01))
    r, fid = smb.create_resp(s.t, 0)
    s.s2c(r, think=0.0008)
    callid = rng.randint(1, 400)
    bind = P.dcerpc_bind(callid, uuid, ver, auth=(acct, "cifs", dst.fqdn))
    s.c2s(smb.write_req(fid, 0, bind), think=0.001)
    s.s2c(smb.write_resp(len(bind)), think=0.0006)
    s.c2s(smb.read_req(fid, 0, 1024), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_bind_ack(callid, sec_addr, auth=True)), think=0.0008)
    return PipeSession(s, smb, pre, fid, callid, acct, dst)


# ---------------------------------------------------------------------------- LDAP write operations
def ldap_modify_request(msgid, dn, changes):
    """RFC 4511 ModifyRequest ([APPLICATION 6]). ``changes`` = [(op, attr, [values])] with op 0 add,
    1 delete, 2 replace."""
    chg = []
    for op, attr, vals in changes:
        part = A.seq(A.octets(attr.encode()), A.set_(*[A.octets(v if isinstance(v, bytes) else v.encode()) for v in vals]))
        chg.append(A.seq(A.enum(op), part))
    return P._ldap_msg(msgid, A.tlv(0x66, A.octets(dn.encode()) + A.seq(*chg)))


def ldap_modify_response(msgid, rc=0):
    """ModifyResponse ([APPLICATION 7], an LDAPResult)."""
    return P._ldap_msg(msgid, A.tlv(0x67, A.enum(rc) + A.octets(b"") + A.octets(b"")))


class LdapSession:
    """A Kerberos-bound LDAP session (the same bind the engine's own LDAP flows use)."""

    def __init__(self, s, pre, out, user, dst):
        self.s, self.pre, self.out, self.user, self.dst = s, pre, out, user, dst
        self.mid = 1

    def next(self):
        self.mid += 1
        return self.mid

    def search(self, base, scope, filt, attrs, entries, think=None):
        mid = self.next()
        self.s.c2s(P.ldap_search_request(mid, base, scope, filt, attrs), think=think if think is not None else rng.uniform(0.002, 0.03))
        body = b"".join(P.ldap_search_entry(mid, dn, at) for dn, at in entries) + P.ldap_search_done(mid)
        self.s.s2c(body, think=rng.uniform(0.001, 0.006))

    def modify(self, dn, changes, rc=0, think=None):
        mid = self.next()
        self.s.c2s(ldap_modify_request(mid, dn, changes), think=think if think is not None else rng.uniform(0.002, 0.03))
        self.s.s2c(ldap_modify_response(mid, rc), think=rng.uniform(0.001, 0.008))

    def finish(self):
        self.s.c2s(P.ldap_unbind(self.next()), think=rng.uniform(0.01, 0.2))
        return F.merged(self.pre, self.out, self.s.close(think=0.0005))


def open_ldap(ctx, src, dst, ts, user=None):
    """Kerberos ldap/ ticket, TCP 389, GSS-SPNEGO bind."""
    from ...core import TcpSession
    acct = user or own_user(src)
    pre, t = F.kerberos_tgs(ctx, src, "ldap", dst, ts, user=None if acct == own_user(src) else acct)
    out = arp_between(ctx, src, dst, t)
    s = TcpSession(ctx.link, src, dst, 389, t + 0.001, vantage=vantage_for(ctx, src, dst)).handshake()
    s.c2s(P.ldap_bind_request(1, P.krb_ap_req_token(acct, "ldap", dst.fqdn)), think=0.0005)
    s.s2c(P.ldap_bind_response(1), think=rng.uniform(0.001, 0.004))
    return LdapSession(s, pre, out, acct, dst)

"""Lateral-movement and impact actions (ATT&CK tactics "lateral-movement" and "impact").

These emit the *shape* of remote administration traffic between internal hosts so a network sensor
can be tested. Nothing is functional: service-control and DCOM calls carry sized filler, the staged
"binary" is a few filler bytes behind the two-byte file-type magic, and credentials are dummy.
"""
from . import ActionSpec, register
from .recon import deterministic, own_user
from ... import flows as F
from ... import protocols as P
from ...core import rng


# --------------------------------------------------------------------------- smb_admin_exec
@deterministic
def smb_admin_exec(ctx, src, dst, *, ts, binary_name="svcupdate.exe", size=40_000, user=None):
    """PsExec-style remote service run, inert. On the wire: one SMB2 session (Kerberos), a write of filler
    to ADMIN$, then IPC$ with an svcctl bind and three sealed calls (open manager, create service,
    start service), then logoff. The written file is "MZ" followed by random filler: no code."""
    acct = user or own_user(src)
    s, smb, pre = F._smb_open(ctx, src, dst, "ADMIN$", ts, user=acct)
    s.c2s(smb.create_req(binary_name, write=True), think=rng.uniform(0.002, 0.02))
    r, fid = smb.create_resp(s.t, 0)
    s.s2c(r, think=0.0008)
    data = b"MZ" + P.blob(max(0, int(size) - 2))
    off = 0
    while off < len(data):
        part = data[off:off + 65536]
        s.c2s(smb.write_req(fid, off, part), think=0.0003)
        s.s2c(smb.write_resp(len(part)), think=0.0005)
        off += len(part)
    s.c2s(smb.close_req(fid), think=0.002)
    s.s2c(smb.close_resp(s.t, len(data)), think=0.0008)
    F._smb_untree(s, smb, think=rng.uniform(0.05, 0.3))
    F._smb_retree(s, smb, dst, "IPC$")
    s.c2s(smb.create_req("svcctl", pipe=True), think=0.003)
    r2, fid2 = smb.create_resp(s.t, 0)
    s.s2c(r2, think=0.0008)
    callid = rng.randint(1, 400)
    bind = P.dcerpc_bind(callid, P.SVCCTL_UUID, 2, auth=(acct, "cifs", dst.fqdn))
    s.c2s(smb.write_req(fid2, 0, bind), think=0.001)
    s.s2c(smb.write_resp(len(bind)), think=0.0006)
    s.c2s(smb.read_req(fid2, 0, 1024), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_bind_ack(callid, "\\PIPE\\svcctl", auth=True)), think=0.0008)
    for opnum, rq, rs in ((15, 260, 40), (12, 320, 60), (19, 120, 24)):
        callid += 1
        req = P.dcerpc_request(callid, opnum, P.blob(rq), sealed=True)
        s.c2s(smb.write_req(fid2, 0, req), think=rng.uniform(0.002, 0.01))
        s.s2c(smb.write_resp(len(req)), think=0.0006)
        s.c2s(smb.read_req(fid2, 0, 1024), think=0.0004)
        s.s2c(smb.read_resp(P.dcerpc_response(callid, P.blob(rs), sealed=True)), think=rng.uniform(0.001, 0.01))
    s.c2s(smb.close_req(fid2), think=0.003)
    s.s2c(smb.close_resp(s.t, 0), think=0.0008)
    return F.merged(pre, F._smb_close(s, smb))


# --------------------------------------------------------------------------- wmi_exec
@deterministic
def wmi_exec(ctx, src, dst, *, ts):
    """DCOM/WMI remote call pattern, inert. On the wire: tcp/135 activation (bind, RemoteCreateInstance), then a
    second connection to a dynamic port (49152-49230) that binds the WMI interfaces and makes four
    sealed calls with filler bodies."""
    from ... import incidents as I
    return I.wmi_exec(ctx, src, dst, ts)


# --------------------------------------------------------------------------- rdp_session
@deterministic
def rdp_session(ctx, src, dst, *, ts, duration_s=45.0, user=None):
    """An established RDP session. On the wire: name lookup, Kerberos ticket for TERMSRV, X.224 negotiation,
    TLS, CredSSP, then input and bitmap traffic (small client records, large server records) for duration_s."""
    return F.rdp_session(ctx, src, dst, ts, float(duration_s), user=user)


# --------------------------------------------------------------------------- ransomware_smb
RANSOM_NOTE = (b"This is a generic placeholder note for sensor testing. No data was changed. "
               b"Nothing here is a real demand or a real contact point.\r\n")


@deterministic
def ransomware_smb(ctx, src, dst, *, ts, share="Dept", files=10, max_file_kb=48, ext=".encrypted",
                   note_name="README_RESTORE.txt", user=None):
    """Sensor-detection pattern only, modest volume. On the wire: one SMB2 session, a directory listing, then for each
    file an open, in-place read and rewrite of filler (high entropy, same length), a rename to <name><ext>,
    and finally one generic note file written to the share. File bodies are random filler and the note is
    placeholder text: this reproduces the access pattern a sensor looks for, not an encryptor."""
    acct = user or own_user(src)
    s, smb, pre = F._smb_open(ctx, src, dst, share, ts, user=acct)
    s.streaming = True
    s.c2s(smb.create_req("", write=False), think=rng.uniform(0.002, 0.02))
    r, dfid = smb.create_resp(s.t, 0, directory=True)
    s.s2c(r, think=0.0008)
    cap = int(max_file_kb) * 1024
    names = []
    while len(names) < int(files):
        nm = rng.choice(F.FILE_NAMES).replace("{n}", str(rng.randint(10000, 99999)))
        if nm in names:
            stem, dot, suffix = nm.rpartition(".")
            nm = "%s-%d%s%s" % (stem, rng.randint(2, 9), dot, suffix)
        if nm not in names:
            names.append(nm)
    listing = [(nm, rng.randint(max(1024, cap // 4), cap), False) for nm in sorted(names)]
    rng.shuffle(listing)
    s.s2c(smb.query_dir_resp(listing + [("Archive", 0, True)], s.t), think=rng.uniform(0.001, 0.004))
    s.c2s(smb.close_req(dfid), think=0.0006)
    s.s2c(smb.close_resp(s.t, 0), think=0.0006)
    for nm, size, _ in listing:
        s.c2s(smb.open_existing_req(nm), think=rng.uniform(0.0008, 0.006))
        rr, fid = smb.create_resp(s.t, size, action=1)
        s.s2c(rr, think=0.0006)
        off = 0
        while off < size:
            n = min(65536, size - off)
            s.c2s(smb.read_req(fid, off, n), think=0.0002)
            s.s2c(smb.read_resp(P.blob(n)), think=0.0003)
            s.c2s(smb.write_req(fid, off, P.blob(n)), think=0.0002)
            s.s2c(smb.write_resp(n), think=0.0003)
            off += n
        s.c2s(smb.set_info_rename_req(fid, nm + ext), think=0.0004)
        s.s2c(smb.set_info_resp(), think=0.0004)
        s.c2s(smb.close_req(fid), think=0.0004)
        s.s2c(smb.close_resp(s.t, size), think=0.0004)
    s.c2s(smb.create_req(note_name, write=True), think=0.001)
    rn, nfid = smb.create_resp(s.t, 0)
    s.s2c(rn, think=0.0004)
    s.c2s(smb.write_req(nfid, 0, RANSOM_NOTE), think=0.0004)
    s.s2c(smb.write_resp(len(RANSOM_NOTE)), think=0.0004)
    s.c2s(smb.close_req(nfid), think=0.0004)
    s.s2c(smb.close_resp(s.t, len(RANSOM_NOTE)), think=0.0004)
    return F.merged(pre, F._smb_close(s, smb))


# --------------------------------------------------------------------------- registration
register(ActionSpec(
    token="smb_admin_exec", fn=smb_admin_exec, title="SMB admin-share remote service", tactic="lateral-movement",
    techniques=["T1021.002", "T1569.002"], protocols=["Kerberos", "SMB2", "DCERPC"],
    summary="SMB2 write of filler to ADMIN$ then svcctl open, create and start calls on IPC$ (inert).",
    params={"binary_name": {"type": "str", "default": "svcupdate.exe", "help": "file name written to ADMIN$"},
            "size": {"type": "int", "default": 40000, "help": "bytes written (filler behind the MZ magic)"},
            "user": {"type": "str", "default": None, "help": "account used (default: the source's own)"}},
    src="internal", dst="internal", needs=("FILE1",), min_duration_s=3.0))

register(ActionSpec(
    token="wmi_exec", fn=wmi_exec, title="WMI remote call pattern", tactic="lateral-movement",
    techniques=["T1047"], protocols=["DCERPC", "DCOM"],
    summary="DCOM activation on tcp/135, then a dynamic-port connection binding the WMI interfaces with sealed filler calls (inert).",
    params={}, src="internal", dst="internal", needs=("FILE1",), min_duration_s=2.0))

register(ActionSpec(
    token="rdp_session", fn=rdp_session, title="RDP session to a server", tactic="lateral-movement",
    techniques=["T1021.001"], protocols=["DNS", "Kerberos", "RDP", "TLS"],
    summary="Kerberos TERMSRV ticket then an established RDP session with input and bitmap traffic.",
    params={"duration_s": {"type": "float", "default": 45.0, "help": "session length in seconds"},
            "user": {"type": "str", "default": None, "help": "account in the RDP cookie and ticket"}},
    src="internal", dst="internal", needs=("DC1",), min_duration_s=45.0))

register(ActionSpec(
    token="ransomware_smb", fn=ransomware_smb, title="SMB mass-rename pattern (sensor test)", tactic="impact",
    techniques=["T1486"], protocols=["Kerberos", "SMB2"],
    summary="Many SMB2 opens, in-place read/rewrites of filler and renames to a new extension, then one placeholder note file.",
    params={"share": {"type": "str", "default": "Dept", "help": "share the pattern runs against"},
            "files": {"type": "int", "default": 10, "help": "files touched"},
            "max_file_kb": {"type": "int", "default": 48, "help": "largest file size in KiB"},
            "ext": {"type": "str", "default": ".encrypted", "help": "extension appended on rename"},
            "note_name": {"type": "str", "default": "README_RESTORE.txt", "help": "placeholder note file name"},
            "user": {"type": "str", "default": None, "help": "account used (default: the source's own)"}},
    src="internal", dst="internal", needs=("FILE1",), min_duration_s=5.0))

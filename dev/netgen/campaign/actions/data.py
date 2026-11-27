"""Collection, covert-channel, exfiltration and impact actions (the DATA group).

Wire behaviour only. Every body is inert filler from the engine's seeded generator, carrying at most
a file-type magic number (zip, 7z, rar). Rows returned by the database are made-up values under
``.example.test`` names. Credentials are dummies. Nothing here decodes to a command, a tool or real data.
See ``c2.py`` for the determinism note.

  sql_collect          TDS login, schema listing, then large SELECT result sets
  archive_stage        SMB2 write of a big archive into a staging directory
  icmp_tunnel          ICMP echo request/reply pairs with opaque, variable-sized payloads
  cloud_service_c2     HTTPS polling of a public web-service API host
  cloud_storage_upload HTTPS multi-part object upload (initiate, parts, complete)
  smtp_exfil           SMTP session with a large base64 attachment
  smb_delete_burst     SMB2 delete-on-close requests across many files on a share
"""
import base64

from ... import flows as F
from ... import protocols as P
from ...identity import get_current
from . import ActionSpec, register
from .recon import _icmp_frame
from .c2 import (_p, _rb, _b32, _b64, _gap, _req, _resp, _tls_open, _tls_close, _host_of, _client_ua, _sz, _lookup)

MAX_BYTES = 200_000_000

_MAGIC = {"zip": b"PK\x03\x04\x14\x00\x00\x00\x08\x00", "7z": b"7z\xbc\xaf\x27\x1c\x00\x04", "rar": b"Rar!\x1a\x07\x01\x00"}

_FIRST = ["Alex", "Blair", "Casey", "Drew", "Emery", "Finley", "Gray", "Harper", "Indy", "Jules", "Kai", "Lane"]
_LAST = ["Archer", "Bishop", "Carver", "Dalton", "Ellis", "Fisher", "Gentry", "Hale", "Ingram", "Joyce", "Keane", "Lowe"]
_REGIONS = ["EMEA", "APAC", "NA-East", "NA-West", "LATAM"]


def _bytes_cap(n, lo=1024):
    return min(max(int(n), lo), MAX_BYTES)


# ---------------------------------------------------------------------------- sql_collect
def _person_rows(n, start):
    rows = []
    for i in range(n):
        fn, ln = F.rng.choice(_FIRST), F.rng.choice(_LAST)
        rows.append((start + i, "%s %s" % (fn, ln), "%s.%s%d@mail.example.test" % (fn.lower(), ln.lower(), F.rng.randint(1, 99)),
                     F.rng.choice(_REGIONS), F.rng.randint(0, 250000), None))
    return rows


def sql_collect(ctx, src, dst, *, ts, tables=3, rows_per_table=4000, user="svc_report", db="Logistics", gap_s=4.0):
    """Bulk reading of a database over TDS (TCP 1433): pre-login, login with a dummy account, a metadata query
    that lists the tables, then ``tables`` large ``SELECT *`` statements whose result sets run to thousands of
    rows each, spread over many 4 KB TDS packets. Row values are made-up; the sensor sees one client pulling
    far more rows and bytes than a normal application query. Not simulated: SQL injection, xp_cmdshell,
    TLS-wrapped TDS."""
    tables = max(1, min(int(tables), 12))
    rows_per_table = max(10, min(int(rows_per_table), 60000))
    t = ts + F.rng.uniform(0.005, 0.05)
    out = list(ctx.arp_for(src, dst, t))
    s = ctx.tcp(src, dst, 1433, t + 0.001, rate=100e6).handshake()
    s.c2s(P.tds_prelogin(True), think=0.0004)
    s.s2c(P.tds_prelogin(False), think=F.rng.uniform(0.0005, 0.002))
    s.c2s(P.tds_login7(user, app="Reporting Export", host=src.name, db=db), think=0.0006)
    s.s2c(P.tds_login_ack(db), think=F.rng.uniform(0.001, 0.004))
    spid = F.rng.randint(51, 120)
    names = ["Customers", "Orders", "Invoices", "Accounts", "Contacts", "Employees", "Payments", "Shipments",
             "Carriers", "Vendors", "Contracts", "Tickets"]
    chosen = names[:tables]
    s.c2s(P.tds_sql_batch("SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'"),
          think=F.rng.uniform(0.2, 1.5))
    s.s2c(P.tds_split(0x04, P.tds_result([("TABLE_SCHEMA", "nvarchar"), ("TABLE_NAME", "nvarchar")],
                                         [("dbo", n) for n in names]), spid), think=F.rng.uniform(0.002, 0.01))
    cols = [("PersonId", "int"), ("FullName", "nvarchar"), ("Email", "nvarchar"), ("Region", "nvarchar"),
            ("Balance", "int"), ("CreatedAt", "datetime")]
    start = 100000
    for name in chosen:
        s.c2s(P.tds_sql_batch("SELECT * FROM dbo.%s" % name), think=_gap(gap_s, 0.5))
        n = max(10, int(rows_per_table * F.rng.uniform(0.7, 1.3)))
        data = P.tds_split(0x04, P.tds_result(cols, _person_rows(n, start)), spid)
        start += n
        for off in range(0, len(data), 4096 * 16):          # a result stream, sent as the server produces it
            s.s2c(data[off:off + 4096 * 16], think=F.rng.uniform(0.002, 0.03))
    out += s.close(think=F.rng.uniform(0.05, 0.4))
    return F.merged(out)


# ---------------------------------------------------------------------------- archive_stage
def archive_stage(ctx, src, dst, *, ts, share="Dept", directory="Temp\\stage", archive_mb=40.0, parts=1,
                  format="zip", chunk=1048576):
    """Staging data on a file server: one SMB2 session (Kerberos), tree connect, then CREATE and sequential
    WRITEs of ``parts`` archive files (``archive_mb`` megabytes in all, 1 MiB writes) into ``directory`` of
    the share. The first bytes are the archive's magic number (zip, 7z or rar), the rest is incompressible
    filler. Not simulated: the archiving itself (compression runs on the host, not on the wire)."""
    total = _bytes_cap(float(archive_mb) * 1_000_000, 4096)
    parts = max(1, min(int(parts), 50))
    chunk = max(4096, min(int(chunk), 4 * 1048576))
    magic = _MAGIC.get(str(format).lower(), _MAGIC["zip"])
    ext = str(format).lower() if str(format).lower() in _MAGIC else "zip"
    s, smb, pre = F._smb_open(ctx, src, dst, share, ts)
    s.per_byte = 8.0 / 900e6
    directory = str(directory).strip("\\/").replace("/", "\\")
    done, i = 0, 0
    while done < total and i < parts:
        size = total - done if i == parts - 1 else min(total - done, max(4096, int(total / parts * F.rng.uniform(0.7, 1.3))))
        name = "%s\\%s_%s.%s" % (directory, F.rng.choice(["backup", "export", "data", "docs", "archive"]), _b32(6), ext) if directory \
            else "%s_%s.%s" % ("archive", _b32(6), ext)
        s.c2s(smb.create_req(name, write=True), think=F.rng.uniform(0.002, 0.03))
        r, fid = smb.create_resp(s.t, 0)
        s.s2c(r, think=0.0008)
        off = 0
        while off < size:
            n = min(chunk, size - off)
            part = (magic + _rb(n - len(magic))) if off == 0 and n > len(magic) else _rb(n)
            s.c2s(smb.write_req(fid, off, part), think=0.0002)
            s.s2c(smb.write_resp(n), think=0.0004)
            off += n
            s.t += n / 60e6 * F.rng.uniform(0.7, 1.3)
        s.c2s(smb.close_req(fid), think=0.0006)
        s.s2c(smb.close_resp(s.t, size), think=0.0006)
        done += size
        i += 1
    return F.merged(pre, F._smb_close(s, smb))


# ---------------------------------------------------------------------------- icmp_tunnel
def icmp_tunnel(ctx, src, dst, *, ts, count=120, interval_s=1.0, jitter=0.1, size_min=64, size_max=900,
                fixed_size=0, reply_ratio=1.0):
    """A covert channel in ICMP echo: ``count`` echo requests from the source to the destination, each with an
    opaque payload of a different size between ``size_min`` and ``size_max`` bytes (or always ``fixed_size``),
    sent on a steady cadence with the same identifier and a rising sequence number, and an echo reply
    (``reply_ratio`` of them) whose payload size differs from the request, the way a tunnel's replies carry
    data back. Ordinary ping payloads are fixed and printable; these are random and vary. Payloads are filler,
    not a tunnelling protocol."""
    count = max(1, min(int(count), 5000))
    cap = 1452 if ctx.v6 is not None else 1472                  # path MTU less the IP and ICMP headers
    lo, hi = sorted((max(0, int(size_min)), min(cap, max(0, int(size_max)))))
    fixed = min(cap, max(0, int(fixed_size)))
    ident = F.rng.randint(1, 65535)
    out = list(ctx.arp_for(src, dst, ts))
    t = ts + F.rng.uniform(0.005, 0.05)
    for seq in range(1, count + 1):
        n = fixed or _sz(lo, hi)
        out.append(_icmp_frame(ctx, src, dst, src, t, ident, seq, True, _rb(n)))
        if F.rng.random() < float(reply_ratio):
            m = fixed or _sz(lo, hi)
            out.append(_icmp_frame(ctx, dst, src, src, t + F.rng.uniform(0.02, 0.12), ident, seq, False, _rb(m)))
        t += _gap(interval_s, jitter)
    return F.merged(out)


# ---------------------------------------------------------------------------- cloud_service_c2
def cloud_service_c2(ctx, src, dst, *, ts, count=12, interval_s=30.0, jitter=0.2, sni="", keepalive=True,
                     path_prefix="/v1/channels"):
    """Polling of a public web-service API host over decryptable TLS: DNS lookup, then ``count`` small GETs of a
    channel/inbox path with a dummy bearer token and a short JSON reply (usually empty, now and then a larger
    item), and every few polls a small POST that returns a result. The TLS SNI is a cloud-service name (``sni``
    or the destination's name) rather than an unknown server, which is what makes this traffic look legitimate.
    One kept-open session by default, or a new session per poll with ``keepalive`` off. Not simulated: the
    service's real API."""
    host = sni or _host_of(dst)
    ua = _client_ua(ctx, src)
    chan = "ch-" + _b32(10)
    token = "Bearer " + _b64(40)
    count = max(1, int(count))
    pre = []
    if sni and sni != dst.fqdn and F._wants_dns(ctx, src, sni, ts, True):
        pre = F.dns_lookup(ctx, src, sni, ts, external=True, answers=[(P.DNS_A, dst.ipb)])
    dns_ok = not sni

    def poll(s, tls, i, first):
        think = F.rng.uniform(0.0008, 0.004) if first else _gap(interval_s, jitter)
        if i and i % 4 == 0:
            body = ('{"result":"%s","seq":%d}' % (_b64(_sz(40, 160)), i)).encode()
            req = _req("POST", "%s/%s/results" % (path_prefix, chan), host, ua,
                       ["Authorization: " + token, "Content-Type: application/json"], body)
            reply = b'{"ok":true}'
        else:
            req = _req("GET", "%s/%s/messages?after=%d" % (path_prefix, chan, i), host, ua,
                       ["Authorization: " + token, "Accept: application/json"])
            reply = b'{"items":[],"next":"%d"}' % (i + 1) if F.rng.random() < 0.7 else \
                ('{"items":[{"id":"m%d","text":"%s"}],"next":"%d"}' % (i, _b64(_sz(80, 600)), i + 1)).encode()
        s.c2s(tls.app_data(True, req), think=think)
        s.s2c(tls.app_data(False, _resp("200 OK", reply, "application/json", s.t)), think=F.rng.uniform(0.03, 0.15))

    if keepalive:
        p2, s, tls = _tls_open(ctx, src, dst, ts + (0.05 if pre else 0), host=host, profile="winhttp", rate=50e6, dns=dns_ok)
        for i in range(count):
            poll(s, tls, i, i == 0)
        return F.merged(pre, _tls_close(s, tls, p2, 0.4))
    out, t = list(pre), ts + (0.05 if pre else 0)
    for i in range(count):
        p2, s, tls = _tls_open(ctx, src, dst, t, host=host, profile="winhttp", rate=50e6, dns=dns_ok)
        poll(s, tls, i, True)
        out += _tls_close(s, tls, p2, 0.3)
        t += _gap(interval_s, jitter)
    return F.merged(out)


# ---------------------------------------------------------------------------- cloud_storage_upload
def cloud_storage_upload(ctx, src, dst, *, ts, total_bytes=3_000_000, part_bytes=524288, bucket="", sni="",
                         object_name=""):
    """A multi-part object upload to a storage-style host over decryptable TLS: DNS lookup, one session, an
    initiate POST (reply carries an upload id), then parts of about ``part_bytes`` each as PUTs of inert filler
    (each answered with an entity tag), and a closing POST that completes the object. The host name is an
    object-storage style name (``sni`` or the destination's name, ``<bucket>.`` prefix added when ``bucket`` is
    set). Not simulated: request signing and the service's real API."""
    total = _bytes_cap(total_bytes)
    base = max(8192, int(part_bytes))
    host = sni or _host_of(dst)
    if bucket and not sni and not dst.fqdn:
        host = "%s.objects.example" % bucket
    elif bucket and not sni:
        host = "%s.%s" % (bucket, host)
    ua = _client_ua(ctx, src)
    obj = "/" + (object_name or ("export-%s.zip" % _b32(8)))
    pre = []
    if host != dst.fqdn and F._wants_dns(ctx, src, host, ts, True):
        pre = F.dns_lookup(ctx, src, host, ts, external=True, answers=[(P.DNS_A, dst.ipb)])
    p2, s, tls = _tls_open(ctx, src, dst, ts + (0.05 if pre else 0), host=host, profile=getattr(src, "tls_profile", "winhttp"),
                           rate=80e6, dns=False)
    upid = _b64(40).replace("+", "-").replace("/", "_")
    s.c2s(tls.app_data(True, _req("POST", obj + "?uploads", host, ua, ["Content-Type: application/octet-stream", "Content-Length: 0"])),
          think=F.rng.uniform(0.001, 0.004))
    s.s2c(tls.app_data(False, _resp("200 OK", ('<?xml version="1.0"?><InitiateMultipartUploadResult><Key>%s</Key><UploadId>%s</UploadId>'
                                              '</InitiateMultipartUploadResult>' % (obj[1:], upid)).encode(), "application/xml", s.t)),
          think=F.rng.uniform(0.02, 0.08))
    sent, part, etags = 0, 1, []
    while sent < total:
        ramp = min(1.0, 0.4 + part * 0.2)
        n = min(total - sent, max(8192, int(base * ramp * F.rng.uniform(0.8, 1.2))))
        data = _rb(n)
        req = _req("PUT", "%s?partNumber=%d&uploadId=%s" % (obj, part, upid), host, ua, ["Content-Type: application/octet-stream"], data)
        s.c2s(tls.app_data(True, req), think=F.rng.uniform(0.02, 0.4))
        et = _b32(26)
        etags.append(et)
        s.s2c(tls.app_data(False, _resp("200 OK", b"", "text/plain", s.t, headers=['ETag: "%s"' % et])), think=F.rng.uniform(0.02, 0.15))
        sent += n
        part += 1
    done = ("<CompleteMultipartUpload>%s</CompleteMultipartUpload>" % "".join(
        "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>" % (i + 1, e) for i, e in enumerate(etags))).encode()
    s.c2s(tls.app_data(True, _req("POST", "%s?uploadId=%s" % (obj, upid), host, ua, ["Content-Type: application/xml"], done)),
          think=F.rng.uniform(0.02, 0.2))
    s.s2c(tls.app_data(False, _resp("200 OK", ('<?xml version="1.0"?><CompleteMultipartUploadResult><Key>%s</Key></CompleteMultipartUploadResult>'
                                              % obj[1:]).encode(), "application/xml", s.t)), think=F.rng.uniform(0.05, 0.3))
    return F.merged(pre, _tls_close(s, tls, p2, 0.5))


# ---------------------------------------------------------------------------- smtp_exfil
def smtp_exfil(ctx, src, dst, *, ts, attachment_bytes=1_500_000, filename="", subject="Quarterly figures", recipient=""):
    """A clear-text SMTP submission to an external mail host (TCP 25): DNS lookup, 220 banner, EHLO, MAIL FROM a
    corporate address, RCPT TO an outside address, DATA with a MIME multipart message whose one attachment is
    ``attachment_bytes`` bytes of filler (zip magic first) as 76-column base64, then 250 and QUIT. Not simulated:
    STARTTLS, authentication, real message content."""
    size = _bytes_cap(attachment_bytes, 512)
    fname = filename or "report_%s.zip" % _b32(5)
    dom = get_current().domain
    sender = "%s@%s" % (P.username_for(src.name), dom)
    host = dst.fqdn or ("mx." + _b32(6) + ".example.test")
    rcpt = recipient or ("inbox@%s" % (host.split(".", 1)[1] if "." in host else "mail.example.test"))
    pre = _lookup(ctx, src, dst, ts)
    t = ts + F.rng.uniform(0.005, 0.05) + (0.02 if pre else 0.0)
    out = list(pre) + ctx.arp_for(src, dst, t)
    s = ctx.tcp(src, dst, 25, t + 0.001, rate=50e6).handshake()
    s.s2c(("220 %s ESMTP ready\r\n" % host).encode(), think=F.rng.uniform(0.02, 0.15))
    s.c2s(("EHLO %s.%s\r\n" % (src.name.lower(), dom)).encode(), think=F.rng.uniform(0.03, 0.12))
    s.s2c(("250-%s\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n" % host).encode(),
          think=F.rng.uniform(0.01, 0.05))
    s.c2s(("MAIL FROM:<%s>\r\n" % sender).encode(), think=F.rng.uniform(0.02, 0.1))
    s.s2c(b"250 2.1.0 Ok\r\n", think=F.rng.uniform(0.01, 0.04))
    s.c2s(("RCPT TO:<%s>\r\n" % rcpt).encode(), think=F.rng.uniform(0.02, 0.08))
    s.s2c(b"250 2.1.5 Ok\r\n", think=F.rng.uniform(0.01, 0.04))
    s.c2s(b"DATA\r\n", think=F.rng.uniform(0.02, 0.06))
    s.s2c(b"354 End data with <CR><LF>.<CR><LF>\r\n", think=F.rng.uniform(0.01, 0.04))
    bnd = "=_part_" + _b32(16)
    head = ("From: <%s>\r\nTo: <%s>\r\nSubject: %s\r\nDate: Mon, 14 Sep 2026 09:00:00 +0000\r\nMessage-ID: <%s@%s>\r\n"
            "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n"
            "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPlease find the file attached.\r\n\r\n"
            "--%s\r\nContent-Type: application/zip; name=\"%s\"\r\nContent-Transfer-Encoding: base64\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n\r\n"
            % (sender, rcpt, subject, _b32(12), dom, bnd, bnd, bnd, fname, fname)).encode()
    raw = _MAGIC["zip"] + _rb(size - len(_MAGIC["zip"]))
    b64 = base64.b64encode(raw)
    lines = b"\r\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))
    tail = ("\r\n--%s--\r\n.\r\n" % bnd).encode()
    body = head + lines + tail
    s.c2s(body[:len(head)], think=F.rng.uniform(0.03, 0.15))
    for off in range(len(head), len(body), 32768):
        s.c2s(body[off:off + 32768], think=F.rng.uniform(0.0008, 0.006))
    s.s2c(("250 2.0.0 Ok: queued as %010X\r\n" % F.rng.getrandbits(40)).encode(), think=F.rng.uniform(0.05, 0.3))
    s.c2s(b"QUIT\r\n", think=F.rng.uniform(0.03, 0.1))
    s.s2c(b"221 2.0.0 Bye\r\n", think=F.rng.uniform(0.01, 0.03))
    return F.merged(out, s.close(think=F.rng.uniform(0.01, 0.04)))


# ---------------------------------------------------------------------------- smb_delete_burst
def smb_delete_burst(ctx, src, dst, *, ts, share="Dept", files=150, gap_s=0.01):
    """A mass delete on a share, pattern only: one SMB2 session (Kerberos), tree connect, a directory listing,
    then for each of ``files`` names an open for delete (DELETE access with the delete-on-close option) and the
    close that removes it, in a quick run, then tree disconnect and logoff. The listing is a stand-in; no file
    content moves. Not simulated: the files' original contents or any recovery step."""
    files = max(1, min(int(files), 5000))
    s, smb, pre = F._smb_open(ctx, src, dst, share, ts)
    names = []
    for k in range(files):
        n = F.rng.choice(F.FILE_NAMES)
        base, dot, ext = n.rpartition(".")
        names.append(n.replace("{n}", str(10000 + k)) if "{n}" in n else "%s-%04d%s%s" % (base, k, dot, ext))
    s.c2s(smb.create_req("", write=False), think=F.rng.uniform(0.002, 0.02))
    r, dfid = smb.create_resp(s.t, 0, directory=True)
    s.s2c(r, think=0.0008)
    s.c2s(smb.query_dir_req(dfid), think=0.0006)
    s.s2c(smb.query_dir_resp([(n, F.rng.randint(20000, 900000), False) for n in names[:80]], s.t), think=F.rng.uniform(0.001, 0.006))
    s.c2s(smb.close_req(dfid), think=0.0006)
    s.s2c(smb.close_resp(s.t, 0), think=0.0006)
    for n in names:
        s.c2s(smb.create_req(n, delete_on_close=True), think=max(0.0003, float(gap_s) * F.rng.uniform(0.5, 1.5)))
        r, fid = smb.create_resp(s.t, 0)
        s.s2c(r, think=0.0006)
        s.c2s(smb.close_req(fid), think=0.0004)
        s.s2c(smb.close_resp(s.t, 0), think=0.0005)
    return F.merged(pre, F._smb_close(s, smb))


# ---------------------------------------------------------------------------- registration
register(ActionSpec(
    token="sql_collect", fn=sql_collect, title="SQL bulk collection", tactic="collection",
    techniques=["T1213"], protocols=["TCP", "TDS"],
    summary="A TDS login to a database server followed by a table listing and several large SELECT result sets of thousands of rows.",
    params={"tables": _p("int", 3, "Number of tables read in full."), "rows_per_table": _p("int", 4000, "Typical rows per table."),
            "user": _p("str", "svc_report", "Dummy database account."), "db": _p("str", "Logistics", "Database name."),
            "gap_s": _p("float", 4.0, "Mean seconds between statements.")},
    src="internal", dst="internal", needs=("SQL1",), min_duration_s=20.0))

register(ActionSpec(
    token="archive_stage", fn=archive_stage, title="Archive staging over SMB", tactic="collection",
    techniques=["T1560.001", "T1074.001"], protocols=["Kerberos", "SMB2"],
    summary="SMB2 writes of a large archive (zip, 7z or rar magic, inert body) into a staging directory on a file server.",
    params={"share": _p("str", "Dept", "Share name."), "directory": _p("str", "Temp\\stage", "Staging directory inside the share."),
            "archive_mb": _p("float", 40.0, "Megabytes written in total."), "parts": _p("int", 1, "Number of archive files."),
            "format": _p("str", "zip", "zip, 7z or rar (sets the magic number and extension)."),
            "chunk": _p("int", 1048576, "Bytes per SMB write.")},
    src="internal", dst="internal", needs=("DC1",), min_duration_s=15.0))

register(ActionSpec(
    token="icmp_tunnel", fn=icmp_tunnel, title="ICMP echo tunnel", tactic="command-and-control",
    techniques=["T1095"], protocols=["ICMP"],
    summary="ICMP echo requests and replies with opaque, variable-sized payloads at a steady cadence.",
    params={"count": _p("int", 120, "Echo requests sent."), "interval_s": _p("float", 1.0, "Mean seconds between requests."),
            "jitter": _p("float", 0.1, "Fractional jitter on the interval."), "size_min": _p("int", 64, "Smallest payload in bytes."),
            "size_max": _p("int", 900, "Largest payload in bytes (max 1472)."),
            "fixed_size": _p("int", 0, "Payload size used for every packet (0 = vary)."),
            "reply_ratio": _p("float", 1.0, "Share of requests that get a reply (0 to 1).")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=60.0))

register(ActionSpec(
    token="cloud_service_c2", fn=cloud_service_c2, title="Cloud-service polling", tactic="command-and-control",
    techniques=["T1102.002"], protocols=["DNS", "TLS", "HTTPS"],
    summary="Small HTTPS GET/POST polls of a public web-service API host under a cloud-service TLS name, answered with short JSON.",
    params={"count": _p("int", 12, "Number of polls."), "interval_s": _p("float", 30.0, "Mean seconds between polls."),
            "jitter": _p("float", 0.2, "Fractional jitter on the interval."),
            "sni": _p("str", "", "Service host name for DNS, TLS and Host; default the destination's name."),
            "keepalive": _p("bool", True, "Poll over one kept-open session (off: a new session per poll)."),
            "path_prefix": _p("str", "/v1/channels", "API path prefix.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=60.0))

register(ActionSpec(
    token="cloud_storage_upload", fn=cloud_storage_upload, title="Cloud object-storage upload", tactic="exfiltration",
    techniques=["T1567.002"], protocols=["DNS", "TLS", "HTTPS"],
    summary="A multi-part HTTPS upload to an object-storage style host: initiate, PUT of parts of filler, complete.",
    params={"total_bytes": _p("int", 3000000, "Bytes uploaded in total."), "part_bytes": _p("int", 524288, "Typical part size."),
            "bucket": _p("str", "", "Bucket name used as a host-name prefix."),
            "sni": _p("str", "", "Storage host name; default the destination's name."),
            "object_name": _p("str", "", "Object key; default a random archive name.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=15.0))

register(ActionSpec(
    token="smtp_exfil", fn=smtp_exfil, title="SMTP exfiltration", tactic="exfiltration",
    techniques=["T1048.003"], protocols=["DNS", "SMTP", "IMF"],
    summary="A clear-text SMTP session to an external mail host carrying a large base64 attachment of inert filler.",
    params={"attachment_bytes": _p("int", 1500000, "Raw attachment size in bytes."), "filename": _p("str", "", "Attachment file name."),
            "subject": _p("str", "Quarterly figures", "Message subject."), "recipient": _p("str", "", "Outside recipient address.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=10.0))

register(ActionSpec(
    token="smb_delete_burst", fn=smb_delete_burst, title="SMB delete burst", tactic="impact",
    techniques=["T1485"], protocols=["Kerberos", "SMB2"],
    summary="A quick run of SMB2 open-for-delete and close requests across many files on a share.",
    params={"share": _p("str", "Dept", "Share name."), "files": _p("int", 150, "Number of files deleted."),
            "gap_s": _p("float", 0.01, "Mean seconds between deletes.")},
    src="internal", dst="internal", needs=("DC1",), min_duration_s=10.0))

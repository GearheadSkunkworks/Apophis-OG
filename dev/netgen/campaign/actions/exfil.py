"""Exfiltration and collection actions.

Wire behaviour only: uploads and queries carry random filler (never real data) from the engine's
seeded generator. See ``c2.py`` for the determinism note.
"""

from ... import flows as F
from ... import protocols as P
from . import ActionSpec, register
from .c2 import (_p, _rb, _b32, _req, _resp, _tls_open, _tls_close, _host_of, _client_ua, _lookup,
                 _domain_of, _dns_stream, QTYPES)

MAX_UPLOAD = 200_000_000


def https_upload(ctx, src, dst, *, ts, total_bytes=2_000_000, chunk_bytes=262144, method="PUT", path="/upload", chunked=False):
    """Chunked upload of random filler to an external host over decryptable TLS: DNS lookup, one session, then
    parts of about ``chunk_bytes`` each (a PUT/POST per part, or HTTP chunked transfer encoding when ``chunked``),
    a short 201/200 per part, with the size ramp and per-part jitter of a real upload client."""
    total = min(max(int(total_bytes), 1024), MAX_UPLOAD)
    base = max(4096, int(chunk_bytes))
    method = "POST" if str(method).upper() == "POST" else "PUT"
    host = _host_of(dst)
    ua = _client_ua(ctx, src)
    pre, s, tls = _tls_open(ctx, src, dst, ts, profile=getattr(src, "tls_profile", "winhttp"), rate=80e6)
    sent, part = 0, 0
    while sent < total:
        ramp = min(1.0, 0.3 + part * 0.2)
        n = min(total - sent, max(4096, int(base * ramp * F.rng.uniform(0.7, 1.3))))
        data = _rb(n)
        if chunked:
            body = b"".join(b"%x\r\n" % len(data[i:i + 16384]) + data[i:i + 16384] + b"\r\n" for i in range(0, len(data), 16384)) + b"0\r\n\r\n"
            req = _req(method, "%s/part-%04d" % (path.rstrip("/"), part), host, ua,
                       ["Content-Type: application/octet-stream", "Transfer-Encoding: chunked"], body)
        else:
            req = _req(method, "%s/part-%04d" % (path.rstrip("/"), part), host, ua, ["Content-Type: application/octet-stream"], data)
        s.c2s(tls.app_data(True, req), think=F.rng.uniform(0.03, 0.5))
        s.s2c(tls.app_data(False, _resp("201 Created" if method == "PUT" else "200 OK", b'{"ok":true}', "application/json", s.t)),
              think=F.rng.uniform(0.02, 0.15))
        sent += n
        part += 1
    return _tls_close(s, tls, pre, 0.5)


def ftp_upload(ctx, src, dst, *, ts, size=500000, filename="", user="backup", password="not-a-real-password"):
    """An FTP session to an external server, in clear text: control channel on port 21 (220 banner, USER/PASS with
    dummy credentials, TYPE I, PASV), a passive-mode data connection, STOR of an inert archive-looking file
    (zip magic plus filler), closed by the client (the sender's FIN ends the file), 226, QUIT."""
    size = min(max(int(size), 512), MAX_UPLOAD)
    name = filename or "backup_%s.zip" % _b32(6)
    pre = _lookup(ctx, src, dst, ts)
    t = ts + F.rng.uniform(0.005, 0.05) + (0.02 if pre else 0.0)
    out = list(pre) + ctx.arp_for(src, dst, t)
    c = ctx.tcp(src, dst, 21, t + 0.001, rate=50e6).handshake()
    c.s2c(P.ftp_line("220 %s FTP server ready." % (dst.fqdn or dst.name)), think=F.rng.uniform(0.02, 0.12))
    c.c2s(P.ftp_line("USER %s" % user), think=F.rng.uniform(0.08, 0.4))
    c.s2c(P.ftp_line("331 Password required for %s." % user), think=F.rng.uniform(0.01, 0.05))
    c.c2s(P.ftp_line("PASS %s" % password), think=F.rng.uniform(0.05, 0.3))
    c.s2c(P.ftp_line("230 User %s logged in." % user), think=F.rng.uniform(0.02, 0.09))
    c.c2s(P.ftp_line("TYPE I"), think=F.rng.uniform(0.05, 0.2))
    c.s2c(P.ftp_line("200 Type set to I."), think=0.02)
    dp = F.rng.randrange(49152, 65500)
    h = dst.ipb
    c.c2s(P.ftp_line("PASV"), think=F.rng.uniform(0.05, 0.3))
    c.s2c(P.ftp_line("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)." % (h[0], h[1], h[2], h[3], dp >> 8, dp & 0xFF)),
          think=F.rng.uniform(0.01, 0.05))
    c.c2s(P.ftp_line("STOR %s" % name), think=F.rng.uniform(0.05, 0.4))
    d = ctx.tcp(src, dst, dp, c.t + F.rng.uniform(0.004, 0.02), rtt=c.rtt, rate=50e6).handshake()
    c.s2c(P.ftp_line("150 Opening BINARY mode data connection."), think=0.02)
    d.t = max(d.t, c.t + 0.0005)                       # the 150 precedes the first data byte
    body = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + _rb(size - 10)
    for off in range(0, len(body), 8192):
        d.c2s(body[off:off + 8192], think=F.rng.uniform(0.0008, 0.006))
    pk = d.close(by_client=True, think=F.rng.uniform(0.01, 0.06))
    c.s2c(P.ftp_line("226 Transfer complete."), think=F.rng.uniform(0.01, 0.05))
    c.c2s(P.ftp_line("QUIT"), think=F.rng.uniform(0.1, 0.6))
    c.s2c(P.ftp_line("221 Goodbye."), think=0.02)
    return F.merged(out, pk, c.close(think=F.rng.uniform(0.01, 0.05)))


def dns_exfil(ctx, src, dst, *, ts, queries=60, label_len=63, labels=3, qtype="A", gap_s=0.15, domain=""):
    """Data-in-DNS exfiltration: ``queries`` lookups whose names are ``labels`` long random base32 labels
    (up to 63 characters each, 253 in all) under the destination's domain, sent in a quick run; the zone's
    server answers each with a small benign record. Filler only, no real data."""
    dom = _domain_of(dst, domain)
    qt = QTYPES.get(str(qtype).upper(), P.DNS_A)
    ll = min(63, max(8, int(label_len)))
    nl = max(1, min(int(labels), (253 - len(dom) - 1) // (ll + 1)))
    n = max(1, int(queries))
    names = [".".join(_b32(ll) for _ in range(nl)) + "." + dom for _ in range(n)]
    gaps = [max(0.01, float(gap_s) * F.rng.uniform(0.5, 1.5)) for _ in range(n)]
    return _dns_stream(ctx, src, dst, dom, ts, names, qt, gaps, (8, 32))


def smb_collect(ctx, src, dst, *, ts, share="Dept", total_mb=20.0, files=12):
    """Internal collection before exfiltration: the source host reads many files from a share on the
    destination server over SMB2 (Kerberos session, directory listing, then sequential reads), pulling
    ``total_mb`` megabytes across ``files`` files."""
    total = int(min(max(float(total_mb), 0.1), 2000.0) * 1_000_000)
    return F.smb_bulk_transfer(ctx, src, dst, share, total, ts, direction="read", files=max(1, int(files)))


register(ActionSpec(
    token="https_upload", fn=https_upload, title="HTTPS upload", tactic="exfiltration",
    techniques=["T1567", "T1048.002"], protocols=["DNS", "TLS", "HTTPS"],
    summary="Parts of random filler uploaded with PUT or POST to an external host over decryptable TLS.",
    params={"total_bytes": _p("int", 2000000, "Bytes to upload in total."), "chunk_bytes": _p("int", 262144, "Typical part size."),
            "method": _p("str", "PUT", "PUT or POST."), "path": _p("str", "/upload", "Path prefix of each part."),
            "chunked": _p("bool", False, "Use HTTP chunked transfer encoding inside each part.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=10.0))

register(ActionSpec(
    token="ftp_upload", fn=ftp_upload, title="FTP upload", tactic="exfiltration",
    techniques=["T1048.003"], protocols=["DNS", "FTP"],
    summary="A clear-text FTP session to an external server: dummy login, passive data connection, STOR of an inert archive.",
    params={"size": _p("int", 500000, "File size in bytes."), "filename": _p("str", "", "Remote file name."),
            "user": _p("str", "backup", "FTP user name."), "password": _p("str", "not-a-real-password", "Dummy FTP password.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=10.0))

register(ActionSpec(
    token="dns_exfil", fn=dns_exfil, title="DNS exfiltration", tactic="exfiltration",
    techniques=["T1048.003", "T1071.004"], protocols=["DNS"],
    summary="Many DNS queries whose long random base32 labels sit under a destination domain, each answered by its server.",
    params={"queries": _p("int", 60, "Number of queries."), "label_len": _p("int", 63, "Length of each label (max 63)."),
            "labels": _p("int", 3, "Labels per name."), "qtype": _p("str", "A", "A, TXT, CNAME or AAAA."),
            "gap_s": _p("float", 0.15, "Mean seconds between queries."),
            "domain": _p("str", "", "Destination domain; default the destination's name.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=15.0))

register(ActionSpec(
    token="smb_collect", fn=smb_collect, title="SMB data collection", tactic="collection",
    techniques=["T1039", "T1074.001"], protocols=["Kerberos", "SMB2"],
    summary="Sequential SMB2 reads of many files from an internal share, staging data before exfiltration.",
    params={"share": _p("str", "Dept", "Share name."), "total_mb": _p("float", 20.0, "Megabytes read in total."),
            "files": _p("int", 12, "Number of files read.")},
    src="internal", dst="internal", needs=("DC1",), min_duration_s=10.0))

"""E3 writers: Zeek-style ssl.log / x509.log / http.log (zeekapp) and the pcapng converter (pcapngconv),
plus the exporter wiring. Hand-built frames and TLS bytes; two scale-0.004 builds at the bottom (the
same two scenarios test_tag_sidecar uses).

Run from dev/:  python -m unittest tests.test_zeekapp
"""
import datetime
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import build_manifest as BM  # noqa: E402 - sys.path is set up first
import exports_logs as XL  # noqa: E402 - sys.path is set up first
import exports_pcapng as XP  # noqa: E402 - sys.path is set up first
import flowtable  # noqa: E402 - sys.path is set up first
import opengenerator_build as OGB  # noqa: E402 - sys.path is set up first
import pcapngconv  # noqa: E402 - sys.path is set up first
import pcapprofile  # noqa: E402 - sys.path is set up first
import zeekapp as ZA  # noqa: E402 - sys.path is set up first
import zeeklogs  # noqa: E402 - sys.path is set up first
from checks import check_rfc791  # noqa: E402 - sys.path is set up first
from checks import compare_zeek_style as H  # noqa: E402 - sys.path is set up first
from cryptography import x509  # noqa: E402 - sys.path is set up first
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402 - sys.path is set up first
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402 - sys.path is set up first
from cryptography.x509.oid import NameOID  # noqa: E402 - sys.path is set up first
SYN, FIN, ACK, PSH = 2, 1, 16, 8
C, S = "10.0.0.5", "10.0.0.80"
T0 = 1_700_000_000.0
UTC = datetime.timezone.utc


def slurp(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def spill(p):
    with open(p, "rb") as f:
        return f.read()


# ---- frames (checksums left zero: the parsers and tshark ignore them)
def _frame(src, dst, seg):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(seg), 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x02\0\0\0\0\2" + b"\x02\0\0\0\0\1" + b"\x08\x00" + h + seg


def seg(sp, dp, seq, fl, pay=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, 1, 5 << 4, fl, 65535, 0, 0) + pay


class Conv:
    """A hand-driven TCP conversation: .c(data) / .s(data) append in-order segments; .frames = (ts, frame)."""

    def __init__(self, sp=40000, dp=80, t=T0):
        self.sp, self.dp, self.t = sp, dp, t
        self.cs, self.ss, self.frames = 1000, 5000, []
        self._f(C, S, sp, dp, self.cs - 1, SYN)
        self._f(S, C, dp, sp, self.ss - 1, SYN | ACK)
        self._f(C, S, sp, dp, self.cs, ACK)

    def _f(self, a, b, sp, dp, sq, fl, pay=b""):
        self.t += 0.001
        self.frames.append((self.t, _frame(a, b, seg(sp, dp, sq, fl, pay))))

    def c(self, data, seq=None):
        for i in range(0, len(data), 1400) if seq is None else (0,):        # one segment unless auto-split
            part = data[i:i + 1400] if seq is None else data
            self._f(C, S, self.sp, self.dp, self.cs if seq is None else seq, ACK | PSH, part)
            if seq is None:
                self.cs += len(part)

    def s(self, data, seq=None):
        for i in range(0, len(data), 1400) if seq is None else (0,):
            part = data[i:i + 1400] if seq is None else data
            self._f(S, C, self.dp, self.sp, self.ss if seq is None else seq, ACK | PSH, part)
            if seq is None:
                self.ss += len(part)

    def close(self):
        self._f(C, S, self.sp, self.dp, self.cs, FIN | ACK)
        self._f(S, C, self.dp, self.sp, self.ss, FIN | ACK)


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in sorted(frames, key=lambda x: x[0]):
            f.write(struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)), len(fr), len(fr)) + fr)


# ---- TLS bytes
def rec(ct, body):
    return bytes([ct, 3, 3]) + struct.pack("!H", len(body)) + body


def hs(typ, body):
    return bytes([typ]) + len(body).to_bytes(3, "big") + body


def client_hello(sni, sid=b"\x01" * 32, alpn=b"h2"):
    exts = b""
    if sni is not None:
        n = sni if isinstance(sni, bytes) else sni.encode()
        exts += struct.pack("!HHHBH", 0, len(n) + 5, len(n) + 3, 0, len(n)) + n
    if alpn:
        lst = bytes([len(alpn)]) + alpn
        exts += struct.pack("!HHH", 16, len(lst) + 2, len(lst)) + lst
    body = b"\x03\x03" + b"\x11" * 32 + bytes([len(sid)]) + sid + struct.pack("!H", 4) + b"\xc0\x2f\x00\x9c" + b"\x01\x00"
    return rec(22, hs(1, body + struct.pack("!H", len(exts)) + exts))


def server_hello(cipher=0xC02F, sid=b"\x01" * 32, version=0x0303, supported=None, alpn=b"h2"):
    exts = b""
    if supported:
        exts += struct.pack("!HHH", 43, 2, supported)
    if alpn:
        lst = bytes([len(alpn)]) + alpn
        exts += struct.pack("!HHH", 16, len(lst) + 2, len(lst)) + lst
    body = struct.pack("!H", version) + b"\x22" * 32 + bytes([len(sid)]) + sid + struct.pack("!HB", cipher, 0) \
        + struct.pack("!H", len(exts)) + exts
    return rec(22, hs(2, body))


def cert_msg(ders):
    lst = b"".join(len(d).to_bytes(3, "big") + d for d in ders)
    return rec(22, hs(11, len(lst).to_bytes(3, "big") + lst))


_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_cert(cn="www.example.com", sans=("www.example.com",), nb=None, na=None, org=None):
    now = datetime.datetime(2023, 11, 14, tzinfo=UTC)
    nb, na = nb or now - datetime.timedelta(days=30), na or now + datetime.timedelta(days=365)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] + ([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org)] if org else [])
    name = x509.Name(attrs)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(_KEY.public_key())
         .serial_number(0xABC123).not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return b.sign(_KEY, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def tls_conv(sni="www.example.com", der=None, sp=40001, resume=False, **sh):
    cv = Conv(sp=sp, dp=443)
    cv.c(client_hello(sni))
    if resume:
        cv.s(server_hello(**sh) + rec(20, b"\x01"))
    else:
        cv.s(server_hello(**sh) + cert_msg([der or make_cert()]) + rec(22, hs(14, b"")))
    cv.c(rec(22, hs(16, b"\0" * 8)) + rec(20, b"\x01") + rec(22, b"\xee" * 40))
    cv.s(rec(20, b"\x01") + rec(22, b"\xee" * 40))
    cv.close()
    return cv


OK0 = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"


def http_conv(req, resp, sp=40002, dp=80, split=None):
    cv = Conv(sp=sp, dp=dp)
    for part in ([req] if split is None else [req[:split], req[split:]]):
        cv.c(part)
    cv.s(resp)
    cv.close()
    return cv


def analyze(convs, tmp):
    p = os.path.join(tmp, "t.pcap")
    write_pcap(p, [f for cv in convs for f in cv.frames])
    st = {}
    return ZA.analyze(p, stats=st), st, p


def frames_of(path):
    return [(round(t, 6), f) for t, f in pcapprofile.iter_frames(path)]


def data_lines(path):
    return [ln for ln in slurp(path).split("\n") if ln and not ln.startswith("#")]


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def logs(self, convs):
        (ssl, x5, ht), st, pcap = analyze(convs, self.d)
        out = {}
        for name, fn, rows in (("ssl", ZA.write_ssl_log, ssl), ("x509", ZA.write_x509_log, x5), ("http", ZA.write_http_log, ht)):
            p = os.path.join(self.d, name + ".log")
            self.assertEqual(fn(rows, p), len(rows))
            out[name] = (p, H.read_log(p))
        return out, st, pcap


class SslX509Tests(Base):
    def test_handshake_fields_and_chain(self):
        der = make_cert("www.example.com", ("www.example.com", "*.cdn.example.com"), org="Example Org")
        out, st, _ = self.logs([tls_conv(der=der)])
        s = out["ssl"][1][0]
        self.assertEqual((s["version"], s["cipher"], s["server_name"], s["next_protocol"], s["established"]),
                         ("TLSv12", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "www.example.com", "h2", "T"))
        self.assertEqual(s["cert_chain_fps"], hashlib.sha256(der).hexdigest())
        self.assertEqual(s["subject"], "O=Example Org,CN=www.example.com")
        self.assertEqual((s["sni_matches_cert"], s["cert_dates"], s["resumed"]), ("T", "valid", "F"))
        x = out["x509"][1][0]
        self.assertEqual((x["certificate.version"], x["certificate.serial"], x["certificate.key_type"],
                          x["certificate.key_length"], x["certificate.exponent"], x["certificate.sig_alg"]),
                         ("3", "ABC123", "rsa", "2048", "65537", "sha256WithRSAEncryption"))
        self.assertEqual(x["san.dns"], "www.example.com,*.cdn.example.com")
        self.assertEqual((x["basic_constraints.ca"], x["host_cert"], x["client_cert"]), ("F", "T", "F"))
        self.assertEqual(float(x["certificate.not_valid_before"]), datetime.datetime(2023, 10, 15, tzinfo=UTC).timestamp())
        self.assertEqual((st["tls_flows"], st["tls_flows_without_visible_certs"]), (1, 0))

    def test_uid_joins_conn_log(self):
        out, _, pcap = self.logs([tls_conv(), http_conv(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", OK0)])
        cp = os.path.join(self.d, "conn.log")
        zeeklogs.write_conn_log(list(flowtable.flows(pcap)), cp)
        conn = {(r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"]): r["uid"] for r in H.read_log(cp)}
        for name in ("ssl", "http"):
            self.assertTrue(out[name][1])
            for r in out[name][1]:
                self.assertEqual(r["uid"], conn[(r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"])])

    def test_expired_and_not_yet_valid(self):
        past = datetime.datetime(2001, 1, 1, tzinfo=UTC)
        out, _, _ = self.logs([
            tls_conv(der=make_cert(nb=past, na=past + datetime.timedelta(days=10)), sp=40010),
            tls_conv(der=make_cert(nb=datetime.datetime(2090, 1, 1, tzinfo=UTC),
                                   na=datetime.datetime(2091, 1, 1, tzinfo=UTC)), sp=40011)])
        self.assertEqual(sorted(r["cert_dates"] for r in out["ssl"][1]), ["expired", "not_yet_valid"])

    def test_sni_mismatch_and_wildcard(self):
        out, _, _ = self.logs([tls_conv(sni="a.cdn.example.com", der=make_cert("x", ("*.cdn.example.com",)), sp=40020),
                               tls_conv(sni="other.test", der=make_cert(), sp=40021)])
        self.assertEqual({r["server_name"]: r["sni_matches_cert"] for r in out["ssl"][1]},
                         {"a.cdn.example.com": "T", "other.test": "F"})

    def test_tls13_has_no_visible_chain(self):
        cv = Conv(sp=40030, dp=443)
        cv.c(client_hello("t13.example.com"))
        cv.s(server_hello(cipher=0x1301, supported=0x0304) + rec(20, b"\x01") + rec(23, b"\xaa" * 200))
        cv.c(rec(20, b"\x01") + rec(23, b"\xbb" * 50))
        cv.close()
        out, st, _ = self.logs([cv])
        s = out["ssl"][1][0]
        self.assertEqual((s["version"], s["cipher"], s["cert_chain_fps"], s["established"]),
                         ("TLSv13", "TLS_AES_128_GCM_SHA256", None, "T"))
        self.assertEqual(out["x509"][1], [])
        self.assertEqual(st["tls_flows_without_visible_certs"], 1)

    def test_resumed_session_and_alert(self):
        out, _, _ = self.logs([tls_conv(resume=True, sp=40040)])
        self.assertEqual(out["ssl"][1][0]["resumed"], "T")
        cv = Conv(sp=40041, dp=443)
        cv.c(client_hello("x.example.com"))
        cv.s(rec(21, bytes([2, 40])))
        out, _, _ = self.logs([cv])
        s = out["ssl"][1][0]
        self.assertEqual((s["last_alert"], s["established"], s["cipher"]), ("handshake_failure", "F", None))

    def test_segmented_hello_out_of_order_and_retransmit(self):
        ch = client_hello("seg.example.com")
        sh = server_hello() + cert_msg([make_cert("seg.example.com", ("seg.example.com",))])
        cv = Conv(sp=40050, dp=443)
        base = cv.cs
        cv.c(ch[40:], seq=base + 40)           # the second piece first: a hole
        cv.c(ch[:40], seq=base)                # fills it
        cv.c(ch[:40], seq=base)                # a retransmission: ignored
        cv.cs += len(ch)
        for i in range(0, len(sh), 100):       # the server flight in 100-byte segments
            cv.s(sh[i:i + 100])
        cv.close()
        out, st, _ = self.logs([cv])
        s = out["ssl"][1][0]
        self.assertEqual((s["server_name"], s["cipher"], s["sni_matches_cert"]),
                         ("seg.example.com", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "T"))
        self.assertEqual(st["streams_broken"], 0)

    def test_unfillable_hole_marks_the_stream_broken(self):
        cv = Conv(sp=40051, dp=443)
        for i in range(ZA.PEND_SEGS + 2):                      # more segments past a hole than the pending bound
            cv.c(b"\x16" * 10, seq=cv.cs + 100 + 20 * i)
        cv.close()
        (_, _, _), st, _ = analyze([cv], self.d)
        self.assertEqual((st["tcp_flows"], st["tls_flows"]), (1, 0))                  # never sniffed: nothing delivered
        cv2 = Conv(sp=40052, dp=443)
        cv2.c(client_hello("h.example.com"))
        for i in range(ZA.PEND_SEGS + 2):
            cv2.s(b"\x16\x03\x03" * 3, seq=cv2.ss + 500 + 20 * i)
        cv2.close()
        (_, _, _), st, _ = analyze([cv2], self.d)
        self.assertEqual(st["streams_broken"], 1)

    def test_hostile_names_cannot_forge_rows(self):
        evil = "evil\t.com\nFORGED\tROW\x00\x07,x\\"
        der = make_cert(cn="cn\tinj\nline", sans=("a\tb.test",), org="O\r\nx")
        out, _, _ = self.logs([tls_conv(sni=evil.encode(), der=der)])
        for name, width in (("ssl", len(ZA.SSL_FIELDS)), ("x509", len(ZA.X509_FIELDS))):
            for ln in data_lines(out[name][0]):
                self.assertEqual(len(ln.split("\t")), width, name)
        self.assertEqual(len(data_lines(out["ssl"][0])), 1)
        txt = slurp(out["ssl"][0])
        self.assertNotIn("FORGED\tROW", txt)
        for needle in ("\\x09", "\\x0a", "\\x5c"):
            self.assertIn(needle, txt)

    def test_malformed_certificate_gets_a_fingerprint_row(self):
        junk = b"\x30\x03\x01\x01\xff"
        out, _, _ = self.logs([tls_conv(der=junk)])
        x = out["x509"][1][0]
        self.assertEqual(x["fingerprint"], hashlib.sha256(junk).hexdigest())
        self.assertIsNone(x["certificate.subject"])

    def test_garbage_and_truncated_handshakes_do_not_raise(self):
        cv = Conv(sp=40060, dp=443)
        cv.c(b"\x16\x03\x01\x00\x0e" + b"\x01\x00\x00\x1c" + b"\x00" * 10)         # a ClientHello cut short
        cv.s(b"\x16\x03\x03\x00\x05\xff\xff\xff\xff\xff")                           # a junk handshake message
        cv.c(b"\x17\x03\x03\xff\xff")                                               # an absurd record length
        cv.close()
        (ssl, x5, _), _, _ = analyze([cv], self.d)
        self.assertEqual(x5, [])
        self.assertLessEqual(len(ssl), 1)

    def test_oversize_handshake_message_is_skipped_and_counted(self):
        cv = Conv(sp=40070, dp=443)
        cv.c(client_hello("big.example.com"))
        huge = bytes([11]) + (ZA.CAP + 10).to_bytes(3, "big")
        sh = hs(2, b"\x03\x03" + b"\x22" * 32 + b"\x00" + struct.pack("!HB", 0xC02F, 0))
        cv.s(rec(22, sh) + rec(22, huge + b"\0" * 1000))
        for _ in range(5):
            cv.s(rec(22, b"\0" * 16000))
        cv.close()
        (ssl, _, _), st, _ = analyze([cv], self.d)
        self.assertEqual((st["messages_over_cap"], len(ssl)), (1, 1))

    def test_other_traffic_is_ignored(self):
        cv = Conv(sp=40080, dp=22)
        cv.c(b"SSH-2.0-test\r\n")
        cv.s(b"SSH-2.0-other\r\n")
        cv.close()
        (ssl, x5, ht), st, _ = analyze([cv], self.d)
        self.assertEqual((ssl, x5, ht, st["tcp_flows"]), ([], [], [], 1))


class HttpTests(Base):
    def rows(self, convs):
        out, st, _ = self.logs(convs)
        return out["http"][1], st

    def test_request_response_fields(self):
        req = (b"POST /a/b?x=1 HTTP/1.1\r\nHost: h.example.com\r\nUser-Agent: UA/1\r\nReferer: http://r/\r\n"
               b"Origin: http://o\r\nContent-Length: 5\r\n\r\nhello")
        r, _ = self.rows([http_conv(req, b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc")])
        self.assertEqual(len(r), 1)
        x = r[0]
        self.assertEqual((x["method"], x["host"], x["uri"], x["version"], x["user_agent"], x["referrer"], x["origin"]),
                         ("POST", "h.example.com", "/a/b?x=1", "1.1", "UA/1", "http://r/", "http://o"))
        self.assertEqual((x["request_body_len"], x["response_body_len"], x["status_code"], x["status_msg"], x["trans_depth"]),
                         ("5", "3", "404", "Not Found", "1"))

    def test_keepalive_pipeline_chunked_head_and_info(self):
        cv = Conv(sp=40100)
        cv.c(b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nHEAD /2 HTTP/1.1\r\nHost: a\r\n\r\nGET /3 HTTP/1.1\r\nHost: a\r\n\r\n")
        cv.s(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd" b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"
             b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
             b"3\r\nxyz\r\n5;ext=1\r\n12345\r\n0\r\nTrailer: x\r\n\r\n")
        cv.close()
        r, st = self.rows([cv])
        self.assertEqual([x["uri"] for x in r], ["/1", "/2", "/3"])
        self.assertEqual([x["response_body_len"] for x in r], ["4", "0", "8"])        # HEAD: no body despite the length
        self.assertEqual([x["trans_depth"] for x in r], ["1", "2", "3"])
        self.assertEqual((r[2]["info_code"], r[0]["info_code"]), ("100", None))
        self.assertEqual(st["http_flows"], 1)

    def test_body_split_across_segments_is_counted_not_stored(self):
        cv = Conv(sp=40110)
        cv.c(b"GET /big HTTP/1.1\r\nHost: a\r\n\r\n")
        cv.s(b"HTTP/1.1 200 OK\r\nContent-Length: 300000\r\n\r\n" + b"x" * 1000)
        for _ in range(299):
            cv.s(b"y" * 1000)
        cv.close()
        r, st = self.rows([cv])
        self.assertEqual(r[0]["response_body_len"], "300000")
        self.assertEqual((st["messages_over_cap"], st["streams_broken"]), (0, 0))

    def test_close_delimited_response_and_unanswered_request(self):
        cv = Conv(sp=40120)
        cv.c(b"GET /x HTTP/1.0\r\n\r\n")
        cv.s(b"HTTP/1.0 200 OK\r\n\r\nbodybytes")
        cv.close()
        cv2 = Conv(sp=40121)
        cv2.c(b"GET /lost HTTP/1.1\r\nHost: z\r\n\r\n")
        cv2.close()
        r, _ = self.rows([cv, cv2])
        by = {x["uri"]: x for x in r}
        self.assertEqual(by["/x"]["response_body_len"], "9")
        self.assertIsNone(by["/lost"]["status_code"])

    def test_open_event_stream_is_followed_by_the_next_response(self):
        cv = Conv(sp=40125)
        cv.c(b"GET /s HTTP/1.1\r\nHost: a\r\n\r\nGET /t HTTP/1.1\r\nHost: a\r\n\r\n")
        cv.s(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n")
        cv.s(b"id: 1\ndata: x\n\n")
        cv.s(OK0)
        cv.close()
        r, _ = self.rows([cv])
        self.assertEqual([(x["uri"], x["status_code"]) for x in r], [("/s", "200"), ("/t", "200")])
        self.assertEqual(r[0]["response_body_len"], "15")

    def test_split_header(self):
        r, _ = self.rows([http_conv(b"GET /s HTTP/1.1\r\nHost: s\r\n\r\n", OK0, split=11, sp=40130)])
        self.assertEqual((r[0]["uri"], r[0]["status_code"]), ("/s", "200"))

    def test_hostile_values_cannot_forge_rows(self):
        req = (b"GET /p\x01ath\x7f%0d HTTP/1.1\r\nHost: ev\til\x00.com\r\nUser-Agent: a\tb\x7f\xc3\xa9\\\r\n"
               b"X-Forged: \r\n\r\n")
        out, _, _ = self.logs([http_conv(req, b"HTTP/1.1 200 O\tK\x01\r\nContent-Length: 0\r\n\r\n")])
        lines = data_lines(out["http"][0])
        self.assertEqual(len(lines), 1)
        self.assertEqual(len(lines[0].split("\t")), len(ZA.HTTP_FIELDS))
        for needle in ("\\x09", "\\x00", "\\x7f", "\\x5c"):
            self.assertIn(needle, lines[0])

    def test_oversize_header_and_garbage_do_not_raise(self):
        cv = Conv(sp=40140)
        cv.c(b"GET /ok HTTP/1.1\r\nHost: a\r\nX: " + b"a" * (ZA.CAP + 100) + b"\r\n\r\n")
        cv.close()
        cv2 = Conv(sp=40141)
        cv2.c(b"GET /ok HTTP/1.1\r\nContent-Length: abc\r\n\r\n")
        cv2.c(b"\xff" * 50)
        cv2.close()
        r, st = self.rows([cv, cv2])
        self.assertLessEqual(len(r), 2)
        self.assertEqual(st["messages_over_cap"], 1)

    def test_https_content_is_out_of_scope(self):
        r, _ = self.rows([tls_conv()])
        self.assertEqual(r, [])

    def test_vlan_tagged_frames_are_followed(self):
        cv = http_conv(b"GET /v HTTP/1.1\r\nHost: v\r\n\r\n", OK0, sp=40150)
        p = os.path.join(self.d, "v.pcap")
        write_pcap(p, [(t, f[:12] + b"\x81\x00\x00\x14" + f[12:]) for t, f in cv.frames])
        self.assertEqual([x["uri"] for x in ZA.analyze(p)[2]], ["/v"])


class DeterminismAndFlowTests(Base):
    def test_same_pcap_same_rows(self):
        cvs = [tls_conv(), http_conv(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", OK0)]
        a, _, p = analyze(cvs, self.d)
        self.assertEqual(a, ZA.analyze(p))

    def test_port_reuse_after_close_starts_a_new_flow(self):
        a = http_conv(b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\n", OK0, sp=40200)
        b = Conv(sp=40200, t=T0 + 5)
        b.c(b"GET /2 HTTP/1.1\r\nHost: a\r\n\r\n")
        b.s(OK0)
        b.close()
        (_, _, ht), st, _ = analyze([a, b], self.d)
        self.assertEqual([x["uri"] for x in ht], ["/1", "/2"])
        self.assertNotEqual(ht[0]["uid"], ht[1]["uid"])
        self.assertEqual(st["tcp_flows"], 2)

    def test_empty_and_non_ip_capture(self):
        p = os.path.join(self.d, "e.pcap")
        write_pcap(p, [(T0, b"\xff" * 60)])
        self.assertEqual(ZA.analyze(p), ([], [], []))
        write_pcap(p, [])
        self.assertEqual(ZA.analyze(p), ([], [], []))

    def test_json_output_round_trips(self):
        (ssl, _, _), _, _ = analyze([tls_conv()], self.d)
        p = os.path.join(self.d, "s.json")
        ZA.write_ssl_log(ssl, p, "json")
        self.assertEqual(json.loads(slurp(p).splitlines()[0])["server_name"], "www.example.com")


# ---------------------------------------------------------------- pcapng

class PcapngTests(Base):
    def setUp(self):
        super().setUp()
        self.pcap = os.path.join(self.d, "c.pcap")
        cvs = [tls_conv(), http_conv(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx")]
        write_pcap(self.pcap, [f for c in cvs for f in c.frames] + [(T0 + 9, b"\x01" * 61)])   # an odd length: block padding
        self.n = len(frames_of(self.pcap))

    def tags(self, table, ids):
        p = os.path.join(self.d, "c.tags")
        BM.write_tags(p, {t: (i, 0, 0, []) for i, t in enumerate(table)}, bytearray(ids))
        return p

    def test_round_trip_frames_and_times_equal(self):
        out = os.path.join(self.d, "c.pcapng")
        r = pcapngconv.convert(self.pcap, out)
        self.assertEqual(r["packets"], self.n)
        self.assertEqual(frames_of(out), frames_of(self.pcap))
        self.assertEqual(pcapprofile.kind(out), "pcapng")

    def test_deterministic(self):
        a, b = os.path.join(self.d, "a.pcapng"), os.path.join(self.d, "b.pcapng")
        pcapngconv.convert(self.pcap, a, comment="x")
        pcapngconv.convert(self.pcap, b, comment="x")
        self.assertEqual(spill(a), spill(b))

    def test_comments_off_by_default_and_on_by_option(self):
        tags = self.tags(["baseline:web", "incident:demo"], [i % 2 for i in range(self.n)])
        off, on = os.path.join(self.d, "off.pcapng"), os.path.join(self.d, "on.pcapng")
        pcapngconv.convert(self.pcap, off, tags_path=tags)
        r = pcapngconv.convert(self.pcap, on, tags_path=tags, comments=True)
        self.assertNotIn(b"incident:demo", spill(off))
        self.assertEqual(r["comments"], self.n)
        self.assertIn(b"incident:demo", spill(on))
        self.assertEqual(frames_of(on), frames_of(self.pcap))

    def test_comments_need_matching_sidecar(self):
        out = os.path.join(self.d, "x.pcapng")
        with self.assertRaises(ValueError):
            pcapngconv.convert(self.pcap, out, comments=True)
        with self.assertRaises(ValueError):
            pcapngconv.convert(self.pcap, out, tags_path=self.tags(["t"], [0] * (self.n - 1)), comments=True)
        self.assertFalse(os.path.exists(out) or os.path.exists(out + ".tmp"))

    def test_overflow_tag_id_gets_no_comment(self):
        tags = self.tags(["only"], [0] + [255] * (self.n - 1))
        r = pcapngconv.convert(self.pcap, os.path.join(self.d, "o.pcapng"), tags_path=tags, comments=True)
        self.assertEqual(r["comments"], 1)

    def test_keylog_separate_by_default_embedded_on_request(self):
        kl = os.path.join(self.d, "k.log")
        with open(kl, "w") as f:
            f.write("CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48 + "\n")
        sep, emb = os.path.join(self.d, "s.pcapng"), os.path.join(self.d, "e.pcapng")
        r1 = pcapngconv.convert(self.pcap, sep, keylog_path=kl)
        r2 = pcapngconv.convert(self.pcap, emb, keylog_path=kl, embed_keys=True)
        self.assertEqual((r1["embedded_keylog_bytes"], r2["embedded_keylog_bytes"]), (0, os.path.getsize(kl)))
        self.assertNotIn(b"CLIENT_RANDOM", spill(sep))
        self.assertIn(b"CLIENT_RANDOM", spill(emb))
        with self.assertRaises(ValueError):
            pcapngconv.convert(self.pcap, os.path.join(self.d, "z.pcapng"), embed_keys=True)

    def test_rejects_non_pcap_and_truncated_leaving_no_file(self):
        junk = os.path.join(self.d, "j.pcap")
        with open(junk, "wb") as f:
            f.write(b"not a pcap at all, definitely" * 3)
        out = os.path.join(self.d, "j.pcapng")
        with self.assertRaises(ValueError):
            pcapngconv.convert(junk, out)
        cut = os.path.join(self.d, "cut.pcap")
        with open(cut, "wb") as g:
            g.write(spill(self.pcap)[:-7])
        with self.assertRaises(ValueError):
            pcapngconv.convert(cut, out)
        self.assertFalse(os.path.exists(out) or os.path.exists(out + ".tmp"))

    def test_nanosecond_and_big_endian_pcaps_convert_to_the_same_times(self):
        def mk(path, magic, end, div):
            with open(path, "wb") as f:
                f.write(struct.pack(end + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
                fr = b"\xaa" * 60
                f.write(struct.pack(end + "IIII", 1700000000, 123456 * div, 60, 60) + fr)
        for name, magic, end, div in (("ns", 0xA1B23C4D, "<", 1000), ("be", 0xA1B2C3D4, ">", 1)):
            p, o = os.path.join(self.d, name + ".pcap"), os.path.join(self.d, name + ".pcapng")
            mk(p, magic, end, div)
            self.assertEqual(pcapngconv.convert(p, o)["first_ts"], (1700000000, 123456), name)

    def test_rfc791_checker_reads_pcapng(self):
        out = os.path.join(self.d, "r.pcapng")
        pcapngconv.convert(self.pcap, out)
        ex = ("ip.checksum", "tcp.checksum")
        self.assertEqual(check_rfc791.check(self.pcap, quiet=True, exempt=ex)[0], check_rfc791.check(out, quiet=True, exempt=ex)[0])

    @unittest.skipUnless(H.tshark_path() and H.capinfos_path(), "tshark/capinfos not installed")
    def test_tshark_and_capinfos_agree_with_the_pcap(self):
        out = os.path.join(self.d, "t.pcapng")
        kl = os.path.join(self.d, "k.log")
        with open(kl, "w") as f:
            f.write("CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48 + "\n")
        pcapngconv.convert(self.pcap, out, tags_path=self.tags(["a", "b"], [0] * self.n), comments=True,
                           keylog_path=kl, embed_keys=True, comment="gen 1; params abc")
        diffs, summ = H.compare_pcapng(self.pcap, out)
        self.assertEqual(diffs, [], summ)
        self.assertEqual(summ["pcapng"]["packets"], self.n)
        got = subprocess.run([H.tshark_path(), "-r", out, "-T", "fields", "-e", "frame.comment"], capture_output=True,
                             text=True, check=True, timeout=60).stdout.split()
        self.assertEqual((len(got), set(got)), (self.n, {"a"}))

    @unittest.skipUnless(H.tshark_path(), "tshark not installed")
    def test_tshark_agrees_with_the_logs(self):
        cvs = [tls_conv(sni="a.example.com", sp=41000),
               tls_conv(sni="b.example.com", sp=41001, der=make_cert("b.example.com", ("b.example.com",))),
               http_conv(b"GET /q?z=1 HTTP/1.1\r\nHost: a\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", sp=41002)]
        out, _, pcap = self.logs(cvs)
        self.assertEqual(H.compare_ssl(pcap, out["ssl"][0])[0], [])
        self.assertEqual(H.compare_x509(pcap, out["x509"][0])[0], [])
        self.assertEqual(H.compare_http(pcap, out["http"][0])[0], [])


# ---------------------------------------------------------------- exporters and the build

class FakeWriter:
    def __init__(self, n):
        self.n = n


class ExporterTests(Base):
    def ctx(self, exports=(), tags_path=None, opts=None):
        cvs = [tls_conv(), http_conv(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", OK0)]
        out = os.path.join(self.d, "e.pcap")
        write_pcap(out, [f for c in cvs for f in c.frames])
        return OGB._ExportCtx(out=out, writer=FakeWriter(len(frames_of(out))), exports=set(exports), tags_path=tags_path,
                              keylog=None, pcapng_options=opts or {}, generator="9.9", params_sha256="ab" * 32)

    def test_not_requested_means_nothing(self):
        e = self.ctx()
        self.assertEqual((XL.export(e), XP.export(e)), ({}, {}))
        self.assertEqual(os.listdir(self.d), ["e.pcap"])

    def test_blocks_and_files(self):
        e = self.ctx({"ssl", "http", "pcapng"})
        res = {**XL.export(e), **XP.export(e)}
        self.assertEqual(sorted(res), ["http", "pcapng", "ssl"])
        for k, b in res.items():
            self.assertNotIn("error", b, b)
            self.assertTrue(b["exports_consistent"], k)
            for f in b["files"]:
                self.assertTrue(os.path.isfile(os.path.join(self.d, f)))
        self.assertEqual(res["ssl"]["files"], ["e-ssl.log", "e-x509.log"])
        self.assertEqual(res["pcapng"]["files"], ["e.pcapng"])
        self.assertEqual(res["ssl"]["records"], {"ssl": 1, "x509": 1})
        self.assertEqual(res["ssl"]["rules"]["reassembly_cap_bytes"], ZA.CAP)
        self.assertNotIn("10.0.0", json.dumps(res), "no addresses in the manifest blocks")

    def test_consistency_flag_goes_false_on_a_count_mismatch(self):
        e = self.ctx({"ssl"})
        e.writer = FakeWriter(e.writer.n + 1)
        self.assertFalse(XL.export(e)["ssl"]["exports_consistent"])

    def test_sidecar_overflow_reports_error_for_comments_but_the_logs_still_work(self):
        e = self.ctx({"ssl", "pcapng"}, opts={"comments": True}, tags_path=None)
        res = {**XL.export(e), **XP.export(e)}
        self.assertIn("tag sidecar is missing", res["pcapng"]["error"])
        self.assertNotIn("files", res["pcapng"])
        self.assertNotIn("error", res["ssl"])
        self.assertFalse(os.path.exists(XP.pcapng_path(e.out)))

    def test_a_failing_writer_is_recorded_not_raised(self):
        e = self.ctx({"ssl", "http"})
        e.out = os.path.join(self.d, "missing.pcap")               # the pcap is gone: analyze fails
        res = XL.export(e)
        self.assertIn("Error", res["ssl"]["error"])
        self.assertIn("Error", res["http"]["error"])
        self.assertEqual(sorted(os.listdir(self.d)), ["e.pcap"])


NAMES = ["ndr-rdp-brute", "npm-sql1-service-failure"]


def _build(d, stem, **kw):
    return OGB.build(scale=0.004, out=os.path.join(d, stem + ".pcap"), keylog=os.path.join(d, stem + ".keys"),
                     inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None,
                     modules=NAMES, progress=False, **kw)


class BuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-e3-")
        cls.on = _build(cls.d, "on", exports=["ssl", "http", "pcapng"], pcapng_comments=True)
        cls.off = _build(cls.d, "off")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def manifest(self, stem):
        with open(os.path.join(self.d, stem + ".manifest.json")) as f:
            return json.load(f)

    def test_off_build_adds_nothing_and_on_build_is_equivalent(self):
        self.assertEqual((self.on["packets"], self.on["protocols"]), (self.off["packets"], self.off["protocols"]))
        self.assertNotIn("exports", self.off)
        self.assertNotIn("exports", self.manifest("off"))
        self.assertEqual(sorted(f for f in os.listdir(self.d) if f.startswith("off")),
                         ["off-generation-report.csv", "off.keys", "off.manifest.json", "off.pcap"])

    def test_manifest_lists_every_new_file_with_bytes_and_sha(self):
        m = self.manifest("on")
        outs = {o["name"]: o for o in m["outputs"]}
        for name in ("on-ssl.log", "on-x509.log", "on-http.log", "on.pcapng", "on.tags"):
            self.assertIn(name, outs)
            p = os.path.join(self.d, name)
            self.assertEqual((outs[name]["bytes"], outs[name]["sha256"]), (os.path.getsize(p), BM.sha256_file(p)))
        self.assertEqual(sorted(m["exports"]), ["http", "pcapng", "ssl"])
        self.assertEqual(m["parameters"]["exports"], ["http", "pcapng", "ssl"])
        self.assertEqual(m["parameters"]["pcapng_options"], {"comments": True})
        self.assertTrue(all(b["exports_consistent"] for b in m["exports"].values()))
        self.assertEqual(m["exports"]["pcapng"]["comment_count"], self.on["packets"])
        self.assertNotEqual(m["parameters"], self.manifest("off")["parameters"])   # else a rebuild would delete the earlier copy

    def test_pcapng_matches_the_pcap_and_comments_carry_tags(self):
        a, b = os.path.join(self.d, "on.pcap"), os.path.join(self.d, "on.pcapng")
        self.assertEqual(frames_of(a), frames_of(b))
        self.assertIn(b"incident:ndr-rdp-brute", spill(b))
        self.assertNotIn(b"CLIENT_RANDOM", spill(b))                            # the key log stays separate by default

    def test_logs_agree_with_tshark(self):
        if not H.tshark_path():
            self.skipTest("tshark not installed")
        pcap = os.path.join(self.d, "on.pcap")
        for fn, log in ((H.compare_ssl, "on-ssl.log"), (H.compare_x509, "on-x509.log"), (H.compare_http, "on-http.log")):
            diffs, summ = fn(pcap, os.path.join(self.d, log))
            self.assertEqual(diffs, [], (log, summ))

    def test_unknown_export_and_pcapng_option_without_pcapng_are_refused(self):
        with self.assertRaises(ValueError):
            _build(self.d, "bad", exports=["nope"])
        with self.assertRaises(ValueError):
            _build(self.d, "bad", exports=["ssl"], pcapng_embed_keys=True)

    def test_hold_previous_moves_the_export_files_with_their_pcap(self):
        d = tempfile.mkdtemp(prefix="og-e3-hold-")
        self.addCleanup(shutil.rmtree, d, True)
        _build(d, "h", exports=["pcapng", "ssl"])
        self.assertTrue(os.path.isfile(os.path.join(d, "h.pcapng")))
        _build(d, "h")                                         # different settings: the first build is kept
        self.assertFalse(os.path.exists(os.path.join(d, "h.pcapng")))
        self.assertFalse(os.path.exists(os.path.join(d, "h-ssl.log")))
        kept = [os.path.join(r, f) for r, _, fs in os.walk(os.path.join(d, "earlier-builds")) for f in fs]
        for want in ("h.pcapng", "h-ssl.log", "h-x509.log"):
            self.assertTrue(any(k.endswith(want) for k in kept), (want, kept))


if __name__ == "__main__":
    unittest.main()

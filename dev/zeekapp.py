"""Zeek-style ssl.log, x509.log and plaintext http.log from a finished classic pcap (one pass).

"Zeek-style" means the standard Zeek column names, types and TSV header block (zeeklogs.write_rows),
filled by this module's own rules. It is NOT claimed to match a real Zeek run; that claim waits for a
reference run. The column sets are from memory of recent Zeek releases and are not verified against one.

analyze(pcap_path, rules=None, stats=None) streams the capture once, follows IPv4 TCP flows with the
same flow boundaries and the same uid as flowtable/zeeklogs.write_conn_log (so uid joins to conn.log),
reassembles each direction under a cap, sniffs the payload (not the port) and returns three lists of
row dicts keyed by Zeek field name: (ssl_rows, x509_rows, http_rows).

Reassembly (bounded, recorded): per direction, in-order bytes are fed to the parser; a segment past a
hole waits in a pending set of at most PEND_SEGS segments / CAP bytes, a retransmission is trimmed, and
a stream that overflows either bound is marked broken and parsed no further (stats["streams_broken"]).
Buffered bytes per direction never exceed CAP (65,536): TLS keeps only an incomplete record or
handshake message, HTTP only an incomplete header block or chunk-size line; HTTP bodies are counted and
skipped, not stored. A message that claims to be larger than CAP is skipped and counted
(stats["messages_over_cap"]). Only TCP over untagged or 802.1Q/QinQ-tagged IPv4 is followed; IPv6 and
fragments are not.

ssl.log: version/cipher/curve/server_name/next_protocol/established/last_alert from the handshake as
sent; the certificate chain only when it is in the clear (TLS 1.2 and earlier, and the clear TLS 1.3-shaped
Certificate message the engine emits; a real TLS 1.3 handshake is encrypted, so its rows carry no chain). resumed is true when the server echoes a non-empty session id
without sending a certificate (TLS 1.2 and earlier). subject/issuer are the server leaf's, as in older
Zeek. sni_matches_cert compares server_name with the leaf's DNS SANs (or CN) with one wildcard label.
cert_dates is NOT a Zeek column: "valid" / "expired" / "not_yet_valid" compares the flow time with the
leaf's validity dates; the chain itself is never validated. ssl_history is not produced.
x509.log: one row per certificate per connection in which it was seen in the clear (as Zeek logs one
per file), fingerprint = SHA-256 of the DER. host_cert is true for the first certificate of a server
chain and client_cert for the first of a client chain.
http.log: one row per request, paired with the n-th final response on the flow (1xx responses fill
info_code/info_msg). Sizes are wire bytes of the body (content-encoded, NOT decompressed: Zeek reports
the decoded size). A close-delimited response counts bytes to the end of the flow, except that a later segment opening with
an HTTP status line is taken as the next response (the engine's SSE streams stay open and are answered on again). username/password,
file ids and mime types are not produced. HTTPS content is out of scope.

Determinism: rows are a pure function of the pcap bytes; ordering is by (ts, uid, sequence).
"""
import datetime
import hashlib
import os
import re
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import flowtable  # noqa: E402 - sys.path is set up first
import pcapprofile  # noqa: E402 - sys.path is set up first
import zeeklogs  # noqa: E402 - sys.path is set up first
CAP = 65536                        # bytes buffered per direction
PEND_SEGS = 64                     # out-of-order segments held per direction
RULES = {"reassembly_cap_bytes": CAP, "pending_segments": PEND_SEGS,
         "tcp_idle": flowtable.RULES["tcp_idle"], "flow_boundaries": "same as flowtable (idle gap, SYN after FIN/RST)"}

_M32 = 0xFFFFFFFF
_SWEEP_S = 30.0

SSL_FIELDS = [
    ("ts", "time"), ("uid", "string"), ("id.orig_h", "addr"), ("id.orig_p", "port"),
    ("id.resp_h", "addr"), ("id.resp_p", "port"), ("version", "string"), ("cipher", "string"),
    ("curve", "string"), ("server_name", "string"), ("resumed", "bool"), ("last_alert", "string"),
    ("next_protocol", "string"), ("established", "bool"), ("cert_chain_fps", "vector[string]"),
    ("client_cert_chain_fps", "vector[string]"), ("subject", "string"), ("issuer", "string"),
    ("client_subject", "string"), ("client_issuer", "string"), ("sni_matches_cert", "bool"),
    ("cert_dates", "string")]

X509_FIELDS = [
    ("ts", "time"), ("fingerprint", "string"), ("certificate.version", "count"),
    ("certificate.serial", "string"), ("certificate.subject", "string"), ("certificate.issuer", "string"),
    ("certificate.not_valid_before", "time"), ("certificate.not_valid_after", "time"),
    ("certificate.key_alg", "string"), ("certificate.sig_alg", "string"), ("certificate.key_type", "string"),
    ("certificate.key_length", "count"), ("certificate.exponent", "string"), ("certificate.curve", "string"),
    ("san.dns", "vector[string]"), ("san.uri", "vector[string]"), ("san.email", "vector[string]"),
    ("san.ip", "vector[addr]"), ("basic_constraints.ca", "bool"), ("basic_constraints.path_len", "count"),
    ("host_cert", "bool"), ("client_cert", "bool")]

HTTP_FIELDS = [
    ("ts", "time"), ("uid", "string"), ("id.orig_h", "addr"), ("id.orig_p", "port"),
    ("id.resp_h", "addr"), ("id.resp_p", "port"), ("trans_depth", "count"), ("method", "string"),
    ("host", "string"), ("uri", "string"), ("referrer", "string"), ("version", "string"),
    ("user_agent", "string"), ("origin", "string"), ("request_body_len", "count"),
    ("response_body_len", "count"), ("status_code", "count"), ("status_msg", "string"),
    ("info_code", "count"), ("info_msg", "string"), ("tags", "set[enum]"), ("username", "string"),
    ("password", "string"), ("proxied", "set[string]"), ("orig_fuids", "vector[string]"),
    ("orig_filenames", "vector[string]"), ("orig_mime_types", "vector[string]"),
    ("resp_fuids", "vector[string]"), ("resp_filenames", "vector[string]"),
    ("resp_mime_types", "vector[string]")]

TLS_VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv10", 0x0302: "TLSv11", 0x0303: "TLSv12", 0x0304: "TLSv13"}
CIPHERS = {
    0x0004: "TLS_RSA_WITH_RC4_128_MD5", 0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256"}
CURVES = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001D: "x25519", 0x001E: "x448"}
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
          42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
          45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
          49: "access_denied", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
          71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
          90: "user_canceled", 112: "unrecognized_name"}
SIG_ALGS = {"1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
            "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
            "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
            "1.2.840.10045.4.3.4": "ecdsa-with-SHA512", "1.3.101.112": "ED25519"}


def _txt(b):
    return b.decode("ascii", "replace")


def _ver(v):
    return TLS_VERSIONS.get(v, "unknown-0x%04x" % v)


# ---------------------------------------------------------------- reassembly


class _Stream:
    """One TCP direction: sequence-ordered bytes, bounded. push() returns the bytes now deliverable."""
    __slots__ = ("nxt", "pend", "pend_bytes", "broken")

    def __init__(self):
        self.nxt = None
        self.pend = {}
        self.pend_bytes = 0
        self.broken = False

    def push(self, seq, data, syn):
        if syn:
            self.nxt = (seq + 1) & _M32
        if not data or self.broken:
            return None
        if self.nxt is None:
            self.nxt = seq
        d = (seq - self.nxt) & _M32
        if d >= 0x80000000:                              # starts before what we have: trim the overlap
            over = (self.nxt - seq) & _M32
            if over >= len(data):
                return None                              # a pure retransmission
            data, d = data[over:], 0
        if d:
            if len(self.pend) >= PEND_SEGS or self.pend_bytes + len(data) > CAP:
                self.broken = True
                self.pend.clear()
                return None
            if seq not in self.pend:
                self.pend[seq] = data
                self.pend_bytes += len(data)
            return None
        out = data
        self.nxt = (self.nxt + len(data)) & _M32
        while self.pend and self.nxt in self.pend:
            more = self.pend.pop(self.nxt)
            self.pend_bytes -= len(more)
            out += more
            self.nxt = (self.nxt + len(more)) & _M32
        return out


# ---------------------------------------------------------------- TLS


class _Tls:
    """TLS record/handshake parser for one direction. Fields land in the shared per-flow dict `t`."""

    def __init__(self, side, t, st):
        self.side, self.t, self.st = side, t, st
        self.buf = bytearray()
        self.hs = bytearray()
        self.skip = 0                                    # bytes of an over-cap handshake message left to drop
        self.enc = False
        self.dead = False

    def feed(self, data, ts):
        if self.dead:
            return
        b = self.buf
        b += data
        while len(b) >= 5:
            ct, ln = b[0], b[3] << 8 | b[4]
            if ct not in (20, 21, 22, 23) or b[1] != 3 or ln > 18432:
                self.dead = True                         # not TLS (or garbage): stop, keep what we have
                self.buf = bytearray()
                return
            if len(b) < 5 + ln:
                break
            body = bytes(b[5:5 + ln])
            del b[:5 + ln]
            self._record(ct, body, ts)
            if self.dead:
                return
        if len(b) > CAP:
            self.dead = True
            self.st["streams_capped"] += 1
            self.buf = bytearray()

    def _record(self, ct, body, ts):
        t = self.t
        if ct == 20:
            self.enc = True
            t["ccs_" + self.side] = True
        elif ct == 23:
            t["app_" + self.side] = True
            self.dead = True                             # nothing more in the clear
        elif ct == 21 and not self.enc and len(body) >= 2:
            t["alert"] = ALERTS.get(body[1], "alert_%d" % body[1])
        elif ct == 22 and not self.enc:
            if t["ts"] is None:
                t["ts"] = ts
            self.hs += body
            while True:
                if self.skip:
                    n = min(self.skip, len(self.hs))
                    del self.hs[:n]
                    self.skip -= n
                    if self.skip:
                        break
                if len(self.hs) < 4:
                    break
                ln = self.hs[1] << 16 | self.hs[2] << 8 | self.hs[3]
                if ln > CAP:
                    self.st["messages_over_cap"] += 1
                    self.skip = ln + 4                   # drop it as it streams past
                    continue
                if len(self.hs) < 4 + ln:
                    break
                typ, msg = self.hs[0], bytes(self.hs[4:4 + ln])
                del self.hs[:4 + ln]
                try:
                    self._msg(typ, msg, ts)
                except (IndexError, struct.error, ValueError):
                    t["malformed"] = True

    def _msg(self, typ, m, ts):
        t, c = self.t, self.side == "c"
        if typ == 1 and c:
            self._client_hello(m)
        elif typ == 2 and not c:
            self._server_hello(m)
        elif typ == 11:
            tls13 = t.get("s_ver") == 0x0304                 # context byte first, an extension block after each certificate
            o = 1 if tls13 else 0
            end = o + 3 + (m[o] << 16 | m[o + 1] << 8 | m[o + 2])
            o, ders = o + 3, []
            while o + 3 <= end:
                n = m[o] << 16 | m[o + 1] << 8 | m[o + 2]
                ders.append(m[o + 3:o + 3 + n])
                o += 3 + n + (2 + (m[o + 3 + n] << 8 | m[o + 4 + n]) if tls13 else 0)
            t["certs_" + self.side] = ders
            t["certs_ts_" + self.side] = ts
        elif typ == 12 and not c and len(m) >= 4 and m[0] == 3:
            t["curve"] = CURVES.get(m[1] << 8 | m[2], "0x%04x" % (m[1] << 8 | m[2]))

    @staticmethod
    def _exts(m, o):
        end = o + 2 + (m[o] << 8 | m[o + 1])
        o += 2
        while o + 4 <= end:
            typ, n = m[o] << 8 | m[o + 1], m[o + 2] << 8 | m[o + 3]
            yield typ, m[o + 4:o + 4 + n]
            o += 4 + n

    def _client_hello(self, m):
        t = self.t
        o = 34
        t["c_sid"] = bytes(m[o + 1:o + 1 + m[o]])
        t["c_ver"] = m[0] << 8 | m[1]
        o += 1 + m[o]
        o += 2 + (m[o] << 8 | m[o + 1])
        o += 1 + m[o]
        if o + 2 <= len(m):
            for typ, d in self._exts(m, o):
                if typ == 0 and len(d) >= 5 and d[2] == 0:
                    t["sni"] = _txt(d[5:5 + (d[3] << 8 | d[4])])

    def _server_hello(self, m):
        t = self.t
        o = 34
        t["s_sid"] = bytes(m[o + 1:o + 1 + m[o]])
        o += 1 + m[o]
        t["cipher"] = m[o] << 8 | m[o + 1]
        t["s_ver"] = m[0] << 8 | m[1]
        o += 3
        if o + 2 <= len(m):
            for typ, d in self._exts(m, o):
                if typ == 43 and len(d) >= 2:
                    t["s_ver"] = d[0] << 8 | d[1]
                elif typ == 16 and len(d) >= 4:
                    t["alpn"] = _txt(d[3:3 + d[2]])


# ---------------------------------------------------------------- HTTP

_HDR, _CL, _CLOSE, _CSIZE, _CDATA, _CCRLF, _CTRAIL = range(7)
_REQ_LINE = re.compile(rb"^([A-Za-z]{3,16}) (\S+) HTTP/(\d\.\d)$")
_RESP_LINE = re.compile(rb"^HTTP/(\d\.\d) (\d{3})(?: (.*))?$")
_RESP_START = re.compile(rb"^HTTP/\d\.\d \d{3} ")
_START = re.compile(rb"^(?:[A-Za-z]{3,16} \S+ HTTP/\d\.\d\r\n|HTTP/\d\.\d \d{3})")


class _Http:
    """Streaming HTTP/1.x parser for one direction; messages land in self.msgs (dicts). `peer` is the
    other direction's parser (a response needs its request's method to know whether a body follows)."""

    def __init__(self, resp, st):
        self.resp, self.st, self.peer = resp, st, None
        self.buf = bytearray()
        self.mode = _HDR
        self.n = 0                                       # bytes left in the current body part
        self.cur = None
        self.msgs = []
        self.hts = None
        self.dead = False

    def feed(self, data, ts):
        while data and not self.dead:
            m = self.mode
            if m == _HDR:
                if not self.buf:
                    self.hts = ts
                self.buf += data
                i = self.buf.find(b"\r\n\r\n")
                if i < 0 or i > CAP:
                    if len(self.buf) > CAP:
                        self.dead = True
                        self.st["messages_over_cap"] += 1
                    return
                head, data = bytes(self.buf[:i]), bytes(self.buf[i + 4:])
                self.buf = bytearray()
                if not self._start(head):
                    self.dead = True
            elif m in (_CL, _CDATA, _CCRLF):
                k = min(self.n, len(data))
                if m != _CCRLF:
                    self.cur["body"] += k
                self.n -= k
                data = data[k:]
                if self.n == 0:
                    if m == _CL:
                        self.mode, self.cur = _HDR, None
                    elif m == _CDATA:
                        self.mode, self.n = _CCRLF, 2
                    else:
                        self.mode = _CSIZE
            elif m == _CLOSE:
                if _RESP_START.match(data):                      # a keep-alive stream (SSE) with no length that the server
                    self.mode, self.cur = _HDR, None             # then answers on again: a segment that opens with a status line
                    continue                                     # is the next response, not more body
                self.cur["body"] += len(data)
                return
            else:                                        # a chunk-size line, or a trailer line
                self.buf += data
                i = self.buf.find(b"\r\n")
                if i < 0:
                    if len(self.buf) > CAP:
                        self.dead = True
                    return
                line, data = bytes(self.buf[:i]), bytes(self.buf[i + 2:])
                self.buf = bytearray()
                if m == _CSIZE:
                    try:
                        size = int(line.split(b";")[0].strip(), 16)
                    except ValueError:
                        self.dead = True
                        return
                    self.mode, self.n = (_CDATA, size) if size else (_CTRAIL, 0)
                elif not line:                           # a blank line ends the trailers
                    self.mode, self.cur = _HDR, None

    def _start(self, head):
        lines = head.split(b"\r\n")
        msg = {"ts": self.hts, "body": 0, "h": {}}
        if self.resp:
            m = _RESP_LINE.match(lines[0])
            if not m:
                return False
            msg.update(version=_txt(m.group(1)), code=int(m.group(2)), text=_txt(m.group(3) or b""))
        else:
            m = _REQ_LINE.match(lines[0])
            if not m:
                return False
            msg.update(method=_txt(m.group(1)), uri=_txt(m.group(2)), version=_txt(m.group(3)))
        for ln in lines[1:]:
            k, sep, v = ln.partition(b":")
            if sep:
                msg["h"].setdefault(k.strip().lower(), v.strip())
        self.msgs.append(msg)
        self.cur = msg
        h = msg["h"]
        if self.resp:
            code = msg["code"]
            j = sum(1 for x in self.msgs[:-1] if x["code"] >= 200)       # index among final responses
            head_req = bool(self.peer) and j < len(self.peer.msgs) and self.peer.msgs[j]["method"] == "HEAD"
            if code == 101:
                return False                                              # the stream is no longer HTTP
            if 100 <= code < 200 or code in (204, 304) or head_req:
                self.mode, self.cur = _HDR, None
                return True
        if b"chunked" in h.get(b"transfer-encoding", b"").lower():
            self.mode = _CSIZE
        elif b"content-length" in h:
            try:
                n = int(h[b"content-length"])
            except ValueError:
                return False
            if n < 0:
                return False
            self.mode, self.n = (_CL, n) if n else (_HDR, 0)
            if not n:
                self.cur = None
        elif self.resp:
            self.mode = _CLOSE
        else:
            self.mode, self.cur = _HDR, None
        return True


# ---------------------------------------------------------------- x509 and row building


def _x509_row(der, ts, host, client):
    row = {n: None for n, _ in X509_FIELDS}
    row.update(ts=ts, fingerprint=hashlib.sha256(der).hexdigest(), host_cert=host, client_cert=client)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
        c = x509.load_der_x509_certificate(der)
        nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        row.update({"certificate.version": c.version.value + 1, "certificate.serial": format(c.serial_number, "X"),
                    "certificate.subject": c.subject.rfc4514_string(), "certificate.issuer": c.issuer.rfc4514_string(),
                    "certificate.not_valid_before": nb.timestamp(), "certificate.not_valid_after": na.timestamp(),
                    "certificate.sig_alg": SIG_ALGS.get(c.signature_algorithm_oid.dotted_string,
                                                        c.signature_algorithm_oid.dotted_string)})
        k = c.public_key()
        if isinstance(k, rsa.RSAPublicKey):
            row.update({"certificate.key_alg": "rsaEncryption", "certificate.key_type": "rsa",
                        "certificate.key_length": k.key_size, "certificate.exponent": str(k.public_numbers().e)})
        elif isinstance(k, ec.EllipticCurvePublicKey):
            row.update({"certificate.key_alg": "id-ecPublicKey", "certificate.key_type": "ecdsa",
                        "certificate.key_length": k.key_size, "certificate.curve": k.curve.name})
        elif isinstance(k, dsa.DSAPublicKey):
            row.update({"certificate.key_alg": "dsaEncryption", "certificate.key_type": "dsa",
                        "certificate.key_length": k.key_size})
        try:
            san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            row["san.dns"] = san.get_values_for_type(x509.DNSName) or None
            row["san.uri"] = san.get_values_for_type(x509.UniformResourceIdentifier) or None
            row["san.email"] = san.get_values_for_type(x509.RFC822Name) or None
            row["san.ip"] = [str(a) for a in san.get_values_for_type(x509.IPAddress)] or None
        except x509.ExtensionNotFound:
            pass
        try:
            bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
            row["basic_constraints.ca"], row["basic_constraints.path_len"] = bc.ca, bc.path_length
        except x509.ExtensionNotFound:
            pass
    except (ValueError, TypeError, ImportError) as e:   # a malformed certificate still gets its fingerprint row
        row["parse_error"] = type(e).__name__
    return row


def _name_matches(sni, row):
    subj = row.get("certificate.subject") or ""
    names = row.get("san.dns") or ([subj[3:].split(",")[0]] if subj.startswith("CN=") else [])
    sni = sni.lower().rstrip(".")
    for nm in names:
        nm = nm.lower()
        if nm == sni or (nm.startswith("*.") and "." in sni and sni.split(".", 1)[1] == nm[2:]):
            return True
    return False


def _tls_rows(f, uid, t, ssl, x509, seq, cache):
    if t.get("c_sid") is None and t.get("cipher") is None:
        return                                           # no hello was parsed: nothing to log
    ts0 = t["ts"]
    chains = {}
    for side in ("s", "c"):
        for i, der in enumerate(t.get("certs_" + side) or ()):
            r = cache.get(der)
            if r is None:
                r = cache[der] = _x509_row(der, 0.0, False, False)
            r = dict(r, ts=t["certs_ts_" + side], host_cert=side == "s" and i == 0, client_cert=side == "c" and i == 0)
            x509.append((r["ts"], r["fingerprint"], uid, seq[0], r))
            seq[0] += 1
            chains.setdefault(side, []).append(r)
    ver = t.get("s_ver") or t.get("c_ver")
    leaf, cleaf = (chains.get("s") or [None])[0], (chains.get("c") or [None])[0]
    sni, cipher = t.get("sni"), t.get("cipher")
    resumed = None
    if t.get("s_sid") is not None and (t.get("s_ver") or 0) < 0x0304:
        resumed = bool(t["s_sid"]) and t["s_sid"] == t.get("c_sid") and "s" not in chains
    dates = None
    if leaf and leaf.get("certificate.not_valid_before") is not None:
        dates = ("not_yet_valid" if ts0 < leaf["certificate.not_valid_before"] else
                 "expired" if ts0 > leaf["certificate.not_valid_after"] else "valid")
    ssl.append((ts0, uid, seq[0], {
        "ts": ts0, "uid": uid, "id.orig_h": f[0], "id.orig_p": f[1], "id.resp_h": f[2], "id.resp_p": f[3],
        "version": _ver(ver) if ver else None,
        "cipher": None if cipher is None else CIPHERS.get(cipher, "unknown-0x%04x" % cipher),
        "curve": t.get("curve"), "server_name": sni, "resumed": resumed, "last_alert": t.get("alert"),
        "next_protocol": t.get("alpn"),
        "established": bool(cipher is not None and (t.get("ccs_s") or t.get("app_s"))),
        "cert_chain_fps": [r["fingerprint"] for r in chains["s"]] if "s" in chains else None,
        "client_cert_chain_fps": [r["fingerprint"] for r in chains["c"]] if "c" in chains else None,
        "subject": leaf and leaf["certificate.subject"], "issuer": leaf and leaf["certificate.issuer"],
        "client_subject": cleaf and cleaf["certificate.subject"],
        "client_issuer": cleaf and cleaf["certificate.issuer"],
        "sni_matches_cert": _name_matches(sni, leaf) if sni and leaf else None, "cert_dates": dates}))
    seq[0] += 1


def _http_rows(f, uid, reqs, resps, http, seq):
    finals, infos = [], {}
    for r in resps:
        if r["code"] < 200 and r["code"] != 101:
            infos[len(finals)] = r
        else:
            finals.append(r)
    for i, q in enumerate(reqs):
        p, inf, h = (finals[i] if i < len(finals) else None), infos.get(i), q["h"]
        row = {n: None for n, _ in HTTP_FIELDS}
        row.update({
            "ts": q["ts"], "uid": uid, "id.orig_h": f[0], "id.orig_p": f[1], "id.resp_h": f[2], "id.resp_p": f[3],
            "trans_depth": i + 1, "method": q["method"], "host": _txt(h[b"host"]) if b"host" in h else None,
            "uri": q["uri"], "referrer": _txt(h[b"referer"]) if b"referer" in h else None, "version": q["version"],
            "user_agent": _txt(h[b"user-agent"]) if b"user-agent" in h else None,
            "origin": _txt(h[b"origin"]) if b"origin" in h else None, "request_body_len": q["body"],
            "response_body_len": p["body"] if p else None, "status_code": p["code"] if p else None,
            "status_msg": p["text"] if p else None, "info_code": inf["code"] if inf else None,
            "info_msg": inf["text"] if inf else None, "tags": []})
        http.append((q["ts"], uid, seq[0], row))
        seq[0] += 1


# ---------------------------------------------------------------- the pass


class _Flow:
    __slots__ = ("key", "src", "sport", "dst", "dport", "start", "last", "fo", "fr", "cs", "ss", "kind",
                 "tls", "po", "pr", "closed", "pre", "pre_fwd")


def _addrs(f):
    return socket.inet_ntoa(f.src), f.sport, socket.inet_ntoa(f.dst), f.dport


def analyze(pcap_path, rules=None, stats=None):
    """-> (ssl_rows, x509_rows, http_rows). See the module docstring. `stats` (dict) is filled."""
    st = stats if stats is not None else {}
    st.update(packets=0, tcp_flows=0, tls_flows=0, http_flows=0, streams_capped=0, streams_broken=0,
              messages_over_cap=0, tls_flows_without_visible_certs=0)
    idle = float((rules or {}).get("tcp_idle", flowtable.RULES["tcp_idle"]))
    ssl, x509, http, cache, seq = [], [], [], {}, [0]
    tab, nxt, n = {}, None, 0

    def end(f):
        kind, f.kind = f.kind, "done"
        if kind not in ("tls", "http"):
            return
        st["streams_broken"] += f.cs.broken + f.ss.broken
        a = _addrs(f)
        uid = zeeklogs._uid("tcp", a[0], a[1], a[2], a[3], "%.6f" % f.start)
        if kind == "tls":
            if not (f.tls.get("certs_s") or f.tls.get("certs_c")):
                st["tls_flows_without_visible_certs"] += 1
            _tls_rows(a, uid, f.tls, ssl, x509, seq, cache)
        else:
            reqs, resps = (f.pr.msgs, f.po.msgs) if f.po.resp else (f.po.msgs, f.pr.msgs)
            _http_rows(a, uid, reqs, resps, http, seq)
        f.cs = f.ss = f.po = f.pr = f.tls = None

    for n, (ts, fr) in enumerate(pcapprofile.iter_frames(pcap_path), 1):
        ts = round(ts, 6)
        if nxt is None:
            nxt = ts + _SWEEP_S
        elif ts >= nxt:
            nxt = ts + _SWEEP_S
            for k in [k for k, f in tab.items() if ts - f.last > idle]:
                end(tab.pop(k))
        if fr is None or len(fr) < 38:
            continue
        o = 12
        while len(fr) >= o + 6 and fr[o] << 8 | fr[o + 1] in (0x8100, 0x88A8):
            o += 4
        if len(fr) < o + 36 or fr[o] != 8 or fr[o + 1] != 0 or fr[o + 2] >> 4 != 4 or fr[o + 11] != 6:
            continue
        ip = o + 2
        ihl = (fr[ip] & 15) * 4
        l4 = ip + ihl
        if (fr[ip + 6] << 8 | fr[ip + 7]) & 0x1FFF or ihl < 20 or len(fr) < l4 + 20:
            continue
        tl = fr[ip + 2] << 8 | fr[ip + 3]
        doff = (fr[l4 + 12] >> 4) * 4
        if doff < 20:
            continue
        sp, dp, fl = fr[l4] << 8 | fr[l4 + 1], fr[l4 + 2] << 8 | fr[l4 + 3], fr[l4 + 13]
        src, dst = bytes(fr[ip + 12:ip + 16]), bytes(fr[ip + 16:ip + 20])
        k = (src, sp, dst, dp)
        f = tab.get(k)
        fwd = f is not None
        if f is None:
            f = tab.get((dst, dp, src, sp))
        if f is not None and (ts - f.last > idle or (fl & 0x12 == 0x02 and (f.fo | f.fr) & 0x05)):
            del tab[f.key]
            end(f)
            f = None
        if f is None:
            f = _Flow()
            f.key, f.src, f.sport, f.dst, f.dport, f.start, f.last = k, src, sp, dst, dp, ts, ts
            f.fo = f.fr = 0
            f.cs, f.ss, f.kind, f.tls, f.po, f.pr, f.closed = _Stream(), _Stream(), None, None, None, None, False
            f.pre, f.pre_fwd = b"", None
            tab[k] = f
            st["tcp_flows"] += 1
            fwd = True
        f.last = ts
        if fwd:
            f.fo |= fl
        else:
            f.fr |= fl
        if f.kind not in ("done", "other"):
            pay = fr[l4 + doff:ip + tl]
            data = (f.cs if fwd else f.ss).push(int.from_bytes(fr[l4 + 4:l4 + 8], "big"), bytes(pay), bool(fl & 2)) \
                if (pay or fl & 2) else None
            if data and f.kind is None:
                # sniff the payload, not the port; a first segment shorter than the start line waits (bounded)
                if f.pre_fwd is None:
                    f.pre_fwd = fwd
                if f.pre_fwd != fwd:
                    f.kind = "other"                             # the other side spoke before we could tell
                else:
                    f.pre += data
                    data = f.pre
                    if data[0] == 0x16 and len(data) < 2:
                        data = None
                    elif data[0] == 0x16 and data[1] == 3:
                        f.kind, f.tls = "tls", {"ts": None, "ccs_c": False, "ccs_s": False, "app_c": False, "app_s": False}
                        f.po, f.pr = _Tls("c", f.tls, st), _Tls("s", f.tls, st)
                        st["tls_flows"] += 1
                    elif _START.match(data[:4096]):
                        resp = data.startswith(b"HTTP/")         # the first data's direction is a response
                        mine, other = _Http(resp, st), _Http(not resp, st)
                        mine.peer, other.peer = other, mine
                        f.kind = "http"
                        f.po, f.pr = (mine, other) if fwd else (other, mine)
                        st["http_flows"] += 1
                    elif b"\r\n" not in data and len(data) < 4096 and data[:1].isalpha():
                        data = None                              # maybe a partial request line: wait for more
                    else:
                        f.kind = "other"
                if f.kind == "other":
                    f.cs = f.ss = None
                if f.kind in ("tls", "http"):
                    f.pre = b""
            if data:
                if f.kind in ("tls", "http"):
                    (f.po if fwd else f.pr).feed(data, ts)           # po = originator's parser, pr = responder's
                    if f.po.dead and f.pr.dead:
                        end(f)
        if fl & 4 or (f.fo & 1 and f.fr & 1):
            if not f.closed:
                f.closed = True
                end(f)                                   # rows out now; the stub stays so strays fold in
    for f in tab.values():
        end(f)
    st.update(packets=n, ssl_rows=len(ssl), x509_rows=len(x509), http_rows=len(http))
    ssl.sort(key=lambda r: r[:3])
    x509.sort(key=lambda r: r[:4])
    http.sort(key=lambda r: r[:3])
    return [r[-1] for r in ssl], [r[-1] for r in x509], [r[-1] for r in http]


def _span(rows):
    return (rows[0]["ts"], max(r["ts"] for r in rows)) if rows else (0, 0)


def write_ssl_log(rows, path, fmt="tsv"):
    return zeeklogs.write_rows(path, "ssl", SSL_FIELDS, rows, fmt, *_span(rows))


def write_x509_log(rows, path, fmt="tsv"):
    return zeeklogs.write_rows(path, "x509", X509_FIELDS, rows, fmt, *_span(rows))


def write_http_log(rows, path, fmt="tsv"):
    return zeeklogs.write_rows(path, "http", HTTP_FIELDS, rows, fmt, *_span(rows))

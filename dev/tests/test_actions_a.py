"""Tests for the campaign actions in c2.py, delivery.py and exfil.py (ACTIONS-A).

Run from dev/:  python -m unittest tests.test_actions_a
Builds a real engine context (hosts, link, PKI, key log) the way opengenerator_build.build() does,
calls every action, and checks the packets: RFC 791 IPv4, TCP/UDP checksums, ports, DNS, key log,
determinism, and (when tshark is installed) a real dissector pass with no malformed or checksum errors.
"""
import io
import os
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import netgen
from checks.tshark_locate import find_tshark
from netgen import flows as F
from netgen.core import Host, ArpModel, PcapWriter
from netgen.identity import H
from netgen.model import build_hosts, set_capture_day
from netgen.tls import PKI
from netgen.campaign import actions as A

HERE = os.path.dirname(os.path.abspath(__file__))
INVENTORY = os.path.join(os.path.dirname(HERE), "inventory.json")
TSHARK = find_tshark()
DAY = "2026-03-14"
T0 = 1773489600.0         # 2026-03-14 12:00 UTC, inside the pinned day for any sensible timezone

_PKI = {}


def make_world(seed_urandom=None):
    """A fresh engine context. The PKI is built once per process (it mints RSA keys from the system
    CSPRNG) so two runs can be compared byte for byte."""
    netgen.reseed_all()
    set_capture_day(DAY)
    hosts, link, sites, resolvers = build_hosts(INVENTORY)
    if "pki" not in _PKI:
        _PKI["pki"] = PKI(day=set_capture_day(DAY))
    ctx = F.Ctx(hosts, link, ArpModel(link), _PKI["pki"], io.StringIO(), scale=1.0)
    ctx.sites = sites
    ctx.isp_resolvers = resolvers
    return ctx


def ext_host(ip, fqdn, hops=9):
    h = Host(fqdn.split(".")[0].upper() if fqdn else "EXT", ip,
             "02:00:5e:%02x:%02x:%02x" % tuple(F.rng.randrange(256) for _ in range(3)),
             "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
    h.hops = hops
    return h


def _csum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def check_packet(frame):
    """Return a list of problems with one Ethernet frame (empty = valid). Non-IPv4 frames are skipped."""
    bad = []
    if len(frame) < 14:
        return ["short frame"]
    et = struct.unpack("!H", frame[12:14])[0]
    if et != 0x0800:
        return bad
    ip = frame[14:]
    if len(ip) < 20:
        return ["short ip"]
    vihl, tos, tl, ident, ff, ttl, proto, ck = struct.unpack("!BBHHHBBH", ip[:12])
    ihl = (vihl & 0xF) * 4
    if vihl >> 4 != 4:
        bad.append("version")
    if ihl < 20 or ihl > len(ip):
        return bad + ["ihl"]
    if tl < ihl or tl > len(ip):
        bad.append("total length %d vs %d" % (tl, len(ip)))
        tl = min(tl, len(ip))
    if ttl == 0:
        bad.append("ttl 0")
    if _csum(ip[:ihl]) != 0:
        bad.append("ip checksum")
    seg = ip[ihl:tl]
    pseudo = ip[12:20] + struct.pack("!BBH", 0, proto, len(seg))
    if proto == 6:
        if len(seg) < 20 or _csum(pseudo + seg) != 0:
            bad.append("tcp checksum")
    elif proto == 17:
        if len(seg) < 8:
            bad.append("short udp")
        elif struct.unpack("!H", seg[6:8])[0] != 0 and _csum(pseudo + seg) != 0:
            bad.append("udp checksum")
        elif struct.unpack("!H", seg[4:6])[0] != len(seg):
            bad.append("udp length")
    return bad


def flow_ports(pkts, src_ip):
    """{(proto, dport)} for packets sent by src_ip."""
    out = set()
    sip = bytes(int(x) for x in src_ip.split("."))
    for _, f in pkts:
        if len(f) < 34 or struct.unpack("!H", f[12:14])[0] != 0x0800 or f[26:30] != sip:
            continue
        ihl = (f[14] & 0xF) * 4
        proto = f[23]
        if proto in (6, 17):
            out.add((proto, struct.unpack("!H", f[14 + ihl + 2:14 + ihl + 4])[0]))
    return out


def _skip_name(b, i):
    n = 0
    while True:
        if i >= len(b):
            raise ValueError("name runs off the message")
        ln = b[i]
        if ln == 0:
            return i + 1, n
        if ln & 0xC0 == 0xC0:
            return i + 2, n
        if ln > 63:
            raise ValueError("label > 63")
        n += ln + 1
        i += 1 + ln
        if n > 255:
            raise ValueError("name > 255")


def parse_dns(payload):
    """Walk a whole DNS message; return (id, flags, qd, an, ns, ar, qname-length). Raises on malformed."""
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", payload[:12])
    i = 12
    qlen = 0
    for _ in range(qd):
        i, qlen = _skip_name(payload, i)
        i += 4
    for _ in range(an + ns + ar):
        i, _n = _skip_name(payload, i)
        _t, _c, _ttl, rdl = struct.unpack("!HHIH", payload[i:i + 10])
        i += 10 + rdl
    if i > len(payload):
        raise ValueError("record runs off the message")
    return tid, flags, qd, an, ns, ar, qlen


def dns_messages(pkts):
    for _, f in pkts:
        if len(f) > 42 and struct.unpack("!H", f[12:14])[0] == 0x0800 and f[23] == 17:
            ihl = (f[14] & 0xF) * 4
            sp, dp = struct.unpack("!HH", f[14 + ihl:14 + ihl + 4])
            if 53 in (sp, dp):
                yield sp, dp, f[14 + ihl + 8:]


# token -> (kwargs, expected ports sent by the client, dst kind, tls?)
CASES = {
    "https_beacon": (dict(count=3, interval_s=5.0), {(6, 443)}, "ext", True),
    "http_beacon": (dict(count=3, interval_s=5.0, method="mixed"), {(6, 80)}, "ext", False),
    "dns_beacon": (dict(count=4, interval_s=5.0), {(17, 53)}, "ext", False),
    "dns_tunnel": (dict(bursts=2, per_burst=6), {(17, 53)}, "ext", False),
    "dga_lookup": (dict(count=5), {(17, 53)}, "ext", False),
    "tor_connect": (dict(duration_s=20.0, records=8), {(6, 443)}, "tor", True),
    "payload_download": (dict(size=60000, filetype="zip"), {(6, 80)}, "ext", False),
    "phishing_visit": (dict(think_s=2.0), {(6, 443)}, "ext", True),
    "https_upload": (dict(total_bytes=400000, chunk_bytes=65536), {(6, 443)}, "ext", True),
    "ftp_upload": (dict(size=40000), {(6, 21)}, "ext", False),
    "dns_exfil": (dict(queries=12), {(17, 53)}, "ext", False),
    "smb_collect": (dict(total_mb=1.0, files=3), {(6, 445)}, "int", False),
}


def run_all(det=False):
    """Run every action in one world. Returns (ctx, {token: packets}, src)."""
    ctx = make_world()
    src = ctx.h[H("WS-009")]
    ext = ext_host("198.18.20.5", "update-check.c2.example.test")
    tor = ext_host("198.18.21.7", "", 11)
    filesrv = ctx.h[H("FILE1")]
    res = {}
    t = T0
    for tok, (kw, _ports, kind, _tls) in CASES.items():
        dst = {"ext": ext, "tor": tor, "int": filesrv}[kind]
        res[tok] = A.get(tok).fn(ctx, src, dst, ts=t, **kw)
        t += 300.0
    return ctx, res, src


def _urandom_patch():
    r = random.Random(4242)
    return mock.patch("os.urandom", lambda n: r.randbytes(n))


class ActionsA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.load_all()
        with _urandom_patch():
            cls.ctx, cls.res, cls.src = run_all()

    def test_registered(self):
        specs = A.all_specs()
        for tok in CASES:
            self.assertIn(tok, specs)
            sp = specs[tok]
            self.assertTrue(sp.summary and sp.techniques and sp.protocols and sp.tactic and sp.title)
            for name, d in sp.params.items():
                self.assertEqual(set(d), {"type", "default", "help"}, (tok, name))

    def test_param_names_match_functions(self):
        import inspect
        for tok in CASES:
            sp = A.get(tok)
            sig = inspect.signature(sp.fn).parameters
            self.assertEqual(set(sp.params), {n for n in sig if n not in ("ctx", "src", "dst", "ts")}, tok)

    def test_nonempty_and_valid_ipv4(self):
        for tok, pk in self.res.items():
            self.assertTrue(pk, tok)
            self.assertEqual([p[0] for p in pk], sorted(p[0] for p in pk), tok + " not time-sorted")
            for _ts, f in pk:
                self.assertEqual(check_packet(f), [], tok)

    def test_ports(self):
        for tok, (_kw, ports, _k, _t) in CASES.items():
            got = flow_ports(self.res[tok], self.src.ip)
            self.assertTrue(ports <= got, "%s: wanted %s got %s" % (tok, ports, got))
        # the DNS lookup of the C2 name goes out on 53 for the named-host TCP actions
        self.assertIn((17, 53), flow_ports(self.res["https_beacon"], self.src.ip))
        self.assertIn((17, 53), flow_ports(self.res["payload_download"], self.src.ip))

    def test_ftp_has_data_connection(self):
        ports = flow_ports(self.res["ftp_upload"], self.src.ip)
        self.assertTrue(any(p > 49151 for pr, p in ports if pr == 6))

    def test_dns_parses(self):
        for tok in ("dns_beacon", "dns_tunnel", "dga_lookup", "dns_exfil", "https_beacon", "phishing_visit"):
            n = 0
            for _sp, _dp, payload in dns_messages(self.res[tok]):
                parse_dns(payload)
                n += 1
            self.assertGreater(n, 1, tok)

    def test_dns_shapes(self):
        # dns_beacon: fixed-length first label; dns_exfil: long names within the 253 limit
        qn = [parse_dns(p)[6] for sp, dp, p in dns_messages(self.res["dns_beacon"]) if dp == 53]
        self.assertTrue(qn)
        ex = [parse_dns(p)[6] for sp, dp, p in dns_messages(self.res["dns_exfil"]) if dp == 53]
        self.assertTrue(max(ex) > 150 and max(ex) <= 253, max(ex))
        # dga: NXDOMAIN responses present, then at least one NOERROR answer
        rc = [parse_dns(p)[1] & 0xF for sp, dp, p in dns_messages(self.res["dga_lookup"]) if sp == 53 and parse_dns(p)[1] & 0x8000]
        self.assertGreaterEqual(rc.count(3), 4)
        self.assertIn(0, rc)

    def test_keylog_written_for_tls(self):
        lines = [l for l in self.ctx.keylog.getvalue().splitlines() if l.startswith("CLIENT_RANDOM")]
        self.assertGreaterEqual(len(lines), 6)    # https_beacon 3 sessions + phishing + upload + tor
        self.assertTrue(all(len(l.split()) == 3 for l in lines))

    def test_tor_records_multiple_of_cell(self):
        # find client application-data records on the tor flow: TLS record type 23, length = 8+16 overhead + 514*k
        sip = bytes(int(x) for x in self.src.ip.split("."))
        lens = []
        for _, f in self.res["tor_connect"]:
            if len(f) < 60 or struct.unpack("!H", f[12:14])[0] != 0x0800 or f[26:30] != sip or f[23] != 6:
                continue
            ihl = (f[14] & 0xF) * 4
            tcp = f[14 + ihl:]
            pl = tcp[(tcp[12] >> 4) * 4:]
            if len(pl) > 5 and pl[0] == 23 and pl[1:3] == b"\x03\x03":
                lens.append(struct.unpack("!H", pl[3:5])[0] - 24)
        self.assertTrue(lens)
        self.assertTrue(all(n % 514 == 0 for n in lens if n < 1400), lens)

    def test_payload_magic_and_dummy_creds(self):
        blob = b"".join(f for _, f in self.res["payload_download"])
        self.assertIn(b"PK\x03\x04", blob)
        self.assertIn(b"Content-Type: application/zip", blob)
        blob = b"".join(f for _, f in self.res["ftp_upload"])
        self.assertIn(b"STOR backup_", blob)
        self.assertIn(b"PASS not-a-real-password", blob)

    def test_no_real_names_or_template_leaks(self):
        import inspect
        import netgen.campaign.actions.c2 as c2, netgen.campaign.actions.delivery as dl, netgen.campaign.actions.exfil as ex
        for m in (c2, dl, ex):
            src = inspect.getsource(m)
            for bad in ("os.urandom", "import random", "uuid", "datetime.now", "time.time", "EXL-", "Extra" + "Hop", "Vec" + "tra"):
                self.assertNotIn(bad, src, (m.__name__, bad))

    def test_deterministic(self):
        def sig():
            with _urandom_patch():
                _c, res, _s = run_all()
            return res
        a, b = sig(), sig()
        def shape(pk):
            out = []
            for _ts, f in pk:
                ihl = (f[14] & 0xF) * 4 if len(f) > 34 and f[12:14] == b"\x08\x00" else 0
                out.append((f[12:14], f[26:34] if ihl else b"", f[14 + ihl + 2:14 + ihl + 4] if ihl else b"",
                            f[14 + ihl + 13] if ihl and f[23] == 6 else 0))
            return out
        for tok in CASES:
            self.assertEqual(len(a[tok]), len(b[tok]), tok)
            if CASES[tok][3]:
                # TLS: the engine mints certificate keys from system entropy, so handshake bytes (and the
                # timing that follows from their length) may differ; the flow shape must not.
                self.assertEqual(shape(a[tok]), shape(b[tok]), tok + " flow shape differs")
            else:
                self.assertEqual(a[tok], b[tok], tok + " differs between two seeded runs")

    def test_other_dates_and_identity(self):
        # the same actions run with a different capture day (the PKI day is fixed per process, the packets must still be valid)
        ctx = make_world()
        set_capture_day("2025-11-02")
        ctx.keylog = io.StringIO()
        src = ctx.h[H("WS-009")]
        ext = ext_host("198.18.20.9", "other.c2.example.test")
        for tok in ("https_beacon", "dns_beacon", "dga_lookup"):
            pk = A.get(tok).fn(ctx, src, ext, ts=T0 + 86400 * 200, **CASES[tok][0])
            self.assertTrue(pk)
            for _, f in pk:
                self.assertEqual(check_packet(f), [], tok)
        set_capture_day(DAY)

    def test_nameless_destination(self):
        ctx = make_world()
        src = ctx.h[H("WS-009")]
        ip_only = ext_host("198.18.22.3", "")
        for tok in ("https_beacon", "http_beacon", "payload_download", "https_upload", "ftp_upload", "dns_beacon", "dga_lookup"):
            pk = A.get(tok).fn(ctx, src, ip_only, ts=T0, **{k: v for k, v in CASES[tok][0].items()})
            self.assertTrue(pk, tok)
            for _, f in pk:
                self.assertEqual(check_packet(f), [], tok)

    @unittest.skipUnless(TSHARK, "tshark not installed")
    def test_tshark_clean(self):
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "a.pcap")
            allp = []
            for pk in self.res.values():
                allp += pk
            allp.sort(key=lambda p: p[0])
            w = PcapWriter(path)
            for ts, f in allp:
                w.write(ts, f)
            w.close()
            flt = ('_ws.malformed || ip.checksum.status == "Bad" || tcp.checksum.status == "Bad" || udp.checksum.status == "Bad"'
                   ' || _ws.expert.severity == "Error"')
            r = subprocess.run([TSHARK, "-r", path, "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
                                "-o", "ip.check_checksum:TRUE", "-Y", flt, "-T", "fields", "-e", "frame.number",
                                "-e", "_ws.col.Protocol", "-e", "_ws.col.Info"], capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stderr[-500:])
            self.assertEqual(r.stdout.strip(), "", r.stdout[:1500])
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

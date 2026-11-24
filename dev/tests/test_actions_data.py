"""Tests for the campaign actions in data.py (DATA worker).

Run from dev/:  python -m unittest tests.test_actions_data
Checks every action: packets exist and are RFC 791 valid with correct TCP/UDP checksums, expected ports and
protocol fields, ICMP payload sizes, SMTP/TDS framing, determinism, and (when tshark is installed) a dissector
pass with no malformed, checksum or expert-error results.
"""
import inspect
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from netgen.core import PcapWriter
from netgen.identity import H
from netgen.campaign import actions as A
from tests.test_actions_a import (make_world, ext_host, check_packet, flow_ports, T0, TSHARK, _urandom_patch)

# token -> (kwargs, expected ports sent by the client, dst kind, tls?)
CASES = {
    "sql_collect": (dict(tables=2, rows_per_table=300), {(6, 1433)}, "sql", False),
    "archive_stage": (dict(archive_mb=3.0, parts=2), {(6, 445)}, "int", False),
    "icmp_tunnel": (dict(count=25, interval_s=1.0), set(), "ext", False),
    "cloud_service_c2": (dict(count=5, interval_s=5.0, sni="api.notes-sync.example"), {(6, 443), (17, 53)}, "ext", True),
    "cloud_storage_upload": (dict(total_bytes=900000, part_bytes=262144, bucket="data-lake-7"), {(6, 443)}, "ext", True),
    "smtp_exfil": (dict(attachment_bytes=200000), {(6, 25), (17, 53)}, "ext", False),
    "smb_delete_burst": (dict(files=30), {(6, 445)}, "int", False),
}


def run_all():
    ctx = make_world()
    src = ctx.h[H("WS-009")]
    ext = ext_host("198.18.20.5", "relay.storage-host.example.test")
    res, t = {}, T0
    for tok, (kw, _p, kind, _t) in CASES.items():
        dst = {"ext": ext, "int": ctx.h[H("FILE1")], "sql": ctx.h[H("SQL1")]}[kind]
        res[tok] = A.get(tok).fn(ctx, src, dst, ts=t, **kw)
        t += 400.0
    return ctx, res, src


def _tcp_payloads(pkts, from_ip=None, dport=None, sport=None):
    out = []
    for _, f in pkts:
        if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6:
            continue
        ihl = (f[14] & 0xF) * 4
        tl = struct.unpack("!H", f[16:18])[0]
        tcp = f[14 + ihl:14 + tl]
        sp, dp = struct.unpack("!HH", tcp[:4])
        pl = tcp[(tcp[12] >> 4) * 4:]
        if pl and (dport is None or dp == dport) and (sport is None or sp == sport):
            out.append(pl)
    return out


def _icmp(pkts):
    out = []
    for _, f in pkts:
        if len(f) > 34 and f[12:14] == b"\x08\x00" and f[23] == 1:
            ihl = (f[14] & 0xF) * 4
            tl = struct.unpack("!H", f[16:18])[0]
            m = f[14 + ihl:14 + tl]
            out.append((m[0], struct.unpack("!HH", m[4:8]), m[8:]))
    return out


class ActionsData(unittest.TestCase):
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
            self.assertTrue(sp.summary and sp.techniques and sp.protocols and sp.tactic and sp.title, tok)
            for name, d in sp.params.items():
                self.assertEqual(set(d), {"type", "default", "help"}, (tok, name))
            sig = inspect.signature(sp.fn).parameters
            self.assertEqual(set(sp.params), {n for n in sig if n not in ("ctx", "src", "dst", "ts")}, tok)
        from netgen.campaign import attack
        for tok in CASES:
            self.assertEqual(attack.validate_ids(A.get(tok).techniques), [], tok)
            self.assertIn(A.get(tok).tactic, [t if isinstance(t, str) else t.get("id", t) for t in attack.tactics()] +
                          [t.get("slug") for t in attack.tactics() if isinstance(t, dict)], tok)

    def test_nonempty_and_valid_ipv4(self):
        for tok, pk in self.res.items():
            self.assertTrue(pk, tok)
            self.assertEqual([p[0] for p in pk], sorted(p[0] for p in pk), tok)
            for _ts, f in pk:
                self.assertEqual(check_packet(f), [], tok)

    def test_ports(self):
        for tok, (_kw, ports, _k, _t) in CASES.items():
            got = flow_ports(self.res[tok], self.src.ip)
            self.assertTrue(ports <= got, "%s: wanted %s got %s" % (tok, ports, got))

    def test_icmp_tunnel(self):
        msgs = _icmp(self.res["icmp_tunnel"])
        req = [m for m in msgs if m[0] == 8]
        rep = [m for m in msgs if m[0] == 0]
        self.assertEqual(len(req), 25)
        self.assertEqual(len(rep), 25)
        self.assertEqual(len({m[1][0] for m in msgs}), 1, "one identifier")
        self.assertEqual([m[1][1] for m in req], list(range(1, 26)))
        sizes = [len(m[2]) for m in req]
        self.assertGreater(len(set(sizes)), 10, "variable payload sizes")
        self.assertTrue(all(64 <= n <= 900 for n in sizes), sizes)
        self.assertNotEqual(req[0][2][:16], bytes(range(0x61, 0x61 + 16)), "not a ping pattern")
        # steady cadence
        ts = [t for t, f in self.res["icmp_tunnel"] if f[12:14] == b"\x08\x00" and f[23] == 1 and f[34] == 8]
        gaps = [b - a for a, b in zip(ts, ts[1:], strict=False)]
        self.assertTrue(all(0.7 <= g <= 1.3 for g in gaps), gaps)

    def test_icmp_size_limits(self):
        ctx = make_world()
        src = ctx.h[H("WS-009")]
        ext = ext_host("198.18.20.6", "")
        pk = A.get("icmp_tunnel").fn(ctx, src, ext, ts=T0, count=6, size_min=1400, size_max=9000, fixed_size=0)
        for _ts, f in pk:
            self.assertEqual(check_packet(f), [])
            self.assertLessEqual(len(f), 1514)
        self.assertTrue(all(len(m[2]) <= 1472 for m in _icmp(pk)))

    def test_smtp(self):
        c2s = b"".join(_tcp_payloads(self.res["smtp_exfil"], dport=25))
        s2c = b"".join(_tcp_payloads(self.res["smtp_exfil"], sport=25))
        for tok in (b"EHLO ", b"MAIL FROM:<", b"RCPT TO:<", b"DATA\r\n", b"Content-Transfer-Encoding: base64", b"\r\n.\r\n", b"QUIT\r\n"):
            self.assertIn(tok, c2s)
        self.assertTrue(s2c.startswith(b"220 "))
        self.assertIn(b"250 2.0.0 Ok: queued", s2c)
        # base64 attachment decodes to zip magic
        import base64
        body = c2s.split(b"filename=", 1)[1].split(b"\r\n\r\n", 1)[1].split(b"\r\n--", 1)[0]
        raw = base64.b64decode(b"".join(body.split(b"\r\n")))
        self.assertEqual(raw[:4], b"PK\x03\x04")
        self.assertEqual(len(raw), 200000)
        self.assertNotIn(b".exe", c2s.lower())

    def test_tds(self):
        pl = b"".join(_tcp_payloads(self.res["sql_collect"], dport=1433))
        self.assertTrue(pl[:1] == b"\x12", "pre-login first")
        self.assertIn(b"\x10\x00", pl)                                  # login7 packet type present
        self.assertIn("SELECT * FROM dbo.Customers".encode("utf-16-le"), pl)
        server = _tcp_payloads(self.res["sql_collect"], sport=1433)
        self.assertGreater(sum(len(p) for p in server), 20000)          # result sets are large
        self.assertNotIn(b"xp_cmdshell".decode().encode("utf-16-le"), pl)

    def test_archive_magic_and_path(self):
        blob = b"".join(f for _, f in self.res["archive_stage"])
        self.assertIn(b"PK\x03\x04\x14\x00\x00\x00\x08\x00", blob)
        self.assertIn("Temp\\stage\\".encode("utf-16-le"), blob)
        self.assertGreater(len(blob), 3_000_000)

    def test_smb_delete_uses_delete_on_close(self):
        blob = b"".join(f for _, f in self.res["smb_delete_burst"])
        self.assertGreaterEqual(blob.count(b"\xfeSMB"), 30 * 4)
        # CREATE requests carrying FILE_DELETE_ON_CLOSE (0x1000) in CreateOptions
        n = 0
        for pl in _tcp_payloads(self.res["smb_delete_burst"], dport=445):
            i = pl.find(b"\xfeSMB")
            while i >= 0:
                if struct.unpack("<H", pl[i + 12:i + 14])[0] == 5 and not struct.unpack("<I", pl[i + 16:i + 20])[0] & 1:
                    opts = struct.unpack("<I", pl[i + 64 + 40:i + 64 + 44])[0]
                    if opts & 0x1000:
                        n += 1
                i = pl.find(b"\xfeSMB", i + 4)
        self.assertGreaterEqual(n, 30)

    def test_https_sni_and_keylog(self):
        for tok in ("cloud_service_c2", "cloud_storage_upload"):
            blob = b"".join(f for _, f in self.res[tok])
            self.assertIn(b"\x16\x03\x03", blob)
        self.assertIn(b"api.notes-sync.example", b"".join(f for _, f in self.res["cloud_service_c2"]))
        self.assertIn(b"data-lake-7.relay.storage-host.example.test", b"".join(f for _, f in self.res["cloud_storage_upload"]))
        lines = [l for l in self.ctx.keylog.getvalue().splitlines() if l.startswith("CLIENT_RANDOM")]
        self.assertGreaterEqual(len(lines), 2)

    def test_no_forbidden_text(self):
        import netgen.campaign.actions.data as mod
        text = inspect.getsource(mod)
        for bad in ("os.urandom", "import random", "uuid", "datetime.now", "time.time", "EXL-", "Extra" + "Hop", "Vec" + "tra",
                    "Micro" + "soft", "Ama" + "zon", "x-amz", "Goo" + "gle", "Drop" + "box"):
            self.assertNotIn(bad, text, bad)

    def test_deterministic(self):
        def sig():
            with _urandom_patch():
                _c, res, _s = run_all()
            return res
        a, b = sig(), sig()
        for tok in CASES:
            self.assertEqual(len(a[tok]), len(b[tok]), tok)
            if CASES[tok][3]:
                sh = lambda pk: [(f[12:14], f[26:34], f[14 + (f[14] & 0xF) * 4 + 2:14 + (f[14] & 0xF) * 4 + 4]) for _t, f in pk]
                self.assertEqual(sh(a[tok]), sh(b[tok]), tok)
            else:
                self.assertEqual(a[tok], b[tok], tok)

    def test_nameless_and_missing(self):
        ctx = make_world()
        src = ctx.h[H("WS-009")]
        ip_only = ext_host("198.18.22.3", "")
        for tok, kw in (("cloud_service_c2", dict(count=3)), ("cloud_storage_upload", dict(total_bytes=200000)),
                        ("smtp_exfil", dict(attachment_bytes=5000)), ("icmp_tunnel", dict(count=4))):
            pk = A.get(tok).fn(ctx, src, ip_only, ts=T0, **kw)
            self.assertTrue(pk, tok)
            for _ts, f in pk:
                self.assertEqual(check_packet(f), [], tok)

    @unittest.skipUnless(os.path.exists(TSHARK), "tshark not installed")
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
                   ' || icmp.checksum.status == "Bad" || _ws.expert.severity == "Error"')
            r = subprocess.run([TSHARK, "-r", path, "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
                                "-o", "ip.check_checksum:TRUE", "-Y", flt, "-T", "fields", "-e", "frame.number",
                                "-e", "_ws.col.Protocol", "-e", "_ws.col.Info"], capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stderr[-500:])
            self.assertEqual(r.stdout.strip(), "", r.stdout[:1500])
            r = subprocess.run([TSHARK, "-r", path, "-T", "fields", "-e", "_ws.col.Protocol"], capture_output=True, text=True, timeout=300)
            protos = set(r.stdout.split())
            for need in ("ICMP", "TDS", "SMB2", "SMTP", "SMTP/IMF"):
                self.assertIn(need, protos, need + " not dissected; saw %s" % sorted(protos))
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

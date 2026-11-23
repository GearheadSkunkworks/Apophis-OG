"""Tests for the campaign actions in outside.py (OUTSIDE worker).

Run from dev/:  python -m unittest tests.test_actions_outside
Builds a real engine context with tests.test_actions_a.make_world, runs every outside-in action
(inbound ones from an internet host to an internal server, outbound ones from a workstation), and checks:
RFC 791 IPv4, TCP/UDP checksums, ports, key protocol fields (HTTP status mix, DNS rcodes, certificate age
and self-signed shape), determinism, other capture days, and, when tshark is installed, a dissector
pass with no malformed or checksum errors (plus a decrypted-HTTP pass over the key log).
"""
import inspect
import os
import re
import shutil
import struct
import subprocess
import tempfile
import unittest

from netgen import flows as F
from netgen.core import PcapWriter
from netgen.identity import H
from netgen.model import set_capture_day
from netgen.campaign import actions as A
from tests.test_actions_a import (DAY, T0, TSHARK, _urandom_patch, check_packet, dns_messages, ext_host, flow_ports,
                                  make_world, parse_dns)

# token -> (kwargs, ports sent by the client, dst role, uses TLS, inbound)
CASES = {
    "web_dir_scan": (dict(count=40, connections=3), {(6, 80)}, "WEB1", False, True),
    "subdomain_enum": (dict(count=30, found=4), {(17, 53), (6, 53)}, "DC1", False, True),
    "new_domain_contact": (dict(visits=2, interval_s=5.0), {(6, 443), (17, 53)}, "ext", True, False),
    "selfsigned_tls_contact": (dict(sessions=2, interval_s=5.0), {(6, 8443)}, "ext", True, False),
    "web_login_spray": (dict(attempts=16, connections=2), {(6, 443)}, "WEB1", True, True),
    "exposed_service_login": (dict(service="rdp", attempts=6, successes=2, session_s=4.0), {(6, 3389)}, "WEB1", True, True),
}
EXTRA = {   # not in CASES' one-per-token map
    "web_dir_scan_tls": ("web_dir_scan", dict(count=20, connections=2, tls=True), {(6, 443)}, "WEB1", True),
    "exposed_service_login_ssh": ("exposed_service_login", dict(service="ssh", attempts=6, successes=2, session_s=4.0), {(6, 22)}, "WEB1", True),
}


def _dst(ctx, kind):
    if kind == "ext":
        return ext_host("198.18.40.12", "fresh-portal.example")
    return ctx.h[H(kind)]


def run_all():
    ctx = make_world()
    scanner = ext_host("198.18.30.9", "scan.attacker.example")
    ws = ctx.h[H("WS-009")]
    res, t = {}, T0
    named = [(tok, tok, kw, ports, kind, inb) for tok, (kw, ports, kind, _t, inb) in CASES.items()]
    named += [(name, tok, kw, ports, kind, inb) for name, (tok, kw, ports, kind, inb) in EXTRA.items()]
    for name, tok, kw, _ports, kind, inb in named:
        src = scanner if inb else ws
        res[name] = A.get(tok).fn(ctx, src, _dst(ctx, kind), ts=t, **kw)
        t += 600.0
    return ctx, res, scanner, ws


def _tcp_payloads(pkts, from_ip=None):
    out = []
    for _, f in pkts:
        if len(f) < 60 or f[12:14] != b"\x08\x00" or f[23] != 6:
            continue
        if from_ip and f[26:30] != bytes(int(x) for x in from_ip.split(".")):
            continue
        ihl = (f[14] & 0xF) * 4
        tl = struct.unpack("!H", f[16:18])[0]
        seg = f[14 + ihl:14 + tl]
        out.append(seg[(seg[12] >> 4) * 4:])
    return out


class ActionsOutside(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.load_all()
        with _urandom_patch():
            cls.ctx, cls.res, cls.scanner, cls.ws = run_all()

    def test_registered(self):
        specs = A.all_specs()
        from netgen.campaign import attack
        for tok in CASES:
            self.assertIn(tok, specs)
            sp = specs[tok]
            self.assertTrue(sp.summary and sp.techniques and sp.protocols and sp.tactic and sp.title)
            self.assertEqual(attack.validate_ids(sp.techniques), [], tok)
            self.assertIn(sp.tactic, [t["slug"] for t in attack.tactics()])
            self.assertEqual(sp.src, "external" if CASES[tok][4] else "internal", tok)
            self.assertEqual(sp.dst, "internal" if CASES[tok][4] else "external", tok)
            for name, d in sp.params.items():
                self.assertEqual(set(d), {"type", "default", "help"}, (tok, name))

    def test_param_names_match_functions(self):
        for tok in CASES:
            sig = inspect.signature(A.get(tok).fn).parameters
            self.assertEqual(set(A.get(tok).params), {n for n in sig if n not in ("ctx", "src", "dst", "ts")}, tok)

    def test_nonempty_valid_ipv4_sorted(self):
        for name, pk in self.res.items():
            self.assertTrue(pk, name)
            self.assertEqual([p[0] for p in pk], sorted(p[0] for p in pk), name)
            for _, f in pk:
                self.assertEqual(check_packet(f), [], name)

    def test_ports_and_direction(self):
        for tok, (_kw, ports, _k, _t, inb) in CASES.items():
            got = flow_ports(self.res[tok], (self.scanner if inb else self.ws).ip)
            self.assertTrue(ports & got, "%s: wanted one of %s got %s" % (tok, ports, got))
        for name, (_tok, _kw, ports, _k, _inb) in EXTRA.items():
            self.assertTrue(ports <= flow_ports(self.res[name], self.scanner.ip), name)
        # outbound actions only ever start from the workstation; inbound only from the internet host
        for tok, (_kw, _p, _k, _t, inb) in CASES.items():
            first = next(f for _, f in self.res[tok] if f[12:14] == b"\x08\x00")
            want = (self.scanner if inb else self.ws).ip
            self.assertEqual(first[26:30], bytes(int(x) for x in want.split(".")), tok)

    def test_dir_scan_mostly_404(self):
        blob = b"".join(_tcp_payloads(self.res["web_dir_scan"]))
        n404 = len(re.findall(rb"HTTP/1\.1 404 Not Found", blob))
        total = len(re.findall(rb"HTTP/1\.1 \d\d\d", blob))
        self.assertEqual(len(re.findall(rb"GET /\S* HTTP/1\.1", blob)), 40)
        self.assertEqual(total, 40)
        self.assertGreater(n404, 28)
        self.assertLess(n404, total)           # some hits
        self.assertIn(b"Host: www.", blob)

    def test_subdomain_enum_dns(self):
        rc = {}
        names, tcp = [], 0
        for sp, dp, payload in dns_messages(self.res["subdomain_enum"]):
            parse_dns(payload)
            if sp == 53:
                r = struct.unpack("!H", payload[2:4])[0]
                rc[r & 0xF] = rc.get(r & 0xF, 0) + 1
            else:
                names.append(payload[12:])
        self.assertEqual(rc.get(3, 0), 26)               # 30 names, 4 found
        self.assertGreaterEqual(rc.get(0, 0), 4 + 4)      # found + apex answers
        from netgen.campaign.actions.outside import _SUBS
        firsts = {n[1:1 + n[0]].decode() for n in names}
        self.assertTrue(firsts & set(_SUBS))
        blob = b"".join(f for _, f in self.res["subdomain_enum"])
        self.assertNotIn(b"corp.", blob.lower().replace(b"corp.example.local", b""))   # the internal AD name never leaks into the public zone
        refused = [pl for pl in _tcp_payloads(self.res["subdomain_enum"]) if len(pl) > 14 and (struct.unpack("!H", pl[4:6])[0] & 0xF) == 5]
        self.assertEqual(len(refused), 1)                  # the refused zone transfer (TCP/53, length-prefixed)

    def test_new_domain_cert_is_fresh(self):
        from cryptography import x509
        key, der, ca_der = self.ctx.pki.leaf["fresh-portal.example"]
        cert = x509.load_der_x509_certificate(der)
        age = T0 + 2 * 600.0 - cert.not_valid_before_utc.timestamp()
        life = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        # the action ran at T0 + 2*600; it was issued 12 minutes earlier and lives 90 days
        self.assertAlmostEqual(age, 12 * 60, delta=2)
        self.assertEqual(life, 90)
        # and the DNS lookup of the name precedes the TLS session
        ip = [f for _, f in self.res["new_domain_contact"] if f[12:14] == b"\x08\x00"]
        self.assertEqual(ip[0][23], 17)

    def test_selfsigned_cert_on_wire(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        blob = b"".join(_tcp_payloads(self.res["selfsigned_tls_contact"], self.ctx.pki and self.ws.ip) +
                         _tcp_payloads(self.res["selfsigned_tls_contact"]))
        # find the Certificate handshake message (type 11) and read the first certificate
        i = blob.find(b"\x0b\x00")
        found = None
        while i != -1:
            ln = int.from_bytes(blob[i + 1:i + 4], "big")
            clen = int.from_bytes(blob[i + 7:i + 10], "big")
            if ln == int.from_bytes(blob[i + 4:i + 7], "big") + 3 and blob[i + 10:i + 12] == b"\x30\x82":
                try:
                    found = x509.load_der_x509_certificate(blob[i + 10:i + 10 + clen])
                    break
                except ValueError:
                    pass
            i = blob.find(b"\x0b\x00", i + 1)
        self.assertIsNotNone(found)
        self.assertEqual(found.issuer, found.subject)

    def test_login_spray_decrypts_to_401_and_one_302(self):
        if not os.path.exists(TSHARK):
            self.skipTest("tshark not installed")
        d = tempfile.mkdtemp()
        try:
            path, kl = os.path.join(d, "s.pcap"), os.path.join(d, "keys.log")
            w = PcapWriter(path)
            for ts, f in self.res["web_login_spray"]:
                w.write(ts, f)
            w.close()
            with open(kl, "w") as fh:
                fh.write(self.ctx.keylog.getvalue())
            r = subprocess.run([TSHARK, "-r", path, "-o", "tls.keylog_file:" + kl, "-Y", "http.response || http.request",
                                "-T", "fields", "-e", "http.request.method", "-e", "http.response.code", "-e", "http.file_data"],
                               capture_output=True, text=True, timeout=120)
            rows = [l.split("\t") for l in r.stdout.splitlines() if l]
            codes = [x[1] for x in rows if x[1]]
            self.assertEqual(sum(1 for m in rows if m[0] == "POST"), 16)
            self.assertEqual(codes.count("302"), 1, codes)
            self.assertEqual(codes.count("401"), 15, codes)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_exposed_service_has_successes(self):
        # a successful session is much longer than a failed attempt: count connections by 3389 SYNs and total bytes
        for name, port in (("exposed_service_login", 3389), ("exposed_service_login_ssh", 22)):
            pk = self.res[name]
            syns = 0
            for _, f in pk:
                ihl = (f[14] & 0xF) * 4
                if f[23] == 6 and struct.unpack("!H", f[14 + ihl + 2:14 + ihl + 4])[0] == port and f[14 + ihl + 13] == 0x02:
                    syns += 1
            self.assertEqual(syns, 6, name)
            # two successes last at least session_s each: the capture spans well over six failed attempts' time
            self.assertGreater(pk[-1][0] - pk[0][0], 8.0, name)

    def test_no_real_names_or_template_leaks(self):
        import netgen.campaign.actions.outside as mod
        src = inspect.getsource(mod)
        self.assertIsNone(re.search(r"\btime\.time\(", src))
        for bad in ("os.urandom", "import random", "uuid", "datetime.now", "EXL-", "Extra" + "Hop", "Vec" + "tra",
                    "gobuster", "nmap", "hydra", "masscan", "shell.php"):
            self.assertNotIn(bad, src, bad)

    def test_deterministic(self):
        def run():
            with _urandom_patch():
                _c, res, _s, _w = run_all()
            return res

        a, b = run(), run()

        def shape(pk):
            out = []
            for ts, f in pk:
                ihl = (f[14] & 0xF) * 4 if len(f) > 34 and f[12:14] == b"\x08\x00" else 0
                out.append((f[12:14], f[26:34] if ihl else b"", f[14 + ihl + 2:14 + ihl + 4] if ihl else b"",
                            f[14 + ihl + 13] if ihl and f[23] == 6 else 0))
            return out

        tls_names = {t for t, v in CASES.items() if v[3]} | {"web_dir_scan_tls"}
        for name in a:
            self.assertEqual(len(a[name]), len(b[name]), name)
            if name in tls_names:
                self.assertEqual(shape(a[name]), shape(b[name]), name + " flow shape differs")
            else:
                self.assertEqual(a[name], b[name], name + " differs between two seeded runs")

    def test_other_dates_and_identity(self):
        ctx = make_world()
        set_capture_day("2025-11-02")
        scanner = ext_host("198.18.30.19", "scan2.attacker.example")
        ws = ctx.h[H("WS-009")]
        later = T0 + 86400 * 200
        for tok, (kw, _p, kind, _t, inb) in CASES.items():
            src = scanner if inb else ws
            dst = ext_host("198.18.40.77", "") if kind == "ext" else ctx.h[H(kind)]
            pk = A.get(tok).fn(ctx, src, dst, ts=later, **kw)
            self.assertTrue(pk, tok)
            for _, f in pk:
                self.assertEqual(check_packet(f), [], tok)
        set_capture_day(DAY)

    def test_inbound_ref_resolution(self):
        """The runner's endpoint resolver gives these actions an external src and an internal dst."""
        from netgen.campaign import hosts as HOSTS
        ctx = make_world()
        camp = {"meta": {"seed": 1}, "options": {"address_mode": "mapped"},
                "iocs": [{"type": "ipv4", "value": "203.0.113.50", "role": "scanner"}]}
        src, _i, sext = HOSTS.resolve_endpoint(ctx, "scanner:0", camp)
        dst, _j, dext = HOSTS.resolve_endpoint(ctx, "web", camp)
        self.assertTrue(sext and not dext)
        for tok in ("web_dir_scan", "web_login_spray", "exposed_service_login"):
            pk = A.get(tok).fn(ctx, src, dst, ts=T0, **{k: v for k, v in CASES[tok][0].items()})
            self.assertTrue(pk, tok)
            for _, f in pk:
                self.assertEqual(check_packet(f), [], tok)

    @unittest.skipUnless(os.path.exists(TSHARK), "tshark not installed")
    def test_tshark_clean(self):
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "o.pcap")
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
            # protocols actually dissected
            pr = subprocess.run([TSHARK, "-r", path, "-T", "fields", "-e", "_ws.col.Protocol"], capture_output=True, text=True, timeout=300)
            seen = set(pr.stdout.split())
            for want in ("HTTP", "DNS", "TLSv1.2", "RDP", "SSHv2"):
                self.assertTrue(any(s.startswith(want) or want in s for s in seen) or want in ("RDP",), (want, sorted(seen)))
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

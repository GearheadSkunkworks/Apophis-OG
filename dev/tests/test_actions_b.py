"""Tests for the campaign actions in recon.py, access.py and lateral.py.

Run from dev/:  python -m unittest tests.test_actions_b
Builds a small environment the way opengenerator_build.build() does, calls every action and checks the
packets: RFC 791 header validity, TCP/UDP/ICMP checksums, ports and protocols, closed/open scan
responses, and byte-identical output across two reseeded runs. A tshark pass runs when tshark exists.
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
if DEV not in sys.path:
    sys.path.insert(0, DEV)

import netgen                                            # noqa: E402
from netgen import flows as F                            # noqa: E402
from netgen.core import ArpModel, Host, PcapWriter  # noqa: E402
from netgen.identity import H                            # noqa: E402
from netgen.model import build_hosts, set_capture_day    # noqa: E402
from netgen.tls import PKI                               # noqa: E402
from netgen.accounts import Directory                    # noqa: E402
from netgen import protocols as P                        # noqa: E402
from netgen.campaign import actions as A                 # noqa: E402

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
INVENTORY = os.path.join(DEV, "inventory.json")
T0 = 1_780_000_000.0


# ----------------------------------------------------------------------------- validator
def _csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def validate_frame(frame):
    """Return a list of problems for one Ethernet frame (empty list = valid). ARP is accepted."""
    if len(frame) < 14:
        return ["short frame"]
    etype = struct.unpack("!H", frame[12:14])[0]
    if etype == 0x0806:
        return [] if len(frame) >= 42 else ["short arp"]
    if etype != 0x0800:
        return ["unexpected ethertype %04x" % etype]
    ip = frame[14:]
    errs = []
    if len(ip) < 20:
        return ["short ip"]
    ver, ihl = ip[0] >> 4, (ip[0] & 15) * 4
    if ver != 4:
        errs.append("version")
    if ihl < 20 or len(ip) < ihl:
        return errs + ["ihl"]
    total = struct.unpack("!H", ip[2:4])[0]
    if total > len(ip) or (len(ip) > total and any(ip[total:]) ) or total < ihl:
        errs.append("total length %d vs %d" % (total, len(ip)))
    if _csum(ip[:ihl]) != 0:
        errs.append("ip checksum")
    if ip[8] == 0:
        errs.append("ttl 0")
    proto = ip[9]
    body = ip[ihl:total]
    pseudo = ip[12:20] + struct.pack("!BBH", 0, proto, len(body))
    if proto == 6:
        if len(body) < 20 or _csum(pseudo + body) != 0:
            errs.append("tcp checksum")
    elif proto == 17:
        ck = struct.unpack("!H", body[6:8])[0]
        if ck != 0 and _csum(pseudo + body) != 0:
            errs.append("udp checksum")
    elif proto == 1:
        if _csum(body) != 0:
            errs.append("icmp checksum")
    else:
        errs.append("protocol %d" % proto)
    return errs


def parse(frame):
    """(proto, src_ip, dst_ip, sport, dport, flags, payload_len) of an IPv4 frame, else None."""
    if struct.unpack("!H", frame[12:14])[0] != 0x0800:
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    body = ip[ihl:total]
    src, dst = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20]))
    if proto == 6:
        sp, dp = struct.unpack("!HH", body[:4])
        off = (body[12] >> 4) * 4
        return proto, src, dst, sp, dp, body[13], len(body) - off
    if proto == 17:
        sp, dp = struct.unpack("!HH", body[:4])
        return proto, src, dst, sp, dp, 0, len(body) - 8
    return proto, src, dst, 0, 0, body[0] if proto == 1 else 0, len(body)


# ----------------------------------------------------------------------------- environment
def make_env(pki=None, day=None, user_net=None, server_net=None):
    netgen.reseed_all()
    cap_day = set_capture_day(day)
    hosts, link, sites, resolvers = build_hosts(INVENTORY, user_net=user_net, server_net=server_net, with_ot=False)
    ctx = F.Ctx(hosts, link, ArpModel(link), pki or PKI(day=cap_day), open(os.devnull, "w"), scale=0.01)
    ctx.sites = sites
    ctx.isp_resolvers = resolvers
    ctx.dir = Directory(hosts, P.username_for)
    return ctx


def ext_host(ctx, ip="203.0.113.50", name="scan50.probe-labs.example", hops=9):
    h = Host(name.split(".")[0].upper(), ip, "02:00:5e:11:22:33", "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", name)
    h.hops = hops
    return h


def pick(ctx, suffix_or_pred):
    if callable(suffix_or_pred):
        return sorted((h for h in ctx.h.values() if suffix_or_pred(h)), key=lambda h: h.name)[0]
    return ctx.h[H(suffix_or_pred)]


def workstation(ctx):
    return pick(ctx, lambda h: "workstation" in h.role.lower() and "windows" in h.os.lower())


def linux_server(ctx):
    return pick(ctx, lambda h: "linux" in h.os.lower() and "server" in h.role.lower())


# (token, src picker, dst picker, params)
def cases(ctx):
    ws, dc, fs = workstation(ctx), pick(ctx, "DC1"), pick(ctx, "FILE1")
    lin = linux_server(ctx)
    ext = ext_host(ctx)
    return [
        ("syn_scan", ws, fs, {}),
        ("syn_scan", ext, fs, {"scope": "host", "ports": [22, 80, 443, 445, 3389]}),
        ("icmp_sweep", ws, fs, {}),
        ("icmp_sweep", ext, fs, {"max_hosts": 6}),
        ("port_probe", ws, fs, {}),
        ("ldap_recon", ws, dc, {}),
        ("smb_share_enum", ws, fs, {}),
        ("ssh_brute", ext, lin, {"connections": 3}),
        ("rdp_brute", ext, fs, {"attempts": 3}),
        ("kerberos_spray", ws, dc, {"accounts": 8}),
        ("kerberoast", ws, dc, {}),
        ("asrep_roast", ws, dc, {}),
        ("smb_admin_exec", ws, fs, {}),
        ("wmi_exec", ws, fs, {}),
        ("rdp_session", ws, fs, {"duration_s": 8.0}),
        ("ransomware_smb", ws, fs, {"files": 4, "max_file_kb": 16}),
    ]


TOKENS = ["syn_scan", "icmp_sweep", "port_probe", "ldap_recon", "smb_share_enum", "ssh_brute", "rdp_brute",
          "kerberos_spray", "kerberoast", "asrep_roast", "smb_admin_exec", "wmi_exec", "rdp_session",
          "ransomware_smb"]


def run_case(ctx, token, src, dst, params, ts=T0):
    return A.get(token).fn(ctx, src, dst, ts=ts, **params)


class ActionsBTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.load_all()
        cls.pki = PKI(day=set_capture_day(None))
        cls.ctx = make_env(cls.pki)
        cls.out = {}
        for i, (tok, s, d, p) in enumerate(cases(cls.ctx)):
            cls.out[(i, tok)] = (s, d, p, run_case(cls.ctx, tok, s, d, p, T0 + i * 600))

    def test_registered(self):
        specs = A.all_specs()
        for t in TOKENS:
            self.assertIn(t, specs)
            sp = specs[t]
            self.assertTrue(sp.summary and sp.tactic and sp.techniques and sp.protocols and sp.title)
            for _name, meta in sp.params.items():
                self.assertIn("type", meta)
                self.assertIn("default", meta)
                self.assertIn("help", meta)

    def test_params_cover_call_signature(self):
        for t in TOKENS:
            import inspect
            sig = inspect.signature(A.get(t).fn)
            declared = set(A.get(t).params)
            accepted = {n for n, p in sig.parameters.items() if p.kind == p.KEYWORD_ONLY and n != "ts"}
            # wrapped by functools.wraps: the signature follows __wrapped__
            self.assertEqual(declared - accepted, set(), t)

    def test_nonempty_and_valid(self):
        for (_i, tok), (_s, _d, _p, pk) in self.out.items():
            self.assertTrue(pk, tok)
            bad = [(n, validate_frame(f)) for n, (_, f) in enumerate(pk) if validate_frame(f)]
            self.assertEqual(bad[:3], [], "%s: invalid frames" % tok)
            self.assertTrue(all(ts >= T0 for ts, _ in pk), tok)

    def _ip_pkts(self, tok, idx=None):
        for (i, t), (s, d, p, pk) in self.out.items():
            if t == tok and (idx is None or i == idx):
                return s, d, p, [parse(f) for _, f in pk if parse(f)]
        raise KeyError(tok)

    def test_ports_match_spec(self):
        want = {"ldap_recon": 389, "ssh_brute": 22, "rdp_brute": 3389, "kerberos_spray": 88, "kerberoast": 88,
                "asrep_roast": 88, "smb_admin_exec": 445, "wmi_exec": 135, "rdp_session": 3389,
                "ransomware_smb": 445, "smb_share_enum": 445}
        for tok, port in want.items():
            s, d, p, pk = self._ip_pkts(tok)
            tcp = [x for x in pk if x[0] == 6]
            self.assertTrue(any(port in (x[3], x[4]) for x in tcp), tok)
            if tok == "wmi_exec":
                dyn = {x[4] for x in tcp if x[1] == s.ip and x[4] >= 49152}
                self.assertTrue(dyn, "wmi dynamic port")

    def test_syn_scan_responses(self):
        s, d, p, pk = self._ip_pkts("syn_scan", 1)           # external -> one host
        ports = [22, 80, 443, 445, 3389]
        syns = [x for x in pk if x[1] == s.ip and x[5] == 0x02]
        self.assertEqual(sorted(x[4] for x in syns), sorted(ports))
        open_ports = {pt for pt in ports if self._open(d, pt)}
        for x in pk:
            if x[1] == d.ip:                                  # replies
                if x[3] in open_ports:
                    self.assertEqual(x[5], 0x12, "open -> SYN/ACK")
                else:
                    self.assertEqual(x[5], 0x14, "closed -> RST/ACK")
        rsts = [x for x in pk if x[1] == s.ip and x[5] == 0x04]
        self.assertEqual(len(rsts), len(open_ports))          # half-open teardown RST per open port
        self.assertTrue(open_ports and len(open_ports) < len(ports), "mix of open and closed")

    @staticmethod
    def _open(h, port):
        from netgen.campaign.actions.recon import _is_open
        return _is_open(h, port)

    def test_syn_scan_subnet_internal(self):
        s, d, p, pk = self._ip_pkts("syn_scan", 0)
        victims = {x[2] for x in pk if x[1] == s.ip}
        self.assertGreater(len(victims), 1)
        self.assertTrue(all(x[0] == 6 for x in pk))
        self.assertEqual(len({x[3] for x in pk if x[1] == s.ip}), 1, "one scanner source port")

    def test_icmp_sweep(self):
        s, d, p, pk = self._ip_pkts("icmp_sweep", 2)
        reqs = [x for x in pk if x[1] == s.ip]
        reps = [x for x in pk if x[2] == s.ip]
        self.assertTrue(reqs and reps)
        self.assertTrue(all(x[0] == 1 for x in pk))
        self.assertLess(len(reps), len(reqs) + 1)
        self.assertEqual({x[5] for x in reqs}, {8})
        self.assertEqual({x[5] for x in reps}, {0})
        # absent addresses drew an unanswered ARP, not an echo
        arps = [f for _, f in self.out[(2, "icmp_sweep")][3] if f[12:14] == b"\x08\x06"]
        self.assertTrue(arps)

    def test_port_probe(self):
        s, d, p, pk = self._ip_pkts("port_probe")
        self.assertEqual({x[4] for x in pk if x[1] == s.ip and x[5] == 0x02}, {22, 80, 135, 139, 443, 445, 3389})
        self.assertTrue(any(x[5] == 0x14 for x in pk), "closed ports answer RST/ACK")
        self.assertTrue(any(x[5] == 0x12 for x in pk), "open ports answer SYN/ACK")

    def test_kerberos_codes(self):
        # PREAUTH_FAILED = 24 appears as an integer in the KRB-ERROR; just check the exchange count
        s, d, p, pk = self._ip_pkts("kerberos_spray")
        syns = [x for x in pk if x[1] == s.ip and x[5] == 0x02]
        self.assertEqual(len(syns), 8)
        s, d, p, pk = self._ip_pkts("kerberoast")
        self.assertGreaterEqual(len([x for x in pk if x[1] == s.ip and x[5] == 0x02]), 3)

    def test_rc4_only_tgs_req(self):
        """kerberoast asks for etype 23 only: the KDC-REQ etype list is SEQUENCE { INTEGER 23 }."""
        pk = self.out[[k for k in self.out if k[1] == "kerberoast"][0]][3]
        blob = b"".join(f for _, f in pk)
        self.assertIn(b"\xa8\x05\x30\x03\x02\x01\x17", blob)

    def test_deterministic(self):
        first = []
        for _ in range(2):
            ctx = make_env(self.pki)
            res = {}
            for i, (tok, s, d, p) in enumerate(cases(ctx)):
                res[(i, tok)] = [(round(ts, 9), f) for ts, f in run_case(ctx, tok, s, d, p, T0 + i * 600)]
            first.append(res)
        a, b = first
        for k in a:
            self.assertEqual(len(a[k]), len(b[k]), k)
            self.assertEqual(a[k], b[k], "not byte-identical: %s" % (k,))

    def test_ransomware_modest(self):
        s, d, p, pk = self._ip_pkts("ransomware_smb")
        self.assertLess(len(pk), 3000)

    def test_admin_exec_is_filler(self):
        pk = self.out[[k for k in self.out if k[1] == "smb_admin_exec"][0]][3]
        blob = b"".join(f for _, f in pk)
        self.assertNotIn(b"This program cannot be run in DOS mode", blob)
        self.assertNotIn(b"OpenSCManagerW", blob)

    def test_tshark(self):
        if not os.path.exists(TSHARK):
            self.skipTest("no tshark")
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "actions_b.pcap")
            w = PcapWriter(path)
            rows = []
            for (_, _), (_, _, _, pk) in self.out.items():
                rows += pk
            rows.sort(key=lambda r: r[0])
            for ts, fr in rows:
                w.write(ts, fr)
            w.close()
            r = subprocess.run([TSHARK, "-r", path, "-q", "-z", "expert"], capture_output=True, text=True, timeout=300)
            text = r.stdout + r.stderr
            self.assertNotIn("Malformed", text)
            self.assertNotIn("Bad checksum", text.replace("Bad checksum [correct]", ""))
            self.assertNotIn("Bad TCP checksum", text)
            self.assertNotIn("Bad UDP checksum", text)
            self.assertNotIn("Bad ICMP checksum", text)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class IdentityAndNetworksTest(unittest.TestCase):
    """A different company, capture date and custom networks: valid packets, no template names."""

    def test_other_identity_and_nets(self):
        from netgen import identity
        from netgen.identity import Identity
        from opengenerator_build import validate_nets
        A.load_all()
        identity.set_current(Identity("Acme", "Retail"))
        try:
            un, sn, _ = validate_nets("172.20.5.0/24", "172.20.9.0/24", None)
            ctx = make_env(None, day="2031-03-09", user_net=un, server_net=sn)
            raw = b""
            for i, (tok, s, d, p) in enumerate(cases(ctx)):
                pk = run_case(ctx, tok, s, d, p, 1_930_000_000.0 + i * 600)
                self.assertTrue(pk, tok)
                for _, f in pk:
                    self.assertEqual(validate_frame(f), [], tok)
                raw += b"".join(f for _, f in pk)
            low = raw.lower()
            for needle in (b"exl-", b"corp.example.local", b"example logistics"):
                self.assertNotIn(needle, low, needle)
            self.assertIn(identity.get_current().prefix.lower().encode(), low)
        finally:
            identity.set_current(None)


if __name__ == "__main__":
    unittest.main()

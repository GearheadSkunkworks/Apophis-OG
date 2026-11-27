"""Tests for the Zeek-style writers (zeeklogs.py) and the tshark comparison harness.

Run from dev/:  python -m unittest tests.test_zeeklogs
"""
import json
import os
import shutil
import socket
import struct
import tempfile
import unittest

import zeeklogs as Z
from checks import compare_zeek_style as H

SYN, FIN, RST, PSH, ACK = 2, 1, 4, 8, 16


def slurp(p):
    with open(p) as f:
        return f.read()


def flow(**kw):
    f = dict(proto="tcp", src="10.0.0.1", sport=40000, dst="10.0.0.2", dport=443, start=1700000000.5,
             end=1700000001.0, orig_pkts=5, resp_pkts=4, orig_ip_bytes=400, resp_ip_bytes=900,
             orig_bytes=100, resp_bytes=600, flags_orig=SYN | ACK | FIN | PSH, flags_resp=SYN | ACK | FIN,
             tag="t", tags=[], first_pkt=0, last_pkt=8)
    f.update(kw)
    return f


# ---- hand-built IPv4 frames (test code only; checksums left zero, the parser and tshark ignore them)
def _ip4(src, dst, proto, seg):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(seg), 1, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x02\0\0\0\0\2" + b"\x02\0\0\0\0\1" + b"\x08\x00" + h + seg


def tcp_frame(src, sp, dst, dp, fl, pay=b""):
    return _ip4(src, dst, 6, struct.pack("!HHIIBBHHH", sp, dp, 1, 1, 5 << 4, fl, 65535, 0, 0) + pay)


def udp_frame(src, sp, dst, dp, pay):
    return _ip4(src, dst, 17, struct.pack("!HHHH", sp, dp, 8 + len(pay), 0) + pay)


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in frames:
            f.write(struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)), len(fr), len(fr)) + fr)


def _qname(n):
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"


def dns_msg(tid, name, qtype=1, rcode=0, answers=(), resp=False):
    """answers: [(ipv4 string, ttl)] as A records using a name pointer."""
    flags = (0x8180 if resp else 0x0100) | rcode
    m = struct.pack("!HHHHHH", tid, flags, 1, len(answers), 0, 0) + _qname(name) + struct.pack("!HH", qtype, 1)
    for ip, ttl in answers:
        m += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
    return m


C, S = "10.0.0.5", "10.0.0.53"


def dns_frames():
    r = lambda ts, tid, sp, name, **k: (ts, udp_frame(S, 53, C, sp, dns_msg(tid, name, resp=True, **k)))
    q = lambda ts, tid, sp, name: (ts, udp_frame(C, sp, S, 53, dns_msg(tid, name)))
    return [
        q(1.0, 1, 5001, "a.example.com"), r(1.05, 1, 5001, "a.example.com", answers=[("192.0.2.1", 300)]),
        q(2.0, 2, 5002, "nx.example.com"), r(2.01, 2, 5002, "nx.example.com", rcode=3),
        q(3.0, 3, 5003, "lost.example.com"), q(3.5, 3, 5003, "lost.example.com"),   # retransmit, never answered
        r(4.0, 9, 5009, "orphan.example.com", answers=[("192.0.2.9", 60)]),
    ]


class ConnLogTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def write(self, flows, fmt="tsv", **kw):
        p = os.path.join(self.d, "conn." + fmt)
        Z.write_conn_log(flows, p, fmt, **kw)
        return p

    def test_tsv_header_and_fields(self):
        p = self.write([flow(), flow(sport=40001, start=1700000002.0)])
        lines = slurp(p).splitlines()
        self.assertEqual(lines[0], "#separator \\x09")
        self.assertIn("#path\tconn", lines)
        fields = next(x for x in lines if x.startswith("#fields")).split("\t")[1:]
        types = next(x for x in lines if x.startswith("#types")).split("\t")[1:]
        self.assertEqual(fields[:8], ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service"])
        self.assertEqual(len(fields), len(types))
        data = [x for x in lines if not x.startswith("#")]
        self.assertEqual(len(data), 2)
        for x in data:
            self.assertEqual(len(x.split("\t")), len(fields))
        self.assertTrue(lines[-1].startswith("#close"))

    def test_tsv_and_json_agree(self):
        flows = [flow(), flow(dport=53, proto="udp", flags_orig=0, flags_resp=0, start=1700000003.0)]
        t = {r["uid"]: r for r in H.read_log(self.write(flows, "tsv"))}
        j = {r["uid"]: r for r in H.read_log(self.write(flows, "json"))}
        self.assertEqual(set(t), set(j))
        for u, r in t.items():
            for k, v in r.items():
                if v is None or k == "tunnel_parents":
                    continue
                jv = j[u][k]
                self.assertEqual("%.6f" % jv if isinstance(jv, float) else str(jv).replace("True", "T").replace("False", "F"), v, k)

    def test_json_is_lines_of_objects(self):
        for x in slurp(self.write([flow()], "json")).splitlines():
            self.assertIsInstance(json.loads(x), dict)

    def test_uid_stable_and_distinct(self):
        self.assertEqual(slurp(self.write([flow()])), slurp(self.write([flow()])))
        u = lambda **k: H.read_log(self.write([flow(**k)]))[0]["uid"]
        self.assertNotEqual(u(), u(sport=1))
        self.assertEqual(len(u()), 18)

    def test_service_by_port_needs_answer(self):
        r = H.read_log(self.write([flow(dport=445), flow(dport=22, resp_pkts=0, flags_resp=0)]))
        by = {x["id.resp_p"]: x for x in r}
        self.assertEqual(by["445"]["service"], "smb")
        self.assertIsNone(by["22"]["service"])

    def test_conn_state_cases(self):
        cs = Z.conn_state
        self.assertEqual(cs("tcp", 4, SYN | ACK | FIN, SYN | ACK | FIN), "SF")
        self.assertEqual(cs("tcp", 0, SYN, 0), "S0")
        self.assertEqual(cs("tcp", 1, SYN, RST | ACK), "REJ")
        self.assertEqual(cs("tcp", 3, SYN | ACK | RST, SYN | ACK), "RSTO")
        self.assertEqual(cs("tcp", 3, SYN | ACK, SYN | ACK | RST), "RSTR")
        self.assertEqual(cs("tcp", 3, SYN | ACK, SYN | ACK), "S1")
        self.assertEqual(cs("tcp", 3, SYN | ACK | FIN, SYN | ACK), "S2")
        self.assertEqual(cs("tcp", 3, SYN | ACK, SYN | ACK | FIN), "S3")
        self.assertEqual(cs("tcp", 0, ACK | PSH, 0), "OTH")           # one-way, mid-stream
        self.assertEqual(cs("tcp", 2, ACK, SYN | ACK), "SHR")
        self.assertEqual(cs("udp", 0, 0, 0), "S0")
        self.assertEqual(cs("udp", 2, 0, 0), "SF")
        self.assertEqual(cs("tcp", 4, "SAF", "SAF"), "SF")             # letter strings accepted

    def test_history(self):
        h = Z.history
        self.assertEqual(h("tcp", SYN | ACK | FIN, SYN | ACK | FIN, 10, 20), "ShADdFf")
        self.assertEqual(h("tcp", SYN, 0, 0, 0), "S")
        self.assertEqual(h("tcp", SYN, RST | ACK, 0, 0), "Sr")
        self.assertEqual(h("udp", 0, 0, 5, 5), "")

    def test_unset_payload_bytes_when_side_silent(self):
        r = H.read_log(self.write([flow(resp_pkts=0, resp_bytes=0, resp_ip_bytes=0, flags_resp=0, flags_orig=SYN | FIN)]))[0]
        self.assertIsNone(r["resp_bytes"])
        self.assertEqual(r["conn_state"], "SH")

    def test_local_nets_rule(self):
        r = H.read_log(self.write([flow()], rules={"local_nets": ["10.0.0.0/30"]}))[0]
        self.assertEqual((r["local_orig"], r["local_resp"]), ("T", "T"))
        self.assertIsNone(H.read_log(self.write([flow()]))[0]["local_orig"])

    def test_bad_format_rejected(self):
        with self.assertRaises(ValueError):
            Z.write_conn_log([flow()], os.path.join(self.d, "x"), "csv")


class DnsLogTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.pcap = os.path.join(self.d, "d.pcap")
        write_pcap(self.pcap, dns_frames())

    def rows(self, fmt="tsv"):
        p = os.path.join(self.d, "dns." + fmt)
        n = Z.write_dns_log(self.pcap, p, fmt)
        r = H.read_log(p)
        self.assertEqual(n, len(r))
        return {x["query"]: x for x in r}

    def test_pairing(self):
        r = self.rows()
        self.assertEqual(len(r), 4)                                    # retransmit collapsed
        a = r["a.example.com"]
        self.assertEqual((a["qtype_name"], a["rcode_name"], a["answers"], a["TTLs"]), ("A", "NOERROR", "192.0.2.1", "300.000000"))
        self.assertAlmostEqual(float(a["rtt"]), 0.05, places=4)
        self.assertEqual(r["nx.example.com"]["rcode_name"], "NXDOMAIN")
        self.assertEqual(r["nx.example.com"]["rejected"], "T")
        self.assertIsNone(r["nx.example.com"]["answers"])
        lost = r["lost.example.com"]
        self.assertIsNone(lost["rtt"])
        self.assertIsNone(lost["rcode"])
        self.assertEqual(lost["ts"], "3.000000")
        self.assertIsNone(r["orphan.example.com"]["rtt"])
        self.assertEqual(r["orphan.example.com"]["rcode_name"], "NOERROR")

    def test_json_agrees(self):
        t, j = self.rows("tsv"), self.rows("json")
        self.assertEqual(set(t), set(j))
        self.assertEqual(j["a.example.com"]["answers"], ["192.0.2.1"])
        self.assertNotIn("rtt", j["lost.example.com"])

    def test_hostile_name_cannot_break_tsv_rows(self):
        evil = dns_msg(1, "a.b", 1)
        evil = evil.replace(b"\x01a\x01b", b"\x04x\ty\n")           # label with a tab and a newline
        write_pcap(self.pcap, [(1.0, udp_frame(C, 5001, S, 53, evil))])
        p = os.path.join(self.d, "e.log")
        Z.write_dns_log(self.pcap, p)
        data = [x for x in slurp(p).splitlines() if not x.startswith("#")]
        self.assertEqual(len(data), 1)
        self.assertEqual(len(data[0].split("\t")), len(Z.DNS_FIELDS))
        self.assertIn("x\\x09y\\x0a", data[0])

    def test_ipv6_transaction(self):
        def ip6(src, dst, seg):
            h = struct.pack("!IHBB", 0x60000000, len(seg), 17, 64) + socket.inet_pton(socket.AF_INET6, src) \
                + socket.inet_pton(socket.AF_INET6, dst)
            return b"\x02\0\0\0\0\2\x02\0\0\0\0\1\x86\xdd" + h + seg
        u6 = lambda s, sp, d, dp, pay: ip6(s, d, struct.pack("!HHHH", sp, dp, 8 + len(pay), 0) + pay)
        c6, s6 = "2001:db8::1", "2001:db8::53"
        write_pcap(self.pcap, [(1.0, u6(c6, 5000, s6, 53, dns_msg(7, "v6.example.com", 28))),
                               (1.1, u6(s6, 53, c6, 5000, dns_msg(7, "v6.example.com", 28, resp=True)))])
        r = self.rows()["v6.example.com"]
        self.assertEqual((r["id.orig_h"], r["qtype_name"], r["rcode_name"]), (c6, "AAAA", "NOERROR"))

    def test_header(self):
        p = os.path.join(self.d, "dns.log")
        Z.write_dns_log(self.pcap, p)
        txt = slurp(p)
        self.assertIn("#path\tdns", txt)
        self.assertIn("#fields\tts\tuid\tid.orig_h", txt)


@unittest.skipUnless(H.tshark_path(), "tshark not installed")
class HarnessTests(unittest.TestCase):
    def test_tiny_pcap_agrees_and_mismatch_is_caught(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        pcap = os.path.join(d, "t.pcap")
        c, s = "10.0.0.1", "10.0.0.2"
        base = [(1.0, tcp_frame(c, 1234, s, 80, SYN)), (1.1, tcp_frame(s, 80, c, 1234, SYN | ACK)),
                (1.2, tcp_frame(c, 1234, s, 80, ACK | PSH, b"x" * 50)), (1.3, udp_frame(c, 5000, "10.0.0.9", 123, b"\0" * 48))]
        write_pcap(pcap, sorted(base + dns_frames(), key=lambda x: x[0]))
        u = lambda sp, dst, dp, op, rp, t0, t1: flow(proto="udp", src=C, sport=sp, dst=dst, dport=dp, orig_pkts=op,
                                                      resp_pkts=rp, start=t0, end=t1, flags_orig=0, flags_resp=0)
        flows = [flow(src=c, sport=1234, dst=s, dport=80, orig_pkts=2, resp_pkts=1, start=1.0, end=1.2),
                 u(5000, "10.0.0.9", 123, 1, 0, 1.3, 1.3) | {"src": c},
                 u(5001, S, 53, 1, 1, 1.0, 1.05), u(5002, S, 53, 1, 1, 2.0, 2.01),
                 u(5003, S, 53, 2, 0, 3.0, 3.5), u(5009, S, 53, 0, 1, 4.0, 4.0)]
        conn, dns = os.path.join(d, "conn.log"), os.path.join(d, "dns.log")
        Z.write_conn_log(flows, conn)
        Z.write_dns_log(pcap, dns)
        self.assertEqual(H.compare_conn(pcap, conn)[0], [])
        self.assertEqual(H.compare_dns(pcap, dns)[0], [])
        # a flow split in two still merges to the same 5-tuple total
        split = [flow(src=c, sport=1234, dst=s, dport=80, orig_pkts=1, resp_pkts=1, start=1.0, end=1.1),
                 flow(src=c, sport=1234, dst=s, dport=80, orig_pkts=1, resp_pkts=0, start=1.2, end=1.2)] + flows[1:]
        Z.write_conn_log(split, conn)
        self.assertEqual(H.compare_conn(pcap, conn)[0], [])
        # a wrong count is reported
        Z.write_conn_log([flow(src=c, sport=1234, dst=s, dport=80, orig_pkts=9, resp_pkts=1)] + flows[1:], conn)
        self.assertTrue(any("frame count" in x for x in H.compare_conn(pcap, conn)[0]))
        self.assertEqual(H.main([pcap, "--conn", conn, "--dns", dns]), 1)


if __name__ == "__main__":
    unittest.main()

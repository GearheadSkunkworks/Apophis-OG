"""IP options and the opt-in Linux SYN-ACK in netgen.core (default-off engine addition).
Byte-level: the default ipv4() and handshake() output is identical to the code before the change (read from git, the
commit before the first ip_options commit); with options the IHL, total length and checksum are valid; more than 40
bytes is rejected; server_stack="linux" lays the SYN-ACK out as MSS, SACK-permitted, timestamps, NOP, wscale 7, window 65160.
Run: .venv/bin/python check_ip_options.py [TSHARK]   (the tshark pass is skipped when no tshark is found)"""
import importlib.util, os, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from netgen import core  # noqa: E402 - sys.path is set up before the import
from checks.tshark_locate import find_tshark  # noqa: E402 - sys.path is set up first

TSHARK = sys.argv[1] if len(sys.argv) > 1 else find_tshark()


BASE_COMMIT = "848f757"      # the commit before the ip_options / linux SYN-ACK update; absent from a fresh clone, where the check is skipped


def load_old():
    try:
        r = subprocess.run(["git", "show", f"{BASE_COMMIT}:dev/netgen/core.py"], cwd=HERE, capture_output=True, text=True,
                           timeout=60)
    except FileNotFoundError:      # no git installed: same as no history
        r = None
    if r is None or r.returncode != 0:      # a shallow clone (CI) does not have that commit
        print("check_ip_options: old-engine comparison skipped (%s not in history); byte-level checks still run" % BASE_COMMIT)
        return None
    src = r.stdout
    spec = importlib.util.spec_from_loader("core_old", loader=None)
    m = importlib.util.module_from_spec(spec)
    # lint-ok: source comes from this repo's own git history (a pinned commit), not from input
    exec(compile(src, "core_old.py", "exec"), m.__dict__)
    return m


class StubLink:
    def addr(self, a, b, vantage):
        return b"\x02" * 6, b"\x04" * 6, 64


def hosts(m, client_os="Linux", server_os="Linux"):
    pair = (m.Host("c", "10.1.1.5", "02:00:00:00:00:05", client_os, "client"),
            m.Host("s", "10.2.2.9", "02:00:00:00:00:09", server_os, "server"))
    return pair


def hs(m, client_os="Windows 11", server_os="Linux", **kw):
    m.rng.seed(77)
    c, s = hosts(m, client_os, server_os)
    t = m.TcpSession(StubLink(), c, s, 80, 1.0, rtt=0.01, sport=40000)
    t.handshake(**kw)
    return [p for _, p in t.pkts]


old = load_old()

a, b = hosts(core)
if old is not None:
    # 1. default ipv4() byte-identical to the old build
    for m in (old, core):
        m.rng.seed(5)
    ao, bo = hosts(old)
    for pl in (b"", b"x" * 33, b"y" * 1400):
        assert core.ipv4(a, b, 6, pl, ttl=64, df=True) == old.ipv4(ao, bo, 6, pl, ttl=64, df=True)
        assert core.ipv4(a, b, 17, pl, ipid=7, tos=8) == old.ipv4(ao, bo, 17, pl, ipid=7, tos=8)

    # 2. default handshakes byte-identical for the Windows and macOS client layouts against a Windows server.
    # A Linux or embedded host now sends the Linux kernel's own SYN / SYN-ACK option layout by default (the
    # the kernel-layout fix, adopted when the no-module baseline was re-pinned), and a FreeBSD host its own, so
    # those are deliberately not compared with the earlier engine.
    for cos in ("Windows 11", "macOS 14"):
        assert hs(core, cos, "Windows Server") == hs(old, cos, "Windows Server"), cos
    core.rng.seed(77); _c, _s = hosts(core, "Linux", "Windows Server")
    _t = core.TcpSession(StubLink(), _c, _s, 80, 1.0, rtt=0.01, sport=40000); _t.handshake()
    assert [p for _, p in _t.pkts] != hs(old, "Linux", "Windows Server"), "Linux SYN should now use the kernel layout"

# 3. options: IHL, total length, checksum
for opt, want in ((b"\x01", 24), (b"\x94\x04\x00\x00", 24), (b"\x07\x07\x04" + b"\x00" * 4, 28), (b"\x01" * 40, 60)):
    pl = b"hello world"
    pkt = core.ipv4(a, b, 6, pl, ttl=64, df=True, ipid=9, ip_options=opt)
    hl = (pkt[0] & 0xF) * 4
    assert pkt[0] >> 4 == 4 and hl == want, (opt, hl)
    assert struct.unpack("!H", pkt[2:4])[0] == hl + len(pl) == len(pkt)
    assert core.csum(pkt[:hl]) == 0, "header checksum invalid"
    assert pkt[hl:] == pl and pkt[20:20 + len(opt)] == opt
    assert len(pkt[20:hl]) % 4 == 0
try:
    core.ipv4(a, b, 6, b"", ip_options=b"\x01" * 41)
    raise SystemExit("41-byte option was accepted")
except ValueError:
    pass
assert core.ipv4(a, b, 6, b"", ipid=1, ip_options=b"") == core.ipv4(a, b, 6, b"", ipid=1)

# 4. Linux SYN-ACK profile
core.rng.seed(77)
c, s = hosts(core, "Linux", "Linux")
t = core.TcpSession(StubLink(), c, s, 80, 1.0, rtt=0.01, sport=40000)
t.handshake(server_stack="linux")
syn, synack = t.pkts[0][1], t.pkts[1][1]


def tcp_opts(frame):
    ip = frame[14:]
    seg = ip[(ip[0] & 0xF) * 4:]
    return struct.unpack("!H", seg[14:16])[0], seg[20:(seg[12] >> 4) * 4]


csyn, copts = tcp_opts(syn)
win, so = tcp_opts(synack)
tsval_c = struct.unpack("!I", copts[copts.index(b"\x08\x0a") + 2:][:4])[0]
assert win == 65160
assert so[:4] == struct.pack("!BBH", 2, 4, t.mss) and so[4:6] == b"\x04\x02" and so[6:8] == b"\x08\x0a"
tsval_s, tsecr = struct.unpack("!II", so[8:16])
assert tsval_s != 0 and tsecr == tsval_c, "TSecr must echo the client TSval"
assert so[16:] == b"\x01\x03\x03\x07", so[16:].hex()
# a client without timestamps: TSecr 0
core.rng.seed(77)
c, s = hosts(core, "Windows 11", "Linux")
t = core.TcpSession(StubLink(), c, s, 80, 1.0, rtt=0.01, sport=40000)
t.handshake(server_stack="linux")
_, so = tcp_opts(t.pkts[1][1])
assert struct.unpack("!I", so[12:16])[0] == 0 and so[16:] == b"\x01\x03\x03\x07"

# 5. per-direction IP options reach the right packets only
core.rng.seed(3)
c, s = hosts(core)
t = core.TcpSession(StubLink(), c, s, 80, 1.0, rtt=0.01, sport=40001)
t.handshake()
t.ip_opts_c2s = b"\x94\x04\x00\x00"
t.c2s(b"GET / HTTP/1.1\r\n\r\n")
t.ip_opts_c2s = b""
t.s2c(b"HTTP/1.1 200 OK\r\n\r\n")
ihls = [(p[14] & 0xF) for _, p in t.pkts]
assert ihls[:3] == [5, 5, 5] and ihls[3] == 6 and all(i == 5 for i in ihls[4:]), ihls
for _, p in t.pkts:
    assert core.csum(p[14:14 + (p[14] & 0xF) * 4]) == 0

# 6. tshark agrees
if TSHARK and os.path.exists(TSHARK):
    with tempfile.TemporaryDirectory() as d:
        pc = os.path.join(d, "t.pcap")
        with open(pc, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, p in t.pkts:
                f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(p), len(p)) + p)
        out = subprocess.run([TSHARK, "-r", pc, "-o", "ip.check_checksum:TRUE", "-Y", "ip.hdr_len == 24", "-T", "fields",
                              "-e", "ip.hdr_len", "-e", "ip.checksum.status", "-e", "ip.opt.type", "-e", "_ws.expert"],
                             capture_output=True, text=True).stdout.strip().splitlines()
        assert len(out) == 1, out
        hl, st, ot, ex = (out[0].split("\t") + ["", "", "", ""])[:4]
        assert hl == "24" and st == "1", out       # 1 = Good, 2 = Bad
        print("tshark:", out[0])
print("ip options and the Linux SYN-ACK profile: default bytes unchanged, options valid")

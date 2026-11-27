"""
Core packet machinery for the OpenGenerator demo pcap generator.

Everything is built with struct packing (no scapy) so that millions of
frames can be produced in minutes. Every IPv4 header conforms to RFC 791:
version 4, IHL 5, correct total length, per-host incrementing ID, DF on TCP,
valid TTL, correct header checksum, correct protocol number. TCP/UDP
checksums are computed over the pseudo-header as required by RFC 793/768.
"""
import heapq
import random
import socket
import struct
import sys

ETH_IP = 0x0800
ETH_ARP = 0x0806
BCAST = b"\xff" * 6

SEED = 4242                 # reseeded per build by netgen.reseed_all()
rng = random.Random(SEED)


# ----------------------------------------------------------------- checksums
def csum(data: bytes) -> int:
    """Internet checksum (RFC 1071). 2**16 = 1 (mod 65535), so the ones'-complement sum of the 16-bit words is the whole number mod
    65535 (a nonzero number that divides evenly is 65535, not 0). Same value as summing the words, in one C call."""
    if len(data) & 1:
        data += b"\x00"
    s = int.from_bytes(data, sys.byteorder) % 65535
    if not s and any(data):
        s = 65535
    return (~s) & 0xFFFF


# ---------------------------------------------------------------------- hosts
# (mss, tls_profile) by device class. Wireless and tunnelled paths clamp below 1460 in the
# real world; appliances and agents present far smaller TLS hellos than browsers do.
def _endpoint_profile(os_low, role):
    r = (role or "").lower()
    if "phone" in r or "voip" in r:
        return 1460, "embedded"
    if "printer" in r or "board" in r or "access point" in r or "controller" in r:
        return 1400, "embedded"
    if "firewall" in r or "switch" in r or "sensor" in r:
        return 1460, "embedded"
    if "macos" in os_low:
        return 1460, rng.choice(["safari", "chrome"])
    if "windows" in os_low and "server" in r:
        return 1460, "winhttp"
    if "windows" in os_low:
        # a real fleet is a mix of browsers, and a slice of it is on wireless or VPN
        return rng.choice([1460, 1460, 1460, 1400, 1380]), rng.choice(
            ["chrome", "chrome", "edge", "firefox", "winhttp"])
    return 1460, "openssl"


class Host:
    __slots__ = ("name", "ip", "ipb", "mac", "ttl", "subnet", "os", "role", "_port", "ipid",
                 "fqdn", "gw", "hops", "mss", "tls_profile")

    def __init__(self, name, ip, mac, os_="", role="", subnet="", fqdn=""):
        self.name = name
        self.ip = ip
        self.ipb = socket.inet_aton(ip)
        self.mac = bytes.fromhex(mac.replace(":", ""))
        self.os = os_
        self.role = role
        self.subnet = subnet
        self.fqdn = fqdn
        low = os_.lower()
        # Path MSS and TLS client fingerprint both vary by what the device actually is. The
        # baseline previously offered one MSS (1460) and one cipher list for every host on the
        # network, which means a single JA3 for the whole estate — a strong synthetic tell, and
        # it makes any fingerprint-based analytic useless against the capture.
        self.mss, self.tls_profile = _endpoint_profile(low, role)
        if "windows" in low:
            self.ttl = 128
            self._port = rng.randint(49152, 55000)
        elif "macos" in low or "ios" in low and "cisco" not in low:
            self.ttl = 64
            self._port = rng.randint(49152, 55000)
        elif "pan-os" in low or "ios-xe" in low or "aruba" in low:
            self.ttl = 64
            self._port = rng.randint(20000, 30000)
        else:  # linux / embedded
            self.ttl = 64
            self._port = rng.randint(32768, 50000)
        self.ipid = rng.randint(1, 60000)
        self.gw = None
        self.hops = 0

    def eph(self):
        self._port += 1
        if self._port > 65000:
            self._port = 49152 if self.ttl == 128 else 32768
        return self._port

    def next_ipid(self):
        self.ipid = (self.ipid + 1) & 0xFFFF
        return self.ipid

    def __repr__(self):
        return f"<{self.name} {self.ip}>"


def same_subnet(a: Host, b: Host) -> bool:
    return a.ipb[:3] == b.ipb[:3]


# ---------------------------------------------------------------------- frames
def eth(dst: bytes, src: bytes, etype: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", etype) + payload


def ipv4(src: Host, dst: Host, proto: int, payload: bytes, ttl=None, df=False, ipid=None, tos=0, ip_options: bytes = b"") -> bytes:
    if ip_options:      # opt-in IP options (RFC 791): padded with 0x00 (EOL) to a 4-byte multiple, 40 bytes at most
        if len(ip_options) % 4:
            ip_options += b"\x00" * (4 - len(ip_options) % 4)
        if len(ip_options) > 40:
            raise ValueError("IP options may not exceed 40 bytes")
    total = 20 + len(ip_options) + len(payload)
    if ipid is None:
        ipid = src.next_ipid()
    flags = 0x4000 if df else 0
    ihl = 5 + len(ip_options) // 4
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, tos, total, ipid, flags, ttl if ttl is not None else src.ttl, proto, 0, src.ipb, dst.ipb) + ip_options
    hdr = hdr[:10] + struct.pack("H", csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(src: Host, dst: Host, sport: int, dport: int, payload: bytes, nocsum=False) -> bytes:
    length = 8 + len(payload)
    if nocsum:      # an all-zero checksum means "none" over IPv4 (RFC 768); CAPWAP requires it (RFC 5415 3.1)
        return struct.pack("!HHHH", sport, dport, length, 0) + payload
    pseudo = src.ipb + dst.ipb + struct.pack("!BBH", 0, 17, length)
    seg = struct.pack("!HHHH", sport, dport, length, 0) + payload
    c = csum(pseudo + seg)
    if c == 0:
        c = 0xFFFF
    return seg[:6] + struct.pack("H", c) + seg[8:]


def tcp(src: Host, dst: Host, sport, dport, seq, ack, flags, window, payload=b"", options=b"") -> bytes:
    if len(options) % 4:
        options += b"\x00" * (4 - len(options) % 4)
    doff = (5 + len(options) // 4) << 12
    seg = struct.pack("!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, doff | flags, window, 0, 0) + options + payload
    pseudo = src.ipb + dst.ipb + struct.pack("!BBH", 0, 6, len(seg))
    c = csum(pseudo + seg)
    return seg[:16] + struct.pack("H", c) + seg[18:]


def arp(op: int, smac: bytes, sip: bytes, tmac: bytes, tip: bytes) -> bytes:
    return struct.pack("!HHBBH", 1, ETH_IP, 6, 4, op) + smac + sip + tmac + tip


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


# -------------------------------------------------------------- link resolver
class Link:
    """
    Resolves the Ethernet addressing seen by the sensor for a packet from a
    to b, given that the capture is taken on the interface facing `vantage`
    (the client-side subnet). Returns (dst_mac, src_mac, ttl).
    """

    def __init__(self, fw_a: Host, fw_b: Host, fw_out: Host, *extra: Host, routing=None):
        # Keyed on /24 prefix, so the number of inside interfaces is not fixed. `extra` carries
        # the optional OT legs (cell/area, site operations, IDMZ) when that subnet is enabled;
        # with none passed this is exactly the two-subnet Link it has always been.
        self.fw = {fw_a.ipb[:3]: fw_a, fw_b.ipb[:3]: fw_b}
        for h in extra:
            self.fw[h.ipb[:3]] = h
        self.fw_out = fw_out
        # named refs so callers can ask "which subnet is the server side?" without
        # hard-coding an address prefix (the internal /24s are configurable)
        self.fw_a, self.fw_b = fw_a, fw_b
        self.fw_extra = list(extra)
        # routing is None for the single-firewall topology (behaviour is unchanged, byte for
        # byte). When the dual-firewall IDMZ sandwich is built, it carries the zone map and the
        # directly-attached gateway per /24 so that cell/area and site-operations sit behind
        # EXL-OTFW1, the IDMZ has a router on each side, and enterprise<->cell is two L3 hops.
        self.routing = routing
        if routing:
            self.fw.update(routing["default_gw"])   # cell/ops default-route via EXL-OTFW1

    def _zone(self, h: Host):
        """0 enterprise, 1 IDMZ, 2 OT; -1 for anything off the modelled estate (internet)."""
        if not self.routing:
            return 0
        return self.routing["zone"].get(h.ipb[:3], -1)

    def gateway_toward(self, local: Host, remote: Host):
        """The router whose MAC appears on `local`'s segment for traffic heading to `remote`.
        Single-router segments return their one gateway; the IDMZ (two routers) picks the
        enterprise-facing EXL-FW1 or the OT-facing EXL-OTFW1 by where `remote` lives."""
        if self.routing and local.ipb[:3] == self.routing["idmz_pfx"]:
            return (self.routing["idmz_south"] if self._zone(remote) == 2
                    else self.routing["idmz_north"])
        return self.fw.get(local.ipb[:3])

    def hop_count(self, a: Host, b: Host):
        """Routers between a and b: 1 across a single firewall, 2 enterprise<->cell across
        both. Internet legs keep the old single-hop convention and carry the rest in a.hops."""
        if not self.routing:
            return 1
        za, zb = self._zone(a), self._zone(b)
        if za < 0 or zb < 0:
            return 1
        if a.ipb[:3] == b.ipb[:3]:
            return 0
        return max(1, abs(za - zb))

    @property
    def user_prefix(self):
        """First three bytes of the user subnet, for /24 membership tests."""
        return self.fw_a.ipb[:3]

    @property
    def server_prefix(self):
        return self.fw_b.ipb[:3]

    # The app's own default addressing; scenario modules that add hosts at fixed addresses
    # (published appliances, VPN clients) are written against these.
    _DEFAULT_NETS = {"10.10.10": "user", "10.10.20": "server"}

    @classmethod
    def for_nets(cls, user_cidr: str, server_cidr: str):
        """A Link that knows only the two inside /24s (no gateways): enough for place(), user_net,
        server_net and the prefixes, for callers that need the addressing without a topology."""
        import types
        leg = lambda c: types.SimpleNamespace(subnet=c, ipb=socket.inet_aton(c.split("/")[0]))
        link = cls.__new__(cls)
        link.fw_a, link.fw_b = leg(user_cidr), leg(server_cidr)
        return link

    @property
    def user_net(self):
        return self.fw_a.subnet

    @property
    def server_net(self):
        return self.fw_b.subnet

    def place(self, ip: str) -> str:
        """Re-home a default-addressed host onto the configured user/server /24, keeping its last
        octet (the same rule remap_inventory applies to inventory hosts). Addresses outside the
        two default internal /24s (external actors, anything already custom) pass through."""
        head, _, last = ip.rpartition(".")
        side = self._DEFAULT_NETS.get(head)
        if side == "user":
            return ".".join(str(b) for b in self.fw_a.ipb[:3]) + "." + last
        if side == "server":
            return ".".join(str(b) for b in self.fw_b.ipb[:3]) + "." + last
        return ip

    def gateway_for(self, h: Host):
        return self.fw.get(h.ipb[:3])

    def addr(self, a: Host, b: Host, vantage: Host):
        """Ethernet addressing of a packet a->b captured on vantage's segment."""
        if same_subnet(a, b):
            return b.mac, a.mac, a.ttl
        if same_subnet(a, vantage):          # leaving the segment via its gateway
            return self.gateway_toward(a, b).mac, a.mac, a.ttl
        # arriving on the segment from the last router before it: one hop for a single
        # firewall, two for enterprise<->cell across both, plus any internet router hops.
        return b.mac, self.gateway_toward(b, a).mac, a.ttl - self.hop_count(a, b) - a.hops


# ------------------------------------------------------------------ arp model
class ArpModel:
    """
    Tracks neighbour-cache freshness so that each conversation is preceded by
    an observable ARP request/reply the way real stacks behave (Windows
    reachable time ~30-45 s, Linux base_reachable_time 30 s +/- 50%).
    """

    def __init__(self, link: Link):
        self.link = link
        self.cache = {}  # (requester_mac, target_ip) -> expiry ts

    def _expiry(self, requester: Host):
        low = requester.os.lower()
        if "pan-os" in low:                     # firewall ARP cache: 1800 s default
            return 1800 * rng.uniform(0.9, 1.1)
        if requester.ttl == 128:                # Windows: reachable time 30-45 s, but refreshes are mostly unicast
            return 45 * rng.uniform(1.0, 2.2)
        return 60 * rng.uniform(1.0, 3.0)       # Linux/embedded: confirmed by upper-layer feedback most of the time

    def resolve(self, requester: Host, target: Host, ts: float):
        """Yield (ts, frame) for ARP request/reply if the entry is stale."""
        key = (requester.mac, target.ipb)
        if self.cache.get(key, 0) > ts:
            return []
        self.cache[key] = ts + self._expiry(requester)
        req = eth(BCAST, requester.mac, ETH_ARP, arp(1, requester.mac, requester.ipb, b"\x00" * 6, target.ipb))
        rep = eth(requester.mac, target.mac, ETH_ARP, arp(2, target.mac, target.ipb, requester.mac, requester.ipb))
        return [(ts, req), (ts + rng.uniform(0.00008, 0.0006), rep)]

    def before_flow(self, a: Host, b: Host, ts: float, vantage: Host = None):
        """ARP exchanges that precede a flow a->b as seen on vantage's segment."""
        vantage = vantage or a
        out = []
        if same_subnet(a, b):
            out += self.resolve(a, b, ts)
            out += self.resolve(b, a, ts + 0.002)
        else:
            local = a if same_subnet(a, vantage) else b
            remote = b if local is a else a
            gw = self.link.gateway_toward(local, remote)
            if gw is not None:
                out += self.resolve(local, gw, ts)
                out += self.resolve(gw, local, ts + 0.002)  # firewall resolving the local host for return traffic
        return out

    def gratuitous(self, h: Host, ts: float):
        f = eth(BCAST, h.mac, ETH_ARP, arp(1, h.mac, h.ipb, b"\x00" * 6, h.ipb))
        return [(ts, f)]

    def probe(self, h: Host, ts: float):
        """RFC 5227 ARP probe (sender IP 0.0.0.0) then announcement."""
        p = eth(BCAST, h.mac, ETH_ARP, arp(1, h.mac, b"\x00" * 4, b"\x00" * 6, h.ipb))
        out = [(ts, p), (ts + 0.25, p), (ts + 0.5, p)]
        out += self.gratuitous(h, ts + 1.5)
        return out


# -------------------------------------------------------------- tcp sessions
class TcpSession:
    """
    A scripted TCP conversation. Application code calls c2s()/s2c() to push
    data and then close(); the session emits properly sequenced segments with
    delayed ACKs, MSS segmentation and realistic timing. All frames are
    addressed as seen from the client's segment (vantage = client).
    """

    def __init__(self, link: Link, client: Host, server: Host, dport: int, t0: float, rtt=None, sport=None,
                 mss=1460, vantage=None, rate=None):
        self.link = link
        self.c, self.s = client, server
        self.sport = sport or client.eph()
        self.dport = dport
        self.t = t0
        self.vantage = vantage or client
        if rtt is None:
            if same_subnet(client, server):
                rtt = rng.uniform(0.00025, 0.0009)
            elif link.gateway_for(server) is not None:
                rtt = rng.uniform(0.0006, 0.0025)
            else:
                rtt = rng.uniform(0.018, 0.070)
        self.rtt = rtt
        if rate is None:
            rate = 600e6 if rtt < 0.003 else 60e6
        self.per_byte = 8.0 / rate
        # the client's path MSS, unless a caller overrides it explicitly
        self.mss = mss if mss != 1460 else getattr(client, "mss", 1460)
        self.cseq = rng.randint(1, 0xFFFFFFF0)
        self.sseq = rng.randint(1, 0xFFFFFFF0)
        self.cwin = 64240 if client.ttl == 128 else 65535
        self.swin = 64240 if server.ttl == 128 else 65535
        self.ws_c, self.ws_s = 8, 7
        self.pkts = []
        self.open = False
        self._c_unacked = 0
        self._s_unacked = 0
        self.ip_opts_c2s = b""      # opt-in IP options put on every client->server / server->client packet (set before the packet is emitted)
        self.ip_opts_s2c = b""
        self.streaming = False      # True: bulk data keeps flowing while the receiver's ACKs travel back

    # -- low level -----------------------------------------------------------
    def _frame(self, a: Host, b: Host, sport, dport, seq, ack, flags, win, payload=b"", opts=b""):
        dmac, smac, ttl = self.link.addr(a, b, self.vantage)
        seg = tcp(a, b, sport, dport, seq, ack, flags, win, payload, opts)
        ipo = self.ip_opts_c2s if a is self.c else self.ip_opts_s2c
        pkt = ipv4(a, b, 6, seg, ttl=ttl, df=True, ip_options=ipo)
        return eth(dmac, smac, ETH_IP, pkt)

    def _emit(self, a, b, sport, dport, seq, ack, flags, win, payload=b"", opts=b""):
        self.pkts.append((self.t, self._frame(a, b, sport, dport, seq, ack, flags, win, payload, opts)))

    def _ack_from_server(self, hold=True):
        t0 = self.t
        self.t += self.rtt / 2 * rng.uniform(0.6, 1.2)
        self._emit(self.s, self.c, self.dport, self.sport, self.sseq, self.cseq, ACK, self.swin)
        self._c_unacked = 0
        if not hold:
            self.t = t0     # streaming: the sender keeps sending while the ACK is on its way

    def _ack_from_client(self, hold=True):
        t0 = self.t
        self.t += self.rtt / 2 * rng.uniform(0.6, 1.2)
        self._emit(self.c, self.s, self.sport, self.dport, self.cseq, self.sseq, ACK, self.cwin)
        self._s_unacked = 0
        if not hold:
            self.t = t0

    # -- api -----------------------------------------------------------------
    def handshake(self, syn_delay=0.0, server_stack=None):
        c, s = self.c, self.s
        copts = struct.pack("!BBH", 2, 4, self.mss) + b"\x01\x03\x03" + bytes([self.ws_c]) + b"\x01\x01\x04\x02"
        if c.ttl == 64 and "macos" in c.os.lower():
            copts = struct.pack("!BBH", 2, 4, self.mss) + b"\x01\x03\x03\x06\x01\x01\x08\x0a" + struct.pack("!II", rng.randint(1, 2**31), 0) + b"\x04\x02\x00\x00"
        elif c.ttl == 64 and ("linux" in c.os.lower() or "embedded" in c.os.lower()):
            # a Linux (or embedded-Linux, e.g. an IP camera) stack's SYN: MSS, SACK-permitted,
            # timestamps, NOP, window scale 7 (not the Windows layout) -- "embedded" fell through
            # to the Windows default before, despite its ttl already being 64.
            copts = (struct.pack("!BBH", 2, 4, self.mss) + b"\x04\x02\x08\x0a" + struct.pack("!II", rng.randint(1, 2**31), 0)
                     + b"\x01\x03\x03\x07")
        sopts = struct.pack("!BBH", 2, 4, self.mss) + b"\x01\x03\x03" + bytes([self.ws_s]) + b"\x01\x01\x04\x02"
        # A FreeBSD stack (the NetScaler appliance, opt-in by a "freebsd" OS string; no baseline
        # host has one) sends MSS, NOP, wscale 6, SACK-permitted, timestamps and window 65535.
        cwin0 = 64240
        if "freebsd" in c.os.lower():
            copts = (struct.pack("!BBH", 2, 4, self.mss) + b"\x01\x03\x03\x06\x04\x02\x08\x0a"
                     + struct.pack("!II", rng.randint(1, 2**31), 0))
            cwin0 = 65535
        if "freebsd" in s.os.lower():
            sopts = (struct.pack("!BBH", 2, 4, self.mss) + b"\x01\x03\x03\x06\x04\x02\x08\x0a"
                     + struct.pack("!II", rng.randint(1, 2**31), 0))
        swin0 = 65535
        if server_stack == "linux":
            # opt-in Linux server SYN-ACK: MSS, SACK-permitted, timestamps (TSecr echoes the client's TSval
            # when the client sent timestamps), NOP, window scale 7; window 65160
            tsecr = 0
            i = 0
            while i < len(copts):
                k = copts[i]
                if k == 0:
                    break
                if k == 1:
                    i += 1
                    continue
                if k == 8 and copts[i + 1] == 10:
                    tsecr = struct.unpack("!I", copts[i + 2:i + 6])[0]
                    break
                i += copts[i + 1]
            sopts = (struct.pack("!BBH", 2, 4, self.mss) + b"\x04\x02\x08\x0a" + struct.pack("!II", rng.randint(1, 2**31), tsecr)
                     + b"\x01\x03\x03\x07")
            swin0 = 65160
        self._emit(c, s, self.sport, self.dport, self.cseq, 0, SYN, cwin0, b"", copts)
        self.cseq += 1
        self.t += self.rtt * rng.uniform(0.8, 1.1) + syn_delay     # syn_delay: accept queue wait
        self._emit(s, c, self.dport, self.sport, self.sseq, self.cseq, SYN | ACK, swin0, b"", sopts)
        self.sseq += 1
        self.t += self.rtt / 2 * rng.uniform(0.8, 1.1)
        self._emit(c, s, self.sport, self.dport, self.cseq, self.sseq, ACK, self.cwin)
        self.open = True
        return self

    def _send(self, from_c: bool, data: bytes, think: float):
        self.t += think
        a, b = (self.c, self.s) if from_c else (self.s, self.c)
        sp, dp = (self.sport, self.dport) if from_c else (self.dport, self.sport)
        # the receiver of previous data ACKs it before the direction changes
        if from_c and self._s_unacked:
            self._ack_from_client()
        if not from_c and self._c_unacked:
            self._ack_from_server()
        n = len(data)
        off = 0
        segs_since_ack = 0
        serial = self.per_byte
        while off < n:
            chunk = data[off:off + self.mss]
            off += len(chunk)
            last = off >= n
            flags = ACK | (PSH if last or len(chunk) < self.mss else 0)
            if from_c:
                self._emit(a, b, sp, dp, self.cseq, self.sseq, flags, self.cwin, chunk)
                self.cseq += len(chunk)
                self._c_unacked += len(chunk)
            else:
                self._emit(a, b, sp, dp, self.sseq, self.cseq, flags, self.swin, chunk)
                self.sseq += len(chunk)
                self._s_unacked += len(chunk)
            self.t += len(chunk) * serial
            segs_since_ack += 1
            if segs_since_ack >= 2 and not last:
                # delayed ACK every two full segments (RFC 1122)
                segs_since_ack = 0
                if from_c:
                    self._ack_from_server(hold=not self.streaming)
                else:
                    self._ack_from_client(hold=not self.streaming)

    def c2s(self, data: bytes, think=0.0):
        self._send(True, data, think)
        return self

    def s2c(self, data: bytes, think=0.0):
        self._send(False, data, think)
        return self

    def idle(self, seconds: float):
        self.t += seconds
        return self

    def at(self, ts: float):
        """Move the clock forward to ts (never backwards)."""
        if ts > self.t:
            self.t = ts
        return self

    def drain(self):
        out = self.pkts
        self.pkts = []
        return out

    def close(self, by_client=True, think=0.0):
        self.t += think
        # ACK any outstanding data first
        if self._c_unacked:
            self._ack_from_server()
        if self._s_unacked:
            self._ack_from_client()
        c, s = self.c, self.s
        if by_client:
            self._emit(c, s, self.sport, self.dport, self.cseq, self.sseq, FIN | ACK, self.cwin)
            self.cseq += 1
            self.t += self.rtt / 2
            self._emit(s, c, self.dport, self.sport, self.sseq, self.cseq, ACK, self.swin)
            self.t += rng.uniform(0.0001, 0.003)
            self._emit(s, c, self.dport, self.sport, self.sseq, self.cseq, FIN | ACK, self.swin)
            self.sseq += 1
            self.t += self.rtt / 2
            self._emit(c, s, self.sport, self.dport, self.cseq, self.sseq, ACK, self.cwin)
        else:
            self._emit(s, c, self.dport, self.sport, self.sseq, self.cseq, FIN | ACK, self.swin)
            self.sseq += 1
            self.t += self.rtt / 2
            self._emit(c, s, self.sport, self.dport, self.cseq, self.sseq, ACK, self.cwin)
            self.t += rng.uniform(0.0001, 0.003)
            self._emit(c, s, self.sport, self.dport, self.cseq, self.sseq, FIN | ACK, self.cwin)
            self.cseq += 1
            self.t += self.rtt / 2
            self._emit(s, c, self.dport, self.sport, self.sseq, self.cseq, ACK, self.swin)
        self.open = False
        return self.pkts

    def refused(self, think=0.0, attempts=1, gap=0.5):
        """Connection refused: SYN answered by RST/ACK (service not listening). A Windows client
        retransmits the SAME SYN (same source port, same initial sequence number) at ~0.5s then
        ~1s -- not a fresh connection attempt from a new port each time (NPM-01 brief fix 5)."""
        c, s = self.c, self.s
        copts = struct.pack("!BBH", 2, 4, self.mss) + b"\x01\x03\x03" + bytes([self.ws_c]) + b"\x01\x01\x04\x02"
        self.t += think
        delays = (0.5, 1.0)
        for i in range(attempts):
            self._emit(c, s, self.sport, self.dport, self.cseq, 0, SYN, 64240, b"", copts)
            self.t += self.rtt * rng.uniform(0.8, 1.2)
            self._emit(s, c, self.dport, self.sport, 0, self.cseq + 1, RST | ACK, 0)
            if i < attempts - 1:
                self.t += delays[min(i, len(delays) - 1)]
        self.open = False
        return self.pkts

    def rst_from_server(self, think=0.0):
        """The server process died: its stack answers the next client data with a bare RST."""
        self.t += think
        self._emit(self.s, self.c, self.dport, self.sport, self.sseq, 0, RST, 0)
        self.open = False
        return self.pkts

    def client_data_then_rst(self, data: bytes, think=0.0):
        """Client sends a request into a dead server socket and gets RST back (Windows: RST, no ACK)."""
        self._send(True, data, think)
        self.t += self.rtt * rng.uniform(0.8, 1.3)
        self._emit(self.s, self.c, self.dport, self.sport, self.sseq, 0, RST, 0)
        self.open = False
        return self.pkts

    def zero_window(self, next_data: bytes, probes=3, first_wait=5.0, reopen=None):
        """
        Server advertises a zero receive window; the client sends zero-window probes
        (one byte of the pending data) with exponential backoff until the window opens.
        Returns the data still to be sent (all of it; the probed byte was not accepted).

        reopen: seconds until the receiver's application reads and reopens the window. When set,
        probes follow the persist timer (first_wait, doubling) only while they fall before that
        moment and the window update arrives at the reopen time (NPM-03 brief fix 4). When None the
        original fixed schedule is kept.
        """
        if self._c_unacked:
            self._ack_from_server()
        self.t += rng.uniform(0.01, 0.2) if reopen is None else rng.uniform(0.001, 0.01)
        self._emit(self.s, self.c, self.dport, self.sport, self.sseq, self.cseq, ACK, 0)   # ZeroWindow
        wait = first_wait
        if reopen is not None:
            t_zero, elapsed = self.t, 0.0
            while elapsed + wait < reopen:
                self.t = t_zero + elapsed + wait
                self._emit(self.c, self.s, self.sport, self.dport, self.cseq, self.sseq, ACK, self.cwin, next_data[:1])  # probe
                self.t += self.rtt / 2
                self._emit(self.s, self.c, self.dport, self.sport, self.sseq, self.cseq, ACK, 0)   # probe ACK, still zero
                elapsed += wait
                wait *= 2
            self.t = t_zero + reopen
            self._emit(self.s, self.c, self.dport, self.sport, self.sseq, self.cseq, ACK, self.swin)  # WindowUpdate
            return next_data
        for _ in range(probes):
            self.t += wait
            self._emit(self.c, self.s, self.sport, self.dport, self.cseq, self.sseq, ACK, self.cwin, next_data[:1])  # probe
            self.t += self.rtt / 2
            self._emit(self.s, self.c, self.dport, self.sport, self.sseq, self.cseq, ACK, 0)   # probe ACK, still zero
            wait *= 2
        self.t += rng.uniform(0.5, 3.0)
        self._emit(self.s, self.c, self.dport, self.sport, self.sseq, self.cseq, ACK, self.swin)  # WindowUpdate
        return next_data

    def retransmit_last_client_segment(self, data: bytes, delays=(0.3, 0.6, 1.2)):
        """Client RTO retransmissions of an unacknowledged request (server too busy to ACK)."""
        seg = data[:self.mss]
        seq0 = self.cseq - len(data) if len(data) <= self.mss else self.cseq - len(data)
        for d in delays:
            self.t += d
            self._emit(self.c, self.s, self.sport, self.dport, seq0, self.sseq, ACK | PSH, self.cwin, seg)
        return self

    def fast_retransmit(self, data: bytes, dup_acks=3, lost_index=1, think=0.0, lost_count=1):
        """Server->client data with one segment genuinely missing from the capture, the client
        dup-ACKing the gap, and the server fast-retransmitting it.

        This is what produces `tcp.analysis.fast_retransmission` in Wireshark, which needs a
        retransmission preceded by at least two duplicate ACKs and arriving shortly after the
        last of them. Simply resending an already-ACKed segment is a *spurious* retransmission
        and is what the earlier loss emulation produced.

        The skipped segment advances the sequence number without being emitted, so the capture
        has a real hole — receivers (and tshark) see the gap rather than being told about it.

        Every handshake in this engine negotiates SACK-Permitted (kind 4, `handshake()`'s
        `copts`/`sopts`), so a real client would describe the data it has after the hole in each
        duplicate ACK's SACK option (RFC 2018), not just repeat the left edge blind (NPM-10
        brief fix 1).
        """
        self.t += think
        if self._c_unacked:
            self._ack_from_server()
        segs = [data[i:i + self.mss] for i in range(0, len(data), self.mss)] or [b""]
        lost_index = max(0, min(lost_index, len(segs) - 1))
        # burst loss (NPM-10 brief fix 4): lost_count adjacent segments, never the very last one
        lost_count = max(1, min(lost_count, len(segs) - 1 - lost_index)) if len(segs) > 1 else 1
        lost_seq, lost_payload = None, b""
        serial = self.per_byte
        for i, chunk in enumerate(segs):
            last = i == len(segs) - 1
            flags = ACK | (PSH if last or len(chunk) < self.mss else 0)
            if lost_index <= i < lost_index + lost_count and len(segs) > 1:
                # dropped in flight: the bytes are consumed but never appear on the wire
                if lost_seq is None:
                    lost_seq = self.sseq
                lost_payload += chunk
                self.sseq += len(chunk)
                self._s_unacked += len(chunk)
                self.t += len(chunk) * serial
                continue
            self._emit(self.s, self.c, self.dport, self.sport, self.sseq, self.cseq, flags,
                       self.swin, chunk)
            self.sseq += len(chunk)
            self._s_unacked += len(chunk)
            self.t += len(chunk) * serial

        if lost_seq is not None:
            # SACK block for data already received after the hole (RFC 2018); none if the lost
            # segment was the last of the burst -- nothing has arrived past it yet to describe.
            sack_opt = b""
            if lost_index + lost_count < len(segs):
                block = struct.pack("!II", (lost_seq + len(lost_payload)) & 0xFFFFFFFF, self.sseq & 0xFFFFFFFF)   # sequence numbers wrap at 2**32
                sack_opt = struct.pack("!BB", 5, 2 + len(block)) + block
            # the ACK that establishes the hole's ack number -- not itself a Wireshark
            # "duplicate" (it has nothing to repeat yet), so the loop below always produces
            # exactly `dup_acks` flagged duplicates, never one short (NPM-10 brief fix 2).
            self.t += self.rtt / 2 * rng.uniform(0.3, 0.6)
            self._emit(self.c, self.s, self.sport, self.dport, self.cseq, lost_seq,
                       ACK, self.cwin, opts=sack_opt)
            # the receiver keeps re-ACKing the left edge of the hole: these are the duplicates
            for _ in range(max(3, dup_acks)):
                self.t += self.rtt / 2 * rng.uniform(0.4, 0.9)
                self._emit(self.c, self.s, self.sport, self.dport, self.cseq, lost_seq,
                           ACK, self.cwin, opts=sack_opt)
            # ... and the sender reacts before the retransmission timer would fire,
            # re-sending every lost segment (one burst of MSS-sized segments)
            self.t += rng.uniform(0.002, 0.012)
            r_off = 0
            while r_off < len(lost_payload):
                piece = lost_payload[r_off:r_off + self.mss]
                self._emit(self.s, self.c, self.dport, self.sport, lost_seq + r_off, self.cseq,
                           ACK | PSH, self.swin, piece)
                r_off += len(piece)
                self.t += len(piece) * serial
        self.t += self.rtt / 2 * rng.uniform(0.6, 1.2)
        self._emit(self.c, self.s, self.sport, self.dport, self.cseq, self.sseq, ACK, self.cwin)
        self._s_unacked = 0
        return self

    def tail_loss_rto(self, data: bytes, rto=0.3, think=0.0):
        """Server->client data whose last segment is lost: no later data, so no duplicate ACKs;
        the sender's retransmission timer fires (Windows min RTO ~300 ms) and the segment goes
        out again (Wireshark: RTO retransmission). NPM-10 brief fix 3."""
        self.t += think
        if self._c_unacked:
            self._ack_from_server()
        segs = [data[i:i + self.mss] for i in range(0, len(data), self.mss)] or [b""]
        if len(segs) < 2:
            return self.s2c(data)
        self.s2c(b"".join(segs[:-1]))
        lost = segs[-1]
        seq = self.sseq
        # this time the loss is downstream of the sensor: the original is captured, the client
        # never gets it, nothing follows, so no duplicate ACKs; only the timer repairs it
        self._emit(self.s, self.c, self.dport, self.sport, seq, self.cseq, ACK | PSH, self.swin, lost)
        self.sseq += len(lost)
        self._s_unacked += len(lost)
        self.t += rto * rng.uniform(1.0, 1.15)
        self._emit(self.s, self.c, self.dport, self.sport, seq, self.cseq, ACK | PSH, self.swin, lost)
        self.t += self.rtt / 2 * rng.uniform(0.6, 1.2)
        self._emit(self.c, self.s, self.sport, self.dport, self.cseq, self.sseq, ACK, self.cwin)
        self._s_unacked = 0
        return self

    def syn_only(self, retries=3):
        """Client SYNs with no answer (Windows retransmits at 1, 2, 4 s ... )."""
        c, s = self.c, self.s
        copts = struct.pack("!BBH", 2, 4, self.mss) + b"\x01\x03\x03" + bytes([self.ws_c]) + b"\x01\x01\x04\x02"
        delay = 1.0 if c.ttl == 128 else 1.0
        for _i in range(retries + 1):
            self._emit(c, s, self.sport, self.dport, self.cseq, 0, SYN, 64240, b"", copts)
            self.t += delay
            delay *= 2
        return self.pkts


# --------------------------------------------------------------- udp helper
def udp_frame(link: Link, a: Host, b: Host, sport, dport, payload: bytes, vantage: Host, ttl=None, tos=0, df=False, nocsum=False):
    dmac, smac, t = link.addr(a, b, vantage)
    pkt = ipv4(a, b, 17, udp(a, b, sport, dport, payload, nocsum), ttl=ttl if ttl is not None else t, df=df, tos=tos)
    return eth(dmac, smac, ETH_IP, pkt)


def udp_bcast(a: Host, sport, dport, payload: bytes, dst_ip=b"\xff\xff\xff\xff", dst_mac=BCAST, src_ip=None, ttl=None):
    class _D:  # minimal stand-in for a broadcast/multicast destination
        ipb = dst_ip
    class _S:
        ipb = src_ip if src_ip is not None else a.ipb
        ttl = a.ttl
        next_ipid = a.next_ipid
    s = _S()
    pkt = ipv4(s, _D, 17, udp(s, _D, sport, dport, payload), ttl=ttl if ttl is not None else a.ttl)
    return eth(dst_mac, a.mac, ETH_IP, pkt)


def mcast_mac(ip: bytes) -> bytes:
    return b"\x01\x00\x5e" + bytes([ip[1] & 0x7F]) + ip[2:]


# ------------------------------------------------------------------ pcap out
# ------------------------------------------------------- per-packet classification
# Protocol identification for the generation report. Ports are the *evidence* used to name the
# protocol, not the thing reported: a reply from 443 and a request to 443 are both HTTPS, and
# media has no port identity at all, so everything rolls up to a protocol name.
PORT_PROTOCOL = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    123: "NTP", 135: "DCE/RPC", 137: "NBNS", 138: "NBDS", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP", 389: "LDAP", 443: "HTTPS",
    445: "SMB2", 464: "Kerberos", 465: "SMTPS", 514: "Syslog", 515: "LPD",
    587: "SMTP", 623: "IPMI", 631: "IPP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "TDS", 1645: "RADIUS", 1812: "RADIUS", 1900: "SSDP",
    3000: "MCP", 3128: "HTTP-Proxy", 3268: "LDAP", 3269: "LDAPS", 3389: "RDP",
    5060: "SIP", 5061: "SIP-TLS", 5246: "CAPWAP", 5247: "CAPWAP",
    5353: "mDNS", 5355: "LLMNR", 5985: "WinRM", 5986: "WinRM",
    8080: "HTTP", 8443: "HTTPS", 9100: "JetDirect", 2049: "NFS",
    # OT / ICS. Modbus/BACnet/DNP3 are the always-on baseline process protocols (the richly-
    # metriced ones). As of 2026-10 the platform ALSO parses EtherNet/IP, Siemens S7comm, OPC UA,
    # synchrophasor (IEEE C37.118) and ICCP/TASE.2 (MMS); those are emitted by the selectable OT
    # protocol scenarios, not the baseline, so a default build is unchanged. TCP 102 carries BOTH
    # S7comm and MMS (ICCP/TASE.2) -- same transport, different upper layer -- so the label is
    # coarse; the sensor disambiguates by payload. PROFINET and IEC 61850 remain unsupported.
    502: "Modbus", 20000: "DNP3", 47808: "BACnet",
    44818: "EtherNet/IP", 2222: "EtherNet/IP-IO", 102: "S7comm", 4840: "OPC-UA",
    4712: "Synchrophasor", 4713: "Synchrophasor",
}
_KNOWN = PORT_PROTOCOL
# EtherNet/IP's 44818 is inside the Linux ephemeral range (32768-50000), so it is consulted only
# after both ports failed the table above: a client port that happens to be 44818 talking to a
# known service keeps that service's name, exactly as before the OT options existed.
_FALLBACK = {44818: "EtherNet/IP"}


def classify(frame: bytes):
    """The protocol name for one Ethernet frame.

    Runs on every packet as it is written, so it stays to slices and dict lookups — no second
    pass over a multi-gigabyte capture and no dependency on an external dissector.

    Media is the case ports cannot answer: RTP and RTCP are dynamic at both ends, so they are
    identified the way a dissector does it — version 2 in the top two bits, then the payload
    type — rather than by port.
    """
    et = frame[12:14]
    if et == b"\x08\x06":
        return "ARP"
    if et != b"\x08\x00":
        if et == b"\x86\xdd":               # additive arms: the default day emits only IPv4 and ARP
            return _classify6(frame)
        if et == b"\x81\x00" or et == b"\x88\xa8":
            return classify(frame[:12] + frame[16:])        # a VLAN tag: classify the frame it wraps
        return "Ethernet-other"
    ihl = (frame[14] & 0x0F) * 4
    proto = frame[23]
    off = 14 + ihl
    if proto == 6 or proto == 17:
        sp = (frame[off] << 8) | frame[off + 1]
        dp = (frame[off + 2] << 8) | frame[off + 3]
        name = _KNOWN.get(sp) or _KNOWN.get(dp)
        if name:
            return name
        name = _FALLBACK.get(sp) or _FALLBACK.get(dp)
        if name:
            return name
        if proto == 17:
            if len(frame) > off + 9:
                b0 = frame[off + 8]
                if b0 & 0xC0 == 0x80:             # version 2
                    # RTCP's packet type is the whole byte (200-207 = SR/RR/SDES/BYE/APP).
                    # RTP's payload type is only the low 7 bits — the top bit is the marker —
                    # so the raw value has to be tested first or every SR reads as PT 72.
                    raw = frame[off + 9]
                    if 200 <= raw <= 207:
                        return "RTCP"
                    pt = raw & 0x7F
                    if pt < 35 or 96 <= pt <= 127:
                        return "RTP"
            if dp == 4789 and len(frame) > off + 16 and frame[off + 8] == 0x08 and not (frame[20] & 0x3F or frame[21]):
                return "VXLAN"                  # I flag set, not a fragment (whose "ports" are payload bytes)
            return "UDP-other"
        return "TCP-other"
    if proto == 1:
        return "ICMP"
    if proto == 2:
        return "IGMP"
    if proto == 47:
        return "GRE"
    return "IP-proto-%d" % proto


def _classify6(frame: bytes):
    """Protocol name for an IPv6 frame (EtherType 0x86DD), after any VLAN tags are removed.

    Walks the hop-by-hop / routing / destination-options / fragment chain to the upper layer. A
    non-first fragment has no port fields and is named "IPv6-fragment". The TCP/UDP leg mirrors the
    IPv4 leg of classify(); that one stays inline and untouched because it is the pinned hot path.
    """
    if len(frame) < 54:
        return "IPv6-other"
    nh, off = frame[20], 54
    for _ in range(8):                                      # bounded: a hostile chain cannot loop us
        if nh == 0 or nh == 43 or nh == 60:
            if len(frame) < off + 2:
                return "IPv6-other"
            nh, off = frame[off], off + (frame[off + 1] + 1) * 8
        elif nh == 44:
            if len(frame) < off + 8:
                return "IPv6-other"
            if ((frame[off + 2] << 8) | frame[off + 3]) >> 3:
                return "IPv6-fragment"
            nh, off = frame[off], off + 8
        else:
            break
    if nh == 6 or nh == 17:
        if len(frame) < off + 4:
            return "IPv6-other"
        sp = (frame[off] << 8) | frame[off + 1]
        dp = (frame[off + 2] << 8) | frame[off + 3]
        name = _KNOWN.get(sp) or _KNOWN.get(dp) or _FALLBACK.get(sp) or _FALLBACK.get(dp)
        if name:
            return name
        if nh == 17:
            if dp == 4789 and len(frame) > off + 16 and frame[off + 8] == 0x08:
                return "VXLAN"
            if len(frame) > off + 9 and frame[off + 8] & 0xC0 == 0x80:
                raw = frame[off + 9]
                if 200 <= raw <= 207:
                    return "RTCP"
                pt = raw & 0x7F
                if pt < 35 or 96 <= pt <= 127:
                    return "RTP"
            return "UDP-other"
        return "TCP-other"
    if nh == 58:
        return "ICMPv6"
    if nh == 47:
        return "GRE"
    return "IPv6-proto-%d" % nh


MIN_FRAME, REC_HDR = 60, 16                 # pcap records: frames are padded to 60 bytes, each record has a 16-byte header


def record_bytes(n: int) -> int:
    """Bytes one frame of n bytes takes in the pcap, padding and record header included."""
    return max(n, MIN_FRAME) + REC_HDR


class VlanTagger:
    """Pure, RNG-free 802.1Q/802.1ad tagging for PcapWriter (opt-in; the default day never builds one).

    One VID per flow, taken from the segment the frame is seen on (the engine's vantage model):
    the MAC of a firewall leg names the segment of a routed frame, so both directions of a flow
    agree; a same-subnet frame takes its source subnet. The VID is the subnet's third octet
    (10.10.20.0/24 -> 20; an octet of 0 maps to 1), or one fixed ID. With `svid`, an 802.1ad outer tag
    (0x88A8) wraps the 0x8100 customer tag. The tag goes on the unpadded frame, so the writer pads after.
    """

    @staticmethod
    def check(scheme, vid, svid):
        """Raise ValueError for an option set the tagger cannot build (also used to validate before a link exists)."""
        if scheme not in ("subnet", "fixed"):
            raise ValueError("vlan scheme must be 'subnet' or 'fixed'")
        for v in (vid, svid):
            if v is not None and not 1 <= v <= 4094:
                raise ValueError("a VLAN ID must be 1-4094")
        if scheme == "fixed" and vid is None:
            raise ValueError("vlan scheme 'fixed' needs a vid")

    def __init__(self, link, scheme="subnet", vid=None, svid=None, hosts=()):
        self.check(scheme, vid, svid)
        from .frames6 import eth_qinq, eth_tag          # lazy: frames6 imports this module
        self._tag, self._qinq = eth_tag, eth_qinq
        self.scheme, self.vid, self.svid = scheme, vid, svid
        legs = {}                                       # firewall-leg MAC -> its subnets' VIDs
        for p, h in link.fw.items():
            legs.setdefault(h.mac, set()).add(self._octet(p[2]))
        # a router MAC that serves several subnets (the OT default gateway) cannot name the segment
        self._mac = {m: next(iter(v)) for m, v in legs.items() if len(v) == 1}
        self._amb = {m for m, v in legs.items() if len(v) > 1}
        self._pfx = {p: self._octet(p[2]) for p in link.fw}
        self._dflt = self._octet(link.fw_a.ipb[2])
        self._host = {h.mac: self._octet(h.ipb[2]) for h in hosts}    # only read for IPv6 frames (below)
        self.tagged = 0

    @staticmethod
    def _octet(o):
        return o or 1

    def vid_of(self, frame):
        if self.scheme == "fixed":
            return self.vid
        dst, src = bytes(frame[0:6]), bytes(frame[6:12])
        v = self._mac.get(src) or self._mac.get(dst)
        if v is None and frame[12:14] in (b"\x08\x00", b"\x08\x06"):
            a, b = (26, 30) if frame[12:14] == b"\x08\x00" else (28, 38)    # IPv4 src/dst, ARP spa/tpa
            ends = [bytes(frame[a:a + 3]), bytes(frame[b:b + 3])]
            for e in (ends[::-1] if src in self._amb else ends):
                v = self._pfx.get(e)
                if v:
                    break
        elif v is None and frame[12:14] == b"\x86\xdd":
            v = self._vid6(src, frame)
        return v or self._dflt

    def _vid6(self, src, frame):
        """The segment of an IPv6 frame no firewall leg names: its sender's segment by MAC (a host or a
        gateway leg that serves several subnets), else the subnet ID of a ULA source (the third octet of its
        IPv4 subnet, see frames6.ula). Link-local frames of unknown senders fall to the default."""
        v = self._host.get(src)
        if v is None and frame[22] == 0xFD:
            sid = (frame[28] << 8) | frame[29]
            v = self._octet(sid) if self._octet(sid) in self._pfx.values() else None
        return v

    def __call__(self, frame):
        self.tagged += 1
        v = self.vid_of(frame)
        return self._qinq(frame, self.svid, v) if self.svid else self._tag(frame, v)


class PcapWriter:
    def __init__(self, path, tagger=None):
        self.tagger = tagger                # optional frame -> frame transform applied before padding
        self.f = open(path, "wb", buffering=8 * 1024 * 1024)  # noqa: SIM115 handle outlives this scope
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        self.n = 0
        self.bytes = 0
        self.last_ts = 0.0
        # protocol name -> packet count, for the generation report
        self.protocols = {}

    def write(self, ts: float, frame: bytes):
        if ts < self.last_ts:
            ts = self.last_ts
        self.last_ts = ts
        if self.tagger is not None:
            frame = self.tagger(frame)      # before padding, so a short frame costs no extra bytes
        n = len(frame)
        if n < MIN_FRAME:
            frame = frame + b"\x00" * (MIN_FRAME - n)
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
        self.f.write(frame)
        self.n += 1
        self.bytes += record_bytes(len(frame))
        k = classify(frame)
        self.protocols[k] = self.protocols.get(k, 0) + 1
        return n                            # frame bytes as the engine counts them (tag included, padding not)

    def close(self):
        self.f.close()


# ------------------------------------------------------------------ scheduler

# How often Engine.run() polls its caller's should_continue(). A generate can take minutes at
# scale 1.0, so a Stop button needs a checkpoint far more often than the 200,000-packet
# progress callback — but the poll costs a modulo on every packet, so it is not free either.
# 20,000 packets is roughly a second of generation.
CANCEL_EVERY = 20_000


class Cancelled(Exception):
    """Raised out of Engine.run() when the caller's should_continue() returns False.

    Not an error: it means a human pressed Stop. It carries the packet count so the caller can
    say how far the run got before discarding the partial file.
    """

    def __init__(self, packets=0):
        super().__init__(f"generation cancelled after {packets:,} packets")
        self.packets = packets

class Engine:
    """
    Streams an arbitrary number of concurrent flows into one time-ordered
    pcap. A flow is any iterator yielding (ts, frame) with non-decreasing ts.
    Flows are registered with a start time and only materialised when the
    clock reaches them, so memory stays bounded.
    """

    def __init__(self, writer: PcapWriter, side_writer=None, side_tag_prefix=None, side_copy=True):
        self.w = writer
        self.side = side_writer            # optional second pcap for flows whose tag starts with side_tag_prefix
        self.side_tag_prefix = side_tag_prefix
        self.side_copy = side_copy         # True: side frames also go to the main file (merged day + fault-only file)
        self.wrap = None                   # opt-in (tag, frame) -> [frames] for the main file (netgen.tunnel.Tunneler)
        self.pending = []   # (start_ts, seq, factory)
        self.active = []    # (next_ts, seq, iterator, frame)
        self.seq = 0
        self.stats = {}
        self.tag_log = None   # opt-in sidecar: bytearray, one tag-id byte per MAIN-writer packet (see record_tags)
        self.tag_rec = {}     # tag -> [id, first_n, last_n, spans]; n = 1-based main-writer packet number

    def record_tags(self, gap=600.0):
        """Opt in to the per-packet tag sidecar. No random draws; the capture bytes are unchanged.
        Spans are [first_ts, last_ts, packets], gaps above `gap` seconds start a new span."""
        self.tag_log, self.tag_gap, self.tag_overflow = bytearray(), gap, False

    def _tag(self, tag, ts):
        r = self.tag_rec.get(tag)
        n = self.w.n                                   # the main writer has just taken this frame
        if r is None:
            if len(self.tag_rec) > 255:                # one byte cannot name a 257th tag: stop, never abort the build
                self.tag_log = None
                self.tag_overflow = True
                return
            r = self.tag_rec[tag] = [len(self.tag_rec), n, n, [[ts, ts, 0]]]
        sp = r[3][-1]
        if ts - sp[1] > self.tag_gap:
            sp = [ts, ts, 0]
            r[3].append(sp)
        sp[1] = ts
        sp[2] += 1
        r[2] = n
        self.tag_log.append(r[0])

    def schedule(self, ts: float, factory, tag="misc"):
        self.seq += 1
        heapq.heappush(self.pending, (ts, self.seq, factory, tag))

    def _start(self, factory, tag):
        it = iter(factory())
        self._advance(it, tag)

    def _advance(self, it, tag):
        try:
            ts, frame = next(it)
        except StopIteration:
            return
        self.seq += 1
        heapq.heappush(self.active, (ts, self.seq, it, frame, tag))

    def run(self, progress=None, should_continue=None):
        """Drain every scheduled flow into the writer in timestamp order.

        `should_continue` is an optional predicate polled every CANCEL_EVERY packets; when it
        returns False the run aborts with `Cancelled`. It emits nothing and changes no bytes —
        a cancelled run is simply a shorter one, which the caller then discards.
        """
        pending, active = self.pending, self.active
        pg = cp = 0
        while pending or active:
            if pending and (not active or pending[0][0] <= active[0][0]):
                ts, _, factory, tag = heapq.heappop(pending)
                self._start(factory, tag)
                continue
            ts, _, it, frame, tag = heapq.heappop(active)
            side = self.side is not None and self.side_tag_prefix is not None and tag.startswith(self.side_tag_prefix)
            if side:
                self.side.write(ts, frame)
            if side and not self.side_copy:
                n, k, rb = len(frame), 1, record_bytes(len(frame))
            else:
                n = k = rb = 0                        # the main writer returns the tagged length when VLAN tagging is on
                for f in (frame,) if self.wrap is None else self.wrap(tag, frame):   # a tunnel wrapper may emit several
                    m = self.w.write(ts, f)
                    if self.tag_log is not None:
                        self._tag(tag, ts)
                    n, k, rb = n + m, k + 1, rb + record_bytes(m)
            st = self.stats.get(tag)
            if st is None:
                st = self.stats[tag] = [0, 0, 0, ts, ts]
            st[0] += k
            st[1] += n
            st[2] += rb                               # pcap bytes, the same figure PcapWriter.bytes adds
            st[4] = ts                                 # [packets, frame bytes, pcap bytes, first_ts, last_ts]
            self._advance(it, tag)
            if progress and self.w.n // 200000 != pg:                 # crossing, not equality: a tunnel wrapper writes several frames at once
                pg = self.w.n // 200000
                progress(self.w)
            if should_continue is not None and self.w.n // CANCEL_EVERY != cp:
                cp = self.w.n // CANCEL_EVERY
                if not should_continue():
                    raise Cancelled(self.w.n)

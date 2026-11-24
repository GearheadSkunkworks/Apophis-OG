"""CAPWAP tunnels between the access points and the wireless controller.

Wire format follows RFC 5415 (CAPWAP) with the IEEE 802.11 binding of RFC 5416 and DTLS 1.2 (RFC 6347):

  * the AP uses ephemeral UDP source ports for the control and data channels, the controller listens on
    5246 / 5247, and the UDP checksum is computed over the IPv4 pseudo-header (RFC 768; RFC 5415 section 3.1 allows zero only where the sender chooses it);
  * control messages are sent with DSCP CS6 (section 4.5.2.1);
  * Discovery Request / Response are clear text, every other control message is inside DTLS behind the
    4-byte CAPWAP DTLS header (sections 4.1, 4.2); the data channel runs clear text (AC policy "C");
  * the WTP sends an Echo Request every EchoInterval (30 s). An unanswered Request is retransmitted
    unchanged after RetransmitInterval (3 s), the interval doubling and capped at half the EchoInterval,
    up to MaxRetransmit (5); then the DTLS session is torn down (sections 4.5.3, 4.7, 4.8);
  * the data channel keep-alive carries only a Session ID element and every header field but HLEN and the
    K bit is zero (section 4.4.1); the DataChannelDeadInterval is 60 s;
  * a rejoin waits DTLSSessionDelete (5 s), sends Discovery Requests after a random delay (one padded with
    0xFF for the PMTU probe, section 3.5), waits at least DiscoveryInterval (5 s) after the last Discovery
    Response, runs the DTLS handshake of RFC 6347 (HelloVerifyRequest cookie exchange, each flight
    retransmitted on the 1 s doubling timer), then Join, Configuration Status and Change State Event, then
    the data channel keep-alive, then Run.

A control-plane stall on the controller is a list of intervals in which it does not answer. A request that
arrives during a stall is lost, or is queued and answered when the controller recovers (the answer then
arrives late, once for every queued copy). Nothing else about the controller is modelled.

Every AP is a Life: a day of sessions with fixed ports, session id and DTLS record counters. A normal 30 s
tick is generated lazily; the ticks a stall touches are planned up front, with the rejoins, because the
client DHCP / DNS storm has to start when the AP is back.
"""
import datetime
import hashlib
import heapq
import random
import struct

from .identity import get_current, H
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CTRL_PORT, DATA_PORT = 5246, 5247
TOS_CS6 = 0xC0                       # RFC 5415 4.5.2.1
ECHO_INTERVAL = 30.0                 # 4.7.7
RETRANSMIT = (0.0, 3.0, 9.0, 21.0, 36.0, 51.0)   # 3 s doubling, capped at EchoInterval / 2 (4.5.3); MaxRetransmit 5
ECHO_DEADLINE = 66.0                 # last retransmission + 15 s
DATA_DEAD = 60.0                     # DataChannelDeadInterval (4.7.3)
DTLS_SESSION_DELETE = 5.0            # 4.7.6
DISCOVERY_INTERVAL = 5.0             # 4.7.5
MAX_DISCOVERY_INTERVAL = 20.0        # 4.7.10
MAX_DISCOVERIES = 10                 # 4.8.5
SILENT_INTERVAL = 30.0               # 4.7.13
WAIT_DTLS = 60.0                     # 4.7.15
DTLS_FLIGHT_RETX = (0.0, 1.0, 3.0, 7.0, 15.0, 31.0)   # RFC 6347 4.2.4.1: 1 s initial timer, doubled each time
MAX_FAILED_DTLS = 3                  # 4.8.6
QUEUE_P = 0.55                       # chance a request that meets a stall is queued rather than lost
CAP = 1390                           # largest DTLS payload per datagram
ECHO_PLAIN = 16                      # CAPWAP header (8) + control header (8), no elements

DTLS12, DTLS10 = 0xFEFD, 0xFEFF
SUITE = 0xC030                       # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
VENDOR_CISCO = 9                     # IANA enterprise number, Cisco Systems: the inventory has Cisco Aironet APs and an AireOS controller
CAPWAP_DTLS_HDR = b"\x01\x00\x00\x00"              # CAPWAP DTLS header: payload type 1, 24 reserved bits (4.2)


def _u(*key):
    """Deterministic uniform [0,1) from a key, so a normal tick is a pure function of its slot."""
    h = hashlib.blake2b("|".join(map(str, key)).encode(), digest_size=8).digest()
    return int.from_bytes(h, "big") / 2 ** 64


# ------------------------------------------------------------------ CAPWAP framing
def el(etype: int, value: bytes) -> bytes:
    return struct.pack("!HH", etype, len(value)) + value


def capwap_header(wbid=1, keepalive=False) -> bytes:
    """8-byte CAPWAP header (4.3): version 0, payload type 0, HLEN 2, RID 0. The keep-alive zeroes WBID (4.4.1)."""
    return bytes([0x00, 2 << 3, (wbid << 1) & 0xFE, 0x08 if keepalive else 0x00, 0, 0, 0, 0])


def control_message(mtype: int, seq: int, elems: bytes = b"") -> bytes:
    """CAPWAP header + control header (4.5.1). Message Element Length counts the bytes after the
    Sequence Number: the Flags octet plus the elements."""
    return capwap_header() + struct.pack("!IBHB", mtype, seq & 0xFF, len(elems) + 1, 0) + elems


def data_keepalive(session_id: bytes) -> bytes:
    elem = el(35, session_id)                        # Session ID (4.6.37)
    return capwap_header(wbid=0, keepalive=True) + struct.pack("!H", 2 + len(elem)) + elem


def radio_info(radio_id: int, rtype: int) -> bytes:
    return el(1048, bytes([radio_id]) + struct.pack("!I", rtype))   # RFC 5416 6.25


def discovery_request(ap, seq: int, pad: int = 0) -> bytes:
    chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"        # Cisco serials: FCW + YYWW + four characters
    serial = ("FCW%02d%02d" % (21 + int(_u(ap.name, "yy") * 3), 1 + int(_u(ap.name, "ww") * 52))
              + "".join(chars[int(_u(ap.name, "s%d" % i) * len(chars))] for i in range(4))).encode()
    board = struct.pack("!I", VENDOR_CISCO) + b"".join(
        struct.pack("!HH", t, len(v)) + v for t, v in
        ((0, b"AIR-AP3802I-B-K9"), (1, serial), (2, b"0x0158"), (3, b"B0"), (4, ap.mac)))
    descriptor = bytes([2, 2, 1]) + bytes([0x01, 0x00, 0x00]) + b"".join(     # radios, one Encryption sub-element
        struct.pack("!IHH", 0, t, len(v)) + v for t, v in ((0, b"V03"), (1, b"8.10.185.0"), (2, b"15.3(3)JPN2")))
    elems = (el(20, b"\x01") + el(38, board) + el(39, descriptor) + el(41, b"\x04") + el(44, b"\x00")
             + radio_info(1, 0x0D) + radio_info(2, 0x0A))
    if pad:
        elems += el(52, b"\xff" * pad)               # MTU Discovery Padding (4.6.32)
    return control_message(1, seq, elems)


def discovery_response(wlc, seq: int, wtp_count: int) -> bytes:
    info = b"".join(struct.pack("!IHH", 0, t, len(v)) + v for t, v in ((4, b"AIR-CTVM-K9"), (5, b"8.10.185.0")))
    descriptor = struct.pack("!HHHHBBBB", 24, 3000, wtp_count, 1000, 0x02, 2, 0, 0x02) + info
    elems = (el(1, descriptor) + el(4, H("WLC1").encode()) + radio_info(1, 0x0F) + radio_info(2, 0x0F)
             + el(10, wlc.ipb + struct.pack("!H", wtp_count)))
    return control_message(2, seq, elems)


# ------------------------------------------------------------------ DTLS 1.2 records (RFC 6347)
def dtls_record(ctype: int, ver: int, epoch: int, seq: int, frag: bytes) -> bytes:
    return struct.pack("!BHH", ctype, ver, epoch) + seq.to_bytes(6, "big") + struct.pack("!H", len(frag)) + frag


def hs_fragment(mtype: int, body: bytes, mseq: int, off: int, n: int) -> bytes:
    return (bytes([mtype]) + len(body).to_bytes(3, "big") + mseq.to_bytes(2, "big")
            + off.to_bytes(3, "big") + n.to_bytes(3, "big") + body[off:off + n])


def hs_whole(mtype: int, body: bytes, mseq: int) -> bytes:
    """The form that goes into the handshake hash (RFC 6347 4.2.6): as if unfragmented."""
    return hs_fragment(mtype, body, mseq, 0, len(body))


class Counter:
    def __init__(self):
        self.v = 0

    def next(self):
        v = self.v
        self.v += 1
        return v


def encrypted(rnd, ctype: int, epoch: int, seq: int, plain_len: int) -> bytes:
    """An epoch 1 AES-GCM record: 8-byte explicit nonce (epoch || seq), ciphertext, 16-byte tag."""
    nonce = struct.pack("!H", epoch) + seq.to_bytes(6, "big")
    return dtls_record(ctype, DTLS12, epoch, seq, nonce + rnd.randbytes(plain_len) + rnd.randbytes(16))


def pack_flight(items, cap=CAP):
    """Pack handshake messages into datagrams, fragmenting a message across datagrams when it does not fit.
    items: ('hs', mtype, body, mseq, ver, epoch, counter) | ('raw', record_bytes)."""
    out, cur = [], bytearray()

    def flush():
        nonlocal cur
        if cur:
            out.append(CAPWAP_DTLS_HDR + bytes(cur))
            cur = bytearray()

    for it in items:
        if it[0] in ("raw", "ccs"):
            rec = it[1] if it[0] == "raw" else dtls_record(20, DTLS12, 0, it[1].next(), b"\x01")   # numbered in sequence
            if len(cur) + len(rec) > cap:
                flush()
            cur += rec
            continue
        _, mtype, body, mseq, ver, epoch, ctr = it
        off, total = 0, len(body)
        while True:
            room = cap - len(cur) - 13 - 12
            if room < 80 and cur:
                flush()
                room = cap - 13 - 12
            n = min(total - off, room)
            cur += dtls_record(22, ver, epoch, ctr.next(), hs_fragment(mtype, body, mseq, off, n))
            off += n
            if off >= total:
                break
            flush()
    flush()
    return out


def cert_list(chain):
    body = b"".join(len(c).to_bytes(3, "big") + c for c in chain)
    return len(body).to_bytes(3, "big") + body


def ip_fragment(frame: bytes, mtu: int = 1500) -> list:
    """Split an Ethernet/IPv4 frame whose datagram exceeds the link MTU into RFC 791 fragments: one identification,
    MF on all but the last, offsets in 8-byte units, each header with its own length and checksum. The first
    fragment carries the UDP header; the UDP checksum was computed over the whole datagram, as RFC 768 requires.
    A datagram with DF set, or one that fits, is returned unchanged (no IP options: copy-flag handling not needed)."""
    from . import core as C
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    if len(ip) <= mtu or ip[6] & 0x40 or ihl != 20:
        return [frame]
    body, step, out = ip[ihl:], (mtu - ihl) // 8 * 8, []
    for off in range(0, len(body), step):
        chunk = body[off:off + step]
        more = off + step < len(body)
        h = bytearray(ip[:ihl])
        struct.pack_into("!HHH", h, 2, ihl + len(chunk), struct.unpack_from("!H", ip, 4)[0], (0x2000 if more else 0) | (off // 8))
        h[10:12] = b"\0\0"
        h[10:12] = struct.pack("H", C.csum(bytes(h)))
        out.append(frame[:14] + bytes(h) + chunk)
    return out


# ------------------------------------------------------------------ sessions and the controller
class Session:
    """One DTLS/CAPWAP session of an AP: fixed ports and session id, DTLS epoch 1 record counters."""

    def __init__(self, rnd, first=0.0, rec=(0, 0)):
        self.cport = rnd.randint(49152, 65535)
        self.dport = rnd.randint(49152, 65535)
        while self.dport == self.cport:
            self.dport = rnd.randint(49152, 65535)
        self.sid = rnd.randbytes(16)                 # Session ID (4.6.37): chosen by the WTP, 16 octets
        self.first = first                           # time of slot 0
        self.j0, self.j1 = 0, None                   # live slots [j0, j1)
        self.skips = []                              # slot ranges [a, b) taken by planned episodes
        self.rec = {"ap": rec[0], "ac": rec[1]}      # epoch 1 record counters when the session goes live
        self.ctr = dict(self.rec)

    def tick_time(self, j):
        return self.first + ECHO_INTERVAL * j + (_u(self.sid.hex(), j, "n") - 0.5) * 0.04

    def reply_delay(self, j):
        return 0.0008 + _u(self.sid.hex(), j, "r") * 0.0022

    def kp_offset(self, j):
        return 0.2 + _u(self.sid.hex(), j, "k") * 0.8

    def is_skipped(self, j):
        return any(a <= j < b for a, b in self.skips)

    def slot_after(self, t):
        """First slot whose tick is at or after t."""
        j = max(int((t - self.first) // ECHO_INTERVAL) - 1, 0)
        while self.tick_time(j) < t:
            j += 1
        return j


class Ac:
    """The controller's willingness to answer."""

    def __init__(self, stalls):
        self.stalls = sorted(stalls)

    def stall_end(self, t):
        for s, e in self.stalls:
            if s <= t < e:
                return e
        return None

    def reply(self, r, t, proc):
        """When the controller answers a request seen at t, or None."""
        e = self.stall_end(t)
        if e is None:
            return t + proc
        if r.random() < QUEUE_P:
            return e + proc + r.uniform(0.01, 1.5)   # the backlog is worked off when it recovers
        return None


def exchange(r, ac, t0, offsets, deadline, proc):
    """Send a request at t0 + offsets until answered. Returns (copies, replies, done)."""
    copies, replies, done = [], [], None
    for off in offsets:
        tk = t0 + off
        if tk >= deadline or (done is not None and tk >= done):
            break
        copies.append(tk)
        rt = ac.reply(r, tk, proc())
        if rt is not None:
            replies.append(rt)
            if rt <= deadline:
                done = rt if done is None else min(done, rt)
    return copies, replies, done


class Plane:
    """All AP tunnels of one capture."""

    def __init__(self, ctx, t_start, t_end):
        self.ctx = ctx
        self.t_start, self.t_end = t_start, t_end
        self.stalls, self.window = [], None
        self.dead_aps = ()
        self.homed = {}                              # ap.name -> number of clients homed on it
        self.lives = {}
        self.certs = {}
        self.live = False                            # True once a stream is running: the baseline day carries the tunnels

    def set_fault(self, stalls, window, homed, dead_aps):
        self.stalls, self.window = sorted(stalls), window
        self.homed, self.dead_aps = homed, tuple(dead_aps)
        self.lives.clear()

    def life(self, ap):
        if ap.name not in self.lives:
            self.lives[ap.name] = Life(self, ap)
        return self.lives[ap.name]

    def stream(self, ap, t_start, t_end):
        self.live = True
        return self.life(ap).stream(t_start, t_end)

    def stream_all(self, aps, t_start, t_end):
        """Every listed AP's tunnel events in [t_start, t_end), merged in time order. A scenario that finds no
        baseline stream (plane.live is False) emits its own traffic with this."""
        return heapq.merge(*(self.life(ap).stream(t_start, t_end) for ap in aps), key=lambda f: f[0])

    def wlc_chain(self):
        key, der, ca_der = self.ctx.pki.cert_for(self.ctx.h[H("WLC1")].fqdn)
        return key, [der, ca_der]

    def ap_chain(self, ap):
        """A client certificate for the AP, issued by the same CA (EKU clientAuth)."""
        if ap.name not in self.certs:
            pki = self.ctx.pki
            key = rsa.generate_private_key(65537, 2048)
            now = pki.anchor - datetime.timedelta(days=pki.LEAF_BEFORE_DAYS)
            subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "%s.%s" % (ap.name.lower(), get_current().domain))])
            cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(pki.ca_cert.subject)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=pki.LEAF_LIFE_DAYS))
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                    .sign(pki.ca_key, hashes.SHA256()))
            self.certs[ap.name] = (key, [cert.public_bytes(serialization.Encoding.DER),
                                         pki.ca_cert.public_bytes(serialization.Encoding.DER)])
        return self.certs[ap.name]


def get_plane(ctx):
    plane = getattr(ctx, "capwap_plane", None)
    if plane is None:
        from .model import T_START, T_END
        plane = ctx.capwap_plane = Plane(ctx, T_START, T_END)
    return plane


# ------------------------------------------------------------------ one AP over the day
class Life:
    def __init__(self, plane, ap):
        self.plane, self.ap = plane, ap
        self.wlc = plane.ctx.h[H("WLC1")]
        self.r = random.Random("capwap/" + ap.name)
        r = self.r
        up = r.randint(20000, 400000)                # records since the session came up; the AC has sent about as many
        self.sessions = [Session(r, plane.t_start + r.uniform(0, 30), (up, up + r.randint(0, 2500)))]
        self.events = []                             # (t, side, chan, session, kind, spec)
        self.rejoins = []                            # (teardown_t, run_t)
        self.reconnects = []                         # times a homed client re-associates
        self.dead_from = None
        self.planned = False
        self.wseq = r.randint(0, 255)                # the WTP's request counter (4.5.1.2), continues across sessions

    # --------------------------------------------------------------- planning
    def plan(self):
        if self.planned:
            return
        self.planned = True
        pl = self.plane
        if pl.window is None:
            return
        lo, hi = pl.window
        r = self.r
        ac = Ac(pl.stalls)
        sess = self.sessions[0]
        if self.ap.name in pl.dead_aps:
            self._plan_dead(sess, lo, hi, r)
            return
        j = sess.slot_after(lo - 60)
        horizon = max([e for _, e in pl.stalls] + [hi]) + 240
        while True:
            sess = self.sessions[-1]
            T = sess.tick_time(j)
            if T > horizon or T > pl.t_end - 200:
                break
            kp = T + sess.kp_offset(j)
            if not (ac.stall_end(T) or ac.stall_end(kp) or ac.stall_end(T + 0.004)):
                j += 1
                continue
            j = self._episode(sess, j, T, kp, ac, r)

    def _episode(self, sess, j, T, kp, ac, r):
        """Plan the Echo and keep-alive exchanges of slot j under a stall. Returns the next live slot."""
        proc = lambda: 0.0008 + r.random() * 0.0022
        e_copies, e_replies, e_done = exchange(r, ac, T, RETRANSMIT, T + ECHO_DEADLINE, proc)
        k_copies, k_replies, k_done = exchange(r, ac, kp, RETRANSMIT, kp + DATA_DEAD, proc)
        fails = []
        if e_done is None:
            fails.append(T + ECHO_DEADLINE)
        if k_done is None:
            fails.append(kp + DATA_DEAD)
        fail_t = min(fails) if fails else None
        horizon = fail_t if fail_t is not None else float("inf")
        for n, tk in enumerate(e_copies):
            if tk < horizon:
                self._ctrl(sess, "ap", tk, (13, ECHO_PLAIN, "new" if n == 0 else "retx"))
        for rt in e_replies:                          # a reply after the teardown reaches a closed socket
            self._ctrl(sess, "ac", rt, (14, ECHO_PLAIN, "resp"), late=rt >= horizon)
        for tk in k_copies:
            if tk < horizon:
                self._data(sess, "ap", tk)
        for rt in k_replies:
            self._data(sess, "ac", rt, late=rt >= horizon)
        if fail_t is None:
            last = max([t for t in e_copies + e_replies + k_copies + k_replies] + [T])
            nj = sess.slot_after(last + 5.0)
            sess.skips.append((j, nj))
            return nj
        sess.j1 = j                                   # the session dies in this slot
        self._rejoin(sess, fail_t, ac)
        return self.sessions[-1].j0

    def _plan_dead(self, sess, lo, hi, r):
        """A hard-failed AP: healthy until it fails, then silent. The controller notices and closes its end."""
        fail = lo + (hi - lo) * (0.20 + 0.15 * _u(self.ap.name, "fail"))
        sess.j1 = sess.slot_after(fail)
        self.dead_from = fail
        self.events.append((fail + 2 * ECHO_INTERVAL + 5 + r.uniform(0, 3), "ac", "c", sess, "alert", None))

    def _rejoin(self, old, fail_t, ac):
        r = self.r
        self.events.append((fail_t + r.uniform(0.001, 0.01), "ap", "c", old, "alert", None))   # DTLS close_notify
        t = fail_t + DTLS_SESSION_DELETE + r.uniform(0.0, 0.4)
        failed = 0
        while True:
            new = Session(r, rec=(1, 1))             # the Finished messages used epoch 1 seq 0
            t += r.uniform(2.0, 12.0)                # random delay < MaxDiscoveryInterval before the first Request
            resp, n = None, 0
            while resp is None and n < MAX_DISCOVERIES:
                self.events.append((t, "ap", "c", new, "clear", ("disc", 0)))
                rt = ac.reply(r, t, 0.0008 + r.random() * 0.004)
                n += 1
                if rt is not None:
                    self.events.append((rt, "ac", "c", new, "clear", ("discr",)))
                    resp = rt
                else:
                    t += r.uniform(2.0, MAX_DISCOVERY_INTERVAL)
            if resp is None:                         # Sulking
                t += SILENT_INTERVAL
                continue
            tp = resp + r.uniform(0.2, 0.8)          # PMTU probe: Discovery Request padded with 0xFF (3.5)
            self.events.append((tp, "ap", "c", new, "clear", ("disc", 1380)))
            rt = ac.reply(r, tp, 0.0008 + r.random() * 0.004)
            if rt is not None:
                self.events.append((rt, "ac", "c", new, "clear", ("discr",)))
                resp = rt
            hs_ev, t_done, ok = self._handshake(resp + DISCOVERY_INTERVAL + r.uniform(0.0, 1.5), ac)
            for ev in hs_ev:
                self.events.append((ev[0], ev[1], "c", new, "raw", ev[2]))
            if ok:
                break
            failed += 1
            t = t_done
            if failed >= MAX_FAILED_DTLS:
                failed = 0
                t += SILENT_INTERVAL
        # Join, Configuration Status, Change State Event: inside DTLS epoch 1, one outstanding request at a time
        t = t_done + r.uniform(0.01, 0.05)
        for mreq, lreq, mrsp, lrsp, plo, phi in (
                (3, 1180 + int(r.random() * 40), 4, 1700 + int(r.random() * 700), 0.04, 0.5),   # the Response carries the full radio and WLAN configuration: one DTLS record larger than the MTU, IP-fragmented
                (5, 330 + int(r.random() * 120), 6, 190 + int(r.random() * 120), 0.01, 0.15),
                (11, 110 + int(r.random() * 40), 12, 24, 0.01, 0.12)):
            copies, replies, done = exchange(r, ac, t, RETRANSMIT, t + ECHO_DEADLINE, lambda: plo + r.random() * (phi - plo))  # noqa: B023 closure runs inside the iteration
            for n, tk in enumerate(copies):
                self._ctrl(new, "ap", tk, (mreq, lreq, "new" if n == 0 else "retx"))
            for rt in replies:
                self._ctrl(new, "ac", rt, (mrsp, lrsp, "resp"))
            t = (done if done is not None else t + ECHO_DEADLINE) + r.uniform(0.002, 0.03)
        t_kp = t + r.uniform(0.05, 0.4)              # Data Check: the first keep-alive binds the data channel
        self._data(new, "ap", t_kp)
        self._data(new, "ac", t_kp + 0.001 + r.random() * 0.002)
        run_t = t_kp + 0.01
        new.first = run_t + ECHO_INTERVAL
        self.sessions.append(new)
        self.rejoins.append((fail_t, run_t))
        for k in range(self.plane.homed.get(self.ap.name, 0)):    # homed clients re-associate once the radios are up
            if r.random() < 0.9:
                tc = run_t + 8.0 + r.expovariate(1 / 14.0)
                self.reconnects.append((tc, k))
                self._ctrl(new, "ac", tc - 0.45 - 0.2 * r.random(), (25, 120 + int(r.random() * 40), "new"))   # Station Configuration
                self._ctrl(new, "ap", tc - 0.4 - 0.1 * r.random(), (26, 24, "resp"))

    def _ctrl(self, sess, side, t, spec, late=False):
        self.events.append((t, side, "c", sess, "dtls_late" if late else "dtls", spec))

    def _data(self, sess, side, t, late=False):
        self.events.append((t, side, "d", sess, "raw_late" if late else "raw", data_keepalive(sess.sid)))

    # --------------------------------------------------------------- DTLS handshake (RFC 6347)
    def _handshake(self, t0, ac):
        """Returns ([(t, side, datagram)], time the last server flight arrived, ok)."""
        r, pl = self.r, self.plane
        ev = []
        cs, ss = Counter(), Counter()                  # epoch 0 record numbers per direction
        srv = []                                       # (time, build) of the controller's sends, numbered in time order at the end
        cli_rand = struct.pack("!I", int(t0)) + r.randbytes(28)
        srv_rand = struct.pack("!I", int(t0)) + r.randbytes(28)
        cookie = r.randbytes(20)
        suites = (0xC030, 0xC02F, 0xC028, 0xC027, 0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F, 0x00FF)
        exts = (struct.pack("!HH", 11, 4) + bytes([3, 0, 1, 2])                       # ec_point_formats
                + struct.pack("!HHHHHH", 10, 8, 6, 23, 24, 25)                        # supported_groups
                + struct.pack("!HHH", 13, 12, 10) + struct.pack("!HHHHH", 0x0601, 0x0501, 0x0401, 0x0301, 0x0201)
                + struct.pack("!HHB", 0xFF01, 1, 0))                                  # renegotiation_info

        def client_hello(ck):
            return (struct.pack("!H", DTLS12) + cli_rand + b"\x00" + bytes([len(ck)]) + ck
                    + struct.pack("!H", 2 * len(suites)) + b"".join(struct.pack("!H", s) for s in suites)
                    + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)

        def flight(t_first, build, proc):
            """Send a flight on the 1 s doubling timer until the peer's flight comes back."""
            replies, done = [], None
            for off in DTLS_FLIGHT_RETX:
                tk = t_first + off
                if tk >= t_first + WAIT_DTLS or (done is not None and tk >= done):
                    break
                for k, d in enumerate(build()):
                    ev.append((tk + k * 0.0003, "ap", d))
                rt = ac.reply(r, tk, proc())
                if rt is not None:
                    replies.append(rt)
                    done = rt if done is None else min(done, rt)
            return sorted(replies), done      # record numbers go out in the order the answers do

        # flights 1 and 2: ClientHello without a cookie -> HelloVerifyRequest
        replies, done = flight(t0, lambda: pack_flight([("hs", 1, client_hello(b""), 0, DTLS10, 0, cs)]),
                               lambda: 0.0008 + r.random() * 0.003)
        if done is None:
            return self._flush(ev, srv), t0 + WAIT_DTLS, False
        hvr = struct.pack("!H", DTLS10) + bytes([len(cookie)]) + cookie
        for rt in replies:
            srv.append((rt, lambda: pack_flight([("hs", 3, hvr, 0, DTLS10, 0, ss)])))
        # flights 3 and 4: ClientHello with the cookie -> ServerHello, Certificate, ServerKeyExchange,
        # CertificateRequest, ServerHelloDone
        t3 = done + 0.001 + r.random() * 0.004
        wkey, wchain = pl.wlc_chain()
        spoint = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        ecparams = b"\x03" + struct.pack("!H", 23) + bytes([len(spoint)]) + spoint
        sig = wkey.sign(cli_rand + srv_rand + ecparams, padding.PKCS1v15(), hashes.SHA256())
        dn = pl.ctx.pki.ca_cert.subject.public_bytes()
        sig_algs = struct.pack("!HHHHH", 0x0601, 0x0501, 0x0401, 0x0301, 0x0201)
        ext_sh = struct.pack("!HHB", 0xFF01, 1, 0) + struct.pack("!HH", 11, 2) + bytes([1, 0])
        server_msgs = [
            (2, struct.pack("!H", DTLS12) + srv_rand + b"\x00" + struct.pack("!HB", SUITE, 0)
             + struct.pack("!H", len(ext_sh)) + ext_sh),
            (11, cert_list(wchain)),
            (12, ecparams + struct.pack("!HH", 0x0401, len(sig)) + sig),
            (13, bytes([1, 1]) + struct.pack("!H", len(sig_algs)) + sig_algs
             + struct.pack("!HH", len(dn) + 2, len(dn)) + dn),
            (14, b""),
        ]
        ch2 = client_hello(cookie)
        replies, done3 = flight(t3, lambda: pack_flight([("hs", 1, ch2, 1, DTLS10, 0, cs)]),
                                lambda: 0.05 + r.random() * 0.07)
        if done3 is None:
            return self._flush(ev, srv), t3 + WAIT_DTLS, False
        for rt in replies:
            srv.append((rt, lambda: pack_flight([("hs", mt, body, 1 + i, DTLS12, 0, ss) for i, (mt, body) in enumerate(server_msgs)])))
        # flights 5 and 6: Certificate, ClientKeyExchange, CertificateVerify, ChangeCipherSpec, Finished
        # -> ChangeCipherSpec, Finished
        t5 = done3 + 0.003 + r.uniform(0.15, 0.5)    # the AP's CPU: an ECDH key and an RSA signature
        akey, achain = pl.ap_chain(self.ap)
        cpoint = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        cert_body, cke = cert_list(achain), bytes([len(cpoint)]) + cpoint
        transcript = (hs_whole(1, ch2, 1) + b"".join(hs_whole(mt, b, 1 + i) for i, (mt, b) in enumerate(server_msgs))
                      + hs_whole(11, cert_body, 2) + hs_whole(16, cke, 3))
        cv_sig = akey.sign(transcript, padding.PKCS1v15(), hashes.SHA256())
        cv = struct.pack("!HH", 0x0401, len(cv_sig)) + cv_sig

        def f5():
            return pack_flight([("hs", 11, cert_body, 2, DTLS12, 0, cs), ("hs", 16, cke, 3, DTLS12, 0, cs),
                                ("hs", 15, cv, 4, DTLS12, 0, cs),
                                ("ccs", cs), ("raw", encrypted(r, 22, 1, 0, 24))])      # Finished: 12-byte header + 12-byte verify_data
        replies, done5 = flight(t5, f5, lambda: 0.02 + r.random() * 0.05)
        if done5 is None:
            return self._flush(ev, srv), t5 + WAIT_DTLS, False
        for rt in replies:
            srv.append((rt, lambda: pack_flight([("ccs", ss), ("raw", encrypted(r, 22, 1, 0, 24))])))
        for rt, build in sorted(srv, key=lambda x: x[0]):
            for k, d in enumerate(build()):
                ev.append((rt + k * 0.0003, "ac", d))
        ev.sort(key=lambda x: x[0])
        return ev, done5, True

    @staticmethod
    def _flush(ev, srv):
        for rt, build in sorted(srv, key=lambda x: x[0]):
            for k, d in enumerate(build()):
                ev.append((rt + k * 0.0003, "ac", d))
        ev.sort(key=lambda x: x[0])
        return ev

    # --------------------------------------------------------------- the stream
    def stream(self, t_start, t_end):
        ctx = self.plane.ctx
        self.plan()
        for sess in self.sessions:
            sess.ctr = dict(sess.rec)
        last = {"ap": None, "icmp": -9.0}             # last Discovery Request sequence (clear text); last ICMP error sent
        state = {"w": self.wseq}

        def steady():
            for sess in self.sessions:
                j = sess.j0
                while sess.j1 is None or j < sess.j1:
                    T = sess.tick_time(j)
                    if T >= t_end:
                        break
                    if T >= t_start and not sess.is_skipped(j):
                        d, kp = sess.reply_delay(j), sess.tick_time(j) + sess.kp_offset(j)
                        yield (T - 0.0001, "ap", "c", sess, "arp", None)
                        yield (T, "ap", "c", sess, "dtls", (13, ECHO_PLAIN, "new"))
                        yield (T + d, "ac", "c", sess, "dtls", (14, ECHO_PLAIN, "resp"))
                        yield (kp, "ap", "d", sess, "raw", data_keepalive(sess.sid))
                        yield (kp + d * 1.3, "ac", "d", sess, "raw", data_keepalive(sess.sid))
                    j += 1

        planned = (e for e in sorted(self.events, key=lambda e: e[0]) if t_start <= e[0] < t_end)
        for ev in heapq.merge(steady(), planned, key=lambda e: e[0]):
            yield from self._emit(ctx, ev, last, state)

    def _emit(self, ctx, ev, last, state):
        t, side, chan, sess, kind, spec = ev
        ap, wlc, r = self.ap, self.wlc, self.r
        late = kind.endswith("_late")                 # a controller reply that reaches a socket the AP has closed
        kind = kind.replace("_late", "")
        if kind == "arp":
            yield from ctx.arp_for(ap, wlc, t)
            return
        sp, dp = (sess.cport, CTRL_PORT) if chan == "c" else (sess.dport, DATA_PORT)
        tos = TOS_CS6 if chan == "c" else 0
        df = False
        if kind == "raw":
            payload = spec
        elif kind == "clear":
            if spec[0] == "disc":
                seq = state["w"] & 0xFF
                state["w"] += 1
                last["ap"] = seq
                pad = spec[1]
                if pad:                                # PMTU probe sized to a 1500-byte link, DF set (RFC 1191)
                    pad = 1472 - len(discovery_request(ap, seq, 0)) - 4
                    df = True
                payload = discovery_request(ap, seq, pad)
            else:
                payload = discovery_response(wlc, last["ap"], 1 + int(_u(sess.sid.hex(), "wtp") * 11))
        else:                                         # a record inside the DTLS session, epoch 1
            n = sess.ctr[side]
            sess.ctr[side] = n + 1
            if kind == "alert":
                payload = CAPWAP_DTLS_HDR + encrypted(r, 21, 1, n, 2)       # close_notify
            else:
                payload = CAPWAP_DTLS_HDR + encrypted(r, 23, 1, n, spec[1])
        if side == "ap":
            frame = ctx.udp(ap, wlc, sp, dp, payload, t, tos=tos, df=df)
        else:
            frame = ctx.udp(wlc, ap, dp, sp, payload, t, vantage=ap, tos=tos)
        for k, fr in enumerate(ip_fragment(frame[1])):
            yield (frame[0] + k * 0.00002, fr)
        if late and t - last["icmp"] >= 1.0:           # Linux rate-limits ICMP errors to one a second
            last["icmp"] = t
            yield self._port_unreachable(ctx, t + 0.0004, frame[1])

    def _port_unreachable(self, ctx, t, frame):
        """ICMP Destination Unreachable / Port Unreachable (RFC 792; RFC 1122 4.1.3.5) from the AP for a datagram
        that reaches a socket it has already closed. Quotes that datagram's own IP header and first 8 bytes."""
        from . import core as C
        ap, wlc = self.ap, self.wlc
        hdr = struct.pack("!BBHI", 3, 3, 0, 0)
        quoted = frame[14:14 + 28]
        icmp = hdr[:2] + struct.pack("H", C.csum(hdr + quoted)) + hdr[4:] + quoted
        dmac, smac, ttl = ctx.link.addr(ap, wlc, ap)
        return (t, C.eth(dmac, smac, C.ETH_IP, C.ipv4(ap, wlc, 1, icmp, ttl=ttl)))

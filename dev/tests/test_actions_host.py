"""Tests for the host-side campaign actions in actions/host.py (HOST worker).

Run from dev/:  python -m unittest tests.test_actions_host
Uses the same real engine context as test_actions_a (hosts, link, PKI, key log) and checks, for every action:
non-empty time-sorted packets, RFC 791 IPv4 plus TCP/UDP checksums, expected ports, key protocol fields
(interface UUIDs, opnums, LDAP operations, HTTP methods), dummy-only content, determinism, fail-soft, and, when
tshark is installed, a dissector pass with no malformed, checksum or expert-error findings.
"""
import inspect
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from netgen import protocols as P
from netgen.core import PcapWriter
from netgen.identity import H
from netgen.campaign import actions as A
from netgen.campaign import attack
from tests.test_actions_a import (make_world, ext_host, check_packet, flow_ports, _urandom_patch, TSHARK, T0)

# token -> (kwargs, ports the client must send to, destination key)
CASES = {
    "winrm_exec": (dict(command="hostname"), {(6, 5985)}, "FILE1"),
    "winrm_exec#enc": (dict(command="whoami", mode="encrypted"), {(6, 5985), (6, 88)}, "FILE1"),
    "ssh_remote_exec": (dict(sessions=2, commands=2, gap_s=3.0), {(6, 22)}, "BACKUP1"),
    "remote_schtask": (dict(delete_after_s=5.0), {(6, 445), (6, 88)}, "FILE1"),
    "svcctl_persist": (dict(), {(6, 445)}, "FILE1"),
    "gpo_modify": (dict(), {(6, 389), (6, 445)}, "DC1"),
    "privileged_group_add": (dict(), {(6, 389)}, "DC1"),
    "eventlog_clear": (dict(), {(6, 445)}, "FILE1"),
    "security_service_stop": (dict(), {(6, 445)}, "FILE1"),
    "dcsync": (dict(), {(6, 135)}, "DC1"),
    "lolbin_fetch": (dict(component="certutil"), {(6, 80), (17, 53)}, "ext"),
    "lolbin_fetch#bits": (dict(component="bitsadmin", size=20000), {(6, 80)}, "ext"),
    "lolbin_fetch#tls": (dict(component="curl", scheme="https", size=20000), {(6, 443)}, "ext"),
    "security_update_block": (dict(count=4, interval_s=20.0, mode="mixed"), {(17, 53), (6, 443)}, "ext"),
    "security_update_block#nx": (dict(count=2, interval_s=20.0, dns="nxdomain"), {(17, 53)}, "ext"),
}
TOKENS = sorted({k.split("#")[0] for k in CASES})
TLS_CASES = {"winrm_exec#enc", "lolbin_fetch#tls"}


def _src(ctx):
    return ctx.h[H("WS-009")]


def run_all():
    ctx = make_world()
    src = _src(ctx)
    ext = ext_host("198.18.20.5", "files.cdn.example.test")
    res, t = {}, T0
    for key, (kw, _ports, dk) in CASES.items():
        dst = ext if dk == "ext" else ctx.h[H(dk)]
        res[key] = A.get(key.split("#")[0]).fn(ctx, src, dst, ts=t, **kw)
        t += 600.0
    return ctx, res, src


def _blob(pk):
    return b"".join(f for _, f in pk)


class ActionsHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.load_all()
        with _urandom_patch():
            cls.ctx, cls.res, cls.src = run_all()

    # ------------------------------------------------------------------ registry
    def test_registered(self):
        specs = A.all_specs()
        for tok in TOKENS:
            self.assertIn(tok, specs)
            sp = specs[tok]
            self.assertTrue(sp.summary and sp.techniques and sp.protocols and sp.tactic and sp.title, tok)
            self.assertEqual(attack.validate_ids(sp.techniques), [], tok)
            self.assertIsNotNone(attack.tactic(sp.tactic), tok)
            self.assertTrue((sp.fn.__doc__ or sp.fn.__wrapped__.__doc__), tok)
            for name, d in sp.params.items():
                self.assertEqual(set(d), {"type", "default", "help"}, (tok, name))

    def test_tactics_covered(self):
        by = {}
        for sp in A.all_specs().values():
            by.setdefault(sp.tactic, set()).add(sp.token)
        for tac, toks in (("execution", {"winrm_exec", "ssh_remote_exec"}), ("persistence", {"remote_schtask", "svcctl_persist"}),
                          ("privilege-escalation", {"gpo_modify", "privileged_group_add"}),
                          ("stealth", {"eventlog_clear", "lolbin_fetch"}),
                          ("defense-impairment", {"security_service_stop", "security_update_block"}),
                          ("credential-access", {"dcsync"})):
            self.assertTrue(toks <= by.get(tac, set()), tac)

    def test_param_names_match_functions(self):
        for tok in TOKENS:
            sp = A.get(tok)
            sig = inspect.signature(sp.fn).parameters
            self.assertEqual(set(sp.params), {n for n in sig if n not in ("ctx", "src", "dst", "ts")}, tok)

    def test_endpoint_kinds_truthful(self):
        for tok in TOKENS:
            sp = A.get(tok)
            if tok in ("lolbin_fetch", "security_update_block"):
                self.assertEqual((sp.src, sp.dst), ("internal", "external"), tok)
            else:
                self.assertEqual((sp.src, sp.dst), ("internal", "internal"), tok)
            self.assertIn("DC1", sp.needs)

    # ------------------------------------------------------------------ packets
    def test_nonempty_valid_ipv4_sorted(self):
        for key, pk in self.res.items():
            self.assertTrue(pk, key)
            self.assertEqual([p[0] for p in pk], sorted(p[0] for p in pk), key + " not time-sorted")
            for _, f in pk:
                self.assertEqual(check_packet(f), [], key)

    def test_ports(self):
        for key, (_kw, ports, _d) in CASES.items():
            got = flow_ports(self.res[key], self.src.ip)
            self.assertTrue(ports <= got, "%s: wanted %s got %s" % (key, ports, got))

    # ------------------------------------------------------------------ protocol fields
    def test_winrm_plain_soap(self):
        b = _blob(self.res["winrm_exec"])
        for needle in (b"POST /wsman HTTP/1.1", b"Microsoft WinRM Client", b"Authorization: Basic ", b"transfer/Create",
                       b"shell/Command", b"<rsp:Command>hostname</rsp:Command>", b"shell/Receive", b"shell/Signal", b"transfer/Delete",
                       b"windows/shell/cmd"):
            self.assertIn(needle, b, needle)
        import base64
        tok = b.split(b"Authorization: Basic ")[1].split(b"\r\n")[0]
        self.assertIn(b"not-a-real-password", base64.b64decode(tok))

    def test_winrm_only_benign_commands(self):
        ctx = make_world()
        pk = A.get("winrm_exec").fn(ctx, _src(ctx), ctx.h[H("FILE1")], ts=T0, command="evil-thing")
        b = _blob(pk)
        self.assertIn(b"<rsp:Command>hostname</rsp:Command>", b)
        self.assertNotIn(b"evil-thing", b)

    def test_winrm_encrypted_shape(self):
        b = _blob(self.res["winrm_exec#enc"])
        self.assertIn(b"HTTP/1.1 401 Unauthorized", b)
        self.assertIn(b"Authorization: Negotiate ", b)
        self.assertIn(b"multipart/encrypted", b)
        self.assertNotIn(b"<rsp:Command>", b)

    def test_ssh_shape(self):
        b = _blob(self.res["ssh_remote_exec"])
        self.assertEqual(b.count(b"SSH-2.0-OpenSSH_9.6p1"), 2)

    def _rpc_has(self, key, uuid, pipe_name, opnums):
        b = _blob(self.res[key])
        self.assertIn(uuid, b, key + " interface uuid")
        self.assertIn(pipe_name.encode("utf-16-le"), b, key + " pipe name")
        found = set()
        for part in b.split(b"\x05\x00\x00\x03\x10\x00\x00\x00")[1:]:        # DCERPC request PDU headers
            if len(part) >= 16:
                found.add(struct.unpack("<H", part[14:16])[0])
        self.assertTrue(set(opnums) <= found, "%s opnums %s found %s" % (key, opnums, found))

    def test_rpc_interfaces_and_opnums(self):
        self._rpc_has("remote_schtask", P._dce_uuid("86d35949-83c9-4044-b424-db363231fd0c"), "atsvc", (1, 12, 13))
        self._rpc_has("svcctl_persist", P.SVCCTL_UUID, "svcctl", (15, 12, 0))
        self._rpc_has("eventlog_clear", P._dce_uuid("82273fdc-e32a-18c3-3f78-827929dc23ea"), "eventlog", (7, 0, 2))
        self._rpc_has("security_service_stop", P.SVCCTL_UUID, "svcctl", (15, 16, 1, 6, 0))
        self.assertNotIn(19, self._opnums("svcctl_persist"))     # CreateService only, never StartService

    def _opnums(self, key):
        out = set()
        for part in _blob(self.res[key]).split(b"\x05\x00\x00\x03\x10\x00\x00\x00")[1:]:
            if len(part) >= 16:
                out.add(struct.unpack("<H", part[14:16])[0])
        return out

    def test_ldap_modify_operations(self):
        for key, attr in (("privileged_group_add", b"member"), ("gpo_modify", b"versionNumber")):
            b = _blob(self.res[key])
            self.assertIn(b"\x66", b)
            self.assertIn(attr, b)
        gm = _blob(self.res["gpo_modify"])
        self.assertIn(b"gPLink", gm)
        self.assertIn("GPT.INI".encode("utf-16-le"), gm)
        self.assertIn("SYSVOL".encode("utf-16-le"), gm)
        pg = _blob(self.res["privileged_group_add"])
        self.assertIn(b"CN=Domain Admins,CN=Users,", pg)

    def test_dcsync_drsuapi(self):
        self.assertIn(P.DRSUAPI_UUID, _blob(self.res["dcsync"]))

    def test_lolbin_look_and_inert_body(self):
        b = _blob(self.res["lolbin_fetch"])
        self.assertIn(b"User-Agent: Microsoft-CryptoAPI/10.0", b)
        self.assertIn(b"GET /files/update.exe HTTP/1.1", b)
        self.assertIn(b"MZ\x90\x00", b)
        bits = _blob(self.res["lolbin_fetch#bits"])
        self.assertIn(b"HEAD /files/update.exe", bits)
        self.assertIn(b"Range: bytes=0-19999", bits)
        self.assertIn(b"206 Partial Content", bits)
        self.assertNotIn(b"This program cannot be run", b)     # no PE structure, just magic plus filler

    def test_update_block_never_completes(self):
        pk = self.res["security_update_block"]
        sip = bytes(int(x) for x in self.src.ip.split("."))
        syn_only = syn_ack = rst = 0
        for _, f in pk:
            if f[12:14] != b"\x08\x00" or f[23] != 6:
                continue
            ihl = (f[14] & 0xF) * 4
            flags = f[14 + ihl + 13]
            if f[26:30] == sip and flags == 0x02:
                syn_only += 1
            if f[30:34] == sip and flags & 0x12 == 0x12:
                syn_ack += 1
            if f[30:34] == sip and flags & 0x04:
                rst += 1
        self.assertEqual(syn_ack, 0)
        self.assertGreaterEqual(syn_only, 4)
        self.assertGreaterEqual(rst, 1)
        nx = self.res["security_update_block#nx"]
        self.assertNotIn((6, 443), flow_ports(nx, self.src.ip))
        self.assertIn(b"securityvendor", _blob(nx))

    # ------------------------------------------------------------------ rules
    def test_no_real_names_or_nondeterminism(self):
        import netgen.campaign.actions.host as host
        import netgen.campaign.actions._rpc as rpc
        for m in (host, rpc):
            src = inspect.getsource(m)
            for bad in ("os.urandom", "import random", "uuid4", "datetime.now", "time.time", "EXL-", "Extra" + "Hop", "Vec" + "tra"):
                self.assertNotIn(bad, src, (m.__name__, bad))

    def test_deterministic(self):
        def sig():
            with _urandom_patch():
                _c, res, _s = run_all()
            return res

        def shape(pk):
            out = []
            for _ts, f in pk:
                ihl = (f[14] & 0xF) * 4 if len(f) > 34 and f[12:14] == b"\x08\x00" else 0
                out.append((f[12:14], f[26:34] if ihl else b"", f[14 + ihl + 2:14 + ihl + 4] if ihl else b"",
                            f[14 + ihl + 13] if ihl and f[23] == 6 else 0))
            return out
        a, b = sig(), sig()
        for key in CASES:
            self.assertEqual(len(a[key]), len(b[key]), key)
            if key in TLS_CASES:
                self.assertEqual(shape(a[key]), shape(b[key]), key + " flow shape differs")
            else:
                self.assertEqual(a[key], b[key], key + " differs between two seeded runs")

    def test_fail_soft(self):
        ctx = make_world()
        src = _src(ctx)
        for tok in TOKENS:
            self.assertEqual(A.get(tok).fn(ctx, None, ctx.h[H("FILE1")], ts=T0), [], tok)
            self.assertEqual(A.get(tok).fn(ctx, src, None, ts=T0), [], tok)
        del ctx.h[H("DC1")]
        for tok in TOKENS:
            self.assertEqual(A.get(tok).fn(ctx, src, ctx.h[H("FILE1")], ts=T0), [], tok)

    def test_nameless_external_destination(self):
        ctx = make_world()
        ip_only = ext_host("198.18.22.3", "")
        for tok, kw in (("lolbin_fetch", {}), ("security_update_block", dict(count=2, interval_s=20.0))):
            pk = A.get(tok).fn(ctx, _src(ctx), ip_only, ts=T0, **kw)
            self.assertTrue(pk, tok)
            for _, f in pk:
                self.assertEqual(check_packet(f), [], tok)

    def test_other_identity(self):
        from netgen.model import set_capture_day
        ctx = make_world()
        # same actions on the default network with a different capture day
        set_capture_day("2025-11-02")
        try:
            for tok in ("remote_schtask", "gpo_modify", "winrm_exec", "lolbin_fetch"):
                dst = ext_host("198.18.20.9", "other.cdn.example.test") if tok == "lolbin_fetch" else ctx.h[H("FILE1" if tok != "gpo_modify" else "DC1")]
                pk = A.get(tok).fn(ctx, _src(ctx), dst, ts=T0 + 86400 * 200)
                self.assertTrue(pk, tok)
                for _, f in pk:
                    self.assertEqual(check_packet(f), [], tok)
        finally:
            set_capture_day("2026-03-14")

    # ------------------------------------------------------------------ dissector
    @unittest.skipUnless(os.path.exists(TSHARK), "tshark not installed")
    def test_tshark_clean(self):
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "h.pcap")
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
            base = [TSHARK, "-r", path, "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE", "-o", "ip.check_checksum:TRUE"]
            r = subprocess.run(base + ["-Y", flt, "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Protocol", "-e", "_ws.col.Info"],
                               capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stderr[-500:])
            self.assertEqual(r.stdout.strip(), "", r.stdout[:1500])
            # the dissector recognises what the actions claim to emit
            r = subprocess.run(base + ["-T", "fields", "-e", "_ws.col.Protocol"], capture_output=True, text=True, timeout=300)
            seen = set(r.stdout.split())
            for proto in ("HTTP", "SSHv2", "SMB2", "DCERPC", "LDAP", "KRB5", "DNS"):
                self.assertIn(proto, seen, proto)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

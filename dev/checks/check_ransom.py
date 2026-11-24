"""ndr-ransomware-encryption: the SMB2 traffic of the encryptor is valid and shows what a sensor needs.

Generates the scenario and reassembles every TCP stream the workstation opens to port 445, then checks per
stream: each encrypted file is opened with FILE_OPEN and DELETE access (never truncated), read and written
block for block, renamed to <name>.akira with SET_INFO FileRenameInformation on the same handle (so the new
name is visible on the wire), and no .akira name is ever created; the ransom note is written once per share in
a short SMB session of its own (a stream that holds no storm), and its text carries the NDR-08 chat code."""
import collections
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import opengenerator_build  # noqa: E402
from netgen import incidents  # noqa: E402

WS = bytes([10, 10, 10, 147])
CODE = incidents.AKIRA_CHAT_CODE.encode()


def streams(path):
    d = open(path, "rb").read()
    off, out = 24, collections.defaultdict(lambda: {"c": b"", "s": b""})
    while off < len(d):
        cl = struct.unpack("<I", d[off + 8:off + 12])[0]
        fr = d[off + 16:off + 16 + cl]
        off += 16 + cl
        if len(fr) < 54 or fr[12:14] != b"\x08\x00" or fr[23] != 6:
            continue
        ihl = (fr[14] & 15) * 4
        src, dst = fr[26:30], fr[30:34]
        tcp = fr[14 + ihl:14 + struct.unpack("!H", fr[16:18])[0]]
        sp, dp = struct.unpack("!HH", tcp[:4])
        pl = tcp[(tcp[12] >> 4) * 4:]
        if src == WS and dp == 445:
            out[(sp, dst)]["c"] += pl
        elif dst == WS and sp == 445:
            out[(dp, src)]["s"] += pl
    return out


def messages(buf):
    i = 0
    while i + 4 <= len(buf):
        n = int.from_bytes(buf[i + 1:i + 4], "big")
        yield buf[i + 4:i + 4 + n]
        i += 4 + n


def check(path):
    errs, storms, notes = collections.Counter(), 0, []
    for (_port, _srv), st in streams(path).items():
        local = collections.Counter()
        opened, creates, _handles, reads, writes, renames, flag, nw = [], {}, {}, collections.Counter(), collections.Counter(), 0, 0, 0
        resp = {}
        for m in messages(st["s"]):
            if m[:4] == b"\xfeSMB" and struct.unpack("<H", m[12:14])[0] == 5 and struct.unpack("<I", m[8:12])[0] == 0:
                resp[struct.unpack("<Q", m[24:32])[0]] = m[64 + 64:64 + 80]
        for m in messages(st["c"]):
            if m[:4] != b"\xfeSMB":
                continue
            cmd, mid = struct.unpack("<H", m[12:14])[0], struct.unpack("<Q", m[24:32])[0]
            b = m[64:]
            if cmd == 5:
                disp, no, nl = struct.unpack("<I", b[36:40])[0], struct.unpack("<H", b[44:46])[0], struct.unpack("<H", b[46:48])[0]
                name = m[no:no + nl].decode("utf-16-le")
                access = struct.unpack("<I", b[24:28])[0]
                if name.endswith(".akira"):
                    local[".akira must appear by rename, not create"] += 1
                if name and not name.endswith("txt"):
                    if disp != 1 or not access & 0x10000:
                        local["encrypted file must be opened FILE_OPEN with DELETE access"] += 1
                    opened.append(name)
                    if mid in resp:
                        creates[resp[mid]] = name
                elif name:
                    if disp == 1:
                        local["note must be created, not opened"] += 1
            elif cmd == 8:
                reads[b[16:32]] += struct.unpack("<I", b[4:8])[0]
            elif cmd == 9:
                length, fid = struct.unpack("<I", b[4:8])[0], b[16:32]
                data = b[struct.unpack("<H", b[2:4])[0] - 64:][:length]
                if fid in creates:
                    writes[fid] += length
                else:
                    nw += 1
                    flag += CODE in data
            elif cmd == 17:
                typ, cls, blen, boff = struct.unpack("<BBIH", b[2:10])
                fid, buf = b[16:32], m[boff:boff + blen]
                nl = struct.unpack("<I", buf[16:20])[0]
                new = buf[20:20 + nl].decode("utf-16-le")
                if (typ, cls) != (1, 10) or creates.get(fid) is None or new != creates[fid] + ".akira":
                    local["rename must be FileRenameInformation of the open file to <name>.akira"] += 1
                renames += 1
        if renames:
            storms += 1
            if len(set(opened)) != len(opened):
                local["each file is opened and renamed once"] += 1
            if reads != writes or any(writes[f] == 0 for f in creates):
                local["every file read and written back block for block"] += 1
            if nw or flag:
                local["the storm session must not carry the note"] += 1
        elif nw:
            notes.append((flag, nw))
        if renames or flag:
            errs.update(local)
    return errs, storms, notes


with tempfile.TemporaryDirectory() as td:
    pcap = os.path.join(td, "t.pcap")
    sys.argv = ["opengenerator_build.py", "--scale", "0.002", "--module", "ndr-ransomware-encryption", "--out", pcap,
                "--no-certs", "--no-iocs"]
    opengenerator_build.main()
    errs, storms, notes = check(pcap)
assert not errs, dict(errs)
assert storms == 2, "two shares are encrypted, saw %d storm sessions" % storms
assert notes == [(1, 1), (1, 1)], "one note write per share, in its own session, with the chat code: %s" % notes
print("ransomware SMB2 valid on the wire: %d storm sessions, renames on the open handle, note in its own session" % storms)

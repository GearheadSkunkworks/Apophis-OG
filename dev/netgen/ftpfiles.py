"""
Real content for the files moved over the smart board's FTP server.

The data channel used to carry `os.urandom()` filler. That is fine for volume and useless for
everything else: a file carved out of the capture is noise, it will not open, and nothing can
be read out of it. For a transfer to be worth anything downstream — a Files table, or a human
exporting one and double-clicking it — every byte on the wire has to BE the file: complete,
correct length, and readable.

Rules that make the files reconstructable:

* **No truncation, ever.** The declared size, the `150` response and the bytes on the data
  channel are all `len(content)`. The old code scaled sizes by the capture's `scale` factor,
  which would hand you a fragment of a PNG that no viewer will open.
* **Deterministic.** Same build, same bytes. A demo whose evidence changes每 run is not
  evidence. Nothing here uses a random source.
* **Structurally valid.** The PDFs have correct xref offsets, the PNGs have correct CRCs and
  real zlib-compressed pixel data, the tar.gz is a genuine gzip of a genuine tar. They open.

`exp0101.txt` is the deliberately-planted credential file: a list of accounts whose passwords
are "protected" with a Caesar shift, which is the point — it is trivially reversible and is
exactly the kind of thing that turns up on a forgotten anonymous FTP share.
"""
import binascii
from .identity import get_current, H
import gzip
import io as _io
import struct
import tarfile
import zlib

CAESAR_SHIFT = 7


def caesar(text: str, shift: int = CAESAR_SHIFT) -> str:
    """Rotate letters, leave everything else alone. Digits are rotated too, so the result
    looks scrambled rather than half-readable."""
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + shift) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + shift) % 26 + 65))
        elif "0" <= ch <= "9":
            out.append(chr((ord(ch) - 48 + shift) % 10 + 48))
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------- text documents
def _txt(lines) -> bytes:
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def room_schedule_csv() -> bytes:
    rows = ["room,date,start,end,organiser,subject,attendees"]
    data = [
        ("Boardroom", "08:00", "09:00", "hyamamoto", "Ops stand-up", 9),
        ("Boardroom", "09:30", "10:30", "mtanaka", "Carrier rate review", 6),
        ("Atrium", "10:00", "11:00", "abrennan", "Warehouse capacity planning", 12),
        ("Boardroom", "11:00", "12:00", "iibrahim", "Customs compliance briefing", 7),
        ("Dock Office", "13:00", "14:30", "akowalski", "Peak season readiness", 15),
        ("Boardroom", "14:00", "15:00", "coduya", "Fleet telematics rollout", 5),
        ("Atrium", "15:30", "16:30", "roduya", "Vendor QBR - LuminaBoard", 8),
        ("Boardroom", "16:00", "17:00", "dhaddad", "Incident post-mortem", 11),
    ]
    for room, a, b, who, subj, n in data:
        rows.append(f"{room},2026-03-02,{a},{b},{who},{subj},{n}")
    return _txt(rows)


def attendee_list_csv() -> bytes:
    rows = ["badge_id,surname,given_name,department,access_level,last_seen"]
    people = [
        ("NW-1042", "Yamamoto", "Hana", "Operations", "standard", "2026-03-02 07:58"),
        ("NW-1108", "Tanaka", "Mei", "Procurement", "standard", "2026-03-02 09:21"),
        ("NW-1177", "Brennan", "Aidan", "Warehouse", "standard", "2026-03-02 09:55"),
        ("NW-1203", "Ibrahim", "Imani", "Compliance", "elevated", "2026-03-02 10:47"),
        ("NW-1250", "Kowalski", "Anna", "Logistics", "standard", "2026-03-02 12:58"),
        ("NW-1288", "Oduya", "Chidi", "Fleet", "standard", "2026-03-02 13:44"),
        ("NW-1301", "Haddad", "Dana", "IT", "administrator", "2026-03-02 15:52"),
        ("NW-1355", "Reyes", "Alex", "Facilities", "standard", "2026-03-02 16:10"),
    ]
    for r in people:
        rows.append(",".join(r))
    return _txt(rows)


def display_config_xml() -> bytes:
    return _txt([
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<displayConfig product="LuminaBoard 75" firmware="4.2.11" serial="LB75-2291-0034">',
        f'  <network dhcp="true" hostname="{H("SB-03")}">',
        '    <service name="http"  port="80"   enabled="true"/>',
        '    <service name="ftp"   port="21"   enabled="true" anonymous="true"/>',
        '    <service name="mcp"   port="3000" enabled="false"/>',
        '    <service name="ssh"   port="22"   enabled="false"/>',
        '  </network>',
        '  <display brightness="72" orientation="landscape" sleepAfterMinutes="45"/>',
        f'  <calendar provider="exchange" mailbox="boardroom@{get_current().domain}"/>',
        '  <storage sharePath="/pub" writable="true" quotaMB="8192"/>',
        '</displayConfig>',
    ])


def calibration_profile_json() -> bytes:
    return _txt([
        "{",
        '  "profile": "factory-2026-01",',
        '  "panel": { "model": "LB75", "serial": "LB75-2291-0034" },',
        '  "touch": { "points": 20, "offsetX": -0.4, "offsetY": 1.1, "driftPpm": 38 },',
        '  "colour": { "gamma": 2.2, "whitePointK": 6504, "deltaE": 1.8 },',
        '  "lastCalibrated": "2026-01-19T08:40:00Z",',
        '  "calibratedBy": "svc_scan"',
        "}",
    ])


def meeting_notes_txt() -> bytes:
    return _txt([
        "Boardroom - 2 March 2026 - Peak season readiness",
        "=" * 48, "",
        "Present: A. Kowalski (chair), M. Tanaka, I. Ibrahim, D. Haddad",
        "", "1. Dock throughput",
        "   - Lane 3 scanner still dropping reads at >180 parcels/hour.",
        "   - Action: D. Haddad to raise with the integrator by 6 March.",
        "", "2. Carrier mix",
        "   - Two regional carriers over capacity from 14 March.",
        "   - Action: M. Tanaka to confirm fallback rates.",
        "", "3. Systems",
        "   - The boardroom display is being used as a file drop again.",
        "   - Nobody could say who enabled it. Action: D. Haddad to check.",
        "", "Next review: 16 March 2026, 13:00.",
    ])


# Set by flows.ftp_content for the duration of one build: maps a stock-subnet address onto the
# configured user/server /24 (Link.place). The identity until then, so the stock files are unchanged.
place = lambda ip: ip


def device_inventory_csv() -> bytes:
    rows = ["hostname,ip,role,os,firmware,last_checkin"]
    data = [
        (H("SB-01"), place("10.10.10.36"), "smartboard", "LuminaOS 4.2.9", "4.2.9", "2026-03-02 07:41"),
        (H("SB-02"), place("10.10.10.37"), "smartboard", "LuminaOS 4.3.0", "4.3.0", "2026-03-02 10:15"),
        (H("SB-03"), place("10.10.10.38"), "smartboard", "LuminaOS 4.2.11", "4.2.11", "2026-03-02 08:02"),
        (H("SB-04"), place("10.10.10.39"), "smartboard", "LuminaOS 4.2.9", "4.2.9", "2026-03-02 07:39"),
        (H("PRINT1"), place("10.10.20.70"), "print server", "Windows Server 2019", "-", "2026-03-02 06:12"),
        (H("WLC1"), place("10.10.20.50"), "wlan controller", "AireOS 8.10", "8.10.185", "2026-03-02 05:58"),
    ]
    for r in data:
        rows.append(",".join(r))
    return _txt(rows)


def syslog_latest_log() -> bytes:
    return _txt([
        f"Mar  2 07:12:04 {H('SB-03')} systemd[1]: Started LuminaBoard display agent.",
        f"Mar  2 07:12:06 {H('SB-03')} vsftpd[812]: starting, listening on 0.0.0.0:21",
        f"Mar  2 07:12:06 {H('SB-03')} vsftpd[812]: anonymous_enable=YES write_enable=YES",
        f"Mar  2 08:17:00 {H('SB-03')} vsftpd[844]: [anonymous] OK LOGIN: Client " + place("10.10.10.118"),
        f"Mar  2 09:01:14 {H('SB-03')} vsftpd[861]: [anonymous] OK LOGIN: Client 203.0.113.47",
        f"Mar  2 09:01:22 {H('SB-03')} vsftpd[861]: [anonymous] OK DOWNLOAD: /pub/exp0101.txt",
        f"Mar  2 10:44:51 {H('SB-03')} displayd[903]: calendar sync ok (boardroom@{get_current().domain})",
        f"Mar  2 12:30:18 {H('SB-03')} vsftpd[977]: [anonymous] OK UPLOAD: /pub/signage/welcome-slide.png",
        f"Mar  2 14:02:39 {H('SB-03')} kernel: [ 24881.10] usb 1-2: new high-speed USB device",
    ])


def playlist_m3u() -> bytes:
    return _txt([
        "#EXTM3U",
        f"#EXTINF:12,Welcome - {get_current().org}",
        "welcome-slide.png",
        "#EXTINF:20,Safety reminder - high-vis in all dock areas",
        "safety-notice.png",
        "#EXTINF:15,Q1 performance",
        "quarterly-summary.png",
        "#EXTINF:30,Vendor showcase - LuminaBoard",
        "room-banner.png",
    ])


def notes_txt() -> bytes:
    return _txt([
        "Reminder for facilities:",
        "  - Boardroom display stays on until 18:00 during peak season.",
        "  - The FTP drop is for signage only. Do not put schedules on it.",
        "  - If the panel shows the vendor logo at boot, call IT (ext. 4412).",
    ])


def agenda_txt() -> bytes:
    return _txt([
        "EXAMPLE LOGISTICS - QUARTERLY OPERATIONS REVIEW",
        "2026 Q1 - Boardroom - 09:00 to 12:30", "",
        "09:00  Welcome and safety brief            A. Kowalski",
        "09:15  Peak season retrospective           M. Tanaka",
        "10:00  Carrier performance and rate card   I. Ibrahim",
        "10:45  Break",
        "11:00  Warehouse automation pilot          C. Oduya",
        "11:45  IT and security update              D. Haddad",
        "12:15  Actions and close                   A. Kowalski",
    ])


def update_notice_lines():
    return [
        "LuminaBoard firmware 4.3.0 - release notice",
        "",
        "Affected devices: LB75 panels running 4.2.x",
        "Scheduled window: 10:15 local, staged per room",
        "",
        "Changes in this release:",
        "  - Adds the LuminaBoard Assistant agent service (port 3000).",
        "  - Calendar sync reliability improvements.",
        "  - Security: the anonymous file share remains enabled for",
        "    backwards compatibility. Administrators who do not use it",
        "    should disable it from Settings > Network > File sharing.",
        "",
        "Questions: support@luminaboard-cloud.net",
    ]


# ---------------------------------------------------------------- the planted credential file
def exp0101_txt() -> bytes:
    """A credential list "protected" with a Caesar shift.

    Left sitting on an anonymous share. The header is in clear so that whoever finds it knows
    what they have; the rows are shifted, which is the joke — it is reversible by hand and
    provides no protection whatsoever.
    """
    header = [
        "# exported 2026-03-02 09:01 - boardroom kiosk provisioning",
        "# DO NOT DISTRIBUTE - obfuscated (shift cipher, key below)",
        f"# key: caesar+{CAESAR_SHIFT}",
        "# format: username:password:scope",
        "",
    ]
    creds = [
        ("svc_scan", "Sc4nn3r-Pull!", "monitoring"),
        ("svc_print", "Pr1nt-Sp00l#22", "print"),
        ("svc_legacy", "L3gacy-Conn3ct", "lob-app"),
        ("kiosk", "Kiosk-Boardroom1", "display"),
        ("helpdesk1", "H3lpD3sk-Temp!", "tier1"),
        ("adm_helpdesk", "Srv1ceD3sk-2026", "tier1-admin"),
        ("boardroom", "Example-Room75", "calendar"),
        ("ftpdrop", "An0nymous-Drop", "file-share"),
        ("adm_sqlops", "Db-0ps-Rotate99", "database"),
        ("mtanaka", "Spring-2026-Mt!", "user"),
    ]
    body = [caesar(f"{u}:{p}:{s}") for u, p, s in creds]
    footer = ["", "# end of export - 10 records"]
    return _txt(header + body + footer)


# ---------------------------------------------------------------- real binary formats
def png(width: int, height: int, bands) -> bytes:
    """A genuine PNG: signature, IHDR, IDAT (zlib of filtered scanlines), IEND, CRCs correct."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", binascii.crc32(tag + data) & 0xFFFFFFFF))

    raw = bytearray()
    n = len(bands)
    for y in range(height):
        raw.append(0)                                  # filter type 0 (None)
        r, g, b = bands[min(n - 1, y * n // height)]
        for x in range(width):
            k = (x * 255) // max(1, width - 1)
            raw += bytes((min(255, (r * k) // 255 + 20), min(255, (g * k) // 255 + 20),
                          min(255, (b * k) // 255 + 20)))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)   # 8-bit truecolour
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 6)) + chunk(b"IEND", b""))


def png_sized(size: int) -> bytes:
    """A genuine PNG of exactly `size` bytes (>= 1 KB): a small gradient logo, padded with a valid tEXt chunk
    placed before IEND, so every chunk CRC is correct and a dissector decodes it. Deterministic."""
    base = png(96, 40, [(0, 170, 239), (28, 31, 99)])
    iend = base[-12:]
    head = base[:-12]
    pad = max(0, size - len(head) - len(iend) - 12 - len(b"Comment\0"))
    unit = ("%s Labs intranet logo. " % get_current().name).encode()
    text = b"Comment\0" + (unit * (pad // len(unit) + 1))[:pad]
    tag = b"tEXt"
    chunk = struct.pack(">I", len(text)) + tag + text + struct.pack(">I", binascii.crc32(tag + text) & 0xFFFFFFFF)
    return head + chunk + iend


def pdf(title: str, lines) -> bytes:
    """A minimal but valid PDF with a real xref table, so viewers open it."""
    def esc(t):
        return t.replace("\\\\", "\\\\\\\\").replace("(", "\\\\(").replace(")", "\\\\)")

    content = ["BT", "/F1 16 Tf", "72 720 Td", f"({esc(title)}) Tj", "/F1 11 Tf", "0 -28 Td"]
    for ln in lines:
        content.append(f"({esc(ln)}) Tj")
        content.append("0 -15 Td")
    content.append("ET")
    stream = "\n".join(content).encode("latin-1", "replace")

    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n"
            "%%EOF\n").encode()
    return bytes(out)


def targz(members) -> bytes:
    """A genuine gzip-compressed tar. Members are (name, bytes).

    The gzip *header* carries its own mtime, and `tarfile.open(mode="w:gz")` stamps it with
    the current time — so pinning the tar member mtimes is not enough and every build produced
    a different archive. Wrapping an explicit GzipFile with mtime=0 is what actually makes this
    reproducible; the byte-for-byte carve test caught it.
    """
    raw = _io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1772409600
            info.mode = 0o644
            tf.addfile(info, _io.BytesIO(data))
    out = _io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=6, mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def firmware_bin() -> bytes:
    """A firmware image: readable ASCII header and strings, padded to a plausible length.

    Not a real executable — but `strings` on it tells you exactly what it is, which is what
    matters for someone who exported it from a capture and wants to know what left the device.

    CRP-04 brief fix 4: a real firmware image for a device like this runs into the low
    megabytes, not a few KB -- the pad below is sized for that (~2 MiB total)."""
    head = _txt([
        "LUMINABOARD-FIRMWARE",
        "product=LB75", "version=4.2.11", "build=20260119.2",
        "serial=LB75-2291-0034", "region=NA",
        "signature=UNSIGNED-DEVELOPMENT-IMAGE",
        "notice=Recovery image. Do not distribute outside Lumina Display Systems.",
        "",
    ])
    sections = _txt([f"section {n} offset=0x{(n * 4096):06x} name={s}"
                     for n, s in enumerate(["bootloader", "kernel", "rootfs", "assets",
                                            "calendar-agent", "ftpd", "recovery"], start=1)])
    pad = bytes(((i * 37 + 11) % 251 for i in range(2 * 1024 * 1024)))
    return head + sections + pad


def crash_dump(n: int) -> bytes:
    """n bytes that look like a device memory/core dump: deterministic (no random source,
    same rule as everything else here) but not periodic within gzip's 32 KiB window, so it
    does not collapse to almost nothing the way a simple linear-congruential pad would -- the
    support bundle (CRP-04 brief fix 4) needs a believable *compressed* size on the wire, and a
    trivially-compressible filler would silently undo the point of making it bigger."""
    out = bytearray(n)
    state = 0x2545F4914F6CDD1D
    for i in range(n):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (state >> 56) & 0xFF
    return bytes(out)

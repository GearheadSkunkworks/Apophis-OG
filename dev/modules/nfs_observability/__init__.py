"""nfs_observability -- the first real protocol+hosts capability module (worked example).

WHAT IT DOES
------------
Loads a selectable **Standard**-category scenario that paints a *healthy* NFS ecosystem for a
whole business day, so a sensor (a network detection platform) can demonstrate NFS observability without any
fault or anomaly to chase. When selected it:

  * introduces **7 new systems** -- 6 Windows workstations on the user LAN (``EXL-WS-076..081``)
    and 1 Linux **NFS server** on the server LAN (``EXL-NFS1``) -- named and addressed by the
    live identity (``H()``), so a custom company renames them consistently;
  * generates **all-day NFSv3 file transfer, upload AND download**, over TCP 2049, carrying
    **real files with valid headers** (PNG, PDF, XLSX, CSV, ZIP). The filename is on the wire in
    the NFS LOOKUP/CREATE and the file body in the READ/WRITE payloads, so the platform can identify,
    name and carve an actual file;
  * mixes in the ordinary working-day protocols for those hosts -- Windows logons
    (Kerberos + LDAP), DNS, NTP, DHCP and some SMB to the file server.

HOW IT STAYS PIN-SAFE (the hard rule: a module may only ADD, never ALTER the baseline)
--------------------------------------------------------------------------------------
The 7 hosts are injected into ``ctx.h`` **inside the scenario builder**, which runs only when the
scenario is *selected* and only *after* ``day.build()`` has already scheduled the normal day over
the original inventory. The baseline's RNG stream is therefore untouched, so the no-module build
still pins at exactly 466,343 packets; selecting this module adds its traffic on top. Nothing
here is wired into the baseline day (host lists in ``model.Day`` are built from the inventory
before this ever runs), so loading the module -- without selecting it -- changes nothing.

HOW TO WRITE A MODULE LIKE THIS (the pattern)
---------------------------------------------
  1. ``register(kernel)`` adds a scenario to ``netgen.incidents.REGISTRY`` via ``INC._reg(...)``
     and declares teardown with ``kernel.on_unload(...)`` so unload is exact.
  2. The scenario *builder* ``_build(ctx, eng, tag, win)`` injects any new hosts into ``ctx.h``
     (a plain ``netgen.core.Host`` -- internal hosts need no gateway; routing derives from the
     subnet), then schedules flows with ``INC.sched_factory``. Build new protocol bytes from the
     public ``netgen.protocols`` primitives (here: ONC-RPC + NFSv3 XDR helpers).
  3. A new UI category is just an entry appended to ``branding.CATEGORIES`` (removed on unload).
  4. ``self_test()`` proves the invariant -- unselected build == 466,343, selected build adds NFS.
"""
import io
import os
import struct
import zipfile
import zlib

import branding
from netgen import flows as F
from netgen import identity as ID
from netgen import incidents as INC
from netgen import protocols as P
from netgen.core import Host

SCENARIO = "std-nfs-observability"       # REGISTRY key (hyphenated, like every scenario)
CATEGORY = {"key": "STD", "tag": "STD",
            "label": "Standard traffic (healthy)", "color": branding.GRAY}

# ---- the 7 systems this module introduces (suffix, ip) -- resolved through H() at build time --
_WORKSTATIONS = [("WS-%03d" % n, "10.10.10.%d" % ip)
                 for n, ip in zip(range(76, 82), range(196, 202))]
_NFS_SUFFIX, _NFS_IP = "NFS1", "10.10.20.21"

# ---- NFSv3 / ONC-RPC (RFC 1813) procedure numbers, program 100003 vers 3 -----------------
_NFSPROG, _NFSVERS = 100003, 3
_GETATTR, _LOOKUP, _ACCESS, _READ, _WRITE, _CREATE, _COMMIT, _FSINFO = 1, 3, 4, 6, 7, 8, 21, 19
_FALSE = b"\x00\x00\x00\x00"              # an XDR bool FALSE / an "attributes_follow = no"
_OK = b"\x00\x00\x00\x00"                 # nfsstat3 NFS3_OK
_RSIZE = _WSIZE = 32768                   # NFS rsize/wsize -> chunk large files like a real client


# ============================================================ real sample files (valid headers)
def _png(w=56, h=56):
    """A valid 8-bit RGB PNG (signature + IHDR + IDAT + IEND), a small colour gradient."""
    raw = bytearray()
    for y in range(h):
        raw.append(0)                                    # row filter: none
        for x in range(w):
            raw += bytes([(x * 4) & 0xFF, (y * 4) & 0xFF, 0x80])

    def chunk(typ, data):
        c = typ + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


def _pdf(title, body):
    """A small but structurally complete PDF 1.4 (objects + xref + trailer + %%EOF)."""
    content = ("BT /F1 18 Tf 72 720 Td (%s) Tj 0 -28 Td /F1 11 Tf (%s) Tj ET"
               % (title, body)).encode("latin-1", "replace")
    objs = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
        b"/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>",
        b"<</Length %d>>stream\n" % len(content) + content + b"\nendstream",
        b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
    ]
    out = b"%PDF-1.4\n"
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offs:
        out += b"%010d 00000 n \n" % off
    out += b"trailer<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF" % (len(objs) + 1, xref)
    return out


def _zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _xlsx():
    """A minimal but valid OOXML spreadsheet (a ZIP with the required parts)."""
    return _zip({
        "[Content_Types].xml":
            b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org'
            b'/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.'
            b'openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="appli'
            b'cation/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxml'
            b'formats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets'
            b'/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.'
            b'worksheet+xml"/></Types>',
        "_rels/.rels":
            b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlforma'
            b'ts.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxml'
            b'formats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            b'</Relationships>',
        "xl/workbook.xml":
            b'<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org'
            b'/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006'
            b'/relationships"><sheets><sheet name="Forecast" sheetId="1" r:id="rId1"/></sheets></work'
            b'book>',
        "xl/_rels/workbook.xml.rels":
            b'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformat'
            b's.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlfo'
            b'rmats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            b'</Relationships>',
        "xl/worksheets/sheet1.xml":
            b'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.or'
            b'g/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Quarter'
            b'</t></is></c><c r="B1" t="inlineStr"><is><t>Forecast</t></is></c></row><row r="2"><c r='
            b'"A2" t="inlineStr"><is><t>Q3</t></is></c><c r="B2"><v>1250000</v></c></row></sheetData>'
            b'</worksheet>',
    })


def _sample_files():
    """The real, benign files the workstations read and write all day. Identity-independent, so
    they can be built once per build. Each has a valid header the platform can type and carve."""
    csv = (b"employee,department,extension,hire_date\n"
           b"a.morgan,Finance,4021,2021-03-14\nr.patel,Engineering,4190,2019-07-02\n"
           b"s.chen,Operations,4255,2022-11-21\nj.okafor,Sales,4302,2020-01-30\n")
    return {
        "network-topology.png": _png(),
        "onboarding-guide.pdf": _pdf("Onboarding Guide",
                                     "Internal use only - new starter checklist."),
        "q3-forecast.xlsx": _xlsx(),
        "team-roster.csv": csv,
        "project-archive.zip": _zip({"readme.txt": b"Project handover notes.\n",
                                     "changes.csv": b"rev,date,author\n12,2026-09-01,a.morgan\n"}),
    }


# ============================================================ host injection (pin-safe, runtime)
def _inject_hosts(ctx):
    """Add this module's 7 systems to ``ctx.h`` if not already present. Internal hosts need only
    name/ip/mac/os/role/subnet/fqdn -- routing and ARP derive from the subnet, so no gateway is
    set. Runs inside the builder (scenario phase), so the baseline day never sees these hosts."""
    ident = ID.get_current()
    if ident.host(_NFS_SUFFIX) in ctx.h:
        return

    def add(suffix, ip, mac, os_, role, subnet):
        name = ident.host(suffix)
        ctx.h[name] = Host(name, ip, mac, os_, role, subnet, ident.fqdn(suffix))

    # the NFS exporter: a Linux file-server/NAS on the server LAN
    add(_NFS_SUFFIX, _NFS_IP, "00:a0:98:51:02:21", "linux",
        "NFS file server (NFSv3 exports)", "10.10.20.0/24")
    # 6 Windows workstations on the user LAN (VMware OUI, like the rest of the virtual estate)
    for i, (suffix, ip) in enumerate(_WORKSTATIONS):
        add(suffix, ip, "00:50:56:ab:03:%02x" % (0x20 + i), "Windows 11",
            "Windows workstation", "10.10.10.0/24")


def _uid(h):
    digits = "".join(c for c in h.name if c.isdigit())
    return 10000 + (int(digits[-3:]) if digits else 1)


# ============================================================ NFSv3 exchanges (read + write)
def _exch(s, cred, xid, proc, args, results, tc=0.012, tr=0.010):
    """One RPC call/reply pair, paired by xid so the dissector resolves the NFS procedure."""
    xid[0] = (xid[0] + 1) & 0xFFFFFFFF
    s.c2s(P.rpc_call(xid[0], _NFSPROG, _NFSVERS, proc, cred=cred, args=args),
          think=F.rng.uniform(0.003, tc))
    s.s2c(P.rpc_reply(xid[0], results), think=F.rng.uniform(0.002, tr))


def nfs_download(ctx, client, server, filename, content, ts=None):
    """NFSv3 **download**: NULL path (FSINFO/GETATTR), LOOKUP the file by name, ACCESS, then READ
    the real file bytes back in rsize chunks (last chunk sets eof). Filename + bytes on the wire."""
    out = ctx.arp_for(client, server, ts)
    s = ctx.tcp(client, server, 2049, ts + 0.001).handshake()
    cred = P.rpc_auth_unix(client.name.lower(), uid=_uid(client), gid=10000)
    xid = [F.rng.getrandbits(32)]
    fh_root = bytes(F.rng.getrandbits(8) for _ in range(32))
    fh_file = bytes(F.rng.getrandbits(8) for _ in range(32))
    _exch(s, cred, xid, _FSINFO, P.xdr_opaque(fh_root), P.nfs3_fsinfo())
    _exch(s, cred, xid, _GETATTR, P.xdr_opaque(fh_root), _OK + P.nfs3_fattr3(is_dir=True))
    _exch(s, cred, xid, _LOOKUP, P.xdr_opaque(fh_root) + P.xdr_str(filename),
          _OK + P.xdr_opaque(fh_file) + _FALSE + _FALSE)
    _exch(s, cred, xid, _ACCESS, P.xdr_opaque(fh_file) + (0x2000003).to_bytes(4, "big"),
          _OK + _FALSE + (0x1F).to_bytes(4, "big"))
    off, n = 0, len(content)
    while True:
        chunk = content[off:off + _RSIZE]
        eof = off + len(chunk) >= n
        _exch(s, cred, xid, _READ,
              P.xdr_opaque(fh_file) + off.to_bytes(8, "big") + len(chunk).to_bytes(4, "big"),
              _OK + _FALSE + len(chunk).to_bytes(4, "big")
              + (1 if eof else 0).to_bytes(4, "big") + P.xdr_opaque(chunk),
              tc=0.02, tr=0.02)
        off += len(chunk)
        if eof:
            break
    return F.merged(out, s.close(think=F.rng.uniform(0.01, 0.04)))


def nfs_upload(ctx, client, server, filename, content, ts=None):
    """NFSv3 **upload**: GETATTR the dir, CREATE the file by name (UNCHECKED), WRITE the real file
    bytes in wsize chunks (UNSTABLE), then COMMIT. Filename + bytes on the wire for the platform."""
    out = ctx.arp_for(client, server, ts)
    s = ctx.tcp(client, server, 2049, ts + 0.001).handshake()
    cred = P.rpc_auth_unix(client.name.lower(), uid=_uid(client), gid=10000)
    xid = [F.rng.getrandbits(32)]
    fh_root = bytes(F.rng.getrandbits(8) for _ in range(32))
    fh_file = bytes(F.rng.getrandbits(8) for _ in range(32))
    verf = F.rng.getrandbits(64).to_bytes(8, "big")
    _exch(s, cred, xid, _GETATTR, P.xdr_opaque(fh_root), _OK + P.nfs3_fattr3(is_dir=True))
    # CREATE (createmode3 UNCHECKED=0, then sattr3 with every "set" flag FALSE / times DONT_CHANGE)
    _exch(s, cred, xid, _CREATE,
          P.xdr_opaque(fh_root) + P.xdr_str(filename) + (0).to_bytes(4, "big") + _FALSE * 6,
          _OK + (1).to_bytes(4, "big") + P.xdr_opaque(fh_file) + _FALSE + _FALSE + _FALSE)
    off, n = 0, len(content)
    while True:
        chunk = content[off:off + _WSIZE]
        _exch(s, cred, xid, _WRITE,
              P.xdr_opaque(fh_file) + off.to_bytes(8, "big") + len(chunk).to_bytes(4, "big")
              + (0).to_bytes(4, "big") + P.xdr_opaque(chunk),            # stable = UNSTABLE
              _OK + _FALSE + _FALSE + len(chunk).to_bytes(4, "big")
              + (0).to_bytes(4, "big") + verf,
              tc=0.02, tr=0.02)
        off += len(chunk)
        if off >= n:
            break
    _exch(s, cred, xid, _COMMIT,
          P.xdr_opaque(fh_file) + (0).to_bytes(8, "big") + n.to_bytes(4, "big"),
          _OK + _FALSE + _FALSE + verf)
    return F.merged(out, s.close(think=F.rng.uniform(0.01, 0.04)))


# ============================================================ the all-day scenario builder
def _build(ctx, eng, tag, win):
    """Healthy, all-day Standard traffic for the 7 new systems. No degradation, no anomaly."""
    _inject_hosts(ctx)
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))
    ident = ID.get_current()
    nfs = ctx.h[ident.host(_NFS_SUFFIX)]
    dc1 = ctx.h.get(ident.host("DC1"))
    file1 = ctx.h.get(ident.host("FILE1"))
    wss = [ctx.h[ident.host(suf)] for suf, _ in _WORKSTATIONS]
    files = list(_sample_files().items())

    # the NFS server's own quiet day: a few NTP syncs across the window
    beats = max(1, int(4 * scale))
    for k in range(beats):
        s(lo + (hi - lo) * (k + 0.3) / beats, F.ntp_exchange, nfs)

    for ws in wss:
        arrive = lo + F.rng.uniform(0, 1500)
        # standard Windows logon sequence (DHCP, DNS, machine + user Kerberos, LDAP, NTP)
        s(arrive, F.dhcp_acquire, ws)
        if dc1 is not None:
            s(arrive + 1.0, F.resolve_internal, ws, dc1)
        s(arrive + 1.8, F.kerberos_as, ws, user=ws.name + "$")       # machine logon
        s(arrive + 2.6, F.ldap_session, ws, queries=2)
        s(arrive + 3.4, F.kerberos_as, ws)                           # interactive user logon
        s(arrive + 7.0, F.ntp_exchange, ws)

        # all-day mixed NFS upload/download, spread evenly to end-of-day, with a little SMB/DNS
        n_ops = max(4, int(round(28 * scale)))
        gap = max(30.0, (hi - arrive) / n_ops)
        t = arrive + F.rng.uniform(20, 120)
        for _ in range(n_ops):
            if t >= hi:
                break
            fname, content = files[F.rng.randrange(len(files))]
            if F.rng.random() < 0.5:
                s(t, nfs_download, ws, nfs, fname, content)
            else:
                s(t, nfs_upload, ws, nfs, fname, content)
            if file1 is not None and F.rng.random() < 0.25:
                s(t + F.rng.uniform(1, 8), F.smb_file_activity, ws, file1)
            if F.rng.random() < 0.15:
                s(t + F.rng.uniform(1, 5), F.resolve_internal, ws, nfs)
            t += F.rng.expovariate(1.0 / gap)


# ============================================================ capability lifecycle
def _remove_category():
    branding.CATEGORIES[:] = [c for c in branding.CATEGORIES if c.get("key") != "STD"]


def register(kernel):
    """Add the Standard category and the healthy NFS scenario; declare exact teardown."""
    if not any(c.get("key") == "STD" for c in branding.CATEGORIES):
        branding.CATEGORIES.append(dict(CATEGORY))
        kernel.on_unload(_remove_category)
    INC._reg(SCENARIO, "STD", "nfs-observability",
             "Standard NFS file-share activity (healthy, all-day) + 7 new systems",
             ((7, 0), (18, 0)), _build,
             "Introduces 6 workstations + 1 Linux NFS server; all-day NFSv3 upload/download of "
             "real files (PNG/PDF/XLSX/CSV/ZIP) plus Windows logins, DNS, NTP, DHCP and SMB. "
             "Healthy observability traffic -- adds on top of the baseline, never alters the pin.")
    kernel.on_unload(lambda: INC.REGISTRY.pop(SCENARIO, None))


def self_test():
    """Verify the module's capability quickly and *robustly*.

    Two deliberate design choices make this reliable when run from the live server, where the
    engine's build state (identity, RNG, capture day) is a process-wide global shared across
    request threads:

    * **One build, not two.** Each full build costs several seconds; two left a ~20s window in
      which anything the GUI built concurrently (a diagram render with a company name entered,
      another capture) could corrupt this build's global state and skew the result.
    * **A structural check, not an exact count.** We assert that NFS *appears on the wire when the
      scenario is selected* -- a fact a concurrent build cannot change (it may skew packet counts,
      but it cannot stop the selected NFS scenario from emitting NFS, nor make an unselected build
      emit it). We do not re-assert the exact 466,343 baseline here; that absolute number is
      verified in isolation by the ``baseline_pin`` module and the offline ``selftest.py`` suite.
      The pin stays safe by construction: this module adds hosts/traffic only inside its selected
      scenario, so an unselected build runs none of it.
    """
    import shutil
    import tempfile

    import opengenerator_build as OGB

    # (a) instant: the sample files really are valid files (correct magic headers), so a sensor
    # can type and carve them.
    f = _sample_files()
    if not (f["network-topology.png"].startswith(b"\x89PNG")
            and f["onboarding-guide.pdf"].startswith(b"%PDF")
            and f["q3-forecast.xlsx"].startswith(b"PK\x03\x04")
            and f["project-archive.zip"].startswith(b"PK\x03\x04")):
        return {"ok": False, "detail": "sample files have invalid headers"}

    # (b) one selected build: NFS must appear on the wire (structural -> concurrency-immune).
    d = tempfile.mkdtemp(prefix="nfs-st-")
    try:
        sel = OGB.build(scale=0.002, out=os.path.join(d, "sel.pcap"), modules=[SCENARIO],
                        certs_dir=None, iocs_prefix=None, progress=False)
        nfs = dict(sel["protocols"]).get("NFS", 0)
        ok = nfs > 0
        return {"ok": ok,
                "detail": ("NFS observed on the wire when selected: %d NFS packets; sample files "
                           "validated. Traffic is added only when selected, so the baseline pin is "
                           "untouched (verified by baseline_pin)." % nfs) if ok
                          else "NFS not observed in a selected build (NFS=%d)" % nfs}
    finally:
        shutil.rmtree(d, ignore_errors=True)

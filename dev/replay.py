#!/usr/bin/env python3
"""
replay.py — tcpreplay integration for the OpenGenerator GUI.

Replays a generated capture onto a network interface so a the platform sensor sees it.
Everything here is stdlib-only; `tcpreplay` itself is an *external* dependency that the
user installs (Homebrew), not something the .app bundles.

Three jobs:

1. **Preflight** (`preflight`) — find `tcpreplay`, read its version, enumerate interfaces,
   validate the pcap. Returns a structured report so the UI can say exactly what is
   missing and how to install it, instead of failing at launch time.

2. **Indexing** (`index_pcap`) — walk the pcap's record headers to get the exact packet
   count, byte total, capture duration and a coarse packet->timestamp map. tcpreplay
   reports *packets sent*, so an exact total is what turns that into a real percentage
   (file size overstates it: it includes the 24-byte file header and 16 bytes per record).
   The timestamp map is what lets the UI show the position in the captured business day.

3. **Running** (`start`, `status`, `stop`) — launch tcpreplay with root privileges, tail its
   `--stats` output, and expose live progress.

Privilege model (deliberate): raw packet injection needs root, so the password prompt is
macOS's own native authorization dialog, raised via
`osascript -e 'do shell script ... with administrator privileges'`. The password is typed
into the OS dialog and handed straight to authorizationd — it never travels through the
web UI, the HTTP API, or this process's memory. There is intentionally no password field
in the GUI, and nothing here ever reads, stores or logs a credential.

Stopping without a second prompt: the privileged shell starts tcpreplay *and* a small
watcher that polls for a stop-file in the run's temp dir. Creating that file is
unprivileged, so "Stop" works without re-authenticating.
"""
import copy
import hashlib
import ipaddress
import json
import math
import mmap
import os
import re
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata

import settings_store

# ---------------------------------------------------------------------------
# tool discovery
# ---------------------------------------------------------------------------

# A .app launched from Finder inherits a minimal PATH -- typically just /usr/bin:/bin:
# /usr/sbin:/sbin -- so `which` alone finds nothing that a package manager installed. These
# are the places a macOS package manager actually puts things.
#
# Built at CALL time, not import time: HOMEBREW_PREFIX and $HOME come from the environment,
# and this module is imported inside a frozen bundle whose environment is not the shell's.
def _search_paths():
    out = []

    def add(*dirs):
        for d in dirs:
            if d and d not in out:
                out.append(d)

    # An explicitly configured Homebrew wins: it is the only one that can sit anywhere.
    prefix = os.environ.get("HOMEBREW_PREFIX")
    if prefix:
        add(os.path.join(prefix, "bin"), os.path.join(prefix, "sbin"))
    add("/opt/homebrew/bin", "/opt/homebrew/sbin")      # Homebrew, Apple Silicon
    add("/usr/local/bin", "/usr/local/sbin")            # Homebrew, Intel
    add("/opt/local/bin", "/opt/local/sbin")            # MacPorts
    add("/opt/pkg/bin", "/opt/pkg/sbin")                # pkgsrc
    add("/run/current-system/sw/bin")                   # Nix, system profile
    home = os.path.expanduser("~")
    add(os.path.join(home, ".nix-profile", "bin"),      # Nix, per-user profile
        os.path.join(home, ".local", "bin"),
        os.path.join(home, "bin"))
    add("/usr/bin", "/bin", "/usr/sbin", "/sbin")       # the system, last
    return out


# Tools that come from the same package, whichever manager installed it.
_PACKAGED = {"tcpreplay": "tcpreplay", "tcprewrite": "tcpreplay", "tcpreplay-edit": "tcpreplay"}


def find_tool(name):
    """Locate an executable: PATH first, then every package-manager location we know of."""
    from shutil import which
    p = which(name)
    if p:
        return p
    for d in _search_paths():
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


_MACHO_MAGIC = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
_RPATH_RE = re.compile(r"^\s+path (.+) \(offset \d+\)$")


def parse_dylib_refs(otool_l, otool_rpaths, here):
    """Candidate files for every non-system library a Mach-O binary loads, from `otool -L` and the LC_RPATH lines of `otool -l`.
    /usr/lib and /System are SIP-protected and skipped; @loader_path and @executable_path resolve beside the binary (`here`);
    @rpath expands to every rpath entry (dyld takes the first that exists, so each directory counts). Pure."""
    def at(p):
        for pre in ("@loader_path", "@executable_path"):
            if p == pre or p.startswith(pre + "/"):
                return os.path.normpath(here + p[len(pre):])
        return p
    rpaths = [at(m.group(1)) for m in map(_RPATH_RE.match, otool_rpaths.splitlines()) if m]
    out = []
    for line in otool_l.splitlines()[1:]:
        dep = line.strip().split(" (compatibility", 1)[0].strip()
        if not dep or dep.startswith(("/usr/lib/", "/System/")):
            continue
        if dep.startswith("@rpath/"):
            out += [os.path.normpath(os.path.join(r, dep[7:])) for r in rpaths] or [dep]
        else:
            out.append(at(dep))
    return out


def _dylib_candidates(real):
    """The files a root-run Mach-O binary could load (None when that cannot be told, which counts as unsafe). macOS only:
    a text script or a non-macOS binary has none."""
    try:
        with open(real, "rb") as fh:
            if fh.read(4) not in _MACHO_MAGIC:
                return []
        l_out = subprocess.run(["/usr/bin/otool", "-L", real], capture_output=True, text=True, timeout=30, check=True).stdout
        r_out = subprocess.run(["/usr/bin/otool", "-l", real], capture_output=True, text=True, timeout=30, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_dylib_refs(l_out, r_out, os.path.dirname(real))


def _chain_root_owned(path, owners):
    """`path` (or, when it does not exist yet, its nearest existing parent) and every directory above it are owned by `owners`
    and not group/world-writable: nobody but root can put or swap a file there."""
    p = os.path.realpath(path)
    while not os.path.lexists(p) and p != os.path.dirname(p):
        p = os.path.dirname(p)
    while True:
        try:
            st = os.stat(p)
        except OSError:
            return False
        if st.st_uid not in owners or st.st_mode & 0o022:
            return False
        if p == os.path.dirname(p):
            return True
        p = os.path.dirname(p)


def root_check(path, owners=(0,), deps_of=None):
    """None when `path` may be executed as root, else the reason as a short phrase. The real file and its parent directory
    must be owned by `owners` (root) and not group/world-writable, and (macOS) every library it loads must sit under
    root-owned, non-writable directories. A tool in a user-owned folder never qualifies, so a process running as the
    person cannot plant the binary or the dylib that the administrator prompt then runs as root. That includes a user-owned
    package-manager prefix such as a single-user Homebrew: a root-owned copy of its tcpreplay still loads /opt/homebrew
    libraries and is refused (use MacPorts or a static build). `owners` and `deps_of` are parameters only for tests."""
    try:
        real = os.path.realpath(path)
        pst, dst = os.stat(real), os.stat(os.path.dirname(real))
    except OSError:
        return "it cannot be read"
    if not all(st.st_uid in owners and not st.st_mode & 0o022 for st in (pst, dst)):
        return "it is not in a root-owned folder"
    deps = (deps_of or _dylib_candidates)(real) if (deps_of or sys.platform == "darwin") else []
    if deps is None:
        return "the libraries it loads could not be listed (is /usr/bin/otool available?)"
    for d in deps:
        if not _chain_root_owned(d, owners):
            return "it loads the library %s, which is not in a root-owned folder" % d
    return None


def root_safe(path, owners=(0,), deps_of=None):
    """True when root_check finds nothing against running `path` as root."""
    return root_check(path, owners, deps_of) is None


def privileged_tool(name, found=None, fallback_dirs=("/usr/local/bin", "/opt/local/bin", "/opt/homebrew/bin"),
                    owners=(0,)):
    """The path to run as root for `name`: `found` if root_safe, else the first safe fallback, else None."""
    found = found or find_tool(name)
    if found and root_safe(found, owners):
        return found
    for d in fallback_dirs:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK) and root_safe(cand, owners):
            return cand
    return None


def root_copy_hint(path):
    """The one-time command that puts a root-owned copy where privileged_tool looks. Pure."""
    return "sudo install -d /usr/local/bin && sudo install -m 755 -o root -g wheel %s /usr/local/bin/%s" % (
        shlex.quote(path), os.path.basename(path))


# Privileged helpers are looked up here only: a PATH entry the person (or their other programs) can write must
# not decide what runs with a password or a keyring secret in its hands.
SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/run/wrappers/bin", "/run/current-system/sw/bin")


def system_tool(name, dirs=SYSTEM_DIRS):
    """Absolute path of `name` in a fixed system directory, else None. Never consults PATH."""
    for d in dirs:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def install_hint(name):
    """How to install `name`, phrased for the package manager this Mac actually has.

    Telling a MacPorts user to run `brew install` invites the conclusion that the app is
    broken, so the hint follows the evidence on the box rather than assuming Homebrew.
    """
    pkg = _PACKAGED.get(name)
    if not pkg:
        return ""
    if sys.platform.startswith("linux"):
        return linux_install_hint(parse_os_release(_read_text("/etc/os-release")), pkg)
    from shutil import which
    has_brew = bool(which("brew")) or any(
        os.path.isfile(os.path.join(d, "brew")) for d in _search_paths())
    has_port = bool(which("port")) or any(
        os.path.isfile(os.path.join(d, "port")) for d in _search_paths())
    hints = []
    if has_brew:
        hints.append("brew install %s" % pkg)
    if has_port:
        hints.append("sudo port install %s" % pkg)
    if hints:
        return " or ".join(hints)
    # Neither manager present: name both rather than pick one for them.
    return "brew install %s (Homebrew, see brew.sh) or sudo port install %s" % (pkg, pkg)


_VERSIONS = {}                                         # path -> version line, for the process lifetime


def tool_version(path):
    """First meaningful line of `<tool> --version` (tcpreplay prints a root warning first)."""
    if path in _VERSIONS:
        return _VERSIONS[path]
    _VERSIONS[path] = v = _tool_version(path)
    return v


def _tool_version(path):
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
        for line in (r.stdout + "\n" + r.stderr).splitlines():
            line = line.strip()
            if line and not line.lower().startswith("warning"):
                return line
    except Exception:                                  # noqa: BLE001 - best-effort probe, falls back to an empty result
        pass
    return ""


def list_interfaces():
    """Interfaces available for replay, likely-physical ones first."""
    if sys.platform.startswith("linux"):
        rows = linux_details(read_linux_ifaces(), read_default_route_ifaces())
        if rows:
            return [d["name"] for d in rows]
    try:
        names = [n for _i, n in socket.if_nameindex()]
    except Exception:                                  # noqa: BLE001 - best-effort probe, falls back to an empty list
        return []

    def rank(n):
        if n.startswith("en"):
            return (0, n)                              # physical / Wi-Fi on macOS
        if n.startswith(("bridge", "vlan", "vmnet", "utun", "ppp", "feth")):
            return (2, n)
        if n == "lo0" or n.startswith("lo"):
            return (3, n)                              # loopback: smoke tests only
        return (1, n)
    return sorted(set(names), key=rank)


# ---------------------------------------------------------------------------
# pcap indexing
# ---------------------------------------------------------------------------

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),   # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4": (">", False),   # big-endian, microsecond
    b"\x4d\x3c\xb2\xa1": ("<", True),    # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d": (">", True),    # big-endian, nanosecond
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_INDEX_CACHE = {}
_INDEX_LOCK = threading.Lock()


def pcap_kind(path):
    """'pcap', 'pcapng' or None — cheap magic-number sniff for preflight."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return None
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    return None


def index_pcap(path, max_marks=4096, on_progress=None):
    """Walk the record headers of a classic pcap.

    Returns {packets, bytes, first_ts, last_ts, duration, linktype, marks, exact}.
    `bytes` is the sum of capture lengths — i.e. what tcpreplay counts as "bytes sent" —
    which is what makes the percentage line up with its stats output.
    `marks` is a sampled [(packet_index, ts), ...] list used to map "packets sent" back to
    a position in the captured day. pcapng is not walked (our generator writes classic
    pcap); it comes back exact=False and the UI falls back to a file-size estimate.
    """
    try:
        st = os.stat(path)
    except OSError as e:
        raise RuntimeError(f"cannot read {path}: {e}") from e
    key = (os.path.abspath(path), st.st_size, int(st.st_mtime))
    with _INDEX_LOCK:
        hit = _INDEX_CACHE.get(key)
    if hit:
        return hit

    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            raise RuntimeError("file is too short to be a pcap")
        if head[:4] == PCAPNG_MAGIC:
            info = {"packets": 0, "bytes": st.st_size, "first_ts": 0.0, "last_ts": 0.0,
                    "duration": 0.0, "linktype": None, "marks": [], "exact": False,
                    "format": "pcapng", "file_bytes": st.st_size}
            with _INDEX_LOCK:
                _INDEX_CACHE[key] = info
            return info
        if head[:4] not in PCAP_MAGICS:
            raise RuntimeError("not a pcap file (bad magic number)")
        endian, nano = PCAP_MAGICS[head[:4]]
        linktype = struct.unpack(endian + "I", head[20:24])[0]

        if st.st_size <= 24:
            info = {"packets": 0, "bytes": 0, "first_ts": 0.0, "last_ts": 0.0, "duration": 0.0,
                    "linktype": linktype, "marks": [], "exact": True, "format": "pcap",
                    "file_bytes": st.st_size}
            with _INDEX_LOCK:
                _INDEX_CACHE[key] = info
            return info

        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            unpack = struct.Struct(endian + "IIII").unpack_from
            div = 1e9 if nano else 1e6
            size = len(mm)
            off, n, nbytes = 24, 0, 0
            first_ts = last_ts = 0.0
            marks, stride = [], 256
            truncated = False
            while off + 16 <= size:
                ts_s, ts_f, caplen, _origlen = unpack(mm, off)
                if caplen > 0x400000 or off + 16 + caplen > size:
                    truncated = True                   # partial trailing record
                    break
                ts = ts_s + ts_f / div
                if n == 0:
                    first_ts = ts
                last_ts = ts
                if n % stride == 0:
                    marks.append((n, ts))
                    if len(marks) > max_marks:         # halve resolution, keep memory flat
                        marks = marks[::2]
                        stride *= 2
                n += 1
                nbytes += caplen
                off += 16 + caplen
                if on_progress and (n & 0xFFFF) == 0:
                    on_progress(off, size)
        finally:
            mm.close()

    info = {"packets": n, "bytes": nbytes, "first_ts": first_ts, "last_ts": last_ts,
            "duration": max(0.0, last_ts - first_ts), "linktype": linktype, "marks": marks,
            "exact": True, "format": "pcap", "file_bytes": st.st_size, "truncated": truncated}
    with _INDEX_LOCK:
        _INDEX_CACHE[key] = info
    return info


def ts_at_packet(marks, idx):
    """Interpolate the capture timestamp at packet `idx` from the sampled marks."""
    if not marks:
        return None
    lo, hi = 0, len(marks) - 1
    if idx <= marks[0][0]:
        return marks[0][1]
    if idx >= marks[hi][0]:
        return marks[hi][1]
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if marks[mid][0] <= idx:
            lo = mid
        else:
            hi = mid
    (n0, t0), (n1, t1) = marks[lo], marks[hi]
    if n1 == n0:
        return t0
    return t0 + (t1 - t0) * (idx - n0) / (n1 - n0)


# ---------------------------------------------------------------------------
# labelled interfaces (additive to the flat list)
# ---------------------------------------------------------------------------

_VIRTUAL_PREFIXES = ("bridge", "vlan", "vmnet", "utun", "ppp", "feth", "awdl", "llw", "gif",
                     "stf", "anpi", "ap", "veth", "docker", "br-", "virbr", "tun", "tap",
                     "vboxnet", "wg", "dummy")


def parse_hardware_ports(text):
    """`networksetup -listallhardwareports` text -> {device: hardware port name}. Pure."""
    out, port = {}, None
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            dev = line.split(":", 1)[1].strip()
            if dev:
                out[dev] = port
            port = None
    return out


def format_speed(mbps):
    """Megabits per second -> '100 Mb/s', '1 Gb/s', '2.5 Gb/s'. None for unknown. Pure."""
    try:
        m = float(mbps)
    except (TypeError, ValueError):
        return None
    if m <= 0:
        return None
    if m >= 1000:
        g = m / 1000.0
        return ("%d Gb/s" % g) if g == int(g) else ("%g Gb/s" % round(g, 1))
    return "%d Mb/s" % int(m)


def _speed_from_media(media):
    m = re.search(r"\(\s*(\d+(?:\.\d+)?)\s*(G?)base", media or "", re.I)
    if not m:
        return None
    val = float(m.group(1))
    return format_speed(val * 1000 if m.group(2) else val)


def parse_ifconfig(text):
    """`ifconfig <name>` text -> {link_up: bool|None, speed: str|None}. Pure.
    link_up comes from the `status:` line; interfaces without one (utun, lo) give None."""
    link_up, speed = None, None
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("status:"):
            val = line.split(":", 1)[1].strip().lower()
            link_up = True if val == "active" else (False if val == "inactive" else None)
        elif line.startswith("media:"):
            speed = _speed_from_media(line)
    return {"link_up": link_up, "speed": speed}


def classify_macos(name, port=None):
    """Interface kind from its name and macOS hardware-port name. Pure."""
    p = (port or "").lower()
    if name == "lo0" or name.startswith("lo"):
        return "loopback"
    if "wi-fi" in p or "wifi" in p or "airport" in p:
        return "wifi"
    if "bridge" in p or "vlan" in p or "vpn" in p:
        return "virtual"
    if name.startswith(_VIRTUAL_PREFIXES):
        return "virtual"
    if p:
        return "wired"      # any other named hardware port (Ethernet, USB/Thunderbolt adapters)
    return "other"


def classify_linux(name, dev_type=None, virtual=False, wireless=False):
    """Interface kind from /sys facts (ARPHRD type, virtual path, wireless dir). Pure."""
    if name == "lo" or dev_type == 772:
        return "loopback"
    if virtual or name.startswith(_VIRTUAL_PREFIXES):
        return "virtual"
    if wireless or name.startswith(("wl", "wlan")):
        return "wifi"
    if dev_type == 1:
        return "wired"
    return "other"


_KIND_TITLE = {"wired": "Ethernet", "wifi": "Wi-Fi", "virtual": "Virtual",
               "loopback": "Loopback", "other": "Interface"}


def interface_label(name, kind, link_up, speed):
    """Plain human label, e.g. 'Ethernet (en5), cable connected, 1 Gb/s'. Pure."""
    label = "%s (%s)" % (_KIND_TITLE.get(kind, "Interface"), name)
    if kind == "wired":
        if link_up is True:
            label += ", cable connected"
        elif link_up is False:
            label += ", no cable"
        if speed:
            label += ", " + speed
    return label


def pick_recommended(details):
    """Name of the single best candidate (wired, link up), else None. Pure.
    Prefers the fastest known speed; ties keep the existing list order."""
    def mbps(s):
        m = re.match(r"([\d.]+) (Gb|Mb)/s", s or "")
        return float(m.group(1)) * (1000 if m.group(2) == "Gb" else 1) if m else 0
    best = None
    for d in details:
        if d["kind"] == "wired" and d["link_up"] is True:
            if best is None or mbps(d["speed"]) > mbps(best["speed"]):
                best = d
    return best["name"] if best else None


def _run_text(argv, timeout=3):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except Exception:                                  # noqa: BLE001 - best-effort probe, falls back to an empty string
        return ""


def _read_sys(name, leaf):
    try:
        with open("/sys/class/net/%s/%s" % (name, leaf)) as f:
            return f.read().strip()
    except Exception:                                  # noqa: BLE001 - best-effort probe, falls back to None
        return None


def _probe_one(name, hw_ports):
    kind, link_up, speed = "other", None, None
    try:
        if sys.platform == "darwin":
            kind = classify_macos(name, hw_ports.get(name))
            info = parse_ifconfig(_run_text(["ifconfig", name]))
            link_up, speed = info["link_up"], info["speed"]
        elif sys.platform.startswith("linux"):
            t = _read_sys(name, "type")
            real = os.path.realpath("/sys/class/net/" + name)
            kind = classify_linux(name, int(t) if t and t.isascii() and t.isdigit() else None,
                                  "/sys/devices/virtual" in real,
                                  os.path.isdir("/sys/class/net/%s/wireless" % name))
            st = _read_sys(name, "operstate")
            link_up = True if st == "up" else (False if st in ("down", "lowerlayerdown") else None)
            sp = _read_sys(name, "speed")
            speed = format_speed(sp) if sp and sp.isascii() and sp.lstrip("-").isdigit() else None
    except Exception:                                  # noqa: BLE001 - best-effort probe, falls back to an unknown link state
        kind, link_up, speed = "other", None, None
    return {"name": name, "label": interface_label(name, kind, link_up, speed),
            "kind": kind, "link_up": link_up, "speed": speed, "recommended": False}


def interfaces_detail(names=None):
    """Labelled interfaces: [{name,label,kind,link_up,speed,recommended}]. Never raises."""
    try:
        names = list_interfaces() if names is None else names
        if sys.platform.startswith("linux"):
            rows = [r for r in read_linux_ifaces() if r["name"] in names]
            if rows:
                return linux_details(rows, read_default_route_ifaces())
        hw = parse_hardware_ports(_run_text(["networksetup", "-listallhardwareports"])) \
            if sys.platform == "darwin" else {}
        out = [_probe_one(n, hw) for n in names]
        rec = pick_recommended(out)
        for d in out:
            d["recommended"] = d["name"] == rec
        return out
    except Exception:                                  # noqa: BLE001 - interface probe failure falls back to a plain name list
        return [{"name": n, "label": n, "kind": "other", "link_up": None, "speed": None,
                 "recommended": False} for n in (names or [])]


# ---------------------------------------------------------------------------
# Linux: install hints, interface ranking, the elevation chain
# ---------------------------------------------------------------------------
# Everything here is a pure function over injected facts (os-release text, a sysfs tree,
# capability probe results, which(1) results) so the unit tests run on any OS; the thin probe
# functions are the only code that touches the machine. Nothing here runs an installer, stores
# or logs a password, or uses a shell. Privilege is only ever sought for the tcpreplay binary.

# IFNAMSIZ is 16 including the NUL. No leading '-' so a name can never be read as an option.
_LINUX_IFACE_RE = re.compile(r"[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,14}")


def valid_linux_iface(name):
    return isinstance(name, str) and bool(_LINUX_IFACE_RE.fullmatch(name))


def clean_abs_path(path):
    """`path` when it is a plain absolute path (no NUL, newline or CR), else None."""
    if isinstance(path, str) and path.startswith("/") and not any(c in path for c in "\0\n\r"):
        return path
    return None


def _read_text(path, cap=65536):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(cap)
    except OSError:
        return ""


def parse_os_release(text):
    """{'id': 'ubuntu', 'like': ['debian']} from /etc/os-release text. Pure."""
    kv = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition("=")
        if sep and k in ("ID", "ID_LIKE"):
            kv[k] = v.strip().strip("\"'").lower()
    return {"id": kv.get("ID", ""), "like": kv.get("ID_LIKE", "").split()}


def linux_install_hint(osr, pkg):
    """The command a person runs to install `pkg`, for their distro family. Never executed. Pure."""
    ids = {osr.get("id", "")} | set(osr.get("like", []))
    if ids & {"debian", "ubuntu"}:
        return "sudo apt install %s" % pkg
    if osr.get("id") == "fedora":
        return "sudo dnf install %s" % pkg
    if ids & {"rhel", "centos", "rocky", "almalinux", "ol"}:        # RHEL 9 family: tcpreplay is in EPEL
        return "sudo dnf install epel-release && sudo dnf install %s" % pkg
    if "fedora" in ids:
        return "sudo dnf install %s" % pkg
    if ids & {"suse", "opensuse", "sles"}:
        return "sudo zypper install %s" % pkg
    if "arch" in ids:
        return "sudo pacman -S %s" % pkg
    if "alpine" in ids:
        return "sudo apk add %s" % pkg
    return "sudo apt install %s (Debian/Ubuntu) or sudo dnf install %s (Fedora/RHEL)" % (pkg, pkg)


def read_linux_ifaces(root="/sys/class/net"):
    """One row per interface from a sysfs tree: type, operstate, speed, virtual, wireless. Never raises."""
    rows = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return rows
    for n in names:
        if not valid_linux_iface(n):
            continue
        d = os.path.join(root, n)

        def rd(leaf):
            t = _read_text(os.path.join(d, leaf), 64).strip()
            return t or None
        t, sp = rd("type"), rd("speed")
        rows.append({"name": n, "type": int(t) if t and t.isascii() and t.isdigit() else None,
                     "operstate": rd("operstate"), "speed": sp if sp and sp.isascii() and sp.lstrip("-").isdigit() else None,
                     "virtual": "/devices/virtual/" in os.path.realpath(d) + "/",
                     "wireless": os.path.isdir(os.path.join(d, "wireless"))})
    return rows


def parse_default_route_ifaces(text):
    """Interfaces carrying an IPv4 default route, from /proc/net/route text. Pure."""
    out = set()
    for line in (text or "").splitlines()[1:]:
        f = line.split()
        if len(f) >= 8 and f[1] == "00000000" and f[7] == "00000000":
            out.add(f[0])
    return out


def read_default_route_ifaces():
    return parse_default_route_ifaces(_read_text("/proc/net/route"))


_LINUX_KIND_ORDER = {"wired": 0, "wifi": 1, "other": 2, "virtual": 3, "loopback": 4}


def linux_details(rows, default_ifaces=frozenset()):
    """Labelled, ranked interface list for Linux. Pure.

    lo and virtual interfaces (docker, veth, bridges, tunnels) and the interface that carries the
    default route are listed LAST and flagged `discouraged` with a `warning`; they stay selectable.
    The recommendation is the fastest wired link that is up and not discouraged.
    """
    out = []
    for r in rows:
        kind = classify_linux(r["name"], r["type"], r["virtual"], r["wireless"])
        up = {"up": True, "down": False, "lowerlayerdown": False}.get(r["operstate"])
        speed = format_speed(r["speed"]) if r["speed"] else None
        warn = ""
        if kind == "loopback":
            warn = "Loopback is only useful as a smoke test; a sensor will not see this traffic."
        elif kind == "virtual":
            warn = "Virtual interface (container, VM, bridge or tunnel); a sensor on the lab network will not see this traffic."
        elif r["name"] in default_ifaces:
            warn = "This interface carries this computer's default route; replaying here can put the traffic on a production network."
        out.append({"name": r["name"], "label": interface_label(r["name"], kind, up, speed), "kind": kind,
                    "link_up": up, "speed": speed, "recommended": False,
                    "discouraged": bool(warn), "warning": warn})
    out.sort(key=lambda d: (d["discouraged"], _LINUX_KIND_ORDER.get(d["kind"], 2), d["link_up"] is not True, d["name"]))
    rec = pick_recommended([d for d in out if not d["discouraged"]])
    for d in out:
        d["recommended"] = d["name"] == rec
    return out


# -- file capabilities ------------------------------------------------------

_CAP_NET_RAW = 13


def parse_vfs_caps(blob):
    """True when a `security.capability` xattr gives CAP_NET_RAW as permitted and effective. Pure.

    Layout (linux/capability.h): u32 magic_etc (revision in the top byte, bit 0 = effective),
    then (permitted, inheritable) u32 pairs per capability word; CAP_NET_RAW is bit 13 of word 0.
    """
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 12:
        return False
    magic, permitted = struct.unpack("<II", bytes(blob[:8]))
    return bool(magic & 1) and bool(permitted & (1 << _CAP_NET_RAW))


def parse_getcap(text):
    """True when `getcap <file>` output shows cap_net_raw with the effective and permitted flags. Pure.
    Handles both `file cap_net_raw=ep` (libcap 2.x) and `file = cap_net_raw+ep` (older)."""
    for m in re.finditer(r"([a-z_,]+)[=+]([eip]+)", text or ""):
        if "cap_net_raw" in m.group(1).split(",") and {"e", "p"} <= set(m.group(2)):
            return True
    return False


def probe_file_caps(path, getxattr=None, run=None):
    """Does the binary at `path` carry cap_net_raw+ep? Reads the xattr, falls back to getcap(8)."""
    getxattr = getxattr or getattr(os, "getxattr", None)
    real = os.path.realpath(path)
    if getxattr:
        try:
            return parse_vfs_caps(getxattr(real, "security.capability"))
        except OSError:
            return False                                   # ENODATA: no capability set
    gc = system_tool("getcap")
    return bool(gc) and parse_getcap((run or _run_text)([gc, real]))


# -- the elevation chain ----------------------------------------------------

def decide_elevation(euid, tcpreplay, has_cap, sudo_path, sudo_ok, pkexec_path, has_display, hint):
    """Choose how a replay gets raw-socket rights. Pure; every input is a probe result.

    Order: already root, cap_net_raw on the tcpreplay binary, passwordless sudo for that exact
    binary, pkexec (a person is prompted), else none. Returns
    {mode, ok, prefix, stoppable, message}; `prefix` is argv placed before tcpreplay's own argv.
    `stoppable` is False for pkexec: that process is root-owned and the unprivileged stop-file
    watcher cannot signal it, and Stop must not ask for a second password.
    """
    def out(mode, ok, prefix, message, stoppable=True):
        return {"mode": mode, "ok": ok, "prefix": prefix, "stoppable": stoppable, "message": message}
    if not clean_abs_path(tcpreplay):
        return out("none", False, [], "tcpreplay was not found. Install it with: %s" % hint)
    if euid == 0:
        return out("root", True, [], "Running as root; no elevation needed.")
    if has_cap:
        return out("capability", True, [], "tcpreplay has the cap_net_raw capability; no elevation needed.")
    if sudo_ok and clean_abs_path(sudo_path):
        return out("sudo", True, [sudo_path, "-n", "--"],
                   "Passwordless sudo is configured for tcpreplay; no prompt will appear.")
    if has_display and clean_abs_path(pkexec_path):
        return out("pkexec", True, [pkexec_path],
                   "A system dialog will ask for an administrator password. The password goes to that "
                   "dialog, never to this app. Stop cannot end a replay started this way before it "
                   "finishes; grant the capability below to avoid that.", stoppable=False)
    return out("none", False, [],
               "Replay needs permission to send raw packets. One-time fix, as an administrator: "
               "sudo setcap cap_net_raw+ep %s (re-run it after tcpreplay is upgraded). "
               "Alternatively start this server as root." % shlex.quote(tcpreplay))


def probe_sudo(sudo_path, tcpreplay):
    """True when `sudo -n` may run exactly this tcpreplay without a password. Never prompts."""
    try:
        r = subprocess.run([sudo_path, "-n", "-l", tcpreplay], capture_output=True, text=True,
                           timeout=5, stdin=subprocess.DEVNULL)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def linux_elevation(tcpreplay):
    """decide_elevation over this machine's real probes."""
    path = clean_abs_path(tcpreplay) or ""
    sudo = system_tool("sudo") if path else None
    return decide_elevation(
        euid=os.geteuid(), tcpreplay=path, has_cap=bool(path) and probe_file_caps(path),
        sudo_path=sudo, sudo_ok=bool(sudo) and os.geteuid() != 0 and probe_sudo(sudo, path),
        pkexec_path=system_tool("pkexec"),
        has_display=bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
        hint=install_hint("tcpreplay"))


def public_elevation(e):
    """The part of a decision the UI sees (no argv)."""
    return {k: e[k] for k in ("mode", "ok", "stoppable", "message")}


def tcpreplay_has_stats(help_text):
    """False only when `tcpreplay --help` clearly lacks --stats; unknown output keeps today's behaviour. Pure."""
    return not help_text or "--stats" in help_text


def linux_terminal_argv(script, which, env):
    """argv that shows the monitor script in a terminal emulator, or None without a display. Pure."""
    if not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")) or not clean_abs_path(script):
        return None
    for term, flag in (("x-terminal-emulator", "-e"), ("gnome-terminal", "--"), ("konsole", "-e"),
                       ("xfce4-terminal", "-x"), ("xterm", "-e")):
        p = which(term)
        if p:
            return [p, flag, script]
    return None


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

PREFLIGHT_TTL = 10.0                                   # seconds; a tool installed while the app is open shows after this
_PREFLIGHT = {}                                        # (pcap, stat, iface) -> (monotonic time, report)


def preflight(pcap=None, iface=None, fresh=False):
    """Check every dependency up front and report precisely what is missing. The report is reused for
    PREFLIGHT_TTL seconds for the same capture (path, size, mtime) and interface; fresh=True re-checks."""
    try:
        st = os.stat(os.path.expanduser(pcap)) if pcap else None
    except OSError:
        st = None
    key = (pcap, (st.st_size, st.st_mtime_ns) if st else None, iface)
    hit = _PREFLIGHT.get(key)
    if hit and not fresh and time.monotonic() - hit[0] < PREFLIGHT_TTL:
        return copy.deepcopy(hit[1])
    report = _preflight(pcap, iface)
    if len(_PREFLIGHT) >= 8:
        _PREFLIGHT.clear()                             # bounded: a few recent (pcap, iface) pairs is plenty
    _PREFLIGHT[key] = (time.monotonic(), report)
    return copy.deepcopy(report)


def _preflight(pcap=None, iface=None):
    tools, missing = [], []

    def check(name, required, why):
        path = find_tool(name)
        entry = {"name": name, "required": required, "found": bool(path), "path": path or "",
                 "version": tool_version(path) if path else "", "why": why,
                 "hint": install_hint(name)}
        tools.append(entry)
        if required and not path:
            missing.append(name)
        return entry

    check("tcpreplay", True, "replays the capture onto an interface")
    check("tcprewrite", False, "optional: rewrite MACs/IPs before replay")
    if sys.platform == "darwin":
        osa = {"name": "osascript", "required": True, "why": "raises the macOS administrator prompt",
               "path": "/usr/bin/osascript", "found": os.path.exists("/usr/bin/osascript"),
               "version": "", "hint": "part of macOS"}
        tools.append(osa)
        if not osa["found"]:
            missing.append("osascript")

    report = {"ok": False, "platform": sys.platform, "tools": tools, "missing": missing,
              "interfaces": list_interfaces(), "interfaces_detail": [], "errors": [], "warnings": [], "pcap": None}

    report["interfaces_detail"] = interfaces_detail(report["interfaces"])

    if sys.platform.startswith("linux"):
        tp = next((t["path"] for t in tools if t["name"] == "tcpreplay"), "")
        if tp:
            elev = linux_elevation(tp)
            report["elevation"] = public_elevation(elev)
            if not elev["ok"]:
                report["warnings"].append(elev["message"])
            if not tcpreplay_has_stats(_run_text([tp, "--help"], 5)):
                report["warnings"].append(
                    "This tcpreplay has no --stats option: progress is not shown, the result is reported at the end.")
    elif sys.platform not in ("darwin",) and os.geteuid() != 0:
        report["warnings"].append(
            "Automatic privilege elevation is implemented for macOS only. On this platform, "
            "start the server as root (or with sudo) to enable replay.")

    for name in missing:
        hint = install_hint(name)
        report["errors"].append(f"'{name}' was not found." + (f" Install it with: {hint}" if hint else ""))

    if pcap:
        pcap = os.path.expanduser(pcap)
        if not os.path.isfile(pcap):
            report["errors"].append(f"Capture file not found: {pcap}")
        elif not os.access(pcap, os.R_OK):
            report["errors"].append(f"Capture file is not readable: {pcap}")
        else:
            kind = pcap_kind(pcap)
            if kind is None:
                report["errors"].append(f"{os.path.basename(pcap)} is not a pcap/pcapng file.")
            else:
                report["pcap"] = {"path": pcap, "format": kind,
                                  "bytes": os.path.getsize(pcap)}
                if kind == "pcapng":
                    report["warnings"].append(
                        "pcapng detected: exact packet-count progress is unavailable, "
                        "progress will be estimated from file size.")

    bad_iface = (not valid_linux_iface(iface)) if sys.platform.startswith("linux") \
        else not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,31}", iface or "x")
    if iface and bad_iface:                            # even when listing interfaces fails
        report["errors"].append("That is not a valid interface name.")
    elif iface:
        names = report["interfaces"]
        if names and iface not in names:
            report["errors"].append(f"Interface '{iface}' does not exist. Available: {', '.join(names)}")
        elif sys.platform.startswith("linux"):
            for d in report["interfaces_detail"]:
                if d["name"] == iface and d.get("warning"):
                    report["warnings"].append(d["warning"])
        elif iface.startswith("lo"):
            report["warnings"].append(
                "Loopback is only useful as a smoke test — a sensor will not see this traffic.")

    report["limits"] = dict(LIMITS)
    report["ok"] = not report["errors"]
    return report


# ---------------------------------------------------------------------------
# run state
# ---------------------------------------------------------------------------

RSTATE = {
    "running": False, "done": False, "error": None, "phase": "idle", "stopped": False,
    "pcap": "", "iface": "", "speed": "", "loop": 1, "pid": 0,
    "total_packets": 0, "total_bytes": 0, "capture_duration": 0.0, "exact": True,
    "sent_packets": 0, "sent_bytes": 0, "elapsed": 0.0,
    "percent": 0.0, "remaining_packets": 0, "remaining_bytes": 0, "eta_seconds": None,
    "capture_clock": "", "capture_start": "", "capture_end": "",
    "capture_elapsed": 0.0, "capture_remaining": 0.0,
    "rate_pps": 0.0, "rate_mbps": 0.0,
    "log": [], "exit_code": None, "started": 0.0,
    "replay_id": "", "record": "", "record_error": "", "resumed_from": None,
    "elevation": "", "stoppable": True,
}
RLOCK = threading.Lock()
_RUN = {"dir": None, "stopfile": None, "logfile": None, "proc": None, "thread": None, "rec": None}

# A replay outlives this process. tcpreplay is launched detached and root-owned
# (`nohup ... &` under osascript), so restarting the server leaves it running with the
# stop-file path -- the only unprivileged handle on it -- known to nobody. RUNFILE is that
# path written down, so a fresh process can find the run again, resume tracking it, and
# still stop it without a second password prompt.
RUNFILE = None                                     # tests point this at a file; None = the per-user run folder
ROOT_LOG_BASE = "/private/var/run"                 # macOS: where the root shell keeps its log (root-owned)
RUNFILE_MAX = 1_000_000
RUN_KEEP_DAYS = 14


def _state_dir(create=False):
    """The per-user run-state folder (inside the 0700 settings folder): run-file, stop file, logs, monitor window.
    Never a shared temp folder, where another user could plant a file this process would later trust."""
    d = os.path.join(settings_store.settings_dir(), "run")
    if create:
        settings_store.ensure_private_dir(d)
    return d


def _runfile():
    return RUNFILE or os.path.join(_state_dir(), "replay-current.json")


def _prune_old_runs(base, days=RUN_KEEP_DAYS):
    """Remove finished run folders we own that are older than `days`; the folder of a live replay is never that old."""
    cutoff = time.time() - days * 86400
    try:
        names = os.listdir(base)
    except OSError:
        return
    for n in names:
        p = os.path.join(base, n)
        try:
            st = os.lstat(p)
            if n.startswith("nwtg-replay-") and stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() \
                    and st.st_mtime < cutoff:
                shutil.rmtree(p)
        except OSError:
            continue


def _owned_private_dir(path, euid):
    """lstat-based: a real directory (no symlink) owned by `euid` that group and others cannot write."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_uid == euid and not st.st_mode & 0o022


def run_paths_ok(info, euid=None, state_dir=None, root_log_base=ROOT_LOG_BASE, root_uid=0):
    """May this run-file's paths be trusted? Pure policy over lstat: the stop file must be `STOP` in a run folder
    of ours (a `nwtg-replay-*` directory inside the per-user state folder, owned by us, not writable by others);
    the log must be `tcpreplay.log` in that same folder, or in a root-owned `og-replay-<uid>-*` folder under
    `root_log_base` (the macOS administrator path). Anything else is refused, so a planted run-file cannot make
    this process read or write a path someone else chose."""
    euid = os.geteuid() if euid is None else euid
    base = os.path.realpath(state_dir or _state_dir())
    rundir, stopfile, logfile = (info.get(k) for k in ("dir", "stopfile", "logfile"))
    if not all(isinstance(x, str) and os.path.isabs(x) for x in (rundir, stopfile, logfile)):
        return False
    if not os.path.basename(rundir).startswith("nwtg-replay-") or not _owned_private_dir(rundir, euid) \
            or os.path.realpath(rundir) != os.path.join(base, os.path.basename(rundir)):     # inside the state folder, not a link
        return False
    if stopfile != os.path.join(rundir, "STOP"):
        return False
    if logfile == os.path.join(rundir, "tcpreplay.log"):
        return True
    root_dir = os.path.dirname(logfile)
    return (os.path.basename(logfile) == "tcpreplay.log"
            and os.path.realpath(os.path.dirname(root_dir)) == os.path.realpath(root_log_base)
            and re.fullmatch(r"og-replay-%d-[0-9a-f]{12}" % euid, os.path.basename(root_dir)) is not None
            and _owned_private_dir(root_dir, root_uid))


def _write_runfile(**info):
    """Record the in-flight run: a fresh 0600 file in the same folder, then an atomic replace. Best effort:
    failing to write must not fail the replay."""
    path = _runfile()
    try:
        settings_store.ensure_private_dir(os.path.dirname(path))
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".run-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(info, f)
            os.replace(tmp, path)
        except BaseException:
            os.unlink(tmp)
            raise
    except OSError:
        pass


def _clear_runfile():
    try:
        os.remove(_runfile())
    except OSError:
        pass


def _read_runfile():
    """The recorded run, or None. The file must be a regular file we own, opened without following a symlink."""
    try:
        fd = os.open(_runfile(), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd) as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
                return None
            info = json.loads(f.read(RUNFILE_MAX))
        return info if isinstance(info, dict) else None
    except (OSError, ValueError):
        return None


def reattach():
    """Pick up a replay this process did not start. Call once at server startup.

    Returns a short description when a live replay was adopted, else None. Every failure
    mode here ends in "no replay running", never an exception: a broken run-file must not
    stop the server from starting.
    """
    info = _read_runfile()
    if not info:
        return None
    if not run_paths_ok(info):                         # run-file is ours (owner checked) but its paths are not: drop it
        _clear_runfile()
        return None
    logfile = info.get("logfile") or ""
    stopfile = info.get("stopfile") or ""
    try:
        with open(logfile, "r", errors="replace") as f:
            text = f.read()
    except OSError:
        _clear_runfile()                               # log is gone; nothing to adopt
        return None

    if EXIT_RE.search(text):                           # it finished while we were away
        _clear_runfile()
        return None
    m = PID_RE.search(text)
    pid = int(m.group(1)) if m else 0
    if not pid or _pid_alive(pid) is False:            # died, or never got far enough to log a pid
        _clear_runfile()
        return None

    idx = info.get("idx") or {}
    loop = int(info.get("loop") or 1)
    with RLOCK:
        RSTATE.update(
            running=True, done=False, error=None, phase="replaying", stopped=False,
            pcap=info.get("pcap", ""), iface=info.get("iface", ""),
            speed=info.get("speed", ""), loop=loop, pid=pid,
            total_packets=int(info.get("total_packets") or 0),
            total_bytes=int(info.get("total_bytes") or 0),
            capture_duration=float(info.get("capture_duration") or 0.0),
            exact=bool(info.get("exact", True)),
            capture_start=info.get("capture_start", ""), capture_end=info.get("capture_end", ""),
            started=float(info.get("started") or time.time()),
            log=[], exit_code=None,
        )
    _RUN.update(dir=info.get("dir"), logfile=logfile, stopfile=stopfile, proc=None, rec=info.get("rec"))
    _log(f"reattached to a replay already in progress (pid {pid}).")
    # _watch tails from offset 0, so the log view and the counters rebuild themselves from
    # what tcpreplay has already written -- no state needs to survive in this process.
    t = threading.Thread(target=_watch, args=(logfile, idx, loop, None), daemon=True)
    _RUN["thread"] = t
    t.start()
    return {"pid": pid, "pcap": info.get("pcap", ""), "iface": info.get("iface", "")}

STAT_RE = re.compile(r"Actual:\s+(\d+)\s+packets\s+\((\d+)\s+bytes\)\s+sent in\s+([\d.]+)\s+seconds")
PID_RE = re.compile(r"^PID:\s*(\d+)", re.M)
EXIT_RE = re.compile(r"^OGRP-EXIT:(-?\d+)", re.M)


def _log(msg):
    with RLOCK:
        RSTATE["log"].append(msg)
        del RSTATE["log"][:-400]


def _reset(pcap, iface, speed_desc, loop):
    with RLOCK:
        RSTATE.update(running=True, done=False, error=None, phase="indexing", stopped=False,
                      pcap=pcap, iface=iface, speed=speed_desc, loop=loop, pid=0,
                      total_packets=0, total_bytes=0, capture_duration=0.0, exact=True,
                      sent_packets=0, sent_bytes=0, elapsed=0.0, percent=0.0,
                      remaining_packets=0, remaining_bytes=0, eta_seconds=None,
                      capture_clock="", capture_start="", capture_end="",
                      capture_elapsed=0.0, capture_remaining=0.0,
                      rate_pps=0.0, rate_mbps=0.0, log=[], exit_code=None, started=time.time(),
                      replay_id="", record="", record_error="", resumed_from=None,
                      elevation="", stoppable=True)
    _RUN.update(dir=None, stopfile=None, logfile=None, proc=None, rec=None)    # nothing of the previous run: a Stop now must not touch its files


# ---------------------------------------------------------------------------
# human-set options (validated here, the one place every caller goes through)
# ---------------------------------------------------------------------------

# Hard bounds. --topspeed is not offered at all: it discards the timing a sensor test depends on, and
# the multiplier is capped so a content-only run cannot exceed 10x.
LIMITS = {"default_multiplier": 1.0, "max_multiplier": 10.0, "min_multiplier": 0.01,
          "max_pps": 1000000, "max_mbps": 10000, "max_loop": 10000,
          "max_maxsleep_ms": 3600000, "max_packet_no": 2 ** 31 - 1,
          "default_overlap_packets": 500, "max_overlap_packets": 100000,
          "max_label_chars": 64, "max_note_chars": 1000, "max_rebase_seconds": 7 * 86400}
SPEED_MODES = ("multiplier", "pps", "mbps")
RECORD_VERSION = 1
HASH_CAP = 2 * 1024 ** 3               # larger files are not hashed here; the record says so
RECORD_MAX_BYTES = 256 * 1024          # a record is small; a bigger file beside the capture is not ours
_ID_RE = re.compile(r"[0-9a-f]{12}")


def _int_field(v, name, lo, hi):
    """A JSON integer in [lo, hi]. Rejects bool, float, string: an option is never coerced."""
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{name} must be a whole number")
    if not lo <= v <= hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return v


def _clean_text(v, name, limit):
    """Free text from the person: control and format characters removed, whitespace folded, length checked."""
    if v is None:
        return ""
    if not isinstance(v, str):
        raise ValueError(f"{name} must be text")
    if len(v) > limit * 8:
        raise ValueError(f"{name} is longer than {limit} characters")
    out = "".join(" " if c in "\n\r\t" else c for c in v
                  if c in "\n\r\t" or unicodedata.category(c) not in ("Cc", "Cf", "Cs", "Co", "Cn"))
    out = " ".join(out.split())
    if len(out) > limit:
        raise ValueError(f"{name} is longer than {limit} characters")
    return out


def _looks_like_address(text):
    if "://" in text:
        return True
    for tok in re.split(r"[\s,;/]+", text):
        try:
            ipaddress.ip_address(tok.strip("[]()"))
            return True
        except ValueError:
            continue
    return False


def parse_options(data):
    """Validate the human's replay options; returns the normalised dict, or raises ValueError.

    Every numeric option is a bounded integer (or a finite float for the speed value), never coerced
    from text. Nothing here is passed to a shell: build_argv turns the result into an argv list.
    """
    if not isinstance(data, dict):
        raise ValueError("replay options must be an object")
    mode = data.get("speed_mode", "multiplier")
    if mode == "topspeed":
        raise ValueError("top speed is not available: it discards the original timing")
    if mode not in SPEED_MODES:
        raise ValueError("speed_mode must be one of: " + ", ".join(SPEED_MODES))
    val = data.get("speed_value")
    if val is None and mode == "multiplier":
        val = LIMITS["default_multiplier"]
    if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
        raise ValueError("speed_value must be a number")
    lo, hi = {"multiplier": (LIMITS["min_multiplier"], LIMITS["max_multiplier"]),
              "pps": (1, LIMITS["max_pps"]), "mbps": (0.01, LIMITS["max_mbps"])}[mode]
    if not lo <= val <= hi:
        raise ValueError(f"speed_value for {mode} must be between {lo:g} and {hi:g}")
    out = {"speed_mode": mode, "speed_value": float(val),
           "loop": _int_field(data.get("loop", 1), "loop", 1, LIMITS["max_loop"]),
           "preload": bool(data.get("preload", False)), "monitor": bool(data.get("monitor", True))}
    ms = data.get("maxsleep_ms")
    out["maxsleep_ms"] = None if ms is None else _int_field(ms, "maxsleep_ms", 1, LIMITS["max_maxsleep_ms"])
    inc = data.get("include")
    if inc is None:
        out["include"] = None
    else:
        if not isinstance(inc, dict) or set(inc) - {"start", "end"}:
            raise ValueError("include must be {start, end} with whole packet numbers")
        a = _int_field(inc.get("start"), "include.start", 1, LIMITS["max_packet_no"])
        b = inc.get("end")
        b = None if b is None else _int_field(b, "include.end", a, LIMITS["max_packet_no"])
        out["include"] = {"start": a, "end": b}
    rf = data.get("resume_from")
    if rf is not None and (not isinstance(rf, str) or not _ID_RE.fullmatch(rf)):
        raise ValueError("resume_from must be a replay id")
    if rf and out["include"]:
        raise ValueError("resume_from and include cannot be combined: a resume sets its own range")
    out["resume_from"] = rf
    out["overlap_packets"] = _int_field(data.get("overlap_packets", LIMITS["default_overlap_packets"]),
                                        "overlap_packets", 0, LIMITS["max_overlap_packets"])
    out["rebase_seconds"] = _int_field(data.get("rebase_seconds", 0), "rebase_seconds",
                                       -LIMITS["max_rebase_seconds"], LIMITS["max_rebase_seconds"])
    label = _clean_text(data.get("sensor_label"), "sensor_label", LIMITS["max_label_chars"])
    if _looks_like_address(label):
        raise ValueError("sensor_label is a name you choose, not an address")
    out["sensor_label"] = label
    out["note"] = _clean_text(data.get("note"), "note", LIMITS["max_note_chars"])
    return out


# ---------------------------------------------------------------------------
# launching
# ---------------------------------------------------------------------------

def build_argv(tcpreplay, pcap, iface, speed_mode="multiplier", speed_value=1.0, loop=1,
               stats_every=1, preload=False, write_to=None, maxsleep_ms=None, include=None):
    """Assemble the tcpreplay command line.

    -P prints the PID at startup and --stats gives periodic progress; both are what the
    progress tracker reads.
    """
    if speed_mode not in SPEED_MODES:                  # includes topspeed: never built into a command line
        raise ValueError("unsupported speed mode: %s" % speed_mode)
    argv = [tcpreplay, "-P"]
    if stats_every:                                    # 0 = an old tcpreplay without --stats (Linux probe)
        argv.append(f"--stats={int(stats_every)}")
    if speed_mode == "pps":
        argv.append(f"--pps={speed_value}")
    elif speed_mode == "mbps":
        argv.append(f"--mbps={speed_value}")
    else:
        argv.append(f"--multiplier={speed_value}")
    if loop and int(loop) != 1:
        argv.append(f"--loop={int(loop)}")
    if maxsleep_ms:
        argv.append(f"--maxsleep={int(maxsleep_ms)}")
    if include:
        argv.append("--include=%d-%s" % (include["start"], "" if include.get("end") is None else int(include["end"])))
    if preload:
        argv.append("--preload-pcap")
    if write_to:                                       # test path: no interface, no root
        argv += ["-w", write_to]
    else:
        argv += ["-i", iface]
    argv.append(pcap)
    return argv


def _root_log_dir(euid, replay_id, base=ROOT_LOG_BASE):
    """The root-owned folder the administrator shell keeps its log in. Pure."""
    return os.path.join(base, "og-replay-%d-%s" % (euid, replay_id))


def _inner_script(argv, logfile, stopfile, root_logdir=None):
    """Shell run as root: start tcpreplay, plus a watcher that honours the stop-file.

    The watcher means "Stop" does not need a second authorization prompt — creating the
    stop-file is an ordinary unprivileged write. Root only ever *tests* that path; it writes nothing into a
    folder the person owns. With `root_logdir` (the macOS administrator path) the log lives in a folder root
    creates itself, `mkdir` failing if the name already exists, so no one can have put a link there first.
    """
    cmd = " ".join(shlex.quote(a) for a in argv)
    log, stop = shlex.quote(logfile), shlex.quote(stopfile)
    pre = f"umask 022\nmkdir -m 755 {shlex.quote(root_logdir)} || exit 1\n" if root_logdir else ""
    return pre + (
        f"{cmd} > {log} 2>&1 &\n"                    # lint-ok: the log is inside a folder root made itself, mkdir fails if it exists
        "TP=$!\n"
        f'( while kill -0 $TP 2>/dev/null; do\n'
        f'    if [ -f {stop} ]; then kill -TERM $TP 2>/dev/null; break; fi\n'
        "    sleep 0.3\n"
        "  done ) &\n"
        "W=$!\n"
        "wait $TP\n"
        "EC=$?\n"
        "kill $W 2>/dev/null\n"
        f'echo "OGRP-EXIT:$EC" >> {log}\n'
    )


def _monitor_script(rundir, logfile, stopfile, pcap, iface, speed, loop):
    """A .command the user can watch and stop the replay from, without the GUI or a password.

    This is the failsafe for the case the run-file cannot cover: the server hung, was
    force-quit, or the whole app died. tcpreplay is detached and root-owned, so the only
    thing that can still reach it is the stop-file -- and creating that file needs no
    privileges at all, which is why this window can offer a stop with no password prompt.

    Closing the window deliberately does NOT stop the replay; Control-C does.

    The generated shell deliberately contains **no backslash escapes**: values are injected
    with shlex.quote and everything else is a quoted here-doc, so nothing in a file path can
    terminate a string or be re-interpreted on its way through Python.
    """
    path = os.path.join(rundir, "replay-monitor.command")
    q = shlex.quote
    banner = (
        "-------------------------------------------------------------------------\n"
        "  OpenGenerator - replay monitor\n"
        "-------------------------------------------------------------------------"
    )
    lines = [
        "#!/bin/sh",
        "# OpenGenerator -- replay monitor (failsafe window).",
        "# Generated per run; safe to delete once the replay has finished.",
        "LOG=" + q(logfile),
        "STOP=" + q(stopfile),
        "cat <<'BANNER'",
        banner,
        "BANNER",
        "echo " + q("  capture   : " + os.path.basename(pcap)),
        "echo " + q("  interface : " + (iface or "(file)")),
        "echo " + q("  speed     : " + str(speed) + "   loop: " + str(loop)),
        "echo " + q("  full path : " + pcap),
        "echo " + q("  stop file : " + stopfile),
        "cat <<'BANNER'",
        "",
        "  TO STOP THE REPLAY:  press Control-C in this window.",
        "  No password is needed - stopping only creates a file.",
        "",
        "  From any other terminal, the equivalent is:",
        "      touch " + stopfile,
        "",
        "  Closing this window does NOT stop the replay. This window is a",
        "  failsafe: it keeps working if the application hangs, is closed,",
        "  or is restarted.",
        "-------------------------------------------------------------------------",
        "",
        "BANNER",
        # Control-C requests the stop and then keeps tailing, so the user sees tcpreplay
        # actually wind down instead of being left wondering whether it worked.
        "trap 'touch \"$STOP\"; echo; echo \"  Stop requested - waiting for tcpreplay to wind down ...\"; echo' INT",
        "tail -f \"$LOG\" 2>/dev/null &",
        "TAILPID=$!",
        "while :; do",
        "  if grep -q '^OGRP-EXIT:' \"$LOG\" 2>/dev/null; then break; fi",
        "  if [ ! -f \"$LOG\" ]; then break; fi",
        "  sleep 1",
        "done",
        "sleep 1",
        "kill $TAILPID 2>/dev/null",
        "echo",
        "echo '  Replay finished. You can close this window.'",
        "echo",
    ]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o755)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def _open_monitor_window(script_path):
    """Show the monitor in Terminal. Never let a failed window fail the replay.

    `open -a Terminal <script>` goes through LaunchServices, not Apple Events, so it does
    NOT trigger an Automation (TCC) consent prompt the way `osascript -e 'tell app
    "Terminal"'` would. That matters: this runs unattended right after the admin prompt,
    and a second permission dialog there would be baffling.
    """
    if sys.platform.startswith("linux"):
        from shutil import which
        argv = linux_terminal_argv(script_path, which, os.environ)
        try:
            if argv:
                subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
            return bool(argv)
        except OSError:
            return False
    try:
        subprocess.run(["/usr/bin/open", "-a", "Terminal", script_path],
                       capture_output=True, text=True, timeout=15)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _osa_escape(s):
    """Escape a Python string for embedding in an AppleScript double-quoted literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _launch_privileged(inner):
    """Raise macOS's native admin prompt and start the (backgrounded) privileged shell.

    The password is entered in the OS dialog and consumed by authorizationd; it is never
    seen by this process. osascript returns as soon as the job is backgrounded, so its fds
    are fully redirected to avoid blocking on an inherited pipe.
    """
    outer = "nohup /bin/sh -c " + shlex.quote(inner) + " >/dev/null 2>&1 </dev/null & echo OGRP-OK"
    script = f'do shell script "{_osa_escape(outer)}" with administrator privileges'
    r = subprocess.run(["/usr/bin/osascript", "-e", script],
                       capture_output=True, text=True)
    if r.returncode != 0:
        err = (r.stderr or "").strip()
        if "-128" in err or "User canceled" in err or "User cancelled" in err:
            raise RuntimeError("Administrator authorization was cancelled — replay not started.")
        raise RuntimeError(f"Could not obtain administrator privileges: {err or 'unknown error'}")
    return None


def _wait_for_file(path, seconds):
    """True once `path` exists, polling up to `seconds`."""
    gate, end = threading.Event(), time.monotonic() + seconds
    while time.monotonic() < end:
        if os.path.exists(path):
            return True
        gate.wait(0.2)
    return os.path.exists(path)


def _launch_unprivileged(inner):
    """Run the same shell directly — used when already root, and by the self-test."""
    return subprocess.Popen(["/bin/sh", "-c", inner], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)


# ---------------------------------------------------------------------------
# progress tracking
# ---------------------------------------------------------------------------

def _recompute(idx, sent_packets, sent_bytes, elapsed, loop):
    """Turn tcpreplay's counters into played/remaining figures for the UI."""
    loop = max(1, int(loop or 1))
    total_p = (idx["packets"] or 0) * loop
    total_b = (idx["bytes"] or 0) * loop
    out = {}
    if total_p:
        pct = min(100.0, 100.0 * sent_packets / total_p)
    elif total_b:
        pct = min(100.0, 100.0 * sent_bytes / total_b)
    else:
        pct = 0.0
    out["percent"] = pct
    out["remaining_packets"] = max(0, total_p - sent_packets)
    out["remaining_bytes"] = max(0, total_b - sent_bytes)
    out["rate_pps"] = sent_packets / elapsed if elapsed > 0 else 0.0
    out["rate_mbps"] = (sent_bytes * 8 / 1e6) / elapsed if elapsed > 0 else 0.0

    # position within the captured day (this loop iteration)
    if idx["marks"] and idx["packets"]:
        in_loop = sent_packets % idx["packets"] if loop > 1 else min(sent_packets, idx["packets"])
        ts = ts_at_packet(idx["marks"], in_loop + idx.get("offset", 0))
        if ts:
            out["capture_clock"] = time.strftime("%H:%M:%S", time.localtime(ts))
            out["capture_elapsed"] = max(0.0, ts - idx["first_ts"])
            out["capture_remaining"] = max(0.0, idx["last_ts"] - ts)

    # wall-clock ETA: prefer the observed send rate, which is correct for every speed mode
    if out["rate_pps"] > 0 and out["remaining_packets"]:
        out["eta_seconds"] = out["remaining_packets"] / out["rate_pps"]
    elif total_p and pct > 0 and elapsed > 0:
        out["eta_seconds"] = elapsed * (100.0 - pct) / pct
    else:
        out["eta_seconds"] = None
    return out


def _pid_alive(pid):
    """Is the (possibly root-owned) tcpreplay process still there?"""
    if not pid:
        return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                                    # exists, owned by root
    except OSError:
        return None


def _watch(logfile, idx, loop, proc):
    """Tail tcpreplay's output and keep RSTATE current until it exits.

    `OGRP-EXIT:<code>` from the wrapper shell is the authoritative end. If that never
    arrives (the shell was killed, or the privileged job vanished) we fall back to
    watching the pid, and the run is only called successful if the packet count actually
    reached the total — otherwise it is reported as a failure rather than silently "done".
    """
    pos, pid_seen, exit_code, tail = 0, False, None, ""
    idle = 0
    while True:
        time.sleep(0.4)
        try:
            with open(logfile, "r", errors="replace") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
        except OSError:
            chunk = ""
        if chunk:
            idle = 0
            tail = (tail + chunk)[-8000:]
            for line in chunk.splitlines():
                line = line.strip()
                if not line or line.startswith(("Actual:", "Rated:", "OGRP-EXIT:")):
                    continue
                _log(line)
            if not pid_seen:
                m = PID_RE.search(tail)
                if m:
                    pid_seen = True
                    with RLOCK:
                        RSTATE["pid"] = int(m.group(1))
                        RSTATE["phase"] = "replaying"
            stats = STAT_RE.findall(chunk)
            if stats:
                pkts, nbytes, secs = stats[-1]
                pkts, nbytes, secs = int(pkts), int(nbytes), float(secs)
                upd = _recompute(idx, pkts, nbytes, secs, loop)
                with RLOCK:
                    RSTATE.update(sent_packets=pkts, sent_bytes=nbytes, elapsed=secs, **upd)
            m = EXIT_RE.search(tail)
            if m:
                exit_code = int(m.group(1))
                break
        else:
            idle += 1
            with RLOCK:
                pid = RSTATE["pid"]
            gone = (proc is not None and proc.poll() is not None)
            if pid_seen and _pid_alive(pid) is False:
                gone = True
            if gone and idle > 5:                      # process finished and log drained
                break
            if idle > 7200:                            # ~48 min with no output at all
                _log("no output from tcpreplay for a long time — giving up on tracking.")
                break

    # The stop-file is the stop signal, whoever created it. replay.stop() sets
    # RSTATE["stopped"] as well, but the monitor window (and anyone typing `touch` in a
    # terminal) only creates the file -- and that is deliberate, because creating a file
    # needs no privileges. Without this check a stop from the failsafe window is reported
    # as "Replay failed", which is both wrong and alarming.
    sf = _RUN.get("stopfile")
    stopped_by_file = bool(sf and os.path.exists(sf))
    with RLOCK:
        if stopped_by_file and not RSTATE["stopped"]:
            RSTATE["stopped"] = True
            _outside_stop = True
        else:
            _outside_stop = False
        stopped = RSTATE["stopped"]
        reached_end = (RSTATE["total_packets"] > 0
                       and RSTATE["sent_packets"] >= RSTATE["total_packets"])
        RSTATE["running"] = False
        RSTATE["exit_code"] = exit_code
        if stopped:
            RSTATE["phase"] = "stopped"
            RSTATE["done"] = True
        elif exit_code == 0 or (exit_code is None and reached_end):
            RSTATE["phase"] = "done"
            RSTATE["done"] = True
            if RSTATE["total_packets"]:
                RSTATE["percent"] = 100.0
            RSTATE["remaining_packets"] = 0
            RSTATE["remaining_bytes"] = 0
            RSTATE["eta_seconds"] = 0
            RSTATE["capture_remaining"] = 0.0
        else:
            RSTATE["phase"] = "error"
            RSTATE["error"] = (
                f"tcpreplay exited with status {exit_code} before finishing "
                f"({RSTATE['sent_packets']:,} of {RSTATE['total_packets']:,} packets sent). "
                "See the log below." if exit_code not in (None,) else
                "tcpreplay stopped unexpectedly before finishing "
                f"({RSTATE['sent_packets']:,} of {RSTATE['total_packets']:,} packets sent). "
                "See the log below.")
    if _outside_stop:
        _log("stop requested from the monitor window.")
    _clear_runfile()                                   # the run is over; nothing to adopt
    with RLOCK:
        phase = RSTATE["phase"]
    _log({"stopped": "replay stopped by user.", "error": "replay failed."}.get(phase, "replay finished."))
    _finish_record(phase, exit_code, idx)


# ---------------------------------------------------------------------------
# the replay record: one small JSON per run, beside the capture
# ---------------------------------------------------------------------------
# It says what was replayed and how, so a later result can be tied to it. It holds only what the app
# already knows: file names (never paths), hashes taken from the capture's own manifest, the interface
# KIND (never its name), the options the person chose and their free-text label and note. It never
# holds a sensor address, key, token or any sensor-provider setting, and a failure's message is never
# copied in (it can carry paths), only a short class.

def _stem(path):
    return path[:-5] if path.endswith(".pcap") else path


def _read_json(path, cap=RECORD_MAX_BYTES):
    """A small JSON object from disk, or None (missing, too big, unreadable, not an object)."""
    try:
        if os.path.getsize(path) > cap:
            return None
        with open(path, "r", encoding="utf-8") as f:
            v = json.load(f)
    except (OSError, ValueError):
        return None
    return v if isinstance(v, dict) else None


def _hex64(v):
    return v if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) else None


def _sha256_file(path):
    if os.path.getsize(path) > HASH_CAP:
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def identify(pcap, compute=True):
    """What is known about the file being replayed: {file, capture, warnings}.

    A full capture takes its sha256 from the manifest beside it (when the manifest lists this file at this
    size); a slice cites its source capture and manifest from its own sidecar and is hashed itself.
    `compute=False` never reads the file's bytes (the sha256 stays None unless a manifest gave it).
    """
    name, size, stem = os.path.basename(pcap), os.path.getsize(pcap), _stem(pcap)
    file = {"name": name, "bytes": size, "sha256": None, "sha256_source": None, "slice": None, "packets": None}
    cap = {"pcap_name": name, "pcap_sha256": None, "manifest": None}
    warnings = []
    side = _read_json(stem + ".json")
    if side and side.get("kind") in ("A", "B", "C") and _hex64(side.get("source_pcap_sha256")):
        file["slice"] = {k: side[k] for k in ("kind", "scenario", "baseline", "kept_packets", "source_packets")
                         if isinstance(side.get(k), (str, int))}
        src = os.path.basename(str(side.get("source_pcap") or ""))
        cap = {"pcap_name": src or None, "pcap_sha256": side["source_pcap_sha256"],
               "manifest": {"name": _stem(src) + ".manifest.json" if src else None,
                            "manifest_sha256": _hex64(side.get("manifest_sha256"))}}
    else:
        m = _read_json(stem + ".manifest.json", cap=64 * 1024 * 1024)
        row = next((o for o in (m or {}).get("outputs", []) if isinstance(o, dict)
                    and os.path.basename(str(o.get("name"))) == name), None)
        if m and row and _hex64(row.get("sha256")):
            if row.get("bytes") == size:
                file["sha256"], file["sha256_source"] = row["sha256"], "manifest"
                cap["pcap_sha256"] = row["sha256"]
                cap["manifest"] = {"name": _stem(name) + ".manifest.json",
                                   "manifest_sha256": _hex64(m.get("manifest_sha256"))}
            else:
                warnings.append("the file's size differs from its manifest: it is not the file the manifest describes")
    if compute and file["sha256"] is None:
        file["sha256"] = _sha256_file(pcap)
        file["sha256_source"] = "computed" if file["sha256"] else None
        if file["sha256"] is None:
            warnings.append("the file is too large to hash here: no sha256 recorded")
        if cap["pcap_sha256"] is None and file["slice"] is None:
            cap["pcap_sha256"] = file["sha256"]
    return {"file": file, "capture": cap, "warnings": warnings}


def record_path(pcap, rid):
    if not _ID_RE.fullmatch(rid or ""):
        raise ValueError("not a replay id")
    return "%s.replay-%s.json" % (_stem(pcap), rid)


def read_record(pcap, rid):
    """The stored record for `rid` beside `pcap`, or None."""
    rec = _read_json(record_path(pcap, rid))
    return rec if rec and rec.get("kind") == "replay" and isinstance(rec.get("replay"), dict) else None


def resume_point(rec):
    """{resumable, next_packet, reason} for a stored record: the next packet a stopped run did not send."""
    r = rec.get("replay") or {}
    if r.get("ended") == "finished":
        return {"resumable": False, "next_packet": None, "reason": "that run finished"}
    if r.get("loop") != 1:
        return {"resumable": False, "next_packet": None, "reason": "only a single pass (loop 1) can be resumed"}
    off, total = r.get("stop_offset_packets"), (r.get("file") or {}).get("packets")
    inc = r.get("include")
    last = min(x for x in (total, (inc or {}).get("end")) if x) if (total or (inc or {}).get("end")) else None
    if not isinstance(off, int) or last is None:
        return {"resumable": False, "next_packet": None, "reason": "the run's position is not known"}
    if off >= last:
        return {"resumable": False, "next_packet": None, "reason": "every packet was already sent"}
    return {"resumable": True, "next_packet": off + 1, "reason": ""}


def _resolve_resume(pcap, o):
    """Turn resume_from into the include range and the `resumed_from` block. RuntimeError when it cannot."""
    prev = read_record(pcap, o["resume_from"])
    if prev is None:
        raise RuntimeError("no record of that replay was found beside this capture")
    rp = resume_point(prev)
    if not rp["resumable"]:
        raise RuntimeError("cannot resume: " + rp["reason"])
    now, was = identify(pcap, compute=False)["file"], (prev["replay"].get("file") or {})
    if now["name"] != was.get("name") or now["bytes"] != was.get("bytes") or \
            (now["sha256"] and was.get("sha256") and now["sha256"] != was["sha256"]):
        raise RuntimeError("cannot resume: the file is not the one that run replayed")
    nxt = rp["next_packet"]
    start = max(1, nxt - o["overlap_packets"])
    end = ((prev["replay"].get("include") or {}).get("end"))
    return ({"start": start, "end": end},
            {"replay_id": o["resume_from"], "from_packet": nxt, "start_packet": start,
             "overlap_packets": nxt - start, "continuous_1x": False,
             "statement": "a resumed run is not a continuous 1x run"})


def list_records(pcap):
    """Summaries of the records beside `pcap`, oldest first, each with its resume point and a stale flag."""
    base, out = _stem(pcap), []
    d = os.path.dirname(os.path.abspath(pcap))
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return out
    prefix = os.path.basename(base) + ".replay-"
    cur = identify(pcap, compute=False) if os.path.isfile(pcap) else None
    for n in names:
        m = re.fullmatch(re.escape(prefix) + r"([0-9a-f]{12})\.json", n)
        rec = read_record(pcap, m.group(1)) if m else None
        if not rec:
            continue
        r = rec["replay"]
        was = (r.get("file") or {}).get("sha256")
        now = cur["file"]["sha256"] if cur else None
        out.append({"id": r.get("id"), "ended": r.get("ended"), "start_epoch": r.get("start_epoch"),
                    "sent_packets": r.get("sent_packets"), "sensor_label": r.get("sensor_label"),
                    "resumed_from": r.get("resumed_from"), "resume": resume_point(rec),
                    "stale": bool(was and now and was != now), "name": n})
    return sorted(out, key=lambda x: x.get("start_epoch") or 0)


def _begin_record(pcap, iface, write_to, idx, loop, speed_mode, speed_value, o):
    """The per-run facts the record will be built from. Hashing happens here, in the run thread."""
    ident = identify(pcap)
    ident["file"]["packets"] = idx["packets"] if idx["exact"] else None
    inc = o.get("include")
    first = inc["start"] if inc else 1
    last = None
    if idx["exact"]:
        last = min(inc["end"], idx["packets"]) if inc and inc.get("end") else idx["packets"]
        if first > idx["packets"]:
            raise RuntimeError("the packet range starts after the last packet (%d)" % idx["packets"])
    kind = "file" if write_to else (interfaces_detail([iface])[0]["kind"] if iface else None)
    return {"id": o["id"], "pcap_path": pcap, "file": ident["file"], "capture": ident["capture"],
            "warnings": ident["warnings"],
            "speed": {"mode": speed_mode, "value": speed_value, "maxsleep_ms": o.get("maxsleep_ms")},
            "include": inc, "loop": int(loop), "rebase_seconds": o.get("rebase_seconds", 0),
            "interface_kind": kind, "sensor_label": o.get("sensor_label", ""), "note": o.get("note", ""),
            "resumed_from": o.get("resumed_from"), "first_packet": first, "last_packet": last,
            "start_epoch": None}


def _finish_record(phase, exit_code, idx, reason=None):
    """Write the record for the run that just ended (once). Never raises: a record must not fail a replay."""
    ctx, _RUN["rec"] = _RUN.get("rec"), None
    if not ctx or not ctx.get("start_epoch"):
        return                                         # nothing was launched (cancelled, tool missing): no traffic, no record
    with RLOCK:
        sent = int(RSTATE["sent_packets"])
    first, last, loop = ctx["first_packet"], ctx["last_packet"], ctx["loop"]
    start_off, stop_off = first - 1, None
    if last is not None:
        n = last - first + 1
        stop_off = last if sent >= n * loop else start_off + sent % n
    marks = (idx or {}).get("marks") or []
    ended = {"done": "finished", "stopped": "stopped"}.get(phase, "error")
    r = {"id": ctx["id"], "capture": ctx["capture"], "file": ctx["file"], "speed": ctx["speed"],
         "include": ctx["include"], "loop": loop, "rebase_seconds": ctx["rebase_seconds"],
         "interface_kind": ctx["interface_kind"], "start_epoch": ctx["start_epoch"], "stop_epoch": time.time(),
         "start_offset_packets": start_off, "stop_offset_packets": stop_off,
         "start_capture_ts": ts_at_packet(marks, start_off) if sent else None,
         "stop_capture_ts": ts_at_packet(marks, stop_off - 1) if marks and stop_off else None,
         "sent_packets": sent, "ended": ended,
         "error_class": None if ended != "error" else (reason or ("tcpreplay_exit_%d" % exit_code if exit_code is not None
                                                                  else "tracking_lost")),
         "resumed_from": ctx["resumed_from"],
         "continuous_1x": (ctx["resumed_from"] is None and ctx["speed"]["mode"] == "multiplier"
                           and ctx["speed"]["value"] == 1.0 and ctx["speed"]["maxsleep_ms"] is None
                           and ctx["include"] is None),
         "sensor_label": ctx["sensor_label"], "note": ctx["note"], "warnings": ctx["warnings"]}
    path = record_path(ctx["pcap_path"], ctx["id"])
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".replay-record-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"record_version": RECORD_VERSION, "kind": "replay", "replay": r}, f, indent=2)
                f.write("\n")
            os.chmod(tmp, 0o644)                       # mkstemp makes 0600; the record sits beside the capture
            os.replace(tmp, path)
        except BaseException:
            os.unlink(tmp)
            raise
    except OSError as e:
        _log("could not write the replay record (%s)." % (e.strerror or "I/O error"))
        with RLOCK:
            RSTATE["record_error"] = "the replay record could not be written beside the capture"
        return
    with RLOCK:
        RSTATE["record"] = os.path.basename(path)
    _log("replay record written: " + os.path.basename(path))


def _run(pcap, iface, speed_mode, speed_value, loop, speed_desc, write_to=None,
         privileged=True, preload=False, monitor=True, opts=None):
    opts = opts or {}
    idx = None
    try:
        tcpreplay = find_tool("tcpreplay")
        if not tcpreplay:
            raise RuntimeError("'tcpreplay' was not found. Install it with: %s"
                               % install_hint("tcpreplay"))
        if privileged:                                 # it will run as root: only from a root-trusted location
            safe = privileged_tool("tcpreplay", tcpreplay)
            if not safe:
                why = root_check(tcpreplay) or "no root-owned copy was found in the usual places"
                if "library" in why:                           # a root-owned copy would load the same libraries: the copy hint would mislead
                    raise RuntimeError(
                        "tcpreplay was found at %s, but %s, so it will not be run as root. Install a build whose libraries are "
                        "all root-owned (MacPorts: sudo port install tcpreplay) or a statically linked one, or run the app as root."
                        % (tcpreplay, why))
                raise RuntimeError(
                    "tcpreplay was found at %s, but %s, so it will not be run as root. Put a root-owned copy where it can be trusted: %s"
                    % (tcpreplay, why, root_copy_hint(tcpreplay)))
            tcpreplay = safe
        elev = None                                    # Linux elevation decision (None: macOS / root / test path)
        if privileged and os.geteuid() != 0 and sys.platform.startswith("linux"):
            elev = linux_elevation(tcpreplay)
            if not elev["ok"]:
                raise RuntimeError(elev["message"])
            with RLOCK:
                RSTATE.update(elevation=elev["mode"], stoppable=elev["stoppable"])

        _log(f"indexing {os.path.basename(pcap)} …")
        idx = index_pcap(pcap)
        with RLOCK:
            RSTATE.update(total_packets=(idx["packets"] or 0) * max(1, int(loop or 1)),
                          total_bytes=(idx["bytes"] or 0) * max(1, int(loop or 1)),
                          capture_duration=idx["duration"], exact=idx["exact"],
                          remaining_packets=(idx["packets"] or 0) * max(1, int(loop or 1)),
                          remaining_bytes=(idx["bytes"] or 0) * max(1, int(loop or 1)))
            if idx["first_ts"]:
                RSTATE["capture_start"] = time.strftime("%H:%M:%S", time.localtime(idx["first_ts"]))
                RSTATE["capture_end"] = time.strftime("%H:%M:%S", time.localtime(idx["last_ts"]))
                RSTATE["capture_remaining"] = idx["duration"]
        if idx["exact"]:
            _log(f"{idx['packets']:,} packets, {idx['bytes']/1e6:.1f} MB, "
                 f"{idx['duration']/3600:.2f} h of capture time.")
            if idx.get("truncated"):
                _log("warning: the file ends with a truncated record; replaying what is complete.")
            if idx["linktype"] not in (1, None):
                _log(f"warning: link-layer type {idx['linktype']} is not Ethernet.")
        else:
            _log("pcapng: exact packet totals unavailable, progress is estimated.")

        ctx = _begin_record(pcap, iface, write_to, idx, loop, speed_mode, speed_value, opts)
        _RUN["rec"] = ctx
        if opts.get("include") and idx["exact"]:           # progress counts the chosen range, not the whole file
            n = ctx["last_packet"] - ctx["first_packet"] + 1
            idx = dict(idx, packets=n, bytes=0, offset=ctx["first_packet"] - 1)
            with RLOCK:
                RSTATE.update(total_packets=n * max(1, int(loop or 1)), total_bytes=0,
                              remaining_packets=n * max(1, int(loop or 1)), remaining_bytes=0)

        base = _state_dir(create=True)
        _prune_old_runs(base)
        rundir = tempfile.mkdtemp(prefix="nwtg-replay-", dir=base)      # 0700, ours, exclusive
        stopfile = os.path.join(rundir, "STOP")
        root_logdir = None
        if elev is None and privileged and os.geteuid() != 0 and sys.platform == "darwin":
            root_logdir = _root_log_dir(os.geteuid(), (opts.get("id") or os.urandom(6).hex()))
            logfile = os.path.join(root_logdir, "tcpreplay.log")        # root creates and writes it, we only read
        else:
            logfile = os.path.join(rundir, "tcpreplay.log")
            os.close(os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        _RUN.update(dir=rundir, logfile=logfile, stopfile=stopfile, proc=None)
        with RLOCK:
            stopped_early = RSTATE["stopped"]
        if stopped_early:                              # Stop (or shutdown) arrived while the capture was being indexed
            with RLOCK:
                RSTATE.update(running=False, done=True, phase="stopped")
            _log("stopped before the replay began; nothing was sent.")
            return
        # Written BEFORE launch: if the server dies between here and the first log line,
        # the next process can still find the stop-file and shut the replay down.
        with RLOCK:
            runinfo = dict(dir=rundir, logfile=logfile, stopfile=stopfile, pcap=pcap,
                           iface=iface, speed=speed_desc, loop=loop, idx=idx, rec=ctx,
                           total_packets=RSTATE["total_packets"],
                           total_bytes=RSTATE["total_bytes"],
                           capture_duration=RSTATE["capture_duration"],
                           exact=RSTATE["exact"], capture_start=RSTATE["capture_start"],
                           capture_end=RSTATE["capture_end"], started=RSTATE["started"])
            _write_runfile(**runinfo)

        stats = 1
        if sys.platform.startswith("linux") and not tcpreplay_has_stats(_run_text([tcpreplay, "--help"], 5)):
            stats = 0
            _log("this tcpreplay has no --stats: progress is not shown; the result is reported at the end.")
        argv = build_argv(tcpreplay, pcap, iface, speed_mode, speed_value, loop, stats_every=stats,
                          preload=preload, write_to=write_to, maxsleep_ms=opts.get("maxsleep_ms"),
                          include=opts.get("include"))
        if elev:
            argv = elev["prefix"] + argv
        _log("$ " + " ".join(shlex.quote(a) for a in argv))
        inner = _inner_script(argv, logfile, stopfile, root_logdir)

        proc = None
        if elev is None and privileged and os.geteuid() != 0:
            if sys.platform != "darwin":
                raise RuntimeError(
                    "Replay needs root. Automatic elevation is implemented for macOS only — "
                    "restart the server with sudo on this platform.")
            with RLOCK:
                RSTATE["phase"] = "prompting"
            _log("requesting administrator authorization (macOS will prompt) …")
            _launch_privileged(inner)
            if not _wait_for_file(logfile, 15):
                raise RuntimeError("the administrator helper did not start tcpreplay (no log appeared).")
        else:
            if elev and elev["mode"] == "pkexec":
                with RLOCK:
                    RSTATE["phase"] = "prompting"
                _log("requesting administrator authorization (a system dialog will prompt) …")
            elif elev:
                _log("elevation: %s." % elev["mode"])
            proc = _launch_unprivileged(inner)
            _RUN["proc"] = proc
        ctx["start_epoch"] = time.time()                # after any password prompt: the moment traffic began
        _write_runfile(**dict(runinfo, rec=ctx))
        with RLOCK:
            RSTATE["phase"] = "replaying"
        _log("tcpreplay started.")
        if monitor:
            try:
                mpath = _monitor_script(rundir, logfile, stopfile, pcap,
                                        iface or "(file)", speed_desc, loop)
                if _open_monitor_window(mpath):
                    _log("monitor window opened — Control-C there stops the replay "
                         "even if this application is closed.")
                else:
                    _log("could not open the monitor window; the replay is unaffected.")
            except OSError as e:                       # a failsafe must never be the thing that fails
                _log(f"could not create the monitor window ({e}); the replay is unaffected.")
        _watch(logfile, idx, loop, proc)
    except Exception as e:                             # noqa: BLE001 - worker failure is recorded in replay state and shown to the user
        import traceback
        with RLOCK:
            RSTATE.update(running=False, done=False, phase="error", error=str(e))
        _log(traceback.format_exc().strip())
        _finish_record("error", None, idx, reason="run_failed")


def start(pcap, iface, write_to=None, privileged=True, **options):
    """Begin a replay. Raises if one is already running, an option is invalid (ValueError) or preflight fails.

    `options` are the human's raw choices (speed_mode, speed_value, loop, preload, monitor, maxsleep_ms,
    include, resume_from, overlap_packets, rebase_seconds, sensor_label, note); parse_options checks them all.
    """
    o = parse_options(options)
    pcap = os.path.abspath(os.path.expanduser(pcap or ""))
    with RLOCK:                                        # check-and-claim atomically; roll back below on failure
        if RSTATE["running"]:
            raise RuntimeError("a replay is already in progress")
        RSTATE["running"] = True
    try:
        pre = preflight(pcap, None if write_to else iface)
        if not pre["ok"]:
            raise RuntimeError("; ".join(pre["errors"]))
        if o["resume_from"]:
            if pre["pcap"]["format"] != "pcap":
                raise RuntimeError("cannot resume a pcapng file: packet numbers are not known")
            o["include"], o["resumed_from"] = _resolve_resume(pcap, o)
        else:
            o["resumed_from"] = None
        if o["include"] and pre["pcap"]["format"] != "pcap":
            raise RuntimeError("a packet range needs a classic pcap file")
    except BaseException:
        with RLOCK:
            RSTATE["running"] = False
        raise

    mode, value = o["speed_mode"], o["speed_value"]
    desc = {"pps": f"{value:g} pps", "mbps": f"{value:g} Mbps"}.get(mode, f"{value:g}x original timing")
    if o["maxsleep_ms"]:
        desc += f", idle gaps capped at {o['maxsleep_ms']} ms"
    if o["include"]:
        desc += ", packets %d-%s" % (o["include"]["start"], o["include"]["end"] or "end")
    o["id"] = os.urandom(6).hex()
    _reset(pcap, iface, desc, o["loop"])
    with RLOCK:
        RSTATE.update(replay_id=o["id"], resumed_from=o["resumed_from"])
    t = threading.Thread(target=_run, args=(pcap, iface, mode, value, o["loop"], desc),
                         kwargs={"write_to": write_to, "privileged": privileged,
                                 "preload": o["preload"], "monitor": o["monitor"], "opts": o}, daemon=True)
    _RUN["thread"] = t
    t.start()
    return {"ok": True, "pcap": pcap, "iface": iface, "speed": desc, "replay_id": o["id"],
            "resumed_from": o["resumed_from"]}


def stop():
    """Ask the privileged watcher to terminate tcpreplay (no second password prompt)."""
    with RLOCK:
        if not RSTATE["running"]:
            return {"ok": False, "error": "no replay is running"}
        if not RSTATE["stoppable"]:
            return {"ok": False, "error": "this replay was started with an administrator prompt and cannot be "
                                          "stopped without a second one; it ends when the capture finishes"}
        RSTATE["stopped"] = True
        RSTATE["phase"] = "stopping"
    sf = _RUN.get("stopfile")
    if sf:
        try:
            os.close(os.open(sf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600))
        except FileExistsError:
            pass                                       # a stop was already requested (the monitor window, or twice)
        except OSError as e:
            return {"ok": False, "error": f"could not signal stop: {e}"}
    _log("stop requested …")
    return {"ok": True}


def status():
    with RLOCK:
        s = dict(RSTATE)
    s["elapsed_wall"] = int(time.time() - s["started"]) if s["started"] else 0
    return s


# ---------------------------------------------------------------------------
# self-test: exercises the whole pipeline with -w /dev/null (no interface, no root)
# ---------------------------------------------------------------------------

def _self_test(pcap, seconds=6, stop_after=None):
    print(f"preflight: {json.dumps(preflight(pcap), indent=1, default=str)[:600]} …\n")
    start(pcap, iface="", speed_mode="pps", speed_value=120000, loop=1,
          write_to="/dev/null", privileged=False)
    t0 = time.time()
    while time.time() - t0 < seconds:
        time.sleep(1.0)
        if stop_after and time.time() - t0 >= stop_after:
            stop_after = None
            print("  -> requesting stop")
            stop()
        s = status()
        print(f"  [{s['phase']:>9}] {s['percent']:5.1f}%  sent {s['sent_packets']:>9,}/"
              f"{s['total_packets']:,}  remain {s['remaining_packets']:>9,}  "
              f"clock {s['capture_clock'] or '—'}  eta "
              f"{'—' if s['eta_seconds'] is None else format(s['eta_seconds'], '.1f')}s")
        if not s["running"]:
            break
    s = status()
    print(f"\nfinal phase={s['phase']} error={s['error']} exit={s['exit_code']} "
          f"sent={s['sent_packets']:,}/{s['total_packets']:,} pct={s['percent']:.1f}")
    return 0 if s["phase"] in ("done", "stopped") else 1


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "--self-test":
        secs = float(sys.argv[3]) if len(sys.argv) > 3 else 6
        sys.exit(_self_test(sys.argv[2], secs))
    print(json.dumps(preflight(sys.argv[1] if len(sys.argv) > 1 else None), indent=1))

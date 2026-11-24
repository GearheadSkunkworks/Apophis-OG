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
import json
import mmap
import os
import re
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

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


def _brew_prefixes():
    ps = [os.environ.get("HOMEBREW_PREFIX"), "/opt/homebrew", "/usr/local"]
    return [p for p in ps if p and os.path.isdir(p)]


def root_safe(path, prefixes=None):
    """True when `path` may be executed as root: its real file and the parent dir are root-owned
    (or owned by the owner of the package-manager prefix the real path lives in) and neither is
    group/world-writable. A user-writable ~/.local/bin/tcpreplay therefore never qualifies."""
    try:
        real = os.path.realpath(path)
        pst, dst = os.stat(real), os.stat(os.path.dirname(real))
    except OSError:
        return False
    owners = {0}
    for p in (_brew_prefixes() if prefixes is None else prefixes):
        rp = os.path.realpath(p)
        if real.startswith(rp + os.sep):
            owners.add(os.stat(rp).st_uid)
    return all(st.st_uid in owners and not st.st_mode & 0o022 for st in (pst, dst))


def privileged_tool(name, found=None, fallback_dirs=("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"),
                    prefixes=None):
    """The path to run as root for `name`: `found` if root_safe, else the first safe fallback, else None."""
    found = found or find_tool(name)
    if found and root_safe(found, prefixes):
        return found
    for d in fallback_dirs:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK) and root_safe(cand, prefixes):
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


def tool_version(path):
    """First meaningful line of `<tool> --version` (tcpreplay prints a root warning first)."""
    try:
        r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10)
        for line in (r.stdout + "\n" + r.stderr).splitlines():
            line = line.strip()
            if line and not line.lower().startswith("warning"):
                return line
    except Exception:                                  # noqa: BLE001
        pass
    return ""


def list_interfaces():
    """Interfaces available for replay, likely-physical ones first."""
    try:
        names = [n for _i, n in socket.if_nameindex()]
    except Exception:                                  # noqa: BLE001
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
    except Exception:                                  # noqa: BLE001
        return ""


def _read_sys(name, leaf):
    try:
        with open("/sys/class/net/%s/%s" % (name, leaf)) as f:
            return f.read().strip()
    except Exception:                                  # noqa: BLE001
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
            kind = classify_linux(name, int(t) if t and t.isdigit() else None,
                                  "/sys/devices/virtual" in real,
                                  os.path.isdir("/sys/class/net/%s/wireless" % name))
            st = _read_sys(name, "operstate")
            link_up = True if st == "up" else (False if st in ("down", "lowerlayerdown") else None)
            sp = _read_sys(name, "speed")
            speed = format_speed(sp) if sp and sp.lstrip("-").isdigit() else None
    except Exception:                                  # noqa: BLE001
        kind, link_up, speed = "other", None, None
    return {"name": name, "label": interface_label(name, kind, link_up, speed),
            "kind": kind, "link_up": link_up, "speed": speed, "recommended": False}


def interfaces_detail(names=None):
    """Labelled interfaces: [{name,label,kind,link_up,speed,recommended}]. Never raises."""
    try:
        names = list_interfaces() if names is None else names
        hw = parse_hardware_ports(_run_text(["networksetup", "-listallhardwareports"])) \
            if sys.platform == "darwin" else {}
        out = [_probe_one(n, hw) for n in names]
        rec = pick_recommended(out)
        for d in out:
            d["recommended"] = d["name"] == rec
        return out
    except Exception:                                  # noqa: BLE001
        return [{"name": n, "label": n, "kind": "other", "link_up": None, "speed": None,
                 "recommended": False} for n in (names or [])]


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------

def preflight(pcap=None, iface=None):
    """Check every dependency up front and report precisely what is missing."""
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

    if sys.platform not in ("darwin",) and os.geteuid() != 0:
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

    if iface and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,31}", iface):       # even when listing interfaces fails
        report["errors"].append("That is not a valid interface name.")
    elif iface:
        names = report["interfaces"]
        if names and iface not in names:
            report["errors"].append(f"Interface '{iface}' does not exist. Available: {', '.join(names)}")
        elif iface.startswith("lo"):
            report["warnings"].append(
                "Loopback is only useful as a smoke test — a sensor will not see this traffic.")

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
}
RLOCK = threading.Lock()
_RUN = {"dir": None, "stopfile": None, "logfile": None, "proc": None, "thread": None}

# A replay outlives this process. tcpreplay is launched detached and root-owned
# (`nohup ... &` under osascript), so restarting the server leaves it running with the
# stop-file path -- the only unprivileged handle on it -- known to nobody. RUNFILE is that
# path written down, so a fresh process can find the run again, resume tracking it, and
# still stop it without a second password prompt.
RUNFILE = os.path.join(tempfile.gettempdir(), "nwtg-replay-current.json")


def _write_runfile(**info):
    """Record the in-flight run. Best effort: failing to write must not fail the replay."""
    try:
        with open(RUNFILE, "w") as f:
            json.dump(info, f)
    except OSError:
        pass


def _clear_runfile():
    try:
        os.remove(RUNFILE)
    except OSError:
        pass


def _read_runfile():
    try:
        with open(RUNFILE) as f:
            info = json.load(f)
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
    _RUN.update(dir=info.get("dir"), logfile=logfile, stopfile=stopfile, proc=None)
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
                      rate_pps=0.0, rate_mbps=0.0, log=[], exit_code=None, started=time.time())


# ---------------------------------------------------------------------------
# launching
# ---------------------------------------------------------------------------

def build_argv(tcpreplay, pcap, iface, speed_mode="multiplier", speed_value=1.0, loop=1,
               stats_every=1, preload=False, write_to=None):
    """Assemble the tcpreplay command line.

    -P prints the PID at startup and --stats gives periodic progress; both are what the
    progress tracker reads.
    """
    argv = [tcpreplay, "-P", f"--stats={int(stats_every)}"]
    if speed_mode == "topspeed":
        argv.append("--topspeed")
    elif speed_mode == "pps":
        argv.append(f"--pps={speed_value}")
    elif speed_mode == "mbps":
        argv.append(f"--mbps={speed_value}")
    else:
        argv.append(f"--multiplier={speed_value}")
    if loop and int(loop) != 1:
        argv.append(f"--loop={int(loop)}")
    if preload:
        argv.append("--preload-pcap")
    if write_to:                                       # test path: no interface, no root
        argv += ["-w", write_to]
    else:
        argv += ["-i", iface]
    argv.append(pcap)
    return argv


def _inner_script(argv, logfile, stopfile):
    """Shell run as root: start tcpreplay, plus a watcher that honours the stop-file.

    The watcher means "Stop" does not need a second authorization prompt — creating the
    stop-file is an ordinary unprivileged write.
    """
    cmd = " ".join(shlex.quote(a) for a in argv)
    log, stop = shlex.quote(logfile), shlex.quote(stopfile)
    return (
        f"{cmd} > {log} 2>&1 &\n"
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
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o755)
    return path


def _open_monitor_window(script_path):
    """Show the monitor in Terminal. Never let a failed window fail the replay.

    `open -a Terminal <script>` goes through LaunchServices, not Apple Events, so it does
    NOT trigger an Automation (TCC) consent prompt the way `osascript -e 'tell app
    "Terminal"'` would. That matters: this runs unattended right after the admin prompt,
    and a second permission dialog there would be baffling.
    """
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
        ts = ts_at_packet(idx["marks"], in_loop)
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


def _run(pcap, iface, speed_mode, speed_value, loop, speed_desc, write_to=None,
         privileged=True, preload=False, monitor=True):
    try:
        tcpreplay = find_tool("tcpreplay")
        if not tcpreplay:
            raise RuntimeError("'tcpreplay' was not found. Install it with: %s"
                               % install_hint("tcpreplay"))
        if privileged:                                 # it will run as root: only from a root-trusted location
            safe = privileged_tool("tcpreplay", tcpreplay)
            if not safe:
                raise RuntimeError(
                    "tcpreplay was found at %s, but that location is writable by non-administrators, so it "
                    "will not be run as root. Install it with: %s" % (tcpreplay, install_hint("tcpreplay")))
            tcpreplay = safe

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

        rundir = tempfile.mkdtemp(prefix="nwtg-replay-")
        logfile = os.path.join(rundir, "tcpreplay.log")
        stopfile = os.path.join(rundir, "STOP")
        open(logfile, "w").close()
        _RUN.update(dir=rundir, logfile=logfile, stopfile=stopfile, proc=None)
        # Written BEFORE launch: if the server dies between here and the first log line,
        # the next process can still find the stop-file and shut the replay down.
        with RLOCK:
            _write_runfile(dir=rundir, logfile=logfile, stopfile=stopfile, pcap=pcap,
                           iface=iface, speed=speed_desc, loop=loop, idx=idx,
                           total_packets=RSTATE["total_packets"],
                           total_bytes=RSTATE["total_bytes"],
                           capture_duration=RSTATE["capture_duration"],
                           exact=RSTATE["exact"], capture_start=RSTATE["capture_start"],
                           capture_end=RSTATE["capture_end"], started=RSTATE["started"])

        argv = build_argv(tcpreplay, pcap, iface, speed_mode, speed_value, loop,
                          preload=preload, write_to=write_to)
        _log("$ " + " ".join(shlex.quote(a) for a in argv))
        inner = _inner_script(argv, logfile, stopfile)

        proc = None
        if privileged and os.geteuid() != 0:
            if sys.platform != "darwin":
                raise RuntimeError(
                    "Replay needs root. Automatic elevation is implemented for macOS only — "
                    "restart the server with sudo on this platform.")
            with RLOCK:
                RSTATE["phase"] = "prompting"
            _log("requesting administrator authorization (macOS will prompt) …")
            _launch_privileged(inner)
        else:
            proc = _launch_unprivileged(inner)
            _RUN["proc"] = proc
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
    except Exception as e:                             # noqa: BLE001
        import traceback
        with RLOCK:
            RSTATE.update(running=False, done=False, phase="error", error=str(e))
        _log(traceback.format_exc().strip())


def start(pcap, iface, speed_mode="multiplier", speed_value=1.0, loop=1, preload=False,
          write_to=None, privileged=True, monitor=True):
    """Begin a replay. Raises if one is already running or preflight fails."""
    pcap = os.path.abspath(os.path.expanduser(pcap or ""))
    with RLOCK:                                        # check-and-claim atomically; roll back below on failure
        if RSTATE["running"]:
            raise RuntimeError("a replay is already in progress")
        RSTATE["running"] = True
    try:
        pre = preflight(pcap, None if write_to else iface)
        if not pre["ok"]:
            raise RuntimeError("; ".join(pre["errors"]))
    except BaseException:
        with RLOCK:
            RSTATE["running"] = False
        raise

    desc = {"topspeed": "top speed", "pps": f"{speed_value} pps", "mbps": f"{speed_value} Mbps"}.get(
        speed_mode, f"{speed_value}x original timing")
    _reset(pcap, iface, desc, loop)
    t = threading.Thread(target=_run, args=(pcap, iface, speed_mode, speed_value, loop, desc),
                         kwargs={"write_to": write_to, "privileged": privileged,
                                 "preload": preload, "monitor": monitor}, daemon=True)
    _RUN["thread"] = t
    t.start()
    return {"ok": True, "pcap": pcap, "iface": iface, "speed": desc}


def stop():
    """Ask the privileged watcher to terminate tcpreplay (no second password prompt)."""
    with RLOCK:
        if not RSTATE["running"]:
            return {"ok": False, "error": "no replay is running"}
        RSTATE["stopped"] = True
        RSTATE["phase"] = "stopping"
    sf = _RUN.get("stopfile")
    if sf:
        try:
            open(sf, "w").close()
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

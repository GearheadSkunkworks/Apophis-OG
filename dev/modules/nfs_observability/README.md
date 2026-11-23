# nfs_observability — a capability module for OpenGenerator

A loadable module that paints a **healthy, all-day NFS file-sharing environment** into a generated
capture, so a network sensor (such as a commercial network detection platform) can demonstrate NFS observability on a
normal, non-anomalous day. It is also the project's **reference example** for the most capable kind
of module — one that introduces new systems, speaks a protocol the baseline does not, and adds its
own category to the interface — all without ever changing the pinned baseline.

> **New to writing modules?** Read **[TUTORIAL.md](TUTORIAL.md)** next. It teaches how this module
> is built, line of reasoning by line of reasoning, assuming no prior Python or networking
> knowledge, so you can build your own.

---

## What it adds to a capture

When its scenario is **selected** for a build, this module:

- **Introduces 7 new systems**
  - 6 Windows workstations on the user network — `EXL-WS-076` … `EXL-WS-081`
  - 1 Linux NFS file server on the server network — `EXL-NFS1`
  - All are named and addressed to match the environment's existing convention, and they rename
    automatically if you build under a different company name.
- **Generates realistic NFSv3 traffic all day long, in both directions**
  - Workstations **download** files from the server (NFS `READ`) and **upload** files to it
    (NFS `CREATE` + `WRITE` + `COMMIT`), over TCP port 2049.
  - The files transferred are **real, valid files** — a PNG image, a PDF, an Excel `.xlsx`, a CSV,
    and a ZIP archive. Their **names** and their **contents** both travel on the wire, so a sensor
    can identify the file type, read its name, and reconstruct ("carve") the actual file.
- **Adds the ordinary supporting traffic** those systems would produce on a working day
  - Windows logons (Kerberos + LDAP to the domain controller), DNS lookups, NTP time sync, DHCP
    address leases, and some SMB file access.
- **Adds a new interface category — "Standard"** (tag `STD`), grouping healthy, no-anomaly traffic
  separately from the Security / Performance / Crypto / OT scenario categories.

Everything is **healthy**: there is no fault, slowdown, or attack. The module exists only to show
what a normal NFS ecosystem looks like to a sensor.

---

## The one firm guarantee

**This module never alters the baseline.** The project's no-scenario baseline is pinned to exactly
**466,343 packets**, and that number is sacred. This module only ever *adds* traffic *on top* of the
baseline, and only when you actively select it:

- Module **not loaded** → baseline is 466,343.
- Module **loaded but not selected** → baseline is still exactly 466,343.
- Module **selected** → baseline 466,343 **plus** the NFS environment on top (about +9,434 packets
  at the regression scale, scaling up with the build scale).

The guarantee holds **by construction**: the new systems and their traffic are created inside the
scenario, *after* the normal day has already been generated, so the baseline is never disturbed (the
tutorial explains *how*). The module's own self-test confirms NFS appears on the wire only when the
scenario is selected; the exact 466,343 figure is verified separately by the `baseline_pin` module
and the project's regression suite.

---

## How to use it

### In the graphical interface
1. Open the **Capability modules** panel (inside the "What gets built" card).
2. Find **nfs_observability** and click **Load**. (Tick **auto-load on startup** to keep it loaded
   across restarts.)
3. Scroll to **Choose scenarios**. A new **Standard** category appears, containing
   *"Standard NFS file-share activity (healthy, all-day) + 7 new systems."* Tick it.
4. Click **Generate**. The resulting capture contains the normal business day plus the NFS
   environment.

### Headless (from a Python script)
Capability modules are loaded by the server/GUI, not by the plain command-line builder, so to use
this module without the interface you load it through the capability kernel first, then build with
its scenario selected:
```bash
cd dev
python3 - <<'PY'
from netgen import platform as cap
import opengenerator_build as OGB
k = cap.Kernel(); k.discover(); k.load("nfs_observability")   # load the module
OGB.build(scale=0.05, out="nfs-demo.pcap", modules=["std-nfs-observability"])
PY
```

### What to look for in the result
- Traffic on **TCP port 2049** between the six new workstations and `EXL-NFS1`.
- Seven new devices (`EXL-WS-076`…`081`, `EXL-NFS1`) once the sensor classifies the capture.
- In the sensor's NFS records / file analysis: the filenames (`onboarding-guide.pdf`,
  `q3-forecast.xlsx`, `network-topology.png`, `team-roster.csv`, `project-archive.zip`) and the
  files themselves, carried in both reads and writes.

---

## Files in this module

| File | What it is |
|------|------------|
| `manifest.json` | The module's identity card: its name, version, kind (`scenario`), and description. The platform reads this to list the module. |
| `__init__.py` | The module itself — all the code: the new systems, the NFS traffic, the sample files, the registration, and the self-test. |
| `README.md` | This overview. |
| `TUTORIAL.md` | A from-scratch teaching walkthrough for building your own module. |

---

## Where to change things

All of these live in `__init__.py` and are called out in the tutorial:

- **How many workstations / their names and addresses** — the `_WORKSTATIONS` list and `_NFS_IP`
  near the top.
- **Which files are transferred** — the `_sample_files()` routine.
- **How much traffic / how it's spread across the day** — the `n_ops` and `gap` values in `_build`.
- **Which supporting protocols** the hosts use — the scheduled calls in `_build`.

---

## Compatibility

- Works with the default company and with any custom company name/industry (hostnames and domains
  follow the chosen identity automatically).
- Respects the build `--scale`: small scales produce a light but present NFS day; full scale
  produces a busy one.
- Requires nothing beyond the engine itself (no extra Python packages).

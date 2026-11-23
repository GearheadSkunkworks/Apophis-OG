# Build your own OpenGenerator module — a complete, from-scratch tutorial

This tutorial teaches you how to build a capability module for OpenGenerator by taking apart a real
one, **`nfs_observability`**, piece by piece. It assumes you have **never written Python** and have
**never used a software library**. Wherever a programming idea shows up, it is explained in plain
language before it is used. By the end you will understand every important part of this module and
be able to build your own.

Take it slowly. You do not need to memorize anything — you need to understand what each piece is
*for*. The actual code lives next door in [`__init__.py`](__init__.py); keep it open as you read.

---

## Part 0 — The absolute basics (read this even if you're tempted to skip)

**What is OpenGenerator?** It is a program that writes a *packet capture* — a file (ending in
`.pcap`) that records network traffic as if it had been sniffed off a real company's network. People
feed that file to a network security/performance sensor to test it, demonstrate it, or train on it,
without needing a real network.

**What is a "capture"?** Imagine a security camera for a network. Every message that crosses the
wire — a web request, a login, a file download — is a little package of data called a **packet**. A
capture is just a long list of those packets, in the order they happened, each stamped with a time.
OpenGenerator *invents* a realistic day's worth of these packets and saves them to the `.pcap` file.

**What is a "module"?** The core of OpenGenerator knows how to generate a normal business day. A
**module** is an add-on you can switch on to make it *also* generate something extra — here, a day
of NFS file-sharing. Modules can be loaded and unloaded while the program runs, so you can add or
remove a capability without touching the core.

**What does a module physically look like?** It is a **folder** inside the `modules/` directory with
two files in it:

```
modules/
  nfs_observability/
    manifest.json     <- a short description card
    __init__.py       <- the actual code
```

The folder name (`nfs_observability`) is the module's name. The file named exactly `__init__.py` is
special: in Python, a folder that contains a file called `__init__.py` becomes a **package** — a
unit of code the program can load by the folder's name. You do not need to understand why; just know
that your code goes in `__init__.py`.

### The handful of Python ideas you need

- **A value** is a piece of data: a number like `6`, a piece of text like `"EXL-NFS1"`, or raw
  binary data (explained below).
- **A variable** is a name for a value. `uid = 10000` means "from now on, the name `uid` refers to
  the value 10000."
- **A function** is a named, reusable recipe. It takes in some values (its *parameters*), does some
  work, and usually *returns* a value. You *call* a function by writing its name followed by
  parentheses with the values you're giving it: `add(2, 3)`. In Python you define one with the word
  `def`:
  ```python
  def add(a, b):          # "def" = define a function named add, taking two inputs a and b
      return a + b        # hand back the result
  ```
  (The indentation — the spaces at the start of the line — is how Python knows which lines belong
  *inside* the function. This matters; keep it consistent.)
- **A dictionary** is a lookup table: a set of *keys*, each pointing to a *value*. Written with curly
  braces. `{"name": "EXL-NFS1", "ip": "10.10.20.21"}` has two keys, `"name"` and `"ip"`. You look a
  value up by its key: `host["ip"]` gives `"10.10.20.21"`. Think of a physical dictionary: you look
  up a word (the key) to get its definition (the value).
- **A list** is an ordered sequence of values, written with square brackets: `[76, 77, 78]`. You can
  walk through it one item at a time.
- **Bytes** are raw binary data — the actual 1s-and-0s that travel on a network, shown as pairs of
  hex digits. In Python a bytes value is written with a `b` in front of quotes: `b"hello"`. Network
  packets are built out of bytes, so you will see a lot of them. `b"\x00\x00\x00\x06"` is four bytes
  whose numeric value is 6. You do **not** need to hand-write these — the engine gives you helpers.
- **Importing** means "bring in code that someone else already wrote so you can use it." `import
  branding` makes the `branding` toolbox available under the name `branding`. `from netgen import
  flows as F` brings in the `flows` toolbox but lets you refer to it by the short nickname `F`.

That is genuinely all the Python you need to follow this. Everything else is about *what the engine
offers* and *how to ask for it*.

---

## Part 1 — The big picture: how a capture is built, and where your module plugs in

Before touching the module, understand the assembly line the core runs every time it builds a
capture. Each step hands its result to the next:

1. **Choose the identity.** Who is this fake company? By default "Example Logistics," whose machines
   are named `EXL-...` on domain `corp.example.local`. You can override it. Everything downstream
   reads the identity so names stay consistent.
2. **Reset the dice.** The engine uses a *random number generator* (think of it as a bag of dice) to
   make traffic look natural — slightly different timings, sizes, and choices each place. Before each
   build it **re-seeds** those dice to a fixed starting point, so the *same* inputs always produce
   the *same* capture. This is why the baseline is reliably 609,554 packets every time.
3. **Build the host table.** It reads a list of all the company's machines (the "inventory") and
   creates a **Host** object for each one — a little record holding a machine's name, IP address,
   hardware (MAC) address, operating system, etc. These Hosts are stored in a lookup table called
   `ctx.h`, keyed by machine name. So `ctx.h["EXL-DC1"]` gives you the domain controller's Host.
4. **Build the normal business day.** A component called `Day` looks at those hosts and schedules a
   realistic working day for each — logons in the morning, web browsing, email, file access, and so
   on. **This is the baseline. Its packet count is the pinned number.**
5. **Run the selected scenarios.** *After* the normal day is scheduled, the engine runs each add-on
   scenario you selected (built-in ones, and ones that modules provide). **This is where your module
   does its work.** A scenario adds its own traffic on top of the normal day.
6. **Play it out and write the file.** The engine takes everything that was scheduled, sorts it by
   time, builds the actual packet bytes, and writes them to the `.pcap`.

The single most important thing to notice: **the baseline (step 4) is built _before_ your scenario
(step 5) runs.** That ordering is the key to the golden rule we'll keep coming back to.

### The golden rule

> **A module may only ADD to the capture. It must never ALTER the baseline.**

The pinned baseline of 609,554 packets must stay exactly 609,554 whenever your module is *not
actively selected*. If merely loading your module, or selecting it, changed the existing baseline
packets, that would break the one property the whole project depends on. Everything in this module
is arranged so that the baseline is left completely untouched. We'll see exactly how.

---

## Part 2 — The description card: `manifest.json`

Open `manifest.json`. It is not code — it is a small **dictionary** (keys and values) that describes
the module so the platform can list it without running anything:

```json
{
  "name": "nfs_observability",
  "version": "1.0",
  "kind": "scenario",
  "description": "Standard-traffic module: introduces 6 workstations + 1 Linux NFS server ...",
  "requires": []
}
```

- **name** — the module's name (matches the folder).
- **version** — your version number; bump it as you change the module.
- **kind** — what *type* of capability this is. The options are `scenario` (adds selectable traffic),
  `diagram`, `encoder`, `exporter`, `provider`, `baseline`, and `validation`. Ours adds selectable
  traffic, so it's a `scenario`.
- **description** — a human sentence shown in the interface.
- **requires** — a list of other modules that must be loaded first. Ours needs none, so it's empty
  (`[]`).

That's the whole file. The real work is in `__init__.py`.

---

## Part 3 — Reading `__init__.py` from the top

We'll go through the code in the order it appears, explaining each routine (a *routine* or
*subroutine* is just another word for a function) and, crucially, **which engine feature it uses and
why.**

### 3.1 The imports — borrowing the engine's toolboxes

At the top of the file:

```python
import io, os, struct, zipfile, zlib      # standard Python toolboxes (building files)
import branding                            # the project's names, colours and CATEGORIES list
from netgen import flows as F              # ready-made traffic builders (logins, DNS, SMB, ...)
from netgen import identity as ID          # who the fake company is (names, domain)
from netgen import incidents as INC        # the scenario registry + the scheduler
from netgen import protocols as P          # low-level packet-byte builders (incl. NFS/RPC pieces)
from netgen.core import Host               # the "machine record" type
```

Each line says "bring in a toolbox and let me call it by this short name." You'll use:
- `F` to schedule ready-made traffic (a Kerberos logon, a DNS lookup) without rebuilding it.
- `P` to build protocol bytes (it already contains NFS/RPC helpers).
- `INC` to register your scenario and to get the **scheduler**.
- `ID` to get the current company identity so your machines are named correctly.
- `branding` to add your new category to the interface.
- `Host` to create your new machines.
- `io/os/struct/zipfile/zlib` are general Python tools we only use to fabricate real sample files.

### 3.2 The constants — facts the module refers to repeatedly

```python
SCENARIO = "std-nfs-observability"         # the unique id of our scenario
CATEGORY = {"key": "STD", "tag": "STD",
            "label": "Standard traffic (healthy)", "color": branding.GRAY}

_WORKSTATIONS = [("WS-%03d" % n, "10.10.10.%d" % ip)
                 for n, ip in zip(range(76, 82), range(196, 202))]
_NFS_SUFFIX, _NFS_IP = "NFS1", "10.10.20.21"
```

- `SCENARIO` is the name our scenario is registered under. Using a variable for it means we write it
  once and reuse it, so we can't mistype it.
- `CATEGORY` is a dictionary describing the new "Standard" group in the interface.
- `_WORKSTATIONS` is a **list** of our six new workstations. Each entry is a pair: a name-suffix like
  `"WS-076"` and an IP address like `"10.10.10.196"`. (The `for ... in zip(range(...), range(...))`
  part is just a compact way to generate the six pairs: suffixes WS-076..081 paired with addresses
  .196..201. You can ignore the mechanism and read it as "here are my six workstations.")
- A leading underscore in a name (like `_WORKSTATIONS`) is a gentle convention meaning "this is an
  internal detail of the module." It has no effect on behavior.

Below these are the NFS protocol's numeric codes (`_READ = 6`, `_WRITE = 7`, etc.) and a couple of
constant byte values (`_FALSE`, `_OK`). These come straight from the NFS specification; think of
them as the vocabulary of the protocol. You copy them from the spec; you don't invent them.

### 3.3 Making real files (`_png`, `_pdf`, `_zip`, `_xlsx`, `_sample_files`)

The requirement was that the file transfers carry **real files**, so a sensor can recognize and
reconstruct them. So the module fabricates genuine small files as bytes.

Every real file format starts with a few recognizable bytes called a **magic number** — a PNG image
always starts with the same 8 bytes, a PDF always starts with `%PDF`, a ZIP (and anything built on
ZIP, like an `.xlsx` spreadsheet) always starts with `PK`. A sensor identifies a file by those
leading bytes. So to make a *real* file, we must produce bytes that actually begin with the right
magic number and are internally valid.

- `_png()` builds a valid PNG image: it writes the PNG magic bytes, a header describing the image
  size, the pixel data compressed with `zlib` (a standard compression tool), and an end marker.
- `_pdf()` builds a small but structurally complete PDF document (header, a page, a bit of text, the
  cross-reference table a PDF needs, and the `%%EOF` end marker).
- `_zip()` uses Python's built-in `zipfile` tool to package some contents into a real ZIP archive.
- `_xlsx()` builds a minimal but valid Excel spreadsheet — which is really just a ZIP containing a
  few specific XML files, so it reuses `_zip()`.
- `_sample_files()` ties them together and **returns a dictionary** mapping each filename to its
  bytes:
  ```python
  def _sample_files():
      return {
          "network-topology.png": _png(),
          "onboarding-guide.pdf": _pdf("Onboarding Guide", "Internal use only ..."),
          "q3-forecast.xlsx": _xlsx(),
          "team-roster.csv": csv,                 # csv is just text turned into bytes
          "project-archive.zip": _zip({...}),
      }
  ```

The important lesson here is general: **if your protocol carries a payload and you want the sensor to
do something meaningful with it, the payload must be realistic.** For files, that means valid file
bytes. For other protocols it might mean a valid message structure.

### 3.4 Creating the new machines (`_inject_hosts`) — and the heart of the golden rule

This is the most important routine to understand, because it's where the golden rule is honored.

```python
def _inject_hosts(ctx):
    ident = ID.get_current()                       # who is the company right now?
    if ident.host(_NFS_SUFFIX) in ctx.h:           # already added? then stop (don't double-add)
        return

    def add(suffix, ip, mac, os_, role, subnet):
        name = ident.host(suffix)                  # e.g. "EXL-" + "WS-076" -> "EXL-WS-076"
        ctx.h[name] = Host(name, ip, mac, os_, role, subnet, ident.fqdn(suffix))

    add(_NFS_SUFFIX, _NFS_IP, "00:a0:98:51:02:21", "linux",
        "NFS file server (NFSv3 exports)", "10.10.20.0/24")
    for i, (suffix, ip) in enumerate(_WORKSTATIONS):
        add(suffix, ip, "00:50:56:ab:03:%02x" % (0x20 + i), "Windows 11",
            "Windows workstation", "10.10.10.0/24")
```

What's happening:

- `ctx` is the **build context** — a big bundle the engine hands to your scenario, holding the host
  table `ctx.h`, the network layout, the current build scale, and more.
- `ID.get_current()` asks the engine for the current company identity. `ident.host("WS-076")` turns a
  suffix into the full machine name using the company's prefix (`EXL-WS-076` by default, or
  something else under a custom company). `ident.fqdn("WS-076")` gives the full DNS name
  (`exl-ws-076.corp.example.local`). **Always build names this way**, at the moment you need them, so
  your module works under any company name.
- `Host(name, ip, mac, os, role, subnet, fqdn)` creates a machine record. For machines inside the
  company network you only need these seven facts; the engine figures out routing and address
  resolution from the subnet automatically.
- `ctx.h[name] = ...` files the new Host into the host table under its name, so the rest of the
  scenario (and the engine) can find it.
- The small inner `add(...)` function is just a convenience so we don't repeat those seven arguments
  seven times. The server gets a Linux identity; the six workstations get a Windows identity.

**Now the golden rule.** Recall the assembly line: the baseline business day (step 4) is scheduled
*before* scenarios (step 5). The `Day` component decides which machines get a normal day by scanning
the host table *at step 4*. If we had added our workstations to the host table before then, `Day`
would have given them a normal day too — and, worse, adding machines to that early list nudges the
random-dice sequence, which would change the *existing* machines' traffic. Either way the baseline
packet count would move. **That is exactly what the golden rule forbids.**

The fix is simply *timing*: `_inject_hosts` is called from inside the scenario builder, which runs at
**step 5, after the baseline is already finished.** So when our new machines appear in `ctx.h`, the
baseline has already been built from the original machines and can no longer change. Our machines
exist only for our scenario to use. This is the single most reusable idea in the whole module:
**if your module adds systems, create them inside the scenario builder, never before.**

### 3.5 A tiny helper (`_uid`)

```python
def _uid(h):
    digits = "".join(c for c in h.name if c.isdigit())
    return 10000 + (int(digits[-3:]) if digits else 1)
```

NFS tags each request with a Unix user id number. This routine makes a stable, believable user id
from a machine's name (it pulls the digits out of, say, `EXL-WS-076` and adds them to 10000). It's a
small realism detail. The lesson: small touches like per-user ids make the traffic look less
synthetic.

### 3.6 Building one NFS request/response (`_exch`)

NFS is a *request/response* protocol: the client sends a call, the server sends back a reply, and
each pair is tied together by a number called an **xid** so a sensor can match them up. This routine
builds one such pair:

```python
def _exch(s, cred, xid, proc, args, results, tc=0.012, tr=0.010):
    xid[0] = (xid[0] + 1) & 0xFFFFFFFF                         # next transaction id
    s.c2s(P.rpc_call(xid[0], _NFSPROG, _NFSVERS, proc, cred=cred, args=args),
          think=F.rng.uniform(0.003, tc))                     # client -> server
    s.s2c(P.rpc_reply(xid[0], results), think=F.rng.uniform(0.002, tr))  # server -> client
```

- `s` is a **TCP session** — an open conversation between two machines (we create it in the next
  routines). `s.c2s(...)` means "client-to-server: send these bytes from the client." `s.s2c(...)`
  means "server-to-client." The `think=...` value is a small, slightly random delay before the
  message, so the timing looks human/real rather than inst. `F.rng.uniform(a, b)` is "give me a
  random number between a and b" — that's the engine's dice.
- `P.rpc_call(...)` and `P.rpc_reply(...)` are engine helpers (from the `protocols` toolbox) that
  assemble the raw bytes of an NFS call and reply for you. You supply the transaction id, the program
  numbers that say "this is NFS version 3," the procedure code (`proc` — e.g. 6 for READ), and the
  arguments/results. You do **not** hand-assemble the bytes.
- `xid` is passed as a one-item list `[number]` so the routine can increment it and the caller sees
  the new value. (A plain number couldn't be changed in place; a list can. This is a small Python
  quirk, not something to dwell on.)

The lesson: **a protocol exchange is built from small, repeated call/reply pairs. Write one helper
for the pair, then call it for each step of the conversation.**

### 3.7 Downloading a file (`nfs_download`) and uploading one (`nfs_upload`)

These are the two routines that actually produce the file transfers. They follow the real sequence a
client and server perform. Download:

```python
def nfs_download(ctx, client, server, filename, content, ts=None):
    out = ctx.arp_for(client, server, ts)                       # resolve addresses first
    s = ctx.tcp(client, server, 2049, ts + 0.001).handshake()   # open a TCP session on port 2049
    cred = P.rpc_auth_unix(client.name.lower(), uid=_uid(client), gid=10000)   # who's asking
    xid = [F.rng.getrandbits(32)]                               # a random starting transaction id
    fh_root = bytes(F.rng.getrandbits(8) for _ in range(32))    # a fake directory handle
    fh_file = bytes(F.rng.getrandbits(8) for _ in range(32))    # a fake file handle
    _exch(s, cred, xid, _FSINFO, ...)                           # ask about the filesystem
    _exch(s, cred, xid, _GETATTR, ...)                          # look at the directory
    _exch(s, cred, xid, _LOOKUP, P.xdr_opaque(fh_root) + P.xdr_str(filename), ...)   # find the file BY NAME
    _exch(s, cred, xid, _ACCESS, ...)                           # may I read it?
    # then READ the real bytes back, in chunks, the last chunk marked end-of-file
    off, n = 0, len(content)
    while True:
        chunk = content[off:off + _RSIZE]
        eof = off + len(chunk) >= n
        _exch(s, cred, xid, _READ, ..., _OK + ... + P.xdr_opaque(chunk), ...)
        off += len(chunk)
        if eof:
            break
    return F.merged(out, s.close(think=F.rng.uniform(0.01, 0.04)))   # tidy up and hand back all the packets
```

The key ideas:
- **Addresses first.** `ctx.arp_for(client, server, ts)` produces the little address-resolution
  exchange that real machines do before they talk. It returns some packets we'll include.
- **Open a session.** `ctx.tcp(client, server, 2049, ts).handshake()` opens a TCP conversation on
  port 2049 (the standard NFS port) and performs the three-step TCP handshake. It hands back a
  session object `s`.
- **The real sequence.** A genuine NFS download looks up the file *by name* (`_LOOKUP` with the
  filename), checks access, then reads the bytes. We follow that sequence so a sensor sees a textbook
  NFS read — and critically, the **filename** rides in the `_LOOKUP` and the **file bytes** ride in
  the `_READ` replies. `P.xdr_str(filename)` and `P.xdr_opaque(chunk)` are engine helpers that
  encode text and raw bytes the way NFS requires.
- **Chunking.** Real clients read large files in fixed-size pieces (`_RSIZE`, 32 KB). The `while`
  loop walks through the content a chunk at a time until it has sent it all, marking the final chunk
  as end-of-file. Small files are a single chunk.
- **Return the packets.** Every traffic-building routine must *return* the list of packets it
  produced. `F.merged(...)` combines the address packets and the session's packets (from `s.close()`)
  into one list, which the routine hands back.

`nfs_upload` is the mirror image: it `_CREATE`s the file by name (filename on the wire), `_WRITE`s
the content in chunks (file bytes on the wire), and `_COMMIT`s to flush it. Same building blocks,
different NFS procedures. Between them they produce the required **upload and download** in both
directions, carrying real files.

The general lesson: **to add a new protocol, study its real request/response sequence, then build it
from `ctx.tcp(...)`, `s.c2s`/`s.s2c`, and the `P.*` byte helpers — and always `return F.merged(...)`
of everything you produced.**

### 3.8 The scenario builder (`_build`) — the conductor

This is the routine the engine calls (at step 5) when your scenario is selected. Its job is to
*schedule* all the traffic across the day. It does **not** build packets directly; it tells the
engine *what* should happen and *when*, and the engine builds the packets later.

```python
def _build(ctx, eng, tag, win):
    _inject_hosts(ctx)                           # 1. create our 7 machines (now, safely after baseline)
    s = INC.sched_factory(eng, ctx, tag, win)    # 2. get a scheduler for this scenario's time window
    lo, hi = win                                 #    the window's start and end (seconds into the day)
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))   # how busy to be
    ident = ID.get_current()
    nfs = ctx.h[ident.host(_NFS_SUFFIX)]         # grab our server and workstations out of the host table
    file1 = ctx.h.get(ident.host("FILE1"))       # an existing file server (for some SMB)
    wss = [ctx.h[ident.host(suf)] for suf, _ in _WORKSTATIONS]
    files = list(_sample_files().items())        # the real files, as (name, bytes) pairs

    for ws in wss:                               # for each of our six workstations...
        arrive = lo + F.rng.uniform(0, 1500)     #   it "arrives" sometime in the first 25 minutes
        s(arrive, F.dhcp_acquire, ws)            #   gets an IP address (DHCP)
        s(arrive + 1.0, F.resolve_internal, ws, dc1)         # a DNS lookup
        s(arrive + 1.8, F.kerberos_as, ws, user=ws.name + "$")   # the machine logs on (Kerberos)
        s(arrive + 2.6, F.ldap_session, ws, queries=2)       # talks to the directory (LDAP)
        s(arrive + 3.4, F.kerberos_as, ws)                   # the user logs on
        s(arrive + 7.0, F.ntp_exchange, ws)                  # syncs its clock (NTP)

        n_ops = max(4, int(round(28 * scale)))   # how many file transfers this workstation does today
        gap = max(30.0, (hi - arrive) / n_ops)   # spread them evenly to end of day
        t = arrive + F.rng.uniform(20, 120)
        for _ in range(n_ops):
            if t >= hi:
                break
            fname, content = files[F.rng.randrange(len(files))]   # pick a random file
            if F.rng.random() < 0.5:
                s(t, nfs_download, ws, nfs, fname, content)       # half the time, download
            else:
                s(t, nfs_upload, ws, nfs, fname, content)         # half the time, upload
            if file1 is not None and F.rng.random() < 0.25:
                s(t + F.rng.uniform(1, 8), F.smb_file_activity, ws, file1)   # some SMB too
            t += F.rng.expovariate(1.0 / gap)     # wait a realistic random gap, then do the next one
```

The two things to really understand here:

**(a) The scheduler and its calling convention.** `s = INC.sched_factory(...)` gives you a scheduler
`s`. You schedule an event by calling `s(when, what, ...arguments...)`:
- `when` is the time (in seconds into the day) the event should happen.
- `what` is a traffic-building routine — either a ready-made one from `F` (like `F.kerberos_as`) or
  one of our own (like `nfs_download`).
- the remaining arguments are passed to that routine.

Behind the scenes the scheduler calls your routine as `what(ctx, ...arguments..., ts=when)`. That is
why every traffic routine starts with `ctx` and ends with `ts` — the scheduler fills those in. So
`s(t, nfs_download, ws, nfs, fname, content)` ends up calling
`nfs_download(ctx, ws, nfs, fname, content, ts=t)`. You don't call the routine yourself; you hand it
to `s` and the engine calls it at the right moment.

**(b) Reusing the engine's traffic for the "ordinary day."** We didn't write Kerberos, DNS, NTP,
DHCP, or SMB — the engine already has them in the `F` toolbox. We just *schedule* them for our new
machines. That's the payoff of the host table being shared: our new workstations can use every
existing traffic builder simply by being passed into it. **Before building a protocol yourself,
check whether `F` already has it.**

Notice also `scale`: multiplying the number of operations by the build scale means a small test build
stays light and a full build gets busy — the same knob that scales the rest of the capture.

### 3.9 Switching the module on and off (`register`, `_remove_category`)

`register` is the routine the platform calls when you **Load** the module. Its job is to wire the
module's capabilities into the engine, and to say exactly how to undo that on **Unload**.

```python
def register(kernel):
    if not any(c.get("key") == "STD" for c in branding.CATEGORIES):   # add our UI category once
        branding.CATEGORIES.append(dict(CATEGORY))
        kernel.on_unload(_remove_category)                            # ...and remove it on unload
    INC._reg(SCENARIO, "STD", "nfs-observability",                    # register the scenario
             "Standard NFS file-share activity (healthy, all-day) + 7 new systems",
             ((7, 0), (18, 0)), _build,                               # <- its time window and its builder
             "Introduces 6 workstations + 1 Linux NFS server; ...")
    kernel.on_unload(lambda: INC.REGISTRY.pop(SCENARIO, None))        # remove the scenario on unload
```

- `kernel` is the platform's module manager. The one method you need from it is
  `kernel.on_unload(fn)`: "when this module is unloaded, run `fn` to clean up." You call it once for
  each thing you added, so unloading leaves the engine exactly as it was.
- `branding.CATEGORIES` is the list of interface categories. We add our "Standard" entry to it (if it
  isn't already there) so the interface shows a Standard group, and we register a cleanup that
  removes it on unload.
- `INC._reg(...)` registers our scenario in the engine's scenario registry. Its arguments are: the
  scenario id; the category key it belongs to (`"STD"`); a short slug; a title; the **time window**
  as `((start_hour, start_minute), (end_hour, end_minute))` — here the whole business day, 7:00 to
  18:00; the **builder routine** (`_build`) the engine should call; and a longer note. After this,
  the scenario appears in "Choose scenarios" under the Standard category, selectable like any other.
- The `lambda: ...` is just a tiny unnamed function; here it's the cleanup that removes our scenario
  from the registry on unload. Read it as "on unload, un-register the scenario."

The lesson: **`register` only wires things in; it does not generate traffic. Every wire-in gets a
matching `on_unload` cleanup, so load/unload is perfectly reversible.** Nothing here touches the
baseline — loading the module merely makes a scenario *available*.

### 3.10 Proving it works (`self_test`)

Every module can carry a self-test that the platform (and the regression suite) can run on demand.
Ours does two quick things:

```python
def self_test():
    import opengenerator_build as OGB
    # (a) instant: the sample files really are valid files (correct magic headers)
    f = _sample_files()
    if not (f["network-topology.png"].startswith(b"\x89PNG")
            and f["onboarding-guide.pdf"].startswith(b"%PDF")
            and f["q3-forecast.xlsx"].startswith(b"PK\x03\x04")):
        return {"ok": False, "detail": "sample files have invalid headers"}
    # (b) one selected build: NFS must appear on the wire
    sel = OGB.build(scale=0.002, modules=[SCENARIO], ...)
    nfs = dict(sel["protocols"]).get("NFS", 0)
    return {"ok": nfs > 0, "detail": "... NFS packets ..."}
```

It checks that the sample files are valid (instant), then does **one** build with the scenario
selected and checks that **NFS appears on the wire**. It returns a dictionary saying whether it
passed. There are two deliberate design choices here, and they are the real lesson:

- **One build, not two, and a *structural* check, not an exact number.** An earlier version of this
  test built twice and asserted the baseline was *exactly* 609,554. That was both slow (two full
  builds) and — more importantly — *fragile*. The engine keeps its build state (the company
  identity, the dice, the capture day) as **process-wide shared state**: there is one of each for
  the whole running program. If a *second* build happens to run at the same time (for example you
  press Generate while the test is still building), the two share that state and skew each other's
  packet counts, so an exact-count assertion can report a false failure. Asserting a *structural*
  fact instead — "when the scenario is selected, NFS is on the wire" — cannot be skewed by another
  build: a concurrent build might change *how many* packets there are, but it cannot stop the
  selected NFS scenario from emitting NFS, nor make an unselected build emit it.
- **Don't re-assert the global pin in your module's test.** The exact 609,554 figure is checked in
  isolation by the dedicated `baseline_pin` module and by the offline `selftest.py` suite (which
  run with nothing else going on). Your module's self-test should assert *your* module's promise —
  here, "NFS appears only when selected, carrying real files" — and leave the global pin to the
  tools built for it. (The platform also runs builds **one at a time** behind a single lock, so in
  normal use your test won't collide with another build; the structural style is simply the robust
  default regardless.)

So the rule of thumb: **make your self-test fast and have it assert your module's own behavior
structurally.** Here that promise is "the files are real, and NFS is on the wire when selected."

---

## Part 4 — How this module interacts with the base engine (the whole story in one page)

Putting it together, here is the complete life of a build with this module selected, and exactly
where the module touches the engine:

1. You **Load** the module → the platform calls `register(kernel)`. The module adds the "Standard"
   category to `branding.CATEGORIES` and registers its scenario in `INC.REGISTRY`. **No traffic yet;
   baseline still 609,554.**
2. You **select** the scenario and press **Generate**.
3. The engine sets the identity, re-seeds the dice, builds the host table from the inventory, and
   builds the **normal business day** from those original machines. **Baseline is produced here, from
   the original hosts only — the module's machines don't exist yet.**
4. The engine then runs selected scenarios. For ours it calls `_build(ctx, eng, tag, win)`.
   - `_build` calls `_inject_hosts(ctx)`, which creates the 7 new `Host` records and files them into
     `ctx.h`. (Safe now: the baseline is already done.)
   - `_build` gets a scheduler from `INC.sched_factory` and schedules, across the whole day, each
     workstation's logon sequence (reusing `F.kerberos_as`, `F.resolve_internal`, `F.ldap_session`,
     `F.ntp_exchange`, `F.dhcp_acquire`), a stream of NFS downloads/uploads (our own `nfs_download`
     /`nfs_upload`, built from `P.*` byte helpers and `ctx.tcp`), and some SMB (`F.smb_file_activity`).
5. The engine plays out everything that was scheduled, in time order, building the actual packets and
   writing the `.pcap`. Our NFS routines produce their packets here, carrying real filenames and real
   file bytes on port 2049.
6. Later, you **Unload** the module → the platform runs the `on_unload` cleanups, removing the
   scenario and the category. The engine is back to exactly how it started.

The engine gave the module four things: the **host table** (`ctx.h`) to add machines to and read
machines from, the **scheduler** (`INC.sched_factory`) to place events in time, the **traffic
toolbox** (`F`) to reuse existing protocols, and the **byte toolbox** (`P`) to build a new one. The
module gave the engine one thing back from each traffic routine: a **list of packets** (`F.merged`).
That is the entire contract.

---

## Part 5 — Build your own, step by step

Use this module as a template. Say you want a module that adds a few printers doing IPP printing:

1. **Make the folder and card.** Create `modules/your_module/` with a `manifest.json` (copy ours,
   change `name`, `description`, keep `kind` as `scenario`).
2. **Copy `__init__.py`** from this module into your folder as a starting point.
3. **Change the new systems.** Edit the `_WORKSTATIONS`/server constants and `_inject_hosts` to
   create the machines you want, with free IP addresses in the right subnet and names that follow the
   `H()`/`ident.host(...)` convention. (To find free addresses, look at `inventory.json`.)
4. **Decide your traffic.** If the engine already has your protocol in `F`, just schedule it in
   `_build`. If not, write builder routines like `nfs_download`/`nfs_upload`: open a session with
   `ctx.tcp(...)`, exchange messages with `s.c2s`/`s.s2c`, build bytes with the `P.*` helpers (or
   plain byte literals for simple text protocols), and `return F.merged(...)`.
5. **Pick or add a category.** Reuse an existing category key in `INC._reg` (e.g. `"NPM"`), or add a
   new one to `branding.CATEGORIES` like we did.
6. **Keep the golden rule.** Create any new machines *inside* `_build` (via a helper like
   `_inject_hosts`), never at import time and never before the baseline. Gate everything on selection.
7. **Write a self-test** that asserts *your* module's promise, fast and structurally — e.g. "when
   selected, my protocol/traffic is on the wire" — ideally with a single build. Don't re-assert the
   global 609,554 pin in your own test (that's `baseline_pin`'s job); keep it quick and robust (see
   §3.10 for why).
8. **Test it** (next section). Iterate until green.

---

## Part 6 — Testing and verifying

From the `dev` directory:

```bash
# Run the whole regression suite (loads every module, runs its self-test, checks the pin):
python3 selftest.py

# Or test just your module, quickly, without the interface:
python3 - <<'PY'
from netgen import platform as cap
k = cap.Kernel()           # the module manager
k.discover()               # find modules on disk
k.load("your_module")      # load yours
print(k.self_test("your_module"))   # run its self-test
PY
```

To confirm the traffic really looks right, build a capture with your scenario selected and inspect
it — for this module we confirmed the six workstation addresses and the server address all appear,
the filenames (`onboarding-guide.pdf`, etc.) and file magic bytes (`%PDF`, the PNG signature, `PK`)
appear in the payloads, and both upload (`CREATE`/`WRITE`) and download (`READ`) NFS procedures are
present. Build the equivalent checks for your protocol.

---

## Glossary

- **Packet** — one message on the network; the unit a capture is made of.
- **Capture / pcap** — the output file: a time-ordered list of packets.
- **Baseline** — the normal business day the core generates with no scenarios; pinned at 609,554
  packets and never to be altered by a module.
- **Module / package** — a folder with `__init__.py` that adds a capability.
- **Scenario** — a kind of module/capability that adds selectable traffic on top of the baseline.
- **Host** — a record for one machine (name, IP, MAC, OS, …), stored in the host table `ctx.h`.
- **ctx (context)** — the bundle the engine passes to your scenario: host table, network layout,
  build scale, and helpers like `ctx.tcp` and `ctx.arp_for`.
- **Scheduler** — `INC.sched_factory(...)`; you call it as `s(when, what, ...)` to place an event in
  time. It later calls `what(ctx, ..., ts=when)`.
- **Builder** — a routine that produces traffic and returns its packets via `F.merged(...)`.
- **F / P / INC / ID / branding** — the engine toolboxes: ready-made traffic / protocol bytes /
  scenario registry + scheduler / company identity / interface names & categories.
- **register / on_unload** — wire a module's capabilities in, and the matching cleanups to remove
  them; loading never touches the baseline.
- **Identity** — the fake company (names, domain). Always build names through it so a custom company
  renames everything.
- **Dice / rng / scale** — the random generator that makes traffic natural (re-seeded each build for
  reproducibility) and the knob that sets how busy the capture is.

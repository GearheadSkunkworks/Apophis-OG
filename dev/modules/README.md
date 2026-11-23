# Capability modules — what they are and how to write one

A **capability module** is a self-contained unit of functionality that OpenGenerator discovers
at startup and can **load, unload, and test at run time** — without restarting the server and
without editing any core code. It is how a new capability is added to (or removed from) the
generator without disrupting the rest of it.

The kernel that manages modules is [`netgen/platform`](../netgen/platform/__init__.py). The core
guarantee: **core never imports a capability.** A module *wires itself into* the registry its
kind targets, and declares how to undo that, so loading and unloading are exact and reversible.
The no-module baseline (the plain business day) is always `609,554` packets — a module only
changes a capture when it is loaded *and* its capability is actually used.

> "Capability modules" are not the same as the **scenarios** in the "Choose scenarios" grid.
> Scenarios are the built-in incident injects shipped with the engine. A capability module can
> *add* a scenario (among other things) — see the `scenario` kind below.

---

## What a module actually *does* — by kind

Every module declares a `kind` in its manifest. The kind determines what the module contributes
and which registry it plugs into:

| `kind` | What it does | Targets | Reference example |
|--------|--------------|---------|-------------------|
| **diagram** | Adds a diagram to the picker and `/diagram?name=…`. | `make_diagram.DIAGRAMS` | `demo_diagram` |
| **scenario** | Adds an incident scenario to the "Choose scenarios" grid; when selected, it injects traffic into the capture. | `netgen.incidents.REGISTRY` | `demo_scenario` |
| **encoder** | Overrides or adds a **protocol encoder** — changes how packets of a protocol are built on the wire (every `P.<name>(...)` call picks it up live). | `netgen.protocols` encoder registry | `demo_encoder` |
| **provider** | Adds a sensor-push target — a `SensorProvider` implementation for the "push to sensor" flows. | `sensorops.providers` | `demo_provider` |
| **validation** | Contributes no capability; carries a `self_test` that validates the core (e.g. the 609,554 baseline check). | — | `baseline_pin` |
| **baseline** | *(reserved)* a business-day sub-generator that runs on every build. | `model.register_baseline` | — |
| **exporter** | Adds a post-build output — a new report/export written beside the pcap. Runs on the finished artifacts, puts no packet on the wire, so it never affects the baseline. Keys it returns are merged into the build summary. | `opengenerator_build.register_exporter` | `capture_summary` |

A module may also simply bundle code the others use; `kind` is advisory metadata (an unknown
kind still loads, but the catalog flags it).

---

## The contract

```
modules/<name>/           # <name> must be a valid Python package name (letters, digits, _)
  manifest.json           # metadata, read without importing code
  __init__.py             # the entry point
  ...                     # any supporting files
```

### `manifest.json`

```json
{
  "name": "my_capability",
  "version": "1.0",
  "kind": "scenario",
  "description": "One sentence on what this adds.",
  "requires": [],
  "example": false
}
```

- **name** — the id used by the load/unload API (defaults to the directory name).
- **kind** — one of the kinds above.
- **requires** — names of other modules that must be loaded first.
- **example** — optional; `true` marks it a reference/sample so the GUI labels it clearly.

### `__init__.py`

```python
def register(kernel):
    # Wire the capability into its target registry, and for EVERY thing you add, declare how to
    # undo it so unload is exact:
    kernel.on_unload(lambda: ...remove what you added...)

def unload():        # optional — extra teardown beyond the on_unload callbacks
    ...

def self_test():     # optional — returns {"ok": bool, "detail": str}
    ...
```

`register(kernel)` is the only required function. Call `kernel.on_unload(fn)` once per thing you
register; the kernel runs those callbacks (in reverse) when the module is unloaded. A failed
`register` is rolled back automatically.

---

## Create a module — step by step

1. **Make the folder + manifest.** `modules/my_capability/manifest.json` with the right `kind`.
2. **Write `register(kernel)`** in `__init__.py`: import the target registry, add your
   capability, and declare teardown with `kernel.on_unload(...)`.
3. **Add `self_test()`** so the "Test" button can validate it.
4. **Done.** It appears in the catalog automatically (GUI *Capability modules* panel, or
   `GET /api/capabilities`). Load it, test it, unload it — no restart.

### Worked examples (one per kind)

**A diagram** — wire into `make_diagram.DIAGRAMS`:
```python
import make_diagram as M
def register(kernel):
    M.register("mydiag", "My diagram", "what it shows", order=500)(lambda c: {"svg": "<svg .../>"})
    kernel.on_unload(lambda: M.DIAGRAMS.pop("mydiag", None))
```

**A scenario** — wire into `netgen.incidents.REGISTRY` (builder is `fn(ctx, eng, tag, win)`):
```python
from netgen import incidents as INC, flows as F
def _build(ctx, eng, tag, win):
    s = INC.sched_factory(eng, ctx, tag, win); lo, hi = win
    # schedule flow helpers inside the window, e.g. s(lo+5, F.dns_lookup, some_client, "name")
def register(kernel):
    INC._reg("my-scenario", "NPM", "my-scenario", "My scenario", ((10,0),(10,10)), _build, "note")
    kernel.on_unload(lambda: INC.REGISTRY.pop("my-scenario", None))
```

**A protocol encoder** — override an encoder in `netgen.protocols` (all `P.<name>(...)` calls swap):
```python
from netgen import protocols as P
_builtin = None
def _impl(*a, **k): return _builtin(*a, **k)          # call the original, then change the result
def register(kernel):
    global _builtin
    _builtin = P.register_encoder("ftp_line", _impl)  # returns the previous (built-in) impl
    kernel.on_unload(lambda: P.reset_encoder("ftp_line"))
```

**A sensor provider** — register a `SensorProvider` subclass:
```python
from sensorops.provider import SensorProvider
from sensorops import providers as PV
class MyProvider(SensorProvider):
    name = "myprov"
    # implement the ABC methods...
def register(kernel):
    PV._REGISTRY["myprov"] = MyProvider
    kernel.on_unload(lambda: PV._REGISTRY.pop("myprov", None))
```

**A validation** — a `self_test` that checks something about the core (registers nothing):
```python
def register(kernel):
    pass
def self_test():
    ok = ...                                           # run your check
    return {"ok": ok, "detail": "what you verified"}
```

**An exporter** — a post-build output; `fn(ectx)` returns keys merged into the build summary:
```python
import opengenerator_build as OGB
def _export(e):                                        # e.out, e.writer(.n/.bytes/.protocols),
    path = (e.out[:-5] if e.out.endswith(".pcap") else e.out) + "-myreport.txt"  # e.ctx.h, e.selected
    with open(path, "w") as f: f.write("packets=%d\n" % e.writer.n)
    return {"myreport": path}
def register(kernel):
    OGB.register_exporter("my-report", _export)
    kernel.on_unload(lambda: OGB.EXPORTERS.remove(("my-report", _export)))
```

See the shipped `demo_*` modules (kind `example`) and `baseline_pin` for complete, working
versions of each, and `capture_summary` for a real (non-demo) exporter.

**An advanced module — adds systems + a new protocol + a new category.** When a module needs to
introduce new hosts and speak a protocol the baseline does not, see **`nfs_observability`** —
its **[README](nfs_observability/README.md)** (what it does / how to use it) and its
**[TUTORIAL](nfs_observability/TUTORIAL.md)** (a from-scratch, no-Python-assumed walkthrough that
teaches how to build your own). It is the reference for the hard parts: injecting hosts **inside
the scenario builder** (scenario phase, so the 609,554 pin is never altered — a module may only
*add*), composing a new protocol from the public `netgen.protocols` primitives (NFSv3 upload +
download with real files), and adding a UI category via `branding.CATEGORIES`.

---

## Managing modules

**GUI** — the *Capability modules* panel (inside "What gets built"): per-module **Load / Unload /
Test**, a **Test all loaded** button, and a live summary of the registries under the kernel.

**API**
```
GET  /api/capabilities                 # catalog (every module + loaded flag) + builtin counts
POST /api/capabilities/load   {name}
POST /api/capabilities/unload {name}
POST /api/capabilities/reload {name}   # re-import edited module code without a restart
POST /api/capabilities/test   {name}
POST /api/capabilities/test-all        # run every loaded module's self_test
```

**Rules**
- Modules can't be loaded/unloaded (or self-tested) **while a capture is generating** — the
  capability set is frozen for the duration of a build.
- A loaded **scenario** or **encoder** changes the capture. Unload it to return to the plain
  baseline. Loaded modules are not sticky across a server restart (discovery finds them; it
  loads none automatically).

## Trust

The kernel **imports and runs the Python** in each `modules/<name>/`. A module is code with the
same access as the server process — there is no sandbox. Only add modules you trust.

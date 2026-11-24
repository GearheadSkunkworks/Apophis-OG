"""netgen.platform — the v5b capability kernel.

A *capability module* is a self-contained package under ``/dev/modules/<name>/`` with a
``manifest.json`` and a Python entry point. The kernel **discovers** modules on disk and
**loads / unloads / tests** them at run time, so a capability can be added or removed from the
running server without a restart and without disrupting the core generator.

Core never imports a capability directly. A module wires itself into whatever registry it
targets (``make_diagram.DIAGRAMS``, ``netgen.incidents.REGISTRY``, an encoder table, …) inside
its ``register(kernel)`` hook, and declares teardown via ``kernel.on_unload(fn)`` so an unload
is exact and fully reversible. The kernel therefore stays decoupled from every capability kind.

Module contract -- ``modules/<name>/``::

    manifest.json : {"name", "version", "kind", "description", "requires": [...]}
    __init__.py   : register(kernel)            # wire in; call kernel.on_unload(fn) per hook
                    unload()         (optional)  # extra teardown beyond the on_unload callbacks
                    self_test()      (optional)  # -> {"ok": bool, "detail": str, ...}

``kind`` is advisory metadata for now (diagram / scenario / encoder / exporter / provider /
baseline); later phases add typed registrars, but the load/unload mechanism is kind-agnostic.
"""
import importlib
import json
import os
import sys
import threading

# The dev root (where server.py / make_diagram.py / modules/ live) is three levels up from this
# file: .../dev/netgen/platform/__init__.py -> .../dev. Honour PyInstaller's _MEIPASS when frozen.
_HERE = os.path.dirname(os.path.abspath(__file__))
import overlay as _overlay                                # the installed patch's directory when one is active (updater)
APP_DIR = _overlay.app_dir(getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(_HERE))))
MODULES_DIR = os.path.join(APP_DIR, "modules")

#: Advisory capability kinds. A manifest's `kind` should be one of these; unknown kinds load
#: fine but are flagged in the catalog so the UI can surface a typo.
KINDS = ("diagram", "scenario", "encoder", "exporter", "provider", "baseline", "validation")

#: The modules that SHIP WITH the application. Loading a module runs its code with the server's
#: full privileges and no sandbox (a documented trust boundary), so the catalog flags any module
#: NOT in this set as third-party -- one that was added to modules/ after install -- and the UI
#: surfaces it, since that is the one a user should think twice about before loading. Hardcoded
#: on purpose: a manifest field could be forged by a malicious module, a name in this list cannot
#: be (it lives in signed-at-build code). Update it when a new module is bundled with the app.
SHIPPED_MODULES = frozenset({
    "baseline_pin", "capture_summary", "nfs_observability",
    "demo_diagram", "demo_encoder", "demo_provider", "demo_scenario",
})


class ModuleError(Exception):
    """A capability module could not be discovered, loaded, unloaded, or validated."""


class Kernel:
    """Discovers capability modules under ``modules_dir`` and loads/unloads them at run time.

    Thread-safe (a reentrant lock guards the loaded/available tables), so the server can drive
    load/unload from request threads. A module's teardown is whatever it registered through
    ``on_unload`` during load, run in reverse, so unload leaves the registries exactly as they
    were before the module was loaded.
    """

    def __init__(self, modules_dir=MODULES_DIR):
        self.modules_dir = modules_dir
        self._available = {}     # name -> manifest dict (+ "_pkg", maybe "error")
        self._loaded = {}        # name -> {"module", "undo": [callables], "manifest"}
        self._loading = None     # name currently inside register(); gates on_unload()
        self._sources = {}       # kind -> () -> summary  (the built-in registries)
        self._enabled_file = os.path.join(modules_dir, "enabled.json")   # persisted auto-load set
        self._lock = threading.RLock()

    # ---- persistence (enable on startup) ---------------------------------------------
    def enabled_names(self):
        """The persisted set of modules to auto-load at startup (may be empty)."""
        try:
            with open(self._enabled_file) as f:
                d = json.load(f)
            return sorted(set(d)) if isinstance(d, list) else []
        except (OSError, ValueError):
            return []

    def set_enabled(self, name, on):
        """Add/remove a module from the persisted auto-load set. Returns the new set."""
        cur = set(self.enabled_names())
        cur.add(name) if on else cur.discard(name)
        try:
            with open(self._enabled_file, "w") as f:
                json.dump(sorted(cur), f, indent=1)
        except OSError:
            pass
        return sorted(cur)

    def load_enabled(self):
        """Load every module in the persisted enabled set. Call once at startup, after
        discover(). A module that fails to load is recorded, not fatal."""
        loaded, errors = [], {}
        for name in self.enabled_names():
            try:
                if self.load(name):
                    loaded.append(name)
            except ModuleError as e:
                errors[name] = str(e)
        return {"loaded": loaded, "errors": errors}

    # ---- built-in registries ---------------------------------------------------------
    def register_source(self, kind, enumerate_fn):
        """Put a pre-existing registry *under* the kernel so one place sees every capability.

        ``enumerate_fn()`` returns the current built-in contents for ``kind`` (a count or a
        list). Registered by whoever owns the registry (the server at startup), so the kernel
        itself never imports a capability. Module-provided capabilities also register into these
        same registries, so a source's live total includes loaded modules."""
        self._sources[kind] = enumerate_fn

    def builtins(self):
        """The live summary of every registry under the kernel: ``{kind: count_or_list}``."""
        out = {}
        for kind, fn in self._sources.items():
            try:
                out[kind] = fn()
            except Exception as e:                           # noqa: BLE001
                out[kind] = {"error": str(e)}
        return out

    # ---- discovery -------------------------------------------------------------------
    def discover(self):
        """(Re)scan ``modules_dir`` for ``<name>/manifest.json``. Returns the available map.

        A malformed manifest is recorded with an ``error`` rather than raising, so one bad
        module never hides the rest of the catalog."""
        found = {}
        if os.path.isdir(self.modules_dir):
            for entry in sorted(os.listdir(self.modules_dir)):
                mpath = os.path.join(self.modules_dir, entry, "manifest.json")
                if not os.path.isfile(mpath):
                    continue
                try:
                    with open(mpath) as f:
                        m = json.load(f)
                    if not isinstance(m, dict):
                        raise ValueError("manifest is not a JSON object")
                    m.setdefault("name", entry)
                    m["_pkg"] = entry
                except Exception as e:                       # noqa: BLE001 — never fail discovery
                    m = {"name": entry, "_pkg": entry, "error": str(e)}
                found[m["name"]] = m
        with self._lock:
            # preserve loaded-state for names that are still present
            self._available = found
        return found

    def catalog(self):
        """A JSON-serialisable list of every discovered module and whether it is loaded."""
        enabled = set(self.enabled_names())
        with self._lock:
            out = []
            for name, m in sorted(self._available.items()):
                out.append({
                    "name": name,
                    "version": m.get("version", "-"),
                    "kind": m.get("kind", "-"),
                    "description": m.get("description", ""),
                    "requires": list(m.get("requires", [])),
                    "loaded": name in self._loaded,
                    "enabled": name in enabled,
                    "kind_known": m.get("kind") in KINDS,
                    "example": bool(m.get("example")),
                    "shipped": name in SHIPPED_MODULES,
                    "error": m.get("error"),
                })
            return out

    def is_loaded(self, name):
        with self._lock:
            return name in self._loaded

    # ---- lifecycle -------------------------------------------------------------------
    def load(self, name):
        """Import and register a module. No-op (returns False) if already loaded.

        Rolls back any partial registration if the module's ``register`` raises, so a failed
        load leaves the registries untouched."""
        with self._lock:
            if name in self._loaded:
                return False
            if name not in self._available:
                self.discover()
            m = self._available.get(name)
            if not m:
                raise ModuleError("unknown module %r" % name)
            if "error" in m:
                raise ModuleError("module %r has a bad manifest: %s" % (name, m["error"]))
            for dep in m.get("requires", []):
                if dep not in self._loaded:
                    raise ModuleError("%r requires %r, which is not loaded" % (name, dep))

            modname = "modules.%s" % m["_pkg"]
            try:
                mod = importlib.import_module(modname)
            except Exception as e:                           # import-time failure
                sys.modules.pop(modname, None)
                raise ModuleError("could not import %s: %s" % (modname, e)) from e

            entry = {"module": mod, "undo": [], "manifest": m}
            self._loaded[name] = entry
            self._loading = name
            try:
                reg = getattr(mod, "register", None)
                if not callable(reg):
                    raise ModuleError("%r has no register(kernel)" % name)
                reg(self)
            except Exception as e:
                for fn in reversed(entry["undo"]):           # undo any partial wiring
                    try:
                        fn()
                    except Exception:                        # noqa: BLE001
                        pass
                self._loaded.pop(name, None)
                sys.modules.pop(modname, None)
                if isinstance(e, ModuleError):
                    raise
                raise ModuleError("%r failed to register: %s" % (name, e)) from e
            finally:
                self._loading = None
            return True

    def on_unload(self, fn):
        """Register a teardown callback for the module currently being loaded. Called by a
        module inside its ``register(kernel)`` for every registry entry it adds."""
        if self._loading is None:
            raise ModuleError("on_unload() may only be called from within register(kernel)")
        self._loaded[self._loading]["undo"].append(fn)

    def unload(self, name):
        """Run a module's teardown callbacks (reverse order), call its optional ``unload()``,
        and drop it from ``sys.modules`` so a later load re-imports it fresh. Returns False if
        it was not loaded."""
        with self._lock:
            entry = self._loaded.get(name)
            if not entry:
                return False
            for fn in reversed(entry["undo"]):
                try:
                    fn()
                except Exception:                            # noqa: BLE001 — teardown is best-effort
                    pass
            extra = getattr(entry["module"], "unload", None)
            if callable(extra):
                try:
                    extra()
                except Exception:                            # noqa: BLE001
                    pass
            sys.modules.pop("modules.%s" % entry["manifest"]["_pkg"], None)
            del self._loaded[name]
            return True

    def reload(self, name):
        """Unload (if loaded) then load — picks up edited module code without a server restart."""
        self.unload(name)
        return self.load(name)

    def self_test(self, name):
        """Run a loaded module's ``self_test()`` and return its result dict. A module without
        one is reported as a skipped pass."""
        with self._lock:
            entry = self._loaded.get(name)
        if not entry:
            raise ModuleError("%r is not loaded" % name)
        t = getattr(entry["module"], "self_test", None)
        if not callable(t):
            return {"ok": True, "skipped": True, "detail": "no self_test defined"}
        try:
            res = t()
        except Exception as e:                               # a thrown test is a failed test
            return {"ok": False, "detail": "self_test raised: %s" % e}
        if not isinstance(res, dict):
            return {"ok": bool(res), "detail": str(res)}
        res.setdefault("ok", False)
        return res

    def self_test_all(self):
        """Run every loaded module's self_test and return an aggregate: per-module results plus
        passed/total counts and an overall ``ok``. The one-click regression check -- load the
        validation modules you care about (e.g. the baseline-pin module) and run this."""
        with self._lock:
            names = list(self._loaded)
        results = {}
        for name in names:
            try:
                results[name] = self.self_test(name)
            except Exception as e:                           # noqa: BLE001
                results[name] = {"ok": False, "detail": "error: %s" % e}
        passed = sum(1 for r in results.values() if r.get("ok"))
        return {"ok": all(r.get("ok") for r in results.values()),
                "passed": passed, "total": len(results), "results": results}


#: Process-wide kernel used by the server. Call ``kernel.discover()`` once at startup.
kernel = Kernel()

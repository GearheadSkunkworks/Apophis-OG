#!/usr/bin/env python3
"""The module list of a frozen release, and the check that a patch tree only imports from it.

A patch (overlay) runs on the Python runtime frozen into the full release it patches. PyInstaller bundles only the stdlib
and third-party modules it found at build time, so a patch that imports anything else dies at start ("No module named ...")
and the boot guard rolls it back. 5.5.1 and 5.5.2 did exactly that with `secrets`.

    python3 tools/frozen_modules.py                    # the patch tree (this dev/ tree) imports only modules every platform list has
    python3 tools/frozen_modules.py --refresh App.app  # rewrite frozen-modules.txt from a built app (needs PyInstaller)
    python3 tools/frozen_modules.py --refresh-linux <bundle-dir> <x86_64|aarch64> [out]   # rewrite frozen-modules-linux-<arch>.txt
    python3 tools/frozen_modules.py --diff <built.txt> <committed.txt>   # fail if the committed list names a module the bundle lacks

Refresh on every X.Y.0 full release, from that release's .app, in the same change that bumps VERSION to X.Y.0. The list
is the contract for every X.Y.Z patch after it. The check itself is standard library only.
"""
import ast
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
LIST = os.path.join(HERE, "frozen-modules.txt")
SKIP_TOP = {"tests", "tools", "docs", "__pycache__"}          # not shipped in a patch (make_patch.SKIP_TOP, plus docs)
DEV_ONLY = {"selftest.py", "checks"}                           # shipped but only ever run by the gate, never imported by the app


def load(path=LIST):
    with open(path, encoding="utf-8") as fh:
        return {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}


def local_names(dev=DEV):
    """Top-level names the patch tree itself supplies (modules and packages)."""
    out = set()
    for n in os.listdir(dev):
        if n.endswith(".py"):
            out.add(n[:-3])
        elif os.path.isdir(os.path.join(dev, n)) and n not in SKIP_TOP:
            out.add(n)
    return out


def _guarded(tree):
    """ids of nodes inside a `try` whose handlers catch ImportError/Exception: an optional import that degrades gracefully."""
    ids = set()
    for t in ast.walk(tree):
        if isinstance(t, ast.Try) and any(
                h.type is None or any(isinstance(x, ast.Name) and x.id in ("ImportError", "ModuleNotFoundError", "Exception")
                                      for x in ast.walk(h.type)) for h in t.handlers):
            for stmt in t.body:
                ids.update(id(n) for n in ast.walk(stmt))
    return ids


def violations(dev=DEV, frozen=None):
    """[(file, line, module)] for every import in a shipped .py (top-level or lazy, inside functions too) that is neither
    the patch's own nor in the frozen list. Relative imports and guarded optional imports are skipped."""
    frozen = load() if frozen is None else frozen
    mine = local_names(dev)
    bad = []
    for d, dirs, files in os.walk(dev):
        rel_d = os.path.relpath(d, dev)
        dirs[:] = sorted(x for x in dirs if x != "__pycache__" and not (rel_d == "." and x in SKIP_TOP))
        for f in files:
            if not f.endswith(".py"):
                continue
            if rel_d.split(os.sep)[0] in DEV_ONLY or (rel_d == "." and f in DEV_ONLY):
                continue
            p = os.path.join(d, f)
            with open(p, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), p)
            skip = _guarded(tree)
            for n in ast.walk(tree):
                if id(n) in skip:
                    continue
                if isinstance(n, ast.Import):
                    names = [a.name for a in n.names]
                elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                    names = [n.module]
                else:
                    continue
                for m in names:
                    if m.split(".")[0] in mine or m in frozen or m.split(".")[0] == "__future__":
                        continue
                    bad.append((os.path.relpath(p, dev), n.lineno, m))
    return bad


def _collect(exe, base_zip, dynload_dirs):
    """Every module a frozen executable can import: builtins, modules stored beside the PYZ, the PYZ itself,
    base_library.zip and the lib-dynload extension modules."""
    import tempfile
    from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader
    mods = set(sys.builtin_module_names)
    r = CArchiveReader(exe)
    mods |= {n for n, e in r.toc.items() if e[-1] in ("m", "M")}   # modules stored beside the PYZ (struct, ...)
    with tempfile.TemporaryDirectory() as tmp:
        for name in r.toc:
            if name.endswith(".pyz"):
                pyz = os.path.join(tmp, "x.pyz")
                with open(pyz, "wb") as fh:
                    fh.write(r.extract(name))
                mods |= set(ZlibArchiveReader(pyz).toc)
    with zipfile.ZipFile(base_zip) as z:
        mods |= {n[:-4].replace("/", ".").removesuffix(".__init__") for n in z.namelist() if n.endswith(".pyc")}
    for top in dynload_dirs:
        for d, _dirs, files in os.walk(top):
            if os.path.basename(d) == "lib-dynload":
                mods |= {f.split(".")[0] for f in files if f.endswith(".so")}
    return mods


def _write(mods, out, how):
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("# Modules frozen into the full release a patch runs on. Rebuild: %s\n" % how)
        fh.write("\n".join(sorted(mods)) + "\n")
    print("wrote %d modules to %s" % (len(mods), out))


def refresh(app, out=LIST):
    macos = os.path.join(app, "Contents", "MacOS")
    mods = _collect(os.path.join(macos, os.listdir(macos)[0]),
                    os.path.join(app, "Contents", "Resources", "base_library.zip"),
                    [os.path.join(app, "Contents", "Frameworks")])
    _write(mods, out, "python3 tools/frozen_modules.py --refresh <App.app>")


def linux_list(arch):
    return os.path.join(HERE, "frozen-modules-linux-%s.txt" % arch)


def refresh_linux(bundle, arch, out=None, exe="apophis-server"):
    """Write frozen-modules-linux-<arch>.txt (or `out`) from a built PyInstaller onedir (`bundle` holds the executable and _internal/)."""
    internal = os.path.join(bundle, "_internal")
    mods = _collect(os.path.join(bundle, exe), os.path.join(internal, "base_library.zip"), [internal])
    _write(mods, out or linux_list(arch), "python3 tools/frozen_modules.py --refresh-linux <bundle-dir> <arch>")


def platform_lists():
    """{file name: module set} for the macOS list and every Linux list present. A patch zip serves every platform, so it
    must import only what ALL of them bundle."""
    out = {os.path.basename(LIST): load(LIST)}
    for n in sorted(os.listdir(HERE)):
        if n.startswith("frozen-modules-") and n.endswith(".txt"):
            out[n] = load(os.path.join(HERE, n))
    return out


def diff(a, b):
    """(only in a, only in b), both sorted."""
    return sorted(a - b), sorted(b - a)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--refresh":
        refresh(sys.argv[2])
    elif len(sys.argv) in (4, 5) and sys.argv[1] == "--refresh-linux":
        refresh_linux(sys.argv[2], sys.argv[3], *sys.argv[4:])
    elif len(sys.argv) == 4 and sys.argv[1] == "--diff":    # built list vs committed list: the committed one must not promise more
        gone, new = diff(load(sys.argv[2]), load(sys.argv[3]))
        for m in new:
            print("committed list has %s, the built bundle does not" % m)
        for m in gone:
            print("built bundle has %s, the committed list lacks it (refresh the list)" % m)
        sys.exit(1 if new else 0)
    else:
        bad = [(n, v) for n, mods in platform_lists().items() for v in violations(frozen=mods)]
        for n, (f, ln, m) in bad:
            print("%s:%d imports %s, which the frozen app (%s) does not bundle" % (f, ln, m, n))
        sys.exit(1 if bad else 0)

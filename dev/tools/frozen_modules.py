#!/usr/bin/env python3
"""The module list of a frozen release, and the check that a patch tree only imports from it.

A patch (overlay) runs on the Python runtime frozen into the full release it patches. PyInstaller bundles only the stdlib
and third-party modules it found at build time, so a patch that imports anything else dies at start ("No module named ...")
and the boot guard rolls it back. 5.5.1 and 5.5.2 did exactly that with `secrets`.

    python3 tools/frozen_modules.py                    # the patch tree (this dev/ tree) imports only frozen modules
    python3 tools/frozen_modules.py --refresh App.app  # rewrite frozen-modules.txt from a built app (needs PyInstaller)

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


def refresh(app, out=LIST):
    import tempfile
    from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader
    exe = os.path.join(app, "Contents", "MacOS", os.listdir(os.path.join(app, "Contents", "MacOS"))[0])
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
    with zipfile.ZipFile(os.path.join(app, "Contents", "Resources", "base_library.zip")) as z:
        mods |= {n[:-4].replace("/", ".").removesuffix(".__init__") for n in z.namelist() if n.endswith(".pyc")}
    for d, _dirs, files in os.walk(os.path.join(app, "Contents", "Frameworks")):
        if os.path.basename(d) == "lib-dynload":
            mods |= {f.split(".")[0] for f in files if f.endswith(".so")}
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("# Modules frozen into the full release a patch runs on. Rebuild: python3 tools/frozen_modules.py --refresh <App.app>\n")
        fh.write("\n".join(sorted(mods)) + "\n")
    print("wrote %d modules to %s" % (len(mods), out))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--refresh":
        refresh(sys.argv[2])
    else:
        bad = violations()
        for f, ln, m in bad:
            print("%s:%d imports %s, which the frozen app does not bundle" % (f, ln, m))
        sys.exit(1 if bad else 0)

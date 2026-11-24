"""Patch overlay: lets a patch update replace the app's own source and data without touching the signed app.

A patch update unpacks a full copy of the app's source tree into <settings dir>/overlay/current. At start-up,
activate() puts that tree in front of the bundled one, but only when it is valid for this build (same
MAJOR.MINOR line, newer patch). Python runtime and libraries always come from the bundle, so a patch cannot change them.

Safety: a marker file is written at start and removed once the server is listening. If the marker is still
there at the next start, the last start never finished, so the overlay is set aside and the bundled app runs.
Keep this file small and stable: it is the one part a patch cannot replace (the bundled copy always runs first).
Stdlib only. Inactive unless frozen (or forced by the tests).
"""
import hashlib
import importlib.machinery
import json
import os
import shutil
import sys

# Ed25519 public key of the update channel; the private half stays with the maintainer (tools/make_patch.py signs with it).
PUBLIC_KEY = "c64eb1b2388296a2147bbf68474231ad0276df026ab019c426babc85a44c348f"
SIGNED = (".patch.json", ".patch.sig")          # the signed manifest and its signature, stored inside the overlay tree
_ROOT = None
_BASE = None


def parse(v):
    return tuple(int(p) for p in str(v).strip().split("-")[0].split("."))


def base_dir():
    import settings_store
    return os.path.join(settings_store.settings_dir(), "overlay")


def verify_signed(manifest, sig):
    """The parsed manifest when `sig` (hex) is a valid signature over `manifest` bytes, else ValueError."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBLIC_KEY)).verify(bytes.fromhex(sig.decode("ascii").strip()), manifest)
    except (InvalidSignature, ValueError, UnicodeDecodeError):
        raise ValueError("signature does not check out") from None
    return json.loads(manifest)


def _hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_tree(tree, manifest):
    """The tree holds exactly the files the signed manifest lists, byte for byte (ValueError otherwise)."""
    want = manifest["files"]
    have = {}
    for d, _dirs, files in os.walk(tree):
        for f in files:
            p = os.path.join(d, f)
            if os.path.islink(p):
                raise ValueError("symbolic link in the update")
            rel = os.path.relpath(p, tree).replace(os.sep, "/")
            if rel not in SIGNED:
                have[rel] = p
    if set(have) != set(want):
        raise ValueError("files differ from the signed list")
    for rel, p in have.items():
        if _hash(p) != want[rel]:
            raise ValueError("file changed since signing: " + rel)


def _tree_ok(tree):
    """True when the stored signed manifest is valid for this version and the tree matches it exactly."""
    try:
        with open(os.path.join(tree, SIGNED[0]), "rb") as fh:
            manifest = fh.read()
        with open(os.path.join(tree, SIGNED[1]), "rb") as fh:
            sig = fh.read()
        m = verify_signed(manifest, sig)
        if m.get("version") != _read(os.path.join(tree, "VERSION")) or m.get("product") != "opengenerator":
            return False
        check_tree(tree, m)
        return True
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        return False


def _read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


class _Finder:
    """Meta-path finder that looks in the overlay tree before the bundle."""

    def __init__(self, root):
        self.root = root

    def find_spec(self, name, path=None, target=None):
        spec = importlib.machinery.PathFinder.find_spec(name, [self.root] if path is None else path)
        return spec if spec is not None and spec.origin else None     # never a namespace package


def activate(bundle_dir, base=None, frozen=None):
    """The directory the app should treat as its own: the overlay tree when valid, else bundle_dir."""
    global _ROOT, _BASE
    if _ROOT is not None:
        return _ROOT
    _ROOT = bundle_dir
    if not (getattr(sys, "frozen", False) if frozen is None else frozen) or os.environ.get("OG_NO_OVERLAY"):
        return _ROOT
    _BASE = base = base or base_dir()
    try:
        return _activate(bundle_dir, base)
    except OSError:                                              # unwritable settings dir: run the bundled copy
        _ROOT = bundle_dir
        return _ROOT


def _activate(bundle_dir, base):
    global _ROOT
    cur, marker = os.path.join(base, "current"), os.path.join(base, ".booting")
    if not os.path.isdir(cur):
        return _ROOT
    if os.path.exists(marker):                                   # the last start with this overlay never finished
        shutil.rmtree(os.path.join(base, "bad"), ignore_errors=True)
        os.replace(cur, os.path.join(base, "bad"))
        os.remove(marker)
        return _ROOT
    try:
        mine = parse(_read(os.path.join(bundle_dir, "VERSION")))
        theirs = parse(_read(os.path.join(cur, "VERSION")))
        ok = theirs[:2] == mine[:2] and theirs > mine
    except (ValueError, IndexError):
        ok = False
    if ok and not _tree_ok(cur):                                 # changed on disk since it was installed, or never signed
        shutil.rmtree(os.path.join(base, "bad"), ignore_errors=True)
        os.replace(cur, os.path.join(base, "bad"))
        ok = False
    if not ok:
        return _ROOT
    with open(marker, "w") as fh:
        fh.write("starting")
    sys.meta_path.insert(0, _Finder(cur))
    sys.path.insert(0, cur)
    _ROOT = cur
    return _ROOT


def confirm_boot():
    """The server is listening: this start of the overlay worked."""
    if _BASE:
        try:
            os.remove(os.path.join(_BASE, ".booting"))
        except OSError:
            pass


def app_dir(default):
    """Where the app's data files live: the overlay tree when active, else `default`."""
    return _ROOT if _ROOT is not None else default

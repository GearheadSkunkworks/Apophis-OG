#!/usr/bin/env python3
"""Build and sign a patch update (X.Y.Z, Z above 0) from release/.

    python3 tools/make_patch.py --notes "What changed" [--out ../prod/patch]

    python3 tools/make_patch.py --app ../prod/OpenGenerator-<v>-app.zip --notes "..."   (X.Y.0: signs the full app zip)

Writes og-patch-<v>.zip, og-patch-<v>.json (manifest) and og-patch-<v>.sig into the output folder. Attach those
three files to the GitHub Release for tag v<v>; the installed app finds them there (updater.py).
The zip is the app's source and data tree from release/ (no tests, tools or docs); run promote.py --verify first.
The signing key is read from OG_SIGNING_KEY (default: ~/.og-update-signing/ed25519.pem) and is never stored in the repo.
Standard library plus `cryptography`.
"""
import argparse
import datetime
import getpass
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
KEEP_DOCS = {"docs/redesign/meta-verification.json"}
SKIP_TOP = {"tests", "tools", "__pycache__", ".github"}
# repository documents that belong to the public repo, not to the app tree a patch replaces
SKIP_NAMES = {"README.md", "README-GUI.md", "BUILD-macos.md", "MANIFEST.sha256", ".DS_Store", "LICENSE", "NOTICE", "DISCLAIMER.md",
              "SECURITY.md", "CONTRIBUTING.md", "gearhead-logo-light.png", "gearhead-logo-dark.png"}


def tree_files(src):
    out = []
    for d, dirs, files in os.walk(src):
        rel_d = os.path.relpath(d, src).replace(os.sep, "/")
        dirs[:] = sorted(x for x in dirs if x != "__pycache__" and not (rel_d == "." and x in SKIP_TOP))
        for f in sorted(files):
            rel = f if rel_d == "." else rel_d + "/" + f
            if f in SKIP_NAMES or f.endswith(".pyc") or (rel.startswith("docs/") and rel not in KEEP_DOCS):
                continue
            out.append(rel)
    return out


def check_source(src, files, require_manifest):
    """Refuse symbolic links, and (for a real release) any file that is not exactly what promote.py wrote into MANIFEST.sha256."""
    for rel in files:
        if os.path.islink(os.path.join(src, rel)):
            raise SystemExit("Refusing a symbolic link in the patch source: %s" % rel)
    mpath = os.path.join(src, "MANIFEST.sha256")
    if not os.path.isfile(mpath):
        if require_manifest:
            raise SystemExit("%s has no MANIFEST.sha256: build it with tools/promote.py --apply, then --verify." % src)
        return
    recorded = {}
    with open(mpath, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                h, p = line.rstrip("\n").split("  ", 1)
                recorded[p] = h
    for rel in files:
        with open(os.path.join(src, rel), "rb") as fh:
            if recorded.get(rel) != hashlib.sha256(fh.read()).hexdigest():
                raise SystemExit("%s is not what promote.py wrote (changed or untracked); rebuild with promote.py --apply." % rel)


def load_key(path):
    """The signing key; an encrypted key asks for its passphrase (or reads OG_SIGNING_PASSPHRASE)."""
    from cryptography.hazmat.primitives import serialization
    with open(path, "rb") as fh:
        data = fh.read()
    pw = os.environ.get("OG_SIGNING_PASSPHRASE")
    try:
        return serialization.load_pem_private_key(data, pw.encode() if pw else None)
    except TypeError:
        return serialization.load_pem_private_key(data, getpass.getpass("Signing key passphrase: ").encode())


def protect_key(path):
    """Encrypt the signing key file in place with a passphrase you type twice."""
    from cryptography.hazmat.primitives import serialization
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        key = serialization.load_pem_private_key(data, None)
    except TypeError:
        raise SystemExit("That key is already passphrase-protected.")
    pw = getpass.getpass("New passphrase: ")
    if len(pw) < 12 or pw != getpass.getpass("Again: "):
        raise SystemExit("Passphrases differ, or are shorter than 12 characters; the key was not changed.")
    enc = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(pw.encode()))
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
    with os.fdopen(fd, "wb") as fh:
        fh.write(enc)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    print("The signing key at %s is now passphrase-protected. Keep a backup of the passphrase." % path)


def build(src, out_dir, notes, key_path, require_manifest=False):
    with open(os.path.join(src, "VERSION"), encoding="utf-8") as fh:
        version = fh.read().strip()
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts) or int(parts[2]) == 0:
        raise SystemExit("A patch needs a version like X.Y.Z with Z above 0, not %r (X.Y.0 ships as a full binary)." % version)
    files = tree_files(src)
    check_source(src, files, require_manifest)
    os.makedirs(out_dir, exist_ok=True)
    zpath = os.path.join(out_dir, "og-patch-%s.zip" % version)
    listing = {}
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in files:
            z.write(os.path.join(src, rel), rel)
            with open(os.path.join(src, rel), "rb") as fh:
                listing[rel] = hashlib.sha256(fh.read()).hexdigest()
    with open(zpath, "rb") as fh:
        data = fh.read()
    manifest = json.dumps({"product": "opengenerator", "version": version, "base": ".".join(parts[:2]),
                           "date": datetime.date.today().isoformat(), "notes": notes,
                           "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "files": listing}, indent=2).encode() + b"\n"
    key = load_key(key_path)
    base = os.path.join(out_dir, "og-patch-%s" % version)
    with open(base + ".json", "wb") as fh:
        fh.write(manifest)
    with open(base + ".sig", "w") as fh:
        fh.write(key.sign(manifest).hex() + "\n")
    return version, zpath


def build_app(zip_path, out_dir, notes, key_path):
    """Sign a full app zip (OpenGenerator-<v>-app.zip) so the in-app updater can swap the whole app from any older version.
    Writes og-app-<v>.json and .sig; attach them, with the zip, to the X.Y.0 release."""
    name = os.path.basename(zip_path)
    m = re.fullmatch(r"OpenGenerator-(\d+\.\d+\.\d+)-app\.zip", name)
    if not m:
        raise SystemExit("The app zip must be named OpenGenerator-<X.Y.Z>-app.zip, not %r." % name)
    version = m.group(1)
    with open(zip_path, "rb") as fh:
        data = fh.read()
    manifest = json.dumps({"product": "opengenerator", "kind": "app", "version": version, "date": datetime.date.today().isoformat(),
                           "notes": notes, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}, indent=2).encode() + b"\n"
    key = load_key(key_path)
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, "og-app-%s" % version)
    with open(base + ".json", "wb") as fh:
        fh.write(manifest)
    with open(base + ".sig", "w") as fh:
        fh.write(key.sign(manifest).hex() + "\n")
    return version


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--notes")
    ap.add_argument("--app", metavar="ZIP", help="sign a full app zip (OpenGenerator-<v>-app.zip) instead of building a patch")
    ap.add_argument("--protect-key", action="store_true", help="encrypt the signing key file with a passphrase, then exit")
    ap.add_argument("--src", default=os.path.join(ROOT, "release"))
    ap.add_argument("--out", default=os.path.join(ROOT, "prod", "patch"))
    ap.add_argument("--key", default=os.environ.get("OG_SIGNING_KEY") or os.path.expanduser("~/.og-update-signing/ed25519.pem"))
    a = ap.parse_args()
    if not os.path.isfile(a.key):
        sys.exit("No signing key at %s. Keep the key outside the repo; see docs/release.md." % a.key)
    if a.protect_key:
        return protect_key(a.key)
    if not a.notes:
        sys.exit("--notes \"what changed\" is required.")
    if a.app:
        v = build_app(a.app, a.out, a.notes, a.key)
        return print("app manifest %s written to %s. Attach og-app-%s.json, .sig and the app zip to GitHub Release v%s." % (v, a.out, v, v))
    v, z = build(a.src, a.out, a.notes, a.key, require_manifest=True)
    print("patch %s written to %s (%d KB). Attach the .zip, .json and .sig to GitHub Release v%s." % (v, a.out, os.path.getsize(z) // 1024, v))


if __name__ == "__main__":
    main()

"""Linux side of the in-app update: the full-app swap for a tarball or AppImage install (patch updates need nothing
here: the overlay lives in the user's settings folder on every platform).

Same trust as macOS (updater.install_app): a signed manifest (Ed25519, the key in overlay.py), then the download's sha256,
then, for a tarball, the sha256 of every file against the signed list. Nothing changes on any failure, and nothing is ever
escalated: a deb/rpm install is root-owned, so the answer there is "use the package manager". Platform facts come in as
arguments (`exe`, `appimage`, `writable`) so the decisions are plain functions with tests. Stdlib only.

Manifest (og-app-<v>-linux-<arch>.json, signed as og-app-<v>-linux-<arch>.sig):
  {"product": "opengenerator", "kind": "app", "platform": "linux", "arch": ..., "version": ..., "notes": ...,
   "tarball":  {"name": "apophis-<v>-linux-<arch>.tar.gz", "sha256": ..., "files": {"<path below the top folder>": sha256}},
   "appimage": {"name": "apophis-<v>-<arch>.AppImage", "sha256": ...}}
"""
import hashlib
import os
import shutil
import tarfile
import tempfile

PACKAGE_PREFIXES = ("/usr/lib/apophis/", "/usr/bin/", "/opt/")
ARCHES = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
PACKAGE_TEXT = ("This copy was installed by your package manager (it is root-owned), so it cannot update itself. "
                "Update it with apt, dnf or zypper, or download the newer release and install that.")


class LinuxUpdateError(Exception):
    pass


def arch_of(machine):
    try:
        return ARCHES[machine.strip().lower()]
    except KeyError:
        raise LinuxUpdateError("This computer's architecture is not supported by the updater.") from None


def own_appimage(exe, appimage, appdir):
    """$APPIMAGE when this process really runs from that AppImage, else "". AppImage programs export APPIMAGE (and APPDIR, the
    mount) to everything they start, so a deb or tarball copy launched from one inherits both; only an exe under the mount is
    the AppImage's own. Without this the in-app update would overwrite that foreign file with the signed AppImage."""
    if not appimage or not appdir:
        return ""
    mount = os.path.realpath(appdir).rstrip("/") + "/"
    return appimage if os.path.realpath(exe).startswith(mount) else ""


def tarball_root(exe, isfile=os.path.isfile):
    """<top> when exe is <top>/app/apophis-server with the launcher <top>/apophis beside app/, else None. A dev tree such as
    dist/apophis-server/apophis-server has no launcher, and swapping exe/../.. there would move dist/ itself."""
    app = os.path.dirname(exe)
    root = os.path.dirname(app)
    return root if os.path.basename(app) == "app" and isfile(os.path.join(root, "apophis")) else None


def install_kind(exe, appimage, writable, appdir="", isfile=os.path.isfile):
    """appimage | package | tarball | readonly. `exe` is the real path of the running program, `appimage` $APPIMAGE (or ""),
    `appdir` $APPDIR, `writable(path)` says whether the user can write there. Never guesses a way past a root-owned install."""
    appimage = own_appimage(exe, appimage, appdir)
    if appimage:
        return "appimage" if writable(os.path.dirname(appimage)) else "readonly"
    if exe.startswith(PACKAGE_PREFIXES):
        return "package"
    root = tarball_root(exe, isfile)
    return "tarball" if root and writable(os.path.dirname(root)) and writable(root) else "readonly"


def refuse_text(kind):
    return PACKAGE_TEXT if kind == "package" else "The folder holding this copy is not writable by you; download the newer release instead."


def names(version, arch):
    """(manifest, signature) asset names for this release and architecture."""
    stem = "og-app-%s-linux-%s" % (version, arch)
    return stem + ".json", stem + ".sig"


def pick(manifest, kind, version, arch):
    """The artifact entry for this install kind from a verified manifest (LinuxUpdateError if it is not for this build)."""
    if manifest.get("platform") != "linux" or manifest.get("arch") != arch or manifest.get("kind") != "app" or manifest.get("version") != version:
        raise LinuxUpdateError("This update is not for this version; nothing was changed.")
    art = manifest.get(kind)
    if kind not in ("tarball", "appimage") or not isinstance(art, dict) or not art.get("name") or len(str(art.get("sha256", ""))) != 64:
        raise LinuxUpdateError("This update has no download for this kind of install; nothing was changed.")
    return art


def restart_argv(argv, appimage):
    """What to run to start the new copy: an AppImage is relaunched by its own path (the running one sits in an old mount)."""
    return [appimage] + argv[1:] if appimage else argv


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def extract_tarball(path, dest):
    """Unpack a release tarball's single top folder into `dest` (returns that folder). Plain files, folders and relative links that
    stay inside the tree only; modes are normalised (no setuid, no group/world write)."""
    real = os.path.realpath(dest)
    top = None
    with tarfile.open(path) as tar:
        for m in tar.getmembers():
            parts = m.name.split("/")
            if m.name.startswith("/") or ".." in parts or (top and parts[0] != top):
                raise LinuxUpdateError("The update contains an unsafe path; nothing was changed.")
            top = top or parts[0]
            out = os.path.join(dest, m.name)
            if os.path.commonpath([real, os.path.realpath(os.path.dirname(out))]) != real:
                raise LinuxUpdateError("The update contains an unsafe path; nothing was changed.")
            if m.isdir():
                os.makedirs(out, exist_ok=True)
            elif m.isfile():
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with tar.extractfile(m) as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                os.chmod(out, 0o755 if m.mode & 0o111 else 0o644)
            elif m.issym():
                tgt = os.path.realpath(os.path.join(os.path.dirname(out), m.linkname))
                if os.path.isabs(m.linkname) or os.path.commonpath([real, tgt]) != real:
                    raise LinuxUpdateError("The update contains an unsafe link; nothing was changed.")
                os.makedirs(os.path.dirname(out), exist_ok=True)
                os.symlink(m.linkname, out)
            else:
                raise LinuxUpdateError("The update contains an unsupported file type; nothing was changed.")
    if not top:
        raise LinuxUpdateError("The update is incomplete; nothing was changed.")
    return os.path.join(dest, top)


def check_files(tree, files):
    """Every regular file under `tree` is in the signed list with the same sha256, and nothing is missing."""
    have = {}
    for d, _dirs, fs in os.walk(tree):    # lint-ok: extract_tarball already refused every link that leaves the tree; in-tree links are legitimate
        for f in fs:
            p = os.path.join(d, f)
            if not os.path.islink(p):
                have[os.path.relpath(p, tree).replace(os.sep, "/")] = p
    bad = LinuxUpdateError("The update's files do not match its signed list; nothing was changed.")
    if set(have) != set(files):
        raise bad
    for rel, p in have.items():
        with open(p, "rb") as fh:
            if sha256(fh.read()) != files[rel]:
                raise bad


def _swap(new, target, keep):
    """Put `new` where `target` is; the old one goes to `keep` (so it can be put back by hand). Rolls back on failure."""
    old = target + ".old"
    shutil.rmtree(old, ignore_errors=True)
    if os.path.isfile(old):
        os.remove(old)
    os.replace(target, old)
    try:
        os.replace(new, target)
    except BaseException:
        os.replace(old, target)
        raise
    shutil.rmtree(keep, ignore_errors=True)
    try:
        os.makedirs(keep)
        shutil.move(old, keep)
    except OSError:
        shutil.rmtree(old, ignore_errors=True)


def install(kind, data, art, exe, appimage, keep, expected_version, read_version):
    """Verify `data` (the downloaded file) against the signed entry `art`, then swap it in. `read_version(tree)` is how the new
    tarball tree names its own version (must equal the signed one). Returns the install path that now holds the new copy."""
    if kind not in ("tarball", "appimage"):
        raise LinuxUpdateError(refuse_text(kind))
    if sha256(data) != art["sha256"]:
        raise LinuxUpdateError("The download did not match its checksum; nothing was changed.")
    if kind == "appimage":
        fd, tmp = tempfile.mkstemp(prefix=".og-update-", dir=os.path.dirname(appimage))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.chmod(tmp, 0o755)
            _swap(tmp, appimage, keep)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        return appimage
    root = tarball_root(exe)
    if root is None:
        raise LinuxUpdateError(refuse_text("readonly"))
    work = tempfile.mkdtemp(prefix=".og-update-", dir=os.path.dirname(root))   # beside the install so the rename never crosses a volume
    try:
        zpath = os.path.join(work, "dl.tar.gz")
        with open(zpath, "wb") as fh:
            fh.write(data)
        new = extract_tarball(zpath, os.path.join(work, "x"))
        check_files(new, art["files"])
        if read_version(new) != expected_version:
            raise LinuxUpdateError("The update is for a different version; nothing was changed.")
        _swap(new, root, keep)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return root

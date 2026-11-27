#!/usr/bin/env python3
"""Pure helpers for the Linux download artifacts (tarball, SHA256SUMS). Standard library only.

The build recipe lives in packaging/linux/ and calls this file; it is here so the unit gate can test it.

    linux_pkg.py name  <version> <arch>              # print apophis-<version>-linux-<arch>.tar.gz
    linux_pkg.py tar   <bundle-dir> <version> <arch> <out-dir>   # tar.gz of <bundle-dir>, reproducible; prints the path
    linux_pkg.py sums  <dir>                         # write <dir>/SHA256SUMS covering every other file in <dir>
    linux_pkg.py check <dir>                         # verify <dir>/SHA256SUMS; exit 1 on any mismatch, missing or extra file

L4 (packages, built from the tarball above; every file root-owned, never group/world-writable, no setuid):
    linux_pkg.py deb    <tarball> <out-dir>          # apophis_<ver>_<debarch>.deb (pure Python: ar + tar, reproducible)
    linux_pkg.py root   <tarball> <dest>             # the install tree (/usr/bin, /usr/lib/apophis, /usr/share/...) under <dest>
    linux_pkg.py spec   <tarball> <stage-dir>        # print the RPM spec; %install copies <stage-dir> into the buildroot
    linux_pkg.py appdir <tarball> <dest>             # the AppDir (the tarball tree + AppRun, .DirIcon, top-level desktop and icon)
    linux_pkg.py names  <tarball>                    # print the deb, rpm and AppImage file names, one per line
"""
import gzip
import hashlib
import io
import os
import re
import sys
import shutil
import stat
import tarfile
import tempfile

NAME = "apophis"
SUMS = "SHA256SUMS"
ARCHES = ("x86_64", "aarch64")
_ARCH_ALIASES = {"x86_64": "x86_64", "amd64": "x86_64", "x64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}
_VERSION = re.compile(r"^\d+(\.\d+){1,3}([a-z0-9.+-]*)$")


def norm_arch(machine):
    """`uname -m` / Docker / Debian spelling to the one name used in artifacts."""
    try:
        return _ARCH_ALIASES[machine.strip().lower()]
    except KeyError:
        raise ValueError("unsupported architecture %r (supported: %s)" % (machine, ", ".join(ARCHES))) from None


def check_version(version):
    version = version.strip()
    if not _VERSION.match(version):
        raise ValueError("not a release version: %r" % version)
    return version


def tarball_name(version, arch):
    return "%s-%s-linux-%s.tar.gz" % (NAME, check_version(version), norm_arch(arch))


def top_dir(version, arch):
    return tarball_name(version, arch)[:-len(".tar.gz")]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _artifacts(directory):
    return sorted(n for n in os.listdir(directory) if n != SUMS and os.path.isfile(os.path.join(directory, n)))


def sums_text(directory):
    """`sha256sum` format ("<hex>  <name>"), one line per artifact, sorted. Refuses an empty directory."""
    names = _artifacts(directory)
    if not names:
        raise ValueError("no artifacts in %s" % directory)
    return "".join("%s  %s\n" % (sha256_file(os.path.join(directory, n)), n) for n in names)


def write_sums(directory):
    path = os.path.join(directory, SUMS)
    text = sums_text(directory)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def parse_sums(text):
    """{name: hex}. Accepts the text and binary marks `sha256sum` writes ("  " or " *"); rejects anything else."""
    out = {}
    for n, ln in enumerate(text.splitlines(), 1):
        if not ln.strip():
            continue
        m = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\0]+)", ln)
        if not m:
            raise ValueError("%s line %d is malformed" % (SUMS, n))
        out[m.group(2)] = m.group(1)
    return out


def verify_sums(directory):
    """List of problems (empty = every listed file matches and every file in the directory is listed)."""
    with open(os.path.join(directory, SUMS), encoding="utf-8") as fh:
        want = parse_sums(fh.read())
    bad = []
    for name, digest in sorted(want.items()):
        p = os.path.join(directory, name)
        if not os.path.isfile(p):
            bad.append("%s: listed but missing" % name)
        elif sha256_file(p) != digest:
            bad.append("%s: checksum mismatch" % name)
    bad += ["%s: present but not listed" % n for n in _artifacts(directory) if n not in want]
    return bad


def make_tarball(bundle, version, arch, out_dir):
    """tar.gz holding `bundle`'s contents under apophis-<version>-linux-<arch>/. Reproducible: sorted entries, zero
    mtime and owner, fixed gzip header, so the same bundle always gives the same bytes (and the same checksum)."""
    top = top_dir(version, arch)
    dest = os.path.join(out_dir, tarball_name(version, arch))
    entries = []
    for d, dirs, files in os.walk(bundle):
        dirs.sort()
        rel = os.path.relpath(d, bundle)
        entries.append(rel)
        entries.extend(os.path.normpath(os.path.join(rel, f)) for f in sorted(files))
    with open(dest, "wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for rel in entries:
            src = os.path.join(bundle, rel)
            ti = tar.gettarinfo(src, arcname=top if rel == "." else "%s/%s" % (top, rel))
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = 0, 0, 0, "", ""
            if ti.isreg():
                with open(src, "rb") as fh:
                    tar.addfile(ti, fh)
            else:
                tar.addfile(ti)
    return dest


# ---- L4: .deb, .rpm, AppImage -------------------------------------------------------------------------------------------
MAINTAINER = "Apophis maintainers <noreply@users.noreply.github.com>"
SUMMARY = "Network traffic scenario generator"
DESCRIPTION = ("Apophis generates high-fidelity network traffic scenarios (packet captures) and serves its interface "
               "on 127.0.0.1 for use in a browser. Replaying a capture onto an interface needs tcpreplay, which is "
               "a recommended (optional) dependency.")
MIN_GLIBC = "2.34"                       # the build floor (RHEL 9); Ubuntu 22.04 has 2.35
DEB_ARCH = {"x86_64": "amd64", "aarch64": "arm64"}
_TARBALL = re.compile(r"^apophis-(\d[^/]*)-linux-(x86_64|aarch64)\.tar\.gz$")
_KNOWN_TOP = {"apophis", "app", "share", "LICENSE", "NOTICE", "VERSION"}


def parse_tarball_name(name):
    """(version, arch) from apophis-<version>-linux-<arch>.tar.gz."""
    m = _TARBALL.match(os.path.basename(name))
    if not m:
        raise ValueError("not an Apophis tarball name: %r" % name)
    return check_version(m.group(1)), m.group(2)


def _split_pre(version):
    """'6.0.0rc1' -> ('6.0.0', 'rc1'); '6.0.0' -> ('6.0.0', '')."""
    m = re.match(r"^(\d+(?:\.\d+){1,3})(.*)$", check_version(version))
    return m.group(1), m.group(2)


def deb_version(version):
    """A pre-release sorts BEFORE the release (6.0.0~rc1 < 6.0.0), as dpkg and the version rule need."""
    base, pre = _split_pre(version)
    return base + ("~" + pre.lstrip(".-+") if pre else "")


def rpm_version_release(version):
    """('6.0.0', '1') for a release, ('6.0.0', '0.rc1') for a pre-release (a 0. release sorts before the release's 1)."""
    base, pre = _split_pre(version)
    return base, ("0." + re.sub(r"[^A-Za-z0-9.]", "", pre) if pre else "1")


def deb_name(version, arch):
    return "apophis_%s_%s.deb" % (deb_version(version), DEB_ARCH[norm_arch(arch)])


def rpm_name(version, arch):
    v, r = rpm_version_release(version)
    return "apophis-%s-%s.%s.rpm" % (v, r, norm_arch(arch))


def appimage_name(version, arch):
    return "apophis-%s-%s.AppImage" % (check_version(version), norm_arch(arch))


def norm_mode(mode, is_dir=False):
    """The only modes a package ships: directories 755, programs 755, everything else 644 (no group/world write, no setuid)."""
    return 0o755 if is_dir or mode & 0o111 else 0o644


def _installed_path(rel):
    """Where a file of the tarball tree (path below its top directory) goes in a package, or None to leave it out."""
    top, _, rest = rel.partition("/")
    if top not in _KNOWN_TOP:
        raise ValueError("unexpected entry in the tarball: %r" % rel)
    if top == "apophis":
        return "usr/bin/apophis"
    if top == "app":
        return "usr/lib/apophis" + ("/" + rest if rest else "")
    if top == "share":
        return {"apophis.desktop": "usr/share/applications/apophis.desktop",
                "apophis.png": "usr/share/icons/hicolor/256x256/apps/apophis.png"}.get(rest, "" if not rest else None)
    if top in ("LICENSE", "NOTICE"):
        return "usr/share/doc/apophis/" + top
    return None                           # VERSION: the app's own copy is in _internal/


def _extract(tarball, dest, mapper):
    """Unpack `tarball` below `dest` through mapper(path-below-top) -> relative destination or None. Refuses paths that
    leave `dest`, hard links, devices and symlinks that point outside their own tree; normalises every mode."""
    version, arch = parse_tarball_name(tarball)
    top = top_dir(version, arch)
    os.makedirs(dest, exist_ok=True)
    real = os.path.realpath(dest)
    with tarfile.open(tarball) as tar:
        for m in tar.getmembers():
            if m.name == top:
                continue
            if not m.name.startswith(top + "/"):
                raise ValueError("entry outside %s/: %r" % (top, m.name))
            rel = m.name[len(top) + 1:]
            out = mapper(rel)
            if out is None or out == "":
                continue
            path = os.path.join(dest, out)
            if os.path.commonpath([real, os.path.realpath(os.path.dirname(path))]) != real:
                raise ValueError("path escapes the destination: %r" % m.name)
            if m.isdir():
                os.makedirs(path, exist_ok=True)
                os.chmod(path, 0o755)
            elif m.isfile():
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with tar.extractfile(m) as src, open(path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                os.chmod(path, norm_mode(m.mode))
            elif m.issym():
                if os.path.isabs(m.linkname) or os.path.commonpath([real, os.path.realpath(os.path.join(os.path.dirname(path), m.linkname))]) != real:
                    raise ValueError("symlink points outside the tree: %r -> %r" % (m.name, m.linkname))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                os.symlink(m.linkname, path)
            else:
                raise ValueError("unsupported entry type for %r" % m.name)
    # intermediate directories created implicitly above
    for d, dirs, _ in os.walk(dest):
        os.chmod(d, 0o755)
    return version, arch


def build_root(tarball, dest):
    """The installed file tree of the .deb and .rpm (usr/bin/apophis, usr/lib/apophis/..., usr/share/...)."""
    version, arch = _extract(tarball, dest, _installed_path)
    for need in ("usr/bin/apophis", "usr/lib/apophis/apophis-server", "usr/lib/apophis/_internal/VERSION",
                 "usr/share/applications/apophis.desktop", "usr/share/icons/hicolor/256x256/apps/apophis.png",
                 "usr/share/doc/apophis/LICENSE", "usr/share/doc/apophis/NOTICE"):
        if not os.path.lexists(os.path.join(dest, need)):
            raise ValueError("the tarball lacks %s" % need)
    with open(os.path.join(dest, "usr/lib/apophis/_internal/VERSION"), encoding="utf-8") as fh:
        if fh.read().strip() != version:
            raise ValueError("the bundle's VERSION is not %s" % version)
    return version, arch


def _keep_known(rel):
    if rel.partition("/")[0] not in _KNOWN_TOP:
        raise ValueError("unexpected entry in the tarball: %r" % rel)
    return rel


def build_appdir(tarball, dest):
    """The AppImage tree: the tarball tree itself (the launcher finds the app next to it) plus what AppImage tooling wants."""
    version, arch = _extract(tarball, dest, _keep_known)
    shutil.copy(os.path.join(dest, "share/apophis.desktop"), os.path.join(dest, "apophis.desktop"))
    shutil.copy(os.path.join(dest, "share/apophis.png"), os.path.join(dest, "apophis.png"))
    for f in ("apophis.desktop", "apophis.png"):
        os.chmod(os.path.join(dest, f), 0o644)
    for link, target in (("AppRun", "apophis"), (".DirIcon", "apophis.png")):    # AppRun -> launcher: it resolves symlinks itself
        lp = os.path.join(dest, link)
        if os.path.lexists(lp):
            os.remove(lp)
        os.symlink(target, lp)
    return version, arch


def walk_tree(root):
    """[(relative path, lstat mode)] for everything below root, sorted; the one place package content is enumerated."""
    out = []
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for n in dirs + sorted(files):
            p = os.path.join(d, n)
            out.append((os.path.relpath(p, root), os.lstat(p).st_mode))
    return sorted(out)


def tree_problems(root):
    """Why a tree must not be packaged: group/world-writable, setuid/setgid/sticky, or anything but file/dir/symlink."""
    bad = []
    for rel, mode in walk_tree(root):
        if stat.S_ISLNK(mode):
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            bad.append("%s: not a regular file, directory or symlink" % rel)
        if mode & 0o7022:
            bad.append("%s: mode %o is group/world-writable or setuid/setgid/sticky" % (rel, mode & 0o7777))
    return bad


def _tar_gz_bytes(entries):
    """Reproducible gzip'd tar of [(arcname, source path or None for a directory)]; root-owned, mtime = SOURCE_DATE_EPOCH or 0."""
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=epoch, compresslevel=9) as gz, \
            tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for arc, src in entries:
            ti = tar.gettarinfo(src, arcname=arc) if src else tarfile.TarInfo(arc)
            if not src:
                ti.type, ti.mode = tarfile.DIRTYPE, 0o755
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = epoch, 0, 0, "root", "root"
            if ti.isreg():
                with open(src, "rb") as fh:
                    tar.addfile(ti, fh)
            else:
                tar.addfile(ti)
    return buf.getvalue()


def _ar(members, epoch):
    out = [b"!<arch>\n"]
    for name, data in members:
        out.append(("%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name, epoch, 0, 0, "100644", len(data))).encode("ascii"))
        out.append(data + (b"\n" if len(data) % 2 else b""))
    return b"".join(out)


def deb_control(version, arch, installed_kib):
    return ("Package: apophis\nVersion: %s\nSection: net\nPriority: optional\nArchitecture: %s\nMaintainer: %s\n"
            "Installed-Size: %d\nDepends: libc6 (>= %s)\nRecommends: tcpreplay\nDescription: %s\n %s\n"
            % (deb_version(version), DEB_ARCH[norm_arch(arch)], MAINTAINER, installed_kib, MIN_GLIBC, SUMMARY,
               DESCRIPTION)).encode()


def make_deb(tarball, out_dir):
    """Build apophis_<ver>_<arch>.deb from the tarball without dpkg: ar(debian-binary, control.tar.gz, data.tar.gz)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "root")
        version, arch = build_root(tarball, root)
        bad = tree_problems(root)
        if bad:
            raise ValueError("; ".join(bad))
        entries = [("./", None)]
        md5, size = [], 0
        for rel, mode in walk_tree(root):
            src = os.path.join(root, rel)
            entries.append(("./" + rel + ("/" if stat.S_ISDIR(mode) else ""), None if stat.S_ISDIR(mode) else src))
            if stat.S_ISREG(mode):
                size += os.path.getsize(src)
                md5.append("%s  %s\n" % (hashlib.md5(open(src, "rb").read(), usedforsecurity=False).hexdigest(), rel))   # dpkg's own file format, not security
        data = _tar_gz_bytes(entries)
        cdir = os.path.join(tmp, "control")
        os.makedirs(cdir)
        for name, text in (("control", deb_control(version, arch, (size + 1023) // 1024)), ("md5sums", "".join(md5).encode())):
            with open(os.path.join(cdir, name), "wb") as fh:
                fh.write(text)
            os.chmod(os.path.join(cdir, name), 0o644)
        control = _tar_gz_bytes([("./", None), ("./control", os.path.join(cdir, "control")), ("./md5sums", os.path.join(cdir, "md5sums"))])
    dest = os.path.join(out_dir, deb_name(version, arch))
    with open(dest, "wb") as fh:
        fh.write(_ar([("debian-binary", b"2.0\n"), ("control.tar.gz", control), ("data.tar.gz", data)], int(os.environ.get("SOURCE_DATE_EPOCH", "0"))))
    return dest


def read_deb(path):
    """({member: bytes}, control text, [(name, mode, uid, gid, linkname, type)]) of a .deb; what tests and the verifier inspect."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if not raw.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    members, i = {}, 8
    while i < len(raw):
        name, size = raw[i:i + 16].decode().strip().rstrip("/"), int(raw[i + 48:i + 58])
        members[name] = raw[i + 60:i + 60 + size]
        i += 60 + size + size % 2
    ctl = tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"]))
    text = ctl.extractfile("./control").read().decode()
    data = tarfile.open(fileobj=io.BytesIO(members["data.tar.gz"]))
    return members, text, [(m.name, m.mode, m.uid, m.gid, m.linkname, m.type) for m in data.getmembers()]


def rpm_spec(tarball, stage_dir):
    """The spec for rpmbuild. Bundled libraries are not the distro's: no automatic requires/provides, no stripping, no
    byte-compiling, no debuginfo. %install only copies the tree that `root` made, so file modes are the ones checked here."""
    version, arch = parse_tarball_name(tarball)
    v, r = rpm_version_release(version)
    return """%global debug_package %{{nil}}
%global __strip /bin/true
%global __os_install_post %{{nil}}
%global _build_id_links none
%global _missing_build_ids_terminate_build 0
AutoReqProv: no
Name: apophis
Version: {v}
Release: {r}
Summary: {summary}
License: Apache-2.0
BuildArch: {arch}
Requires: glibc >= {glibc}
Recommends: tcpreplay

%description
{desc}

%prep
%build
%install
cp -a {stage}/. %{{buildroot}}/

%files
%defattr(-,root,root,-)
/usr/bin/apophis
/usr/lib/apophis
/usr/share/applications/apophis.desktop
/usr/share/icons/hicolor/256x256/apps/apophis.png
/usr/share/doc/apophis
""".format(v=v, r=r, summary=SUMMARY, arch=arch, glibc=MIN_GLIBC, desc=DESCRIPTION, stage=stage_dir)


def main(argv):
    try:
        cmd, args = argv[1], argv[2:]
        if cmd == "name" and len(args) == 2:
            print(tarball_name(*args))
        elif cmd == "tar" and len(args) == 4:
            print(make_tarball(*args))
        elif cmd == "sums" and len(args) == 1:
            print(write_sums(args[0]))
        elif cmd == "deb" and len(args) == 2:
            print(make_deb(*args))
        elif cmd == "root" and len(args) == 2:
            build_root(*args)
        elif cmd == "appdir" and len(args) == 2:
            build_appdir(*args)
        elif cmd == "spec" and len(args) == 2:
            print(rpm_spec(*args), end="")
        elif cmd == "names" and len(args) == 1:
            v, a = parse_tarball_name(args[0])
            print(deb_name(v, a), rpm_name(v, a), appimage_name(v, a), sep="\n")
        elif cmd == "check" and len(args) == 1:
            bad = verify_sums(args[0])
            for b in bad:
                print(b, file=sys.stderr)
            return 1 if bad else 0
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (ValueError, OSError, IndexError) as e:
        print("linux_pkg: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

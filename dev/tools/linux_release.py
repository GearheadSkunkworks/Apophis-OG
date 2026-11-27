#!/usr/bin/env python3
"""The Linux release asset set and its one SHA256SUMS. Standard library only; reuses linux_pkg.

    linux_release.py names   <version>               # the 8 asset names (tarball, deb, rpm, AppImage x 2 arches), one per line
    linux_release.py signed  <version>               # the 4 names the owner's signing step adds (og-app-<v>-linux-<arch>.json/.sig)
    linux_release.py collect <build-dir> <version> <out-dir>   # copy the assets from <build-dir>/<arch>/artifacts, write SHA256SUMS
    linux_release.py verify  <out-dir> <version> [--signed]    # exit 1 unless exactly the asset set is there and every digest matches
    linux_release.py files   <out-dir> <version>     # the upload list (assets, SHA256SUMS, signed manifests when present)
    linux_release.py check-signed <manifest.json> <manifest.sig> <version>   # exit 1 unless the signature verifies and the manifest is for <version>

SHA256SUMS covers the 8 assets. The signed manifests are separate: they are signed after the assets exist, by the owner
(make_patch.py --linux asks for the key passphrase itself), and carry their own digests. This file never reads a key.
"""
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import linux_pkg  # noqa: E402 - sys.path is set up first

SUMS = linux_pkg.SUMS


def asset_names(version):
    """Sorted names of every file a Linux release carries under SHA256SUMS."""
    out = []
    for a in linux_pkg.ARCHES:
        out += [linux_pkg.tarball_name(version, a), linux_pkg.deb_name(version, a), linux_pkg.rpm_name(version, a),
                linux_pkg.appimage_name(version, a)]
    return sorted(out)


def signed_names(version):
    """The owner-signed updater manifests (same names updater_linux.names gives)."""
    linux_pkg.check_version(version)
    return sorted("og-app-%s-linux-%s.%s" % (version, a, e) for a in linux_pkg.ARCHES for e in ("json", "sig"))


def collect(build_dir, version, out_dir):
    """Copy the assets out of <build-dir>/<arch>/artifacts into an empty <out-dir> and write the single SHA256SUMS."""
    if os.path.isdir(out_dir) and os.listdir(out_dir):
        raise ValueError("%s is not empty" % out_dir)
    srcs, missing = {}, []
    for n in asset_names(version):
        found = [os.path.join(build_dir, a, "artifacts", n) for a in linux_pkg.ARCHES
                 if os.path.isfile(os.path.join(build_dir, a, "artifacts", n))]
        if found:
            srcs[n] = found[0]
        else:
            missing.append(n)
    if missing:
        raise ValueError("missing from %s: %s" % (build_dir, ", ".join(missing)))
    os.makedirs(out_dir, exist_ok=True)
    for n, p in srcs.items():
        shutil.copyfile(p, os.path.join(out_dir, n))
    return linux_pkg.write_sums(out_dir)


def check_signed(json_path, sig_path, version):
    """Problems (empty = the .sig is a valid signature, with the app's baked-in public key, over exactly these .json bytes, and the
    signed manifest is for `version`). Existence of the two files proves nothing: a stale .sig beside a newer .json is the failure."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import overlay
        with open(json_path, "rb") as fh:
            manifest = fh.read()
        with open(sig_path, "rb") as fh:
            sig = fh.read()
        m = overlay.verify_signed(manifest, sig)
    except ImportError:
        return ["%s: cannot verify the signature here (the 'cryptography' package is missing)" % os.path.basename(json_path)]
    except OSError as e:
        return ["%s: %s" % (os.path.basename(e.filename or json_path), e.strerror)]
    except ValueError:
        return ["%s: the signature does not verify over this manifest (stale .sig, or the manifest changed after signing)" % os.path.basename(json_path)]
    if not isinstance(m, dict) or m.get("version") != version:
        return ["%s: the signed manifest is for version %r, not %s" % (os.path.basename(json_path), m.get("version") if isinstance(m, dict) else None, version)]
    return []


def verify(out_dir, version, signed=False):
    """Problems (empty = the directory holds exactly the asset set and every digest in SHA256SUMS matches)."""
    want, extra_ok = set(asset_names(version)), set(signed_names(version))
    try:
        with open(os.path.join(out_dir, SUMS), encoding="utf-8") as fh:
            listed = linux_pkg.parse_sums(fh.read())
    except OSError as e:
        return ["%s: %s" % (SUMS, e.strerror)]
    bad = ["%s: not listed in %s" % (n, SUMS) for n in sorted(want - set(listed))]
    bad += ["%s: listed but not a Linux release asset" % n for n in sorted(set(listed) - want)]
    for n in sorted(want & set(listed)):
        p = os.path.join(out_dir, n)
        if not os.path.isfile(p):
            bad.append("%s: missing" % n)
        elif linux_pkg.sha256_file(p) != listed[n]:
            bad.append("%s: checksum mismatch" % n)
    present = {n for n in os.listdir(out_dir) if os.path.isfile(os.path.join(out_dir, n))}
    bad += ["%s: unexpected file" % n for n in sorted(present - want - extra_ok - {SUMS})]
    if signed:
        bad += ["%s: signed manifest missing (the owner signs: make_patch.py --linux)" % n for n in sorted(extra_ok - present)]
        for a in linux_pkg.ARCHES:
            j, s = ("og-app-%s-linux-%s.%s" % (version, a, e) for e in ("json", "sig"))
            if j in present and s in present:
                problems = check_signed(os.path.join(out_dir, j), os.path.join(out_dir, s), version)
                bad += problems
                if not problems:                      # the signed per-file digests must be the files this directory holds
                    with open(os.path.join(out_dir, j), encoding="utf-8") as fh:
                        m = json.load(fh)
                    for kind in ("tarball", "appimage"):
                        art = m.get(kind)
                        if isinstance(art, dict) and art.get("name") in listed and art.get("sha256") != listed[art["name"]]:
                            bad.append("%s: signed digest of %s differs from %s" % (j, art["name"], SUMS))
    return bad


def upload_files(out_dir, version):
    """Assets, SHA256SUMS and whichever signed manifests exist, as paths."""
    names = asset_names(version) + [SUMS] + [n for n in signed_names(version) if os.path.isfile(os.path.join(out_dir, n))]
    return [os.path.join(out_dir, n) for n in names]


def main(argv):
    try:
        cmd, args = argv[1], argv[2:]
        if cmd == "names" and len(args) == 1:
            print("\n".join(asset_names(args[0])))
        elif cmd == "signed" and len(args) == 1:
            print("\n".join(signed_names(args[0])))
        elif cmd == "collect" and len(args) == 3:
            print(collect(*args))
        elif cmd == "verify" and len(args) in (2, 3):
            bad = verify(args[0], args[1], signed=args[2:] == ["--signed"])
            for b in bad:
                print(b, file=sys.stderr)
            return 1 if bad else 0
        elif cmd == "check-signed" and len(args) == 3:
            bad = check_signed(*args)
            for b in bad:
                print(b, file=sys.stderr)
            return 1 if bad else 0
        elif cmd == "files" and len(args) == 2:
            print("\n".join(upload_files(*args)))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (ValueError, OSError, IndexError) as e:
        print("linux_release: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

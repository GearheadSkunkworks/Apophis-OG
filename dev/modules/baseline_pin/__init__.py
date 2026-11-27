"""Validation capability module (v5c Phase 6): the 466,343 baseline pin as a self-test.

Makes the project's core regression check a runnable capability. ``register`` adds nothing to
the engine -- this module exists only to carry a ``self_test`` that builds the no-module
baseline and asserts the historical packet count. Load it and hit Test (or "Test all") to
confirm the core still produces exactly 466,343 packets. The build writes to a temp dir with
absolute paths (no chdir) and cleans up after itself.
"""
import os
import shutil
import tempfile

PIN = 466343
SCALE = 0.004


def register(kernel):
    # validation-only: contributes no capability, so there is nothing to tear down
    pass


def self_test():
    import opengenerator_build as B
    inv = os.path.join(os.path.dirname(os.path.abspath(B.__file__)), "inventory.json")
    d = tempfile.mkdtemp(prefix="og-pin-")
    try:
        r = B.build(scale=SCALE, out=os.path.join(d, "pin.pcap"),
                    keylog=os.path.join(d, "pin.keys"), inventory=inv,
                    certs_dir=None, iocs_prefix=None, modules=[], progress=False)
        n = r["packets"]
        return {"ok": n == PIN,
                "detail": "no-module baseline (--scale %s) = %d packets, expected %d"
                          % (SCALE, n, PIN)}
    except Exception as e:                                   # noqa: BLE001 - build failure is the check result, returned as not ok
        return {"ok": False, "detail": "build failed: %s" % e}
    finally:
        shutil.rmtree(d, ignore_errors=True)

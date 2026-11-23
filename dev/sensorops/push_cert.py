"""push_cert — load the generated server certificates and keys into a sensor.

Destructive: it replaces every SSL decryption key on the sensor. The generator mints a fresh
RSA key for every simulated server on every build, so the certs in `certs/` only ever decrypt
the capture they were produced with, and a sensor cannot tell last week's dead key from this
one by name — so the push clears everything, then uploads each .crt/.key pair and maps the
protocol to its port. A key with no protocol mapping is accepted and silently decrypts nothing.

Platform-agnostic: all sensor-API specifics live behind a SensorProvider
(``sensorops.providers``). This module orchestrates the sequence and owns the worker thread
and the cancellable, credential-free status the browser polls (the API key never reaches
``status()``).
"""
import os
import threading
import time

from .providers import get_provider
from ._util import path_hint   # noqa: F401 — re-exported for callers (server.py)

# ---------------------------------------------------------------------------------------
# state. Deliberately holds no credential. status() is polled by the browser, so anything
# in here reaches the page; the API key must never be one of those things.
# ---------------------------------------------------------------------------------------
SSTATE = {
    "running": False, "done": False, "error": None, "phase": "idle",
    "sensor": "", "deleted": 0, "uploaded": 0, "mapped": 0, "failed": 0,
    "unmapped": 0, "shared_mapping": False,
    "total": 0, "log": [], "started": 0.0,
}
SLOCK = threading.Lock()
CANCEL = threading.Event()


def _log(msg):
    with SLOCK:
        SSTATE["log"].append(msg)
        del SSTATE["log"][:-400]


def find_pairs(certs_dir):
    """Every .crt with a matching .key, sorted. The CA has no private key, so it is excluded
    automatically — it is also useless for decryption, which needs the leaf's key.

    Expands `~` itself. The field's own placeholder suggests `~/OpenGenerator-Captures/certs`, and
    without this that exact string finds nothing and reports it as an empty folder.
    """
    out = []
    certs_dir = os.path.expanduser(certs_dir or "")
    if not os.path.isdir(certs_dir):
        return out
    for name in sorted(os.listdir(certs_dir)):
        if not name.endswith(".key"):
            continue
        crt = os.path.join(certs_dir, name[:-4] + ".crt")
        key = os.path.join(certs_dir, name)
        if os.path.exists(crt):
            out.append((name[:-4], crt, key))
    return out


def preflight(sensor, apikey, certs_dir=None):
    """Prove the sensor is reachable, the key works, and say what is about to be destroyed.

    Read-only on purpose: the push deletes every existing decryption key, so the operator is
    told how many there are *before* being asked to confirm, not after.
    """
    report = {"ok": False, "sensor": sensor, "existing": None, "pairs": 0,
              "errors": [], "warnings": [], "appliance": ""}
    if not sensor:
        report["errors"].append("No sensor address given.")
    if not apikey:
        report["errors"].append("No API key given.")
    if report["errors"]:
        return report

    provider = get_provider(sensor, apikey)
    try:
        ident = provider.identity()
        if ident:
            report["appliance"] = "%s (%s, firmware %s)" % (
                ident["hostname"], ident["platform"], ident["version"])
    except Exception as e:                                 # noqa: BLE001
        report["errors"].append(provider.explain(e))
        return report

    try:
        report["existing"] = len(provider.list_decrypt_keys())
    except Exception as e:                                 # noqa: BLE001
        report["errors"].append(provider.explain(e))
        return report

    if certs_dir:
        # A path that does not exist and a folder with nothing in it are different faults with
        # different fixes; never let one failure produce two wrong remedies.
        expanded = os.path.expanduser(certs_dir)
        pairs = find_pairs(expanded)
        report["pairs"] = len(pairs)
        report["certs_dir"] = expanded
        if not os.path.isdir(expanded):
            report["errors"].append(
                "That folder does not exist: %s.%s" % (expanded, path_hint(expanded)))
        elif not pairs:
            report["errors"].append(
                "%s exists but holds no .crt/.key pairs — generate a capture with "
                "‘Export server certs + keys’ ticked first." % expanded)
    if report["existing"]:
        report["warnings"].append(
            "%d SSL decryption key(s) already on this sensor will be DELETED." % report["existing"])
    report["ok"] = not report["errors"]
    return report


def _run(sensor, apikey, certs_dir, protocol, port, label):
    provider = get_provider(sensor, apikey)
    try:
        pairs = find_pairs(certs_dir)
        with SLOCK:
            SSTATE["total"] = len(pairs)
        if not pairs:
            raise RuntimeError("no certificate/key pairs in %s" % certs_dir)

        # 1. Clear what is there. A sensor that accumulates one dead key set per generation
        #    becomes useless, because the generator mints new keys every run and nothing
        #    distinguishes a live key from last week's by name alone.
        with SLOCK:
            SSTATE["phase"] = "deleting"
        _log("removing existing SSL decryption keys …")
        for k in provider.list_decrypt_keys():
            if CANCEL.is_set():
                raise RuntimeError("cancelled")
            kid = k.get("id")
            if not kid:
                continue
            try:
                provider.delete_decrypt_key(kid)
                with SLOCK:
                    SSTATE["deleted"] += 1
            except Exception as e:                         # noqa: BLE001
                _log("  could not delete %s — %s" % ((k.get("name") or kid)[:40], provider.explain(e)))
        _log("removed %d key(s)." % SSTATE["deleted"])

        # 2. Upload, then map. The mapping is not optional: a key with no protocol/port
        #    association is accepted and silently decrypts nothing.
        with SLOCK:
            SSTATE["phase"] = "uploading"
        shared_note = [False]        # log the shared-mapping explanation once, not 89 times
        for i, (name, crt, key) in enumerate(pairs, 1):
            if CANCEL.is_set():
                raise RuntimeError("cancelled")
            friendly = ("%s %s" % (label, name)).strip()[:120]

            # --- upload. Its own try, and `uploaded` is counted only once it has actually
            #     happened — a perfectly good key must not read as FAILED because the (optional)
            #     mapping below came back 400.
            try:
                with open(crt) as f:
                    cert_pem = f.read()
                with open(key) as f:
                    key_pem = f.read()
                kid = provider.create_decrypt_key(friendly, cert_pem, key_pem)
            except Exception as e:                         # noqa: BLE001
                with SLOCK:
                    SSTATE["failed"] += 1
                _log("  FAILED %s — %s" % (name, provider.explain(e)))
                continue
            with SLOCK:
                SSTATE["uploaded"] += 1

            # --- map. A missing mapping decrypts nothing, so it still matters; but an
            #     already-present one is the desired end state, however it got there.
            try:
                if not kid:
                    with SLOCK:
                        SSTATE["unmapped"] += 1
                    _log("  %s uploaded, but the sensor did not return its id — map it "
                         "by hand." % name)
                    continue
                here = any(pr["protocol"] == protocol and pr["port"] == int(port)
                           for pr in provider.key_protocols(kid))
                if not here:
                    provider.map_key_protocol(kid, protocol, port)
                with SLOCK:
                    SSTATE["mapped"] += 1
            except Exception as e:                         # noqa: BLE001
                if provider.is_mapping_conflict(e):
                    with SLOCK:
                        SSTATE["mapped"] += 1
                        SSTATE["shared_mapping"] = True
                    if not shared_note[0]:
                        shared_note[0] = True
                        _log("  %s/%s is already assigned on this sensor. The protocol-to-port "
                             "mapping is a capture-wide setting, so one entry covers every key — "
                             "this is not an error." % (protocol, port))
                else:
                    with SLOCK:
                        SSTATE["unmapped"] += 1
                    _log("  %s uploaded but could not be mapped — %s" % (name, provider.explain(e)))
            if i % 10 == 0 or i == len(pairs):
                _log("  %d of %d …" % (i, len(pairs)))

        with SLOCK:
            bad = SSTATE["failed"] + SSTATE["unmapped"]
            SSTATE["phase"] = "done" if not bad else "error"
            SSTATE["done"] = True
            SSTATE["running"] = False
            if SSTATE["failed"] and SSTATE["unmapped"]:
                SSTATE["error"] = ("%d certificate(s) failed to upload and %d could not be "
                                   "mapped — see the log."
                                   % (SSTATE["failed"], SSTATE["unmapped"]))
            elif SSTATE["failed"]:
                SSTATE["error"] = ("%d certificate(s) failed to upload — see the log."
                                   % SSTATE["failed"])
            elif SSTATE["unmapped"]:
                SSTATE["error"] = ("%d certificate(s) uploaded but could not be mapped to "
                                   "%s/%s — see the log."
                                   % (SSTATE["unmapped"], protocol, port))
        _log("done: %d uploaded, %d covered by %s/%s, %d failed to upload, %d unmapped."
             % (SSTATE["uploaded"], SSTATE["mapped"], protocol, port,
                SSTATE["failed"], SSTATE["unmapped"]))
        if SSTATE["shared_mapping"]:
            _log("note: the %s/%s mapping was already present, so it was reused rather than "
                 "created per key. The sensor can decrypt with these certificates."
                 % (protocol, port))
    except Exception as e:                                 # noqa: BLE001
        with SLOCK:
            SSTATE.update(running=False, done=True, phase="error", error=provider.explain(e))
        _log("stopped: %s" % provider.explain(e))
    finally:
        CANCEL.clear()


def push_cert(sensor, apikey, certs_dir, protocol="http", port=443, label="Example"):
    """Start a certificate push on a worker thread. Raises if one is already running."""
    with SLOCK:
        if SSTATE["running"]:
            raise RuntimeError("a certificate push is already in progress")
        SSTATE.update(running=True, done=False, error=None, phase="starting",
                      sensor=sensor, deleted=0, uploaded=0, mapped=0, failed=0,
                      unmapped=0, shared_mapping=False,
                      total=0, log=[], started=time.time())
    CANCEL.clear()
    _log("pushing certificates from %s to %s" % (certs_dir, sensor))
    t = threading.Thread(target=_run,
                         args=(sensor, apikey, certs_dir, protocol, port, label), daemon=True)
    t.start()
    return {"ok": True, "sensor": sensor}


def stop():
    with SLOCK:
        if not SSTATE["running"]:
            return {"ok": False, "error": "no push is running"}
    CANCEL.set()
    _log("stop requested …")
    return {"ok": True}


def status():
    with SLOCK:
        s = dict(SSTATE)
    s["elapsed"] = int(time.time() - s["started"]) if s["started"] else 0
    return s

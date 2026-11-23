"""push_ti — load the exported STIX 2.1 threat collection into a sensor.

Scoped replacement, NOT the scorched earth push_cert performs: decryption keys are
indistinguishable by name, so that push clears everything; collections are named, so this
deletes only the one collection this tool owns and uploads a fresh copy in its place, leaving
every other collection (built-in or custom) alone. Loading the bundle is what turns the
replayed flows into threat-intelligence matches.

Validates the bundle locally first, checks licensing/console deferral before sending, uploads,
reads the collection back to report how many indicators were actually imported, and optionally
enables detection-on-match. Platform-agnostic: every sensor-API specific lives behind a
SensorProvider (``sensorops.providers``); this module orchestrates and owns the worker thread
and the cancellable, credential-free status.
"""
import os
import json
import threading
import time

from .providers import get_provider
from ._util import path_hint

# Artifact names the generator exports; passed to the provider, which normalises as needed.
COLLECTION_NAME = "ExampleThreatCollection"
STIX_FILENAME = "example-threat-collection.stix.json"

# Deliberately holds no credential, for the same reason as push_cert's SSTATE: the browser
# polls it.
TSTATE = {
    "running": False, "done": False, "error": None, "phase": "idle",
    "sensor": "", "target": "sensor", "collection": COLLECTION_NAME,
    "replaced": 0, "indicators": 0, "imported": None, "detections": "unknown",
    "log": [], "started": 0.0,
}
TLOCK = threading.Lock()
TCANCEL = threading.Event()


def _tlog(msg):
    with TLOCK:
        TSTATE["log"].append(msg)
        del TSTATE["log"][:-400]


def read_bundle(stix_path):
    """Validate locally before sending. A bundle the sensor rejects costs a round trip and an
    opaque error; the two things it must be are cheap to check here."""
    with open(stix_path, "rb") as f:
        raw = f.read()
    doc = json.loads(raw.decode("utf-8"))
    if doc.get("type") != "bundle":
        raise ValueError("%s is not a STIX bundle" % os.path.basename(stix_path))
    n = len([o for o in doc.get("objects", []) if o.get("type") == "indicator"])
    if not n:
        raise ValueError("%s contains no indicators" % os.path.basename(stix_path))
    return raw, n


def collection_preflight(sensor, apikey, stix_path=None, target="sensor"):
    """Read-only: reachable, key works, what is there now, and what we are about to send."""
    report = {"ok": False, "sensor": sensor, "target": target, "appliance": "",
              "collections": None, "existing": 0, "indicators": 0,
              "collection": COLLECTION_NAME, "errors": [], "warnings": []}
    if not sensor:
        report["errors"].append("No appliance address given.")
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
        cols = provider.list_collections()
        report["collections"] = len(cols)
        report["existing"] = len(provider.find_our_collections(cols, COLLECTION_NAME))
    except Exception as e:                                 # noqa: BLE001
        report["errors"].append(provider.explain(e))
        return report

    # Reading collections can succeed on a sensor that will still refuse the upload.
    dep = provider.deployment_check()
    report["deployment"] = dep
    if dep["threat_intel"] is False:
        report["errors"].append(
            "This appliance is not licensed for threat intelligence (the licence reports "
            "threat_intel: false), so it will not accept a collection. Note this is a "
            "separate entitlement from the NDR edition — an appliance can show the security "
            "edition and still lack it.")
    if dep["console"]:
        if dep["console_threat_intel"] is False:
            report["errors"].append(
                "This sensor is managed by the console %s, so it refuses STIX uploads and "
                "defers them to that console — but %s is not licensed for threat "
                "intelligence (threat_intel: false). The collection cannot be loaded on "
                "either one until that entitlement is added to the console."
                % (dep["console"], dep["console"]))
        else:
            report["warnings"].append(
                "This sensor is managed by the console %s, which expects STIX uploads to go to "
                "it and then synchronises indicators to its sensors — point this at %s instead."
                % (dep["console"], dep["console"]))

    if stix_path:
        try:
            _, n = read_bundle(os.path.expanduser(stix_path))
            report["indicators"] = n
        except FileNotFoundError:
            expanded = os.path.expanduser(stix_path)
            folder = os.path.dirname(expanded)
            if folder and not os.path.isdir(folder):
                report["errors"].append(
                    "That folder does not exist: %s.%s" % (folder, path_hint(folder)))
            else:
                report["errors"].append(
                    "No threat collection at %s — generate a capture with "
                    "‘Export threat collection’ ticked first." % expanded)
        except (ValueError, json.JSONDecodeError) as e:
            report["errors"].append("%s" % e)

    if report["existing"]:
        report["warnings"].append(
            "A collection named %s is already present and will be replaced. No other "
            "collection is touched." % COLLECTION_NAME)
    report["ok"] = not report["errors"]
    return report


def _trun(sensor, apikey, stix_path, name, target, detections):
    provider = get_provider(sensor, apikey)
    try:
        try:
            raw, n_ind = read_bundle(stix_path)
        except FileNotFoundError:
            # The raw OSError text names an errno and a path and explains nothing. The real
            # cause is almost always that the capture was generated with the export unticked.
            raise RuntimeError(
                "no threat collection at %s — generate a capture with ‘Export threat "
                "collection’ ticked first." % stix_path)
        except json.JSONDecodeError as e:
            raise RuntimeError("%s is not valid JSON (%s)"
                               % (os.path.basename(stix_path), e))
        with TLOCK:
            TSTATE["indicators"] = n_ind
        _tlog("%s: %d indicator(s), %d bytes" % (os.path.basename(stix_path), n_ind, len(raw)))

        # 1. Remove only our own previous copy. Re-uploading without this would leave two
        #    collections with the same name, one holding indicators from a capture that no
        #    longer exists.
        with TLOCK:
            TSTATE["phase"] = "replacing"
        cols = provider.list_collections()
        mine = provider.find_our_collections(cols, name)
        _tlog("%d collection(s) on the sensor; %d named %s" % (len(cols), len(mine), name))
        for c in mine:
            if TCANCEL.is_set():
                raise RuntimeError("cancelled")
            cid = c.get("id")
            if cid is None:
                continue
            provider.delete_collection(cid)
            with TLOCK:
                TSTATE["replaced"] += 1
            _tlog("  removed previous %s (id %s)" % (name, cid))
        if not mine:
            _tlog("  no previous %s to remove" % name)

        # 2. Upload.
        if TCANCEL.is_set():
            raise RuntimeError("cancelled")
        with TLOCK:
            TSTATE["phase"] = "uploading"
        # detections asks the sensor to raise detections on an indicator match. Some sensors
        # REQUIRE it true at upload time; the choice is passed through rather than forced, so an
        # unticked box fails with the sensor's own explanation instead of being overridden.
        status = provider.upload_collection(name, raw, STIX_FILENAME, detections)
        _tlog("uploaded: HTTP %s" % status)

        # 3. Read it back. Confirms the sensor accepted it, reports how many indicators it
        #    actually imported (revoked/invalid/benign ones are dropped silently), and is where
        #    the detection setting is found.
        with TLOCK:
            TSTATE["phase"] = "verifying"
        mine = provider.find_our_collections(provider.list_collections(), name)
        if not mine:
            raise RuntimeError("the sensor accepted the upload but does not list a "
                               "collection named %s" % name)
        obj = mine[0]
        imported = obj.get("indicators")
        with TLOCK:
            TSTATE["imported"] = imported
        if imported is not None:
            _tlog("sensor imported %s of %d indicator(s)" % (imported, n_ind))
            if isinstance(imported, int) and imported < n_ind:
                _tlog("  (the difference is indicators it treats as invalid, revoked or benign)")

        # 4. Detection on match.
        if detections:
            field = obj.get("detection_field")
            if field is None:
                with TLOCK:
                    TSTATE["detections"] = "manual"
                _tlog("could not identify the detection-on-match setting on this firmware — "
                      "set the match option by hand in the sensor's threat-intelligence settings.")
            elif obj.get("detection_on"):
                with TLOCK:
                    TSTATE["detections"] = "on"
                _tlog("detections on match already enabled (%s)" % field)
            else:
                try:
                    provider.set_collection_detection(obj.get("id"), field)
                    again = provider.find_our_collections(provider.list_collections(), name)
                    ok = bool(again and again[0].get("detection_on"))
                    with TLOCK:
                        TSTATE["detections"] = "on" if ok else "manual"
                    _tlog("detections on match: set %s=true%s"
                          % (field, "" if ok else " — the sensor did not keep it; set the match "
                                                  "option by hand."))
                except Exception as e:                     # noqa: BLE001
                    with TLOCK:
                        TSTATE["detections"] = "manual"
                    _tlog("could not enable detections on match (%s) — set the match option by "
                          "hand in the sensor's threat-intelligence settings." % provider.explain(e))
        else:
            with TLOCK:
                TSTATE["detections"] = "off"
            _tlog("left the detection setting alone, as asked.")

        with TLOCK:
            TSTATE.update(phase="done", done=True, running=False)
        _tlog("done: %s is loaded on %s." % (name, sensor))
    except Exception as e:                                 # noqa: BLE001
        with TLOCK:
            TSTATE.update(running=False, done=True, phase="error", error=provider.explain(e))
        _tlog("stopped: %s" % provider.explain(e))
    finally:
        TCANCEL.clear()


def push_ti(sensor, apikey, stix_path, name=COLLECTION_NAME, target="sensor",
            detections=True):
    """Start a threat-collection push on a worker thread. Raises if one is already running."""
    # Refuse a push that cannot possibly succeed, rather than starting a thread that fails on
    # its first request. The server returns these as 400s.
    if not (sensor or "").strip():
        raise ValueError("no appliance address given")
    if not apikey:
        raise ValueError("no API key given")
    name = get_provider(sensor, apikey).collection_key(name) or COLLECTION_NAME
    stix_path = os.path.expanduser(stix_path)
    with TLOCK:
        if TSTATE["running"]:
            raise RuntimeError("a threat-collection push is already in progress")
        TSTATE.update(running=True, done=False, error=None, phase="starting", sensor=sensor,
                      target=target, collection=name, replaced=0, indicators=0, imported=None,
                      detections="unknown", log=[], started=time.time())
    TCANCEL.clear()
    _tlog("pushing %s to %s (%s)" % (os.path.basename(stix_path), sensor, target))
    t = threading.Thread(target=_trun,
                         args=(sensor, apikey, stix_path, name, target, detections), daemon=True)
    t.start()
    return {"ok": True, "sensor": sensor, "collection": name}


def collection_stop():
    with TLOCK:
        if not TSTATE["running"]:
            return {"ok": False, "error": "no threat-collection push is running"}
    TCANCEL.set()
    _tlog("stop requested …")
    return {"ok": True}


def collection_status():
    with TLOCK:
        s = dict(TSTATE)
    s["elapsed"] = int(time.time() - s["started"]) if s["started"] else 0
    return s

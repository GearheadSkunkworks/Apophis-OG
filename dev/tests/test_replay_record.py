"""R4: the replay record, resume and the validated human-only options. A fake tcpreplay stands in for the real
one and nothing here touches an interface or asks for a password."""
import hashlib
import json
import os
import shutil
import stat
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)

import replay  # noqa: E402 - sys.path is set up first

N = 40

FAKE = '''#!%(py)s
import os, struct, sys, time
a = sys.argv[1:]
if "--version" in a:
    print("tcpreplay version: fake"); sys.exit(0)
open(%(argvlog)r, "a").write(" ".join(a) + "\\n")
pcap = a[-1]
data = open(pcap, "rb").read()
n, off = 0, 24
while off + 16 <= len(data):
    n += 1; off += 16 + struct.unpack("<I", data[off + 8:off + 12])[0]
first, last = 1, n
for x in a:
    if x.startswith("--include="):
        lo, _, hi = x[10:].partition("-"); first = int(lo); last = int(hi) if hi else n
sent = max(0, last - first + 1)
mode = open(%(modefile)r).read().strip()
print("PID: %%d" %% os.getpid(), flush=True)
if mode == "stop":
    print("Actual: 15 packets (900 bytes) sent in 1.0 seconds", flush=True)
    time.sleep(60)
elif mode == "error":
    print("Actual: 10 packets (600 bytes) sent in 1.0 seconds", flush=True)
    sys.exit(3)
else:
    print("Actual: %%d packets (%%d bytes) sent in 1.0 seconds" %% (sent, sent * 60), flush=True)
'''


def make_pcap(path, n=N, pad=0):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i in range(n):
            p = bytes(60 + pad)
            f.write(struct.pack("<IIII", 1000 + i, 0, len(p), len(p)) + p)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.pcap = os.path.join(self.d, "cap.pcap")
        make_pcap(self.pcap)
        raw = open(self.pcap, "rb").read()
        self.sha = hashlib.sha256(raw).hexdigest()
        self.msha = "ab" * 32
        json.dump({"manifest_sha256": self.msha, "outputs": [{"name": "cap.pcap", "bytes": len(raw), "sha256": self.sha}]},
                  open(os.path.join(self.d, "cap.manifest.json"), "w"))
        self.modefile = os.path.join(self.d, "mode")
        self.argvlog = os.path.join(self.d, "argv.log")
        self.fake = os.path.join(self.d, "tcpreplay")
        open(self.fake, "w").write(FAKE % {"py": sys.executable, "argvlog": self.argvlog, "modefile": self.modefile})
        os.chmod(self.fake, os.stat(self.fake).st_mode | stat.S_IXUSR)
        for p in (mock.patch.object(replay, "find_tool", return_value=self.fake),
                  mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": os.path.join(self.d, "settings")}),
                  mock.patch.object(replay, "RUNFILE", os.path.join(self.d, "run.json"))):
            p.start()
            self.addCleanup(p.stop)
        replay.RSTATE.update(running=False)

    def run_replay(self, mode="finish", wait_sent=None, stop=False, **kw):
        open(self.modefile, "w").write(mode)
        kw.setdefault("speed_mode", "multiplier")
        r = replay.start(self.pcap, "", write_to="/dev/null", privileged=False, monitor=False, **kw)
        end = time.time() + 20
        while wait_sent is not None and replay.status()["sent_packets"] < wait_sent and time.time() < end:
            time.sleep(0.1)
        if stop:
            self.assertTrue(replay.stop()["ok"])
        while replay.status()["running"] and time.time() < end:
            time.sleep(0.1)
        while not replay.status()["record"] and not replay.status()["record_error"] and time.time() < end:
            time.sleep(0.1)
        s = replay.status()
        self.assertFalse(s["record_error"], s)
        with open(os.path.join(self.d, s["record"])) as f:
            return r, json.load(f)["replay"]


class Records(Base):
    def test_finished(self):
        r, rec = self.run_replay()
        self.assertEqual(rec["id"], r["replay_id"])
        self.assertEqual((rec["ended"], rec["sent_packets"], rec["start_offset_packets"], rec["stop_offset_packets"]),
                         ("finished", N, 0, N))
        self.assertEqual(rec["file"]["sha256"], self.sha)
        self.assertEqual(rec["file"]["sha256_source"], "manifest")
        self.assertEqual(rec["capture"]["manifest"]["manifest_sha256"], self.msha)
        self.assertEqual(rec["interface_kind"], "file")
        # the capture clock comes from index_pcap's sampled marks, so it is coarse on a file this small
        self.assertEqual(rec["start_capture_ts"], 1000.0)
        self.assertGreaterEqual(rec["stop_capture_ts"], rec["start_capture_ts"])
        self.assertTrue(rec["continuous_1x"] and rec["resumed_from"] is None and rec["error_class"] is None)
        self.assertLess(rec["start_epoch"], rec["stop_epoch"])

    def test_record_is_written_through_an_unpredictable_temp_name(self):
        moves = []
        real = os.replace
        with mock.patch.object(replay.os, "replace", side_effect=lambda a, b: (moves.append((a, b)), real(a, b))[1]):
            _, rec = self.run_replay()
        final = [m for m in moves if m[1].endswith(".json") and ".replay-" in m[1]]
        self.assertEqual(len(final), 1)
        src, dst = final[0]
        self.assertNotEqual(src, dst + ".tmp")
        self.assertEqual(os.path.dirname(src), os.path.dirname(dst))
        self.assertEqual(stat.S_IMODE(os.stat(dst).st_mode) & 0o044, 0o044)           # readable beside the capture

    def test_record_holds_no_paths_or_interface(self):
        _, rec = self.run_replay(sensor_label="lab sensor 1", note="first soak")
        text = json.dumps(rec)
        self.assertNotIn(self.d, text)
        self.assertNotIn("/dev/null", text)
        self.assertEqual((rec["sensor_label"], rec["note"]), ("lab sensor 1", "first soak"))

    def test_stopped(self):
        _, rec = self.run_replay("stop", wait_sent=15, stop=True)
        self.assertEqual((rec["ended"], rec["sent_packets"], rec["stop_offset_packets"]), ("stopped", 15, 15))
        self.assertIsNone(rec["error_class"])
        self.assertEqual(replay.resume_point({"replay": rec}), {"resumable": True, "next_packet": 16, "reason": ""})

    def test_error_keeps_no_message(self):
        _, rec = self.run_replay("error")
        self.assertEqual((rec["ended"], rec["sent_packets"], rec["error_class"]), ("error", 10, "tcpreplay_exit_3"))
        self.assertFalse({"error", "message"} & set(rec))

    def test_options_are_recorded(self):
        _, rec = self.run_replay(maxsleep_ms=2000, include={"start": 5, "end": 20}, rebase_seconds=3600)
        self.assertEqual(rec["speed"]["maxsleep_ms"], 2000)
        self.assertEqual((rec["include"], rec["rebase_seconds"], rec["continuous_1x"]), ({"start": 5, "end": 20}, 3600, False))
        self.assertEqual((rec["start_offset_packets"], rec["stop_offset_packets"], rec["sent_packets"]), (4, 20, 16))
        argv = open(self.argvlog).read()
        self.assertIn("--maxsleep=2000", argv)
        self.assertIn("--include=5-20", argv)

    def test_list_and_read(self):
        _, rec = self.run_replay()
        lst = replay.list_records(self.pcap)
        self.assertEqual([x["id"] for x in lst], [rec["id"]])
        self.assertFalse(lst[0]["stale"])
        self.assertFalse(lst[0]["resume"]["resumable"])
        self.assertEqual(replay.read_record(self.pcap, rec["id"])["replay"]["id"], rec["id"])
        self.assertIsNone(replay.read_record(self.pcap, "0" * 12))
        with self.assertRaises(ValueError):
            replay.read_record(self.pcap, "../../etc/passwd")

    def test_slice_cites_its_source(self):
        sl = os.path.join(self.d, "cap.slice.s1.B.pcap")
        make_pcap(sl, 10)
        json.dump({"kind": "B", "scenario": "s1", "baseline": "window", "source_pcap": "cap.pcap",
                   "source_pcap_sha256": self.sha, "manifest_sha256": self.msha, "kept_packets": 10, "source_packets": N},
                  open(os.path.join(self.d, "cap.slice.s1.B.json"), "w"))
        info = replay.identify(sl)
        self.assertEqual(info["capture"]["pcap_sha256"], self.sha)
        self.assertEqual(info["capture"]["manifest"], {"name": "cap.manifest.json", "manifest_sha256": self.msha})
        self.assertEqual(info["file"]["slice"]["scenario"], "s1")
        self.assertEqual(info["file"]["sha256"], hashlib.sha256(open(sl, "rb").read()).hexdigest())
        self.assertEqual(info["file"]["sha256_source"], "computed")

    def test_manifest_size_mismatch_is_not_trusted(self):
        make_pcap(self.pcap, N, pad=4)                     # a rebuilt file under the same name
        info = replay.identify(self.pcap)
        self.assertEqual(info["file"]["sha256_source"], "computed")
        self.assertNotEqual(info["file"]["sha256"], self.sha)
        self.assertTrue(info["warnings"])


class Resume(Base):
    def stopped(self):
        _, rec = self.run_replay("stop", wait_sent=15, stop=True)
        return rec

    def test_resume_with_overlap(self):
        prev = self.stopped()
        _, rec = self.run_replay("finish", resume_from=prev["id"], overlap_packets=5)
        self.assertIn("--include=11-", open(self.argvlog).read().splitlines()[-1])
        self.assertEqual(rec["resumed_from"], {"replay_id": prev["id"], "from_packet": 16, "start_packet": 11,
                                               "overlap_packets": 5, "continuous_1x": False,
                                               "statement": "a resumed run is not a continuous 1x run"})
        self.assertEqual((rec["start_offset_packets"], rec["stop_offset_packets"], rec["sent_packets"]), (10, N, 30))
        self.assertFalse(rec["continuous_1x"])

    def test_overlap_is_clamped_at_the_first_packet(self):
        prev = self.stopped()
        _, rec = self.run_replay("finish", resume_from=prev["id"], overlap_packets=1000)
        self.assertEqual(rec["resumed_from"]["start_packet"], 1)
        self.assertEqual(rec["resumed_from"]["overlap_packets"], 15)

    def test_default_overlap_and_zero(self):
        prev = self.stopped()
        _, rec = self.run_replay("finish", resume_from=prev["id"], overlap_packets=0)
        self.assertEqual((rec["resumed_from"]["start_packet"], rec["resumed_from"]["from_packet"]), (16, 16))

    def test_finished_run_cannot_be_resumed(self):
        _, rec = self.run_replay()
        with self.assertRaisesRegex(RuntimeError, "finished"):
            replay.start(self.pcap, "", write_to="/dev/null", privileged=False, monitor=False, resume_from=rec["id"])
        self.assertFalse(replay.RSTATE["running"])

    def test_unknown_id_and_other_file_refused(self):
        with self.assertRaisesRegex(RuntimeError, "no record"):
            replay.start(self.pcap, "", write_to="/dev/null", privileged=False, monitor=False, resume_from="0" * 12)
        prev = self.stopped()
        make_pcap(self.pcap, N, pad=4)
        with self.assertRaisesRegex(RuntimeError, "not the one"):
            replay.start(self.pcap, "", write_to="/dev/null", privileged=False, monitor=False, resume_from=prev["id"])

    def test_resume_keeps_the_range_end(self):
        open(self.modefile, "w").write("stop")
        replay.start(self.pcap, "", write_to="/dev/null", privileged=False, monitor=False,
                     include={"start": 3, "end": 30})
        end = time.time() + 20
        while replay.status()["sent_packets"] < 15 and time.time() < end:
            time.sleep(0.1)
        replay.stop()
        while replay.status()["running"] and time.time() < end:
            time.sleep(0.1)
        while not replay.status()["record"] and time.time() < end:
            time.sleep(0.1)
        prev = json.load(open(os.path.join(self.d, replay.status()["record"])))
        self.assertEqual(prev["replay"]["stop_offset_packets"], 17)
        _, rec = self.run_replay("finish", resume_from=prev["replay"]["id"], overlap_packets=2)
        self.assertEqual(rec["include"], {"start": 16, "end": 30})


class Options(unittest.TestCase):
    def bad(self, **kw):
        with self.assertRaises(ValueError, msg=str(kw)):
            replay.parse_options(kw)

    def test_defaults(self):
        o = replay.parse_options({})
        self.assertEqual((o["speed_mode"], o["speed_value"], o["loop"], o["maxsleep_ms"], o["include"]),
                         ("multiplier", 1.0, 1, None, None))

    def test_topspeed_is_refused(self):
        self.bad(speed_mode="topspeed")
        self.bad(speed_mode="topspeed", speed_value=0)
        with self.assertRaises(ValueError):
            replay.build_argv("tcpreplay", "a.pcap", "en0", "topspeed")

    def test_speed_bounds(self):
        self.assertEqual(replay.parse_options({"speed_value": 10})["speed_value"], 10.0)
        for v in (10.01, 0.0, -1, float("nan"), float("inf"), True, "2", [1]):
            self.bad(speed_value=v)
        self.bad(speed_mode="pps")                          # no default outside the multiplier
        self.bad(speed_mode="pps", speed_value=replay.LIMITS["max_pps"] + 1)
        self.bad(speed_mode="mbps", speed_value=replay.LIMITS["max_mbps"] + 1)
        self.bad(speed_mode="warp", speed_value=1)

    def test_integers_are_not_coerced(self):
        for k, good in (("loop", 5), ("maxsleep_ms", 50), ("overlap_packets", 9), ("rebase_seconds", -60)):
            self.assertEqual(replay.parse_options({k: good})[k], good)
            for v in (1.5, "3", True, [1], {}):
                self.bad(**{k: v})
        self.bad(loop=0)
        self.bad(loop=replay.LIMITS["max_loop"] + 1)
        self.bad(maxsleep_ms=0)
        self.bad(maxsleep_ms=replay.LIMITS["max_maxsleep_ms"] + 1)
        self.bad(overlap_packets=-1)
        self.bad(rebase_seconds=replay.LIMITS["max_rebase_seconds"] + 1)

    def test_include(self):
        self.assertEqual(replay.parse_options({"include": {"start": 5}})["include"], {"start": 5, "end": None})
        self.assertEqual(replay.parse_options({"include": {"start": 5, "end": 5}})["include"], {"start": 5, "end": 5})
        for inc in ({}, {"start": 0}, {"start": 5, "end": 4}, {"start": "5"}, {"start": 1, "end": 2, "x": 1}, "5-9", [5, 9],
                    {"start": replay.LIMITS["max_packet_no"] + 1}):
            self.bad(include=inc)

    def test_resume_options(self):
        self.assertEqual(replay.parse_options({"resume_from": "0123456789ab"})["resume_from"], "0123456789ab")
        for v in ("../x", "short", "0123456789AB", 5):
            self.bad(resume_from=v)
        self.bad(resume_from="0123456789ab", include={"start": 3})

    def test_text_fields(self):
        o = replay.parse_options({"note": "a\x00b\x1b[31m\nline‮two", "sensor_label": " lab\tA "})
        self.assertEqual((o["note"], o["sensor_label"]), ("ab[31m linetwo", "lab A"))
        self.bad(note="x" * 1001)
        self.bad(note=5)
        self.bad(sensor_label="y" * 65)
        for addr in ("10.1.2.3", "https://sensor.example", "fe80::1", "sensor 192.168.0.9"):
            self.bad(sensor_label=addr)
        self.assertEqual(replay.parse_options({"sensor_label": "lab-sensor-2"})["sensor_label"], "lab-sensor-2")

    def test_argv_is_a_list_and_carries_the_options(self):
        argv = replay.build_argv("/x/tcpreplay", "a b;rm.pcap", "en0", "multiplier", 2.0, 1,
                                 maxsleep_ms=1500, include={"start": 7, "end": None})
        self.assertIn("--maxsleep=1500", argv)
        self.assertIn("--include=7-", argv)
        self.assertEqual(argv[-1], "a b;rm.pcap")
        self.assertNotIn("--topspeed", argv)


if __name__ == "__main__":
    unittest.main()

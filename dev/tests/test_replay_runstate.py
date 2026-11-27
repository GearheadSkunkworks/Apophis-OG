"""M3/M4/L2 for replay: where run state lives and what is trusted when it is read back, the exclusive stop file,
the root shell that writes nothing into a person's folder, and system-directory lookups. Nothing here starts a replay,
asks for a password or touches an interface; the macOS administrator prompt itself cannot be tested and is not."""
import json
import os
import shlex
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)

import replay  # noqa: E402 - sys.path is set up first

ME = os.geteuid()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": os.path.join(self.tmp, "settings")})
        p.start()
        self.addCleanup(p.stop)
        self.state = replay._state_dir(create=True)

    def rundir(self, name="nwtg-replay-abc123", mode=0o700):
        d = os.path.join(self.state, name)
        os.mkdir(d, mode)
        os.chmod(d, mode)
        return d

    def info(self, rd, **kw):
        i = {"dir": rd, "stopfile": os.path.join(rd, "STOP"), "logfile": os.path.join(rd, "tcpreplay.log")}
        i.update(kw)
        return i


class StateLocation(Base):
    def test_state_is_per_user_private_and_not_in_a_shared_temp_folder(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.state).st_mode), 0o700)
        self.assertTrue(self.state.startswith(os.environ["OG_SETTINGS_DIR"]))
        self.assertFalse(replay._runfile().startswith(tempfile.gettempdir() + os.sep + "nwtg"))
        self.assertNotEqual(os.path.dirname(replay._runfile()), tempfile.gettempdir())

    def test_runfile_is_0600_and_written_atomically(self):
        with mock.patch.object(replay, "RUNFILE", None):
            replay._write_runfile(a=1)
            rf = replay._runfile()
            self.assertEqual(stat.S_IMODE(os.stat(rf).st_mode), 0o600)
            self.assertEqual(replay._read_runfile(), {"a": 1})
            replay._write_runfile(a=2)
            self.assertEqual(replay._read_runfile(), {"a": 2})
            self.assertEqual([n for n in os.listdir(self.state) if n.endswith(".tmp")], [])

    def test_runfile_symlink_is_not_followed(self):
        victim = os.path.join(self.tmp, "victim.json")
        with open(victim, "w") as f:
            json.dump({"dir": "x"}, f)
        rf = os.path.join(self.state, "replay-current.json")
        os.symlink(victim, rf)
        with mock.patch.object(replay, "RUNFILE", None):
            self.assertIsNone(replay._read_runfile())
            replay._write_runfile(a=1)                        # replaces the link; never writes through it
        with open(victim) as f:
            self.assertEqual(json.load(f), {"dir": "x"})

    def test_old_run_folders_are_pruned_and_live_ones_kept(self):
        old, new = self.rundir("nwtg-replay-old"), self.rundir("nwtg-replay-new")
        other = os.path.join(self.state, "keep-me")
        os.mkdir(other)
        t = time.time() - 30 * 86400
        os.utime(old, (t, t))
        os.utime(other, (t, t))
        replay._prune_old_runs(self.state)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(new) and os.path.exists(other))


class PathPolicy(Base):
    def test_our_run_folder_is_accepted(self):
        self.assertTrue(replay.run_paths_ok(self.info(self.rundir())))

    def test_planted_paths_are_refused(self):
        rd = self.rundir()
        victim = os.path.join(self.tmp, "victim")
        cases = {
            "stopfile elsewhere": self.info(rd, stopfile=victim),
            "logfile elsewhere": self.info(rd, logfile=os.path.join(self.tmp, "x")),
            "folder outside state": self.info(self.tmp, stopfile=os.path.join(self.tmp, "STOP"),
                                              logfile=os.path.join(self.tmp, "tcpreplay.log")),
            "relative": self.info(rd, stopfile="STOP"),
            "not strings": self.info(rd, stopfile=None),
            "stop not named STOP": self.info(rd, stopfile=os.path.join(rd, "other")),
        }
        for why, info in cases.items():
            self.assertFalse(replay.run_paths_ok(info), why)

    def test_folder_others_can_write_is_refused(self):
        self.assertFalse(replay.run_paths_ok(self.info(self.rundir(mode=0o770))))
        self.assertFalse(replay.run_paths_ok(self.info(self.rundir("nwtg-replay-w", mode=0o707))))

    def test_wrong_name_and_symlinked_folder_are_refused(self):
        self.assertFalse(replay.run_paths_ok(self.info(self.rundir("plain"))))
        real = self.rundir("nwtg-replay-real")
        link = os.path.join(self.state, "nwtg-replay-link")
        os.symlink(real, link)
        self.assertFalse(replay.run_paths_ok(self.info(link)))

    def test_folder_owned_by_someone_else_is_refused(self):
        self.assertFalse(replay.run_paths_ok(self.info(self.rundir()), euid=ME + 1))

    def test_root_owned_log_folder_policy(self):
        rd = self.rundir()
        base = os.path.join(self.tmp, "varrun")
        os.mkdir(base)
        ld = os.path.join(base, "og-replay-%d-%s" % (ME, "0123456789ab"))
        os.mkdir(ld, 0o755)
        os.chmod(ld, 0o755)
        info = self.info(rd, logfile=os.path.join(ld, "tcpreplay.log"))
        kw = dict(root_log_base=base, root_uid=ME)             # the test user stands in for root
        self.assertTrue(replay.run_paths_ok(info, **kw))
        self.assertFalse(replay.run_paths_ok(info, root_log_base=base, root_uid=ME + 1))     # owner is not root
        os.chmod(ld, 0o777)
        self.assertFalse(replay.run_paths_ok(info, **kw))                                      # others can write
        os.chmod(ld, 0o755)
        bad = self.info(rd, logfile=os.path.join(base, "og-replay-%d-zz" % ME, "tcpreplay.log"))
        self.assertFalse(replay.run_paths_ok(bad, **kw))
        other_uid = os.path.join(base, "og-replay-%d-0123456789ab" % (ME + 1))
        os.mkdir(other_uid, 0o755)
        self.assertFalse(replay.run_paths_ok(self.info(rd, logfile=os.path.join(other_uid, "tcpreplay.log")), **kw))


class Reattach(Base):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(replay, "RUNFILE", os.path.join(self.state, "replay-current.json"))
        p.start()
        self.addCleanup(p.stop)
        replay.RSTATE.update(running=False)
        self.addCleanup(replay.RSTATE.update, running=False)

    def plant(self, info):
        with open(replay.RUNFILE, "w") as f:
            json.dump(info, f)

    def test_the_reviewed_attack_is_not_adopted(self):
        shared = os.path.join(self.tmp, "x")
        with open(shared, "w") as f:
            f.write("PID: %d\n" % os.getpid())                 # a log that claims a live process
        bashrc = os.path.join(self.tmp, "bashrc")
        with open(bashrc, "w") as f:
            f.write("keep")
        self.plant({"logfile": shared, "stopfile": bashrc, "dir": self.tmp})
        self.assertIsNone(replay.reattach())
        self.assertFalse(replay.RSTATE["running"])
        self.assertEqual(replay._RUN.get("stopfile") != bashrc, True)
        self.assertEqual(open(bashrc).read(), "keep")
        self.assertFalse(os.path.exists(replay.RUNFILE))        # the planted record is dropped, not trusted again

    def test_a_genuine_run_is_adopted(self):
        rd = self.rundir()
        log = os.path.join(rd, "tcpreplay.log")
        with open(log, "w") as f:
            f.write("PID: %d\n" % os.getpid())                 # this test process stands in for tcpreplay
        self.plant(self.info(rd, pcap="a.pcap", iface="", loop=1, idx={}))
        with mock.patch.object(replay.threading, "Thread"):    # do not start the tail thread
            got = replay.reattach()
        self.assertEqual(got["pid"], os.getpid())
        self.assertEqual(replay._RUN["stopfile"], os.path.join(rd, "STOP"))


class Stop(Base):
    def setUp(self):
        super().setUp()
        replay.RSTATE.update(running=True, stoppable=True, stopped=False)
        self.addCleanup(replay.RSTATE.update, running=False, stoppable=True, stopped=False, phase="idle")
        self.rd = self.rundir()
        self.sf = os.path.join(self.rd, "STOP")
        p = mock.patch.dict(replay._RUN, {"stopfile": self.sf})
        p.start()
        self.addCleanup(p.stop)

    def test_stop_creates_the_file_0600_exclusively(self):
        self.assertTrue(replay.stop()["ok"])
        self.assertEqual(stat.S_IMODE(os.stat(self.sf).st_mode), 0o600)
        replay.RSTATE.update(running=True, stopped=False)
        self.assertTrue(replay.stop()["ok"])                   # already there (monitor window): still fine

    def test_stop_never_truncates_an_existing_file_or_follows_a_link(self):
        victim = os.path.join(self.tmp, "victim")
        with open(victim, "w") as f:
            f.write("keep")
        os.symlink(victim, self.sf)
        self.assertTrue(replay.stop()["ok"])
        with open(victim) as f:
            self.assertEqual(f.read(), "keep")


class RootShell(unittest.TestCase):
    ARGV = ["/usr/local/bin/tcpreplay", "-i", "en0", "/caps/a b.pcap"]

    def redirect_targets(self, script):
        out = []
        for line in script.splitlines():
            toks = shlex.split(line, comments=False, posix=True)
            for i, t in enumerate(toks):
                if t in (">", ">>", "2>&1"):
                    if t != "2>&1":
                        out.append(toks[i + 1])
                elif t.startswith(">") and len(t) > 1 and not t.startswith(">&"):
                    out.append(t.lstrip(">"))
        return out

    def test_root_writes_only_inside_its_own_folder(self):
        ld = replay._root_log_dir(501, "0123456789ab", base="/private/var/run")
        log = os.path.join(ld, "tcpreplay.log")
        user_stop = "/data/per user/run/nwtg-replay-x/STOP"
        script = replay._inner_script(self.ARGV, log, user_stop, root_logdir=ld)
        self.assertEqual(script.splitlines()[:2], ["umask 022", "mkdir -m 755 %s || exit 1" % shlex.quote(ld)])
        targets = self.redirect_targets(script)
        self.assertTrue(targets and all(t == log for t in targets), targets)
        self.assertNotIn("per user", " ".join(targets))
        self.assertIn("[ -f %s ]" % shlex.quote(user_stop), script)      # the user's path is only tested, never written
        self.assertEqual(shlex.split(script.splitlines()[2].split(" > ")[0]), self.ARGV)

    def test_the_unprivileged_script_is_unchanged(self):
        script = replay._inner_script(self.ARGV, "/r/l", "/r/s")
        self.assertTrue(script.startswith("/usr/local/bin/tcpreplay"))
        self.assertNotIn("mkdir", script)

    def test_root_log_dir_matches_the_policy_regex(self):
        ld = replay._root_log_dir(501, "0123456789ab", base="/b")
        self.assertEqual(ld, "/b/og-replay-501-0123456789ab")


class SystemTools(unittest.TestCase):
    def test_a_tool_on_a_user_path_is_never_chosen(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for n in ("sudo", "pkexec", "getcap"):
            p = os.path.join(d, n)
            open(p, "w").close()
            os.chmod(p, 0o755)
        with mock.patch.dict(os.environ, {"PATH": d + os.pathsep + os.environ.get("PATH", "")}):
            for n in ("sudo", "pkexec", "getcap"):
                self.assertNotEqual(os.path.dirname(replay.system_tool(n) or "/"), d)
            self.assertIsNone(replay.system_tool("sudo", dirs=("/nonexistent-dir",)))

    def test_lookup_returns_a_fixed_directory_entry(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "sudo")
        open(p, "w").close()
        os.chmod(p, 0o755)
        self.assertEqual(replay.system_tool("sudo", dirs=(d,)), p)
        os.chmod(p, 0o644)
        self.assertIsNone(replay.system_tool("sudo", dirs=(d,)))

    def test_elevation_uses_the_system_lookup(self):
        with mock.patch.object(replay, "system_tool", side_effect=lambda n: None) as st, \
                mock.patch.object(replay.os, "geteuid", return_value=1000), \
                mock.patch.object(replay, "probe_file_caps", return_value=False):
            self.assertEqual(replay.linux_elevation("/usr/bin/tcpreplay")["mode"], "none")
        self.assertTrue({c.args[0] for c in st.call_args_list} >= {"sudo", "pkexec"})


if __name__ == "__main__":
    unittest.main()

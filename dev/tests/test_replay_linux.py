"""Linux replay (L1): hints, interface ranking, the elevation chain, argv safety.

Every Linux decision is a pure function over injected facts, so none of this needs Linux, root,
tcpreplay or a network; sysfs is a fake tree in a temp dir.
"""
import os
import shlex
import struct
import tempfile
import unittest
from unittest import mock

import agent_api
import replay

TP = "/usr/bin/tcpreplay"


def elev(**kw):
    base = dict(euid=1000, tcpreplay=TP, has_cap=False, sudo_path="/usr/bin/sudo", sudo_ok=False,
                pkexec_path="/usr/bin/pkexec", has_display=True, hint="sudo apt install tcpreplay")
    base.update(kw)
    return replay.decide_elevation(**base)


class Hints(unittest.TestCase):
    def hint(self, text):
        return replay.linux_install_hint(replay.parse_os_release(text), "tcpreplay")

    def test_per_distro(self):
        self.assertEqual(self.hint('ID=ubuntu\nID_LIKE=debian\n'), "sudo apt install tcpreplay")
        self.assertEqual(self.hint('ID=linuxmint\nID_LIKE="ubuntu debian"\n'), "sudo apt install tcpreplay")
        self.assertEqual(self.hint('ID=fedora\n'), "sudo dnf install tcpreplay")
        self.assertIn("epel-release", self.hint('ID="rocky"\nID_LIKE="rhel centos fedora"\n'))
        self.assertIn("epel-release", self.hint('ID=rhel\n'))
        self.assertEqual(self.hint('ID=opensuse-leap\nID_LIKE="suse opensuse"\n'), "sudo zypper install tcpreplay")
        self.assertEqual(self.hint('ID=arch\n'), "sudo pacman -S tcpreplay")
        self.assertEqual(self.hint('ID=alpine\n'), "sudo apk add tcpreplay")

    def test_unknown_names_both(self):
        h = self.hint("")
        self.assertIn("apt install", h)
        self.assertIn("dnf install", h)

    def test_macos_hint_unchanged(self):
        with mock.patch.object(replay.sys, "platform", "darwin"), \
                mock.patch.object(replay, "_search_paths", return_value=[]), \
                mock.patch("shutil.which", return_value=None):
            self.assertEqual(replay.install_hint("tcpreplay"),
                             "brew install tcpreplay (Homebrew, see brew.sh) or sudo port install tcpreplay")


def fake_sysfs(root, spec):
    """spec: name -> dict(type, operstate, speed, virtual, wireless). Returns the class/net dir."""
    for name, f in spec.items():
        base = os.path.join(root, "devices", "virtual", "net", name) if f.get("virtual") \
            else os.path.join(root, "devices", "pci0", name)
        os.makedirs(base)
        os.makedirs(os.path.join(root, "class", "net"), exist_ok=True)
        os.symlink(base, os.path.join(root, "class", "net", name))
        for leaf in ("type", "operstate", "speed"):
            if f.get(leaf) is not None:
                with open(os.path.join(base, leaf), "w") as fh:
                    fh.write(str(f[leaf]) + "\n")
        if f.get("wireless"):
            os.makedirs(os.path.join(base, "wireless"))
    return os.path.join(root, "class", "net")


SPEC = {
    "lo": dict(type=772, operstate="unknown", virtual=True),
    "docker0": dict(type=1, operstate="down", virtual=True),
    "veth1a2b": dict(type=1, operstate="up", virtual=True),
    "eno1": dict(type=1, operstate="up", speed=1000),
    "enp5s0": dict(type=1, operstate="up", speed=10000),
    "enp6s0": dict(type=1, operstate="down"),
    "wlp3s0": dict(type=1, operstate="up", wireless=True),
}
ROUTE = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
         "eno1\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n"
         "eno1\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n")


class Interfaces(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.net = fake_sysfs(self.tmp.name, SPEC)

    def details(self, route=ROUTE):
        rows = replay.read_linux_ifaces(self.net)
        return replay.linux_details(rows, replay.parse_default_route_ifaces(route))

    def test_ranking_and_flags(self):
        order = [x["name"] for x in self.details()]
        d = {x["name"]: x for x in self.details()}
        self.assertEqual(order[:3], ["enp5s0", "enp6s0", "wlp3s0"])        # usable first, link-up wired first
        self.assertEqual(set(order[-4:]), {"eno1", "docker0", "veth1a2b", "lo"})
        for n in ("lo", "docker0", "veth1a2b"):
            self.assertTrue(d[n]["discouraged"])
            self.assertTrue(d[n]["warning"])
        self.assertIn("default route", d["eno1"]["warning"])
        self.assertFalse(d["enp5s0"]["discouraged"])
        self.assertEqual(d["enp5s0"]["warning"], "")

    def test_recommended_is_fastest_usable_wired(self):
        rec = [x["name"] for x in self.details() if x["recommended"]]
        self.assertEqual(rec, ["enp5s0"])                                   # not eno1 (default route), not docker

    def test_without_default_route_info(self):
        d = {x["name"]: x for x in self.details(route="")}
        self.assertFalse(d["eno1"]["discouraged"])
        self.assertTrue(d["enp5s0"]["recommended"])

    def test_link_and_kind(self):
        d = {x["name"]: x for x in self.details()}
        self.assertTrue(d["enp5s0"]["link_up"])
        self.assertFalse(d["enp6s0"]["link_up"])
        self.assertIsNone(d["lo"]["link_up"])
        self.assertEqual(d["wlp3s0"]["kind"], "wifi")
        self.assertEqual(d["docker0"]["kind"], "virtual")
        self.assertEqual(d["lo"]["kind"], "loopback")
        self.assertEqual(d["enp5s0"]["speed"], "10 Gb/s")

    def test_hostile_names_skipped_and_missing_root(self):
        for n in ("bad name", "-evil", "x" * 16):
            os.makedirs(os.path.join(self.net, n))
        names = [r["name"] for r in replay.read_linux_ifaces(self.net)]
        self.assertEqual(set(names), set(SPEC))
        self.assertEqual(replay.read_linux_ifaces(os.path.join(self.tmp.name, "nope")), [])

    def test_default_route_parse(self):
        self.assertEqual(replay.parse_default_route_ifaces(ROUTE), {"eno1"})
        self.assertEqual(replay.parse_default_route_ifaces(""), set())

    def test_list_interfaces_uses_sysfs_on_linux(self):
        with mock.patch.object(replay.sys, "platform", "linux"), \
                mock.patch.object(replay, "read_linux_ifaces", return_value=replay.read_linux_ifaces(self.net)), \
                mock.patch.object(replay, "read_default_route_ifaces", return_value={"eno1"}):
            self.assertEqual(replay.list_interfaces()[0], "enp5s0")
            self.assertEqual({d["name"] for d in replay.interfaces_detail()}, set(SPEC))


class Validation(unittest.TestCase):
    def test_iface_names(self):
        for ok in ("eth0", "enp5s0", "br-1a2b", "eth0.100", "a:b", "x" * 15):
            self.assertTrue(replay.valid_linux_iface(ok), ok)
        for bad in ("", "x" * 16, "-i", "a b", "eth0\n", "eth0;id", "$(id)", "a/b", "é", None, "eth0\0"):
            self.assertFalse(replay.valid_linux_iface(bad), repr(bad))

    def test_paths(self):
        self.assertEqual(replay.clean_abs_path("/usr/bin/tcpreplay"), "/usr/bin/tcpreplay")
        for bad in ("tcpreplay", "/a\0b", "/a\nb", "/a\rb", "", None):
            self.assertIsNone(replay.clean_abs_path(bad), repr(bad))


def vfs(effective=True, permitted_bits=1 << 13):
    return struct.pack("<III", 0x02000000 | (1 if effective else 0), permitted_bits, 0) + b"\0" * 8


class Caps(unittest.TestCase):
    def test_vfs(self):
        self.assertTrue(replay.parse_vfs_caps(vfs()))
        self.assertFalse(replay.parse_vfs_caps(vfs(effective=False)))
        self.assertFalse(replay.parse_vfs_caps(vfs(permitted_bits=1 << 12)))   # CAP_NET_ADMIN only
        self.assertFalse(replay.parse_vfs_caps(b"\0\0"))
        self.assertFalse(replay.parse_vfs_caps(None))

    def test_getcap(self):
        self.assertTrue(replay.parse_getcap("/usr/bin/tcpreplay cap_net_raw=ep\n"))
        self.assertTrue(replay.parse_getcap("/usr/bin/tcpreplay = cap_net_raw+ep\n"))
        self.assertTrue(replay.parse_getcap("/x cap_net_admin,cap_net_raw=eip\n"))
        self.assertFalse(replay.parse_getcap("/x cap_net_raw=i\n"))
        self.assertFalse(replay.parse_getcap("/x cap_net_admin=ep\n"))
        self.assertFalse(replay.parse_getcap(""))

    def test_probe_xattr_and_fallback(self):
        self.assertTrue(replay.probe_file_caps(TP, getxattr=lambda p, n: vfs()))

        def nodata(p, n):
            raise OSError(61, "no data")
        self.assertFalse(replay.probe_file_caps(TP, getxattr=nodata))
        with mock.patch.object(replay.os, "getxattr", None, create=True), \
                mock.patch.object(replay, "system_tool", return_value="/usr/sbin/getcap"):
            self.assertTrue(replay.probe_file_caps(TP, run=lambda argv: "%s cap_net_raw=ep" % argv[1]))
            self.assertFalse(replay.probe_file_caps(TP, run=lambda argv: ""))


class Elevation(unittest.TestCase):
    def test_matrix(self):
        self.assertEqual(elev(euid=0, has_cap=True, sudo_ok=True)["mode"], "root")
        self.assertEqual(elev(has_cap=True, sudo_ok=True)["mode"], "capability")
        self.assertEqual(elev(sudo_ok=True)["mode"], "sudo")
        self.assertEqual(elev()["mode"], "pkexec")

    def test_prefixes(self):
        self.assertEqual(elev(euid=0)["prefix"], [])
        self.assertEqual(elev(has_cap=True)["prefix"], [])
        self.assertEqual(elev(sudo_ok=True)["prefix"], ["/usr/bin/sudo", "-n", "--"])
        self.assertEqual(elev()["prefix"], ["/usr/bin/pkexec"])

    def test_stoppable_only_without_pkexec(self):
        self.assertFalse(elev()["stoppable"])
        self.assertTrue(elev(sudo_ok=True)["stoppable"])
        self.assertTrue(elev(has_cap=True)["stoppable"])

    def test_none_result(self):
        for kw in (dict(has_display=False), dict(pkexec_path=None), dict(has_display=False, pkexec_path=None)):
            r = elev(**kw)
            self.assertEqual((r["mode"], r["ok"], r["prefix"]), ("none", False, []))
            self.assertIn("sudo setcap cap_net_raw+ep /usr/bin/tcpreplay", r["message"])
            self.assertIn("root", r["message"])

    def test_setcap_message_quotes_path(self):
        r = elev(tcpreplay="/opt/my tools/tcpreplay", has_display=False)
        self.assertIn("'/opt/my tools/tcpreplay'", r["message"])

    def test_missing_or_hostile_tcpreplay(self):
        for tp in ("", None, "tcpreplay", "/usr/bin/tcp\nreplay", "/usr/bin/tcp\0replay"):
            r = elev(tcpreplay=tp, has_cap=True)
            self.assertEqual((r["mode"], r["ok"]), ("none", False))
            self.assertIn("sudo apt install tcpreplay", r["message"])

    def test_hostile_helper_paths_not_used(self):
        self.assertEqual(elev(sudo_ok=True, sudo_path="sudo")["mode"], "pkexec")
        self.assertEqual(elev(pkexec_path="pkexec")["mode"], "none")

    def test_public_view_has_no_argv(self):
        pub = replay.public_elevation(elev(sudo_ok=True))
        self.assertEqual(set(pub), {"mode", "ok", "stoppable", "message"})

    def test_sudo_probe_is_non_interactive_and_list_based(self):
        with mock.patch.object(replay.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0)
            self.assertTrue(replay.probe_sudo("/usr/bin/sudo", TP))
            args, kw = run.call_args
            self.assertEqual(args[0], ["/usr/bin/sudo", "-n", "-l", TP])
            self.assertIsNone(kw.get("shell"))
            self.assertTrue(kw["timeout"])
            run.return_value = mock.Mock(returncode=1)
            self.assertFalse(replay.probe_sudo("/usr/bin/sudo", TP))
            run.side_effect = OSError()
            self.assertFalse(replay.probe_sudo("/usr/bin/sudo", TP))

    def test_linux_elevation_wires_probes(self):
        with mock.patch.object(replay.os, "geteuid", return_value=1000), \
                mock.patch.object(replay, "probe_file_caps", return_value=False), \
                mock.patch.object(replay, "probe_sudo", return_value=True), \
                mock.patch.object(replay, "system_tool", side_effect=lambda n: "/usr/bin/" + n):
            self.assertEqual(replay.linux_elevation(TP)["mode"], "sudo")


class Argv(unittest.TestCase):
    def test_no_shell_and_prefix_is_list(self):
        full = elev(sudo_ok=True)["prefix"] + replay.build_argv(TP, "/caps/a.pcap", "eth0")
        self.assertEqual(full[:4], ["/usr/bin/sudo", "-n", "--", TP])
        self.assertEqual(full[-3:], ["-i", "eth0", "/caps/a.pcap"])

    def test_script_quotes_every_argument(self):
        evil_pcap = "/caps/a b';touch pwned;'.pcap"
        argv = elev()["prefix"] + replay.build_argv(TP, evil_pcap, "eth0")
        first = replay._inner_script(argv, "/tmp/l", "/tmp/s").split(" > ")[0]
        self.assertEqual(shlex.split(first), argv)            # round-trips: nothing escaped its quoting

    def test_stats_flag_optional_and_macos_default_unchanged(self):
        self.assertNotIn("--stats=1", replay.build_argv(TP, "/a.pcap", "eth0", stats_every=0))
        self.assertEqual(replay.build_argv(TP, "/a.pcap", "en0"),
                         [TP, "-P", "--stats=1", "--multiplier=1.0", "-i", "en0", "/a.pcap"])

    def test_stats_probe(self):
        self.assertTrue(replay.tcpreplay_has_stats("  --stats=number  Print statistics"))
        self.assertTrue(replay.tcpreplay_has_stats(""))
        self.assertFalse(replay.tcpreplay_has_stats("usage: tcpreplay [options]\n  --loop=n"))

    def test_terminal_argv(self):
        which = {"xterm": "/usr/bin/xterm", "konsole": "/usr/bin/konsole"}.get
        self.assertEqual(replay.linux_terminal_argv("/tmp/m.command", which, {"DISPLAY": ":0"}),
                         ["/usr/bin/konsole", "-e", "/tmp/m.command"])
        self.assertIsNone(replay.linux_terminal_argv("/tmp/m.command", which, {}))
        self.assertIsNone(replay.linux_terminal_argv("/tmp/m.command", {}.get, {"DISPLAY": ":0"}))
        self.assertIsNone(replay.linux_terminal_argv("/tmp/a\nb", which, {"DISPLAY": ":0"}))


class Preflight(unittest.TestCase):
    def run_pre(self, elevation, iface=None, warning=""):
        with mock.patch.object(replay.sys, "platform", "linux"), \
                mock.patch.object(replay, "find_tool", return_value=TP), \
                mock.patch.object(replay, "tool_version", return_value="tcpreplay 4.4"), \
                mock.patch.object(replay, "_run_text", return_value="--stats"), \
                mock.patch.object(replay, "list_interfaces", return_value=["eth0"]), \
                mock.patch.object(replay, "interfaces_detail",
                                  return_value=[{"name": "eth0", "warning": warning}]), \
                mock.patch.object(replay, "linux_elevation", return_value=elevation):
            return replay.preflight(None, iface, fresh=True)

    def test_elevation_reported_and_iface_warning(self):
        r = self.run_pre(elev(has_cap=True), "eth0", "careful")
        self.assertEqual(r["elevation"]["mode"], "capability")
        self.assertIn("careful", r["warnings"])
        self.assertTrue(r["ok"], r["errors"])

    def test_bad_iface_name_is_an_error(self):
        self.assertIn("not a valid interface", " ".join(self.run_pre(elev(has_cap=True), "-i")["errors"]))

    def test_no_privilege_warns(self):
        r = self.run_pre(elev(has_display=False))
        self.assertEqual(r["elevation"]["mode"], "none")
        self.assertTrue(any("setcap" in w for w in r["warnings"]))

    def test_macos_report_has_no_linux_fields(self):
        with mock.patch.object(replay.sys, "platform", "darwin"):
            self.assertNotIn("elevation", replay.preflight(fresh=True))


class Stop(unittest.TestCase):
    def tearDown(self):
        replay.RSTATE.update(running=False, stoppable=True, stopped=False, phase="idle")

    def test_pkexec_replay_reports_cannot_stop(self):
        replay.RSTATE.update(running=True, stoppable=False, stopped=False)
        r = replay.stop()
        self.assertFalse(r["ok"])
        self.assertFalse(replay.RSTATE["stopped"])

    def test_default_state_is_stoppable(self):
        self.assertTrue(replay.RSTATE["stoppable"])
        self.assertEqual(replay.RSTATE["elevation"], "")


class HumanOnly(unittest.TestCase):
    def test_replay_routes_stay_human_only(self):
        for route in ("/api/replay/start", "/api/replay/stop", "/api/replay/records"):
            self.assertIn(route, agent_api.HUMAN_ONLY)


if __name__ == "__main__":
    unittest.main()

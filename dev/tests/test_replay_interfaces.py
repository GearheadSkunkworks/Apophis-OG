"""Pure-parser tests for the labelled replay interfaces (no real subprocess)."""
import unittest
from unittest import mock

import replay

HW = """Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:00:00:01

Hardware Port: USB 10/100/1000 LAN
Device: en5
Ethernet Address: aa:bb:cc:00:00:02

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: N/A
"""

UP = "en5: flags=8863<UP>\n\tmedia: autoselect (1000baseT <full-duplex>)\n\tstatus: active\n"
DOWN = "en6: flags=8822<BROADCAST>\n\tmedia: autoselect (none)\n\tstatus: inactive\n"


class Parsers(unittest.TestCase):
    def test_hardware_ports(self):
        m = replay.parse_hardware_ports(HW)
        self.assertEqual(m["en0"], "Wi-Fi")
        self.assertEqual(m["bridge0"], "Thunderbolt Bridge")
        self.assertEqual(replay.parse_hardware_ports(""), {})

    def test_ifconfig(self):
        self.assertEqual(replay.parse_ifconfig(UP), {"link_up": True, "speed": "1 Gb/s"})
        self.assertEqual(replay.parse_ifconfig(DOWN), {"link_up": False, "speed": None})
        self.assertEqual(replay.parse_ifconfig("utun0: flags=8051\n"),
                         {"link_up": None, "speed": None})
        self.assertEqual(replay.parse_ifconfig("\tmedia: autoselect (10Gbase-T <full-duplex>)")["speed"],
                         "10 Gb/s")
        self.assertEqual(replay.parse_ifconfig("\tmedia: autoselect (100baseTX <full-duplex>)")["speed"],
                         "100 Mb/s")

    def test_speed(self):
        self.assertEqual(replay.format_speed("2500"), "2.5 Gb/s")
        self.assertEqual(replay.format_speed(-1), None)
        self.assertEqual(replay.format_speed("x"), None)

    def test_classify(self):
        self.assertEqual(replay.classify_macos("en0", "Wi-Fi"), "wifi")
        self.assertEqual(replay.classify_macos("en5", "USB 10/100/1000 LAN"), "wired")
        self.assertEqual(replay.classify_macos("bridge0", "Thunderbolt Bridge"), "virtual")
        self.assertEqual(replay.classify_macos("utun3"), "virtual")
        self.assertEqual(replay.classify_macos("lo0"), "loopback")
        self.assertEqual(replay.classify_macos("zz9"), "other")
        self.assertEqual(replay.classify_linux("eth0", 1), "wired")
        self.assertEqual(replay.classify_linux("wlp2s0", 1, wireless=True), "wifi")
        self.assertEqual(replay.classify_linux("docker0", 1, virtual=True), "virtual")
        self.assertEqual(replay.classify_linux("lo", 772), "loopback")

    def test_labels(self):
        self.assertEqual(replay.interface_label("en5", "wired", True, "1 Gb/s"),
                         "Ethernet (en5), cable connected, 1 Gb/s")
        self.assertEqual(replay.interface_label("en6", "wired", False, None), "Ethernet (en6), no cable")
        self.assertEqual(replay.interface_label("en0", "wifi", True, None), "Wi-Fi (en0)")
        self.assertEqual(replay.interface_label("bridge0", "virtual", None, None), "Virtual (bridge0)")

    def test_recommended_exactly_one(self):
        def d(n, k, up, sp):
            return {"name": n, "kind": k, "link_up": up, "speed": sp}
        det = [d("en0", "wifi", True, None), d("en5", "wired", True, "1 Gb/s"),
               d("en4", "wired", True, "100 Mb/s"), d("en6", "wired", False, None)]
        self.assertEqual(replay.pick_recommended(det), "en5")
        self.assertIsNone(replay.pick_recommended([d("lo0", "loopback", True, None),
                                                   d("en6", "wired", False, None)]))


class Detail(unittest.TestCase):
    def test_macos_assembly_and_shape(self):
        def fake(argv, timeout=3):
            if argv[0] == "networksetup":
                return HW
            return UP if argv[1] == "en5" else ""
        with mock.patch.object(replay.sys, "platform", "darwin"), \
                mock.patch.object(replay, "_run_text", fake):
            out = replay.interfaces_detail(["en0", "en5", "lo0"])
        self.assertEqual([x["name"] for x in out], ["en0", "en5", "lo0"])
        self.assertEqual([x["recommended"] for x in out], [False, True, False])
        self.assertEqual(out[1]["label"], "Ethernet (en5), cable connected, 1 Gb/s")
        for x in out:
            self.assertEqual(set(x), {"name", "label", "kind", "link_up", "speed", "recommended"})

    def test_probe_failure_degrades(self):
        with mock.patch.object(replay, "_run_text", side_effect=RuntimeError("boom")):
            out = replay.interfaces_detail(["en9"])
        self.assertEqual(out[0]["kind"], "other")
        self.assertIsNone(out[0]["link_up"])
        self.assertFalse(out[0]["recommended"])

    def test_preflight_keeps_flat_list(self):
        r = replay.preflight(fresh=True)
        self.assertIn("interfaces", r)
        self.assertIn("interfaces_detail", r)
        self.assertEqual([d["name"] for d in r["interfaces_detail"]], r["interfaces"])


if __name__ == "__main__":
    unittest.main()

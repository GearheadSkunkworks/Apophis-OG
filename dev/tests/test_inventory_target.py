"""A build that needs a missing inventory regenerates it at the path it was given, never in the source tree."""
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import opengenerator_build as OGB  # noqa: E402 - sys.path is set first


def digest(p):
    with open(p, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class InventoryTarget(unittest.TestCase):
    def test_generator_writes_where_asked_and_leaves_the_source_tree_alone(self):
        before = {n: digest(os.path.join(DEV, n)) for n in os.listdir(DEV) if n.startswith("inventory.")}
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "inv.json")
            subprocess.run([sys.executable, os.path.join(DEV, "inventory.py"), target], check=True, timeout=60,
                           capture_output=True)
            self.assertTrue(os.path.getsize(target) > 1000)
            self.assertTrue(os.path.exists(os.path.join(d, "inv.csv")))
        after = {n: digest(os.path.join(DEV, n)) for n in os.listdir(DEV) if n.startswith("inventory.")}
        self.assertEqual(before, after)

    def test_build_hands_the_missing_path_to_the_generator(self):
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "none.json")
            seen = []

            def fake_run(argv, **kw):
                seen.append(argv)
                raise RuntimeError("stop")
            with mock.patch.object(OGB.subprocess, "run", fake_run):
                with self.assertRaises(RuntimeError):
                    OGB.build(scale=0.001, out=os.path.join(d, "o.pcap"), inventory=missing, progress=False)
        self.assertEqual(os.path.abspath(missing), seen[0][-1])


if __name__ == "__main__":
    unittest.main()

"""npm-tcp-loss-storm at full size (scale 1.0) used to crash: the SACK block packed a sequence number past 2**32.

The scenario is built alone (no normal day) in a child process, as the other scenario tests do.
"""
import os
import subprocess
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHILD = """
import sys
sys.path.insert(0, %r)
import opengenerator_build as OGB
class NoDay(OGB.Day):
    def build(self): pass
OGB.Day = NoDay
s = OGB.build(scale=1.0, out=sys.argv[1], keylog=sys.argv[1] + '.k', inventory=%r, certs_dir=None, iocs_prefix=None,
              modules=['npm-tcp-loss-storm'], progress=False, ot_nets=None)
print(s['packets'])
""" % (DEV, os.path.join(DEV, "inventory.json"))


class TcpSeqWrap(unittest.TestCase):
    def test_loss_storm_builds_at_full_scale(self):
        d = tempfile.mkdtemp(prefix="og-seq-")
        r = subprocess.run([sys.executable, "-c", CHILD, os.path.join(d, "x.pcap")], capture_output=True, text=True, timeout=600)
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        self.assertGreater(int(r.stdout.strip().splitlines()[-1]), 100000)


if __name__ == "__main__":
    unittest.main()

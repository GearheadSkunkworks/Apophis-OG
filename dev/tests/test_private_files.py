"""Private keys and the TLS key log are written readable by their owner only (review finding L1)."""
import glob
import os
import shutil
import stat
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)

import opengenerator_build as OGB  # noqa: E402 - sys.path is set first
from netgen.tls import open_private  # noqa: E402 - sys.path is set first


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class Private(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="og-private-")
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_open_private_is_0600_tightens_an_old_file_and_refuses_a_link(self):
        p = os.path.join(self.d, "k")
        with open(p, "w") as fh:
            fh.write("old")
        os.chmod(p, 0o644)
        with open_private(p, "w") as fh:
            fh.write("new")
        self.assertEqual((mode(p), open(p).read()), (0o600, "new"))
        link = os.path.join(self.d, "l")
        os.symlink(p, link)
        with self.assertRaises(OSError):
            open_private(link)

    def test_a_build_writes_its_keys_and_key_log_0600(self):
        certs = os.path.join(self.d, "certs")
        keylog = os.path.join(self.d, "m.keys")
        OGB.build(scale=0.004, out=os.path.join(self.d, "m.pcap"), keylog=keylog,
                  inventory=os.path.join(DEV, "inventory.json"), certs_dir=certs, iocs_prefix=None,
                  modules=list(OGB.INC.REGISTRY)[:1], progress=False)
        keys = glob.glob(os.path.join(certs, "*.key"))
        self.assertTrue(keys)
        for p in keys + [keylog]:
            self.assertEqual(mode(p), 0o600, p)


if __name__ == "__main__":
    unittest.main()

"""truth, ipfix and netflow9 share one flow-table pass, and their files are byte-identical to the unshared runs."""
import hashlib
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import exports_ipfix as XI  # noqa: E402 - sys.path is set first
import exports_truth as XT  # noqa: E402 - sys.path is set first
import flowtable as FT  # noqa: E402 - sys.path is set first
import opengenerator_build as OGB  # noqa: E402 - sys.path is set first


def sha(p):
    with open(p, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class SharedPass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-shared-")
        cls.addClassCleanup(shutil.rmtree, cls.d, ignore_errors=True)
        cls.s = OGB.build(scale=0.002, out=os.path.join(cls.d, "a.pcap"), keylog=os.path.join(cls.d, "a.keys"),
                          inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None,
                          modules=[], progress=False, tag_sidecar=True)

    def ctx(self, d, exports):
        for ext in (".pcap", ".tags"):
            shutil.copy(os.path.join(self.d, "a" + ext), os.path.join(d, "a" + ext))
        return types.SimpleNamespace(out=os.path.join(d, "a.pcap"), tags_path=os.path.join(d, "a.tags"),
                                     exports=exports, writer=types.SimpleNamespace(n=self.s["packets"]))

    def test_one_pass_same_bytes(self):
        everything = {"truth", "ipfix", "netflow9"}
        with tempfile.TemporaryDirectory() as shared, tempfile.TemporaryDirectory() as solo:
            e = self.ctx(shared, everything)
            real, calls = FT.flows, []
            with mock.patch.object(FT, "flows", lambda *a, **k: calls.append(1) or real(*a, **k)):
                XT.export(e)
                XI.export(e)
            self.assertEqual(1, len(calls))
            self.assertNotIn("_flow_pass", e.__dict__)
            XT.export(self.ctx(solo, {"truth"}))
            XI.export(self.ctx(solo, {"ipfix", "netflow9"}))
            a = {n: sha(os.path.join(shared, n)) for n in sorted(os.listdir(shared)) if n.startswith("a-")}
            b = {n: sha(os.path.join(solo, n)) for n in sorted(os.listdir(solo)) if n.startswith("a-")}
            self.assertGreaterEqual(len(a), 5)
            self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()

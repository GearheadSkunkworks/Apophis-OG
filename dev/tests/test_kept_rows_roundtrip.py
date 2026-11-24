"""Kept builds in the Captures library: Remove on a kept row moves the KEPT capture, never the current one (they share a
file name), and Restore of that holding entry puts it back. Real small builds, then the same calls the page makes."""
import json
import os
import shutil
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import captures_store as cs  # noqa: E402
import opengenerator_build as OGB  # noqa: E402

REG = list(OGB.INC.REGISTRY)


def rd(p):
    with open(p, "rb") as fh:
        return fh.read()


def target(it, base):                      # the same rule as OGCards.captureDir in dev/ui/scenario-cards.js
    return it.get("out_dir") or (os.path.dirname(it["path"]) if it.get("kept") else base)


class KeptRows(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="og-kept-rows-"))
        self.out = os.path.join(self.d, "x-all-in-one.pcap")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def build(self, mods):
        return OGB.build(scale=0.004, out=self.out, inventory=os.path.join(DEV, "inventory.json"), certs_dir=os.path.join(self.d, "certs"),
                         iocs_prefix=None, modules=mods, progress=False)

    def test_remove_and_restore_a_kept_row(self):
        self.build(REG[:1])
        first = rd(self.out)
        k = self.build(REG[1:2])["kept_previous"]["dir"]
        current = rd(self.out)
        self.assertNotEqual(first, current)
        kept_pcap = os.path.join(k, "x-all-in-one.pcap")
        self.assertEqual(rd(kept_pcap), first)
        # the library's rows: the server lists kept files by path with kept=true (the listing in server._captures)
        row = {"name": "x-all-in-one.pcap", "path": kept_pcap, "kept": True}
        tgt = target(row, self.d)
        self.assertEqual(tgt, k)
        cs.trash(tgt, row["name"])
        self.assertEqual(rd(self.out), current)                        # the CURRENT capture is untouched
        self.assertFalse(os.path.exists(kept_pcap))                    # the kept one moved to its holding folder
        held = [t for t in cs.listing(self.d)["items"] if t.get("out_dir")]
        self.assertEqual(len(held), 1)
        self.assertEqual(held[0]["out_dir"], k)
        self.assertEqual(held[0]["name"], "x-all-in-one.pcap")
        cs.restore(held[0].get("out_dir") or self.d, held[0]["trash_id"])
        self.assertEqual(rd(kept_pcap), first)                         # back, byte for byte
        self.assertEqual(rd(self.out), current)
        self.assertEqual([t for t in cs.listing(self.d)["items"]], [])


if __name__ == "__main__":
    unittest.main()

"""GET /profile/summary: the headline facts the Lab import card shows (flows, protocols, duration, size)."""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)


def tiny_pcap(path):
    from netgen.core import PcapWriter
    w = PcapWriter(path)
    arp = (b"\xff" * 6 + b"\x02\0\0\0\0\x01" + b"\x08\x06" + b"\0\x01\x08\0\x06\x04\0\x01" + b"\x02\0\0\0\0\x01"
           + b"\x0a\0\0\x01" + b"\0" * 6 + b"\x0a\0\0\x02")
    for i in range(3):
        w.write(1_700_000_000.0 + i, arp)
    w.f.close()


class ProfileSummary(unittest.TestCase):
    def test_summary_route(self):
        import server
        d = tempfile.mkdtemp()
        try:
            tiny_pcap(os.path.join(d, "t.pcap"))
            with open(os.path.join(d, "notpcap.pcap"), "wb") as f:
                f.write(b"x" * 64)
            srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()

            def get(p):
                u = "http://127.0.0.1:%d/profile/summary?path=%s" % (srv.server_port, urllib.parse.quote(p))
                rq = urllib.request.Request(u, headers={"Cookie": "og_ui=" + server.UI_SECRET})
                return json.loads(urllib.request.urlopen(rq).read())
            ok = get(os.path.join(d, "t.pcap"))
            self.assertTrue(ok["ok"], ok)
            self.assertEqual(ok["packets"], 3)
            self.assertEqual(ok["duration"], 2.0)
            self.assertEqual(get(os.path.join(d, "t.pcap")), ok)                    # second read comes from the cache
            self.assertFalse(get(os.path.join(d, "missing.pcap"))["ok"])
            self.assertFalse(get(os.path.join(d, "notpcap.pcap"))["ok"])
            self.assertFalse(get("")["ok"])
            srv.shutdown()
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

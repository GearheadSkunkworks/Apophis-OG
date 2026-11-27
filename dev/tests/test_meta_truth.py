"""Every campaign-action display filter must match the traffic its action really emits (tshark, with the TLS key log).

Filters in ``NEEDS_ENV`` are exempt, each with its reason; keep that list empty unless a filter truly needs keys or
settings the example capture cannot supply.
"""
import os
import sys
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import meta_truth  # noqa: E402 - sys.path is set up before the import

# (token, filter label) -> reason. Nothing needs an exemption at the moment.
NEEDS_ENV = {}


@unittest.skipUnless(meta_truth.TSHARK, "tshark is not installed")
class MetaTruth(unittest.TestCase):
    def test_filters_match_their_traffic(self):
        rows = meta_truth.run()
        self.assertGreater(len(rows), 100)
        bad = [r for r in rows if r["status"] != "match" and (r["token"], r["what"]) not in NEEDS_ENV]
        self.assertFalse(bad, "\n".join("%s / %s: %s %s [%s]" % (r["token"], r["what"], r["status"],
                                                               r["rendered"] or r["template"], r["detail"]) for r in bad))


class TsharkCommand(unittest.TestCase):
    """The tshark command line is built the same way on every platform (no tshark needed to check it)."""

    def _argv(self, flt):
        run = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr=""))
        with mock.patch.object(meta_truth, "TSHARK", "/x/tshark"), mock.patch.object(meta_truth.subprocess, "run", run):
            meta_truth.tshark_count("a.pcap", "k.log", flt)
        return run.call_args.args[0]

    def test_rdp_filters_name_the_rdp_port_for_old_dissectors(self):
        argv = self._argv("rdp.rt_cookie && ip.src == 10.0.0.1")
        self.assertEqual(argv[argv.index("-d") + 1], "tcp.port==3389,tpkt")

    def test_tls_filters_on_the_rdp_port_name_tls_for_old_dissectors(self):
        argv = self._argv("tcp.srcport == 3389 && tls.record.length > 4000")
        self.assertEqual(argv[argv.index("-d") + 1], "tcp.port==3389,tls")

    def test_other_filters_leave_ports_alone(self):
        self.assertNotIn("-d", self._argv("tls.record.length > 4000"))


if __name__ == "__main__":
    unittest.main()

"""The November 2026 scenario batch: registered, well-formed, and the new exploit-probe product classes match."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from intel import cve_profiles  # noqa: E402 - sys.path is set up before the import
from netgen import incidents as INC  # noqa: E402 - sys.path is set up before the import

IDS = ("ndr-gentlemen", "ir-armorycastle-vcenter-cve123890", "ir-outlook-ntlm-leak-cve124194",
       "ir-freeswitch-sip-message-cve116779", "ir-optimjack-supplychain", "ir-puppet-report-rce-cve115731",
       "ir-openssh-sshole-cve123158", "ir-turla-cereal-exchange")


OLDER = ("ir-netscaler-compromise", "ir-netscaler-cve88771", "ir-beyondtrust-cve102764", "ir-metabase-cve72898",
         "ir-sharepoint-cve58644", "ir-panos-globalprotect-cve0257", "ir-vcenter-cve59310",
         "ir-wordpress-upgrade-race", "ir-ipopt-tcp-uaf")


class Nov2026Scenarios(unittest.TestCase):
    def test_registered_with_window_and_builder(self):
        for sid in IDS:
            inc = INC.REGISTRY[sid]
            self.assertTrue(callable(inc.builder), sid)
            (h0, _m0), (h1, _m1) = inc.window
            self.assertLess(h0, h1, sid)

    def test_every_scenario_has_a_diagram_that_follows_remapped_networks(self):
        import make_diagram as M
        sd = M.scenario_diagrams()
        for sid in IDS + OLDER:
            self.assertIn(sid, sd, sid)
            html = M.render(sid, user_net="192.168.10.0/24", server_net="192.168.20.0/24", modules=[sid])
            self.assertIn("Finding it in a capture", html, sid)
            self.assertNotIn("10.10.20.", html, sid)      # injected internal hosts re-home with the network

    def test_every_ir_replay_has_a_diagram(self):
        import make_diagram as M
        missing = [n for n, i in INC.REGISTRY.items() if i.prefix == "IR" and n not in M.scenario_diagrams()]
        self.assertEqual(missing, [])

    def test_ldap_write_encoders_are_ber(self):
        from netgen.armorycastle_vcenter123890 import (ldap_add_request, ldap_add_response,
                                                        ldap_modify_add, ldap_modify_response)
        # LDAPMessage = SEQUENCE { messageID INTEGER, protocolOp }: the op tag follows the 3-byte INTEGER.
        for blob, op in ((ldap_add_request(2, "cn=a,dc=x", {"cn": ["a"]}), 0x68), (ldap_add_response(2), 0x69),
                         (ldap_modify_add(3, "cn=g,dc=x", "member", "cn=a,dc=x"), 0x66), (ldap_modify_response(3), 0x67)):
            self.assertEqual(blob[0], 0x30)
            hdr = 2 if blob[1] < 0x80 else 2 + (blob[1] & 0x7F)
            self.assertEqual(blob[hdr:hdr + 2], b"\x02\x01")
            self.assertEqual(blob[hdr + 3], op)

    def test_new_exploit_probe_product_classes(self):
        for note, want in (("Perforce Puppet Enterprise Deserialization of Untrusted Data", "remote_mgmt"),
                           ("Project MONAI MONAI Label Path Traversal", "web_app"),
                           ("REDCap Remote Code Execution", "web_app"),
                           ("Synology DiskStation Manager Improper Authentication", "network_device")):
            got = cve_profiles.match({"type": "cve", "note": note, "tags": []})
            self.assertEqual(got and got["id"], want, note)


if __name__ == "__main__":
    unittest.main()

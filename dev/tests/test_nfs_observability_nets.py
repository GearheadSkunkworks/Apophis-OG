"""nfs_observability derives its 7 hosts from the run's nets (default nets stay at 10.10.x)."""
import unittest

from tests.test_actions_b import make_env
from modules import nfs_observability as M


class NfsNets(unittest.TestCase):
    def _hosts(self, **nets):
        ctx = make_env(**nets)
        M._inject_hosts(ctx)
        from netgen import identity as ID
        ident = ID.get_current()
        names = [ident.host(s) for s, _ in M._WORKSTATIONS] + [ident.host(M._NFS_SUFFIX)]
        return ctx, [ctx.h[n] for n in names]

    def test_default_nets_unchanged(self):
        _, hs = self._hosts()
        self.assertEqual([h.ip for h in hs[:-1]], ["10.10.10.%d" % i for i in range(196, 202)])
        self.assertEqual(hs[-1].ip, "10.10.20.21")
        self.assertEqual((hs[0].subnet, hs[-1].subnet), ("10.10.10.0/24", "10.10.20.0/24"))

    def test_custom_nets_follow_the_run(self):
        ctx, hs = self._hosts(user_net="172.16.5.0/24", server_net="172.16.9.0/24")
        self.assertTrue(all(h.ip.startswith("172.16.5.") for h in hs[:-1]))
        self.assertEqual(hs[-1].ip, "172.16.9.21")
        self.assertTrue(all(ctx.link.gateway_for(h) is not None for h in hs))


if __name__ == "__main__":
    unittest.main()

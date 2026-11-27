"""The key pool hands out fresh 2048-bit RSA keys, unique, and never touches the seeded RNG."""
import os
import random
import sys
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
from netgen.keypool import next_key  # noqa: E402 - sys.path is set first


class KeyPool(unittest.TestCase):
    def test_unique_2048_and_rng_untouched(self):
        state = random.getstate()
        keys = [next_key() for _ in range(12)]
        self.assertEqual(state, random.getstate())
        self.assertEqual({2048}, {k.key_size for k in keys})
        self.assertEqual(12, len({k.public_key().public_numbers().n for k in keys}))

    def test_call_sites_use_the_pool(self):
        for name in ("tls.py", "capwap.py"):
            with open(os.path.join(DEV, "netgen", name)) as fh:
                self.assertNotIn("rsa.generate_private_key", fh.read(), name)


if __name__ == "__main__":
    unittest.main()

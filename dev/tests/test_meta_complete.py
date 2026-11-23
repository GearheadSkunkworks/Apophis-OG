"""Every registered campaign action must have complete explanatory metadata (plain, tells, filters, wire), so a new
action cannot ship without text for the campaign diagrams."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netgen.campaign.actions import meta  # noqa: E402


class MetaComplete(unittest.TestCase):
    def test_every_action_has_metadata(self):
        self.assertEqual(meta.missing(), [])


if __name__ == "__main__":
    unittest.main()

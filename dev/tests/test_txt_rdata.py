import unittest
from netgen import protocols as P


class TxtRdata(unittest.TestCase):
    def test_spf_is_one_string(self):
        rec = "v=spf1 include:_spf.google.com ~all"
        self.assertEqual(P.txt_rdata([rec]), bytes([len(rec)]) + rec.encode())


if __name__ == "__main__":
    unittest.main()

import sys, unittest
sys.path.insert(0, 'prototype')
from pacta_core.encoding import json_bytes, gzip_bytes, logical_binary_estimate

class EncodingTest(unittest.TestCase):
    def test_encoding_estimates_are_positive_and_ordered(self):
        obj = {'hash': 'a'*64, 'rows': [{'id': 1, 'amount': 20}], 'ok': True}
        self.assertGreater(json_bytes(obj), 0)
        self.assertGreater(gzip_bytes(obj), 0)
        self.assertGreater(logical_binary_estimate(obj), 0)

if __name__ == '__main__':
    unittest.main()

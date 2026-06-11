import unittest
import sys
sys.path.insert(0, 'prototype')
from pacta_core.frontier_witness import witness_record

class FrontierWitnessTest(unittest.TestCase):
    def test_compact_summary_cannot_decide_unsummarized_predicate(self):
        row = witness_record()
        self.assertTrue(row['same_policy_cube_signature'])
        self.assertTrue(row['same_policy_cube_digest'])
        self.assertTrue(row['different_predicate_answer'])
        self.assertEqual(row['required_obligation'], 'opened_row_multiset_or_amount_histogram')

if __name__ == '__main__':
    unittest.main()

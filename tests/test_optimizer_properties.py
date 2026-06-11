import unittest
import sys
sys.path.insert(0, 'prototype')
from pacta_core.optimizer import CertifyingEvidencePlanner, PlanCandidate
from pacta_core.contract_ir import normalize_contract, contract_obligations

BASE = ['request_binding', 'owner_descriptor', 'schema_binding', 'manifest_policy_binding', 'version_binding']

class OptimizerPropertiesTest(unittest.TestCase):
    def test_missing_obligation_rejected_before_cost(self):
        planner = CertifyingEvidencePlanner()
        cheap = PlanCandidate('cheap_unsound', 'open_scan_groupby_predicate', BASE + ['range_completeness'], 100, 0.1, 0.1)
        sound = PlanCandidate('opened_sound', 'open_scan_groupby_predicate', BASE + ['range_completeness','opened_row_multiset','row_predicate_local_eval'], 100000, 5.0, 10.0)
        decision = planner.choose('open_scan_groupby_predicate', [cheap, sound])
        self.assertTrue(decision.admissible)
        self.assertEqual(decision.chosen_plan, 'opened_sound')
        self.assertEqual(len(decision.rejected), 1)
        self.assertIn('opened_row_multiset', ''.join(decision.rejected[0]['reasons']))

    def test_join_and_avg_operators_have_planner_obligations(self):
        planner = CertifyingEvidencePlanner()
        self.assertIn('returned_pair_membership', planner.required_obligations('returned_pair_join_authenticity'))
        self.assertIn('derived_avg_quotient', planner.required_obligations('range_groupby_avg'))
        self.assertIn('schema_binding', planner.required_obligations('complete_fk_join_groupby'))
        self.assertIn('version_binding', planner.required_obligations('complete_mm_join_groupby'))

    def test_typed_contract_normalization_is_stable(self):
        c1 = {'op':'range_groupby','purpose':'analytics','subject':'tenant-1','policy_hash':'abc','hi':20,'lo':10,'group_by':'category','aggregates':['sum(amount)','count']}
        c2 = {'aggregates':('sum(amount)','count'),'group_by':'category','lo':10,'hi':20,'policy_hash':'abc','subject':'tenant-1','purpose':'analytics','op':'range_groupby'}
        self.assertEqual(normalize_contract(c1), normalize_contract(c2))
        obs = contract_obligations(c1)
        for required in ('request_binding','owner_descriptor','schema_binding','manifest_policy_binding','version_binding','range_completeness','aggregate_monoid'):
            self.assertIn(required, obs)

    def test_topk_candidate_missing_tie_completeness_is_rejected(self):
        planner = CertifyingEvidencePlanner()
        cheap = PlanCandidate('topk_without_ties', 'topk_score_threshold', BASE + ['score_range_completeness','returned_tuple_membership'], 1000, 0.1, 0.1)
        sound = PlanCandidate('topk_with_cutoff_ties', 'topk_score_threshold', BASE + ['score_range_completeness','cutoff_tie_completeness','returned_tuple_membership'], 3000, 0.3, 0.2)
        decision = planner.choose('topk_score_threshold', [cheap, sound])
        self.assertTrue(decision.admissible)
        self.assertEqual(decision.chosen_plan, 'topk_with_cutoff_ties')
        self.assertIn('cutoff_tie_completeness', ''.join(decision.rejected[0]['reasons']))


if __name__ == '__main__':
    unittest.main()

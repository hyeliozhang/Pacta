#!/usr/bin/env python3
import copy
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prototype"))

import pacta


class CertificateEncodingStrictnessTest(unittest.TestCase):
    def _single_leaf_groupby(self):
        rows = pacta.generate_sales(1, seed=17)
        row = rows[0]
        policy = pacta.Policy(tenant=int(row["tenant"]), max_sensitivity=2, regions=(int(row["region"]),))
        tree = pacta.MerkleAggregateTree(rows, fanout=4)
        cert = tree.make_groupby_certificate(policy, int(row["day"]), int(row["day"]))
        owner = pacta.owner_digest(tree.relation_descriptor(), cert["manifest"], tree.version)
        self.assertTrue(tree.verify_groupby_certificate(cert, expected_owner_digest=owner, expected_contract=cert["query"]))
        return tree, cert, owner

    def test_rejects_ambiguous_certificate_node_metadata(self):
        tree, cert, owner = self._single_leaf_groupby()
        bad = copy.deepcopy(cert)
        bad["proof"]["count"] = True
        self.assertFalse(tree.verify_groupby_certificate(bad, expected_owner_digest=owner, expected_contract=cert["query"]))

    def test_rejects_ambiguous_result_values(self):
        tree, cert, owner = self._single_leaf_groupby()
        bad = copy.deepcopy(cert)
        group = next(iter(bad["result"]))
        bad["result"][group][0] = True
        self.assertFalse(tree.verify_groupby_certificate(bad, expected_owner_digest=owner, expected_contract=cert["query"]))

    def test_rejects_ambiguous_leaf_path_metadata(self):
        rows = pacta.generate_sales(32, seed=19)
        row = rows[0]
        policy = pacta.Policy(tenant=int(row["tenant"]), max_sensitivity=2, regions=(int(row["region"]),))
        tree = pacta.MerkleAggregateTree(rows, fanout=4)
        cert = tree.make_projection_certificate(policy, int(row["day"]), int(row["day"]))
        owner = pacta.owner_digest(tree.relation_descriptor(), cert["manifest"], tree.version)
        self.assertTrue(tree.verify_projection_certificate(cert, expected_owner_digest=owner, expected_contract=cert["query"]))
        self.assertTrue(cert["items"] and cert["items"][0]["path"], "projection witness should include a non-root leaf path")
        bad = copy.deepcopy(cert)
        bad["items"][0]["path"][0]["child_index"] = True
        self.assertFalse(tree.verify_projection_certificate(bad, expected_owner_digest=owner, expected_contract=cert["query"]))


if __name__ == "__main__":
    unittest.main()

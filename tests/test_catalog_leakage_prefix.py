import unittest, sys, os, copy
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'prototype'))
from pacta_core.catalog import CatalogEntry, sign_entry, verify_signed_entry
from pacta_core.leakage import evaluate_plan_leakage
from pacta_core.prefix_cube import PrefixCube, MerkleList, verify_prefix_cube_certificate, digest as prefix_digest

class CatalogLeakagePrefixTests(unittest.TestCase):
    def test_catalog_rejects_replay_and_tamper(self):
        owner = {"relation_descriptor_digest": "rd", "manifest_root": "mr", "relation_version": 3, "manifest_release_version": 7, "version": 7}
        entry = CatalogEntry("sales", 3, 7, 42, owner, "rd", "mr")
        signed = sign_entry(entry, b"secret").to_dict()
        self.assertTrue(verify_signed_entry(signed, b"secret", min_epoch=42, expected_relation="sales", expected_relation_version=3, expected_manifest_version=7))
        self.assertFalse(verify_signed_entry(signed, b"secret", min_epoch=43, expected_relation="sales", expected_relation_version=3, expected_manifest_version=7))
        relation_tamper = copy.deepcopy(signed)
        relation_tamper["entry"]["owner_digest"]["relation_version"] = 4
        relation_tamper = sign_entry(CatalogEntry(**relation_tamper["entry"]), b"secret").to_dict()
        self.assertFalse(verify_signed_entry(relation_tamper, b"secret", min_epoch=42, expected_relation="sales", expected_relation_version=3, expected_manifest_version=7))
        signed["entry"]["manifest_version"] = 8
        self.assertFalse(verify_signed_entry(signed, b"secret", min_epoch=42, expected_relation="sales", expected_relation_version=3, expected_manifest_version=7))

    def test_catalog_rejects_ambiguous_numeric_versions(self):
        owner = {"relation_descriptor_digest": "rd", "manifest_root": "mr", "relation_version": 3, "manifest_release_version": 7, "version": 7}
        for field, value in (("relation_version", 3.0), ("manifest_version", True), ("epoch", 42.5)):
            entry = CatalogEntry("sales", 3, 7, 42, owner, "rd", "mr").payload()
            entry[field] = value
            signed = sign_entry(CatalogEntry(**entry), b"secret").to_dict()
            self.assertFalse(
                verify_signed_entry(signed, b"secret", min_epoch=42, expected_relation="sales", expected_relation_version=3, expected_manifest_version=7),
                msg=f"catalog {field}={value!r} should fail closed",
            )
        bad_owner = CatalogEntry("sales", 3, 7, 42, dict(owner, relation_version=3.0), "rd", "mr")
        signed = sign_entry(bad_owner, b"secret").to_dict()
        self.assertFalse(verify_signed_entry(signed, b"secret", min_epoch=42, expected_relation="sales", expected_relation_version=3, expected_manifest_version=7))

    def test_leakage_contract_detects_extra_fields(self):
        ok = evaluate_plan_leakage("prefix_cube_view", ["category", "count", "sum(amount)"])
        self.assertTrue(ok.allowed)
        bad = evaluate_plan_leakage("complete_open_scan", ["category", "count", "sum(amount)"])
        self.assertFalse(bad.allowed)
        self.assertIn("amount", bad.excess_fields)

    def test_prefix_cube_matches_oracle_and_rejects_tamper(self):
        rows = [
            {"id": 1, "tenant": 1, "region": 0, "sensitivity": 1, "category": 2, "day": 1, "amount": 10},
            {"id": 2, "tenant": 1, "region": 0, "sensitivity": 2, "category": 2, "day": 3, "amount": 5},
            {"id": 3, "tenant": 2, "region": 0, "sensitivity": 1, "category": 3, "day": 3, "amount": 99},
        ]
        policy = {"tenant": 1, "regions": [0], "max_sensitivity": 2}
        cube = PrefixCube.build(rows, max_day=5)
        cert = cube.certificate(1, 3, policy, relation_descriptor_digest="rd")
        self.assertTrue(verify_prefix_cube_certificate(cert, expected_lo=1, expected_hi=3, expected_policy=policy, expected_relation_descriptor_digest="rd", expected_root=cube.root))
        self.assertEqual(cert["result"], {"2": [2, 15]})
        cert["result"] = {"2": [1, 15]}
        self.assertFalse(verify_prefix_cube_certificate(cert, expected_lo=1, expected_hi=3, expected_policy=policy, expected_relation_descriptor_digest="rd", expected_root=cube.root))

    def test_prefix_cube_binds_range_and_zero_sentinel(self):
        rows = [
            {"id": 1, "tenant": 1, "region": 0, "sensitivity": 1, "category": 2, "day": 0, "amount": 10},
            {"id": 2, "tenant": 1, "region": 0, "sensitivity": 1, "category": 2, "day": 2, "amount": 5},
        ]
        policy = {"tenant": 1, "regions": [0], "max_sensitivity": 2}
        cube = PrefixCube.build(rows, max_day=5)
        cert = cube.certificate(0, 2, policy)
        self.assertTrue(verify_prefix_cube_certificate(cert, expected_lo=0, expected_hi=2, expected_policy=policy, expected_root=cube.root))

        wrong_range = copy.deepcopy(cert)
        wrong_range["lo"] = 1
        self.assertFalse(verify_prefix_cube_certificate(wrong_range, expected_lo=1, expected_hi=2, expected_policy=policy, expected_root=cube.root))

        bad_sentinel = copy.deepcopy(cert)
        payload = {"day": 0, "summary": {}}
        bad_sentinel["before_entry"] = {**payload, "entry_hash": prefix_digest("prefix_cube_entry", payload)}
        self.assertFalse(verify_prefix_cube_certificate(bad_sentinel, expected_lo=0, expected_hi=2, expected_policy=policy, expected_root=cube.root))


    def test_prefix_cube_requires_committed_root_and_strict_numeric_fields(self):
        rows = [
            {"id": 1, "tenant": 1, "region": 0, "sensitivity": 1, "category": 2, "day": 1, "amount": 10},
            {"id": 2, "tenant": 1, "region": 0, "sensitivity": 1, "category": 3, "day": 2, "amount": 7},
        ]
        policy = {"tenant": 1, "regions": [0], "max_sensitivity": 2}
        cube = PrefixCube.build(rows, max_day=5)
        cert = cube.certificate(1, 2, policy, relation_descriptor_digest="rd")
        self.assertTrue(verify_prefix_cube_certificate(cert, expected_lo=1, expected_hi=2, expected_policy=policy, expected_relation_descriptor_digest="rd", expected_root=cube.root))
        self.assertFalse(verify_prefix_cube_certificate(cert, expected_lo=1, expected_hi=2, expected_policy=policy, expected_relation_descriptor_digest="rd"))
        self.assertFalse(verify_prefix_cube_certificate(cert, expected_lo=1, expected_hi=2, expected_policy=policy, expected_relation_descriptor_digest="rd", expected_root="forged-root"))

        for field, value in (("lo", True), ("hi", 2.0), ("hi_index", "2.0"), ("before_index", False)):
            bad = copy.deepcopy(cert)
            bad[field] = value
            self.assertFalse(
                verify_prefix_cube_certificate(bad, expected_lo=1, expected_hi=2, expected_policy=policy, expected_relation_descriptor_digest="rd", expected_root=cube.root),
                msg=f"prefix certificate {field}={value!r} should fail closed",
            )

    def test_merkle_list_binds_path_to_claimed_index(self):
        leaves = [prefix_digest('leaf', {'i': i}) for i in range(5)]
        merkle = MerkleList(leaves)
        proof_for_two = merkle.proof(2)
        self.assertTrue(MerkleList.verify(leaves[2], 2, proof_for_two, merkle.root, n_leaves=len(leaves)))
        self.assertFalse(MerkleList.verify(leaves[2], 1, proof_for_two, merkle.root, n_leaves=len(leaves)))
        self.assertFalse(MerkleList.verify(leaves[2], True, proof_for_two, merkle.root, n_leaves=len(leaves)))

if __name__ == '__main__':
    unittest.main()

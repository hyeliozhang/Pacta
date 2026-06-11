import sys, unittest
sys.path.insert(0, 'prototype')
from pacta_core.contract_ir import normalize_contract, contract_obligations
from pacta import contract_digest, compile_sql_contract, make_manifest, make_policy, UnsupportedQueryError, validate_row_schema, generate_sales, generate_customers, customers_as_sales_like, generate_category_tags, MerkleAggregateTree

class ContractIRTest(unittest.TestCase):
    def test_normalizes_dimension_predicates(self):
        c = {
            'op': 'complete_fk_join_groupby', 'lo': 1, 'hi': 9,
            'join': 'sales.cust_id=customers.cust_id', 'group_by': 'customers.segment',
            'dimension_predicates': ['customers.tenant=sales.tenant', 'customers.active=1'],
            'aggregates': ['count', 'sum(sales.amount)'], 'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'
        }
        n = normalize_contract(c)
        self.assertEqual(n['dimension_predicates'], ['customers.active=1', 'customers.tenant=sales.tenant'])
        self.assertIn('dimension_presence', contract_obligations(n))

    def test_rejects_weak_open_scan_contract(self):
        c = {
            'op': 'open_scan_groupby_predicate', 'lo': 1, 'hi': 9,
            'row_predicate': ['amount', '>=', 50], 'group_by': 'category',
            'aggregates': ['count', 'sum(amount)'], 'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'
        }
        with self.assertRaises(ValueError):
            normalize_contract(c)

    def test_rejects_unsupported_aggregate_and_incomplete_mm_contract(self):
        bad_agg = {
            'op': 'range_groupby', 'lo': 1, 'hi': 9, 'group_by': 'category',
            'aggregates': ['median(amount)'], 'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'
        }
        with self.assertRaises(ValueError):
            normalize_contract(bad_agg)
        missing_tag_policy = {
            'op': 'complete_mm_join_groupby', 'lo': 1, 'hi': 9,
            'join': 'sales.category=category_tags.category', 'group_by': 'category_tags.tag',
            'aggregates': ['count', 'sum(sales.amount)'], 'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'
        }
        with self.assertRaises(ValueError):
            normalize_contract(missing_tag_policy)


    def test_rejects_range_like_contract_without_explicit_bounds(self):
        base = {
            'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc',
            'group_by': 'category', 'aggregates': ['count', 'sum(amount)']
        }
        for missing in ('lo', 'hi'):
            c = dict(base, op='range_groupby', lo=1, hi=9)
            c.pop(missing)
            with self.assertRaises(ValueError, msg=f'missing {missing} should be rejected'):
                normalize_contract(c)
        c = {
            'op': 'complete_fk_join_groupby', 'lo': 1,
            'join': 'sales.cust_id=customers.cust_id', 'group_by': 'customers.segment',
            'dimension_predicates': ['customers.tenant=sales.tenant', 'customers.active=1'],
            'aggregates': ['count', 'sum(sales.amount)'],
            'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'
        }
        with self.assertRaises(ValueError):
            normalize_contract(c)


    def test_rejects_none_like_required_fields(self):
        base = {
            'op': 'range_groupby', 'lo': 1, 'hi': 9, 'group_by': 'category',
            'aggregates': ['count', 'sum(amount)'], 'subject': 'tenant-1',
            'purpose': 'audit', 'policy_hash': 'abc'
        }
        for field in ('subject', 'purpose', 'policy_hash'):
            for bad in (None, '', '   ', 'None', 'null'):
                c = dict(base)
                c[field] = bad
                with self.assertRaises(ValueError, msg=f'{field}={bad!r} should fail closed'):
                    normalize_contract(c)

    def test_rejects_extra_having_predicates(self):
        c = {
            'op': 'range_groupby_having_sum', 'lo': 1, 'hi': 9, 'group_by': 'category',
            'aggregates': ['sum(amount)', 'count'], 'having': {'sum(amount)': ['>=', 100], 'max(amount)': ['<=', 500]},
            'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'
        }
        with self.assertRaises(ValueError):
            normalize_contract(c)
        ok = dict(c)
        ok['having'] = {'sum(amount)': ['>=', 100]}
        self.assertEqual(normalize_contract(ok)['having'], {'sum(amount)': ['>=', 100]})

    def test_join_obligation_vocabulary_binds_dimension_predicates(self):
        returned = {
            'op': 'returned_pair_join_authenticity', 'lo': 1, 'hi': 9,
            'join': 'sales.cust_id=customers.cust_id', 'segment': 3,
            'dimension_predicates': ['customers.tenant=sales.tenant', 'customers.active=1'],
            'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'
        }
        fk = dict(returned, op='complete_fk_join_groupby', group_by='customers.segment',
                  aggregates=['count', 'sum(sales.amount)'])
        fk.pop('segment')
        anti = dict(returned, op='complete_antijoin_groupby', join='NOT EXISTS customers.cust_id=sales.cust_id',
                    group_by='sales.category', aggregates=['count', 'sum(sales.amount)'])
        anti.pop('segment')
        for c in (returned, fk, anti):
            self.assertIn('dimension_predicate_binding', contract_obligations(c))


    def test_returned_pair_join_binds_segment_and_range_in_request_digest(self):
        base = {
            'op': 'returned_pair_join_authenticity', 'lo': 1, 'hi': 9, 'segment': 2,
            'join': 'sales.cust_id=customers.cust_id',
            'dimension_predicates': ['customers.tenant=sales.tenant', 'customers.active=1'],
            'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'
        }
        norm = normalize_contract(base)
        self.assertEqual(norm['segment'], 2)
        self.assertNotEqual(contract_digest(base), contract_digest(dict(base, segment=3)))
        self.assertNotEqual(normalize_contract(base), normalize_contract(dict(base, lo=2)))
        for missing in ('lo', 'hi', 'segment'):
            weak = dict(base)
            weak.pop(missing)
            with self.assertRaises(ValueError, msg=f'returned-pair join missing {missing} should fail closed'):
                normalize_contract(weak)

    def test_rejects_unknown_contract_fields_and_ambiguous_integers(self):
        base = {
            'op': 'range_groupby', 'lo': 1, 'hi': 9, 'group_by': 'category',
            'aggregates': ['count', 'sum(amount)'], 'subject': 'tenant-1',
            'purpose': 'audit', 'policy_hash': 'abc'
        }
        with self.assertRaises(ValueError):
            normalize_contract(dict(base, hidden_filter='amount >= 100'))
        for field, bad in [('lo', True), ('hi', 9.7), ('lo', ''), ('hi', None)]:
            c = dict(base)
            c[field] = bad
            with self.assertRaises(ValueError, msg=f'{field}={bad!r} should not be coerced'):
                normalize_contract(c)

        topk = {'op': 'topk_score_threshold', 'subject': 'tenant-1', 'purpose': 'audit',
                'policy_hash': 'abc', 'k': True, 'score_ge': 80,
                'order': ['score desc', 'id asc']}
        with self.assertRaises(ValueError):
            normalize_contract(topk)
        open_scan = {'op': 'open_scan_groupby_predicate', 'lo': 1, 'hi': 9,
                     'row_predicate': ['amount', '>=', 50.5], 'group_by': 'category',
                     'aggregates': ['count', 'sum(amount)'], 'evidence_plan': 'complete_open_range_scan',
                     'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'}
        with self.assertRaises(ValueError):
            normalize_contract(open_scan)
        having = {'op': 'range_groupby_having_sum', 'lo': 1, 'hi': 9, 'group_by': 'category',
                  'aggregates': ['count', 'sum(amount)'], 'having': {'sum(amount)': ['>=', False]},
                  'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'}
        with self.assertRaises(ValueError):
            normalize_contract(having)



    def test_dimension_schema_descriptor_binds_join_extra_integer_fields(self):
        sales = generate_sales(48, seed=7)
        customers = customers_as_sales_like(generate_customers(sales, seed=3))
        cust_tree = MerkleAggregateTree(customers, key_attr="cust_id", fanout=8)
        cust_schema = cust_tree.relation_descriptor()["schema"]
        self.assertEqual(cust_schema.get("schema_version"), 3)
        self.assertIn("active", cust_schema.get("typed_extra_int", []))
        self.assertIn("segment", cust_schema.get("typed_extra_int", []))

        for field, bad in (("segment", "2"), ("active", True), ("segment", None)):
            tampered = [dict(r) for r in customers]
            tampered[0][field] = bad
            with self.assertRaises(ValueError, msg=f"dimension field {field}={bad!r} should be descriptor-typed"):
                MerkleAggregateTree(tampered, key_attr="cust_id", fanout=8)

        tags = generate_category_tags(categories=4, tags_per_category=2)
        tag_tree = MerkleAggregateTree(tags, key_attr="category", fanout=8)
        self.assertIn("tag", tag_tree.relation_descriptor()["schema"].get("typed_extra_int", []))
        bad_tags = [dict(r) for r in tags]
        bad_tags[0]["tag"] = 1.2
        with self.assertRaises(ValueError):
            MerkleAggregateTree(bad_tags, key_attr="category", fanout=8)

    def test_sql_compiler_rejects_ambiguous_numeric_parameters(self):
        policy = make_policy(tenant=1, complexity=2)
        manifest = make_manifest(policy)
        sql = "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category"
        subject = "tenant-1"
        purpose = policy.purpose
        for bad_params in ([True, 9], [1.5, 9], ["", 9], [None, 9]):
            with self.assertRaises(UnsupportedQueryError, msg=f"{bad_params!r} should fail closed"):
                compile_sql_contract(sql, bad_params, manifest, subject, purpose)
        ok = compile_sql_contract(sql, ["1", "9"], manifest, subject, purpose)
        self.assertEqual((ok["lo"], ok["hi"]), (1, 9))

        join_sql = ("SELECT s.id, c.cust_id FROM sales s JOIN customers c ON s.cust_id = c.cust_id "
                    "WHERE s.day BETWEEN ? AND ? AND c.segment = ? AND c.active = 1")
        with self.assertRaises(UnsupportedQueryError):
            compile_sql_contract(join_sql, [1, 9, 2.5], manifest, subject, purpose)
        ok_join = compile_sql_contract(join_sql, [1, 9, "2"], manifest, subject, purpose)
        self.assertEqual(ok_join["segment"], 2)

    def test_committed_row_schema_rejects_non_integral_encodings(self):
        row = {"id": 1, "tenant": 1, "region": 0, "category": 2, "day": 3, "amount": 10, "score": 5, "sensitivity": 1, "cust_id": 7}
        validate_row_schema(row, "day")
        for field, bad in (("amount", 10.5), ("tenant", True), ("region", "0")):
            tampered = dict(row)
            tampered[field] = bad
            with self.assertRaises(ValueError, msg=f"{field}={bad!r} should fail closed"):
                validate_row_schema(tampered, "day")

    def test_rejects_topk_without_threshold_or_stable_tie_order(self):
        base = {
            'op': 'topk_score_threshold', 'subject': 'tenant-1', 'purpose': 'audit',
            'policy_hash': 'abc', 'k': 5, 'score_ge': 80,
            'order': ['score desc', 'id asc']
        }
        missing_threshold = dict(base)
        missing_threshold.pop('score_ge')
        with self.assertRaises(ValueError):
            normalize_contract(missing_threshold)
        unstable_order = dict(base, order=['score desc'])
        with self.assertRaises(ValueError):
            normalize_contract(unstable_order)
        non_positive_k = dict(base, k=0)
        with self.assertRaises(ValueError):
            normalize_contract(non_positive_k)

    def test_rejects_operator_field_smuggling(self):
        base_groupby = {
            'op': 'range_groupby', 'lo': 1, 'hi': 9, 'group_by': 'category',
            'aggregates': ['count', 'sum(amount)'], 'subject': 'tenant-1',
            'purpose': 'audit', 'policy_hash': 'abc'
        }
        for bad_extra in [
            {'row_predicate': ['amount', '>=', 50]},
            {'having': {'sum(amount)': ['>=', 100]}},
            {'projection': ['id', 'category', 'amount']},
            {'order': ['score desc', 'id asc']},
            {'segment': 2},
            {'dimension_predicates': ['customers.active=1']},
            {'evidence_plan': 'complete_open_range_scan'},
        ]:
            with self.assertRaises(ValueError, msg=f"operator-field smuggling accepted: {bad_extra}"):
                normalize_contract(dict(base_groupby, **bad_extra))

        topk = {'op': 'topk_score_threshold', 'subject': 'tenant-1', 'purpose': 'audit',
                'policy_hash': 'abc', 'k': 5, 'score_ge': 80, 'order': ['score desc', 'id asc']}
        for bad_extra in [
            {'lo': 1, 'hi': 9},
            {'group_by': 'category'},
            {'aggregates': ['count', 'sum(amount)']},
            {'row_predicate': ['amount', '>=', 50]},
        ]:
            with self.assertRaises(ValueError, msg=f"top-k accepted incompatible fields: {bad_extra}"):
                normalize_contract(dict(topk, **bad_extra))

        returned = {
            'op': 'returned_pair_join_authenticity', 'lo': 1, 'hi': 9, 'segment': 2,
            'join': 'sales.cust_id=customers.cust_id',
            'dimension_predicates': ['customers.tenant=sales.tenant', 'customers.active=1'],
            'subject': 'tenant-1', 'purpose': 'audit', 'policy_hash': 'abc'
        }
        for bad_extra in [
            {'aggregates': ['count', 'sum(sales.amount)']},
            {'group_by': 'customers.segment'},
            {'projection': ['id']},
            {'evidence_plan': 'complete_open_range_scan'},
        ]:
            with self.assertRaises(ValueError, msg=f"returned-pair join accepted incompatible fields: {bad_extra}"):
                normalize_contract(dict(returned, **bad_extra))


if __name__ == '__main__':
    unittest.main()

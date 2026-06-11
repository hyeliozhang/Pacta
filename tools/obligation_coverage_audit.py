#!/usr/bin/env python3
"""Audit that manuscript, contract IR, optimizer, and tests stay aligned.

A certifying DB systems artifact can drift in subtle ways: the paper may claim
one verifier obligation, the contract IR may expose another, and the optimizer
may rank candidates using a third vocabulary.  This meta-test makes that drift a
CI failure.  It is intentionally conservative and complements the semantic and
adversarial tests rather than replacing them.
"""
from __future__ import annotations
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prototype"))

from pacta_core.contract_ir import BASE_OBLIGATIONS, OP_ALLOWED_FIELDS, OP_OBLIGATIONS, SUPPORTED_OPS  # noqa: E402
from pacta_core.optimizer import CertifyingEvidencePlanner  # noqa: E402

FAIL: list[str] = []

def fail(msg: str) -> None:
    FAIL.append(msg)

planner = CertifyingEvidencePlanner()
for op in sorted(SUPPORTED_OPS):
    ir = set(BASE_OBLIGATIONS + OP_OBLIGATIONS[op])
    opt = set(planner.required_obligations(op))
    if ir != opt:
        fail(f"obligation vocabulary mismatch for {op}: IR-only={sorted(ir - opt)} optimizer-only={sorted(opt - ir)}")
    if op not in OP_ALLOWED_FIELDS:
        fail(f"operator-field compatibility table missing op: {op}")

tex = (ROOT / "main.tex").read_text(encoding="utf-8")
for phrase in [
    "request digest",
    "manifest-derived",
    "projection safety",
    "descriptor conservation",
    "operator-specific completeness",
    "dimension predicates",
    "negative-control",
    "fail closed",
    "operator-field smuggling",
]:
    if phrase not in tex:
        fail(f"paper missing review-facing phrase: {phrase}")

haystack = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in (ROOT / "tests").glob("test_*.py"))
haystack += "\n" + "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in (ROOT / "prototype").rglob("*.py"))
haystack_lower = haystack.lower()
coverage_terms = {
    "range_groupby": ["range_groupby", "range_completeness"],
    "range_groupby_avg": ["range_groupby_avg", "derived_avg_quotient"],
    "range_groupby_having_sum": ["range_groupby_having_sum", "having"],
    "range_groupby_distinct_customer": ["count(distinct", "duplicate"],
    "range_projection": ["range_projection", "projection"],
    "open_scan_groupby_predicate": ["open_scan", "opened_row_multiset"],
    "topk_score_threshold": ["topk", "cutoff"],
    "returned_pair_join_authenticity": ["returned_pair", "dimension_predicate_binding"],
    "complete_fk_join_groupby": ["complete_fk", "dimension_presence"],
    "complete_antijoin_groupby": ["complete_antijoin", "dimension_absence"],
    "complete_mm_join_groupby": ["many-to-many", "dimension_policy"],
    "operator_field_smuggling": ["operator-field smuggling", "not valid for"],
}
for op, terms in coverage_terms.items():
    for term in terms:
        if term.lower() not in haystack_lower:
            fail(f"test/prototype coverage text missing term for {op}: {term}")

if FAIL:
    print("obligation coverage audit failed:", file=sys.stderr)
    for msg in FAIL:
        print(f" - {msg}", file=sys.stderr)
    sys.exit(1)
print(f"obligation coverage audit passed: {len(SUPPORTED_OPS)} operators aligned across IR, optimizer, manuscript, and tests")

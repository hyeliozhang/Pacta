"""Leakage contracts for governed evidence plans.

The verifier accepts a certificate only after checking integrity.  A governed
release also needs an explicit disclosure contract: which fields are opened by a
plan and whether those fields are allowed by the projection/policy.  This module
keeps the model simple and executable for the artifact.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Mapping, Sequence, Set, Tuple

PLAN_FIELDS: Dict[str, Set[str]] = {
    "policy_cube_summary": {"tenant", "region", "sensitivity", "category", "count", "sum(amount)", "range_density"},
    "tuple_frontier": {"id", "day", "category", "amount", "tenant", "region", "sensitivity", "proof_path"},
    "complete_open_scan": {"id", "day", "category", "amount", "tenant", "region", "sensitivity", "cust_id", "score", "proof_path"},
    "prefix_cube_view": {"tenant", "region", "sensitivity", "category", "count", "sum(amount)", "prefix_epoch"},
    "topk_accumulator": {"id", "score", "cutoff", "tie_count", "proof_path"},
    "join_witness": {"fact_id", "cust_id", "category", "amount", "dimension_key", "dimension_status", "proof_path"},
}

PUBLIC_AUDIT_FIELDS = {"count", "sum(amount)", "category", "tenant", "region", "sensitivity", "range_density", "prefix_epoch", "cutoff", "tie_count", "proof_path", "dimension_status"}

@dataclass(frozen=True)
class LeakageDecision:
    plan: str
    disclosed_fields: Tuple[str, ...]
    allowed: bool
    excess_fields: Tuple[str, ...]
    reason: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def evaluate_plan_leakage(plan: str, projection: Sequence[str], *, released_fields: Sequence[str] = ("category", "count", "sum(amount)")) -> LeakageDecision:
    fields = set(PLAN_FIELDS.get(plan, set()))
    allowed = set(projection) | set(released_fields) | PUBLIC_AUDIT_FIELDS
    excess = tuple(sorted(fields - allowed))
    ok = len(excess) == 0
    return LeakageDecision(plan, tuple(sorted(fields)), ok, excess, "projection-compatible" if ok else "opens-fields-outside-release-contract")


def leakage_matrix(plans: Iterable[str], projection: Sequence[str]) -> List[Dict[str, object]]:
    return [evaluate_plan_leakage(p, projection).to_dict() for p in plans]

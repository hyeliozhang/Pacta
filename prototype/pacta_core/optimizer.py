"""Verifier-preserving evidence-plan optimizer for Pacta.

The optimizer is intentionally separate from certificate generation: it takes a
client contract, observed candidate measurements, and a set of verifier
obligations, then chooses the least-cost admissible evidence plan.  Rejected
plans carry machine-readable reasons so experiments can distinguish a cheap but
unsound plan from a sound physical alternative.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

JSON = Dict[str, object]

BASE_REQUIRED: Tuple[str, ...] = (
    "request_binding",
    "owner_descriptor",
    "schema_binding",
    "manifest_policy_binding",
    "version_binding",
)

OP_REQUIRED: Mapping[str, Sequence[str]] = {
    "range_groupby": ("range_completeness", "aggregate_monoid"),
    "range_groupby_avg": ("range_completeness", "aggregate_monoid", "derived_avg_quotient"),
    "range_groupby_having_sum": ("range_completeness", "aggregate_monoid", "having_over_verified_state"),
    "open_scan_groupby_predicate": ("range_completeness", "opened_row_multiset", "row_predicate_local_eval"),
    "range_projection": ("range_completeness", "opened_row_multiset", "projection_mask"),
    "range_groupby_distinct_customer": ("range_completeness", "opened_row_multiset", "duplicate_elimination"),
    "topk_score_threshold": ("score_range_completeness", "cutoff_tie_completeness", "returned_tuple_membership"),
    "returned_pair_join_authenticity": ("returned_pair_membership", "dimension_predicate_binding", "join_predicate"),
    "complete_fk_join_groupby": ("fact_multiset", "dimension_presence", "dimension_predicate_binding", "join_predicate"),
    "complete_antijoin_groupby": ("fact_multiset", "dimension_absence", "dimension_predicate_binding", "join_predicate"),
    "complete_mm_join_groupby": ("fact_multiset", "dimension_multiset", "dimension_policy_binding", "join_predicate"),
}

# Backward-compatible aliases keep old experiment CSVs readable while the
# optimizer's canonical vocabulary matches the paper and contract IR.
OBLIGATION_ALIASES: Mapping[str, str] = {
    "policy_binding": "manifest_policy_binding",
}

@dataclass(frozen=True)
class PlanCandidate:
    name: str
    operator: str
    obligations: Sequence[str]
    certificate_bytes: int
    server_generation_ms: float
    client_verification_ms: float
    opened_rows: Optional[int] = None
    notes: str = ""

    def total_cost_ms(self) -> float:
        return float(self.server_generation_ms) + float(self.client_verification_ms)

@dataclass(frozen=True)
class PlanDecision:
    operator: str
    chosen_plan: Optional[str]
    admissible: bool
    reason: str
    rejected: Sequence[JSON]
    chosen_cost_bytes: Optional[int] = None
    chosen_total_ms: Optional[float] = None

    def to_json(self) -> JSON:
        return asdict(self)

class CertifyingEvidencePlanner:
    """Rule-based optimizer with explicit verifier obligations.

    Candidates are enumerated, rejected if their evidence does not imply the
    verifier obligations of the operator, and then ranked by a multi-objective
    cost key.  The ranking is not trusted for soundness; admissibility is
    checked first.
    """

    def required_obligations(self, operator: str) -> Sequence[str]:
        if operator not in OP_REQUIRED:
            raise ValueError(f"unsupported operator for planner: {operator}")
        return tuple(dict.fromkeys(BASE_REQUIRED + tuple(OP_REQUIRED[operator])))

    def _canonical_obligations(self, obligations: Sequence[str]) -> set[str]:
        return {OBLIGATION_ALIASES.get(str(o), str(o)) for o in obligations}

    def explain_candidate(self, cand: PlanCandidate) -> List[str]:
        required = set(self.required_obligations(cand.operator))
        present = self._canonical_obligations(cand.obligations)
        missing = sorted(required - present)
        return [f"missing:{m}" for m in missing]

    def choose(self, operator: str, candidates: Iterable[PlanCandidate], *, objective: str = "bytes_then_time") -> PlanDecision:
        examined: List[PlanCandidate] = [c for c in candidates if c.operator == operator]
        rejected: List[JSON] = []
        admissible: List[PlanCandidate] = []
        for cand in examined:
            reasons = self.explain_candidate(cand)
            if reasons:
                rejected.append({**asdict(cand), "reasons": reasons})
            else:
                admissible.append(cand)
        if not admissible:
            return PlanDecision(operator, None, False, "no admissible evidence plan", rejected)
        if objective == "time_then_bytes":
            key = lambda c: (c.total_cost_ms(), c.certificate_bytes)
        else:
            key = lambda c: (c.certificate_bytes, c.total_cost_ms())
        chosen = min(admissible, key=key)
        return PlanDecision(
            operator=operator,
            chosen_plan=chosen.name,
            admissible=True,
            reason="minimum-cost admissible plan",
            rejected=rejected,
            chosen_cost_bytes=chosen.certificate_bytes,
            chosen_total_ms=chosen.total_cost_ms(),
        )

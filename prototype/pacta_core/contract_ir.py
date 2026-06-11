"""Typed governed-query contract IR for Pacta.

This module is intentionally independent of the Merkle tree implementation.  It
turns the paper's supported SQL-style fragment into a canonical, hashable
contract object and exposes the verifier obligations that make a physical
evidence plan admissible.  The main artifact still contains a small SQL-template
front end, but every certificate is verified against this typed IR boundary.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
import re

JSON = Dict[str, Any]

SUPPORTED_OPS = {
    "range_groupby",
    "range_groupby_avg",
    "range_groupby_having_sum",
    "range_groupby_distinct_customer",
    "range_projection",
    "topk_score_threshold",
    "returned_pair_join_authenticity",
    "complete_fk_join_groupby",
    "complete_mm_join_groupby",
    "complete_antijoin_groupby",
    "open_scan_groupby_predicate",
}

RANGE_BOUND_OPS = {
    "range_groupby",
    "range_groupby_avg",
    "range_groupby_having_sum",
    "range_groupby_distinct_customer",
    "range_projection",
    "open_scan_groupby_predicate",
    "returned_pair_join_authenticity",
    "complete_fk_join_groupby",
    "complete_mm_join_groupby",
    "complete_antijoin_groupby",
}

BASE_OBLIGATIONS = (
    "request_binding",
    "owner_descriptor",
    "schema_binding",
    "manifest_policy_binding",
    "version_binding",
)

OP_OBLIGATIONS: Mapping[str, Tuple[str, ...]] = {
    "range_groupby": ("range_completeness", "aggregate_monoid"),
    "range_groupby_avg": ("range_completeness", "aggregate_monoid", "derived_avg_quotient"),
    "range_groupby_having_sum": ("range_completeness", "aggregate_monoid", "having_over_verified_state"),
    "range_groupby_distinct_customer": ("range_completeness", "opened_row_multiset", "duplicate_elimination"),
    "range_projection": ("range_completeness", "opened_row_multiset", "projection_mask"),
    "open_scan_groupby_predicate": ("range_completeness", "opened_row_multiset", "row_predicate_local_eval"),
    "topk_score_threshold": ("score_range_completeness", "cutoff_tie_completeness", "returned_tuple_membership"),
    "returned_pair_join_authenticity": ("returned_pair_membership", "dimension_predicate_binding", "join_predicate"),
    "complete_fk_join_groupby": ("fact_multiset", "dimension_presence", "dimension_predicate_binding", "join_predicate"),
    "complete_antijoin_groupby": ("fact_multiset", "dimension_absence", "dimension_predicate_binding", "join_predicate"),
    "complete_mm_join_groupby": ("fact_multiset", "dimension_multiset", "dimension_policy_binding", "join_predicate"),
}

EXPECTED_AGGREGATES: Mapping[str, Tuple[str, ...]] = {
    "range_groupby": ("count", "sum(amount)"),
    "range_groupby_avg": ("count", "sum(amount)", "avg(amount)"),
    "range_groupby_having_sum": ("count", "sum(amount)"),
    "range_groupby_distinct_customer": ("count(distinct cust_id)",),
    "open_scan_groupby_predicate": ("count", "sum(amount)"),
    "complete_fk_join_groupby": ("count", "sum(sales.amount)"),
    "complete_antijoin_groupby": ("count", "sum(sales.amount)"),
    "complete_mm_join_groupby": ("count", "sum(sales.amount)"),
}

@dataclass(frozen=True)
class GovernedContract:
    op: str
    subject: str
    purpose: str
    policy_hash: str
    lo: int | None = None
    hi: int | None = None
    group_by: str | None = None
    aggregates: Tuple[str, ...] = field(default_factory=tuple)
    projection: Tuple[str, ...] = field(default_factory=tuple)
    order: Tuple[str, ...] = field(default_factory=tuple)
    k: int | None = None
    score_ge: int | None = None
    segment: int | None = None
    row_predicate: Tuple[Any, ...] = field(default_factory=tuple)
    having: Tuple[Any, ...] = field(default_factory=tuple)
    join: str | None = None
    dimension_predicates: Tuple[str, ...] = field(default_factory=tuple)
    dimension_policy_hash: str | None = None
    evidence_plan: str | None = None

    def obligations(self) -> Tuple[str, ...]:
        validate_contract_ir_dict(self.to_dict())
        return tuple(dict.fromkeys(BASE_OBLIGATIONS + OP_OBLIGATIONS[self.op]))

    def to_dict(self) -> JSON:
        d = asdict(self)
        out: JSON = {}
        for k, v in d.items():
            if v is None or v == () or v == [] or v == {}:
                continue
            if isinstance(v, tuple):
                out[k] = list(v)
            else:
                out[k] = v
        return out


def _tuple(x: Any) -> Tuple[Any, ...]:
    if x is None:
        return ()
    if isinstance(x, tuple):
        return x
    if isinstance(x, list):
        return tuple(x)
    return (x,)




ALLOWED_FIELDS = frozenset(GovernedContract.__dataclass_fields__)


OP_ALLOWED_FIELDS: Mapping[str, frozenset[str]] = {
    "range_groupby": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "group_by", "aggregates"}),
    "range_groupby_avg": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "group_by", "aggregates"}),
    "range_groupby_having_sum": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "group_by", "aggregates", "having"}),
    "range_groupby_distinct_customer": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "group_by", "aggregates"}),
    "range_projection": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "projection"}),
    "open_scan_groupby_predicate": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "row_predicate", "group_by", "aggregates", "evidence_plan"}),
    "topk_score_threshold": frozenset({"op", "subject", "purpose", "policy_hash", "k", "score_ge", "order"}),
    "returned_pair_join_authenticity": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "segment", "join", "dimension_predicates"}),
    "complete_fk_join_groupby": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "join", "group_by", "aggregates", "dimension_predicates"}),
    "complete_antijoin_groupby": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "join", "group_by", "aggregates", "dimension_predicates"}),
    "complete_mm_join_groupby": frozenset({"op", "subject", "purpose", "policy_hash", "lo", "hi", "join", "group_by", "aggregates", "dimension_policy_hash"}),
}


def _reject_operator_field_smuggling(contract: Mapping[str, Any], op: str) -> None:
    """Reject known-but-incompatible request fields for an operator.

    Unknown fields are already refused before normalization.  This guard closes
    a more subtle class of mistakes: a field can be part of the global IR
    vocabulary, enter the request digest, and still be meaningless for the
    selected operator.  For example, a row predicate attached to a compact
    range-group-by contract would be hashed but not discharged by the compact
    summary verifier.  Such operator-field smuggling must fail closed.
    """
    allowed = OP_ALLOWED_FIELDS.get(op)
    if allowed is None:
        raise ValueError(f"unsupported governed contract op: {op}")
    present = {k for k, v in contract.items() if not (v is None or v == () or v == [] or v == {})}
    bad = sorted(present - allowed)
    if bad:
        raise ValueError(f"contract field(s) not valid for {op}: {bad}")


def _required_text(contract: Mapping[str, Any], field: str) -> str:
    """Return a required textual field after rejecting None-like values.

    Converting missing values with str(value) is dangerous for a request-bound
    verifier: None would become the literal string "None" and could pass a
    truthiness check.  Required client-visible fields are therefore validated
    before canonicalization.
    """
    value = contract.get(field)
    if not isinstance(value, str):
        raise ValueError(f"contract missing {field}")
    text = value.strip()
    if not text or text.lower() in {"none", "null"}:
        raise ValueError(f"contract missing {field}")
    return text


def _strict_int(value: Any, field: str) -> int:
    """Canonicalize a request-visible integer without truncation.

    Contract digests must not silently turn ``True`` into 1 or 1.9 into 1.
    JSON integers and decimal strings are accepted; booleans, floats, blanks,
    and other values fail closed.
    """
    if isinstance(value, bool):
        raise ValueError(f"contract field {field} must be an integer, not boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if re.fullmatch(r"-?\d+", text):
            return int(text)
    raise ValueError(f"contract field {field} must be an integer")


def _optional_int(contract: Mapping[str, Any], field: str) -> int | None:
    if field not in contract:
        return None
    return _strict_int(contract[field], field)


def _canonical_row_predicate(value: Any) -> Tuple[Any, ...]:
    pred = _tuple(value)
    if not pred:
        return ()
    if len(pred) == 3:
        return (str(pred[0]), str(pred[1]), _strict_int(pred[2], "row_predicate threshold"))
    return pred


def _canonical_having(value: Any) -> Mapping[str, Any] | Tuple[Any, ...]:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        out = {str(k): value[k] for k in sorted(value)}
        if set(out.keys()) == {"sum(amount)"}:
            hv = out["sum(amount)"]
            if isinstance(hv, (list, tuple)) and len(hv) == 2:
                out["sum(amount)"] = [str(hv[0]), _strict_int(hv[1], "HAVING sum(amount) threshold")]
        return out
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def normalize_contract(contract: Mapping[str, Any]) -> JSON:
    """Return a canonical JSON contract with stable list ordering and no noise.

    Normalization closes a subtle implementation hole: two syntactically
    different but semantically equal Python dictionaries should hash to the same
    client request only after all fields have been typed and ordered.  The
    function therefore rejects unknown request-visible fields, sorts dimension
    predicates, converts tuples to lists, checks numeric bounds without
    truncation, and removes absent optional fields.
    """
    extra = sorted(set(contract.keys()) - ALLOWED_FIELDS)
    if extra:
        raise ValueError(f"unsupported contract field(s): {extra}")
    canonical_having = _canonical_having(contract.get("having", ()))
    gc = GovernedContract(
        op=_required_text(contract, "op"),
        subject=_required_text(contract, "subject"),
        purpose=_required_text(contract, "purpose"),
        policy_hash=_required_text(contract, "policy_hash"),
        lo=_optional_int(contract, "lo"),
        hi=_optional_int(contract, "hi"),
        group_by=contract.get("group_by"),
        aggregates=tuple(str(x) for x in _tuple(contract.get("aggregates"))),
        projection=tuple(str(x) for x in _tuple(contract.get("projection"))),
        order=tuple(str(x) for x in _tuple(contract.get("order"))),
        k=_optional_int(contract, "k"),
        score_ge=_optional_int(contract, "score_ge"),
        segment=_optional_int(contract, "segment"),
        row_predicate=_canonical_row_predicate(contract.get("row_predicate", ())),
        having=tuple(canonical_having.items()) if isinstance(canonical_having, Mapping) else tuple(canonical_having),
        join=contract.get("join"),
        dimension_predicates=tuple(sorted(str(x) for x in _tuple(contract.get("dimension_predicates")))),
        dimension_policy_hash=contract.get("dimension_policy_hash"),
        evidence_plan=contract.get("evidence_plan"),
    )
    out = gc.to_dict()
    if out.get("op") in EXPECTED_AGGREGATES and "aggregates" in out:
        supplied = tuple(str(x) for x in out.get("aggregates", []))
        expected = EXPECTED_AGGREGATES[str(out["op"])]
        if len(supplied) == len(expected) and set(supplied) == set(expected):
            out["aggregates"] = list(expected)
    # Preserve HAVING as a canonical JSON object because the legacy certificate
    # generator already uses this representation.  Extra unsupported predicates
    # are rejected by validation below.
    if isinstance(contract.get("having"), Mapping):
        out["having"] = dict(_canonical_having(contract.get("having")))
    validate_contract_ir_dict(out)
    return out

def validate_contract_ir_dict(contract: Mapping[str, Any]) -> None:
    op = str(contract.get("op", ""))
    if op not in SUPPORTED_OPS:
        raise ValueError(f"unsupported governed contract op: {op}")
    _reject_operator_field_smuggling(contract, op)
    for f in ("subject", "purpose", "policy_hash"):
        value = contract.get(f)
        if not isinstance(value, str) or not value.strip() or value.strip().lower() in {"none", "null"}:
            raise ValueError(f"contract missing {f}")
    if op in RANGE_BOUND_OPS:
        if "lo" not in contract or "hi" not in contract:
            raise ValueError("range-like contract must bind lo and hi")
        if _strict_int(contract["lo"], "lo") > _strict_int(contract["hi"], "hi"):
            raise ValueError("invalid range interval")
    elif "lo" in contract and "hi" in contract and _strict_int(contract["lo"], "lo") > _strict_int(contract["hi"], "hi"):
        raise ValueError("invalid range interval")
    if op in EXPECTED_AGGREGATES and tuple(contract.get("aggregates", [])) != EXPECTED_AGGREGATES[op]:
        raise ValueError("aggregate contract mismatch")
    if op in {"range_groupby", "range_groupby_avg", "range_groupby_having_sum", "range_groupby_distinct_customer", "open_scan_groupby_predicate"}:
        if contract.get("group_by") != "category":
            raise ValueError("unsupported grouping key")
    if op == "range_groupby_having_sum":
        hv = contract.get("having")
        if not isinstance(hv, Mapping) or set(hv.keys()) != {"sum(amount)"}:
            raise ValueError("unsupported HAVING predicate")
        having = hv.get("sum(amount)")
        if not (isinstance(having, list) and len(having) == 2 and having[0] == ">="):
            raise ValueError("unsupported HAVING predicate")
        _strict_int(having[1], "HAVING sum(amount) threshold")
    if op == "topk_score_threshold":
        if "k" not in contract or _strict_int(contract["k"], "k") <= 0:
            raise ValueError("top-k contract requires k > 0")
        if "score_ge" not in contract:
            raise ValueError("top-k contract must bind lower score threshold")
        _strict_int(contract["score_ge"], "score_ge")
        if tuple(contract.get("order", [])) != ("score desc", "id asc"):
            raise ValueError("top-k contract must bind deterministic order")
    if op == "open_scan_groupby_predicate":
        pred = contract.get("row_predicate")
        if not (isinstance(pred, list) and len(pred) == 3 and pred[0] == "amount" and pred[1] == ">="):
            raise ValueError("unsupported open-scan row predicate")
        _strict_int(pred[2], "row_predicate threshold")
        if contract.get("evidence_plan") != "complete_open_range_scan":
            raise ValueError("open scan must declare complete_open_range_scan")
    if op == "range_projection" and tuple(contract.get("projection", [])) != ("id", "category", "amount"):
        raise ValueError("projection contract must bind released attributes")
    if op == "returned_pair_join_authenticity":
        expected = ("customers.active=1", "customers.tenant=sales.tenant")
        if contract.get("join") != "sales.cust_id=customers.cust_id" or tuple(sorted(contract.get("dimension_predicates", []))) != expected:
            raise ValueError("returned-pair join contract mismatch")
        if "segment" not in contract:
            raise ValueError("returned-pair join must bind segment")
        _strict_int(contract["segment"], "segment")
    if op == "complete_fk_join_groupby":
        expected = ("customers.active=1", "customers.tenant=sales.tenant")
        if contract.get("join") != "sales.cust_id=customers.cust_id" or contract.get("group_by") != "customers.segment":
            raise ValueError("complete FK join contract mismatch")
        if tuple(sorted(contract.get("dimension_predicates", []))) != expected:
            raise ValueError("complete FK join dimension predicate mismatch")
    if op == "complete_antijoin_groupby":
        expected = ("customers.active=1", "customers.tenant=sales.tenant")
        if contract.get("join") != "NOT EXISTS customers.cust_id=sales.cust_id" or contract.get("group_by") != "sales.category":
            raise ValueError("complete anti-join contract mismatch")
        if tuple(sorted(contract.get("dimension_predicates", []))) != expected:
            raise ValueError("complete anti-join dimension predicate mismatch")
    if op == "complete_mm_join_groupby":
        if contract.get("join") != "sales.category=category_tags.category" or contract.get("group_by") != "category_tags.tag":
            raise ValueError("complete many-to-many join contract mismatch")
        if not isinstance(contract.get("dimension_policy_hash"), str) or not str(contract.get("dimension_policy_hash")).strip():
            raise ValueError("complete many-to-many join must bind tag-side policy")


def contract_obligations(contract: Mapping[str, Any]) -> Tuple[str, ...]:
    norm = normalize_contract(contract)
    return tuple(dict.fromkeys(BASE_OBLIGATIONS + OP_OBLIGATIONS[str(norm["op"])]))

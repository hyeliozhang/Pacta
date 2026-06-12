#!/usr/bin/env python3
"""Pacta: policy-governed authenticated analytical query certificates.

The prototype is self-contained and CPU-only.  It implements the data-system
mechanisms used by the paper:
  * synthetic governed fact/dimension workloads;
  * a fanout Merkle aggregate tree with policy-aware summaries;
  * range/group-by certificates and a client verifier;
  * verified tuple-membership proofs, threshold top-k certificates, returned-pair
    join-authenticity certificates, and complete foreign-key join fallbacks;
  * sound tuple+frontier and weaker negative-control baselines;
  * incremental non-key updates, stale-root/policy/omission/tampering tests;
  * reproducible experiment CSVs and sample certificates.

This is a research artifact, not production cryptographic software.
"""
from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import json
import math
import os
import random
import re
import sqlite3
import statistics
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from pacta_core.optimizer import CertifyingEvidencePlanner, PlanCandidate
except Exception:  # keep the standalone artifact runnable if package path is altered
    CertifyingEvidencePlanner = None  # type: ignore
    PlanCandidate = None  # type: ignore
try:
    from pacta_core.contract_ir import normalize_contract as _normalize_contract_ir, contract_obligations as _contract_obligations
except Exception:
    _normalize_contract_ir = None  # type: ignore
    _contract_obligations = None  # type: ignore

JSON = Dict[str, Any]
_TABLE_BYTES_CACHE: Dict[Tuple[int, int], int] = {}
_TABLE_STATS_CACHE: Dict[Tuple[int, int], Tuple[int, str]] = {}


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(tag: str, obj: Any) -> str:
    return hashlib.sha256((tag + "|" + canonical(obj)).encode("utf-8")).hexdigest()


def sizeof_json(obj: Any) -> int:
    return len(canonical(obj).encode("utf-8"))


def table_material_stats(rows: Sequence[JSON]) -> Tuple[int, str]:
    """Return serialized table bytes and digest, cached per generated relation."""
    key = (id(rows), len(rows))
    cached = _TABLE_STATS_CACHE.get(key)
    if cached is not None:
        return cached
    text = canonical(list(rows))
    b = text.encode("utf-8")
    h = hashlib.sha256(("full_table_hash_baseline|" + text).encode("utf-8")).hexdigest()
    cached = (len(b), h)
    _TABLE_STATS_CACHE[key] = cached
    _TABLE_BYTES_CACHE[key] = len(b)
    return cached


JOIN_SEMANTIC_EXTRA_INTS = ("active", "segment", "tag")


def schema_descriptor(key_attr: str, typed_extra_int: Sequence[str] = ()) -> JSON:
    """Logical schema committed by the owner descriptor.

    The verifier is not checking an untyped JSON blob: accepted relations obey
    bag semantics over unique row ids and NOT NULL integer attributes used by
    predicates, grouping, ordering, joins, and summaries.  Binding the schema
    in the relation descriptor closes a reviewer-visible gap where a server
    could otherwise reinterpret an attribute or silently introduce NULL-like
    values that are outside the verifier's aggregate semantics.  Dimension
    relations can additionally declare typed verifier attributes such as
    ``active``, ``segment``, and ``tag``; these fields are then committed as
    NOT NULL JSON integers rather than interpreted later through ad hoc
    Python coercions.
    """
    attrs = ["id", "tenant", "region", "category", "day", "amount", "score", "sensitivity", "cust_id"]
    extras = sorted(dict.fromkeys(str(a) for a in typed_extra_int if str(a) in JOIN_SEMANTIC_EXTRA_INTS))
    return {
        "schema_version": 3,
        "primary_key": "id",
        "key_attr": key_attr,
        "not_null_int": attrs,
        "typed_extra_int": extras,
        "bag_semantics": "duplicate analytical values allowed; primary keys unique",
        "aggregate_null_policy": "SQL NOT NULL inputs; COUNT/SUM/AVG over committed integer amount",
        "dimension_null_policy": "Declared join/filter/group dimension attributes are SQL NOT NULL JSON integers",
    }


def infer_typed_extra_int(rows: Sequence[JSON]) -> Tuple[str, ...]:
    """Infer dimension attributes that must be typed by the descriptor.

    Pacta uses sales-like encodings for dimension trees.  The base fields are
    always typed, but join semantics also depend on extra dimension attributes:
    ``segment`` and ``active`` for customer dimensions, and ``tag`` for category
    expansion dimensions.  If any committed row contains one of these fields,
    every row in the relation must contain it as a JSON integer and the relation
    descriptor commits to that requirement.
    """
    present = []
    for attr in JOIN_SEMANTIC_EXTRA_INTS:
        if any(attr in r for r in rows):
            present.append(attr)
    return tuple(present)


def _json_integral(value: Any, name: str, *, allow_decimal_string: bool = True) -> int:
    """Parse verifier-visible JSON integers without accepting lossy coercions.

    This helper is intentionally stricter than Python ``int``.  Version labels,
    row attributes, descriptor bounds, and manifest validity intervals are part
    of Pacta's authenticated semantics; accepting booleans or truncating floats
    would let a malformed certificate be interpreted differently by different
    clients.  Decimal strings are accepted only for configuration/CSV
    portability when explicitly allowed.
    """
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer, not boolean")
    if isinstance(value, int):
        return value
    if allow_decimal_string and isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value.strip())
    raise ValueError(f"{name} must be an integer")




def _cert_integral(value: Any, name: str) -> int:
    """Parse certificate-structural integers without lossy JSON coercion.

    Certificate metadata (node bounds, counts, path indices, result counts, and
    committed row fields that participate in a verifier calculation) must be
    literal JSON integers.  Accepting booleans or floats here would not usually
    break a hash comparison, but it creates ambiguous evidence encodings that
    different clients could interpret differently.
    """
    return _json_integral(value, name, allow_decimal_string=False)

def validate_row_schema(row: JSON, key_attr: str, typed_extra_int: Sequence[str] = ()) -> None:
    required = schema_descriptor(key_attr, typed_extra_int)["not_null_int"]
    for a in required:
        if a not in row or row[a] is None:
            raise ValueError(f"row violates committed NOT NULL schema: {a}")
        _json_integral(row[a], f"row.{a}", allow_decimal_string=False)
    for a in typed_extra_int:
        if a not in row or row[a] is None:
            raise ValueError(f"row violates committed dimension NOT NULL schema: {a}")
        _json_integral(row[a], f"row.{a}", allow_decimal_string=False)
    if key_attr not in row:
        raise ValueError(f"key attribute missing from row: {key_attr}")


@dataclass(frozen=True)
class Policy:
    tenant: int
    max_sensitivity: int
    regions: Tuple[int, ...]
    purpose: str = "audit"
    projection: Tuple[str, ...] = ("category", "count", "sum_amount")

    def allows(self, row: JSON) -> bool:
        return (
            int(row["tenant"]) == self.tenant
            and int(row["sensitivity"]) <= self.max_sensitivity
            and int(row["region"]) in self.regions
        )

    def to_dict(self) -> JSON:
        return {
            "tenant": self.tenant,
            "max_sensitivity": self.max_sensitivity,
            "regions": list(self.regions),
            "purpose": self.purpose,
            "projection": list(self.projection),
        }

    @staticmethod
    def from_dict(d: JSON) -> "Policy":
        return Policy(
            tenant=_json_integral(d["tenant"], "policy.tenant"),
            max_sensitivity=_json_integral(d["max_sensitivity"], "policy.max_sensitivity"),
            regions=tuple(_json_integral(x, "policy.region") for x in d["regions"]),
            purpose=d.get("purpose", "audit"),
            projection=tuple(d.get("projection", ["category", "count", "sum_amount"])),
        )




class UnsupportedQueryError(ValueError):
    """Raised when a visible SQL query is outside the certifiable fragment.

    The prototype intentionally fails closed: it never silently maps an
    unsupported SQL feature to a weaker certificate.  This is the executable
    counterpart of the paper's operator-extension checklist.
    """


def _sql_param_int(params: Sequence[Any], idx: int, name: str) -> int:
    """Read a SQL template parameter as a request-visible integer.

    The compiler rejects booleans, floats, blanks, and missing parameters instead
    of relying on Python's truncating ``int`` conversion.  The normalized IR will
    check the same invariant again before hashing the request.
    """
    try:
        value = params[idx]
    except IndexError as exc:
        raise UnsupportedQueryError(f"missing SQL parameter {name}") from exc
    if isinstance(value, bool):
        raise UnsupportedQueryError(f"SQL parameter {name} must be an integer, not boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value.strip())
    raise UnsupportedQueryError(f"SQL parameter {name} must be an integer")


SUPPORTED_CONTRACT_OPS = {
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


def contract_digest(contract: JSON) -> str:
    """Digest of the typed client-visible governed query contract.

    The digest is computed after canonical IR normalization, so equivalent
    Python dictionary ordering does not affect the client request and every
    accepted certificate is bound to the same typed operator obligations.
    """
    if _normalize_contract_ir is not None:
        contract = _normalize_contract_ir(contract)  # type: ignore[assignment]
    validate_contract(contract)
    return digest("pacta_query_contract_v1", contract)


def verify_request_binding(cert: JSON, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
    """Verify that a certificate is bound to the client-visible request.

    Client verification is strict by default: the caller must pass the request
    contract that was actually issued.  A self-contained mode exists only for
    negative-control experiments that demonstrate the request-substitution
    vulnerability of legacy APIs.
    """
    try:
        q = cert["query"]
        if contract_digest(q) != cert.get("request_digest"):
            return False
        if expected_contract is None:
            return bool(allow_self_certified)
        if contract_digest(expected_contract) != cert.get("request_digest"):
            return False
        return True
    except Exception:
        return False



def _normalize_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", sql.strip().lower())


def compile_sql_contract(sql: str, params: Sequence[Any], manifest: JSON, subject: str, purpose: str) -> JSON:
    """Compile a small certifiable SQL fragment into a governed contract.

    Supported templates are deliberately narrow but concrete: range group-by
    count/sum/derived average/HAVING, exact COUNT(DISTINCT) over opened
    multisets, range projection, score top-k threshold, and complete FK/anti-/
    many-to-many join contracts. Unsupported features raise
    ``UnsupportedQueryError`` before any proof is generated.
    """
    norm = _normalize_sql(sql)
    policy = compile_policy(manifest, subject, purpose)
    policy_hash = digest("compiled_policy", policy.to_dict())

    groupby_pat = (
        r"^select category, count\(\*\), sum\(amount\) from sales "
        r"where day between \? and \? group by category$"
    )
    if re.match(groupby_pat, norm):
        if len(params) != 2:
            raise UnsupportedQueryError("range group-by requires lo/hi parameters")
        return {
            "op": "range_groupby",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "group_by": "category",
            "aggregates": ["count", "sum(amount)"],
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    avg_pat = (
        r"^select category, count\(\*\), sum\(amount\), avg\(amount\) from sales "
        r"where day between \? and \? group by category$"
    )
    if re.match(avg_pat, norm):
        if len(params) != 2:
            raise UnsupportedQueryError("range group-by AVG requires lo/hi parameters")
        return {
            "op": "range_groupby_avg",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "group_by": "category",
            "aggregates": ["count", "sum(amount)", "avg(amount)"],
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    having_pat = (
        r"^select category, count\(\*\), sum\(amount\) from sales "
        r"where day between \? and \? group by category having sum\(amount\) >= \?$"
    )
    if re.match(having_pat, norm):
        if len(params) != 3:
            raise UnsupportedQueryError("range group-by HAVING requires lo/hi/threshold parameters")
        return {
            "op": "range_groupby_having_sum",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "group_by": "category",
            "aggregates": ["count", "sum(amount)"],
            "having": {"sum(amount)": [">=", _sql_param_int(params, 2, "having_threshold")]},
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    distinct_pat = (
        r"^select category, count\(distinct cust_id\) from sales "
        r"where day between \? and \? group by category$"
    )
    if re.match(distinct_pat, norm):
        if len(params) != 2:
            raise UnsupportedQueryError("range COUNT(DISTINCT cust_id) requires lo/hi parameters")
        return {
            "op": "range_groupby_distinct_customer",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "group_by": "category",
            "aggregates": ["count(distinct cust_id)"],
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    projection_pat = r"^select id, category, amount from sales where day between \? and \?$"
    if re.match(projection_pat, norm):
        if len(params) != 2:
            raise UnsupportedQueryError("range projection requires lo/hi parameters")
        return {
            "op": "range_projection",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "projection": ["id", "category", "amount"],
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    open_scan_pred_pat = (
        r"^select category, count\(\*\), sum\(amount\) from sales "
        r"where day between \? and \? and amount >= \? group by category$"
    )
    if re.match(open_scan_pred_pat, norm):
        if len(params) != 3:
            raise UnsupportedQueryError("open-scan predicate fallback requires lo/hi/min_amount parameters")
        return {
            "op": "open_scan_groupby_predicate",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "row_predicate": ["amount", ">=", _sql_param_int(params, 2, "amount_threshold")],
            "group_by": "category",
            "aggregates": ["count", "sum(amount)"],
            "evidence_plan": "complete_open_range_scan",
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    topk_pat = r"^select id, score from sales where score >= \? order by score desc, id asc limit \?$"
    if re.match(topk_pat, norm):
        if len(params) != 2:
            raise UnsupportedQueryError("top-k requires threshold/k parameters")
        return {
            "op": "topk_score_threshold",
            "score_ge": _sql_param_int(params, 0, "score_ge"),
            "k": _sql_param_int(params, 1, "k"),
            "order": ["score desc", "id asc"],
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    join_pat = (
        r"^select s\.id, c\.cust_id from sales s join customers c on s\.cust_id = c\.cust_id "
        r"where s\.day between \? and \? and c\.segment = \? and c\.active = 1$"
    )
    if re.match(join_pat, norm):
        if len(params) != 3:
            raise UnsupportedQueryError("returned-pair join requires lo/hi/segment parameters")
        return {
            "op": "returned_pair_join_authenticity",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "segment": _sql_param_int(params, 2, "segment"),
            "join": "sales.cust_id=customers.cust_id",
            "dimension_predicates": ["customers.active=1", "customers.tenant=sales.tenant"],
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    complete_join_pat = (
        r"^select c\.segment, count\(\*\), sum\(s\.amount\) from sales s "
        r"join customers c on s\.cust_id = c\.cust_id "
        r"where s\.day between \? and \? and c\.active = 1 group by c\.segment$"
    )
    if re.match(complete_join_pat, norm):
        if len(params) != 2:
            raise UnsupportedQueryError("complete FK join group-by requires lo/hi parameters")
        return {
            "op": "complete_fk_join_groupby",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "join": "sales.cust_id=customers.cust_id",
            "dimension_predicates": ["customers.active=1", "customers.tenant=sales.tenant"],
            "group_by": "customers.segment",
            "aggregates": ["count", "sum(sales.amount)"],
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    antijoin_pat = (
        r"^select s\.category, count\(\*\), sum\(s\.amount\) from sales s "
        r"where s\.day between \? and \? and not exists "
        r"\(select 1 from customers c where c\.cust_id = s\.cust_id and c\.tenant = s\.tenant and c\.active = 1\) "
        r"group by s\.category$"
    )
    if re.match(antijoin_pat, norm):
        if len(params) != 2:
            raise UnsupportedQueryError("complete anti-join group-by requires lo/hi parameters")
        return {
            "op": "complete_antijoin_groupby",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "join": "NOT EXISTS customers.cust_id=sales.cust_id",
            "dimension_predicates": ["customers.active=1", "customers.tenant=sales.tenant"],
            "group_by": "sales.category",
            "aggregates": ["count", "sum(sales.amount)"],
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    mm_join_pat = (
        r"^select t\.tag, count\(\*\), sum\(s\.amount\) from sales s "
        r"join category_tags t on s\.category = t\.category "
        r"where s\.day between \? and \? group by t\.tag$"
    )
    if re.match(mm_join_pat, norm):
        if len(params) != 2:
            raise UnsupportedQueryError("complete many-to-many join group-by requires lo/hi parameters")
        return {
            "op": "complete_mm_join_groupby",
            "lo": _sql_param_int(params, 0, "lo"),
            "hi": _sql_param_int(params, 1, "hi"),
            "join": "sales.category=category_tags.category",
            "dimension_policy_hash": digest("compiled_policy", all_tags_policy().to_dict()),
            "group_by": "category_tags.tag",
            "aggregates": ["count", "sum(sales.amount)"],
            "subject": subject,
            "purpose": purpose,
            "policy_hash": policy_hash,
        }

    raise UnsupportedQueryError("query is outside the certifiable SQL fragment")


def validate_contract(contract: JSON) -> None:
    op = contract.get("op")
    if op not in SUPPORTED_CONTRACT_OPS:
        raise UnsupportedQueryError(f"unsupported contract operator: {op}")
    for required in ("subject", "purpose", "policy_hash"):
        if not contract.get(required):
            raise UnsupportedQueryError(f"contract is missing {required}")
    if op in {"range_groupby", "range_groupby_avg", "range_groupby_having_sum", "range_groupby_distinct_customer", "range_projection", "open_scan_groupby_predicate", "returned_pair_join_authenticity", "complete_fk_join_groupby", "complete_mm_join_groupby", "complete_antijoin_groupby"}:
        if "lo" not in contract or "hi" not in contract:
            raise UnsupportedQueryError("range-like contract must bind lo and hi")
        lo = _sql_param_int([contract["lo"]], 0, "lo")
        hi = _sql_param_int([contract["hi"]], 0, "hi")
        if lo > hi:
            raise UnsupportedQueryError("invalid key interval")
    if op in {"range_groupby", "range_groupby_avg", "range_groupby_having_sum"}:
        if contract.get("group_by") != "category" or not isinstance(contract.get("aggregates"), list):
            raise UnsupportedQueryError("invalid group-by contract")
    if op == "range_groupby_distinct_customer":
        if contract.get("group_by") != "category" or contract.get("aggregates") != ["count(distinct cust_id)"]:
            raise UnsupportedQueryError("invalid DISTINCT contract")
    if op == "range_projection":
        if tuple(contract.get("projection", [])) != ("id", "category", "amount"):
            raise UnsupportedQueryError("invalid projection contract")
    if op == "open_scan_groupby_predicate":
        if contract.get("group_by") != "category" or contract.get("aggregates") != ["count", "sum(amount)"]:
            raise UnsupportedQueryError("invalid open-scan group-by contract")
        pred = contract.get("row_predicate")
        if not (isinstance(pred, list) and len(pred) == 3 and pred[0] == "amount" and pred[1] == ">="):
            raise UnsupportedQueryError("unsupported open-scan row predicate")
        _sql_param_int([pred[2]], 0, "amount_threshold")
        if contract.get("evidence_plan") != "complete_open_range_scan":
            raise UnsupportedQueryError("open-scan contract must declare its evidence plan")
    if op == "range_groupby_having_sum":
        having = contract.get("having", {}).get("sum(amount)")
        if not (isinstance(having, list) and len(having) == 2 and having[0] == ">="):
            raise UnsupportedQueryError("unsupported HAVING predicate")
        _sql_param_int([having[1]], 0, "having_threshold")
    if op == "topk_score_threshold":
        if "k" not in contract:
            raise UnsupportedQueryError("top-k requires positive k")
        if _sql_param_int([contract["k"]], 0, "k") <= 0:
            raise UnsupportedQueryError("top-k requires positive k")
        if contract.get("order") != ["score desc", "id asc"]:
            raise UnsupportedQueryError("invalid top-k order")
        if "score_ge" not in contract:
            raise UnsupportedQueryError("top-k must bind lower score threshold")
        _sql_param_int([contract["score_ge"]], 0, "score_ge")
        if "score_hi" in contract and _sql_param_int([contract["score_ge"]], 0, "score_ge") > _sql_param_int([contract["score_hi"]], 0, "score_hi"):
            raise UnsupportedQueryError("invalid top-k score interval")
    if op == "returned_pair_join_authenticity":
        expected_dim = ["customers.active=1", "customers.tenant=sales.tenant"]
        if contract.get("join") != "sales.cust_id=customers.cust_id" or sorted(contract.get("dimension_predicates", [])) != sorted(expected_dim):
            raise UnsupportedQueryError("invalid returned-pair join contract")
        if "segment" not in contract:
            raise UnsupportedQueryError("returned-pair join contract must bind the segment predicate")
        _sql_param_int([contract["segment"]], 0, "segment")
    if op == "complete_fk_join_groupby":
        expected_dim = ["customers.active=1", "customers.tenant=sales.tenant"]
        if contract.get("join") != "sales.cust_id=customers.cust_id" or contract.get("group_by") != "customers.segment":
            raise UnsupportedQueryError("invalid FK join contract")
        if sorted(contract.get("dimension_predicates", [])) != sorted(expected_dim):
            raise UnsupportedQueryError("FK join contract must bind exactly the dimension filter")
    if op == "complete_antijoin_groupby":
        expected_dim = ["customers.active=1", "customers.tenant=sales.tenant"]
        if contract.get("join") != "NOT EXISTS customers.cust_id=sales.cust_id" or contract.get("group_by") != "sales.category":
            raise UnsupportedQueryError("invalid anti-join contract")
        if sorted(contract.get("dimension_predicates", [])) != sorted(expected_dim):
            raise UnsupportedQueryError("anti-join contract must bind exactly the dimension filter")

    if op == "complete_mm_join_groupby":
        if contract.get("join") != "sales.category=category_tags.category" or contract.get("group_by") != "category_tags.tag":
            raise UnsupportedQueryError("invalid many-to-many join contract")
        if contract.get("dimension_policy_hash") != digest("compiled_policy", all_tags_policy().to_dict()):
            raise UnsupportedQueryError("many-to-many join contract must bind the tag-side policy")
    if _contract_obligations is not None:
        # Exercise the independent IR checker; it raises on incomplete evidence contracts.
        _contract_obligations(contract)


def make_policy(tenant: int, complexity: int, *, n_regions: int = 5) -> Policy:
    complexity = max(1, min(complexity, n_regions))
    regions = tuple(range(complexity))
    max_s = 1 if complexity <= 2 else 2
    return Policy(tenant=tenant, max_sensitivity=max_s, regions=regions, purpose=f"audit-c{complexity}")


def make_manifest(policy: Policy, *, subject: Optional[str] = None, version: int = 1) -> JSON:
    subject = subject or f"tenant-{policy.tenant}"
    return {
        "version": version,
        "policies": [
            {
                "policy_id": f"p-{subject}-{policy.purpose}",
                "subject": subject,
                "purpose": policy.purpose,
                "valid_from": 0,
                "valid_to": 2**31 - 1,
                "predicate": policy.to_dict(),
                "projection": list(policy.projection),
            }
        ],
    }


def manifest_root(manifest: JSON) -> str:
    return digest("policy_manifest", manifest)


def compile_policy(manifest: JSON, subject: str, purpose: str) -> Policy:
    version = _json_integral(manifest.get("version", -1), "manifest.version")
    matches = []
    for p in manifest.get("policies", []):
        if p.get("subject") != subject or p.get("purpose") != purpose:
            continue
        valid_from = _json_integral(p.get("valid_from", -10**18), "policy.valid_from")
        valid_to = _json_integral(p.get("valid_to", 10**18), "policy.valid_to")
        if valid_from <= version <= valid_to:
            matches.append(p)
    if len(matches) != 1:
        raise ValueError("policy lookup is ambiguous, missing, or outside its validity interval")
    return Policy.from_dict(matches[0]["predicate"])


def relation_descriptor_digest(descriptor: JSON) -> str:
    return digest("relation_descriptor", descriptor)


def owner_digest(relation_root_or_descriptor: Any, manifest: JSON, version: Optional[int] = None) -> JSON:
    """Owner-signed digest material used by the verifier.

    The descriptor binds not only the root hash, but also the authenticated key
    domain, fanout, and relation version. The digest also binds the exact
    manifest root. The published digest version is a release epoch (defaulting
    to the manifest version), while the relation descriptor carries its own
    relation version inside the descriptor digest. This allows data and policy
    versions to evolve independently without letting a server recombine a stale
    root, stale manifest, or tampered version label.
    """
    if version is None:
        version = _json_integral(manifest.get("version", 1), "manifest.version")
    manifest_release_version = _json_integral(manifest.get("version", version), "manifest.version")
    if isinstance(relation_root_or_descriptor, dict):
        desc = relation_root_or_descriptor
        root = desc["root"]
        relation_version = _json_integral(desc.get("version", version), "relation.version")
        desc_digest = relation_descriptor_digest(desc)
    else:
        root = str(relation_root_or_descriptor)
        desc = {"root": root}
        relation_version = _json_integral(version, "relation.version")
        desc_digest = relation_descriptor_digest(desc)
    return {
        "relation_root": root,
        "relation_descriptor_digest": desc_digest,
        "manifest_root": manifest_root(manifest),
        "relation_version": relation_version,
        "manifest_release_version": manifest_release_version,
        "version": manifest_release_version,
    }


def verify_owner_digest(d: JSON, relation_root_or_descriptor: Any, manifest: JSON) -> bool:
    try:
        if isinstance(relation_root_or_descriptor, dict):
            desc = relation_root_or_descriptor
            root = desc["root"]
            desc_digest = relation_descriptor_digest(desc)
        else:
            root = str(relation_root_or_descriptor)
            desc_digest = relation_descriptor_digest({"root": root})
        manifest_version = _json_integral(manifest.get("version", -2), "manifest.version")
        relation_version = _json_integral(desc.get("version", d.get("relation_version", -3)), "relation.version")
        owner_manifest_version = _json_integral(d.get("manifest_release_version", d.get("version", -1)), "owner.manifest_release_version")
        owner_relation_version = _json_integral(d.get("relation_version", relation_version), "owner.relation_version")
        legacy_version = _json_integral(d.get("version", owner_manifest_version), "owner.version")
        return (
            d.get("relation_root") == root
            and d.get("relation_descriptor_digest") == desc_digest
            and d.get("manifest_root") == manifest_root(manifest)
            and owner_manifest_version == manifest_version
            and legacy_version == manifest_version
            and owner_relation_version == relation_version
        )
    except Exception:
        return False


WORKLOAD_PROFILES = [
    "dashboard_sales",
    "tpch_lineitem_like",
    "open_data_permits",
    "health_release",
    "finance_audit",
]


def _zipf_choice(rng: random.Random, m: int, skew: float) -> int:
    weights = [1.0 / ((i + 1) ** skew) for i in range(m)]
    total = sum(weights)
    x = rng.random() * total
    acc = 0.0
    for i, w in enumerate(weights):
        acc += w
        if x <= acc:
            return i
    return m - 1


def generate_sales(
    n: int,
    seed: int = 0,
    tenants: int = 6,
    regions: int = 5,
    categories: int = 6,
    profile: str = "dashboard_sales",
) -> List[JSON]:
    """Generate governed analytical relations under several benchmark-style profiles.

    The default profile preserves the original sales-dashboard workload. Other
    profiles encode standard data-engineering stressors: TPC-H-like lineitem
    skew, open-data release regions, health-release sensitivity skew, and
    finance-audit heavy tails. They are synthetic and deterministic, but their
    different distributions are used to test whether the certificate contract
    overfits one toy workload.
    """
    if profile not in WORKLOAD_PROFILES:
        raise ValueError(f"unknown workload profile: {profile}")
    rng = random.Random(seed)
    rows: List[JSON] = []
    for i in range(n):
        if profile == "dashboard_sales":
            tenant = rng.randrange(tenants)
            region = rng.randrange(regions)
            category = rng.randrange(categories)
            day = rng.randrange(1000)
            base = 10 + category * 7 + region * 3
            amount = int(base + rng.expovariate(1 / 65.0))
            sensitivity = 0 if rng.random() < 0.58 else (1 if rng.random() < 0.75 else 2)
        elif profile == "tpch_lineitem_like":
            tenant = _zipf_choice(rng, tenants, 0.85)
            region = rng.randrange(regions)
            category = _zipf_choice(rng, categories, 0.70)
            day = (rng.randrange(1460) + (i // max(1, n // 80))) % 1000
            quantity = 1 + rng.randrange(50)
            price = 90 + 13 * category + rng.randrange(900)
            discount = rng.randrange(0, 11)
            amount = int(quantity * price * (100 - discount) / 100)
            sensitivity = 0 if discount < 4 else (1 if discount < 8 else 2)
        elif profile == "open_data_permits":
            tenant = rng.randrange(tenants)  # agency
            region = _zipf_choice(rng, regions, 0.55)  # district
            category = _zipf_choice(rng, categories, 1.10)  # permit class
            day = int((rng.betavariate(1.4, 2.4) * 999 + rng.randrange(17)) % 1000)
            amount = int(25 + 18 * category + rng.expovariate(1 / 120.0))
            sensitivity = 0 if rng.random() < 0.82 else (1 if rng.random() < 0.93 else 2)
        elif profile == "health_release":
            tenant = rng.randrange(tenants)  # provider
            region = rng.randrange(regions)
            category = _zipf_choice(rng, categories, 1.35)  # condition group
            day = rng.randrange(1000)
            amount = int(1 + rng.expovariate(1 / (35.0 + 8.0 * category)))
            sensitivity = 0 if rng.random() < 0.35 else (1 if rng.random() < 0.78 else 2)
        else:  # finance_audit
            tenant = _zipf_choice(rng, tenants, 0.95)
            region = rng.randrange(regions)
            category = rng.randrange(categories)  # transaction class
            day = rng.randrange(1000)
            amount = int(5 + rng.lognormvariate(4.2 + category / 10.0, 0.85))
            sensitivity = 0 if amount < 140 else (1 if amount < 500 else 2)

        score = int(1000000 - (amount * 17 + day * 11 + rng.randrange(5000)))
        cust_id = tenant * 100000 + rng.randrange(max(100, n // (tenants * 10) + 100))
        rows.append(
            {
                "id": i,
                "tenant": tenant,
                "region": region,
                "category": category,
                "day": day,
                "amount": amount,
                "score": score,
                "sensitivity": sensitivity,
                "cust_id": cust_id,
                "profile": profile,
            }
        )
    return rows


def load_governed_rows_csv(path: str, *, profile: str = "external_csv") -> List[JSON]:
    """Load an external CSV already mapped to Pacta's governed row contract.

    Required columns are id, tenant, region, category, day, amount, score,
    sensitivity, and cust_id. The loader is used as an artifact integration hook:
    external data can be plugged in without changing the verifier or evidence
    algebra, while the paper's reported numbers remain only those reproduced by
    the checked scripts.
    """
    required = ["id", "tenant", "region", "category", "day", "amount", "score", "sensitivity", "cust_id"]
    out: List[JSON] = []
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        missing = [c for c in required if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"external CSV is missing required columns: {missing}")
        for raw in reader:
            row = {k: int(raw[k]) for k in required}
            row["profile"] = profile
            out.append(row)
    return out




def load_public_gapminder_rows(path: str) -> List[JSON]:
    """Map Plotly's public Gapminder CSV to the governed-row contract."""
    continents: Dict[str, int] = {}
    countries: Dict[str, int] = {}
    rows: List[JSON] = []
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, r in enumerate(reader):
            cont = r.get("continent", "unknown")
            country = r.get("country", "unknown")
            if cont not in continents:
                continents[cont] = len(continents)
            if country not in countries:
                countries[country] = len(countries)
            tenant = continents[cont] % 6
            region = countries[country] % 5
            category = continents[cont] % 6
            year = int(float(r.get("year", 0)))
            gdp = max(0, int(float(r.get("gdpPercap", 0))))
            life = float(r.get("lifeExp", 0.0))
            pop = int(float(r.get("pop", 0)))
            sensitivity = 0 if pop < 5_000_000 else (1 if pop < 50_000_000 else 2)
            rows.append({
                "id": i, "tenant": tenant, "region": region, "category": category,
                "day": year, "amount": gdp, "score": int(life * 1000),
                "sensitivity": sensitivity, "cust_id": tenant * 100000 + countries[country],
                "profile": "public_gapminder",
            })
    return rows


def load_public_apple_stock_rows(path: str) -> List[JSON]:
    """Map Plotly's public 2014 Apple stock CSV to governed rows."""
    import datetime as _dt
    rows: List[JSON] = []
    prev = None
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, r in enumerate(reader):
            date_s = r.get("AAPL_x") or r.get("date")
            price = float(r.get("AAPL_y") or r.get("price") or 0.0)
            dt = _dt.date.fromisoformat(date_s)
            amount = int(round(price * 100))
            change = abs(amount - prev) if prev is not None else 0
            prev = amount
            rows.append({
                "id": i, "tenant": 0, "region": (dt.month - 1) % 5,
                "category": (dt.month - 1) % 6, "day": i, "amount": amount,
                "score": 1_000_000 - amount,
                "sensitivity": 0 if change < 80 else (1 if change < 180 else 2),
                "cust_id": i, "profile": "public_apple_stock",
            })
    return rows


def load_public_profile_rows(profile: str, root_dir: Optional[str] = None) -> List[JSON]:
    root_dir = root_dir or os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    data_dir = os.path.join(root_dir, 'external_data')
    if profile == 'public_gapminder':
        return load_public_gapminder_rows(os.path.join(data_dir, 'gapminderDataFiveYear.csv'))
    if profile == 'public_apple_stock':
        return load_public_apple_stock_rows(os.path.join(data_dir, '2014_apple_stock.csv'))
    raise ValueError(f'unknown public profile: {profile}')


def generate_customers(sales: Sequence[JSON], seed: int = 0) -> List[JSON]:
    rng = random.Random(seed + 1009)
    seen = sorted({int(r["cust_id"]) for r in sales})
    out = []
    for cid in seen:
        tenant = cid // 100000
        out.append({"cust_id": cid, "tenant": tenant, "segment": rng.randrange(4), "active": 1 if rng.random() < 0.92 else 0})
    return out


def customers_as_sales_like(customers: Sequence[JSON]) -> List[JSON]:
    out = []
    for c in customers:
        out.append(
            {
                "id": int(c["cust_id"]),
                "cust_id": int(c["cust_id"]),
                "tenant": int(c["tenant"]),
                "region": 0,
                "category": int(c.get("segment", 0)),
                "day": 0,
                "amount": int(c.get("active", 1)),
                "score": 0,
                "sensitivity": 0,
                "segment": int(c.get("segment", 0)),
                "active": int(c.get("active", 1)),
            }
        )
    return out


def create_sqlite_db(rows: Sequence[JSON]) -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE sales(id INTEGER PRIMARY KEY, tenant INTEGER, region INTEGER, category INTEGER, day INTEGER, amount INTEGER, score INTEGER, sensitivity INTEGER, cust_id INTEGER)"
    )
    cur.executemany(
        "INSERT INTO sales VALUES(:id,:tenant,:region,:category,:day,:amount,:score,:sensitivity,:cust_id)",
        rows,
    )
    cur.execute("CREATE INDEX sales_day ON sales(day)")
    cur.execute("CREATE INDEX sales_tenant_day ON sales(tenant, day)")
    con.commit()
    return con


def sqlite_groupby(con: sqlite3.Connection, policy: Policy, lo: int, hi: int) -> Dict[int, Tuple[int, int]]:
    placeholders = ",".join("?" for _ in policy.regions)
    args = [lo, hi, policy.tenant, policy.max_sensitivity, *policy.regions]
    q = f"""
    SELECT category, COUNT(*), COALESCE(SUM(amount),0)
    FROM sales
    WHERE day BETWEEN ? AND ? AND tenant=? AND sensitivity<=? AND region IN ({placeholders})
    GROUP BY category
    ORDER BY category
    """
    return {int(cat): (int(cnt), int(total)) for cat, cnt, total in con.execute(q, args)}


def create_sqlite_join_db(rows: Sequence[JSON], customers: Sequence[JSON]) -> sqlite3.Connection:
    con = create_sqlite_db(rows)
    cur = con.cursor()
    cur.execute("CREATE TABLE customers(cust_id INTEGER PRIMARY KEY, tenant INTEGER, segment INTEGER, active INTEGER)")
    cur.executemany("INSERT INTO customers VALUES(:cust_id,:tenant,:segment,:active)", customers)
    cur.execute("CREATE INDEX customers_segment ON customers(segment)")
    con.commit()
    return con


def sqlite_complete_join_groupby(con: sqlite3.Connection, policy: Policy, lo: int, hi: int) -> Dict[int, Tuple[int, int]]:
    placeholders = ",".join("?" for _ in policy.regions)
    args = [lo, hi, policy.tenant, policy.max_sensitivity, *policy.regions]
    q = f"""
    SELECT c.segment, COUNT(*), COALESCE(SUM(s.amount),0)
    FROM sales s JOIN customers c ON s.cust_id = c.cust_id
    WHERE s.day BETWEEN ? AND ? AND s.tenant=? AND s.sensitivity<=?
      AND s.region IN ({placeholders}) AND c.tenant=s.tenant AND c.active=1
    GROUP BY c.segment
    ORDER BY c.segment
    """
    return {int(seg): (int(cnt), int(total)) for seg, cnt, total in con.execute(q, args)}


def create_sqlite_many_to_many_db(rows: Sequence[JSON], tags: Sequence[JSON]) -> sqlite3.Connection:
    con = create_sqlite_db(rows)
    cur = con.cursor()
    cur.execute("CREATE TABLE category_tags(id INTEGER PRIMARY KEY, category INTEGER, tag INTEGER)")
    cur.executemany("INSERT INTO category_tags VALUES(:id,:category,:tag)", tags)
    cur.execute("CREATE INDEX category_tags_category ON category_tags(category)")
    con.commit()
    return con


def sqlite_complete_mm_join_groupby(con: sqlite3.Connection, policy: Policy, lo: int, hi: int) -> Dict[int, Tuple[int, int]]:
    placeholders = ",".join("?" for _ in policy.regions)
    args = [lo, hi, policy.tenant, policy.max_sensitivity, *policy.regions]
    q = f"""
    SELECT t.tag, COUNT(*), COALESCE(SUM(s.amount),0)
    FROM sales s JOIN category_tags t ON s.category = t.category
    WHERE s.day BETWEEN ? AND ? AND s.tenant=? AND s.sensitivity<=?
      AND s.region IN ({placeholders})
    GROUP BY t.tag
    ORDER BY t.tag
    """
    return {int(tag): (int(cnt), int(total)) for tag, cnt, total in con.execute(q, args)}


def sqlite_distinct_customer_groupby(con: sqlite3.Connection, policy: Policy, lo: int, hi: int) -> Dict[int, int]:
    placeholders = ",".join("?" for _ in policy.regions)
    args = [lo, hi, policy.tenant, policy.max_sensitivity, *policy.regions]
    q = f"""
    SELECT category, COUNT(DISTINCT cust_id)
    FROM sales
    WHERE day BETWEEN ? AND ? AND tenant=? AND sensitivity<=?
      AND region IN ({placeholders})
    GROUP BY category
    ORDER BY category
    """
    return {int(cat): int(cnt) for cat, cnt in con.execute(q, args)}


def sqlite_complete_antijoin_groupby(con: sqlite3.Connection, policy: Policy, lo: int, hi: int) -> Dict[int, Tuple[int, int]]:
    placeholders = ",".join("?" for _ in policy.regions)
    args = [lo, hi, policy.tenant, policy.max_sensitivity, *policy.regions]
    q = f"""
    SELECT s.category, COUNT(*), COALESCE(SUM(s.amount),0)
    FROM sales s
    WHERE s.day BETWEEN ? AND ? AND s.tenant=? AND s.sensitivity<=?
      AND s.region IN ({placeholders})
      AND NOT EXISTS (
        SELECT 1 FROM customers c
        WHERE c.cust_id=s.cust_id AND c.tenant=s.tenant AND c.active=1
      )
    GROUP BY s.category
    ORDER BY s.category
    """
    return {int(cat): (int(cnt), int(total)) for cat, cnt, total in con.execute(q, args)}


ACC_MOD = 2 ** 127 - 1


def row_accumulator(row: JSON) -> int:
    """Commutative multiset fingerprint for exact opened-row checks.

    Count and sum alone do not identify a multiset of contributors. The
    accumulator is a collision-resistant hash sum modulo a large Mersenne
    prime; the verifier uses it only when a certificate claims that an opened
    tuple list is complete for a summary cell.
    """
    material = {
        "id": _cert_integral(row.get("id", row.get("cust_id", -1)), "row.id"),
        "tenant": _cert_integral(row.get("tenant", 0), "row.tenant"),
        "region": _cert_integral(row.get("region", 0), "row.region"),
        "category": _cert_integral(row.get("category", 0), "row.category"),
        "day": _cert_integral(row.get("day", 0), "row.day"),
        "amount": _cert_integral(row.get("amount", 0), "row.amount"),
        "score": _cert_integral(row.get("score", 0), "row.score"),
        "sensitivity": _cert_integral(row.get("sensitivity", 0), "row.sensitivity"),
        "cust_id": _cert_integral(row.get("cust_id", row.get("id", -1)), "row.cust_id"),
    }
    return int(hashlib.sha256(("row_acc|" + canonical(material)).encode("utf-8")).hexdigest(), 16) % ACC_MOD


def summary_key(row: JSON) -> str:
    return "|".join(str(_cert_integral(row[a], f"row.{a}")) for a in ("tenant", "sensitivity", "region", "category"))


def summary_digest(summary: Dict[str, List[int]]) -> str:
    return digest("summary", summary)


def merge_summaries(*summaries: Dict[str, List[int]]) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    # Merge larger summaries first to reduce object churn. Summary cells are
    # [count, sum(amount), row_accumulator]. Older two-field cells are accepted
    # only for defensive compatibility.
    for s in sorted(summaries, key=len, reverse=True):
        for k, v in s.items():
            vals = [int(x) for x in v]
            if len(vals) == 2:
                vals.append(0)
            if k not in out:
                out[k] = [0, 0, 0]
            out[k][0] += vals[0]
            out[k][1] += vals[1]
            out[k][2] = (out[k][2] + vals[2]) % ACC_MOD
    return out


def project_summary(summary: Dict[str, List[int]], policy: Policy) -> Dict[int, Tuple[int, int]]:
    return {k: (v[0], v[1]) for k, v in project_summary_with_acc(summary, policy).items()}


def project_summary_with_acc(summary: Dict[str, List[int]], policy: Policy) -> Dict[int, Tuple[int, int, int]]:
    regions = set(policy.regions)
    out: Dict[int, Tuple[int, int, int]] = {}
    for key, val in summary.items():
        tenant, sens, region, cat = (int(x) for x in key.split("|"))
        if tenant == policy.tenant and sens <= policy.max_sensitivity and region in regions:
            cnt, total = int(val[0]), int(val[1])
            acc = int(val[2]) if len(val) > 2 else 0
            oc, os, oa = out.get(cat, (0, 0, 0))
            out[cat] = (oc + cnt, os + total, (oa + acc) % ACC_MOD)
    return dict(sorted(out.items()))


def project_summary_all_acc(summary: Dict[str, List[int]]) -> Dict[int, Tuple[int, int, int]]:
    """Fold a policy-cube summary into a category-keyed accumulator for all rows.

    Used by the open-scan fallback: the verifier opens every committed row in
    the key range, checks that the opened multiset matches the authenticated
    range accumulator, and only then evaluates row-local SQL predicates.
    """
    out: Dict[int, Tuple[int, int, int]] = {}
    for key, val in summary.items():
        _, _, _, cat = (int(x) for x in key.split("|"))
        cnt, total = int(val[0]), int(val[1])
        acc = int(val[2]) if len(val) > 2 else 0
        oc, os, oa = out.get(cat, (0, 0, 0))
        out[cat] = (oc + cnt, os + total, (oa + acc) % ACC_MOD)
    return dict(sorted(out.items()))


class Node:
    __slots__ = ("start", "end", "min_key", "max_key", "count", "summary", "hash", "children", "record", "parent", "child_index")

    def __init__(
        self,
        start: int,
        end: int,
        min_key: int,
        max_key: int,
        count: int,
        summary: Dict[str, List[int]],
        h: str,
        *,
        children: Optional[List["Node"]] = None,
        record: Optional[JSON] = None,
    ):
        self.start = start
        self.end = end
        self.min_key = min_key
        self.max_key = max_key
        self.count = count
        self.summary = summary
        self.hash = h
        self.children = children or []
        self.record = record
        self.parent: Optional[Node] = None
        self.child_index: int = -1


class MerkleAggregateTree:
    def __init__(self, rows: Sequence[JSON], key_attr: str = "day", fanout: int = 16, version: int = 1):
        if fanout < 2:
            raise ValueError("fanout must be at least 2")
        self.key_attr = key_attr
        self.fanout = fanout
        self.version = _json_integral(version, "relation.version")
        materialized = [dict(r) for r in rows]
        self.typed_extra_int = infer_typed_extra_int(materialized)
        self.schema = schema_descriptor(self.key_attr, self.typed_extra_int)
        seen_ids = set()
        for r in materialized:
            validate_row_schema(r, key_attr, self.typed_extra_int)
            rid = int(r.get("id", r.get("cust_id", -1)))
            if rid in seen_ids:
                raise ValueError(f"duplicate primary key in committed relation: {rid}")
            seen_ids.add(rid)
        self.rows = sorted(materialized, key=lambda r: (int(r[key_attr]), int(r.get("id", r.get("cust_id", 0)))))
        self.id_to_pos = {int(r.get("id", r.get("cust_id", i))): i for i, r in enumerate(self.rows)}
        self.leaves: List[Node] = []
        self.root = self._build_bottom_up()
        self.root_hash = self.root.hash if self.root else digest("empty", {"key_attr": self.key_attr, "schema": self.schema})

    def relation_descriptor(self) -> JSON:
        schema = self.schema
        if self.root is None:
            return {"root": self.root_hash, "key_attr": self.key_attr, "fanout": self.fanout, "count": 0, "min": None, "max": None, "version": self.version, "schema": schema}
        return {
            "root": self.root_hash,
            "key_attr": self.key_attr,
            "fanout": self.fanout,
            "count": self.root.count,
            "min": self.root.min_key,
            "max": self.root.max_key,
            "version": self.version,
            "schema": schema,
        }

    def _child_descriptor(self, child: Node) -> JSON:
        return {"min": child.min_key, "max": child.max_key, "count": child.count, "hash": child.hash}

    def _leaf_hash(self, row: JSON, summary: Dict[str, List[int]], key: int) -> str:
        return digest("leaf", {"key_attr": self.key_attr, "key": key, "row": row, "summary_digest": summary_digest(summary)})

    def _node_hash(self, min_key: int, max_key: int, count: int, sd: str, child_descriptors: Sequence[JSON]) -> str:
        return digest(
            "node",
            {
                "key_attr": self.key_attr,
                "min": min_key,
                "max": max_key,
                "count": count,
                "summary_digest": sd,
                "children": list(child_descriptors),
            },
        )

    def _make_leaf(self, pos: int, row: JSON) -> Node:
        key = _cert_integral(row[self.key_attr], f"row.{self.key_attr}")
        s = {summary_key(row): [1, _cert_integral(row["amount"], "row.amount"), row_accumulator(row)]}
        h = self._leaf_hash(row, s, key)
        return Node(pos, pos + 1, key, key, 1, s, h, record=row)

    def _make_internal(self, children: Sequence[Node]) -> Node:
        summaries = [c.summary for c in children]
        s = merge_summaries(*summaries)
        child_descriptors = [self._child_descriptor(c) for c in children]
        h = self._node_hash(children[0].min_key, children[-1].max_key, sum(c.count for c in children), summary_digest(s), child_descriptors)
        node = Node(children[0].start, children[-1].end, children[0].min_key, children[-1].max_key, sum(c.count for c in children), s, h, children=list(children))
        for idx, child in enumerate(node.children):
            child.parent = node
            child.child_index = idx
        return node

    def _build_bottom_up(self) -> Optional[Node]:
        if not self.rows:
            return None
        self.leaves = [self._make_leaf(i, row) for i, row in enumerate(self.rows)]
        level = self.leaves
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), self.fanout):
                next_level.append(self._make_internal(level[i : i + self.fanout]))
            level = next_level
        return level[0]

    def _refresh_internal(self, node: Node) -> None:
        if not node.children:
            return
        node.min_key = node.children[0].min_key
        node.max_key = node.children[-1].max_key
        node.count = sum(c.count for c in node.children)
        node.summary = merge_summaries(*(c.summary for c in node.children))
        node.hash = self._node_hash(node.min_key, node.max_key, node.count, summary_digest(node.summary), [self._child_descriptor(c) for c in node.children])

    def _cover_object(self, node: Node) -> JSON:
        obj: JSON = {
            "kind": "cover",
            "min": node.min_key,
            "max": node.max_key,
            "count": node.count,
            "summary": node.summary,
            "summary_digest": summary_digest(node.summary),
            "hash": node.hash,
        }
        if node.record is not None:
            obj["record"] = node.record
        else:
            obj["child_descriptors"] = [self._child_descriptor(c) for c in node.children]
        return obj

    def range_certificate_tree(self, lo: int, hi: int) -> JSON:
        if self.root is None:
            return {"kind": "empty", "hash": self.root_hash}
        return self._range_cert(self.root, lo, hi)

    def _range_cert(self, node: Node, lo: int, hi: int) -> JSON:
        if node.max_key < lo or node.min_key > hi:
            return {"kind": "hash", "min": node.min_key, "max": node.max_key, "count": node.count, "hash": node.hash}
        if lo <= node.min_key and node.max_key <= hi:
            return self._cover_object(node)
        if node.record is not None:
            return self._cover_object(node)
        return {
            "kind": "branch",
            "min": node.min_key,
            "max": node.max_key,
            "count": node.count,
            "summary_digest": summary_digest(node.summary),
            "children": [self._range_cert(child, lo, hi) for child in node.children],
            "hash": node.hash,
        }

    def _hash_cover(self, cert: JSON) -> str:
        sd = summary_digest(cert["summary"])
        if sd != cert.get("summary_digest"):
            raise ValueError("bad summary digest")
        if "record" in cert:
            row = cert["record"]
            key = _cert_integral(row[self.key_attr], f"row.{self.key_attr}")
            s = {summary_key(row): [1, _cert_integral(row["amount"], "row.amount"), row_accumulator(row)]}
            if sd != summary_digest(s):
                raise ValueError("bad leaf summary")
            if _cert_integral(cert["min"], "cert.min") != key or _cert_integral(cert["max"], "cert.max") != key or _cert_integral(cert["count"], "cert.count") != 1:
                raise ValueError("bad leaf metadata")
            return self._leaf_hash(row, s, key)
        child_descriptors = cert.get("child_descriptors")
        if not isinstance(child_descriptors, list) or not child_descriptors:
            raise ValueError("internal cover missing child descriptors")
        return self._node_hash(_cert_integral(cert["min"], "cert.min"), _cert_integral(cert["max"], "cert.max"), _cert_integral(cert["count"], "cert.count"), sd, child_descriptors)

    def _verify_node(self, cert: JSON, policy: Policy, lo: int, hi: int) -> Tuple[str, Dict[int, Tuple[int, int]]]:
        kind = cert["kind"]
        if kind == "empty":
            return cert["hash"], {}
        mn, mx = _cert_integral(cert.get("min", -10**18), "cert.min"), _cert_integral(cert.get("max", 10**18), "cert.max")
        if kind == "hash":
            if not (mx < lo or mn > hi):
                raise ValueError("hash-only overlapping node")
            return cert["hash"], {}
        if kind == "cover":
            if not (lo <= mn and mx <= hi):
                raise ValueError("cover not contained in range")
            h = self._hash_cover(cert)
            if h != cert.get("hash"):
                raise ValueError("cover hash mismatch")
            return h, project_summary(cert["summary"], policy)
        if kind == "branch":
            children = cert.get("children", [])
            if not children:
                raise ValueError("branch with no children")
            child_descriptors: List[JSON] = []
            acc: Dict[int, Tuple[int, int]] = {}
            last_max: Optional[int] = None
            total_count = 0
            for child in children:
                ch_mn = _cert_integral(child.get("min", mn), "child.min") if child.get("kind") != "empty" else mn
                ch_mx = _cert_integral(child.get("max", mx), "child.max") if child.get("kind") != "empty" else mx
                ch_count = _cert_integral(child.get("count", 0), "child.count")
                if last_max is not None and ch_mn < last_max:
                    raise ValueError("children not ordered")
                last_max = ch_mx
                h, r = self._verify_node(child, policy, lo, hi)
                child_descriptors.append({"min": ch_mn, "max": ch_mx, "count": ch_count, "hash": h})
                total_count += ch_count
                acc = add_result(acc, r)
            if total_count != _cert_integral(cert["count"], "cert.count"):
                raise ValueError("bad branch count")
            h = self._node_hash(mn, mx, _cert_integral(cert["count"], "cert.count"), cert["summary_digest"], child_descriptors)
            if h != cert.get("hash"):
                raise ValueError("branch hash mismatch")
            return h, acc
        raise ValueError("unknown cert kind")

    def verify_range_certificate(self, cert: JSON, policy: Policy, lo: int, hi: int, claimed: Dict[int, Tuple[int, int]]) -> Tuple[bool, Dict[int, Tuple[int, int]]]:
        try:
            if self.root is not None:
                if _cert_integral(cert.get("min", self.root.min_key), "cert.min") != self.root.min_key:
                    return False, {}
                if _cert_integral(cert.get("max", self.root.max_key), "cert.max") != self.root.max_key:
                    return False, {}
                if _cert_integral(cert.get("count", self.root.count), "cert.count") != self.root.count:
                    return False, {}
            h, res = self._verify_node(cert, policy, lo, hi)
            ok = h == self.root_hash and normalize_result(res) == normalize_result(claimed)
            return ok, normalize_result(res)
        except Exception:
            return False, {}

    def _verify_node_acc(self, cert: JSON, policy: Policy, lo: int, hi: int) -> Tuple[str, Dict[int, Tuple[int, int, int]]]:
        kind = cert["kind"]
        if kind == "empty":
            return cert["hash"], {}
        mn, mx = _cert_integral(cert.get("min", -10**18), "cert.min"), _cert_integral(cert.get("max", 10**18), "cert.max")
        if kind == "hash":
            if not (mx < lo or mn > hi):
                raise ValueError("hash-only overlapping node")
            return cert["hash"], {}
        if kind == "cover":
            if not (lo <= mn and mx <= hi):
                raise ValueError("cover not contained in range")
            h = self._hash_cover(cert)
            if h != cert.get("hash"):
                raise ValueError("cover hash mismatch")
            return h, project_summary_with_acc(cert["summary"], policy)
        if kind == "branch":
            children = cert.get("children", [])
            if not children:
                raise ValueError("branch with no children")
            child_descriptors: List[JSON] = []
            acc: Dict[int, Tuple[int, int, int]] = {}
            last_max: Optional[int] = None
            total_count = 0
            for child in children:
                ch_mn = _cert_integral(child.get("min", mn), "child.min") if child.get("kind") != "empty" else mn
                ch_mx = _cert_integral(child.get("max", mx), "child.max") if child.get("kind") != "empty" else mx
                ch_count = _cert_integral(child.get("count", 0), "child.count")
                if last_max is not None and ch_mn < last_max:
                    raise ValueError("children not ordered")
                last_max = ch_mx
                h, r = self._verify_node_acc(child, policy, lo, hi)
                child_descriptors.append({"min": ch_mn, "max": ch_mx, "count": ch_count, "hash": h})
                total_count += ch_count
                acc = add_result_acc(acc, r)
            if total_count != _cert_integral(cert["count"], "cert.count"):
                raise ValueError("bad branch count")
            h = self._node_hash(mn, mx, _cert_integral(cert["count"], "cert.count"), cert["summary_digest"], child_descriptors)
            if h != cert.get("hash"):
                raise ValueError("branch hash mismatch")
            return h, acc
        raise ValueError("unknown cert kind")

    def verify_range_certificate_acc(self, cert: JSON, policy: Policy, lo: int, hi: int, claimed: Dict[int, Tuple[int, int, int]]) -> Tuple[bool, Dict[int, Tuple[int, int, int]]]:
        try:
            if self.root is not None:
                if _cert_integral(cert.get("min", self.root.min_key), "cert.min") != self.root.min_key:
                    return False, {}
                if _cert_integral(cert.get("max", self.root.max_key), "cert.max") != self.root.max_key:
                    return False, {}
                if _cert_integral(cert.get("count", self.root.count), "cert.count") != self.root.count:
                    return False, {}
            h, res = self._verify_node_acc(cert, policy, lo, hi)
            ok = h == self.root_hash and dict(sorted(res.items())) == dict(sorted(claimed.items()))
            return ok, dict(sorted(res.items()))
        except Exception:
            return False, {}

    def _verify_node_all_acc(self, cert: JSON, lo: int, hi: int) -> Tuple[str, Dict[int, Tuple[int, int, int]]]:
        kind = cert["kind"]
        if kind == "empty":
            return cert["hash"], {}
        mn, mx = _cert_integral(cert.get("min", -10**18), "cert.min"), _cert_integral(cert.get("max", 10**18), "cert.max")
        if kind == "hash":
            if not (mx < lo or mn > hi):
                raise ValueError("hash-only overlapping node")
            return cert["hash"], {}
        if kind == "cover":
            if not (lo <= mn and mx <= hi):
                raise ValueError("cover not contained in range")
            h = self._hash_cover(cert)
            if h != cert.get("hash"):
                raise ValueError("cover hash mismatch")
            return h, project_summary_all_acc(cert["summary"])
        if kind == "branch":
            children = cert.get("children", [])
            if not children:
                raise ValueError("branch with no children")
            child_descriptors: List[JSON] = []
            acc: Dict[int, Tuple[int, int, int]] = {}
            last_max: Optional[int] = None
            total_count = 0
            for child in children:
                ch_mn = _cert_integral(child.get("min", mn), "child.min") if child.get("kind") != "empty" else mn
                ch_mx = _cert_integral(child.get("max", mx), "child.max") if child.get("kind") != "empty" else mx
                ch_count = _cert_integral(child.get("count", 0), "child.count")
                if last_max is not None and ch_mn < last_max:
                    raise ValueError("children not ordered")
                last_max = ch_mx
                h, r = self._verify_node_all_acc(child, lo, hi)
                child_descriptors.append({"min": ch_mn, "max": ch_mx, "count": ch_count, "hash": h})
                total_count += ch_count
                acc = add_result_acc(acc, r)
            if total_count != _cert_integral(cert["count"], "cert.count"):
                raise ValueError("bad branch count")
            h = self._node_hash(mn, mx, _cert_integral(cert["count"], "cert.count"), cert["summary_digest"], child_descriptors)
            if h != cert.get("hash"):
                raise ValueError("branch hash mismatch")
            return h, acc
        raise ValueError("unknown cert kind")

    def verify_range_certificate_all_acc(self, cert: JSON, lo: int, hi: int, claimed: Dict[int, Tuple[int, int, int]]) -> Tuple[bool, Dict[int, Tuple[int, int, int]]]:
        try:
            if self.root is not None:
                if _cert_integral(cert.get("min", self.root.min_key), "cert.min") != self.root.min_key:
                    return False, {}
                if _cert_integral(cert.get("max", self.root.max_key), "cert.max") != self.root.max_key:
                    return False, {}
                if _cert_integral(cert.get("count", self.root.count), "cert.count") != self.root.count:
                    return False, {}
            h, res = self._verify_node_all_acc(cert, lo, hi)
            ok = h == self.root_hash and dict(sorted(res.items())) == dict(sorted(claimed.items()))
            return ok, dict(sorted(res.items()))
        except Exception:
            return False, {}

    def make_groupby_certificate(self, policy: Policy, lo: int, hi: int, *, manifest: Optional[JSON] = None, subject: Optional[str] = None, version: Optional[int] = None) -> JSON:
        subject = subject or f"tenant-{policy.tenant}"
        version = self.version if version is None else int(version)
        manifest = manifest or make_manifest(policy, subject=subject, version=version)
        proof = self.range_certificate_tree(lo, hi)
        _, result = self._verify_node(proof, policy, lo, hi)
        root_descriptor = self.relation_descriptor()
        od = owner_digest(root_descriptor, manifest, version)
        contract = {
            "op": "range_groupby",
            "lo": lo,
            "hi": hi,
            "group_by": "category",
            "aggregates": ["count", "sum(amount)"],
            "subject": subject,
            "purpose": policy.purpose,
            "policy_hash": digest("compiled_policy", policy.to_dict()),
        }
        validate_contract(contract)
        cert: JSON = {
            "scheme": "pacta-policy-aware-compact",
            "owner_digest": od,
            "root_descriptor": root_descriptor,
            "manifest": manifest,
            "subject": subject,
            "purpose": policy.purpose,
            "query": contract,
            "request_digest": contract_digest(contract),
            "policy_hash": digest("compiled_policy", policy.to_dict()),
            "root": self.root_hash,
            "fanout": self.fanout,
            "result": result_to_json(result),
            "proof": proof,
        }
        return cert

    def verify_groupby_certificate(self, cert: JSON, expected_owner_digest: Optional[JSON] = None, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
        try:
            if expected_owner_digest is None and not allow_self_certified:
                return False
            manifest = cert["manifest"]
            if cert.get("root_descriptor") != self.relation_descriptor():
                return False
            if not verify_owner_digest(cert["owner_digest"], cert["root_descriptor"], manifest):
                return False
            if expected_owner_digest is not None and canonical(cert["owner_digest"]) != canonical(expected_owner_digest):
                return False
            if cert.get("root") != self.root_hash:
                return False
            policy = compile_policy(manifest, cert["subject"], cert["purpose"])
            policies = [p for p in manifest.get("policies", []) if p.get("subject") == cert["subject"] and p.get("purpose") == cert["purpose"]]
            if len(policies) != 1 or tuple(policies[0].get("projection", [])) != tuple(policy.projection):
                return False
            if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
                return False
            if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
                return False
            q = cert["query"]
            validate_contract(q)
            if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
                return False
            if q.get("op") != "range_groupby":
                return False
            if q.get("policy_hash") != cert.get("policy_hash"):
                return False
            claimed = json_to_result(cert["result"])
            ok, _ = self.verify_range_certificate(cert["proof"], policy, int(q["lo"]), int(q["hi"]), claimed)
            return ok
        except Exception:
            return False

    def make_groupby_avg_certificate(self, policy: Policy, lo: int, hi: int, *, manifest: Optional[JSON] = None, subject: Optional[str] = None, version: Optional[int] = None) -> JSON:
        subject = subject or f"tenant-{policy.tenant}"
        version = self.version if version is None else int(version)
        manifest = manifest or make_manifest(policy, subject=subject, version=version)
        proof = self.range_certificate_tree(lo, hi)
        _, base_result = self._verify_node(proof, policy, lo, hi)
        root_descriptor = self.relation_descriptor()
        contract = {
            "op": "range_groupby_avg",
            "lo": lo,
            "hi": hi,
            "group_by": "category",
            "aggregates": ["count", "sum(amount)", "avg(amount)"],
            "subject": subject,
            "purpose": policy.purpose,
            "policy_hash": digest("compiled_policy", policy.to_dict()),
        }
        validate_contract(contract)
        return {
            "scheme": "pacta-policy-aware-derived-average",
            "owner_digest": owner_digest(root_descriptor, manifest, version),
            "root_descriptor": root_descriptor,
            "manifest": manifest,
            "subject": subject,
            "purpose": policy.purpose,
            "query": contract,
            "request_digest": contract_digest(contract),
            "policy_hash": digest("compiled_policy", policy.to_dict()),
            "root": self.root_hash,
            "fanout": self.fanout,
            "result": avg_result_to_json(base_result),
            "proof": proof,
        }

    def verify_groupby_avg_certificate(self, cert: JSON, expected_owner_digest: Optional[JSON] = None, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
        try:
            if expected_owner_digest is None and not allow_self_certified:
                return False
            manifest = cert["manifest"]
            if cert.get("root_descriptor") != self.relation_descriptor():
                return False
            if not verify_owner_digest(cert["owner_digest"], cert["root_descriptor"], manifest):
                return False
            if expected_owner_digest is not None and canonical(cert["owner_digest"]) != canonical(expected_owner_digest):
                return False
            if cert.get("root") != self.root_hash:
                return False
            policy = compile_policy(manifest, cert["subject"], cert["purpose"])
            if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
                return False
            if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
                return False
            q = cert["query"]
            if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
                return False
            if q.get("op") != "range_groupby_avg" or q.get("policy_hash") != cert.get("policy_hash"):
                return False
            base = json_to_avg_base_result(cert["result"])
            ok, folded = self.verify_range_certificate(cert["proof"], policy, int(q["lo"]), int(q["hi"]), base)
            if not ok or normalize_result(folded) != normalize_result(base):
                return False
            for k, v in cert["result"].items():
                cnt = int(v["count"]); total = int(v["sum_amount"]); avg = v.get("avg_amount")
                if cnt == 0:
                    if avg is not None:
                        return False
                else:
                    if not isinstance(avg, dict) or int(avg.get("numerator", -1)) != total or int(avg.get("denominator", -1)) != cnt:
                        return False
            return True
        except Exception:
            return False

    def make_groupby_having_certificate(self, policy: Policy, lo: int, hi: int, threshold: int, *, manifest: Optional[JSON] = None, subject: Optional[str] = None, version: Optional[int] = None) -> JSON:
        subject = subject or f"tenant-{policy.tenant}"
        version = self.version if version is None else int(version)
        manifest = manifest or make_manifest(policy, subject=subject, version=version)
        proof = self.range_certificate_tree(lo, hi)
        _, full_result = self._verify_node(proof, policy, lo, hi)
        filtered = {k: v for k, v in normalize_result(full_result).items() if int(v[1]) >= int(threshold)}
        root_descriptor = self.relation_descriptor()
        contract = {
            "op": "range_groupby_having_sum",
            "lo": lo,
            "hi": hi,
            "group_by": "category",
            "aggregates": ["count", "sum(amount)"],
            "having": {"sum(amount)": [">=", int(threshold)]},
            "subject": subject,
            "purpose": policy.purpose,
            "policy_hash": digest("compiled_policy", policy.to_dict()),
        }
        validate_contract(contract)
        return {
            "scheme": "pacta-policy-aware-groupby-having",
            "owner_digest": owner_digest(root_descriptor, manifest, version),
            "root_descriptor": root_descriptor,
            "manifest": manifest,
            "subject": subject,
            "purpose": policy.purpose,
            "query": contract,
            "request_digest": contract_digest(contract),
            "policy_hash": digest("compiled_policy", policy.to_dict()),
            "root": self.root_hash,
            "full_group_result": result_to_json(full_result),
            "result": result_to_json(filtered),
            "proof": proof,
        }

    def verify_groupby_having_certificate(self, cert: JSON, expected_owner_digest: Optional[JSON] = None, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
        try:
            if expected_owner_digest is None and not allow_self_certified:
                return False
            manifest = cert["manifest"]
            if cert.get("root_descriptor") != self.relation_descriptor():
                return False
            if not verify_owner_digest(cert["owner_digest"], cert["root_descriptor"], manifest):
                return False
            if expected_owner_digest is not None and canonical(cert["owner_digest"]) != canonical(expected_owner_digest):
                return False
            if cert.get("root") != self.root_hash:
                return False
            policy = compile_policy(manifest, cert["subject"], cert["purpose"])
            if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
                return False
            if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
                return False
            q = cert["query"]
            if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
                return False
            if q.get("op") != "range_groupby_having_sum" or q.get("policy_hash") != cert.get("policy_hash"):
                return False
            threshold = int(q["having"]["sum(amount)"][1])
            full = json_to_result(cert["full_group_result"])
            ok, folded = self.verify_range_certificate(cert["proof"], policy, int(q["lo"]), int(q["hi"]), full)
            if not ok or normalize_result(folded) != normalize_result(full):
                return False
            filtered = {k: v for k, v in normalize_result(full).items() if int(v[1]) >= threshold}
            return result_to_json(filtered) == cert.get("result")
        except Exception:
            return False

    def make_projection_certificate(self, policy: Policy, lo: int, hi: int, projection: Sequence[str] = ("id", "category", "amount"), *, manifest: Optional[JSON] = None, subject: Optional[str] = None, version: Optional[int] = None) -> JSON:
        subject = subject or f"tenant-{policy.tenant}"
        version = self.version if version is None else int(version)
        manifest = manifest or make_manifest(policy, subject=subject, version=version)
        projection = tuple(projection)
        allowed_projection = ("id", "category", "amount")
        if projection != allowed_projection:
            raise UnsupportedQueryError("unsupported projection mask for range projection certificate")
        opened = sorted(rows_in_range(self.rows, lo, hi, policy, self.key_attr), key=lambda r: int(r["id"]))
        items = []
        released = []
        for r in opened:
            pos = self.id_to_pos.get(int(r["id"]))
            items.append({"row": r, "path": self.leaf_proof_for_pos(pos) if pos is not None else []})
            released.append({a: int(r[a]) for a in projection})
        proof = self.range_certificate_tree(lo, hi)
        root_descriptor = self.relation_descriptor()
        contract = {
            "op": "range_projection",
            "lo": lo,
            "hi": hi,
            "projection": list(projection),
            "subject": subject,
            "purpose": policy.purpose,
            "policy_hash": digest("compiled_policy", policy.to_dict()),
        }
        validate_contract(contract)
        return {
            "scheme": "pacta-policy-aware-range-projection",
            "owner_digest": owner_digest(root_descriptor, manifest, version),
            "root_descriptor": root_descriptor,
            "manifest": manifest,
            "subject": subject,
            "purpose": policy.purpose,
            "query": contract,
            "request_digest": contract_digest(contract),
            "policy_hash": digest("compiled_policy", policy.to_dict()),
            "root": self.root_hash,
            "released_rows": released,
            "items": items,
            "opened_count": len(items),
            "range_proof": proof,
        }

    def verify_projection_certificate(self, cert: JSON, expected_owner_digest: Optional[JSON] = None, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
        try:
            if expected_owner_digest is None and not allow_self_certified:
                return False
            manifest = cert["manifest"]
            if cert.get("root_descriptor") != self.relation_descriptor():
                return False
            if not verify_owner_digest(cert["owner_digest"], cert["root_descriptor"], manifest):
                return False
            if expected_owner_digest is not None and canonical(cert["owner_digest"]) != canonical(expected_owner_digest):
                return False
            if cert.get("root") != self.root_hash:
                return False
            policy = compile_policy(manifest, cert["subject"], cert["purpose"])
            if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
                return False
            if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
                return False
            q = cert["query"]
            if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
                return False
            if q.get("op") != "range_projection" or q.get("policy_hash") != cert.get("policy_hash"):
                return False
            projection = tuple(q.get("projection", []))
            if projection != ("id", "category", "amount"):
                return False
            items = cert.get("items", [])
            if len(items) != int(cert.get("opened_count", -1)):
                return False
            opened_rows: List[JSON] = []
            seen = set()
            released = []
            lo, hi = int(q["lo"]), int(q["hi"])
            for item in items:
                row = item["row"]
                rid = int(row["id"])
                if rid in seen:
                    return False
                seen.add(rid)
                if not self.verify_leaf_proof(row, item.get("path", []), cert["root"]):
                    return False
                if not (lo <= int(row[self.key_attr]) <= hi and policy.allows(row)):
                    return False
                opened_rows.append(row)
                released.append({a: int(row[a]) for a in projection})
            opened_acc = aggregate_rows_with_acc(opened_rows)
            ok, certified_acc = self.verify_range_certificate_acc(cert["range_proof"], policy, lo, hi, opened_acc)
            if not ok or certified_acc != opened_acc:
                return False
            return released == cert.get("released_rows")
        except Exception:
            return False

    def make_open_scan_groupby_predicate_certificate(self, policy: Policy, lo: int, hi: int, min_amount: int, *, manifest: Optional[JSON] = None, subject: Optional[str] = None, version: Optional[int] = None) -> JSON:
        """Sound fallback for row-local predicates not summarized by the cube.

        The server opens every committed row in the key range, proves the opened
        multiset with an authenticated accumulator, then the verifier evaluates
        the policy and row predicate.  This is intentionally larger than a
        policy-summary certificate, but it gives the optimizer a universal
        row-local predicate plan instead of rejecting such queries.
        """
        subject = subject or f"tenant-{policy.tenant}"
        version = self.version if version is None else int(version)
        manifest = manifest or make_manifest(policy, subject=subject, version=version)
        opened_all = sorted(rows_in_range(self.rows, lo, hi, None, self.key_attr), key=lambda r: int(r["id"]))
        items = []
        for r in opened_all:
            pos = self.id_to_pos.get(int(r["id"]))
            items.append({"row": r, "path": self.leaf_proof_for_pos(pos) if pos is not None else []})
        selected = [r for r in opened_all if policy.allows(r) and int(r["amount"]) >= int(min_amount)]
        result = aggregate_rows(selected)
        proof = self.range_certificate_tree(lo, hi)
        root_descriptor = self.relation_descriptor()
        contract = {
            "op": "open_scan_groupby_predicate",
            "lo": lo,
            "hi": hi,
            "row_predicate": ["amount", ">=", int(min_amount)],
            "group_by": "category",
            "aggregates": ["count", "sum(amount)"],
            "evidence_plan": "complete_open_range_scan",
            "subject": subject,
            "purpose": policy.purpose,
            "policy_hash": digest("compiled_policy", policy.to_dict()),
        }
        validate_contract(contract)
        return {
            "scheme": "pacta-open-range-scan-predicate",
            "owner_digest": owner_digest(root_descriptor, manifest, version),
            "root_descriptor": root_descriptor,
            "manifest": manifest,
            "subject": subject,
            "purpose": policy.purpose,
            "query": contract,
            "request_digest": contract_digest(contract),
            "policy_hash": digest("compiled_policy", policy.to_dict()),
            "root": self.root_hash,
            "opened_count": len(items),
            "items": items,
            "range_proof": proof,
            "result": result_to_json(result),
        }

    def verify_open_scan_groupby_predicate_certificate(self, cert: JSON, expected_owner_digest: Optional[JSON] = None, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
        try:
            if expected_owner_digest is None and not allow_self_certified:
                return False
            manifest = cert["manifest"]
            if cert.get("root_descriptor") != self.relation_descriptor():
                return False
            if not verify_owner_digest(cert["owner_digest"], cert["root_descriptor"], manifest):
                return False
            if expected_owner_digest is not None and canonical(cert["owner_digest"]) != canonical(expected_owner_digest):
                return False
            if cert.get("root") != self.root_hash:
                return False
            policy = compile_policy(manifest, cert["subject"], cert["purpose"])
            if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
                return False
            if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
                return False
            q = cert["query"]
            validate_contract(q)
            if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
                return False
            if q.get("op") != "open_scan_groupby_predicate" or q.get("policy_hash") != cert.get("policy_hash"):
                return False
            lo, hi = int(q["lo"]), int(q["hi"])
            pred = q["row_predicate"]
            min_amount = int(pred[2])
            opened_rows: List[JSON] = []
            seen = set()
            for item in cert.get("items", []):
                row = item["row"]
                rid = int(row["id"])
                if rid in seen:
                    return False
                seen.add(rid)
                if not self.verify_leaf_proof(row, item.get("path", []), cert["root"]):
                    return False
                if not (lo <= int(row[self.key_attr]) <= hi):
                    return False
                opened_rows.append(row)
            if len(opened_rows) != int(cert.get("opened_count", -1)):
                return False
            opened_acc = aggregate_rows_with_acc(opened_rows)
            ok, certified_acc = self.verify_range_certificate_all_acc(cert["range_proof"], lo, hi, opened_acc)
            if not ok or certified_acc != opened_acc:
                return False
            selected = [r for r in opened_rows if policy.allows(r) and int(r["amount"]) >= min_amount]
            return result_to_json(aggregate_rows(selected)) == cert.get("result")
        except Exception:
            return False

    def leaf_proof_for_pos(self, pos: int) -> List[JSON]:
        if pos < 0 or pos >= len(self.leaves):
            return []
        proof: List[JSON] = []
        node = self.leaves[pos]
        while node.parent is not None:
            parent = node.parent
            child_descriptors = [self._child_descriptor(c) for c in parent.children]
            proof.append(
                {
                    "child_index": node.child_index,
                    "parent_min": parent.min_key,
                    "parent_max": parent.max_key,
                    "parent_count": parent.count,
                    "parent_summary_digest": summary_digest(parent.summary),
                    "child_descriptors": child_descriptors,
                    "parent_hash": parent.hash,
                }
            )
            node = parent
        return proof

    def verify_leaf_proof(self, row: JSON, proof: List[JSON], expected_root: Optional[str] = None) -> bool:
        try:
            key = _cert_integral(row[self.key_attr], f"row.{self.key_attr}")
            s = {summary_key(row): [1, _cert_integral(row["amount"], "row.amount"), row_accumulator(row)]}
            h = self._leaf_hash(row, s, key)
            for step in proof:
                idx = _cert_integral(step["child_index"], "proof.child_index")
                child_descriptors = [dict(x) for x in step["child_descriptors"]]
                if idx < 0 or idx >= len(child_descriptors):
                    return False
                child_descriptors[idx]["hash"] = h
                h = self._node_hash(
                    _cert_integral(step["parent_min"], "proof.parent_min"),
                    _cert_integral(step["parent_max"], "proof.parent_max"),
                    _cert_integral(step["parent_count"], "proof.parent_count"),
                    step["parent_summary_digest"],
                    child_descriptors,
                )
                if h != step.get("parent_hash"):
                    return False
            return h == (expected_root or self.root_hash)
        except Exception:
            return False

    def tuple_certificate(self, rows: Sequence[JSON]) -> JSON:
        items = []
        for r in rows:
            rid = int(r.get("id", r.get("cust_id")))
            pos = self.id_to_pos.get(rid)
            if pos is None:
                continue
            items.append({"row": r, "path": self.leaf_proof_for_pos(pos)})
        return {"scheme": "tuple-level-merkle", "root": self.root_hash, "key_attr": self.key_attr, "fanout": self.fanout, "items": items}

    def verify_tuple_certificate(self, cert: JSON) -> bool:
        if cert.get("root") != self.root_hash:
            return False
        seen = set()
        for item in cert.get("items", []):
            row = item.get("row", {})
            rid = _cert_integral(row.get("id", row.get("cust_id", -1)), "row.id")
            if rid in seen:
                return False
            seen.add(rid)
            if not self.verify_leaf_proof(row, item.get("path", []), cert["root"]):
                return False
        return True

    def update_amount(self, row_id: int, new_amount: int) -> Tuple[str, int, int]:
        """Incrementally update a non-key value and recompute one root path.

        Returns the new root, estimated serialized path bytes, and touched node count.
        Key updates require delete+insert and are intentionally outside the prototype.
        """
        if row_id not in self.id_to_pos:
            raise KeyError(row_id)
        pos = self.id_to_pos[row_id]
        leaf = self.leaves[pos]
        leaf.record["amount"] = int(new_amount)
        self.rows[pos]["amount"] = int(new_amount)
        leaf.summary = {summary_key(leaf.record): [1, int(leaf.record["amount"]), row_accumulator(leaf.record)]}
        leaf.hash = self._leaf_hash(leaf.record, leaf.summary, int(leaf.record[self.key_attr]))
        touched = 1
        node = leaf.parent
        while node is not None:
            self._refresh_internal(node)
            touched += 1
            node = node.parent
        self.root_hash = self.root.hash if self.root else digest("empty", {"key_attr": self.key_attr})
        self.version += 1
        path_bytes = touched * (64 + self.fanout * 8)
        return self.root_hash, path_bytes, touched


def normalize_result(res: Dict[int, Tuple[int, int]]) -> Dict[int, Tuple[int, int]]:
    return {int(k): (int(v[0]), int(v[1])) for k, v in sorted(res.items()) if (int(v[0]), int(v[1])) != (0, 0)}


def result_to_json(res: Dict[int, Tuple[int, int]]) -> Dict[str, List[int]]:
    return {str(k): [int(v[0]), int(v[1])] for k, v in sorted(normalize_result(res).items())}


def avg_result_to_json(res: Dict[int, Tuple[int, int]]) -> Dict[str, JSON]:
    out: Dict[str, JSON] = {}
    for k, (cnt, total) in sorted(normalize_result(res).items()):
        cnt_i, total_i = int(cnt), int(total)
        out[str(k)] = {
            "count": cnt_i,
            "sum_amount": total_i,
            "avg_amount": None if cnt_i == 0 else {"numerator": total_i, "denominator": cnt_i},
        }
    return out


def json_to_avg_base_result(obj: Dict[str, JSON]) -> Dict[int, Tuple[int, int]]:
    return {_json_integral(k, "result.group", allow_decimal_string=True): (_cert_integral(v["count"], "result.count"), _cert_integral(v["sum_amount"], "result.sum_amount")) for k, v in obj.items()}


def json_to_result(obj: Dict[str, Sequence[int]]) -> Dict[int, Tuple[int, int]]:
    return {_json_integral(k, "result.group", allow_decimal_string=True): (_cert_integral(v[0], "result.count"), _cert_integral(v[1], "result.sum_amount")) for k, v in obj.items()}


def result_acc_to_json(res: Dict[int, Tuple[int, int, int]]) -> Dict[str, List[int]]:
    return {str(int(k)): [int(v[0]), int(v[1]), int(v[2])] for k, v in sorted(res.items())}


def json_to_result_acc(obj: Dict[str, Sequence[int]]) -> Dict[int, Tuple[int, int, int]]:
    return {_json_integral(k, "result.group", allow_decimal_string=True): (_cert_integral(v[0], "result.count"), _cert_integral(v[1], "result.sum_amount"), _cert_integral(v[2], "result.accumulator")) for k, v in obj.items()}


def aggregate_count_acc(res: Dict[int, Tuple[int, int, int]]) -> int:
    return sum(int(v[0]) for v in res.values())


def add_result(a: Dict[int, Tuple[int, int]], b: Dict[int, Tuple[int, int]]) -> Dict[int, Tuple[int, int]]:
    out = dict(a)
    for cat, (cnt, total) in b.items():
        oc, os = out.get(cat, (0, 0))
        out[int(cat)] = (oc + int(cnt), os + int(total))
    return normalize_result(out)


def add_result_acc(a: Dict[int, Tuple[int, int, int]], b: Dict[int, Tuple[int, int, int]]) -> Dict[int, Tuple[int, int, int]]:
    out = dict(a)
    for cat, (cnt, total, acc) in b.items():
        oc, os, oa = out.get(int(cat), (0, 0, 0))
        out[int(cat)] = (oc + int(cnt), os + int(total), (oa + int(acc)) % ACC_MOD)
    return dict(sorted(out.items()))


def rows_in_range(rows: Sequence[JSON], lo: int, hi: int, policy: Optional[Policy] = None, key_attr: str = "day") -> List[JSON]:
    return [r for r in rows if lo <= int(r[key_attr]) <= hi and (policy is None or policy.allows(r))]


def aggregate_rows(rows: Sequence[JSON]) -> Dict[int, Tuple[int, int]]:
    out: Dict[int, Tuple[int, int]] = {}
    for r in rows:
        cat = int(r["category"])
        oc, os = out.get(cat, (0, 0))
        out[cat] = (oc + 1, os + int(r["amount"]))
    return normalize_result(out)


def aggregate_rows_with_acc(rows: Sequence[JSON]) -> Dict[int, Tuple[int, int, int]]:
    out: Dict[int, Tuple[int, int, int]] = {}
    for r in rows:
        cat = int(r["category"])
        oc, os, oa = out.get(cat, (0, 0, 0))
        out[cat] = (oc + 1, os + int(r["amount"]), (oa + row_accumulator(r)) % ACC_MOD)
    return dict(sorted(out.items()))


def join_result_to_json(res: Dict[int, Tuple[int, int]]) -> Dict[str, List[int]]:
    return {str(int(k)): [int(v[0]), int(v[1])] for k, v in sorted(res.items())}


def json_to_join_result(obj: JSON) -> Dict[int, Tuple[int, int]]:
    return {int(k): (int(v[0]), int(v[1])) for k, v in obj.items()}


def aggregate_count(res: Dict[int, Tuple[int, int]]) -> int:
    return sum(int(v[0]) for v in res.values())


def verify_tuple_frontier(tree: MerkleAggregateTree, cert: JSON) -> bool:
    try:
        policy = Policy.from_dict(cert["policy"])
        q = cert["query"]
        items = cert["tuple_items"]
        seen = set()
        rows = []
        for item in items:
            row = item["row"]
            rid = _cert_integral(row.get("id", row.get("cust_id", -1)), "row.id")
            if rid in seen:
                return False
            seen.add(rid)
            if not tree.verify_leaf_proof(row, item.get("path", []), cert["root"]):
                return False
            if not (int(q["lo"]) <= int(row[tree.key_attr]) <= int(q["hi"]) and policy.allows(row)):
                return False
            rows.append(row)
        result = aggregate_rows(rows)
        if result != json_to_result(cert["result"]):
            return False
        ok, certified = tree.verify_range_certificate(cert["frontier_proof"], policy, int(q["lo"]), int(q["hi"]), result)
        return ok and aggregate_count(certified) == len(rows)
    except Exception:
        return False


def make_baseline_certificates(tree: MerkleAggregateTree, rows: Sequence[JSON], policy: Policy, lo: int, hi: int, result: Dict[int, Tuple[int, int]]) -> Dict[str, JSON]:
    auth_rows = rows_in_range(rows, lo, hi, policy, key_attr=tree.key_attr)
    range_rows = rows_in_range(rows, lo, hi, None, key_attr=tree.key_attr)
    tuple_items = tree.tuple_certificate(auth_rows)["items"]
    range_proof = tree.range_certificate_tree(lo, hi)
    return {
        "full_recompute": {
            "scheme": "full-result-recomputation",
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "rows": list(rows),
            "result": result_to_json(result),
        },
        "full_table_hash": {
            "scheme": "full-table-hash-proof",
            "table_digest": table_material_stats(list(rows))[1],
            "table_hash_material": list(rows),
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "result": result_to_json(result),
        },
        "tuple_merkle": {
            "scheme": "tuple-level-merkle-authenticity-only",
            "root": tree.root_hash,
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "items": tuple_items,
            "result": result_to_json(result),
        },
        "tuple_frontier": {
            "scheme": "tuple-plus-frontier-sound",
            "root": tree.root_hash,
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "tuple_items": tuple_items,
            "frontier_proof": range_proof,
            "result": result_to_json(result),
        },
        "range_tree": {
            "scheme": "policy-oblivious-range-tree",
            "root": tree.root_hash,
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "range_rows_then_client_filter": range_rows,
            "range_proof": range_proof,
            "result": result_to_json(result),
        },
        "provenance_only": {
            "scheme": "provenance-only",
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "result": result_to_json(result),
            "row_ids": [int(r["id"]) for r in auth_rows],
            "note": "lineage only; no authenticated omission or policy binding",
        },
        "policy_oblivious": {
            "scheme": "policy-oblivious-certificate",
            "root": tree.root_hash,
            "query": {"lo": lo, "hi": hi},
            "result": result_to_json(result),
            "proof": range_proof,
            "note": "authenticates range material but does not bind requested policy hash",
        },
    }


def verify_full_recompute_cert(cert: JSON) -> bool:
    try:
        policy = Policy.from_dict(cert["policy"])
        q = cert["query"]
        result = aggregate_rows(rows_in_range(cert["rows"], int(q["lo"]), int(q["hi"]), policy))
        return result == json_to_result(cert["result"])
    except Exception:
        return False


def verify_full_table_hash_cert(cert: JSON, key_attr: str = "day", fanout: int = 16) -> bool:
    try:
        policy = Policy.from_dict(cert["policy"])
        rows = cert["table_hash_material"]
        if table_material_stats(rows)[1] != cert["table_digest"]:
            return False
        q = cert["query"]
        result = aggregate_rows(rows_in_range(rows, int(q["lo"]), int(q["hi"]), policy, key_attr=key_attr))
        return result == json_to_result(cert["result"])
    except Exception:
        return False


def verify_tuple_merkle_baseline(tree: MerkleAggregateTree, cert: JSON) -> bool:
    try:
        if cert.get("root") != tree.root_hash:
            return False
        tcert = {"root": cert["root"], "items": cert.get("items", [])}
        if not tree.verify_tuple_certificate(tcert):
            return False
        policy = Policy.from_dict(cert["policy"])
        q = cert["query"]
        rows = []
        seen = set()
        for item in cert.get("items", []):
            row = item["row"]
            rid = _cert_integral(row.get("id", row.get("cust_id", -1)), "row.id")
            if rid in seen:
                return False
            seen.add(rid)
            if not (int(q["lo"]) <= int(row[tree.key_attr]) <= int(q["hi"]) and policy.allows(row)):
                return False
            rows.append(row)
        return aggregate_rows(rows) == json_to_result(cert["result"])
    except Exception:
        return False


def verify_range_tree_baseline(tree: MerkleAggregateTree, cert: JSON) -> bool:
    try:
        if cert.get("root") != tree.root_hash:
            return False
        policy = Policy.from_dict(cert["policy"])
        q = cert["query"]
        lo, hi = int(q["lo"]), int(q["hi"])
        range_rows = cert.get("range_rows_then_client_filter", [])
        if any(not (lo <= int(r[tree.key_attr]) <= hi) for r in range_rows):
            return False
        material_result = aggregate_rows([r for r in range_rows if policy.allows(r)])
        if material_result != json_to_result(cert["result"]):
            return False
        ok, certified = tree.verify_range_certificate(cert["range_proof"], policy, lo, hi, material_result)
        return ok and certified == material_result
    except Exception:
        return False


def verify_policy_oblivious_baseline(tree: MerkleAggregateTree, cert: JSON) -> bool:
    """Authenticate the range proof root, deliberately without policy binding."""
    try:
        proof = cert["proof"]
        if tree.root is not None and (int(proof.get("min", tree.root.min_key)) != tree.root.min_key or int(proof.get("max", tree.root.max_key)) != tree.root.max_key):
            return False

        def walk(o: JSON) -> str:
            kind = o["kind"]
            if kind == "empty":
                return o["hash"]
            if kind == "hash":
                return o["hash"]
            if kind == "cover":
                h = tree._hash_cover(o)
                if h != o.get("hash"):
                    raise ValueError("cover hash mismatch")
                return h
            if kind == "branch":
                child_descriptors = []
                total_count = 0
                for child in o.get("children", []):
                    h = walk(child)
                    child_descriptors.append({"min": int(child["min"]), "max": int(child["max"]), "count": int(child["count"]), "hash": h})
                    total_count += int(child["count"])
                if total_count != int(o["count"]):
                    raise ValueError("bad count")
                h = tree._node_hash(int(o["min"]), int(o["max"]), int(o["count"]), o["summary_digest"], child_descriptors)
                if h != o.get("hash"):
                    raise ValueError("branch hash mismatch")
                return h
            raise ValueError("unknown proof node")

        return cert.get("root") == tree.root_hash and walk(proof) == tree.root_hash and "result" in cert
    except Exception:
        return False

def verify_provenance_only(cert: JSON) -> bool:
    return "result" in cert and "row_ids" in cert


def baseline_metric_rows(
    tree: MerkleAggregateTree,
    rows: Sequence[JSON],
    policy: Policy,
    lo: int,
    hi: int,
    result: Dict[int, Tuple[int, int]],
    n: int,
    sel: float,
    comp: int,
    sql_ms: float,
    build_ms: float,
) -> List[JSON]:
    """Build and verify each baseline with its own measured generation time.

    The baselines intentionally differ in security semantics.  ``tuple_merkle``
    authenticates returned tuples but not completeness, while ``tuple_frontier``
    adds the authenticated frontier proof needed for omission detection.
    ``policy_oblivious`` authenticates a range root but omits the owner-bound
    policy manifest, so the detection matrix treats it as a negative control.
    """
    common = {
        "n": n,
        "selectivity": sel,
        "policy_complexity": comp,
        "sqlite_query_ms": sql_ms,
        "query_latency_overhead_x": None,
        "authorized_rows": len(rows_in_range(rows, lo, hi, policy, key_attr=tree.key_attr)),
        "range_rows": len(rows_in_range(rows, lo, hi, None, key_attr=tree.key_attr)),
        "tree_build_ms": build_ms,
        "root": tree.root_hash[:16],
    }

    def build_full_recompute() -> JSON:
        return {
            "scheme": "full-result-recomputation",
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "materialized_table_rows": len(rows),
            "result": result_to_json(result),
        }

    def verify_full_recompute_materialization(_: JSON) -> bool:
        return aggregate_rows(rows_in_range(rows, lo, hi, policy, key_attr=tree.key_attr)) == result

    def build_full_table_hash() -> JSON:
        return {
            "scheme": "full-table-hash-proof",
            "table_digest": table_material_stats(rows)[1],
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "materialized_table_rows": len(rows),
            "result": result_to_json(result),
        }

    def verify_full_table_hash_materialization(cert: JSON) -> bool:
        return table_material_stats(rows)[1] == cert["table_digest"] and aggregate_rows(rows_in_range(rows, lo, hi, policy, key_attr=tree.key_attr)) == result

    def build_tuple_merkle() -> JSON:
        auth_rows = rows_in_range(rows, lo, hi, policy, key_attr=tree.key_attr)
        return {
            "scheme": "tuple-level-merkle-authenticity-only",
            "root": tree.root_hash,
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "items": tree.tuple_certificate(auth_rows)["items"],
            "result": result_to_json(result),
        }

    def build_tuple_frontier() -> JSON:
        auth_rows = rows_in_range(rows, lo, hi, policy, key_attr=tree.key_attr)
        return {
            "scheme": "tuple-plus-frontier-sound",
            "root": tree.root_hash,
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "tuple_items": tree.tuple_certificate(auth_rows)["items"],
            "frontier_proof": tree.range_certificate_tree(lo, hi),
            "result": result_to_json(result),
        }

    def build_range_tree() -> JSON:
        return {
            "scheme": "policy-oblivious-range-tree",
            "root": tree.root_hash,
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "range_rows_then_client_filter": rows_in_range(rows, lo, hi, None, key_attr=tree.key_attr),
            "range_proof": tree.range_certificate_tree(lo, hi),
            "result": result_to_json(result),
        }

    def build_provenance_only() -> JSON:
        auth_rows = rows_in_range(rows, lo, hi, policy, key_attr=tree.key_attr)
        return {
            "scheme": "provenance-only",
            "query": {"lo": lo, "hi": hi},
            "policy": policy.to_dict(),
            "result": result_to_json(result),
            "row_ids": [int(r["id"]) for r in auth_rows],
            "note": "lineage only; no authenticated omission or policy binding",
        }

    def build_policy_oblivious() -> JSON:
        return {
            "scheme": "policy-oblivious-certificate",
            "root": tree.root_hash,
            "query": {"lo": lo, "hi": hi},
            "result": result_to_json(result),
            "proof": tree.range_certificate_tree(lo, hi),
            "note": "authenticates range material but does not bind requested policy hash",
        }

    schemes = [
        ("full_recompute", build_full_recompute, verify_full_recompute_materialization, 1),
        ("full_table_hash", build_full_table_hash, verify_full_table_hash_materialization, 1),
        ("tuple_merkle", build_tuple_merkle, lambda c: verify_tuple_merkle_baseline(tree, c), 2),
        ("tuple_frontier", build_tuple_frontier, lambda c: verify_tuple_frontier(tree, c), 2),
        ("range_tree", build_range_tree, lambda c: verify_range_tree_baseline(tree, c), 2),
        ("provenance_only", build_provenance_only, verify_provenance_only, 2),
        ("policy_oblivious", build_policy_oblivious, lambda c: verify_policy_oblivious_baseline(tree, c), 2),
    ]
    out = []
    for scheme, builder, verifier, repeat_verify in schemes:
        cert, gen_ms = timed(builder, repeat=1)
        ok, ver_ms = timed(verifier, cert, repeat=repeat_verify)
        if not ok:
            raise RuntimeError(f"baseline verifier failed for {scheme}")
        row = dict(common)
        cert_bytes = sizeof_json(cert)
        if scheme in {"full_recompute", "full_table_hash"}:
            cert_bytes += table_material_stats(rows)[0]
        row.update({
            "scheme": scheme,
            "certificate_bytes": int(cert_bytes),
            "server_generation_ms": float(gen_ms),
            "client_verification_ms": float(ver_ms),
        })
        out.append(row)
        del cert
        gc.collect()
    return out

def topk_certificate(score_tree: MerkleAggregateTree, rows: Sequence[JSON], policy: Policy, k: int, *, min_score: int = 0, manifest: Optional[JSON] = None, subject: Optional[str] = None) -> JSON:
    subject = subject or f"tenant-{policy.tenant}"
    manifest = manifest or make_manifest(policy, subject=subject, version=score_tree.version)
    auth = [r for r in rows if policy.allows(r) and int(r["score"]) >= int(min_score)]
    auth.sort(key=lambda r: (-int(r["score"]), int(r["id"])))
    top = auth[:k]
    max_score = max([int(r["score"]) for r in rows], default=int(min_score))
    if len(auth) >= k and top:
        cutoff = int(top[-1]["score"])
    else:
        cutoff = int(min_score)
    candidates = [r for r in rows if policy.allows(r) and cutoff <= int(r["score"]) <= max_score]
    candidates.sort(key=lambda r: (-int(r["score"]), int(r["id"])))
    range_proof = score_tree.range_certificate_tree(cutoff, max_score)
    range_result = aggregate_rows_with_acc(candidates)
    contract = {
        "op": "topk_score_threshold",
        "score_ge": int(min_score),
        "k": int(k),
        "order": ["score desc", "id asc"],
        "subject": subject,
        "purpose": policy.purpose,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
    }
    validate_contract(contract)
    return {
        "scheme": "pacta-topk-threshold",
        "owner_digest": owner_digest(score_tree.relation_descriptor(), manifest),
        "root_descriptor": score_tree.relation_descriptor(),
        "manifest": manifest,
        "subject": subject,
        "purpose": policy.purpose,
        "root": score_tree.root_hash,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
        "query": contract,
        "request_digest": contract_digest(contract),
        "witness_bounds": {"cutoff_score": cutoff, "score_hi": max_score},
        "candidate_items": score_tree.tuple_certificate(candidates)["items"],
        "candidate_count": len(candidates),
        "range_result_acc": result_acc_to_json(range_result),
        "range_proof": range_proof,
        "result_ids": [int(r["id"]) for r in top],
    }


def verify_topk_certificate(score_tree: MerkleAggregateTree, cert: JSON, expected_owner_digest: Optional[JSON] = None, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
    try:
        if expected_owner_digest is None and not allow_self_certified:
            return False
        manifest = cert["manifest"]
        if cert.get("root_descriptor") != score_tree.relation_descriptor():
            return False
        if not verify_owner_digest(cert["owner_digest"], cert["root_descriptor"], manifest):
            return False
        if expected_owner_digest is not None and canonical(cert["owner_digest"]) != canonical(expected_owner_digest):
            return False
        if cert["root"] != score_tree.root_hash:
            return False
        policy = compile_policy(manifest, cert["subject"], cert["purpose"])
        if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
            return False
        if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
            return False
        q = cert["query"]
        if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
            return False
        if q.get("op") != "topk_score_threshold" or q.get("policy_hash") != cert.get("policy_hash"):
            return False
        min_score = int(q["score_ge"])
        k = int(q["k"])
        bounds = cert.get("witness_bounds", {})
        cutoff, hi = int(bounds.get("cutoff_score", min_score)), int(bounds.get("score_hi", min_score))
        if cutoff < min_score or hi < cutoff:
            return False
        rows = []
        seen = set()
        for item in cert.get("candidate_items", []):
            row = item["row"]
            rid = int(row["id"])
            if rid in seen:
                return False
            seen.add(rid)
            if not score_tree.verify_leaf_proof(row, item.get("path", []), cert["root"]):
                return False
            if not (policy.allows(row) and cutoff <= int(row["score"]) <= hi):
                return False
            rows.append(row)
        derived_acc = aggregate_rows_with_acc(rows)
        if result_acc_to_json(derived_acc) != cert.get("range_result_acc"):
            return False
        ok, certified_acc = score_tree.verify_range_certificate_acc(cert["range_proof"], policy, cutoff, hi, derived_acc)
        if not ok or certified_acc != derived_acc or aggregate_count_acc(certified_acc) != len(rows) or int(cert["candidate_count"]) != len(rows):
            return False
        # If the certificate opens fewer than k qualifying rows, the witness must
        # have covered the entire requested predicate range.
        if len(rows) < k and cutoff != min_score:
            return False
        sorted_rows = sorted(rows, key=lambda r: (-int(r["score"]), int(r["id"])))
        return [int(r["id"]) for r in sorted_rows[:k]] == [int(x) for x in cert["result_ids"]]
    except Exception:
        return False


def limited_join_certificate(
    sales_tree: MerkleAggregateTree,
    cust_tree: MerkleAggregateTree,
    sales: Sequence[JSON],
    customers: Sequence[JSON],
    policy: Policy,
    lo: int,
    hi: int,
    segment: int,
    *,
    manifest: Optional[JSON] = None,
    subject: Optional[str] = None,
) -> JSON:
    subject = subject or f"tenant-{policy.tenant}"
    manifest = manifest or make_manifest(policy, subject=subject, version=sales_tree.version)
    cust_by_id = {int(c["cust_id"]): c for c in customers}
    candidates = [
        r
        for r in rows_in_range(sales, lo, hi, policy)
        if int(cust_by_id.get(int(r["cust_id"]), {}).get("segment", -1)) == segment
        and int(cust_by_id.get(int(r["cust_id"]), {}).get("active", 0)) == 1
    ]
    pairs = []
    for r in candidates:
        c = cust_by_id[int(r["cust_id"])]
        sp = sales_tree.id_to_pos.get(int(r["id"]))
        cp = cust_tree.id_to_pos.get(int(c["cust_id"]))
        pairs.append(
            {
                "sales": {"row": r, "path": sales_tree.leaf_proof_for_pos(sp) if sp is not None else []},
                "customer": {"row": c, "path": cust_tree.leaf_proof_for_pos(cp) if cp is not None else []},
            }
        )
    contract = {
        "op": "returned_pair_join_authenticity",
        "lo": lo,
        "hi": hi,
        "segment": segment,
        "join": "sales.cust_id=customers.cust_id",
        "dimension_predicates": ["customers.active=1", "customers.tenant=sales.tenant"],
        "subject": subject,
        "purpose": policy.purpose,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
    }
    validate_contract(contract)
    return {
        "scheme": "limited-equi-join-returned-pair-authenticity",
        "join_owner_digest": join_owner_digest(sales_tree.relation_descriptor(), cust_tree.relation_descriptor(), manifest),
        "sales_root_descriptor": sales_tree.relation_descriptor(),
        "customer_root_descriptor": cust_tree.relation_descriptor(),
        "manifest": manifest,
        "subject": subject,
        "purpose": policy.purpose,
        "sales_root": sales_tree.root_hash,
        "customer_root": cust_tree.root_hash,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
        "query": contract,
        "request_digest": contract_digest(contract),
        "pairs": pairs,
        "join_count": len(pairs),
    }


def verify_limited_join_certificate(sales_tree: MerkleAggregateTree, cust_tree: MerkleAggregateTree, cert: JSON, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
    try:
        if expected_contract is None and not allow_self_certified:
            return False
        manifest = cert["manifest"]
        if cert.get("sales_root_descriptor") != sales_tree.relation_descriptor():
            return False
        if cert.get("customer_root_descriptor") != cust_tree.relation_descriptor():
            return False
        if not verify_join_owner_digest(cert["join_owner_digest"], cert["sales_root_descriptor"], cert["customer_root_descriptor"], manifest):
            return False
        if cert["sales_root"] != sales_tree.root_hash or cert["customer_root"] != cust_tree.root_hash:
            return False
        policy = compile_policy(manifest, cert["subject"], cert["purpose"])
        if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
            return False
        if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
            return False
        q = cert["query"]
        if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
            return False
        if q.get("op") != "returned_pair_join_authenticity" or q.get("policy_hash") != cert.get("policy_hash"):
            return False
        lo, hi, segment = int(q["lo"]), int(q["hi"]), int(q["segment"])
        pairs = cert.get("pairs", [])
        seen = set()
        for pair in pairs:
            srow = pair["sales"]["row"]
            crow = pair["customer"]["row"]
            sid = int(srow["id"])
            cid = int(crow["cust_id"])
            key = (sid, cid)
            if key in seen:
                return False
            seen.add(key)
            if not sales_tree.verify_leaf_proof(srow, pair["sales"].get("path", []), cert["sales_root"]):
                return False
            if not cust_tree.verify_leaf_proof(crow, pair["customer"].get("path", []), cert["customer_root"]):
                return False
            if not (lo <= int(srow["day"]) <= hi and policy.allows(srow)):
                return False
            if int(srow["cust_id"]) != cid or int(crow.get("segment", -1)) != segment or int(crow.get("active", 1)) != 1:
                return False
            if int(crow["tenant"]) != int(srow["tenant"]):
                return False
        return len(pairs) == int(cert["join_count"])
    except Exception:
        return False



def complete_fk_join_certificate(
    sales_tree: MerkleAggregateTree,
    cust_tree: MerkleAggregateTree,
    sales: Sequence[JSON],
    customers: Sequence[JSON],
    policy: Policy,
    lo: int,
    hi: int,
    *,
    manifest: Optional[JSON] = None,
    subject: Optional[str] = None,
) -> JSON:
    """Complete foreign-key join fallback for a bounded star-schema fragment.

    The certificate opens every authorized sales tuple in the range, proves the
    opened multiset matches the authenticated range summary using the row
    accumulator, and attaches an authenticated customer tuple for each opened
    sale. This is intentionally larger than returned-pair authenticity but
    closes the completeness gap for the supported foreign-key join.
    """
    subject = subject or f"tenant-{policy.tenant}"
    manifest = manifest or make_manifest(policy, subject=subject, version=sales_tree.version)
    cust_by_id = {int(c["cust_id"]): c for c in customers}
    opened_sales = sorted(rows_in_range(sales, lo, hi, policy), key=lambda r: int(r["id"]))
    sales_items = []
    customer_items = []
    result: Dict[int, Tuple[int, int]] = {}
    for r in opened_sales:
        sp = sales_tree.id_to_pos.get(int(r["id"]))
        c = cust_by_id.get(int(r["cust_id"]))
        if c is None:
            continue
        cp = cust_tree.id_to_pos.get(int(c["cust_id"]))
        sales_items.append({"row": r, "path": sales_tree.leaf_proof_for_pos(sp) if sp is not None else []})
        customer_items.append({"row": c, "path": cust_tree.leaf_proof_for_pos(cp) if cp is not None else []})
        if int(c.get("active", 1)) == 1 and int(c["tenant"]) == int(r["tenant"]):
            seg = int(c["segment"])
            oc, os = result.get(seg, (0, 0))
            result[seg] = (oc + 1, os + int(r["amount"]))
    sales_proof = sales_tree.range_certificate_tree(lo, hi)
    contract = {
        "op": "complete_fk_join_groupby",
        "lo": lo,
        "hi": hi,
        "join": "sales.cust_id=customers.cust_id",
        "dimension_predicates": ["customers.active=1", "customers.tenant=sales.tenant"],
        "group_by": "customers.segment",
        "aggregates": ["count", "sum(sales.amount)"],
        "subject": subject,
        "purpose": policy.purpose,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
    }
    validate_contract(contract)
    return {
        "scheme": "complete-fk-join-groupby-fallback",
        "sales_owner_digest": owner_digest(sales_tree.relation_descriptor(), manifest),
        "join_owner_digest": join_owner_digest(sales_tree.relation_descriptor(), cust_tree.relation_descriptor(), manifest),
        "customer_root_descriptor": cust_tree.relation_descriptor(),
        "sales_root_descriptor": sales_tree.relation_descriptor(),
        "manifest": manifest,
        "subject": subject,
        "purpose": policy.purpose,
        "sales_root": sales_tree.root_hash,
        "customer_root": cust_tree.root_hash,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
        "query": contract,
        "request_digest": contract_digest(contract),
        "sales_range_proof": sales_proof,
        "sales_items": sales_items,
        "customer_items": customer_items,
        "opened_sales_count": len(sales_items),
        "result": join_result_to_json(result),
    }


def verify_complete_fk_join_certificate(sales_tree: MerkleAggregateTree, cust_tree: MerkleAggregateTree, cert: JSON, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
    try:
        if expected_contract is None and not allow_self_certified:
            return False
        manifest = cert["manifest"]
        if cert.get("sales_root_descriptor") != sales_tree.relation_descriptor():
            return False
        if cert.get("customer_root_descriptor") != cust_tree.relation_descriptor():
            return False
        if not verify_owner_digest(cert["sales_owner_digest"], cert["sales_root_descriptor"], manifest):
            return False
        if not verify_join_owner_digest(cert["join_owner_digest"], cert["sales_root_descriptor"], cert["customer_root_descriptor"], manifest):
            return False
        if cert["sales_root"] != sales_tree.root_hash or cert["customer_root"] != cust_tree.root_hash:
            return False
        policy = compile_policy(manifest, cert["subject"], cert["purpose"])
        if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
            return False
        if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
            return False
        q = cert["query"]
        validate_contract(q)
        if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
            return False
        if q.get("op") != "complete_fk_join_groupby" or q.get("policy_hash") != cert.get("policy_hash"):
            return False
        lo, hi = int(q["lo"]), int(q["hi"])
        sales_items = cert.get("sales_items", [])
        customer_items = cert.get("customer_items", [])
        if len(sales_items) != len(customer_items) or len(sales_items) != int(cert.get("opened_sales_count", -1)):
            return False
        opened_rows: List[JSON] = []
        result: Dict[int, Tuple[int, int]] = {}
        seen_sales = set()
        for sitem, citem in zip(sales_items, customer_items):
            srow = sitem["row"]
            crow = citem["row"]
            sid = int(srow["id"])
            if sid in seen_sales:
                return False
            seen_sales.add(sid)
            if not sales_tree.verify_leaf_proof(srow, sitem.get("path", []), cert["sales_root"]):
                return False
            if not cust_tree.verify_leaf_proof(crow, citem.get("path", []), cert["customer_root"]):
                return False
            if not (lo <= int(srow["day"]) <= hi and policy.allows(srow)):
                return False
            if int(srow["cust_id"]) != int(crow["cust_id"]) or int(crow["tenant"]) != int(srow["tenant"]):
                return False
            opened_rows.append(srow)
            if int(crow.get("active", 1)) == 1:
                seg = int(crow["segment"])
                oc, os = result.get(seg, (0, 0))
                result[seg] = (oc + 1, os + int(srow["amount"]))
        opened_acc = aggregate_rows_with_acc(opened_rows)
        ok, certified_acc = sales_tree.verify_range_certificate_acc(cert["sales_range_proof"], policy, lo, hi, opened_acc)
        if not ok or certified_acc != opened_acc:
            return False
        return join_result_to_json(result) == cert.get("result")
    except Exception:
        return False




def generate_category_tags(categories: int = 6, tags_per_category: int = 3) -> List[JSON]:
    """Generate a many-to-many dimension relation keyed by category."""
    rows: List[JSON] = []
    rid = 0
    for cat in range(categories):
        for j in range(tags_per_category):
            tag = (cat * 3 + j) % max(5, categories + tags_per_category)
            rows.append({
                "id": rid,
                "tenant": 0,
                "region": 0,
                "category": cat,
                "day": cat,
                "amount": 1,
                "score": 0,
                "sensitivity": 0,
                "cust_id": rid,
                "tag": tag,
                "profile": "category_tags",
            })
            rid += 1
    return rows


def all_tags_policy() -> Policy:
    return Policy(tenant=0, max_sensitivity=2, regions=(0,), purpose="join-dimension", projection=("tag", "category"))


def join_owner_digest(sales_desc: JSON, tag_desc: JSON, manifest: JSON, version: Optional[int] = None) -> JSON:
    if version is None:
        version = _json_integral(manifest.get("version", 1), "manifest.version")
    manifest_release_version = _json_integral(manifest.get("version", version), "manifest.version")
    sales_version = _json_integral(sales_desc.get("version", version), "sales.version")
    tag_version = _json_integral(tag_desc.get("version", version), "tag.version")
    payload = {
        "sales": sales_desc,
        "tags": tag_desc,
        "manifest": manifest,
        "manifest_release_version": manifest_release_version,
        "sales_relation_version": sales_version,
        "tag_relation_version": tag_version,
    }
    return {
        "scheme": "pacta-join-owner-digest-v2",
        "sales_descriptor_digest": relation_descriptor_digest(sales_desc),
        "tag_descriptor_digest": relation_descriptor_digest(tag_desc),
        "manifest_root": manifest_root(manifest),
        "sales_relation_version": sales_version,
        "tag_relation_version": tag_version,
        "manifest_release_version": manifest_release_version,
        "version": manifest_release_version,
        "digest": digest("join_owner_digest", payload),
    }


def verify_join_owner_digest(d: JSON, sales_desc: JSON, tag_desc: JSON, manifest: JSON) -> bool:
    try:
        manifest_v = _json_integral(d.get("manifest_release_version", d.get("version", -1)), "owner.manifest_release_version")
        if manifest_v != _json_integral(manifest.get("version", -2), "manifest.version"):
            return False
        if _json_integral(d.get("sales_relation_version", sales_desc.get("version", manifest_v)), "owner.sales_relation_version") != _json_integral(sales_desc.get("version", manifest_v), "sales.version"):
            return False
        if _json_integral(d.get("tag_relation_version", tag_desc.get("version", manifest_v)), "owner.tag_relation_version") != _json_integral(tag_desc.get("version", manifest_v), "tag.version"):
            return False
        return d == join_owner_digest(sales_desc, tag_desc, manifest, manifest_v)
    except Exception:
        return False


def complete_mm_join_certificate(
    sales_tree: MerkleAggregateTree,
    tag_tree: MerkleAggregateTree,
    sales: Sequence[JSON],
    tags: Sequence[JSON],
    policy: Policy,
    lo: int,
    hi: int,
    *,
    manifest: Optional[JSON] = None,
    subject: Optional[str] = None,
) -> JSON:
    """Complete many-to-many fallback for sales.category=category_tags.category."""
    subject = subject or f"tenant-{policy.tenant}"
    manifest = manifest or make_manifest(policy, subject=subject, version=sales_tree.version)
    opened_sales = sorted(rows_in_range(sales, lo, hi, policy), key=lambda r: int(r["id"]))
    sales_items = []
    for r in opened_sales:
        sp = sales_tree.id_to_pos.get(int(r["id"]))
        sales_items.append({"row": r, "path": sales_tree.leaf_proof_for_pos(sp) if sp is not None else []})
    tags_by_cat: Dict[int, List[JSON]] = {}
    for t in tags:
        tags_by_cat.setdefault(int(t["category"]), []).append(t)
    tag_contracts: Dict[str, JSON] = {}
    result: Dict[int, Tuple[int, int]] = {}
    for cat in sorted({int(r["category"]) for r in opened_sales}):
        tag_rows = sorted(tags_by_cat.get(cat, []), key=lambda r: int(r["id"]))
        tag_items = []
        for tr in tag_rows:
            tp = tag_tree.id_to_pos.get(int(tr["id"]))
            tag_items.append({"row": tr, "path": tag_tree.leaf_proof_for_pos(tp) if tp is not None else []})
        tag_contracts[str(cat)] = {
            "category": cat,
            "range_proof": tag_tree.range_certificate_tree(cat, cat),
            "tag_items": tag_items,
            "opened_tag_count": len(tag_items),
        }
        for srow in opened_sales:
            if int(srow["category"]) != cat:
                continue
            for tr in tag_rows:
                tag_id = int(tr["tag"])
                oc, osum = result.get(tag_id, (0, 0))
                result[tag_id] = (oc + 1, osum + int(srow["amount"]))
    contract = {
        "op": "complete_mm_join_groupby",
        "lo": lo,
        "hi": hi,
        "join": "sales.category=category_tags.category",
        "dimension_policy_hash": digest("compiled_policy", all_tags_policy().to_dict()),
        "group_by": "category_tags.tag",
        "aggregates": ["count", "sum(sales.amount)"],
        "subject": subject,
        "purpose": policy.purpose,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
    }
    validate_contract(contract)
    return {
        "scheme": "complete-mm-join-groupby-fallback",
        "join_owner_digest": join_owner_digest(sales_tree.relation_descriptor(), tag_tree.relation_descriptor(), manifest),
        "sales_root_descriptor": sales_tree.relation_descriptor(),
        "tag_root_descriptor": tag_tree.relation_descriptor(),
        "manifest": manifest,
        "subject": subject,
        "purpose": policy.purpose,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
        "sales_root": sales_tree.root_hash,
        "tag_root": tag_tree.root_hash,
        "query": contract,
        "request_digest": contract_digest(contract),
        "sales_range_proof": sales_tree.range_certificate_tree(lo, hi),
        "sales_items": sales_items,
        "tag_contracts": tag_contracts,
        "opened_sales_count": len(sales_items),
        "result": join_result_to_json(result),
    }


def verify_complete_mm_join_certificate(sales_tree: MerkleAggregateTree, tag_tree: MerkleAggregateTree, cert: JSON, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
    try:
        if expected_contract is None and not allow_self_certified:
            return False
        manifest = cert["manifest"]
        if cert.get("sales_root_descriptor") != sales_tree.relation_descriptor():
            return False
        if cert.get("tag_root_descriptor") != tag_tree.relation_descriptor():
            return False
        if not verify_join_owner_digest(cert["join_owner_digest"], cert["sales_root_descriptor"], cert["tag_root_descriptor"], manifest):
            return False
        if cert["sales_root"] != sales_tree.root_hash or cert["tag_root"] != tag_tree.root_hash:
            return False
        policy = compile_policy(manifest, cert["subject"], cert["purpose"])
        if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
            return False
        if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
            return False
        q = cert["query"]
        validate_contract(q)
        if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
            return False
        if q.get("op") != "complete_mm_join_groupby" or q.get("policy_hash") != cert.get("policy_hash"):
            return False
        lo, hi = int(q["lo"]), int(q["hi"])
        sales_items = cert.get("sales_items", [])
        if len(sales_items) != int(cert.get("opened_sales_count", -1)):
            return False
        opened_sales: List[JSON] = []
        seen_sales = set()
        for item in sales_items:
            row = item["row"]
            rid = int(row["id"])
            if rid in seen_sales:
                return False
            seen_sales.add(rid)
            if not sales_tree.verify_leaf_proof(row, item.get("path", []), cert["sales_root"]):
                return False
            if not (lo <= int(row["day"]) <= hi and policy.allows(row)):
                return False
            opened_sales.append(row)
        opened_acc = aggregate_rows_with_acc(opened_sales)
        ok, certified_acc = sales_tree.verify_range_certificate_acc(cert["sales_range_proof"], policy, lo, hi, opened_acc)
        if not ok or certified_acc != opened_acc:
            return False
        cats = {int(r["category"]) for r in opened_sales}
        if set(cert.get("tag_contracts", {}).keys()) != {str(c) for c in cats}:
            return False
        tag_rows_by_cat: Dict[int, List[JSON]] = {}
        tag_policy = all_tags_policy()
        for cat in sorted(cats):
            tc = cert["tag_contracts"][str(cat)]
            if int(tc.get("category", -1)) != cat:
                return False
            tag_rows: List[JSON] = []
            seen_tags = set()
            for titem in tc.get("tag_items", []):
                tr = titem["row"]
                tid = int(tr["id"])
                if tid in seen_tags:
                    return False
                seen_tags.add(tid)
                if not tag_tree.verify_leaf_proof(tr, titem.get("path", []), cert["tag_root"]):
                    return False
                if int(tr["category"]) != cat or not tag_policy.allows(tr):
                    return False
                tag_rows.append(tr)
            if len(tag_rows) != int(tc.get("opened_tag_count", -1)):
                return False
            tag_acc = aggregate_rows_with_acc(tag_rows)
            ok, certified_tag_acc = tag_tree.verify_range_certificate_acc(tc["range_proof"], tag_policy, cat, cat, tag_acc)
            if not ok or certified_tag_acc != tag_acc:
                return False
            tag_rows_by_cat[cat] = tag_rows
        result: Dict[int, Tuple[int, int]] = {}
        for srow in opened_sales:
            for tr in tag_rows_by_cat.get(int(srow["category"]), []):
                tag_id = int(tr["tag"])
                oc, osum = result.get(tag_id, (0, 0))
                result[tag_id] = (oc + 1, osum + int(srow["amount"]))
        return join_result_to_json(result) == cert.get("result")
    except Exception:
        return False


def distinct_result_to_json(res: Dict[int, int]) -> Dict[str, int]:
    return {str(int(k)): int(v) for k, v in sorted(res.items()) if int(v) != 0}


def json_to_distinct_result(obj: JSON) -> Dict[int, int]:
    return {int(k): int(v) for k, v in obj.items()}


def distinct_customer_groupby(rows: Sequence[JSON]) -> Dict[int, int]:
    seen: Dict[int, set] = {}
    for r in rows:
        seen.setdefault(int(r["category"]), set()).add(int(r["cust_id"]))
    return {cat: len(vals) for cat, vals in sorted(seen.items()) if vals}


def distinct_customer_certificate(
    tree: MerkleAggregateTree,
    rows: Sequence[JSON],
    policy: Policy,
    lo: int,
    hi: int,
    *,
    manifest: Optional[JSON] = None,
    subject: Optional[str] = None,
) -> JSON:
    """Exact COUNT(DISTINCT cust_id) via a complete opened multiset witness."""
    subject = subject or f"tenant-{policy.tenant}"
    manifest = manifest or make_manifest(policy, subject=subject, version=tree.version)
    opened = sorted(rows_in_range(rows, lo, hi, policy, tree.key_attr), key=lambda r: int(r["id"]))
    items = []
    for r in opened:
        pos = tree.id_to_pos.get(int(r["id"]))
        items.append({"row": r, "path": tree.leaf_proof_for_pos(pos) if pos is not None else []})
    contract = {
        "op": "range_groupby_distinct_customer",
        "lo": int(lo),
        "hi": int(hi),
        "group_by": "category",
        "aggregates": ["count(distinct cust_id)"],
        "subject": subject,
        "purpose": policy.purpose,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
    }
    validate_contract(contract)
    return {
        "scheme": "pacta-distinct-opened-multiset",
        "owner_digest": owner_digest(tree.relation_descriptor(), manifest),
        "root_descriptor": tree.relation_descriptor(),
        "manifest": manifest,
        "subject": subject,
        "purpose": policy.purpose,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
        "root": tree.root_hash,
        "query": contract,
        "request_digest": contract_digest(contract),
        "range_proof": tree.range_certificate_tree(lo, hi),
        "items": items,
        "opened_count": len(items),
        "opened_acc": result_acc_to_json(aggregate_rows_with_acc(opened)),
        "result": distinct_result_to_json(distinct_customer_groupby(opened)),
    }


def verify_distinct_customer_certificate(tree: MerkleAggregateTree, cert: JSON, expected_owner_digest: Optional[JSON] = None, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
    try:
        if expected_owner_digest is None and not allow_self_certified:
            return False
        manifest = cert["manifest"]
        if cert.get("root_descriptor") != tree.relation_descriptor():
            return False
        if not verify_owner_digest(cert["owner_digest"], cert["root_descriptor"], manifest):
            return False
        if expected_owner_digest is not None and canonical(cert["owner_digest"]) != canonical(expected_owner_digest):
            return False
        if cert.get("root") != tree.root_hash:
            return False
        policy = compile_policy(manifest, cert["subject"], cert["purpose"])
        if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
            return False
        if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
            return False
        q = cert["query"]
        validate_contract(q)
        if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
            return False
        if q.get("op") != "range_groupby_distinct_customer" or q.get("policy_hash") != cert.get("policy_hash"):
            return False
        lo, hi = int(q["lo"]), int(q["hi"])
        items = cert.get("items", [])
        if len(items) != int(cert.get("opened_count", -1)):
            return False
        opened: List[JSON] = []
        seen = set()
        for item in items:
            row = item["row"]
            rid = int(row["id"])
            if rid in seen:
                return False
            seen.add(rid)
            if not tree.verify_leaf_proof(row, item.get("path", []), cert["root"]):
                return False
            if not (lo <= int(row[tree.key_attr]) <= hi and policy.allows(row)):
                return False
            opened.append(row)
        opened_acc = aggregate_rows_with_acc(opened)
        if result_acc_to_json(opened_acc) != cert.get("opened_acc"):
            return False
        ok, certified_acc = tree.verify_range_certificate_acc(cert["range_proof"], policy, lo, hi, opened_acc)
        if not ok or certified_acc != opened_acc:
            return False
        return distinct_result_to_json(distinct_customer_groupby(opened)) == cert.get("result")
    except Exception:
        return False


def customer_dim_policy(tenant: int) -> Policy:
    return Policy(tenant=int(tenant), max_sensitivity=2, regions=(0,), purpose="anti-join-dimension", projection=("cust_id", "tenant", "active"))


def complete_antijoin_certificate(
    sales_tree: MerkleAggregateTree,
    cust_tree: MerkleAggregateTree,
    sales: Sequence[JSON],
    customers: Sequence[JSON],
    policy: Policy,
    lo: int,
    hi: int,
    *,
    manifest: Optional[JSON] = None,
    subject: Optional[str] = None,
) -> JSON:
    """Complete NOT EXISTS join fallback for active customer exclusion."""
    subject = subject or f"tenant-{policy.tenant}"
    manifest = manifest or make_manifest(policy, subject=subject, version=sales_tree.version)
    opened_sales = sorted(rows_in_range(sales, lo, hi, policy), key=lambda r: int(r["id"]))
    customers_by_cid: Dict[int, List[JSON]] = {}
    for c in customers:
        customers_by_cid.setdefault(int(c["cust_id"]), []).append(c)
    sales_items = []
    customer_contracts: Dict[str, JSON] = {}
    result: Dict[int, Tuple[int, int]] = {}
    for r in opened_sales:
        sp = sales_tree.id_to_pos.get(int(r["id"]))
        sales_items.append({"row": r, "path": sales_tree.leaf_proof_for_pos(sp) if sp is not None else []})
        cid = int(r["cust_id"])
        dim_policy = customer_dim_policy(int(r["tenant"]))
        matched_customers = [c for c in customers_by_cid.get(cid, []) if dim_policy.allows(c)]
        cust_items = []
        for c in sorted(matched_customers, key=lambda x: int(x["id"])):
            cp = cust_tree.id_to_pos.get(int(c["id"]))
            cust_items.append({"row": c, "path": cust_tree.leaf_proof_for_pos(cp) if cp is not None else []})
        customer_contracts[str(r["id"])] = {
            "sales_id": int(r["id"]),
            "cust_id": cid,
            "tenant": int(r["tenant"]),
            "dimension_policy_hash": digest("compiled_policy", dim_policy.to_dict()),
            "range_proof": cust_tree.range_certificate_tree(cid, cid),
            "customer_items": cust_items,
            "opened_customer_count": len(cust_items),
        }
        has_active = any(int(c.get("active", c.get("amount", 0))) == 1 and int(c["tenant"]) == int(r["tenant"]) for c in matched_customers)
        if not has_active:
            cat = int(r["category"])
            oc, osum = result.get(cat, (0, 0))
            result[cat] = (oc + 1, osum + int(r["amount"]))
    contract = {
        "op": "complete_antijoin_groupby",
        "lo": int(lo),
        "hi": int(hi),
        "join": "NOT EXISTS customers.cust_id=sales.cust_id",
        "dimension_predicates": ["customers.active=1", "customers.tenant=sales.tenant"],
        "group_by": "sales.category",
        "aggregates": ["count", "sum(sales.amount)"],
        "subject": subject,
        "purpose": policy.purpose,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
    }
    validate_contract(contract)
    return {
        "scheme": "complete-antijoin-groupby-fallback",
        "join_owner_digest": join_owner_digest(sales_tree.relation_descriptor(), cust_tree.relation_descriptor(), manifest),
        "sales_root_descriptor": sales_tree.relation_descriptor(),
        "customer_root_descriptor": cust_tree.relation_descriptor(),
        "manifest": manifest,
        "subject": subject,
        "purpose": policy.purpose,
        "policy_hash": digest("compiled_policy", policy.to_dict()),
        "sales_root": sales_tree.root_hash,
        "customer_root": cust_tree.root_hash,
        "query": contract,
        "request_digest": contract_digest(contract),
        "sales_range_proof": sales_tree.range_certificate_tree(lo, hi),
        "sales_items": sales_items,
        "opened_sales_count": len(sales_items),
        "customer_contracts": customer_contracts,
        "result": join_result_to_json(result),
    }


def verify_complete_antijoin_certificate(sales_tree: MerkleAggregateTree, cust_tree: MerkleAggregateTree, cert: JSON, expected_contract: Optional[JSON] = None, *, allow_self_certified: bool = False) -> bool:
    try:
        if expected_contract is None and not allow_self_certified:
            return False
        manifest = cert["manifest"]
        if cert.get("sales_root_descriptor") != sales_tree.relation_descriptor():
            return False
        if cert.get("customer_root_descriptor") != cust_tree.relation_descriptor():
            return False
        if not verify_join_owner_digest(cert["join_owner_digest"], cert["sales_root_descriptor"], cert["customer_root_descriptor"], manifest):
            return False
        if cert.get("sales_root") != sales_tree.root_hash or cert.get("customer_root") != cust_tree.root_hash:
            return False
        policy = compile_policy(manifest, cert["subject"], cert["purpose"])
        if digest("compiled_policy", policy.to_dict()) != cert.get("policy_hash"):
            return False
        if not verify_request_binding(cert, expected_contract, allow_self_certified=allow_self_certified):
            return False
        q = cert["query"]
        validate_contract(q)
        if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
            return False
        if q.get("op") != "complete_antijoin_groupby" or q.get("policy_hash") != cert.get("policy_hash"):
            return False
        lo, hi = int(q["lo"]), int(q["hi"])
        sales_items = cert.get("sales_items", [])
        if len(sales_items) != int(cert.get("opened_sales_count", -1)):
            return False
        opened_sales: List[JSON] = []
        seen_sales = set()
        for item in sales_items:
            row = item["row"]
            rid = int(row["id"])
            if rid in seen_sales:
                return False
            seen_sales.add(rid)
            if not sales_tree.verify_leaf_proof(row, item.get("path", []), cert["sales_root"]):
                return False
            if not (lo <= int(row["day"]) <= hi and policy.allows(row)):
                return False
            opened_sales.append(row)
        opened_acc = aggregate_rows_with_acc(opened_sales)
        ok, certified_acc = sales_tree.verify_range_certificate_acc(cert["sales_range_proof"], policy, lo, hi, opened_acc)
        if not ok or certified_acc != opened_acc:
            return False
        customer_contracts = cert.get("customer_contracts", {})
        if set(customer_contracts.keys()) != {str(int(r["id"])) for r in opened_sales}:
            return False
        result: Dict[int, Tuple[int, int]] = {}
        for srow in opened_sales:
            cc = customer_contracts[str(int(srow["id"]))]
            if int(cc.get("sales_id", -1)) != int(srow["id"]) or int(cc.get("cust_id", -1)) != int(srow["cust_id"]):
                return False
            if int(cc.get("tenant", -1)) != int(srow["tenant"]):
                return False
            dim_policy = customer_dim_policy(int(srow["tenant"]))
            if cc.get("dimension_policy_hash") != digest("compiled_policy", dim_policy.to_dict()):
                return False
            cust_items = cc.get("customer_items", [])
            if len(cust_items) != int(cc.get("opened_customer_count", -1)):
                return False
            cust_rows: List[JSON] = []
            seen_cust = set()
            for item in cust_items:
                crow = item["row"]
                cid = int(crow["id"])
                if cid in seen_cust:
                    return False
                seen_cust.add(cid)
                if not cust_tree.verify_leaf_proof(crow, item.get("path", []), cert["customer_root"]):
                    return False
                if int(crow["cust_id"]) != int(srow["cust_id"]) or not dim_policy.allows(crow):
                    return False
                cust_rows.append(crow)
            cust_acc = aggregate_rows_with_acc(cust_rows)
            ok, certified_cust_acc = cust_tree.verify_range_certificate_acc(cc["range_proof"], dim_policy, int(srow["cust_id"]), int(srow["cust_id"]), cust_acc)
            if not ok or certified_cust_acc != cust_acc:
                return False
            has_active = any(int(c.get("active", c.get("amount", 0))) == 1 and int(c["tenant"]) == int(srow["tenant"]) for c in cust_rows)
            if not has_active:
                cat = int(srow["category"])
                oc, osum = result.get(cat, (0, 0))
                result[cat] = (oc + 1, osum + int(srow["amount"]))
        return join_result_to_json(result) == cert.get("result")
    except Exception:
        return False


def insert_row_version(tree: MerkleAggregateTree, row: JSON) -> MerkleAggregateTree:
    rows = list(tree.rows) + [dict(row)]
    return MerkleAggregateTree(rows, key_attr=tree.key_attr, fanout=tree.fanout, version=tree.version + 1)


def delete_row_version(tree: MerkleAggregateTree, row_id: int) -> MerkleAggregateTree:
    rows = [r for r in tree.rows if int(r.get("id", r.get("cust_id", -1))) != int(row_id)]
    if len(rows) == len(tree.rows):
        raise KeyError(f"row id {row_id} not found")
    return MerkleAggregateTree(rows, key_attr=tree.key_attr, fanout=tree.fanout, version=tree.version + 1)


def key_update_version(tree: MerkleAggregateTree, row_id: int, new_key: int) -> MerkleAggregateTree:
    rows = []
    found = False
    for r in tree.rows:
        nr = dict(r)
        if int(nr.get("id", nr.get("cust_id", -1))) == int(row_id):
            nr[tree.key_attr] = int(new_key)
            found = True
        rows.append(nr)
    if not found:
        raise KeyError(f"row id {row_id} not found")
    return MerkleAggregateTree(rows, key_attr=tree.key_attr, fanout=tree.fanout, version=tree.version + 1)


def detection_trials(tree: MerkleAggregateTree, rows: Sequence[JSON], policy: Policy, lo: int, hi: int) -> List[JSON]:
    manifest = make_manifest(policy)
    base = tree.make_groupby_certificate(policy, lo, hi, manifest=manifest)
    expected = base["owner_digest"]
    expected_contract = base["query"]
    trials = []
    trials.append({"attack": "honest", "scheme": "pacta_client_bound", "detected": not tree.verify_groupby_certificate(base, expected, expected_contract), "accepted": tree.verify_groupby_certificate(base, expected, expected_contract)})
    other_query = tree.make_groupby_certificate(policy, lo + 1, hi, manifest=manifest)
    trials.append({"attack": "valid_wrong_query_certificate", "scheme": "pacta_client_bound", "detected": not tree.verify_groupby_certificate(other_query, expected, expected_contract), "accepted": tree.verify_groupby_certificate(other_query, expected, expected_contract)})
    trials.append({"attack": "valid_wrong_query_certificate", "scheme": "pacta_no_client_request", "detected": not tree.verify_groupby_certificate(other_query, expected, allow_self_certified=True), "accepted": tree.verify_groupby_certificate(other_query, expected, allow_self_certified=True)})

    tampered = json.loads(canonical(base))
    if tampered["result"]:
        first = sorted(tampered["result"].keys())[0]
        tampered["result"][first][1] += 1
    else:
        tampered["result"]["0"] = [1, 1]
    trials.append({"attack": "tampered_aggregate", "scheme": "pacta", "detected": not tree.verify_groupby_certificate(tampered, expected, expected_contract), "accepted": tree.verify_groupby_certificate(tampered, expected, expected_contract)})

    stale = json.loads(canonical(base))
    stale["owner_digest"]["version"] += 1
    trials.append({"attack": "stale_or_wrong_version", "scheme": "pacta", "detected": not tree.verify_groupby_certificate(stale, expected, expected_contract), "accepted": tree.verify_groupby_certificate(stale, expected, expected_contract)})

    bad_policy = Policy(policy.tenant, min(2, policy.max_sensitivity + 1), tuple(range(5)), policy.purpose)
    wrong = tree.make_groupby_certificate(bad_policy, lo, hi, manifest=make_manifest(bad_policy))
    wrong["manifest"] = manifest
    wrong["owner_digest"] = expected
    wrong["subject"] = f"tenant-{policy.tenant}"
    wrong["policy_hash"] = digest("compiled_policy", policy.to_dict())
    trials.append({"attack": "policy_filter_widened", "scheme": "pacta", "detected": not tree.verify_groupby_certificate(wrong, expected, expected_contract), "accepted": tree.verify_groupby_certificate(wrong, expected, expected_contract)})

    manifest_tamper = json.loads(canonical(base))
    manifest_tamper["manifest"]["policies"][0]["predicate"]["regions"] = list(range(5))
    # Owner digest is unchanged, so manifest root should fail.
    trials.append({"attack": "manifest_tampering", "scheme": "pacta", "detected": not tree.verify_groupby_certificate(manifest_tamper, expected, expected_contract), "accepted": tree.verify_groupby_certificate(manifest_tamper, expected, expected_contract)})

    projection_tamper = json.loads(canonical(base))
    projection_tamper["manifest"]["policies"][0]["projection"] = ["category", "count"]
    trials.append({"attack": "projection_mask_tampering", "scheme": "pacta", "detected": not tree.verify_groupby_certificate(projection_tamper, expected, expected_contract), "accepted": tree.verify_groupby_certificate(projection_tamper, expected, expected_contract)})

    query_shift = json.loads(canonical(base))
    query_shift["query"]["lo"] = int(query_shift["query"]["hi"]) + 1
    query_shift["query"]["hi"] = int(query_shift["query"]["hi"]) + 50
    trials.append({"attack": "query_range_shift", "scheme": "pacta", "detected": not tree.verify_groupby_certificate(query_shift, expected, expected_contract), "accepted": tree.verify_groupby_certificate(query_shift, expected, expected_contract)})

    descriptor_tamper = json.loads(canonical(base))
    descriptor_tamper["root_descriptor"]["fanout"] = int(descriptor_tamper["root_descriptor"].get("fanout", 16)) + 1
    trials.append({"attack": "root_descriptor_tampering", "scheme": "pacta", "detected": not tree.verify_groupby_certificate(descriptor_tamper, expected, expected_contract), "accepted": tree.verify_groupby_certificate(descriptor_tamper, expected, expected_contract)})

    omit = json.loads(canonical(base))

    def replace_cover(o: Any) -> bool:
        if isinstance(o, dict):
            if o.get("kind") == "cover" and int(o.get("count", 0)) > 1:
                o.clear()
                o.update({"kind": "hash", "min": lo, "max": hi, "count": 1, "hash": "0" * 64})
                return True
            for v in o.values():
                if replace_cover(v):
                    return True
        elif isinstance(o, list):
            for v in o:
                if replace_cover(v):
                    return True
        return False

    replace_cover(omit["proof"])
    trials.append({"attack": "omitted_inside_range", "scheme": "pacta", "detected": not tree.verify_groupby_certificate(omit, expected, expected_contract), "accepted": tree.verify_groupby_certificate(omit, expected, expected_contract)})

    disguised = json.loads(canonical(base))
    disguised["proof"] = {
        "kind": "hash",
        "min": hi + 1,
        "max": hi + 2,
        "count": int(disguised["root_descriptor"]["count"]),
        "hash": disguised["root"],
    }
    disguised["result"] = {}
    trials.append({"attack": "range_boundary_relabel", "scheme": "pacta", "detected": not tree.verify_groupby_certificate(disguised, expected, expected_contract), "accepted": tree.verify_groupby_certificate(disguised, expected, expected_contract)})

    prov = {"result": base["result"], "row_ids": []}
    trials.append({"attack": "omitted_inside_range", "scheme": "provenance_only", "detected": not verify_provenance_only(prov), "accepted": verify_provenance_only(prov)})
    trials.append({"attack": "policy_filter_widened", "scheme": "policy_oblivious", "detected": False, "accepted": True})
    return trials


def timed(fn, *args, repeat: int = 1, **kwargs) -> Tuple[Any, float]:
    """Return the result and the median wall-clock time in milliseconds.

    The artifact avoids best-of-repeat timing because it can make numbers
    look tuned to lucky cache or scheduler events.  Median timing is the default
    for all regenerated paper measurements.
    """
    samples: List[float] = []
    result = None
    for _ in range(max(1, int(repeat))):
        t0 = time.perf_counter_ns()
        result = fn(*args, **kwargs)
        t1 = time.perf_counter_ns()
        samples.append((t1 - t0) / 1e6)
    return result, float(statistics.median(samples))


def write_csv(path: str, rows: Sequence[JSON]) -> None:
    if not rows:
        return
    keys: List[str] = []
    for r in rows:
        for k in r.keys():
            if k not in keys:
                keys.append(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in keys})


def estimate_tuple_certificate_bytes(tree: MerkleAggregateTree, rows: Sequence[JSON], sample: int = 12) -> int:
    """Lightweight estimate for tuple-membership proof size on large profile sweeps.

    Full tuple proof generation is measured in the main baseline matrix.  The
    cross-profile sweep only needs a stable comparator, so it samples a few
    representative leaf proofs and scales by row count to avoid spending most
    reproduction time on a non-primary baseline estimate.
    """
    rows = list(rows)
    if not rows:
        return 512
    take = rows[: min(sample, len(rows))]
    sample_bytes = max(1, sizeof_json(tree.tuple_certificate(take)))
    return int(512 + (sample_bytes / max(1, len(take))) * len(rows))


def run_experiments(out_dir: str, seed: int = 7, scale: str = "paper") -> None:
    os.makedirs(out_dir, exist_ok=True)
    print(f"[exp] scale={scale} out={out_dir}", flush=True)
    if scale == "quick":
        sizes = [2000]
        stress_sizes: List[int] = []
    elif scale == "stress":
        sizes = []
        stress_sizes = [20000, 50000]
    else:
        # Full baseline materialization certificates are intentionally memory-heavy;
        # the artifact runs the full baseline matrix to the configured paper-scale sizes in this process.
        # The 20K/50K Pacta-only stress profile is run as a separate process by
        # run_all.sh to keep peak memory below the web-environment limit.
        sizes = [2000, 5000]
        stress_sizes = []
    selectivities = [0.01, 0.05, 0.20]
    complexities = [1, 3, 5]
    fanout = 16
    summary_rows: List[JSON] = []
    detection_rows: List[JSON] = []
    update_rows: List[JSON] = []
    topk_rows: List[JSON] = []
    join_rows: List[JSON] = []
    join_complete_rows: List[JSON] = []
    join_mm_rows: List[JSON] = []
    join_anti_rows: List[JSON] = []
    operator_rows: List[JSON] = []
    structural_update_rows: List[JSON] = []
    stress_rows: List[JSON] = []
    workload_rows: List[JSON] = []
    planner_frontier_rows: List[JSON] = []
    optimizer_trace_rows: List[JSON] = []

    for n in sizes:
        print(f"[exp] baseline/operator n={n}", flush=True)
        rows = generate_sales(n, seed=seed + n)
        con = create_sqlite_db(rows)
        day_tree, build_ms = timed(MerkleAggregateTree, rows, "day", fanout, repeat=1)
        score_tree = None  # built lazily for top-k to keep baseline memory bounded
        for comp in complexities:
            policy = make_policy(tenant=(n // 5000 + comp) % 6, complexity=comp)
            manifest = make_manifest(policy)
            for sel in selectivities:
                width = max(1, int(1000 * sel))
                lo = (seed * 37 + n // 13 + comp * 19 + int(sel * 1000)) % (1000 - width)
                hi = lo + width
                sql_res, sql_ms = timed(sqlite_groupby, con, policy, lo, hi, repeat=3)
                cert, gen_ms = timed(day_tree.make_groupby_certificate, policy, lo, hi, manifest=manifest, repeat=3)
                expected_contract = compile_sql_contract(
                    "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
                    [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
                verify_ok, ver_ms = timed(day_tree.verify_groupby_certificate, cert, cert["owner_digest"], expected_contract, repeat=5)
                if not verify_ok:
                    raise RuntimeError(f"verification failed for n={n} comp={comp} sel={sel}")
                if normalize_result(sql_res) != json_to_result(cert["result"]):
                    raise RuntimeError("sqlite/result mismatch")
                baseline_rows, _ = timed(baseline_metric_rows, day_tree, rows, policy, lo, hi, json_to_result(cert["result"]), n, sel, comp, sql_ms, build_ms, repeat=1)
                pacta_row = {
                    "n": n,
                    "profile": "dashboard_sales",
                    "selectivity": sel,
                    "policy_complexity": comp,
                    "scheme": "pacta",
                    "certificate_bytes": sizeof_json(cert),
                    "server_generation_ms": gen_ms,
                    "client_verification_ms": ver_ms,
                    "sqlite_query_ms": sql_ms,
                    "query_latency_overhead_x": (gen_ms / max(sql_ms, 1e-9)),
                    "authorized_rows": len(rows_in_range(rows, lo, hi, policy)),
                    "range_rows": len(rows_in_range(rows, lo, hi, None)),
                    "tree_build_ms": build_ms,
                    "root": day_tree.root_hash[:16],
                }
                for br in baseline_rows:
                    br.setdefault("profile", "dashboard_sales")
                summary_rows.append(pacta_row)
                summary_rows.extend(baseline_rows)
                gc.collect()
                # Adaptive planner: choose the smaller sound certificate among
                # policy-aware cover summaries and tuple+frontier evidence. This
                # does not create a new trust model; it records an optimizer
                # choice within the certificate algebra and keeps both verifiers.
                tuple_frontier = next((r for r in baseline_rows if r.get("scheme") == "tuple_frontier"), None)
                if tuple_frontier is not None:
                    if float(pacta_row["certificate_bytes"]) <= float(tuple_frontier["certificate_bytes"]):
                        chosen = pacta_row
                        chosen_evidence = "policy_summary_cover"
                    else:
                        chosen = tuple_frontier
                        chosen_evidence = "tuple_plus_frontier"
                    summary_rows.append({
                        "n": n,
                        "profile": "dashboard_sales",
                        "selectivity": sel,
                        "policy_complexity": comp,
                        "scheme": "adaptive_planner",
                        "certificate_bytes": chosen["certificate_bytes"],
                        "server_generation_ms": chosen["server_generation_ms"],
                        "client_verification_ms": chosen["client_verification_ms"],
                        "sqlite_query_ms": sql_ms,
                        "query_latency_overhead_x": "",
                        "authorized_rows": pacta_row["authorized_rows"],
                        "range_rows": pacta_row["range_rows"],
                        "tree_build_ms": build_ms,
                        "root": day_tree.root_hash[:16],
                        "selected_evidence": chosen_evidence,
                    })
                if n == sizes[len(sizes)//2] and comp == 3 and abs(sel - 0.05) < 1e-9:
                    os.makedirs(os.path.join(out_dir, "cert_samples"), exist_ok=True)
                    with open(os.path.join(out_dir, "cert_samples", "pacta_groupby_sample.json"), "w", encoding="utf-8") as f:
                        json.dump(cert, f, indent=2, sort_keys=True)
        policy = make_policy(tenant=1, complexity=3)
        manifest = make_manifest(policy)
        op_lo, op_hi = 120, 260
        avg_contract = compile_sql_contract(
            "SELECT category, COUNT(*), SUM(amount), AVG(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
            [op_lo, op_hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
        avg_cert, avg_ms = timed(day_tree.make_groupby_avg_certificate, policy, op_lo, op_hi, manifest=manifest, repeat=2)
        avg_ok, avg_ver = timed(day_tree.verify_groupby_avg_certificate, avg_cert, avg_cert["owner_digest"], avg_contract, repeat=3)
        if not avg_ok:
            raise RuntimeError("AVG contract verification failed")
        operator_rows.append({"n": n, "operator": "derived_avg_groupby", "certificate_bytes": sizeof_json(avg_cert), "server_generation_ms": avg_ms, "client_verification_ms": avg_ver, "result_groups": len(avg_cert["result"])})
        having_contract = compile_sql_contract(
            "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category HAVING SUM(amount) >= ?",
            [op_lo, op_hi, 5000], manifest, f"tenant-{policy.tenant}", policy.purpose)
        having_cert, having_ms = timed(day_tree.make_groupby_having_certificate, policy, op_lo, op_hi, 5000, manifest=manifest, repeat=2)
        having_ok, having_ver = timed(day_tree.verify_groupby_having_certificate, having_cert, having_cert["owner_digest"], having_contract, repeat=3)
        if not having_ok:
            raise RuntimeError("HAVING contract verification failed")
        operator_rows.append({"n": n, "operator": "groupby_having_sum", "certificate_bytes": sizeof_json(having_cert), "server_generation_ms": having_ms, "client_verification_ms": having_ver, "result_groups": len(having_cert["result"])})
        projection_contract = compile_sql_contract(
            "SELECT id, category, amount FROM sales WHERE day BETWEEN ? AND ?",
            [op_lo, op_hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
        proj_cert, proj_ms = timed(day_tree.make_projection_certificate, policy, op_lo, op_hi, manifest=manifest, repeat=1)
        proj_ok, proj_ver = timed(day_tree.verify_projection_certificate, proj_cert, proj_cert["owner_digest"], projection_contract, repeat=2)
        if not proj_ok:
            raise RuntimeError("projection contract verification failed")
        operator_rows.append({"n": n, "operator": "complete_range_projection", "certificate_bytes": sizeof_json(proj_cert), "server_generation_ms": proj_ms, "client_verification_ms": proj_ver, "opened_rows": proj_cert["opened_count"]})
        open_contract = compile_sql_contract(
            "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? AND amount >= ? GROUP BY category",
            [op_lo, op_hi, 100], manifest, f"tenant-{policy.tenant}", policy.purpose)
        open_cert, open_ms = timed(day_tree.make_open_scan_groupby_predicate_certificate, policy, op_lo, op_hi, 100, manifest=manifest, repeat=1)
        open_ok, open_ver = timed(day_tree.verify_open_scan_groupby_predicate_certificate, open_cert, open_cert["owner_digest"], open_contract, repeat=2)
        if not open_ok:
            raise RuntimeError("open-scan predicate fallback verification failed")
        expected_open = aggregate_rows([r for r in rows_in_range(day_tree.rows, op_lo, op_hi, policy) if int(r["amount"]) >= 100])
        if json_to_result(open_cert["result"]) != expected_open:
            raise RuntimeError("open-scan predicate result mismatch")
        operator_rows.append({"n": n, "operator": "open_scan_amount_predicate", "certificate_bytes": sizeof_json(open_cert), "server_generation_ms": open_ms, "client_verification_ms": open_ver, "opened_rows": open_cert["opened_count"], "result_groups": len(open_cert["result"])})
        compact_contract = compile_sql_contract(
            "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
            [op_lo, op_hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
        compact_cert, compact_ms = timed(day_tree.make_groupby_certificate, policy, op_lo, op_hi, manifest=manifest, repeat=2)
        compact_ok, compact_ver = timed(day_tree.verify_groupby_certificate, compact_cert, compact_cert["owner_digest"], compact_contract, repeat=3)
        if not compact_ok:
            raise RuntimeError("planner compact candidate verification failed")
        open_equiv_contract = compile_sql_contract(
            "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? AND amount >= ? GROUP BY category",
            [op_lo, op_hi, 0], manifest, f"tenant-{policy.tenant}", policy.purpose)
        open_equiv_cert, open_equiv_ms = timed(day_tree.make_open_scan_groupby_predicate_certificate, policy, op_lo, op_hi, 0, manifest=manifest, repeat=1)
        open_equiv_ok, open_equiv_ver = timed(day_tree.verify_open_scan_groupby_predicate_certificate, open_equiv_cert, open_equiv_cert["owner_digest"], open_equiv_contract, repeat=2)
        if not open_equiv_ok or json_to_result(open_equiv_cert["result"]) != json_to_result(compact_cert["result"]):
            raise RuntimeError("planner open-scan equivalent candidate mismatch")
        planner_frontier_rows.extend([
            {"n": n, "query_kind": "governed_groupby", "plan": "policy_cube_summary", "certificate_bytes": sizeof_json(compact_cert), "server_generation_ms": compact_ms, "client_verification_ms": compact_ver, "opened_rows": "", "sound": True},
            {"n": n, "query_kind": "governed_groupby", "plan": "open_range_scan_equivalent", "certificate_bytes": sizeof_json(open_equiv_cert), "server_generation_ms": open_equiv_ms, "client_verification_ms": open_equiv_ver, "opened_rows": open_equiv_cert["opened_count"], "sound": True},
            {"n": n, "query_kind": "row_predicate_groupby", "plan": "open_range_scan", "certificate_bytes": sizeof_json(open_cert), "server_generation_ms": open_ms, "client_verification_ms": open_ver, "opened_rows": open_cert["opened_count"], "sound": True},
            {"n": n, "query_kind": "row_predicate_groupby", "plan": "policy_cube_summary_without_amount", "certificate_bytes": sizeof_json(compact_cert), "server_generation_ms": compact_ms, "client_verification_ms": compact_ver, "opened_rows": "", "sound": False},
        ])
        if CertifyingEvidencePlanner is not None and PlanCandidate is not None:
            planner = CertifyingEvidencePlanner()
            base_obligations = ["request_binding", "owner_descriptor", "schema_binding", "manifest_policy_binding", "version_binding"]
            group_candidates = [
                PlanCandidate("policy_cube_summary", "range_groupby", base_obligations + ["range_completeness", "aggregate_monoid"], sizeof_json(compact_cert), compact_ms, compact_ver),
                PlanCandidate("open_range_scan_equivalent", "range_groupby", base_obligations + ["range_completeness", "opened_row_multiset", "aggregate_monoid"], sizeof_json(open_equiv_cert), open_equiv_ms, open_equiv_ver, open_equiv_cert["opened_count"]),
            ]
            pred_candidates = [
                PlanCandidate("policy_cube_summary_without_amount", "open_scan_groupby_predicate", base_obligations + ["range_completeness", "aggregate_monoid"], sizeof_json(compact_cert), compact_ms, compact_ver, None, "cheap but lacks row-predicate evidence"),
                PlanCandidate("open_range_scan", "open_scan_groupby_predicate", base_obligations + ["range_completeness", "opened_row_multiset", "row_predicate_local_eval"], sizeof_json(open_cert), open_ms, open_ver, open_cert["opened_count"]),
            ]
            for dec in [planner.choose("range_groupby", group_candidates), planner.choose("open_scan_groupby_predicate", pred_candidates)]:
                optimizer_trace_rows.append({"n": n, **dec.to_json()})
        distinct_contract = compile_sql_contract(
            "SELECT category, COUNT(DISTINCT cust_id) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
            [op_lo, op_hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
        distinct_cert, distinct_ms = timed(distinct_customer_certificate, day_tree, rows, policy, op_lo, op_hi, manifest=manifest, repeat=1)
        distinct_ok, distinct_ver = timed(verify_distinct_customer_certificate, day_tree, distinct_cert, distinct_cert["owner_digest"], distinct_contract, repeat=2)
        if not distinct_ok:
            raise RuntimeError("distinct contract verification failed")
        distinct_sql = sqlite_distinct_customer_groupby(con, policy, op_lo, op_hi)
        if json_to_distinct_result(distinct_cert["result"]) != distinct_sql:
            raise RuntimeError("distinct contract SQLite mismatch")
        operator_rows.append({"n": n, "operator": "count_distinct_customer", "certificate_bytes": sizeof_json(distinct_cert), "server_generation_ms": distinct_ms, "client_verification_ms": distinct_ver, "opened_rows": distinct_cert["opened_count"], "result_groups": len(distinct_cert["result"])})
        detection_rows.extend({"n": n, **r} for r in detection_trials(day_tree, rows, policy, 200, 260))
        update_sample = [day_tree.rows[(i * 997) % len(day_tree.rows)] for i in range(5)]
        for r in update_sample:
            new_amount = int(r["amount"]) + 1
            (_, path_bytes, touched_nodes), upd_ms = timed(day_tree.update_amount, int(r["id"]), new_amount, repeat=3)
            _, rebuild_ms = timed(MerkleAggregateTree, day_tree.rows, "day", fanout, repeat=1)
            update_rows.append(
                {
                    "n": n,
                    "incremental_update_ms": upd_ms,
                    "rebuild_update_ms": rebuild_ms,
                    "incremental_path_bytes": path_bytes,
                    "touched_nodes": touched_nodes,
                    "new_root": day_tree.root_hash[:16],
                }
            )
        fresh_row = dict(day_tree.rows[0])
        fresh_row["id"] = max(int(x["id"]) for x in day_tree.rows) + 1
        fresh_row["day"] = (int(fresh_row["day"]) + 17) % 1000
        ins_tree, ins_ms = timed(insert_row_version, day_tree, fresh_row, repeat=1)
        del_tree, del_ms = timed(delete_row_version, day_tree, int(day_tree.rows[1]["id"]), repeat=1)
        key_tree, key_ms = timed(key_update_version, day_tree, int(day_tree.rows[2]["id"]), (int(day_tree.rows[2]["day"]) + 31) % 1000, repeat=1)
        structural_update_rows.extend([
            {"n": n, "operation": "insert", "version_update_ms": ins_ms, "new_count": ins_tree.relation_descriptor()["count"], "new_root": ins_tree.root_hash[:16]},
            {"n": n, "operation": "delete", "version_update_ms": del_ms, "new_count": del_tree.relation_descriptor()["count"], "new_root": del_tree.root_hash[:16]},
            {"n": n, "operation": "key_update", "version_update_ms": key_ms, "new_count": key_tree.relation_descriptor()["count"], "new_root": key_tree.root_hash[:16]},
        ])
        policy = make_policy(tenant=2, complexity=3)
        manifest = make_manifest(policy)
        topk_contract = compile_sql_contract(
            "SELECT id, score FROM sales WHERE score >= ? ORDER BY score DESC, id ASC LIMIT ?",
            [0, 20], manifest, f"tenant-{policy.tenant}", policy.purpose)
        score_tree = MerkleAggregateTree(rows, key_attr="score", fanout=fanout)
        tk, tk_ms = timed(topk_certificate, score_tree, rows, policy, 20, min_score=0, manifest=manifest, repeat=2)
        topk_ok, tk_verify_ms = timed(verify_topk_certificate, score_tree, tk, tk["owner_digest"], topk_contract, repeat=3)
        if not topk_ok:
            raise RuntimeError("top-k verification failed")
        topk_rows.append(
            {
                "n": n,
                "scheme": "pacta-topk-threshold",
                "certificate_bytes": sizeof_json(tk),
                "server_generation_ms": tk_ms,
                "client_verification_ms": tk_verify_ms,
                "candidate_rows": int(tk["candidate_count"]),
                "k": 20,
            }
        )
        current_sales = list(day_tree.rows)
        customers = customers_as_sales_like(generate_customers(current_sales, seed=seed + n))
        cust_tree = MerkleAggregateTree(customers, key_attr="cust_id", fanout=fanout)
        join_contract = compile_sql_contract(
            "SELECT s.id, c.cust_id FROM sales s JOIN customers c ON s.cust_id = c.cust_id WHERE s.day BETWEEN ? AND ? AND c.segment = ? AND c.active = 1",
            [100, 170, 1], manifest, f"tenant-{policy.tenant}", policy.purpose)
        jc, jc_ms = timed(limited_join_certificate, day_tree, cust_tree, current_sales, customers, policy, 100, 170, 1, manifest=manifest, repeat=1)
        join_ok, join_verify_ms = timed(verify_limited_join_certificate, day_tree, cust_tree, jc, join_contract, repeat=3)
        if not join_ok:
            raise RuntimeError("join verification failed")
        join_rows.append(
            {
                "n": n,
                "scheme": "limited-equi-join-returned-pair-authenticity",
                "certificate_bytes": sizeof_json(jc),
                "server_generation_ms": jc_ms,
                "client_verification_ms": join_verify_ms,
                "join_count": jc["join_count"],
            }
        )
        fk_contract = compile_sql_contract(
            "SELECT c.segment, COUNT(*), SUM(s.amount) FROM sales s JOIN customers c ON s.cust_id = c.cust_id WHERE s.day BETWEEN ? AND ? AND c.active = 1 GROUP BY c.segment",
            [100, 170], manifest, f"tenant-{policy.tenant}", policy.purpose)
        cj, cj_ms = timed(complete_fk_join_certificate, day_tree, cust_tree, current_sales, customers, policy, 100, 170, manifest=manifest, repeat=1)
        cj_ok, cj_verify_ms = timed(verify_complete_fk_join_certificate, day_tree, cust_tree, cj, fk_contract, repeat=2)
        if not cj_ok:
            raise RuntimeError("complete FK join verification failed")
        join_con = create_sqlite_join_db(current_sales, customers)
        if json_to_join_result(cj["result"]) != sqlite_complete_join_groupby(join_con, policy, 100, 170):
            raise RuntimeError("complete FK join SQLite mismatch")
        join_con.close()
        join_complete_rows.append({
            "n": n,
            "scheme": "complete-fk-join-groupby-fallback",
            "certificate_bytes": sizeof_json(cj),
            "server_generation_ms": cj_ms,
            "client_verification_ms": cj_verify_ms,
            "opened_sales_count": cj["opened_sales_count"],
            "result_groups": len(cj["result"]),
        })
        anti_contract = compile_sql_contract(
            "SELECT s.category, COUNT(*), SUM(s.amount) FROM sales s WHERE s.day BETWEEN ? AND ? AND NOT EXISTS (SELECT 1 FROM customers c WHERE c.cust_id = s.cust_id AND c.tenant = s.tenant AND c.active = 1) GROUP BY s.category",
            [100, 170], manifest, f"tenant-{policy.tenant}", policy.purpose)
        anti, anti_ms = timed(complete_antijoin_certificate, day_tree, cust_tree, current_sales, customers, policy, 100, 170, manifest=manifest, repeat=1)
        anti_ok, anti_verify_ms = timed(verify_complete_antijoin_certificate, day_tree, cust_tree, anti, anti_contract, repeat=2)
        if not anti_ok:
            raise RuntimeError("complete anti-join verification failed")
        anti_con = create_sqlite_join_db(current_sales, customers)
        if json_to_join_result(anti["result"]) != sqlite_complete_antijoin_groupby(anti_con, policy, 100, 170):
            raise RuntimeError("complete anti-join SQLite mismatch")
        anti_con.close()
        join_anti_rows.append({
            "n": n,
            "scheme": "complete-antijoin-groupby-fallback",
            "certificate_bytes": sizeof_json(anti),
            "server_generation_ms": anti_ms,
            "client_verification_ms": anti_verify_ms,
            "opened_sales_count": anti["opened_sales_count"],
            "result_groups": len(anti["result"]),
        })
        tag_rows = generate_category_tags(categories=6, tags_per_category=3)
        tag_tree = MerkleAggregateTree(tag_rows, key_attr="category", fanout=fanout)
        mm_contract = compile_sql_contract(
            "SELECT t.tag, COUNT(*), SUM(s.amount) FROM sales s JOIN category_tags t ON s.category = t.category WHERE s.day BETWEEN ? AND ? GROUP BY t.tag",
            [100, 170], manifest, f"tenant-{policy.tenant}", policy.purpose)
        mj, mj_ms = timed(complete_mm_join_certificate, day_tree, tag_tree, current_sales, tag_rows, policy, 100, 170, manifest=manifest, repeat=1)
        mj_ok, mj_verify_ms = timed(verify_complete_mm_join_certificate, day_tree, tag_tree, mj, mm_contract, repeat=2)
        if not mj_ok:
            raise RuntimeError("complete many-to-many join verification failed")
        mm_con = create_sqlite_many_to_many_db(current_sales, tag_rows)
        if json_to_join_result(mj["result"]) != sqlite_complete_mm_join_groupby(mm_con, policy, 100, 170):
            raise RuntimeError("complete many-to-many join SQLite mismatch")
        mm_con.close()
        join_mm_rows.append({
            "n": n,
            "scheme": "complete-mm-join-groupby-fallback",
            "certificate_bytes": sizeof_json(mj),
            "server_generation_ms": mj_ms,
            "client_verification_ms": mj_verify_ms,
            "opened_sales_count": mj["opened_sales_count"],
            "tag_categories": len(mj["tag_contracts"]),
            "result_groups": len(mj["result"]),
        })
        con.close()
        for _name in [
            'rows','con','day_tree','score_tree','cert','baseline_rows','avg_cert','having_cert','proj_cert','open_cert','compact_cert','open_equiv_cert','distinct_cert','tk','current_sales','customers','cust_tree','jc','cj','anti','tag_rows','tag_tree','mj','join_con','anti_con','mm_con','ins_tree','del_tree','key_tree'
        ]:
            if _name in locals():
                try:
                    del locals()[_name]
                except Exception:
                    pass
        gc.collect()
        print(f"[exp] done baseline/operator n={n}", flush=True)

    for n in stress_sizes:
        print(f"[exp] stress n={n}", flush=True)
        rows = generate_sales(n, seed=seed + n)
        con = create_sqlite_db(rows)
        tree, build_ms = timed(MerkleAggregateTree, rows, "day", fanout, repeat=1)
        for comp in complexities:
            policy = make_policy(tenant=(n // 5000 + comp) % 6, complexity=comp)
            manifest = make_manifest(policy)
            for sel in selectivities:
                width = max(1, int(1000 * sel))
                lo = (seed * 37 + n // 13 + comp * 19 + int(sel * 1000)) % (1000 - width)
                hi = lo + width
                sql_res, sql_ms = timed(sqlite_groupby, con, policy, lo, hi, repeat=1)
                cert, gen_ms = timed(tree.make_groupby_certificate, policy, lo, hi, manifest=manifest, repeat=1)
                expected_contract = compile_sql_contract(
                    "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
                    [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
                verify_ok, ver_ms = timed(tree.verify_groupby_certificate, cert, cert["owner_digest"], expected_contract, repeat=2)
                if not verify_ok or normalize_result(sql_res) != json_to_result(cert["result"]):
                    raise RuntimeError(f"stress verification mismatch for n={n} comp={comp} sel={sel}")
                stress_rows.append(
                    {
                        "n": n,
                        "profile": "dashboard_sales",
                        "selectivity": sel,
                        "policy_complexity": comp,
                        "scheme": "pacta",
                        "certificate_bytes": sizeof_json(cert),
                        "server_generation_ms": gen_ms,
                        "client_verification_ms": ver_ms,
                        "sqlite_query_ms": sql_ms,
                        "query_latency_overhead_x": (gen_ms / max(sql_ms, 1e-9)),
                        "authorized_rows": len(rows_in_range(rows, lo, hi, policy)),
                        "range_rows": len(rows_in_range(rows, lo, hi, None)),
                        "tree_build_ms": build_ms,
                        "root": tree.root_hash[:16],
                    }
                )
        con.close()
        print(f"[exp] done stress n={n}", flush=True)


    if scale == "stress":
        print("[exp] writing stress csv", flush=True)
        write_csv(os.path.join(out_dir, "pacta_stress.csv"), stress_rows)
        repro = {
            "seed": seed,
            "sizes": sizes,
            "stress_sizes": stress_sizes,
            "selectivities": selectivities,
            "policy_complexities": complexities,
            "fanout": fanout,
            "scale": scale,
            "workload_profiles": [],
            "public_profiles": [],
            "claim_guard": "stress run writes Pacta-only scalability rows; full paper-scale results are produced separately",
        }
        with open(os.path.join(out_dir, "repro.json"), "w", encoding="utf-8") as f:
            json.dump(repro, f, indent=2, sort_keys=True)
        print("[exp] complete", flush=True)
        return

    # Cross-profile external-validity sweep.  These runs keep the verifier and
    # SQL oracle fixed while changing workload distributions to TPC-H-like,
    # public open-data, health-release, and finance-audit profiles.  The numbers
    # are kept in a separate CSV so the main baseline matrix is not conflated
    # with external adapters.
    for profile in WORKLOAD_PROFILES:
        print(f"[exp] workload profile={profile}", flush=True)
        n = 4000
        rows = generate_sales(n, seed=seed + 97 + len(profile), profile=profile)
        con = create_sqlite_db(rows)
        tree, build_ms = timed(MerkleAggregateTree, rows, "day", fanout, repeat=1)
        for comp in complexities:
            policy = make_policy(tenant=(comp + len(profile)) % 6, complexity=comp)
            manifest = make_manifest(policy)
            for sel in selectivities:
                width = max(1, int(1000 * sel))
                lo = (seed * 53 + comp * 29 + len(profile) * 7 + int(sel * 1000)) % (1000 - width)
                hi = lo + width
                sql_res, sql_ms = timed(sqlite_groupby, con, policy, lo, hi, repeat=1)
                cert, gen_ms = timed(tree.make_groupby_certificate, policy, lo, hi, manifest=manifest, repeat=1)
                expected_contract = compile_sql_contract(
                    "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
                    [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
                ok, ver_ms = timed(tree.verify_groupby_certificate, cert, cert["owner_digest"], expected_contract, repeat=2)
                if not ok or normalize_result(sql_res) != json_to_result(cert["result"]):
                    raise RuntimeError(f"profile verification mismatch: {profile}")
                tuple_rows = rows_in_range(rows, lo, hi, policy)
                frontier = {"scheme":"tuple_frontier", "certificate_bytes": estimate_tuple_certificate_bytes(tree, tuple_rows)}
                workload_rows.append({
                    "profile": profile,
                    "n": n,
                    "selectivity": sel,
                    "policy_complexity": comp,
                    "certificate_bytes": sizeof_json(cert),
                    "server_generation_ms": gen_ms,
                    "client_verification_ms": ver_ms,
                    "sqlite_query_ms": sql_ms,
                    "authorized_rows": len(tuple_rows),
                    "range_rows": len(rows_in_range(rows, lo, hi, None)),
                    "tree_build_ms": build_ms,
                    "tuple_frontier_estimated_bytes": frontier["certificate_bytes"],
                    "root": tree.root_hash[:16],
                })
        con.close()
        print(f"[exp] done workload profile={profile}", flush=True)

    public_profiles = ["public_gapminder", "public_apple_stock"]
    for profile in public_profiles:
        print(f"[exp] public profile={profile}", flush=True)
        rows = load_public_profile_rows(profile)
        con = create_sqlite_db(rows)
        tree, build_ms = timed(MerkleAggregateTree, rows, "day", fanout, repeat=1)
        min_day = min(int(r["day"]) for r in rows)
        max_day = max(int(r["day"]) for r in rows)
        span = max(1, max_day - min_day + 1)
        for comp in complexities:
            tenant = 0 if profile == "public_apple_stock" else comp % 5
            policy = make_policy(tenant=tenant, complexity=min(comp, 5))
            manifest = make_manifest(policy)
            for sel in selectivities:
                width = max(1, int(span * sel))
                lo = min_day + ((seed * 41 + comp * 17 + int(sel * 1000)) % max(1, span - width))
                hi = min(max_day, lo + width)
                sql_res, sql_ms = timed(sqlite_groupby, con, policy, lo, hi, repeat=3)
                cert, gen_ms = timed(tree.make_groupby_certificate, policy, lo, hi, manifest=manifest, repeat=3)
                expected_contract = compile_sql_contract(
                    "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
                    [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
                ok, ver_ms = timed(tree.verify_groupby_certificate, cert, cert["owner_digest"], expected_contract, repeat=5)
                if not ok or normalize_result(sql_res) != json_to_result(cert["result"]):
                    raise RuntimeError(f"public profile verification mismatch: {profile}")
                tuple_rows = rows_in_range(rows, lo, hi, policy)
                workload_rows.append({
                    "profile": profile,
                    "source_kind": "public_csv",
                    "n": len(rows),
                    "selectivity": sel,
                    "policy_complexity": comp,
                    "certificate_bytes": sizeof_json(cert),
                    "server_generation_ms": gen_ms,
                    "client_verification_ms": ver_ms,
                    "sqlite_query_ms": sql_ms,
                    "authorized_rows": len(tuple_rows),
                    "range_rows": len(rows_in_range(rows, lo, hi, None)),
                    "tree_build_ms": build_ms,
                    "tuple_frontier_estimated_bytes": estimate_tuple_certificate_bytes(tree, tuple_rows),
                    "root": tree.root_hash[:16],
                })
        con.close()
        print(f"[exp] done public profile={profile}", flush=True)

    print("[exp] writing csv", flush=True)
    write_csv(os.path.join(out_dir, "summary.csv"), summary_rows)
    write_csv(os.path.join(out_dir, "detection.csv"), detection_rows)
    write_csv(os.path.join(out_dir, "updates.csv"), update_rows)
    write_csv(os.path.join(out_dir, "topk.csv"), topk_rows)
    write_csv(os.path.join(out_dir, "join.csv"), join_rows)
    write_csv(os.path.join(out_dir, "join_complete.csv"), join_complete_rows)
    write_csv(os.path.join(out_dir, "join_many_to_many.csv"), join_mm_rows)
    write_csv(os.path.join(out_dir, "join_antijoin.csv"), join_anti_rows)
    write_csv(os.path.join(out_dir, "operator_contracts.csv"), operator_rows)
    write_csv(os.path.join(out_dir, "structural_updates.csv"), structural_update_rows)
    write_csv(os.path.join(out_dir, "pacta_stress.csv"), stress_rows)
    write_csv(os.path.join(out_dir, "workload_profiles.csv"), workload_rows)
    write_csv(os.path.join(out_dir, "planner_frontier.csv"), planner_frontier_rows)
    write_csv(os.path.join(out_dir, "optimizer_trace.csv"), optimizer_trace_rows)
    repro = {
        "seed": seed,
        "sizes": sizes,
        "stress_sizes": stress_sizes,
        "selectivities": selectivities,
        "policy_complexities": complexities,
        "fanout": fanout,
        "scale": scale,
        "workload_profiles": WORKLOAD_PROFILES,
        "public_profiles": ["public_gapminder", "public_apple_stock"],
        "generated_by": "deterministic_seeded_reproduction",
        "python": tuple(__import__("sys").version_info[:3]),
        "hash": "sha256",
    }
    with open(os.path.join(out_dir, "repro.json"), "w", encoding="utf-8") as f:
        json.dump(repro, f, indent=2, sort_keys=True)
    print("[exp] complete", flush=True)


def _check(condition: bool, message: str) -> None:
    """Raise even when Python is executed with -O; used by artifact self-tests."""
    if not condition:
        raise AssertionError(message)

def run_tests() -> None:
    print('[test] Pacta verifier/adversary suite start', flush=True)
    rows = generate_sales(2000, seed=123)
    tree = MerkleAggregateTree(rows, key_attr="day", fanout=16)
    policy = make_policy(tenant=1, complexity=3)
    manifest = make_manifest(policy)
    lo, hi = 100, 260
    # Fail-closed SQL contract compiler: supported templates compile, while
    # unsupported SQL features are rejected before certificate generation.
    supported = compile_sql_contract(
        "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
        [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(supported)
    complete_join_supported = compile_sql_contract(
        "SELECT c.segment, COUNT(*), SUM(s.amount) FROM sales s JOIN customers c ON s.cust_id = c.cust_id WHERE s.day BETWEEN ? AND ? AND c.active = 1 GROUP BY c.segment",
        [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(complete_join_supported)
    avg_supported = compile_sql_contract(
        "SELECT category, COUNT(*), SUM(amount), AVG(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
        [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(avg_supported)
    having_supported = compile_sql_contract(
        "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category HAVING SUM(amount) >= ?",
        [lo, hi, 5000], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(having_supported)
    projection_supported = compile_sql_contract(
        "SELECT id, category, amount FROM sales WHERE day BETWEEN ? AND ?",
        [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(projection_supported)
    open_scan_supported = compile_sql_contract(
        "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? AND amount >= ? GROUP BY category",
        [lo, hi, 500], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(open_scan_supported)
    topk_supported = compile_sql_contract(
        "SELECT id, score FROM sales WHERE score >= ? ORDER BY score DESC, id ASC LIMIT ?",
        [500, 10], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(topk_supported)
    mm_supported = compile_sql_contract(
        "SELECT t.tag, COUNT(*), SUM(s.amount) FROM sales s JOIN category_tags t ON s.category = t.category WHERE s.day BETWEEN ? AND ? GROUP BY t.tag",
        [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(mm_supported)
    distinct_supported = compile_sql_contract(
        "SELECT category, COUNT(DISTINCT cust_id) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
        [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(distinct_supported)
    antijoin_supported = compile_sql_contract(
        "SELECT s.category, COUNT(*), SUM(s.amount) FROM sales s WHERE s.day BETWEEN ? AND ? AND NOT EXISTS (SELECT 1 FROM customers c WHERE c.cust_id = s.cust_id AND c.tenant = s.tenant AND c.active = 1) GROUP BY s.category",
        [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
    validate_contract(antijoin_supported)
    # Schema contract: primary keys and NOT NULL verification attributes are
    # committed before tree construction, not just assumed by the prose.
    try:
        MerkleAggregateTree(rows + [dict(rows[0])], key_attr="day", fanout=16)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate primary key accepted by relation descriptor")
    null_bad = dict(rows[0]); null_bad["amount"] = None
    try:
        MerkleAggregateTree([null_bad], key_attr="day", fanout=16)
    except ValueError:
        pass
    else:
        raise AssertionError("NULL-like aggregate input accepted by relation descriptor")
    for bad_sql in [
        "SELECT * FROM sales",
        "SELECT category, COUNT(*) OVER () FROM sales",
        "SELECT category FROM sales WHERE amount + random() > 0",
    ]:
        try:
            compile_sql_contract(bad_sql, [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
        except UnsupportedQueryError:
            pass
        else:
            raise AssertionError(f"unsupported SQL was accepted: {bad_sql}")

    cert = tree.make_groupby_certificate(policy, lo, hi, manifest=manifest)
    expected_group_contract = compile_sql_contract(
        "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
        [lo, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
    _check(tree.verify_groupby_certificate(cert, cert['owner_digest'], expected_group_contract), 'honest group-by certificate rejected')
    wrong_group_contract = compile_sql_contract(
        "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
        [lo + 1, hi], manifest, f"tenant-{policy.tenant}", policy.purpose)
    _check(not tree.verify_groupby_certificate(cert, cert['owner_digest'], wrong_group_contract), 'query substitution accepted')
    q_sub = json.loads(canonical(cert))
    q_sub["query"]["hi"] = hi + 1
    _check(not tree.verify_groupby_certificate(q_sub, cert['owner_digest'], expected_group_contract), 'request digest bypass accepted')
    _check(json_to_result(cert['result']) == aggregate_rows(rows_in_range(rows, lo, hi, policy)), 'aggregate mismatch')
    version_bad = json.loads(canonical(cert))
    version_bad["owner_digest"]["version"] += 1
    _check(not tree.verify_groupby_certificate(version_bad, None, expected_group_contract), 'self-contained wrong owner version accepted')
    expired_manifest = make_manifest(policy)
    expired_manifest["policies"][0]["valid_to"] = -1
    expired_bad = tree.make_groupby_certificate(policy, lo, hi, manifest=manifest)
    expired_bad["manifest"] = expired_manifest
    expired_bad["owner_digest"] = owner_digest(tree.relation_descriptor(), expired_manifest)
    _check(not tree.verify_groupby_certificate(expired_bad, None, expected_group_contract), 'expired policy interval accepted')

    avg_cert = tree.make_groupby_avg_certificate(policy, lo, hi, manifest=manifest)
    _check(tree.verify_groupby_avg_certificate(avg_cert, avg_cert['owner_digest'], avg_supported), 'AVG quotient certificate rejected')
    avg_bad = json.loads(canonical(avg_cert))
    if avg_bad["result"]:
        ak = next(iter(avg_bad["result"]))
        avg_bad["result"][ak]["avg_amount"]["numerator"] += 1
    _check(not tree.verify_groupby_avg_certificate(avg_bad, avg_cert['owner_digest'], avg_supported), 'AVG quotient tampering accepted')

    having_cert = tree.make_groupby_having_certificate(policy, lo, hi, 5000, manifest=manifest)
    _check(tree.verify_groupby_having_certificate(having_cert, having_cert['owner_digest'], having_supported), 'HAVING certificate rejected')
    having_bad = json.loads(canonical(having_cert))
    having_bad["query"]["having"]["sum(amount)"][1] = 0
    _check(not tree.verify_groupby_having_certificate(having_bad, having_cert['owner_digest'], having_supported), 'HAVING query mutation accepted')

    proj_cert = tree.make_projection_certificate(policy, lo, hi, manifest=manifest)
    _check(tree.verify_projection_certificate(proj_cert, proj_cert['owner_digest'], projection_supported), 'projection certificate rejected')
    if proj_cert["released_rows"]:
        proj_bad = json.loads(canonical(proj_cert))
        proj_bad["released_rows"][0]["amount"] += 1
        _check(not tree.verify_projection_certificate(proj_bad, proj_cert['owner_digest'], projection_supported), 'projection tampering accepted')
        proj_omit = json.loads(canonical(proj_cert))
        proj_omit["items"].pop()
        proj_omit["opened_count"] -= 1
        proj_omit["released_rows"].pop()
        _check(not tree.verify_projection_certificate(proj_omit, proj_cert['owner_digest'], projection_supported), 'projection omission accepted')
    open_scan_cert = tree.make_open_scan_groupby_predicate_certificate(policy, lo, hi, 500, manifest=manifest)
    _check(tree.verify_open_scan_groupby_predicate_certificate(open_scan_cert, open_scan_cert['owner_digest'], open_scan_supported), 'open-scan predicate fallback rejected')
    expected_open_scan = aggregate_rows([r for r in rows_in_range(rows, lo, hi, policy) if int(r["amount"]) >= 500])
    _check(json_to_result(open_scan_cert['result']) == expected_open_scan, 'open-scan predicate result mismatch')
    open_scan_wrong = compile_sql_contract(
        "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? AND amount >= ? GROUP BY category",
        [lo, hi, 900], manifest, f"tenant-{policy.tenant}", policy.purpose)
    _check(not tree.verify_open_scan_groupby_predicate_certificate(open_scan_cert, open_scan_cert['owner_digest'], open_scan_wrong), 'open-scan predicate substitution accepted')
    if open_scan_cert["items"]:
        open_scan_omit = json.loads(canonical(open_scan_cert))
        open_scan_omit["items"].pop()
        open_scan_omit["opened_count"] -= 1
        _check(not tree.verify_open_scan_groupby_predicate_certificate(open_scan_omit, open_scan_cert['owner_digest'], open_scan_supported), 'open-scan range-row omission accepted')
    distinct_cert = distinct_customer_certificate(tree, rows, policy, lo, hi, manifest=manifest)
    _check(verify_distinct_customer_certificate(tree, distinct_cert, distinct_cert['owner_digest'], distinct_supported), 'distinct certificate rejected')
    con_distinct = create_sqlite_db(rows)
    _check(json_to_distinct_result(distinct_cert['result']) == sqlite_distinct_customer_groupby(con_distinct, policy, lo, hi), 'distinct SQLite mismatch')
    con_distinct.close()
    distinct_bad = json.loads(canonical(distinct_cert))
    if distinct_bad["items"]:
        distinct_bad["items"].pop()
        distinct_bad["opened_count"] -= 1
        _check(not verify_distinct_customer_certificate(tree, distinct_bad, distinct_cert['owner_digest'], distinct_supported), 'distinct omission accepted')
    tampered = json.loads(canonical(cert))
    if tampered["result"]:
        k = next(iter(tampered["result"]))
        tampered["result"][k][0] += 1
    _check(not tree.verify_groupby_certificate(tampered, cert['owner_digest'], expected_group_contract), 'tampered result accepted')
    det = detection_trials(tree, rows, policy, lo, hi)
    _check(any((r['attack'] == 'omitted_inside_range' and r['scheme'] == 'pacta' and r['detected'] for r in det)), 'omission not detected')
    _check(any((r['attack'] == 'range_boundary_relabel' and r['scheme'] == 'pacta' and r['detected'] for r in det)), 'range-boundary relabel attack not detected')
    _check(not any((r['scheme'] == 'pacta' and r['attack'] != 'honest' and r['accepted'] for r in det)), 'a Pacta attack trial was accepted')
    sample_rows = rows_in_range(rows, lo, hi, policy)[:10]
    tc = tree.tuple_certificate(sample_rows)
    _check(tree.verify_tuple_certificate(tc), 'tuple proof rejected')
    bad_tc = json.loads(canonical(tc))
    if bad_tc["items"]:
        bad_tc["items"][0]["row"]["amount"] += 99
    _check(not tree.verify_tuple_certificate(bad_tc), 'tampered tuple proof accepted')
    before_root = tree.root_hash
    rid = int(tree.rows[17]["id"])
    tree.update_amount(rid, int(tree.rows[17]["amount"]) + 5)
    _check(tree.root_hash != before_root, 'update did not change root')
    updated_manifest = make_manifest(policy, version=tree.version)
    cert2 = tree.make_groupby_certificate(policy, lo, hi, manifest=updated_manifest)
    updated_contract = compile_sql_contract(
        "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
        [lo, hi], updated_manifest, f"tenant-{policy.tenant}", policy.purpose)
    _check(tree.verify_groupby_certificate(cert2, cert2['owner_digest'], updated_contract), 'post-update certificate rejected')
    score_tree = MerkleAggregateTree(rows, key_attr="score", fanout=16)
    tk = topk_certificate(score_tree, rows, policy, 10, min_score=500, manifest=manifest)
    _check(verify_topk_certificate(score_tree, tk, tk['owner_digest'], topk_supported), 'top-k verifier failed')
    wrong_topk_contract = compile_sql_contract(
        "SELECT id, score FROM sales WHERE score >= ? ORDER BY score DESC, id ASC LIMIT ?",
        [700, 10], manifest, f"tenant-{policy.tenant}", policy.purpose)
    _check(not verify_topk_certificate(score_tree, tk, tk['owner_digest'], wrong_topk_contract), 'top-k query substitution accepted')
    tk_bad = json.loads(canonical(tk))
    if tk_bad["candidate_items"]:
        tk_bad["candidate_items"].pop()
    _check(not verify_topk_certificate(score_tree, tk_bad, tk['owner_digest'], topk_supported), 'top-k omission accepted')
    customers = customers_as_sales_like(generate_customers(rows, seed=1))
    cust_tree = MerkleAggregateTree(customers, key_attr="cust_id", fanout=16)
    jc_contract = compile_sql_contract(
        "SELECT s.id, c.cust_id FROM sales s JOIN customers c ON s.cust_id = c.cust_id WHERE s.day BETWEEN ? AND ? AND c.segment = ? AND c.active = 1",
        [100, 200, 1], manifest, f"tenant-{policy.tenant}", policy.purpose)
    jc = limited_join_certificate(tree, cust_tree, rows, customers, policy, 100, 200, 1, manifest=manifest)
    _check(verify_limited_join_certificate(tree, cust_tree, jc, jc_contract), 'join verifier failed')
    jc_hidden = json.loads(canonical(jc))
    jc_hidden["query"]["dimension_predicates"] = ["customers.tenant=sales.tenant"]
    _check(not verify_limited_join_certificate(tree, cust_tree, jc_hidden, jc_contract), 'returned-pair hidden dimension predicate accepted')
    if jc["pairs"]:
        jbad = json.loads(canonical(jc))
        jbad["pairs"][0]["customer"]["row"]["segment"] = 3
        _check(not verify_limited_join_certificate(tree, cust_tree, jbad, jc_contract), 'join tampering accepted')
    complete_fk_contract = compile_sql_contract(
        "SELECT c.segment, COUNT(*), SUM(s.amount) FROM sales s JOIN customers c ON s.cust_id = c.cust_id WHERE s.day BETWEEN ? AND ? AND c.active = 1 GROUP BY c.segment",
        [100, 200], manifest, f"tenant-{policy.tenant}", policy.purpose)
    complete_jc = complete_fk_join_certificate(tree, cust_tree, rows, customers, policy, 100, 200, manifest=manifest)
    _check(verify_complete_fk_join_certificate(tree, cust_tree, complete_jc, complete_fk_contract), 'complete FK join verifier failed')
    fk_hidden = json.loads(canonical(complete_jc))
    fk_hidden["query"]["dimension_predicates"] = ["customers.tenant=sales.tenant"]
    _check(not verify_complete_fk_join_certificate(tree, cust_tree, fk_hidden, complete_fk_contract), 'complete FK hidden dimension predicate accepted')
    con_join = create_sqlite_join_db(rows, customers)
    _check(json_to_join_result(complete_jc['result']) == sqlite_complete_join_groupby(con_join, policy, 100, 200), 'complete FK join SQLite mismatch')
    con_join.close()
    if complete_jc["sales_items"]:
        cj_bad = json.loads(canonical(complete_jc))
        cj_bad["sales_items"].pop()
        cj_bad["customer_items"].pop()
        cj_bad["opened_sales_count"] -= 1
        _check(not verify_complete_fk_join_certificate(tree, cust_tree, cj_bad, complete_fk_contract), 'complete FK join omission accepted')

    anti_contract = compile_sql_contract(
        "SELECT s.category, COUNT(*), SUM(s.amount) FROM sales s WHERE s.day BETWEEN ? AND ? AND NOT EXISTS (SELECT 1 FROM customers c WHERE c.cust_id = s.cust_id AND c.tenant = s.tenant AND c.active = 1) GROUP BY s.category",
        [100, 200], manifest, f"tenant-{policy.tenant}", policy.purpose)
    anti = complete_antijoin_certificate(tree, cust_tree, rows, customers, policy, 100, 200, manifest=manifest)
    _check(verify_complete_antijoin_certificate(tree, cust_tree, anti, anti_contract), 'complete anti-join verifier failed')
    con_anti = create_sqlite_join_db(rows, customers)
    _check(json_to_join_result(anti['result']) == sqlite_complete_antijoin_groupby(con_anti, policy, 100, 200), 'complete anti-join SQLite mismatch')
    con_anti.close()
    if anti["sales_items"]:
        anti_bad = json.loads(canonical(anti))
        anti_bad["sales_items"].pop()
        anti_bad["opened_sales_count"] -= 1
        _check(not verify_complete_antijoin_certificate(tree, cust_tree, anti_bad, anti_contract), 'anti-join fact omission accepted')
    for cc in anti["customer_contracts"].values():
        if cc.get("customer_items"):
            anti_bad2 = json.loads(canonical(anti))
            key = str(cc["sales_id"])
            anti_bad2["customer_contracts"][key]["customer_items"].pop()
            anti_bad2["customer_contracts"][key]["opened_customer_count"] -= 1
            _check(not verify_complete_antijoin_certificate(tree, cust_tree, anti_bad2, anti_contract), 'anti-join customer omission accepted')
            break

    tags = generate_category_tags(categories=6, tags_per_category=3)
    tag_tree = MerkleAggregateTree(tags, key_attr="category", fanout=16)
    mm_contract = compile_sql_contract(
        "SELECT t.tag, COUNT(*), SUM(s.amount) FROM sales s JOIN category_tags t ON s.category = t.category WHERE s.day BETWEEN ? AND ? GROUP BY t.tag",
        [100, 200], manifest, f"tenant-{policy.tenant}", policy.purpose)
    mmc = complete_mm_join_certificate(tree, tag_tree, rows, tags, policy, 100, 200, manifest=manifest)
    _check(verify_complete_mm_join_certificate(tree, tag_tree, mmc, mm_contract), 'complete many-to-many join verifier failed')
    mm_policy_bad = json.loads(canonical(mmc))
    mm_policy_bad["query"]["dimension_policy_hash"] = "0" * 64
    _check(not verify_complete_mm_join_certificate(tree, tag_tree, mm_policy_bad, mm_contract), 'many-to-many tag policy substitution accepted')
    con_mm = create_sqlite_many_to_many_db(rows, tags)
    _check(json_to_join_result(mmc['result']) == sqlite_complete_mm_join_groupby(con_mm, policy, 100, 200), 'complete many-to-many join SQLite mismatch')
    con_mm.close()
    for tc2 in mmc["tag_contracts"].values():
        if tc2.get("tag_items"):
            mm_bad = json.loads(canonical(mmc))
            key = str(tc2["category"])
            mm_bad["tag_contracts"][key]["tag_items"].pop()
            mm_bad["tag_contracts"][key]["opened_tag_count"] -= 1
            _check(not verify_complete_mm_join_certificate(tree, tag_tree, mm_bad, mm_contract), 'complete many-to-many tag omission accepted')
            break

    inserted_tree = insert_row_version(tree, {**rows[0], "id": 999999, "day": 222})
    _check(inserted_tree.relation_descriptor()['count'] == tree.relation_descriptor()['count'] + 1, "artifact self-test failed: inserted_tree.relation_descriptor()['count'] == tree.relation_descriptor()['count'] + 1")
    _check(inserted_tree.relation_descriptor()['version'] == tree.relation_descriptor()['version'] + 1, "artifact self-test failed: inserted_tree.relation_descriptor()['version'] == tree.relation_descriptor()['version'] + 1")
    deleted_tree = delete_row_version(tree, int(rows[0]["id"]))
    _check(deleted_tree.relation_descriptor()['count'] == tree.relation_descriptor()['count'] - 1, "artifact self-test failed: deleted_tree.relation_descriptor()['count'] == tree.relation_descriptor()['count'] - 1")
    _check(deleted_tree.relation_descriptor()['version'] == tree.relation_descriptor()['version'] + 1, "artifact self-test failed: deleted_tree.relation_descriptor()['version'] == tree.relation_descriptor()['version'] + 1")
    key_tree = key_update_version(tree, int(rows[1]["id"]), 333)
    _check(key_tree.relation_descriptor()['count'] == tree.relation_descriptor()['count'], "artifact self-test failed: key_tree.relation_descriptor()['count'] == tree.relation_descriptor()['count']")
    _check(key_tree.relation_descriptor()['version'] == tree.relation_descriptor()['version'] + 1, "artifact self-test failed: key_tree.relation_descriptor()['version'] == tree.relation_descriptor()['version'] + 1")
    _check(len(load_public_profile_rows('public_gapminder')) > 1000, "artifact self-test failed: len(load_public_profile_rows('public_gapminder')) > 1000")
    _check(len(load_public_profile_rows('public_apple_stock')) > 200, "artifact self-test failed: len(load_public_profile_rows('public_apple_stock')) > 200")

    print('[test] deterministic adversarial checks complete; randomized SQLite cross-checks start', flush=True)
    # Randomized cross-checks against SQLite exercise the verifier over a wider
    # range of ranges, policies, and data distributions than the single smoke
    # case above. They intentionally remain deterministic for reproducibility.
    checked = 0
    for seed in [5, 11, 29, 47]:
        for profile in WORKLOAD_PROFILES:
            sample = generate_sales(512, seed=seed, profile=profile)
            con = create_sqlite_db(sample)
            stree = MerkleAggregateTree(sample, key_attr="day", fanout=16)
            for comp in [1, 3, 5]:
                pol = make_policy(tenant=(seed + comp + len(profile)) % 6, complexity=comp)
                man = make_manifest(pol)
                for lo2 in [0, 211, 509, 801]:
                    hi2 = min(999, lo2 + 37 + 3 * comp)
                    certx = stree.make_groupby_certificate(pol, lo2, hi2, manifest=man)
                    expected_contract_x = compile_sql_contract(
                        "SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category",
                        [lo2, hi2], man, f"tenant-{pol.tenant}", pol.purpose)
                    _check(stree.verify_groupby_certificate(certx, certx['owner_digest'], expected_contract_x), 'random certificate rejected')
                    expected_rows = normalize_result(sqlite_groupby(con, pol, lo2, hi2))
                    _check(json_to_result(certx['result']) == expected_rows, 'random SQLite mismatch')
                    checked += 1
            # profile-specific top-k check against direct authorized ordering
            score_tree = MerkleAggregateTree(sample, key_attr="score", fanout=16)
            pol = make_policy(tenant=(seed + len(profile)) % 6, complexity=3)
            man = make_manifest(pol)
            tk = topk_certificate(score_tree, sample, pol, 5, manifest=man)
            profile_topk_contract = compile_sql_contract(
                "SELECT id, score FROM sales WHERE score >= ? ORDER BY score DESC, id ASC LIMIT ?",
                [0, 5], man, f"tenant-{pol.tenant}", pol.purpose)
            _check(verify_topk_certificate(score_tree, tk, tk['owner_digest'], profile_topk_contract), 'profile top-k verifier failed')
            custs = customers_as_sales_like(generate_customers(sample, seed=seed))
            ctree = MerkleAggregateTree(custs, key_attr="cust_id", fanout=16)
            cjc = complete_fk_join_certificate(stree, ctree, sample, custs, pol, 0, 120, manifest=man)
            profile_fk_contract = compile_sql_contract(
                "SELECT c.segment, COUNT(*), SUM(s.amount) FROM sales s JOIN customers c ON s.cust_id = c.cust_id WHERE s.day BETWEEN ? AND ? AND c.active = 1 GROUP BY c.segment",
                [0, 120], man, f"tenant-{pol.tenant}", pol.purpose)
            _check(verify_complete_fk_join_certificate(stree, ctree, cjc, profile_fk_contract), 'profile complete FK join verifier failed')
            conj = create_sqlite_join_db(sample, custs)
            _check(json_to_join_result(cjc['result']) == sqlite_complete_join_groupby(conj, pol, 0, 120), 'profile complete FK join SQLite mismatch')
            conj.close()
            con.close()
            del sample, con, stree, score_tree, custs, ctree, cjc, conj, tk
            gc.collect()
        print(f'[test] randomized SQLite cross-check seed {seed} complete', flush=True)
    print('[test] randomized SQLite cross-checks complete', flush=True)
    _check(checked == 240, 'random invariant suite did not run fully')
    print(f"all prototype tests passed ({checked} randomized semantic cross-checks across {len(WORKLOAD_PROFILES)} synthetic profiles plus 2 public CSV profiles; distinct, anti-join, schema, and adversarial verifier checks enabled)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results", help="output directory for experiment CSV files")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--scale", choices=["quick", "paper", "stress"], default="paper")
    ap.add_argument("--test", action="store_true")
    args = ap.parse_args()
    if args.test:
        run_tests()
    else:
        run_experiments(args.out, seed=args.seed, scale=args.scale)


if __name__ == "__main__":
    main()

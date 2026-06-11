"""Descriptor-only verifier for Pacta group-by certificates.

This verifier is deliberately independent of ``MerkleAggregateTree``.  It
recomputes hashes, manifest policy, request binding, and the range proof using
only the owner descriptor, client contract, and certificate JSON.  It is used by
artifact tests to guard against server/verifier self-consistency bugs.
"""
from __future__ import annotations

import hashlib, json
from typing import Any, Dict, List, Optional, Sequence, Tuple

JSON = Dict[str, Any]
ACC_MOD = 2**127 - 1


def strict_json_int(value: Any, name: str) -> int:
    """Parse verifier-visible integers without accepting bool/float truncation."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer, not boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip() and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise ValueError(f"{name} must be an integer")

def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(tag: str, obj: Any) -> str:
    return hashlib.sha256((tag + "|" + canonical(obj)).encode("utf-8")).hexdigest()

def summary_digest(summary: JSON) -> str:
    return digest("summary", summary)

def manifest_root(manifest: JSON) -> str:
    return digest("policy_manifest", manifest)

def contract_digest(contract: JSON) -> str:
    return digest("pacta_query_contract_v1", contract)

def relation_descriptor_digest(desc: JSON) -> str:
    return digest("relation_descriptor", desc)

def row_accumulator(row: JSON) -> int:
    material = {
        "id": strict_json_int(row.get("id", row.get("cust_id", -1)), "row.id"),
        "tenant": strict_json_int(row.get("tenant", 0), "row.tenant"),
        "region": strict_json_int(row.get("region", 0), "row.region"),
        "category": strict_json_int(row.get("category", 0), "row.category"),
        "day": strict_json_int(row.get("day", 0), "row.day"),
        "amount": strict_json_int(row.get("amount", 0), "row.amount"),
        "score": strict_json_int(row.get("score", 0), "row.score"),
        "sensitivity": strict_json_int(row.get("sensitivity", 0), "row.sensitivity"),
        "cust_id": strict_json_int(row.get("cust_id", row.get("id", -1)), "row.cust_id"),
    }
    return int(hashlib.sha256(("row_acc|" + canonical(material)).encode("utf-8")).hexdigest(), 16) % ACC_MOD

def summary_key(row: JSON) -> str:
    return "|".join(str(strict_json_int(row[a], f"row.{a}")) for a in ("tenant", "sensitivity", "region", "category"))

def leaf_hash(row: JSON, summary: JSON, key: int, key_attr: str) -> str:
    return digest("leaf", {"key_attr": key_attr, "key": key, "row": row, "summary_digest": summary_digest(summary)})

def node_hash(min_key: int, max_key: int, count: int, sd: str, child_descriptors: Sequence[JSON], key_attr: str) -> str:
    return digest("node", {"key_attr": key_attr, "min": min_key, "max": max_key, "count": count, "summary_digest": sd, "children": list(child_descriptors)})

def compile_policy(manifest: JSON, subject: str, purpose: str) -> JSON:
    policies = [p for p in manifest.get("policies", []) if p.get("subject") == subject and p.get("purpose") == purpose]
    if len(policies) != 1:
        raise ValueError("manifest policy lookup not unique")
    pred = policies[0]["predicate"]
    return {
        "tenant": strict_json_int(pred["tenant"], "policy.tenant"),
        "regions": tuple(strict_json_int(x, "policy.region") for x in pred["regions"]),
        "max_sensitivity": strict_json_int(pred["max_sensitivity"], "policy.max_sensitivity"),
        "purpose": str(pred.get("purpose", purpose)),
        "projection": tuple(policies[0].get("projection", pred.get("projection", ()))),
    }

def policy_hash(policy: JSON) -> str:
    return digest("compiled_policy", {
        "tenant": policy["tenant"], "regions": list(policy["regions"]),
        "max_sensitivity": policy["max_sensitivity"], "purpose": policy["purpose"],
        "projection": list(policy["projection"]),
    })

def project_summary(summary: JSON, policy: JSON) -> Dict[int, Tuple[int, int]]:
    regions = set(policy["regions"])
    out: Dict[int, Tuple[int, int]] = {}
    for key, val in summary.items():
        tenant, sens, region, cat = (strict_json_int(x, "summary.key") for x in key.split("|"))
        if tenant == policy["tenant"] and sens <= policy["max_sensitivity"] and region in regions:
            cnt, total = strict_json_int(val[0], "summary.count"), strict_json_int(val[1], "summary.sum")
            oc, os = out.get(cat, (0, 0))
            out[cat] = (oc + cnt, os + total)
    return dict(sorted(out.items()))

def add_result(a: Dict[int, Tuple[int, int]], b: Dict[int, Tuple[int, int]]) -> Dict[int, Tuple[int, int]]:
    out = dict(a)
    for k, (c, s) in b.items():
        oc, os = out.get(k, (0, 0))
        out[k] = (oc + c, os + s)
    return dict(sorted(out.items()))

def _hash_cover(cert: JSON, key_attr: str) -> str:
    sd = summary_digest(cert["summary"])
    if sd != cert.get("summary_digest"):
        raise ValueError("bad summary digest")
    if "record" in cert:
        row = cert["record"]
        key = strict_json_int(row[key_attr], f"row.{key_attr}")
        summary = {summary_key(row): [1, strict_json_int(row["amount"], "row.amount"), row_accumulator(row)]}
        if summary_digest(summary) != sd:
            raise ValueError("bad leaf summary")
        if strict_json_int(cert["min"], "cert.min") != key or strict_json_int(cert["max"], "cert.max") != key or strict_json_int(cert["count"], "cert.count") != 1:
            raise ValueError("bad leaf metadata")
        return leaf_hash(row, summary, key, key_attr)
    child_desc = cert.get("child_descriptors")
    if not isinstance(child_desc, list) or not child_desc:
        raise ValueError("internal cover missing child descriptors")
    return node_hash(strict_json_int(cert["min"], "cert.min"), strict_json_int(cert["max"], "cert.max"), strict_json_int(cert["count"], "cert.count"), sd, child_desc, key_attr)

def _verify_node(cert: JSON, policy: JSON, lo: int, hi: int, key_attr: str) -> Tuple[str, Dict[int, Tuple[int, int]]]:
    kind = cert["kind"]
    if kind == "empty":
        return cert["hash"], {}
    mn, mx = strict_json_int(cert.get("min", -10**18), "cert.min"), strict_json_int(cert.get("max", 10**18), "cert.max")
    if kind == "hash":
        if not (mx < lo or mn > hi):
            raise ValueError("hash-only overlap")
        return cert["hash"], {}
    if kind == "cover":
        if not (lo <= mn and mx <= hi):
            raise ValueError("cover not contained")
        h = _hash_cover(cert, key_attr)
        if h != cert.get("hash"):
            raise ValueError("cover hash mismatch")
        return h, project_summary(cert["summary"], policy)
    if kind == "branch":
        children = cert.get("children", [])
        if not children:
            raise ValueError("empty branch")
        child_descriptors: List[JSON] = []
        acc: Dict[int, Tuple[int, int]] = {}
        total_count = 0
        last_max: Optional[int] = None
        for child in children:
            cmn = strict_json_int(child.get("min", mn), "child.min") if child.get("kind") != "empty" else mn
            cmx = strict_json_int(child.get("max", mx), "child.max") if child.get("kind") != "empty" else mx
            ccnt = strict_json_int(child.get("count", 0), "child.count")
            if last_max is not None and cmn < last_max:
                raise ValueError("children not ordered")
            last_max = cmx
            ch, cr = _verify_node(child, policy, lo, hi, key_attr)
            child_descriptors.append({"min": cmn, "max": cmx, "count": ccnt, "hash": ch})
            total_count += ccnt
            acc = add_result(acc, cr)
        if total_count != strict_json_int(cert["count"], "cert.count"):
            raise ValueError("bad count")
        h = node_hash(mn, mx, strict_json_int(cert["count"], "cert.count"), cert["summary_digest"], child_descriptors, key_attr)
        if h != cert.get("hash"):
            raise ValueError("branch hash mismatch")
        return h, acc
    raise ValueError("unknown node kind")

def verify_groupby_certificate_descriptor_only(cert: JSON, expected_contract: JSON, expected_owner_digest: JSON) -> bool:
    try:
        desc = cert["root_descriptor"]
        owner = cert["owner_digest"]
        if canonical(owner) != canonical(expected_owner_digest):
            return False
        if owner.get("relation_descriptor_digest") != relation_descriptor_digest(desc):
            return False
        if owner.get("relation_root") != desc.get("root") or owner.get("manifest_root") != manifest_root(cert["manifest"]):
            return False
        relation_version = strict_json_int(desc.get("version", owner.get("relation_version", -1)), "relation_version")
        manifest_version = strict_json_int(cert["manifest"].get("version", owner.get("manifest_release_version", owner.get("version", -2))), "manifest_version")
        if strict_json_int(owner.get("relation_version", relation_version), "owner.relation_version") != relation_version:
            return False
        if strict_json_int(owner.get("manifest_release_version", owner.get("version", manifest_version)), "owner.manifest_release_version") != manifest_version:
            return False
        if contract_digest(cert["query"]) != cert.get("request_digest") or contract_digest(expected_contract) != cert.get("request_digest"):
            return False
        q = cert["query"]
        if q.get("subject") != cert.get("subject") or q.get("purpose") != cert.get("purpose"):
            return False
        if q.get("op") != "range_groupby":
            return False
        policy = compile_policy(cert["manifest"], cert["subject"], cert["purpose"])
        if policy_hash(policy) != cert.get("policy_hash") or q.get("policy_hash") != cert.get("policy_hash"):
            return False
        proof = cert["proof"]
        if strict_json_int(proof.get("min", desc.get("min", 0)), "proof.min") != strict_json_int(desc["min"], "desc.min") or strict_json_int(proof.get("max", desc.get("max", 0)), "proof.max") != strict_json_int(desc["max"], "desc.max"):
            return False
        if strict_json_int(proof.get("count", desc.get("count", 0)), "proof.count") != strict_json_int(desc["count"], "desc.count"):
            return False
        h, result = _verify_node(proof, policy, strict_json_int(q["lo"], "query.lo"), strict_json_int(q["hi"], "query.hi"), desc.get("key_attr", "day"))
        claimed = {strict_json_int(k, "result.group"): (strict_json_int(v[0], "result.count"), strict_json_int(v[1], "result.sum")) for k, v in cert["result"].items()}
        return h == desc["root"] == cert.get("root") and dict(sorted(result.items())) == dict(sorted(claimed.items()))
    except Exception:
        return False

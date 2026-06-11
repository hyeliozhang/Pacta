"""Authenticated prefix-cube materialized view baseline.

A prefix cube is a strong OLAP baseline: the owner materializes day-prefix
summaries over policy dimensions and commits the prefix array with a Merkle tree.
A range group-by proof opens two prefix entries (hi and lo-1) and subtracts them.
This can be very compact, but it shifts cost to storage and updates.
"""
from __future__ import annotations

import hashlib, json, random, time, statistics, csv, os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

JSON = Dict[str, Any]


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(tag: str, obj: Any) -> str:
    return hashlib.sha256((tag + "|" + canonical(obj)).encode("utf-8")).hexdigest()


def sizeof_json(obj: Any) -> int:
    return len(canonical(obj).encode("utf-8"))


def _strict_prefix_int(value: Any, name: str) -> int:
    """Parse certificate-visible integers without Python's bool/float coercions."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer, not boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip() and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise ValueError(f"{name} must be an integer")


def policy_allows(row: Mapping[str, Any], policy: Mapping[str, Any]) -> bool:
    return _strict_prefix_int(row["tenant"], "row.tenant") == _strict_prefix_int(policy["tenant"], "policy.tenant") and _strict_prefix_int(row["sensitivity"], "row.sensitivity") <= _strict_prefix_int(policy["max_sensitivity"], "policy.max_sensitivity") and _strict_prefix_int(row["region"], "row.region") in {_strict_prefix_int(x, "policy.region") for x in policy["regions"]}

def summary_key(row: Mapping[str, Any]) -> str:
    return "|".join(str(_strict_prefix_int(row[field], f"row.{field}")) for field in ("tenant", "sensitivity", "region", "category"))

def add_summary(summary: Dict[str, List[int]], row: Mapping[str, Any], delta: int = 1) -> None:
    delta = _strict_prefix_int(delta, "summary.delta")
    k = summary_key(row)
    old = summary.get(k, [0, 0])
    old = [_strict_prefix_int(old[0], "summary.count"), _strict_prefix_int(old[1], "summary.sum")]
    old[0] += delta
    old[1] += delta * _strict_prefix_int(row["amount"], "row.amount")
    if old[0] == 0 and old[1] == 0:
        summary.pop(k, None)
    else:
        summary[k] = old

def project_summary(summary: Mapping[str, Sequence[int]], policy: Mapping[str, Any]) -> Dict[str, List[int]]:
    regions = {_strict_prefix_int(x, "policy.region") for x in policy["regions"]}
    out: Dict[str, List[int]] = {}
    for key, val in summary.items():
        parts = key.split("|")
        if len(parts) != 4:
            raise ValueError("summary key must have four dimensions")
        tenant, sens, region, cat = (_strict_prefix_int(x, "summary.key") for x in parts)
        if tenant == _strict_prefix_int(policy["tenant"], "policy.tenant") and sens <= _strict_prefix_int(policy["max_sensitivity"], "policy.max_sensitivity") and region in regions:
            oc, os = out.get(str(cat), [0, 0])
            out[str(cat)] = [_strict_prefix_int(oc, "summary.count") + _strict_prefix_int(val[0], "summary.count"), _strict_prefix_int(os, "summary.sum") + _strict_prefix_int(val[1], "summary.sum")]
    return dict(sorted(out.items(), key=lambda kv: _strict_prefix_int(kv[0], "summary.category")))

def subtract_summaries(a: Mapping[str, Sequence[int]], b: Mapping[str, Sequence[int]]) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {str(_strict_prefix_int(k, "summary.category")): [_strict_prefix_int(v[0], "summary.count"), _strict_prefix_int(v[1], "summary.sum")] for k, v in a.items()}
    for k, v in b.items():
        cat = str(_strict_prefix_int(k, "summary.category"))
        oc, os = out.get(cat, [0, 0])
        out[cat] = [_strict_prefix_int(oc, "summary.count") - _strict_prefix_int(v[0], "summary.count"), _strict_prefix_int(os, "summary.sum") - _strict_prefix_int(v[1], "summary.sum")]
    return {k: v for k, v in sorted(out.items(), key=lambda kv: _strict_prefix_int(kv[0], "summary.category")) if v != [0, 0]}


class MerkleList:
    def __init__(self, leaves: List[str]):
        self.n = len(leaves)
        size = 1
        while size < max(1, self.n):
            size *= 2
        self.size = size
        self.level = ["" for _ in range(2 * size)]
        empty = digest("empty_prefix_leaf", {})
        for i in range(size):
            self.level[size + i] = leaves[i] if i < self.n else empty
        for i in range(size - 1, 0, -1):
            self.level[i] = digest("prefix_node", [self.level[2 * i], self.level[2 * i + 1]])
        self.root = self.level[1]

    def proof(self, index: int) -> List[JSON]:
        pos = self.size + index
        out: List[JSON] = []
        while pos > 1:
            sib = pos ^ 1
            out.append({"side": "left" if sib < pos else "right", "hash": self.level[sib]})
            pos //= 2
        return out

    @staticmethod
    def verify(leaf_hash: str, index: int, proof: Sequence[Mapping[str, str]], root: str, *, n_leaves: int | None = None) -> bool:
        """Verify a Merkle-list path and bind it to the claimed leaf index.

        The hash recomputation alone authenticates some opened leaf, but an
        index-addressed prefix view must also prove that the opened leaf is the
        client's requested prefix entry.  Therefore the side sequence and path
        length are checked against the claimed index whenever the committed view
        length is known.
        """
        try:
            idx = _strict_prefix_int(index, "merkle.index")
            if n_leaves is not None:
                n = _strict_prefix_int(n_leaves, "merkle.n_leaves")
                if not (0 <= idx < n):
                    return False
                size = 1
                while size < max(1, n):
                    size *= 2
                if len(proof) != size.bit_length() - 1:
                    return False
                pos = size + idx
            else:
                pos = None
            h = leaf_hash
            for step in proof:
                side = step.get("side")
                if side not in {"left", "right"}:
                    return False
                if pos is not None:
                    expected = "left" if (pos ^ 1) < pos else "right"
                    if side != expected:
                        return False
                if side == "left":
                    h = digest("prefix_node", [step["hash"], h])
                else:
                    h = digest("prefix_node", [h, step["hash"]])
                if pos is not None:
                    pos //= 2
            return h == root
        except Exception:
            return False


@dataclass
class PrefixCube:
    max_day: int
    entries: List[JSON]
    leaves: List[str]
    root: str
    merkle: MerkleList

    @classmethod
    def build(cls, rows: Sequence[Mapping[str, Any]], *, max_day: int = 999) -> "PrefixCube":
        by_day: Dict[int, List[Mapping[str, Any]]] = {}
        for r in rows:
            by_day.setdefault(_strict_prefix_int(r["day"], "row.day"), []).append(r)
        current: Dict[str, List[int]] = {}
        entries: List[JSON] = []
        leaves: List[str] = []
        for day in range(max_day + 1):
            for r in by_day.get(day, []):
                add_summary(current, r, +1)
            entry = {"day": day, "summary": {k: list(v) for k, v in sorted(current.items())}}
            h = digest("prefix_cube_entry", entry)
            entry["entry_hash"] = h
            entries.append(entry)
            leaves.append(h)
        merkle = MerkleList(leaves)
        return cls(max_day, entries, leaves, merkle.root, merkle)

    def certificate(self, lo: int, hi: int, policy: Mapping[str, Any], *, relation_descriptor_digest: str = "") -> JSON:
        lo = max(0, _strict_prefix_int(lo, "lo")); hi = min(self.max_day, _strict_prefix_int(hi, "hi"))
        before_idx = max(0, lo - 1)
        hi_entry = self.entries[hi]
        before_entry = {"day": -1, "summary": {}, "entry_hash": digest("prefix_cube_entry", {"day": -1, "summary": {}})} if lo == 0 else self.entries[before_idx]
        hi_proj = project_summary(hi_entry["summary"], policy)
        before_proj = project_summary(before_entry["summary"], policy)
        result = subtract_summaries(hi_proj, before_proj)
        return {
            "scheme": "authenticated_prefix_cube_view",
            "root": self.root,
            "max_day": self.max_day,
            "lo": lo,
            "hi": hi,
            "relation_descriptor_digest": relation_descriptor_digest,
            "policy": {"tenant": _strict_prefix_int(policy["tenant"], "policy.tenant"), "max_sensitivity": _strict_prefix_int(policy["max_sensitivity"], "policy.max_sensitivity"), "regions": [_strict_prefix_int(x, "policy.region") for x in policy["regions"]]},
            "hi_entry": hi_entry,
            "hi_index": hi,
            "hi_path": self.merkle.proof(hi),
            "before_entry": before_entry,
            "before_index": -1 if lo == 0 else before_idx,
            "before_path": [] if lo == 0 else self.merkle.proof(before_idx),
            "result": result,
        }


def _normalize_policy(policy: Mapping[str, Any]) -> JSON:
    return {
        "tenant": _strict_prefix_int(policy["tenant"], "policy.tenant"),
        "max_sensitivity": _strict_prefix_int(policy["max_sensitivity"], "policy.max_sensitivity"),
        "regions": [_strict_prefix_int(x, "policy.region") for x in policy["regions"]],
    }


def verify_prefix_cube_certificate(
    cert: Mapping[str, Any],
    *,
    expected_lo: int | None = None,
    expected_hi: int | None = None,
    expected_policy: Mapping[str, Any] | None = None,
    expected_relation_descriptor_digest: str | None = None,
    expected_root: str | None = None,
) -> bool:
    """Verify an authenticated prefix-cube range certificate.

    The verifier binds the client-visible range (`lo`, `hi`), policy, relation
    descriptor digest, and expected materialized-view root to the two opened
    prefix entries.  Passing the expected root is required: otherwise the server
    could make a self-consistent but uncommitted prefix tree.
    """
    try:
        if expected_root is None:
            return False
        root = str(cert["root"])
        if root != str(expected_root):
            return False
        lo = _strict_prefix_int(cert["lo"], "cert.lo")
        hi = _strict_prefix_int(cert["hi"], "cert.hi")
        max_day = _strict_prefix_int(cert.get("max_day", hi), "cert.max_day")
        if not (0 <= lo <= hi <= max_day):
            return False
        if expected_lo is not None and lo != _strict_prefix_int(expected_lo, "expected_lo"):
            return False
        if expected_hi is not None and hi != _strict_prefix_int(expected_hi, "expected_hi"):
            return False
        if expected_relation_descriptor_digest is not None and str(cert.get("relation_descriptor_digest", "")) != str(expected_relation_descriptor_digest):
            return False

        policy = _normalize_policy(cert["policy"])
        if expected_policy is not None and canonical(policy) != canonical(_normalize_policy(expected_policy)):
            return False

        hi_index = _strict_prefix_int(cert["hi_index"], "cert.hi_index")
        if hi_index != hi:
            return False
        hi_entry = cert["hi_entry"]
        hi_payload = {"day": _strict_prefix_int(hi_entry["day"], "hi_entry.day"), "summary": hi_entry["summary"]}
        if _strict_prefix_int(hi_entry["day"], "hi_entry.day") != hi_index:
            return False
        if digest("prefix_cube_entry", hi_payload) != hi_entry.get("entry_hash"):
            return False
        if not MerkleList.verify(str(hi_entry["entry_hash"]), hi_index, cert["hi_path"], root, n_leaves=max_day + 1):
            return False

        before_index = _strict_prefix_int(cert["before_index"], "cert.before_index")
        expected_before_index = -1 if lo == 0 else lo - 1
        if before_index != expected_before_index:
            return False
        before_entry = cert["before_entry"]
        if before_index >= 0:
            before_payload = {"day": _strict_prefix_int(before_entry["day"], "before_entry.day"), "summary": before_entry["summary"]}
            if _strict_prefix_int(before_entry["day"], "before_entry.day") != before_index:
                return False
            if digest("prefix_cube_entry", before_payload) != before_entry.get("entry_hash"):
                return False
            if not MerkleList.verify(str(before_entry["entry_hash"]), before_index, cert["before_path"], root, n_leaves=max_day + 1):
                return False
        else:
            sentinel_payload = {"day": -1, "summary": {}}
            if before_entry != {**sentinel_payload, "entry_hash": digest("prefix_cube_entry", sentinel_payload)}:
                return False
            if cert.get("before_path") not in ([], ()):
                return False

        hi_proj = project_summary(hi_entry["summary"], policy)
        before_proj = project_summary(before_entry["summary"], policy)
        result = subtract_summaries(hi_proj, before_proj)
        return canonical(result) == canonical(cert["result"])
    except Exception:
        return False


def update_touched_prefixes(day: int, max_day: int = 999) -> int:
    return max(0, _strict_prefix_int(max_day, "max_day") - _strict_prefix_int(day, "day") + 1)


def run_prefix_cube_experiment(rows: Sequence[Mapping[str, Any]], policies: Sequence[Mapping[str, Any]], out_csv: str, *, n: int, relation_descriptor_digest: str = "") -> None:
    os.makedirs(os.path.dirname(out_csv), exist_ok=True)
    build_t0 = time.perf_counter()
    cube = PrefixCube.build(rows)
    build_ms = (time.perf_counter() - build_t0) * 1000.0
    records: List[JSON] = []
    for policy_i, policy in enumerate(policies):
        for width in (10, 50, 200):
            lo = (37 * (policy_i + 1) + width) % (1000 - width)
            hi = lo + width
            gen_samples: List[float] = []
            ver_samples: List[float] = []
            cert = None
            for _ in range(5):
                t0 = time.perf_counter(); cert = cube.certificate(lo, hi, policy, relation_descriptor_digest=relation_descriptor_digest); gen_samples.append((time.perf_counter() - t0) * 1000.0)
                t0 = time.perf_counter(); ok = verify_prefix_cube_certificate(cert, expected_lo=lo, expected_hi=hi, expected_policy=policy, expected_relation_descriptor_digest=relation_descriptor_digest, expected_root=cube.root); ver_samples.append((time.perf_counter() - t0) * 1000.0)
                if not ok: raise RuntimeError("prefix cube verifier rejected generated certificate")
            if cert is None:
                raise RuntimeError("prefix cube certificate generation produced no certificate")
            # Independent row oracle for this materialized view baseline.
            oracle: Dict[str, List[int]] = {}
            for r in rows:
                if lo <= _strict_prefix_int(r["day"], "row.day") <= hi and policy_allows(r, policy):
                    k = str(_strict_prefix_int(r["category"], "row.category")); old = oracle.get(k, [0, 0]); old[0] += 1; old[1] += _strict_prefix_int(r["amount"], "row.amount"); oracle[k] = old
            if canonical(dict(sorted(oracle.items(), key=lambda kv: _strict_prefix_int(kv[0], "summary.category")))) != canonical(cert["result"]):
                raise RuntimeError("prefix cube result mismatch with row oracle")
            records.append({
                "n": n, "scheme": "authenticated_prefix_cube_view", "range_width": width,
                "policy_index": policy_i, "certificate_bytes": sizeof_json(cert),
                "server_generation_ms": statistics.median(gen_samples), "client_verification_ms": statistics.median(ver_samples),
                "view_build_ms": build_ms, "view_entries": len(cube.entries), "view_root": cube.root[:16],
                "touched_prefixes_insert_median": update_touched_prefixes(500),
            })
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(records[0].keys())); w.writeheader(); w.writerows(records)

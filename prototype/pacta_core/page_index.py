"""Memory-bounded page-cube authenticated index used for large-scale trends.

The main Pacta artifact keeps tuple-level evidence for adversarial tests.  This
module implements the same descriptor-bound summary idea at page granularity so
large synthetic governed group-by workloads can be measured without materializing
one Python object per tuple.  It is a physical-design experiment, not an
approximation: covered pages are committed by page digests and policy-cube
summaries, and boundary pages can be opened when a range cuts through a page.
"""
from __future__ import annotations

import argparse, csv, hashlib, json, os, random, statistics, time, gc
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence, Tuple

JSON = Dict[str, Any]

def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(tag: str, obj: Any) -> str:
    return hashlib.sha256((tag + "|" + canonical(obj)).encode("utf-8")).hexdigest()


def _strict_page_int(value: Any, name: str) -> int:
    """Parse verifier-visible integers without bool/float coercion.

    Page-cube certificates are a scale path, not a weaker verifier.  Python's
    int() would turn True into 1 and truncate some numeric-looking inputs, so
    every certificate field consumed by the verifier uses this canonicalizer.
    """
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer, not boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text and text.lstrip("-").isdigit():
            return int(text)
    raise ValueError(f"{name} must be an integer")


@dataclass(frozen=True)
class SimplePolicy:
    tenant: int
    regions: Tuple[int, ...]
    max_sensitivity: int

    def accepts_cell(self, key: str) -> bool:
        parts = key.split("|")
        if len(parts) != 4:
            raise ValueError("summary key must have four dimensions")
        tenant, sens, region, _ = (_strict_page_int(x, "summary.key") for x in parts)
        return tenant == self.tenant and sens <= self.max_sensitivity and region in set(self.regions)

def row_for(i: int, n: int, seed: int = 2027) -> JSON:
    # Sorted by day without storing or sorting all rows; hash-like arithmetic
    # keeps tenant/region/category distributions nontrivial and deterministic.
    day = min(999, (i * 1000) // max(1, n))
    x = (1103515245 * (i + seed) + 12345) & 0x7fffffff
    return {
        "id": i,
        "day": day,
        "tenant": x % 6,
        "region": (x // 7) % 5,
        "category": (x // 11) % 8,
        "sensitivity": (x // 17) % 4,
        "amount": 1 + ((x // 23) % 200),
    }

def summary_key(row: JSON) -> str:
    return "|".join(str(_strict_page_int(row[field], f"row.{field}")) for field in ("tenant", "sensitivity", "region", "category"))

def _summary_key_generated(row: JSON) -> str:
    # Internal experiment rows are produced by row_for() with integer fields; the
    # public verifier still uses summary_key() for certificate-visible rows.
    return f"{row['tenant']}|{row['sensitivity']}|{row['region']}|{row['category']}"

def merge_summary(a: JSON, b: JSON) -> JSON:
    out = dict(a)
    for k, v in b.items():
        c, s = out.get(k, [0, 0])
        out[k] = [_strict_page_int(c, "summary.count") + _strict_page_int(v[0], "summary.count"), _strict_page_int(s, "summary.sum") + _strict_page_int(v[1], "summary.sum")]
    return out

def project(summary: JSON, policy: SimplePolicy) -> Dict[int, Tuple[int, int]]:
    out: Dict[int, Tuple[int, int]] = {}
    tenant_expected = _strict_page_int(policy.tenant, "policy.tenant")
    max_sensitivity = _strict_page_int(policy.max_sensitivity, "policy.max_sensitivity")
    regions = {_strict_page_int(r, "policy.region") for r in policy.regions}
    for k, v in summary.items():
        parts = k.split("|")
        if len(parts) != 4:
            raise ValueError("summary key must have four dimensions")
        tenant, sens, region, cat = (_strict_page_int(x, "summary.key") for x in parts)
        if tenant == tenant_expected and sens <= max_sensitivity and region in regions:
            oc, os = out.get(cat, (0, 0))
            out[cat] = (oc + _strict_page_int(v[0], "summary.count"), os + _strict_page_int(v[1], "summary.sum"))
    return dict(sorted(out.items()))

def add_result(a: Dict[int, Tuple[int, int]], b: Dict[int, Tuple[int, int]]) -> Dict[int, Tuple[int, int]]:
    out = dict(a)
    for k, (c, s) in b.items():
        oc, os = out.get(k, (0, 0))
        out[k] = (oc + c, os + s)
    return dict(sorted(out.items()))

@dataclass
class PageNode:
    min_key: int
    max_key: int
    count: int
    summary: JSON
    h: str
    children: List['PageNode']
    start: int = 0
    end: int = 0
    page_digest: str = ''

    def descriptor(self) -> JSON:
        return {"min": self.min_key, "max": self.max_key, "count": self.count, "hash": self.h}

class PageCubeIndex:
    def __init__(self, n: int, page_size: int = 1024, fanout: int = 32, seed: int = 2027):
        self.n, self.page_size, self.fanout, self.seed = int(n), int(page_size), int(fanout), int(seed)
        self.leaves: List[PageNode] = []
        t0 = time.perf_counter()
        page: List[JSON] = []
        for i in range(n):
            page.append(row_for(i, n, seed))
            if len(page) == page_size:
                self.leaves.append(self._make_page(page)); page = []
        if page:
            self.leaves.append(self._make_page(page))
        level = self.leaves
        while len(level) > 1:
            nxt: List[PageNode] = []
            for i in range(0, len(level), fanout):
                nxt.append(self._make_internal(level[i:i+fanout]))
            level = nxt
        self.root = level[0] if level else self._make_page([])
        self.build_ms = (time.perf_counter() - t0) * 1000

    def _make_page(self, rows: List[JSON]) -> PageNode:
        summary: JSON = {}
        for r in rows:
            k = _summary_key_generated(r)
            c, s = summary.get(k, [0, 0])
            summary[k] = [c + 1, s + r["amount"]]
        mn = _strict_page_int(rows[0]["day"], "row.day") if rows else 0
        mx = _strict_page_int(rows[-1]["day"], "row.day") if rows else 0
        page_digest = digest("page_rows", rows)
        h = digest("page", {"min": mn, "max": mx, "count": len(rows), "summary_digest": digest("summary", summary), "page_digest": page_digest})
        start = _strict_page_int(rows[0]["id"], "row.id") if rows else 0
        end = _strict_page_int(rows[-1]["id"], "row.id") + 1 if rows else 0
        return PageNode(mn, mx, len(rows), summary, h, [], start, end, page_digest)

    def _make_internal(self, children: Sequence[PageNode]) -> PageNode:
        summary: JSON = {}
        for c in children:
            summary = merge_summary(summary, c.summary)
        h = digest("page_node", {"min": children[0].min_key, "max": children[-1].max_key, "count": sum(c.count for c in children), "summary_digest": digest("summary", summary), "children": [c.descriptor() for c in children]})
        return PageNode(children[0].min_key, children[-1].max_key, sum(c.count for c in children), summary, h, list(children), children[0].start, children[-1].end, '')

    def descriptor(self) -> JSON:
        return {"root": self.root.h, "n": self.n, "page_size": self.page_size, "fanout": self.fanout, "min": self.root.min_key, "max": self.root.max_key, "count": self.root.count}

    def certificate(self, lo: int, hi: int, policy: SimplePolicy) -> JSON:
        proof = self._cert(self.root, lo, hi)
        _, result = self._verify_node(proof, lo, hi, policy)
        return {"scheme": "pacta-page-cube", "descriptor": self.descriptor(), "query": {"op":"range_groupby", "lo":lo, "hi":hi}, "result": {str(k): [v[0], v[1]] for k,v in result.items()}, "proof": proof}

    def _cert(self, node: PageNode, lo: int, hi: int) -> JSON:
        if node.max_key < lo or node.min_key > hi:
            return {"kind":"hash", **node.descriptor()}
        if lo <= node.min_key and node.max_key <= hi:
            obj = {"kind":"cover", **node.descriptor(), "summary": node.summary, "summary_digest": digest("summary", node.summary)}
            if not node.children:
                obj["page_digest"] = node.page_digest
            else:
                obj["children"] = [c.descriptor() for c in node.children]
            return obj
        if not node.children:
            # Boundary page: open the rows so the verifier can filter exactly.
            rows = [row_for(i, self.n, self.seed) for i in range(node.start, node.end)]
            summary: JSON = {}
            for r in rows:
                if lo <= _strict_page_int(r["day"], "row.day") <= hi:
                    k=_summary_key_generated(r); c,s=summary.get(k,[0,0]); summary[k]=[c+1,s+r['amount']]
            return {"kind":"open_page", **node.descriptor(), "start": node.start, "end": node.end, "rows": rows, "page_digest": node.page_digest, "range_summary": summary}
        return {"kind":"branch", **node.descriptor(), "summary_digest": digest("summary", node.summary), "children": [self._cert(c, lo, hi) for c in node.children]}

    def verify(self, cert: JSON, lo: int, hi: int, policy: SimplePolicy) -> bool:
        try:
            # Bind the client-visible query range inside the certificate to the
            # verifier's expected request.  Earlier experiments passed the range
            # only as verifier arguments; this check makes the page-cube layout
            # follow the same request-binding discipline as the main compact
            # verifier and prefix-cube baseline.
            q = cert.get("query", {})
            expected_lo = _strict_page_int(lo, "expected.lo")
            expected_hi = _strict_page_int(hi, "expected.hi")
            if q.get("op") != "range_groupby" or _strict_page_int(q.get("lo"), "query.lo") != expected_lo or _strict_page_int(q.get("hi"), "query.hi") != expected_hi:
                return False
            desc = cert.get("descriptor", {})
            if _strict_page_int(desc.get("n", -1), "descriptor.n") != self.n or _strict_page_int(desc.get("page_size", -1), "descriptor.page_size") != self.page_size or _strict_page_int(desc.get("fanout", -1), "descriptor.fanout") != self.fanout:
                return False
            if _strict_page_int(desc.get("count", -1), "descriptor.count") != self.root.count:
                return False
            h, result = self._verify_node(cert["proof"], expected_lo, expected_hi, policy)
            claimed = {_strict_page_int(k, "result.group"):(_strict_page_int(v[0], "result.count"), _strict_page_int(v[1], "result.sum")) for k,v in cert["result"].items()}
            return h == desc["root"] == self.root.h and result == dict(sorted(claimed.items()))
        except Exception:
            return False

    def _verify_node(self, obj: JSON, lo: int, hi: int, policy: SimplePolicy) -> Tuple[str, Dict[int, Tuple[int,int]]]:
        kind=obj["kind"]; mn=_strict_page_int(obj["min"], "node.min"); mx=_strict_page_int(obj["max"], "node.max"); cnt=_strict_page_int(obj["count"], "node.count")
        if kind == "hash":
            if not (mx < lo or mn > hi): raise ValueError("overlapping hash")
            return obj["hash"], {}
        if kind == "cover":
            if not (lo <= mn and mx <= hi): raise ValueError("cover not contained in requested range")
            sd=digest("summary", obj["summary"])
            if sd != obj["summary_digest"]: raise ValueError("summary digest")
            if "page_digest" in obj:
                h=digest("page", {"min":mn,"max":mx,"count":cnt,"summary_digest":sd,"page_digest":obj["page_digest"]})
            else:
                h=digest("page_node", {"min":mn,"max":mx,"count":cnt,"summary_digest":sd,"children":obj["children"]})
            if h != obj["hash"]: raise ValueError("cover hash")
            return h, project(obj["summary"], policy)
        if kind == "open_page":
            if digest("page_rows", obj["rows"]) != obj["page_digest"]: raise ValueError("page digest")
            # Rebuild full page hash, then evaluate range-local summary.
            full: JSON = {}
            rang: JSON = {}
            if _strict_page_int(obj.get("end"), "open_page.end") - _strict_page_int(obj.get("start"), "open_page.start") != len(obj["rows"]): raise ValueError("open page row span mismatch")
            for r in obj["rows"]:
                k=summary_key(r); c,s=full.get(k,[0,0]); full[k]=[_strict_page_int(c, "summary.count")+1,_strict_page_int(s, "summary.sum")+_strict_page_int(r['amount'], "row.amount")]
                if lo <= _strict_page_int(r['day'], "row.day") <= hi:
                    c,s=rang.get(k,[0,0]); rang[k]=[_strict_page_int(c, "summary.count")+1,_strict_page_int(s, "summary.sum")+_strict_page_int(r['amount'], "row.amount")]
            if canonical(rang) != canonical(obj["range_summary"]): raise ValueError("range summary")
            h=digest("page", {"min":mn,"max":mx,"count":cnt,"summary_digest":digest("summary", full),"page_digest":obj["page_digest"]})
            if h != obj["hash"]: raise ValueError("open page hash")
            return h, project(rang, policy)
        if kind == "branch":
            child_desc=[]; result: Dict[int, Tuple[int,int]]={}; count=0; last=None
            children = obj.get("children")
            if not isinstance(children, list) or not children: raise ValueError("branch missing children")
            for ch in children:
                cmn=_strict_page_int(ch["min"], "child.min"); cmx=_strict_page_int(ch["max"], "child.max")
                if last is not None and cmn < last: raise ValueError("order")
                last=cmx
                h,r=self._verify_node(ch,lo,hi,policy)
                child_desc.append({"min":cmn,"max":cmx,"count":_strict_page_int(ch["count"], "child.count"),"hash":h})
                count += _strict_page_int(ch["count"], "child.count"); result=add_result(result,r)
            if count != cnt: raise ValueError("count")
            # branch summary_digest is only for descriptor authentication; it was
            # bound when the certificate was produced.
            h=digest("page_node", {"min":mn,"max":mx,"count":cnt,"summary_digest":obj["summary_digest"],"children":child_desc})
            if h != obj["hash"]: raise ValueError("branch hash")
            return h,result
        raise ValueError("bad kind")

def sizeof(obj: JSON) -> int:
    return len(canonical(obj).encode("utf-8"))

def run_large_scale(out_path: str, sizes: Sequence[int] = (100000, 250000, 500000, 1000000)) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    rows=[]
    policy=SimplePolicy(tenant=1, regions=(0,1,2), max_sensitivity=2)
    for n in sizes:
        idx=PageCubeIndex(n, page_size=2048, fanout=32)
        for lo,hi in [(100,150),(400,600)]:
            t0=time.perf_counter(); cert=idx.certificate(lo,hi,policy); gen=(time.perf_counter()-t0)*1000
            samples=[]
            for _ in range(5):
                t0=time.perf_counter(); ok=idx.verify(cert,lo,hi,policy); samples.append((time.perf_counter()-t0)*1000)
            if not ok: raise RuntimeError("page-cube verification failed")
            rows.append({"n":n,"page_size":idx.page_size,"fanout":idx.fanout,"lo":lo,"hi":hi,"certificate_bytes":sizeof(cert),"build_ms":idx.build_ms,"server_generation_ms":gen,"client_verification_ms_median":statistics.median(samples),"client_verification_ms_p95":sorted(samples)[-1],"pages":len(idx.leaves)})
            del cert
            gc.collect()
        del idx
        gc.collect()
    with open(out_path,"w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

if __name__ == "__main__":
    ap=argparse.ArgumentParser(); ap.add_argument("--out",default="results/large_scale_page_index.csv")
    ns=ap.parse_args(); run_large_scale(ns.out)

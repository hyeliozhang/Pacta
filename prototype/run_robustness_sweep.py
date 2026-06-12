#!/usr/bin/env python3
"""Multi-seed robustness checks for the Pacta artifact.

This is an anti-cherry-picking sweep: it uses seeds that are not used by the
headline matrix, varies workload profile, selectivity, and policy complexity,
and checks every certificate against the same SQLite oracle.
"""
from __future__ import annotations
import csv, os, statistics, sys, time
from collections import defaultdict
from typing import Dict, Iterable, List
sys.path.insert(0, os.path.dirname(__file__))
import pacta
from pacta_core.frontier_witness import write_witness_csv
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RESULTS = os.path.join(ROOT, 'results')
os.makedirs(RESULTS, exist_ok=True)
PROFILES = ['dashboard_sales','tpch_lineitem_like','open_data_permits','health_release','finance_audit']
SEEDS = [1701, 1723, 1759, 1789]
SELECTIVITIES = [0.02, 0.05, 0.10, 0.20]
COMPLEXITIES = [1, 3, 5]
N = 3000

def write_rows(path: str, rows: List[Dict[str, object]]) -> None:
    if not rows: return
    keys=[]
    for r in rows:
        for k in r:
            if k not in keys: keys.append(k)
    tmp = path + '.tmp'
    with open(tmp, 'w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(rows)
    os.replace(tmp, path)

def load_rows(path: str) -> List[Dict[str, object]]:
    if not os.path.exists(path):
        return []
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def setting_key(r: Dict[str, object]):
    return (str(r['profile']), int(r['seed']), float(r['selectivity']), int(r['policy_complexity']))

def timed(fn, *args, repeat: int = 1, **kwargs):
    vals=[]; out=None
    for _ in range(repeat):
        t0=time.perf_counter_ns(); out=fn(*args, **kwargs); vals.append((time.perf_counter_ns()-t0)/1e6)
    return out, statistics.median(vals)

def q(vals: Iterable[float], frac: float) -> float:
    xs=sorted(float(v) for v in vals)
    if not xs: return 0.0
    if len(xs)==1: return xs[0]
    pos=(len(xs)-1)*frac; lo=int(pos); hi=min(lo+1, len(xs)-1); f=pos-lo
    return xs[lo]*(1-f)+xs[hi]*f

def med(vals: Iterable[float]) -> float:
    xs=[float(v) for v in vals]
    return statistics.median(xs) if xs else 0.0

def main() -> None:
    grid_path = os.path.join(RESULTS, 'robustness_grid.csv')
    out: List[Dict[str, object]] = load_rows(grid_path)
    done = {setting_key(r) for r in out}
    expected = len(PROFILES) * len(SEEDS) * len(COMPLEXITIES) * len(SELECTIVITIES)
    for profile in PROFILES:
        for seed in SEEDS:
            if len(done) >= expected:
                break
            rows = pacta.generate_sales(N, seed=seed, profile=profile)
            con = pacta.create_sqlite_db(rows)
            tree, build_ms = timed(pacta.MerkleAggregateTree, rows, 'day', 16)
            for comp in COMPLEXITIES:
                policy = pacta.make_policy(tenant=(seed + comp + len(profile)) % 6, complexity=comp)
                manifest = pacta.make_manifest(policy)
                for sel in SELECTIVITIES:
                    key = (profile, seed, float(sel), comp)
                    if key in done:
                        continue
                    width=max(1, int(1000*sel))
                    lo=(seed*31 + comp*19 + len(profile)*17 + int(sel*1000)) % (1000-width)
                    hi=lo+width
                    sql_res, sql_ms = timed(pacta.sqlite_groupby, con, policy, lo, hi)
                    cert, gen_ms = timed(tree.make_groupby_certificate, policy, lo, hi, manifest=manifest)
                    contract = pacta.compile_sql_contract('SELECT category, COUNT(*), SUM(amount) FROM sales WHERE day BETWEEN ? AND ? GROUP BY category', [lo,hi], manifest, f'tenant-{policy.tenant}', policy.purpose)
                    ok, ver_ms = timed(tree.verify_groupby_certificate, cert, cert['owner_digest'], contract, repeat=5)
                    if not ok or pacta.normalize_result(sql_res) != pacta.json_to_result(cert['result']):
                        raise RuntimeError('robustness semantic mismatch')
                    out.append({'profile':profile,'seed':seed,'n':N,'selectivity':sel,'policy_complexity':comp,
                                'certificate_bytes':pacta.sizeof_json(cert),'server_generation_ms':gen_ms,
                                'client_verification_ms':ver_ms,'sqlite_query_ms':sql_ms,
                                'authorized_rows':len(pacta.rows_in_range(rows, lo, hi, policy)),
                                'range_rows':len(pacta.rows_in_range(rows, lo, hi, None)),
                                'tree_build_ms':build_ms,'semantic_checked':True})
                    done.add(key)
                    write_rows(grid_path, out)
            con.close()
    out = load_rows(grid_path)
    if len(out) != expected:
        raise RuntimeError(f'robustness sweep incomplete: {len(out)} of {expected} settings')
    summary=[]
    for metric in ['certificate_bytes','server_generation_ms','client_verification_ms','sqlite_query_ms','authorized_rows','range_rows']:
        vals=[float(r[metric]) for r in out]
        summary.append({'metric':metric,'n':N,'settings':len(out),'median':med(vals),'p05':q(vals,0.05),'p95':q(vals,0.95),'min':min(vals),'max':max(vals)})
    write_rows(os.path.join(RESULTS, 'robustness_summary.csv'), summary)
    by=defaultdict(list)
    for r in out: by[r['profile']].append(r)
    prof=[]
    for profile, rr in sorted(by.items()):
        prof.append({'profile':profile,'settings':len(rr),'median_certificate_kib':med(float(r['certificate_bytes'])/1024.0 for r in rr),'p95_certificate_kib':q((float(r['certificate_bytes'])/1024.0 for r in rr),0.95),'median_verify_ms':med(r['client_verification_ms'] for r in rr),'p95_verify_ms':q((r['client_verification_ms'] for r in rr),0.95),'median_authorized_rows':med(r['authorized_rows'] for r in rr)})
    write_rows(os.path.join(RESULTS, 'robustness_by_profile.csv'), prof)
    write_witness_csv(os.path.join(RESULTS, 'frontier_indistinguishability.csv'))
    print(f'[robustness] compact robustness sweep complete: {len(out)} settings')
if __name__ == '__main__':
    main()

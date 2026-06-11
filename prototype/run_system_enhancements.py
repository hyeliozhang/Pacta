#!/usr/bin/env python3
from __future__ import annotations
import csv, os, statistics, sys, time
from typing import Dict, List
sys.path.insert(0, os.path.dirname(__file__))
import pacta
from pacta_core.catalog import CatalogEntry, sign_entry, verify_signed_entry, catalog_root, digest
from pacta_core.leakage import leakage_matrix
from pacta_core.prefix_cube import run_prefix_cube_experiment, PrefixCube, verify_prefix_cube_certificate, sizeof_json

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RESULTS = os.path.join(ROOT, 'results')
os.makedirs(RESULTS, exist_ok=True)

def write_rows(path: str, rows: List[Dict[str, object]]) -> None:
    if not rows:
        return
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

def median(xs):
    return statistics.median([float(x) for x in xs]) if xs else 0.0

print('[system] prefix-cube materialized-view baseline', flush=True)
rows_50k = pacta.generate_sales(50000, seed=16050)
policies = [pacta.make_policy(tenant=i % 6, complexity=c).to_dict() for i, c in enumerate([1, 3, 5])]
run_prefix_cube_experiment(rows_50k, policies, os.path.join(RESULTS, 'prefix_cube.csv'), n=50000, relation_descriptor_digest='paper-run')
with open(os.path.join(RESULTS, 'prefix_cube.csv'), newline='', encoding='utf-8') as f:
    pref = list(csv.DictReader(f))
write_rows(os.path.join(RESULTS, 'prefix_cube_medians.csv'), [{
    'scheme': 'authenticated_prefix_cube_view',
    'n': 50000,
    'median_certificate_bytes': median(r['certificate_bytes'] for r in pref),
    'median_generation_ms': median(r['server_generation_ms'] for r in pref),
    'median_verification_ms': median(r['client_verification_ms'] for r in pref),
    'median_view_build_ms': median(r['view_build_ms'] for r in pref),
    'median_touched_prefixes_insert': median(r['touched_prefixes_insert_median'] for r in pref),
}])

print('[system] signed catalog freshness and replay checks', flush=True)
policy = pacta.make_policy(tenant=1, complexity=3)
manifest = pacta.make_manifest(policy, version=9)
tree = pacta.MerkleAggregateTree(rows_50k[:5000], key_attr='day', fanout=16)
owner = pacta.owner_digest(tree.relation_descriptor(), manifest)
entry = CatalogEntry('sales', tree.version, int(manifest['version']), 123, owner, owner['relation_descriptor_digest'], owner['manifest_root'])
signed = sign_entry(entry, b'pacta-artifact-secret').to_dict()
catalog_rows = [
    {'case': 'fresh_signed_descriptor', 'accepted': verify_signed_entry(signed, b'pacta-artifact-secret', min_epoch=123, expected_relation='sales', expected_relation_version=tree.version, expected_manifest_version=9)},
    {'case': 'replayed_epoch', 'accepted': verify_signed_entry(signed, b'pacta-artifact-secret', min_epoch=124, expected_relation='sales', expected_relation_version=tree.version, expected_manifest_version=9)},
]
tampered = {k: v for k, v in signed.items()}
tampered['entry'] = {k: v for k, v in signed['entry'].items()}; tampered['entry']['manifest_version'] = 10
catalog_rows.append({'case': 'tampered_manifest_version', 'accepted': verify_signed_entry(tampered, b'pacta-artifact-secret', min_epoch=123, expected_relation='sales', expected_relation_version=tree.version, expected_manifest_version=9)})
catalog_rows.append({'case': 'catalog_root_prefix', 'accepted': catalog_root([signed])[:16]})
write_rows(os.path.join(RESULTS, 'catalog_freshness.csv'), catalog_rows)

print('[system] executable leakage contracts', flush=True)
projection = ['category', 'count', 'sum(amount)']
leak_rows = leakage_matrix(['policy_cube_summary', 'prefix_cube_view', 'complete_open_scan', 'topk_accumulator', 'join_witness'], projection)
write_rows(os.path.join(RESULTS, 'leakage_profiles.csv'), leak_rows)

print('[system] SSB-style profile sanity run', flush=True)
# A deterministic star-schema-inspired profile: skewed tenants/categories and daily lineorder-style facts.
ssb_rows = pacta.generate_sales(100000, seed=16100)
# Reweight category/day to mimic star-schema dashboard skew while staying within Pacta's committed schema.
for r in ssb_rows:
    r['category'] = (int(r['cust_id']) * 7 + int(r['day']) // 31) % 12
    r['region'] = (int(r['tenant']) + int(r['category'])) % 8
    r['amount'] = 10 + ((int(r['cust_id']) * 13 + int(r['day']) * 3) % 500)
ssb_policy = {'tenant': 2, 'max_sensitivity': 2, 'regions': [0, 1, 2, 3]}
ssb_cube = PrefixCube.build(ssb_rows)
ssb_records: List[Dict[str, object]] = []
for lo, hi in [(10, 40), (100, 220), (300, 620)]:
    gen_s=[]; ver_s=[]; cert=None
    for _ in range(3):
        t0=time.perf_counter(); cert=ssb_cube.certificate(lo, hi, ssb_policy, relation_descriptor_digest='ssb-style'); gen_s.append((time.perf_counter()-t0)*1000.0)
        t0=time.perf_counter(); ok=verify_prefix_cube_certificate(cert, expected_lo=lo, expected_hi=hi, expected_policy=ssb_policy, expected_relation_descriptor_digest='ssb-style', expected_root=ssb_cube.root); ver_s.append((time.perf_counter()-t0)*1000.0)
        if not ok: raise RuntimeError('SSB-style prefix verifier rejected certificate')
    ssb_records.append({'profile':'ssb_star_lineorder_style','n':100000,'lo':lo,'hi':hi,'certificate_bytes':sizeof_json(cert),'server_generation_ms':statistics.median(gen_s),'client_verification_ms':statistics.median(ver_s),'groups':len(cert['result'])})
write_rows(os.path.join(RESULTS, 'ssb_star_profile.csv'), ssb_records)
write_rows(os.path.join(RESULTS, 'ssb_star_medians.csv'), [{
    'profile':'ssb_star_lineorder_style','n':100000,
    'median_certificate_bytes':median(r['certificate_bytes'] for r in ssb_records),
    'median_generation_ms':median(r['server_generation_ms'] for r in ssb_records),
    'median_verification_ms':median(r['client_verification_ms'] for r in ssb_records),
}])
print('[system] enhancements complete', flush=True)

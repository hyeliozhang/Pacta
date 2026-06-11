# Pacta Evidence Log

This document ties the paper claims to reproducible artifact outputs. Paper prose avoids project-path dependencies; paths here are for reviewers inspecting the supplemental package.

- Final polish updates the title author block to two ICDE-style authors with shared affiliation and compact email line, removes the ORCID line from the PDF author block, deduplicates the AI acknowledgement, and regenerates the two schematic figures with larger labels and a stricter single-column camera-ready layout.

## Reproduction commands

Quick check:

```bash
./run_ci.sh
```

Full reproduction:

```bash
./run_all.sh
```

## Paper claims and artifact files

| Paper claim | Artifact evidence |
|---|---|
| Full-baseline median compact Pacta certificate is 31.4 KiB with 3.64 ms generation and 1.98 ms verification | `results/scheme_medians.csv` row `pacta`: 32166.5 bytes, 3.640990 ms generation, 1.979036 ms verification |
| Unsound compact baselines fail specific attacks | `results/detection.csv`; `provenance_only` accepts omission; `policy_oblivious` accepts policy widening |
| Descriptor-only client boundary verifies compact certificates without server tree object | `prototype/pacta_core/independent_verifier.py`; `tests/test_descriptor_verifier.py`; sample in `results/cert_samples/pacta_groupby_sample.json` |
| Contract IR binds typed requests | `prototype/pacta_core/contract_ir.py`; `tests/test_contract_ir.py` |
| SQLite semantic oracle checks governed answers independently | `pacta.run_tests()`; `prototype/pacta.py`; 240 randomized SQLite semantic cross-checks plus two public CSV profile loads |
| Adversarial mutation tests reject wrong evidence | `pacta.run_tests()`; `results/detection.csv`; mutations cover request, manifest, projection, range, version, returned-pair join segment binding, joins, top-k, disclosure, and omissions |
| Optimizer rejects inadmissible shortcuts before cost ranking | `prototype/pacta_core/optimizer.py`; `tests/test_optimizer_properties.py`; `results/optimizer_trace.csv`; `results/planner_frontier_medians.csv` |
| Signed catalog freshness rejects replay and manifest-version tampering | `prototype/pacta_core/catalog.py`; `tests/test_catalog_leakage_prefix.py`; `results/catalog_freshness.csv` |
| Leakage contracts distinguish compact summaries from opened-row plans | `prototype/pacta_core/leakage.py`; `tests/test_catalog_leakage_prefix.py`; `results/leakage_profiles.csv` |
| Exact distinct, AVG, HAVING, projection, open-scan fallback costs | `results/operator_contracts.csv`; `results/operator_contract_medians.csv` |
| Top-k and join/anti-join/many-to-many costs and tests | `results/topk.csv`, `results/join.csv`, `results/join_complete.csv`, `results/join_antijoin.csv`, `results/join_many_to_many.csv`; integrated test suite in `pacta.run_tests()` |
| Non-key and structural update costs | `results/updates.csv`; `results/structural_updates.csv`; `figs/update_cost.pdf` |
| Page-cube 1M-row scale trend | `results/large_scale_page_index.csv`; `results/large_scale_page_medians.csv`; `figs/large_scale_page_index.pdf` |
| Prefix-cube materialized-view baseline | `prototype/pacta_core/prefix_cube.py`; `results/prefix_cube.csv`; `results/prefix_cube_medians.csv`; `figs/physical_design_frontier.pdf` |
| Public tabular profile mappings | `external_data/`, `DATA_ATTRIBUTION.md`, `results/workload_profile_medians.csv` |
| Robustness over unused seeds/profiles/selectivities/policy complexities | `results/robustness_grid.csv`, `results/robustness_summary.csv`, `results/robustness_by_profile.csv` |
| Compact summary cannot decide unsummarized predicates | `prototype/pacta_core/frontier_witness.py`; `results/frontier_indistinguishability.csv`; `tests/test_frontier_witness.py` |

## Key numeric anchors

- Full-baseline matrix: Pacta median 32166.5 bytes (31.4 KiB), 3.640989 ms generation, 1.979036 ms verification.
- Largest medium-policy slice: Pacta 58528.0 bytes (57.2 KiB), 4.837960 ms generation, 2.704279 ms verification.
- Compact-path scalability: median verification 1.67 ms at 2K rows, 2.63 ms at 5K, 4.04 ms at 20K, and 5.96 ms at 50K; generation rises from 2.66 ms to 10.91 ms, with a 164.3 KiB median certificate at 50K.
- 1M page-cube median: 820566.0 bytes (801.3 KiB), 115.543168 ms generation, 84.831028 ms verification, 489.0 authenticated pages, 4.774573 s build.
- Prefix cube at 50K rows: 23057.0 bytes (22.5 KiB), 2.155932 ms generation, 2.888724 ms verification, 1.144015 s view build, 500.0 touched prefixes for an insert.
- 100K star-schema prefix profile: 11562.0 bytes (11.3 KiB), 0.896627 ms generation, 1.337419 ms verification.
- Planner frontier: compact policy-cube median 52245.5 bytes (51.0 KiB) versus open-range scan 3095629.0 bytes (2.95 MiB) for governed group-by; compact plan is inadmissible for unsummarized row predicates.
- Robustness sweep: 240 settings, median 40769.5 bytes (39.8 KiB), p95 83105.0 bytes (81.2 KiB), median verification 2.270523 ms, p95 verification 3.303544 ms.

## Attack and negative-control coverage

The integrated suite checks aggregate tampering, stale/wrong version, policy filter widening, manifest tampering, projection mask tampering, request substitution, query range mutation, root descriptor tampering, omitted in-range tuple, count-distinct omission, anti-join hidden match, open-scan predicate mutation, open-scan omission, top-k predicate substitution, top-k omission, returned-pair join tampering, complete FK join omission, complete many-to-many tag omission, disclosure-contract violation, range-boundary relabeling, post-update certificates, and structural-version rebuilding.

## Submission preflight

`tools/submission_preflight.py` checks that there is no `\nocite` padding, all bibliography entries are cited, the paper has 76 real cited references, the LaTeX log has no errors/undefined citations/overfull hboxes, the PDF has 14 pages with acknowledgement/references starting on page 13, fonts are embedded, and reviewer-facing documentation has no obsolete version labels and no stale nested package directories.

## Numeric consistency guard

`tools/results_consistency.py` recomputes the paper's visible numeric anchors from the bundled CSV files and fails if the manuscript prose/table values drift from the artifact results.

- The artifact keeps the operator-field smuggling guard: known request fields are rejected when attached to an incompatible operator rather than being hashed but semantically ignored.

- It keeps descriptor-typed dimension attributes: customer `active`/`segment` and category-tag `tag` fields are committed as NOT NULL JSON integers in relation descriptors, with regression tests rejecting string, boolean, float, or missing encodings.

- It adds a prefix-cube verifier regression guard: prefix-view certificates must be checked against the expected committed view root and strict numeric range/index fields, so a self-consistent but uncommitted prefix tree fails closed.

- It fixes the LaTeX/preflight blind spot: the final build log has no TeX `!` error markers, and `tools/submission_preflight.py` now fails on any top-level TeX error line.

- It adds scale-path verifier hardening: page-cube certificates now reject compact covers whose descriptor interval is not contained in the requested range, enforce strict integer parsing on page-cube query/descriptor/result/node fields, and prefix-cube Merkle paths are bound to the claimed prefix index and committed view length. Regression coverage is in `tests/test_page_index.py` and `tests/test_catalog_leakage_prefix.py`.
- It adds certificate-encoding hardening: verifier-visible node metadata, leaf-path metadata, result cells, and committed row fields used in certificate checks reject ambiguous boolean/float/null encodings. Regression coverage is in `tests/test_certificate_encoding.py`.

- The artifact performs a figure-specific production pass: all manuscript figures are regenerated from Python with a consistent publication style, vector PDF/PNG exports, embedded non-base fonts, a CI figure/style audit, and a visual full-PDF render check.

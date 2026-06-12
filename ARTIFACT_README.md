# Pacta Artifact README

This supplemental artifact accompanies the paper **"Pacta: Certifying Evidence Plans for Governed Analytical Queries"**.

## Contents

- Paper source: `main.tex`, `references.bib`, `IEEEtran.cls`, `IEEEtran.bst`.
- Compiled manuscript: `main.pdf`.
- Prototype: `prototype/pacta.py` plus the modular `prototype/pacta_core/` package.
- Experiments and figures: `run_all.sh`, `run_ci.sh`, `prototype/plot_results.py`, result CSVs, and vector figures.
- Tests: `tests/` plus the integrated semantic/adversarial test suite.
- External tabular profiles: `external_data/` with attribution in `DATA_ATTRIBUTION.md`.
- Evidence and checks: `EVIDENCE.md`, `STATUS.md`, `FORMAT_CHECK.md`, `ARTIFACT_CHECKLIST.md`, `SCOPE_GUARD.md`, `RELATED_WORK_MATRIX.md`, `SUPPLEMENTAL_SUBMISSION.md`, and `tools/`.

## Quick check

Run:

```bash
bash run_ci.sh
```

Expected outcome: the integrated Pacta semantic/adversarial suite passes, 38 unit tests pass, the manuscript/package preflight reports citation/PDF/font/log checks as OK, the structure and layout guards confirm the intended page/section structure and page-12 body fill, the results-consistency guard confirms that manuscript numeric anchors match the bundled CSVs, and the figure-quality guard confirms vector/PNG exports, fonts, and plot scripts.

## Full reproduction

Run:

```bash
bash run_all.sh
```

This executes the paper-scale matrix, stress experiments, page-cube trend, signed catalog/leakage/prefix-cube/star-schema experiments, multi-seed robustness sweep, tests, figure generation, LaTeX build, and the same preflight checks. The script is portable: it uses `${PYTHON:-python3}` and does not rely on container-specific Python paths.

## Container option

```bash
docker build -t pacta-artifact .
docker run --rm pacta-artifact
```

The Docker image runs `run_all.sh` by default. The accompanying `.dockerignore` keeps local environments, build byproducts, credentials, and local archives outside the build context.

## Main modules

- `pacta.py`: workload generation, descriptor tree, certificate generation/verification, operator experiments, adversarial tests.
- `pacta_core/contract_ir.py`: typed governed-query contract IR and obligation extraction.
- `pacta_core/optimizer.py`: certifying evidence-plan optimizer with schema/version/manifest obligations and rejection reasons.
- `pacta_core/independent_verifier.py`: descriptor-only compact certificate verifier.
- `pacta_core/catalog.py`: signed descriptor catalog and freshness checks.
- `pacta_core/leakage.py`: executable disclosure/leakage contracts for evidence plans.
- `pacta_core/page_index.py`: memory-bounded page-cube authenticated layout.
- `pacta_core/prefix_cube.py`: authenticated prefix-cube materialized-view baseline.
- `pacta_core/measurement.py`: hardware/runtime measurement helpers.
- `pacta_core/encoding.py`: JSON/gzip/logical-binary certificate-size estimates.

## Reproducibility notes

- Synthetic workloads use deterministic seeds; the paper headline run uses seed 2027.
- The robustness sweep uses additional seeds 1701, 1723, 1759, and 1789.
- The public CSV profiles are bundled to avoid network dependence.
- `results/repro.json` records deterministic reproduction settings without a wall-clock timestamp.
- The artifact does not require GPU, cloud services, a blockchain network, trusted hardware, or external paid services.

## Validation scope

The manuscript has 76 cited references with no bibliography padding. The quick check includes bibliography integrity, PDF page structure, embedded fonts, LaTeX log errors, stale package labels, section/page structure, page-12 layout fill, artifact coverage, obligation-coverage alignment, and a CSV-to-manuscript numeric consistency guard.

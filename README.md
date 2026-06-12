# Pacta

Pacta is a reproducibility artifact for **"Pacta: Certifying Evidence Plans for Governed Analytical Queries."** It contains the paper PDF and source, a Python prototype, deterministic experiment outputs, figure-generation code, and checks that connect manuscript claims to artifact files.

## Quick Start

The artifact is CPU-only. It does not require a GPU, cloud service, paid API, blockchain system, trusted hardware, or external network access after cloning.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
bash run_ci.sh
```

The quick check runs syntax checks, verifier tests, unit tests, manuscript/package preflight, numeric consistency checks, and figure/documentation guards.

For a clean container run:

```bash
docker build -t pacta-artifact .
docker run --rm pacta-artifact
```

For full regeneration of bundled result CSVs, figures, and `main.pdf`:

```bash
bash run_all.sh
```

## Repository Layout

| Path | Purpose |
|---|---|
| `main.pdf` | Compiled manuscript corresponding to the source in this repository. |
| `main.tex`, `references.bib`, `IEEEtran.*` | Paper source and template files. |
| `prototype/` | Pacta prototype, experiment drivers, and figure-generation scripts. |
| `prototype/pacta_core/` | Contract IR, optimizer, verifier, catalog, leakage, page-cube, prefix-cube, measurement, and encoding modules. |
| `tests/` | Focused unit tests for core verifier and optimizer behavior. |
| `results/` | Deterministic CSV and JSON outputs used by the manuscript and figures. |
| `figs/` | Reproducible vector/PDF and PNG figures generated from bundled outputs. |
| `tools/` | Preflight, consistency, layout, figure, and obligation checks. |
| `external_data/` | Small public CSV profiles with attribution in `DATA_ATTRIBUTION.md`. |

## Main Checks

- `tools/submission_preflight.py`: citations, bibliography use, LaTeX log health, PDF page shape, and embedded-font checks.
- `tools/results_consistency.py`: manuscript numbers against bundled CSV outputs.
- `tools/layout_audit.py`: page-12 body fill and page-13 transition checks.
- `tools/figure_quality_audit.py`: vector/PNG figure availability, figure fonts, and publication-figure settings.
- `tools/obligation_coverage_audit.py`: alignment among manuscript terminology, contract IR, optimizer obligations, and tests.

## Evidence Map

The fastest way to inspect the artifact is:

1. Read `ARTIFACT_README.md` for the detailed reproduction path.
2. Read `CLAIMS_TO_EVIDENCE.md` to map each major manuscript claim to files and checks.
3. Run `bash run_ci.sh`.
4. Use `bash run_all.sh` when regenerating experiments, figures, and the PDF from scratch.

The artifact uses deterministic seeds. Timing values can vary by machine, but verifier accept/reject decisions, semantic-oracle outcomes, and numeric anchors checked by `tools/results_consistency.py` are fixed by the supplied inputs.

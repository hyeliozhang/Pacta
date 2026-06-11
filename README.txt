Pacta artifact package
=========================================

This package contains the reproducibility artifact for "Pacta: Certifying Evidence Plans for Governed Analytical Queries".

Top-level contents:

- main.pdf: compiled paper.
- main.tex, references.bib, IEEEtran.cls, IEEEtran.bst: paper source.
- prototype/: implementation and experiment drivers.
- prototype/pacta_core/: modular contract IR, optimizer, descriptor-only verifier, signed catalog, leakage contracts, page-cube, prefix-cube, measurement, and encoding components.
- tests/: unit tests for core modules.
- tools/submission_preflight.py, tools/results_consistency.py, tools/paper_audit.py, tools/layout_audit.py, and tools/obligation_coverage_audit.py: citation, PDF, font, log, page-structure, page-12 fill, section-structure, artifact-coverage, obligation-alignment, and numeric-consistency checks.
- external_data/: bundled public CSV profiles with attribution.
- results/: regenerated CSV outputs used by the paper.
- figs/: generated vector figures.
- run_ci.sh: quick artifact and submission preflight.
- run_all.sh: full reproduction command.
- ARTIFACT_README.md, EVIDENCE.md, CLAIMS_TO_EVIDENCE.md, STATUS.md, FORMAT_CHECK.md, ARTIFACT_CHECKLIST.md, SUPPLEMENTAL_SUBMISSION.md, DATA_ATTRIBUTION.md, SCOPE_GUARD.md, and RELATED_WORK_MATRIX.md.

Quick check:

    ./run_ci.sh

Full reproduction:

    ./run_all.sh

The artifact is CPU-only and does not require GPU, cloud services, paid APIs, blockchain infrastructure, or trusted hardware.

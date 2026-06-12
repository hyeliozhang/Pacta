Pacta artifact package
======================

This repository contains the reproducibility artifact for "Pacta: Certifying Evidence Plans for Governed Analytical Queries".

Start here:

- README.md: repository overview, quick-start commands, and file map.
- ARTIFACT_README.md: detailed reproduction instructions.
- CLAIMS_TO_EVIDENCE.md: mapping from manuscript claims to artifact files.
- main.pdf: compiled paper corresponding to the included LaTeX source.

Top-level contents:

- main.tex, references.bib, IEEEtran.cls, IEEEtran.bst: paper source.
- prototype/: implementation and experiment drivers.
- prototype/pacta_core/: modular contract IR, optimizer, descriptor-only verifier, signed catalog, leakage contracts, page-cube, prefix-cube, measurement, and encoding components.
- tests/: unit tests for core modules.
- tools/: citation, PDF, font, log, page-structure, page-12 fill, section-structure, figure-quality, scalability, artifact-coverage, obligation-alignment, and numeric-consistency checks.
- external_data/: bundled public CSV profiles with attribution.
- results/: regenerated CSV outputs used by the paper.
- figs/: generated vector figures.
- run_ci.sh: quick artifact and submission preflight.
- run_all.sh: full reproduction command.
- ARTIFACT_README.md, EVIDENCE.md, CLAIMS_TO_EVIDENCE.md, STATUS.md, FORMAT_CHECK.md, ARTIFACT_CHECKLIST.md, SUPPLEMENTAL_SUBMISSION.md, DATA_ATTRIBUTION.md, SCOPE_GUARD.md, and RELATED_WORK_MATRIX.md.

Quick check:

    bash run_ci.sh

Full reproduction:

    bash run_all.sh

The artifact is CPU-only and does not require GPU, cloud services, paid APIs, blockchain infrastructure, or trusted hardware.

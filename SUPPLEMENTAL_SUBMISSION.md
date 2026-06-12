# Supplemental Artifact Notes

This artifact is organized as an open repository with all files needed to inspect the manuscript, reproduce the bundled outputs, regenerate figures, and rerun consistency checks.

## Package contents

The top level contains:

- `main.pdf` and the LaTeX source files.
- `prototype/`, `tests/`, `tools/`, `external_data/`, `results/`, and `figs/`.
- `run_ci.sh` for a quick artifact check.
- `run_all.sh` for full reproduction.
- `ARTIFACT_README.md`, `EVIDENCE.md`, `CLAIMS_TO_EVIDENCE.md`, `STATUS.md`, `FORMAT_CHECK.md`, `ARTIFACT_CHECKLIST.md`, `DATA_ATTRIBUTION.md`, `SCOPE_GUARD.md`, and `RELATED_WORK_MATRIX.md`.
- `Dockerfile`, `requirements.txt`, `environment.lock.txt`, and `environment.json`.

## Review commands

Quick artifact command:

```bash
bash run_ci.sh
```

Full reproduction command:

```bash
bash run_all.sh
```

The full run regenerates result CSV files, figures, and the PDF. Timing values may vary by machine, but qualitative verifier decisions, attack outcomes, and semantic oracle checks are deterministic under the supplied seeds.

## Access

The artifact is intended for a standard public repository or conference-supported upload mechanism. It does not depend on personal web analytics, external services, private datasets, or reviewer-identifying access controls.

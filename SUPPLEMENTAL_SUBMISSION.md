# Supplemental Submission Plan for ICDE 2027

The supplemental package is organized as a reviewable ZIP or as the contents of an open repository/service that does not expose reviewer identities or IP-tracking analytics to the authors.

## Suggested submission bundle

Include the following at the top level:

- `main.pdf` and the LaTeX source files.
- `prototype/`, `tests/`, `tools/`, `external_data/`, `results/`, and `figs/`.
- `run_ci.sh` for a quick artifact and submission check.
- `run_all.sh` for full reproduction.
- `ARTIFACT_README.md`, `EVIDENCE.md`, `CLAIMS_TO_EVIDENCE.md`, `STATUS.md`, `FORMAT_CHECK.md`, `ARTIFACT_CHECKLIST.md`, `DATA_ATTRIBUTION.md`, `SCOPE_GUARD.md`, and `RELATED_WORK_MATRIX.md`.
- `Dockerfile`, `requirements.txt`, `environment.lock.txt`, and `environment.json`.

## Review commands

Quick artifact command (includes preflight, layout, citation, numeric, and obligation audits):

```bash
./run_ci.sh
```

Full reproduction command:

```bash
./run_all.sh
```

The full run regenerates result CSV files, figures, and the final PDF. Timing values may vary by machine, but qualitative verifier decisions, attack outcomes, and semantic oracle checks are deterministic under the supplied seeds.

## Anonymity and reviewer privacy

ICDE 2027 uses single-blind review, but the supplemental material should still avoid personal webpages and any mechanism that can track reviewer identities. Use the conference-supported upload mechanism or a standard public repository/file service with well-understood privacy behavior.

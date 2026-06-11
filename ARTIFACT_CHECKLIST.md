# Artifact Checklist

This checklist is written for reviewers who want a fast map from claims to executable checks.

## What the quick check covers

`./run_ci.sh` performs:

1. Python syntax checks for the prototype and core modules.
2. The integrated Pacta semantic/adversarial verifier suite.
3. 240 randomized SQLite semantic cross-checks across five synthetic profiles plus two public CSV profiles.
4. Unit tests for contract IR, descriptor-only verification, optimizer legality, catalog freshness, leakage contracts, prefix/page layouts, frontier witnesses, and encoding estimates.
5. Submission preflight: citations, bibliography padding, LaTeX log health, PDF page structure, embedded fonts, no appendix, and stale-label checks.
6. Paper audit: seven-section conference structure, 12-page main body, figure availability, reviewer-facing package cleanliness, and evidence-log coverage.
7. Layout audit: page 12 reaches the bottom writing area and page 13 starts non-counted acknowledgement/references.
8. Results consistency: visible manuscript numbers are recomputed from the bundled CSV files.
9. Obligation coverage audit: contract IR, optimizer obligations, manuscript vocabulary, and test/prototype coverage stay aligned.

## What the full run regenerates

`./run_all.sh` additionally regenerates the experiment CSV files, robustness sweep, large-scale page-cube trend, prefix-cube/star-schema summaries, figures, and final PDF before running the same checks.

## Expected reviewer interpretation

- Passing positive verifier tests show that valid governed certificates are accepted.
- Failing mutation tests show that policy widening, stale versions, missing tuples, request substitution, range substitution, projection tampering, join omissions, top-k omissions, and disclosure violations are rejected.
- Planner traces show why cheaper compact plans are rejected when they lack a required verifier obligation.
- The artifact is a reproducible verifier, evidence-plan, and measurement harness with explicit scale experiments for compact, page-cube, prefix-cube, and update paths.

- The artifact retains the regression guard for operator-field smuggling: known request fields are rejected when attached to an incompatible operator rather than being hashed but semantically ignored.
- Regression tests cover descriptor-typed dimension attributes and prefix-cube expected-root binding: customer segment/active and category tag fields must be committed as JSON integers, and prefix-view proofs must use a committed root.

- Regression guards reject ambiguous certificate node metadata, leaf-path metadata, and result-value encodings; these prevent lenient JSON integer parsing from entering verifier reconstruction.
- The preflight rejects any TeX `!` error marker, closing the previous build-log blind spot.

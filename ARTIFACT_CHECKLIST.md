# Artifact Checklist

This checklist gives a compact map from artifact claims to executable checks.

## What the quick check covers

`bash run_ci.sh` performs:

1. Python syntax checks for the prototype and core modules.
2. The integrated Pacta semantic/adversarial verifier suite.
3. 240 randomized SQLite semantic cross-checks across five synthetic profiles plus two public CSV profiles.
4. Unit tests for contract IR, descriptor-only verification, optimizer legality, catalog freshness, leakage contracts, prefix/page layouts, frontier witnesses, and encoding estimates.
5. Manuscript/package preflight: citations, bibliography padding, LaTeX log health, PDF page structure, embedded fonts, no appendix, and stale-label checks.
6. Structure guard: seven-section conference structure, 12-page main body, figure availability, package cleanliness, and evidence-log coverage.
7. Layout audit: page 12 reaches the bottom writing area and page 13 starts non-counted acknowledgement/references.
8. Results consistency: visible manuscript numbers are recomputed from the bundled CSV files.
9. Obligation coverage audit: contract IR, optimizer obligations, manuscript vocabulary, and test/prototype coverage stay aligned.

## What the full run regenerates

`bash run_all.sh` additionally regenerates the experiment CSV files, robustness sweep, large-scale page-cube trend, prefix-cube/star-schema summaries, figures, and PDF before running the same checks.

## How to read the outputs

- Passing positive verifier tests show that valid governed certificates are accepted.
- Failing mutation tests show that policy widening, stale versions, missing tuples, request substitution, range substitution, projection tampering, join omissions, top-k omissions, and disclosure violations are rejected.
- Planner traces show why cheaper compact plans are rejected when they lack a required verifier obligation.
- The artifact is a reproducible verifier, evidence-plan, and measurement harness with explicit scale experiments for compact, page-cube, prefix-cube, and update paths.
- Regression guards cover operator-field smuggling, descriptor-typed dimension attributes, prefix-cube expected-root binding, strict integer parsing, page-cube boundary covers, and ambiguous certificate encodings.
- The preflight rejects any top-level TeX `!` error marker so malformed build logs cannot pass unnoticed.

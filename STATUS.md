# Pacta Status

This repository is the final artifact package for **Pacta: Certifying Evidence Plans for Governed Analytical Queries**.

## Final additions

- Final author/visual polish uses a compact two-author IEEE author block, removes ORCID from the PDF author block, deduplicates the AI acknowledgement, and redraws the conceptual diagrams with larger labels and lower visual clutter.

- Scale-path verifier hardening: page-cube proof verification now rejects boundary-cover substitution, strict page-cube integer parsing rejects ambiguous query/descriptor/result encodings, and prefix-cube Merkle proof verification binds the path to the claimed prefix index and committed view length.

- Fixed two latent TeX brace errors and hardened `submission_preflight.py` to reject any top-level TeX `!` error marker, not only literal `! LaTeX Error` strings.
- Hardened verifier-side certificate encoding: structural bounds/counts/path indices, result cells, and verifier-used row fields now reject boolean, float, null, and otherwise ambiguous numeric encodings before hash reconstruction or result comparison.
- Added six carried-forward and new regression tests for ambiguous certificate encodings, page-cube boundary-cover substitution, page-cube ambiguous query encoding, and prefix-cube Merkle index binding, bringing the unit-test suite to 38 tests.

## Current state

- Main paper compiles to 14 pages total: 12 research-paper content pages, then AI-generated content acknowledgement and references.
- No appendix is present in the main PDF.
- The manuscript uses 76 real cited references; there is no `\nocite` padding and no uncited bibliography entry.
- The artifact quick check passes the integrated semantic/adversarial suite, 38 unit tests, submission preflight, paper-audit guard, layout audit, CSV-to-manuscript numeric consistency, figure/style audit, and obligation-coverage audit.
- The optimizer obligation vocabulary includes request, owner descriptor, schema, manifest-policy, and version binding before operator-specific obligations are ranked by cost.
- Documentation labels are synchronized for the final artifact; obsolete package labels were removed from reviewer-facing documentation.
- The final paper source ends the main body cleanly before the AI-generated content acknowledgement and references.

## Main implemented contracts

Range group-by count/sum, derived AVG, HAVING, exact count-distinct, complete range projection, row-local open-scan predicates, threshold top-k, returned-pair join authenticity, complete FK joins, complete anti-joins, complete many-to-many joins, signed descriptor freshness, versioned updates, descriptor-only client verification, leakage contracts, page-cube scaling, prefix-cube materialized-view proofs, public tabular mappings, and multi-seed robustness sweeps.

## Contract scope

Pacta verifies governed-result integrity for the implemented typed contracts, and unsupported contracts fail closed or compile to explicit opened evidence. The paper frames this as a verifier contract and physical-design boundary, not as a hidden assumption.

## Earlier accumulated hardening carried forward

- Prefix-cube expected-root binding: materialized prefix-view certificates now require the expected committed view root and strict range/index integers, rejecting self-consistent but uncommitted prefix trees.

- Efficiency/scalability presentation: the paper now has an explicit scale table covering 50K compact proofs, 1M page-cube proofs, 50K prefix-cube views, 100K star-prefix profiles, and 5K update repair.

- Descriptor-typed dimension fields: relation descriptors bind customer `active`/`segment` and tag `tag` attributes as NOT NULL JSON integers, closing a dimension-schema coercion boundary in join verification.

- Removed stale nested package material and internal draft-review reports so the reviewer-facing artifact is clean and professional.
- Hardened returned-pair join contracts so scalar dimension filters such as `segment` are request-digest-bound, and added regression tests for segment/range substitution.
- Made contract normalization fail closed on unknown fields and ambiguous numeric parameters rather than silently dropping or truncating them.
- Hardened descriptor-only and signed-catalog verifiers so manifest versions, relation versions, epochs, rows, and summary values reject bool/float truncation rather than relying on Python coercion.
- Added `tools/paper_audit.py` and `tools/layout_audit.py`, then wired both into `run_ci.sh` and `run_all.sh` to check page/section structure, main-body ending, page-12 fill, figure availability, professional supplemental contents, and core evidence coverage.
- Strengthened the introduction's data-engineering framing without adding a new section or changing the contribution scope.
- Fixed the final main-body punctuation before the non-counted AI acknowledgement/references page.
- Recompiled and revalidated the paper; quick CI passes 240 randomized semantic checks, two public CSV profile checks, 38 unit tests, preflight, paper audit, layout audit, results consistency, figure/style audit, and obligation coverage.

- The final artifact adds a dedicated figure/style audit and regenerates all conceptual and experimental figures from reproducible Python code with a consistent publication layout.

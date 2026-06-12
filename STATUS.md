# Pacta Artifact Status

This repository packages the manuscript, prototype, deterministic outputs, figures, and consistency checks for **Pacta: Certifying Evidence Plans for Governed Analytical Queries**.

## Current state

- `main.pdf` compiles to 14 pages total: 12 research-paper content pages followed by acknowledgement and references.
- No appendix is present in the main PDF.
- The manuscript uses 76 real cited references; there is no `\nocite` padding and no uncited bibliography entry.
- The artifact quick check covers the integrated semantic/adversarial suite, 38 unit tests, manuscript/package preflight, structure and layout guards, CSV-to-manuscript numeric consistency, figure/style checks, and obligation-coverage alignment.
- The optimizer obligation vocabulary includes request, owner descriptor, schema, manifest-policy, and version binding before operator-specific obligations are ranked by cost.
- Documentation labels are synchronized across the paper source, result tables, evidence map, and reproducibility scripts.

## Main implemented contracts

Range group-by count/sum, derived AVG, HAVING, exact count-distinct, complete range projection, row-local open-scan predicates, threshold top-k, returned-pair join authenticity, complete FK joins, complete anti-joins, complete many-to-many joins, signed descriptor freshness, versioned updates, descriptor-only client verification, leakage contracts, page-cube scaling, prefix-cube materialized-view proofs, public tabular mappings, and multi-seed robustness sweeps.

## Contract scope

Pacta verifies governed-result integrity for the implemented typed contracts, and unsupported contracts fail closed or compile to explicit opened evidence. The paper frames this as a verifier contract and physical-design boundary, not as a hidden assumption.

## Regression coverage

- Prefix-cube certificates require the expected committed view root and strict range/index integers, rejecting self-consistent but uncommitted prefix trees.
- Page-cube certificates reject boundary-cover substitution and ambiguous query/descriptor/result encodings.
- Descriptor-typed dimension fields bind customer `active`/`segment` and category `tag` attributes as NOT NULL JSON integers.
- Returned-pair join contracts bind scalar dimension filters such as `segment` into the request digest.
- Contract normalization fails closed on unknown fields and ambiguous numeric parameters.
- Descriptor-only and signed-catalog verifiers reject boolean, float, null, and otherwise ambiguous values for verifier-visible integers.
- `run_ci.sh` checks 240 randomized semantic cases, two public CSV profile mappings, 38 unit tests, manuscript/package preflight, structure/layout constraints, numeric consistency, figure quality, and obligation coverage.

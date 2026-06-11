# Pacta Scope Guard

Pacta is a data-engineering paper on authenticated query processing for governed analytical data sharing. The contribution is the database contract: a query result is accepted only when the verifier can check request binding, descriptor binding, schema binding, manifest-derived policy binding, projection safety, omission completeness, version freshness, disclosure compatibility, and operator-specific completeness.

## In scope

- Typed governed-query contracts for a concrete SQL-style analytical fragment.
- Descriptor-bound authenticated indexes with policy-cube summaries.
- A certifying evidence-plan optimizer that rejects inadmissible shortcuts before cost ranking.
- A strict client verifier and descriptor-only compact certificate verification.
- Signed catalog freshness and manifest release binding.
- Leakage/disclosure contracts for evidence plans.
- Experiments over synthetic profiles, two bundled public tabular profiles, a page-cube scale layout, and an authenticated prefix-cube materialized-view baseline.

## Implemented contract coverage

- Range selection/projection.
- Group-by count/sum, derived AVG, HAVING.
- Exact count-distinct by opened multiset evidence.
- Row-local deterministic predicates through complete open-range scan fallback.
- Threshold top-k with cutoff/tie completeness.
- Returned-pair join authenticity.
- Complete key-foreign-key join witnesses.
- Complete anti-join absence witnesses.
- Complete many-to-many/category-expansion witnesses.
- Non-key update repair and structural-version rebuilding.

## Out of scope

- Confidentiality, hidden access patterns, or encrypted computation as a primary contribution.
- Differential privacy or legal validation of the owner's policy choices.
- Arbitrary SQL, nondeterministic predicates, or uncommitted UDFs.
- A malicious owner or compromised policy compiler.
- Production DBMS throughput claims.

Unsupported SQL features fail closed rather than being silently mapped to weaker evidence.

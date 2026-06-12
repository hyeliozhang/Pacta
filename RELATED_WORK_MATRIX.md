# Related Work Matrix

This matrix records how Pacta is positioned against database, systems, provenance, and security-adjacent literature. The center of gravity is data engineering: governed query-result verification, authenticated physical design, and evidence-plan optimization.

## Authenticated query processing and outsourced databases

| Representative work | Venue family | Relevance | Difference from Pacta |
|---|---|---|---|
| Pang and Tan, query authentication in edge computing | ICDE | Early authenticated query result verification | Does not make policy-filter correctness part of query semantics. |
| Pang et al., completeness/authenticity for publishing | SIGMOD | Completeness and authenticity of relational results | Governed release policies are outside the core semantics. |
| Li et al., dynamic authenticated index structures | SIGMOD | Dynamic outsourced database indexes | Pacta uses dynamic ADS ideas but commits policy-aware aggregate summaries. |
| Li et al., authenticated aggregation | TISSEC / database-security line | Aggregate query authentication | Pacta binds aggregates to policy manifests and governed analytical semantics. |
| Papadopoulos et al., separating authentication from execution | ICDE | Query execution and authentication decoupling | Pacta uses the same principle but adds policy-aware summaries and explanations. |
| Yang et al., authenticated joins | SIGMOD | Authenticated join processing | Pacta implements typed join contracts for returned-pair, FK, anti-join, and many-to-many cases; it does not claim arbitrary SQL join verification. |
| Papadopoulos et al., authenticated streams | VLDBJ | Continuous/fresh result authentication | Pacta handles versioned governed analytical snapshots. |
| Chen et al., authenticated top-k | PVLDB | Rank/top-k authenticated queries | Pacta implements a simpler threshold top-k certificate only. |
| Chen et al., online data integration authentication | SIGMOD | Multi-source result authentication | Pacta focuses on governed policy slices within an analytical relation. |

## Authenticated data structures and verifiable computation

| Representative work | Venue family | Relevance | Difference from Pacta |
|---|---|---|---|
| Merkle trees and signatures | Crypto/security foundation | Hash commitment mechanism | Pacta does not propose a new primitive. |
| Devanbu et al., authenticated tables | JCSS / database-security | Authenticated relational storage | Pacta adds policy-governed analytical operators and benchmark. |
| Martel et al., ADS model | Algorithmica | General ADS foundations | Pacta specializes to relational query certificates. |
| Tamassia, authenticated data structures | Algorithms | General ADS foundations | Used as mechanism only. |
| Goodrich et al., authenticated skip lists/dictionaries | Algorithms/security | Efficient authenticated dictionaries | Pacta uses tree summaries instead of generic dictionary proofs. |
| vSQL and verifiable SQL systems | Security / crypto systems | General SQL correctness proof direction | Pacta is not a general cryptographic SQL proof; it exposes database-specific storage/query trade-offs. |
| Pepper/Pinocchio/verifiable delegation | Security/crypto | General verifiable computation | Too general/heavy for the data-engineering-first story. |

## Access control, privacy, and governance

| Representative work | Venue family | Relevance | Difference from Pacta |
|---|---|---|---|
| Stonebraker access control | Database | Historical DB access-control foundation | Pacta verifies result correctness after policy enforcement. |
| Hippocratic databases | VLDB | Purpose/privacy obligations | Pacta focuses on integrity/auditability, not privacy policy enforcement itself. |
| Fine-grained access control and query rewriting | SIGMOD | Query modification under policies | Pacta certifies that the rewritten/effective query result is correct. |
| Predicated grants | ICDE | Predicate-based database authorization | Pacta binds predicated policies into certificate verification. |
| RBAC and multipolicy systems | Security/access-control | Policy background | Not the primary contribution. |
| Differential privacy / PINQ | Theory/SIGMOD | Disclosure risk and privacy mechanisms | Complementary; Pacta does not provide DP or confidentiality. |
| Membrane / Spark access-control systems | Modern data management/access-control | Access control over analytics systems | Pacta aims at verifiable result certificates, not a policy engine. |

## Provenance, data quality, and workflows

| Representative work | Venue family | Relevance | Difference from Pacta |
|---|---|---|---|
| Lineage / why-where provenance | ICDT / DB theory | Explanation of query results | Provenance alone cannot prove omission completeness. |
| Semiring provenance | PODS | Algebraic explanation foundation | Pacta uses explanations derived from certificates, not as proof replacement. |
| Provenance surveys | Foundations and Trends / surveys | Auditability and workflow motivation | Pacta combines provenance with authenticated result verification. |
| Causality explanations | VLDB | Explanation and responsibility | Not a certificate for all omitted authorized tuples. |
| Data quality and cleaning literature | PVLDB / ACM Books | Trustworthy data pipelines | Pacta addresses integrity of released query results, not data cleaning. |

## Data sharing, markets, and analytical processing

| Representative work | Venue family | Relevance | Difference from Pacta |
|---|---|---|---|
| Dataspaces and DataHub | SIGMOD/CIDR | Collaborative data sharing motivation | Pacta adds verifiable policy-governed query results. |
| Data market platforms | Data management / arXiv | Data asset exchange motivation | Pacta provides auditable analytics certificates for such settings. |
| Data and model markets | PVLDB | Modern sharing/market context | Pacta focuses on result integrity rather than discovery/pricing. |
| ServeDB and VeriDB | ICDE/SIGMOD | Verifiable outsourced database systems close to database deployments | Pacta focuses on policy-bound analytical contracts and optimizer legality rather than only range/SGX verification. |
| Query optimization classics | SIGMOD/CSUR | Operator and cost-model foundation | Pacta frames certificates as query-processing artifacts. |
| Data cubes and aggregate processing | ICDE/SIGMOD | Aggregate summary design | Pacta uses authenticated policy summaries as small cubes. |
| B-tree and column-store systems | Database systems | Physical design lineage | Pacta points to page-oriented future implementation. |
| Dremel/SparkSQL | VLDB/SIGMOD | Analytical execution context | Pacta prototype is lightweight, not a distributed engine. |

## Positioning summary

- Lead with query result verification semantics and storage/index design.
- Use "policy-governed effective query" consistently.
- Do not claim cryptographic novelty.
- Do not claim arbitrary SQL or arbitrary join completeness.
- Emphasize evidence-bound experiments, baselines, negative controls, and limitations.

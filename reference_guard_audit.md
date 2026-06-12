# Reference Audit Summary

- Input: `references.bib`
- Bibliography size: 76 entries
- Citation coverage: 76 unique cited keys, 76 emitted bibliography items, no missing citations, no duplicate BibTeX keys, and no `\nocite{*}` dependency.
- Evidence status: every entry has at least one credible external evidence path through DOI/Crossref, OpenAlex, DBLP, official proceedings pages, or an accessible dataset/software URL. The two bundled Plotly CSV URLs are pinned to repository commit `0c447c47b757ad74edecab31f0d72f849d2e67c2` rather than the mutable `master` branch.
- Metadata hardening: high-confidence DOI metadata was added for the classical authenticated-data-structure, query-processing, access-control, provenance, data-management, and systems references where a stable DOI was available.
- Verification method: bibliography coverage was checked by local citation/BibTeX scans and by source-level metadata review against stable DOI, proceedings, publisher, dataset, and software records.

## Manual Notes

- `mykletun2004outsourced` is intentionally kept as the NDSS 2004 conference citation. Some bibliographic services surface the 2006 ACM TISSEC journal extension under a DOI; using that DOI for the conference entry would mix versions.
- `xia2026sharing` is a real VLDB Journal article with DOI `10.1007/s00778-025-00961-5`; publisher metadata should be treated as the authority if it changes.
- No fabricated or unsupported bibliography entries were found in the cited set.

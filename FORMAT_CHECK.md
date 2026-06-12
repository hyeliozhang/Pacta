# Pacta Manuscript and Artifact Checks

## Template integrity

`IEEEtran.cls` SHA-256:

`da751920a317ed318b7b5cd7fa585a6cc7d28502d457856382e9be24b10a3bd7`

`IEEEtran.bst` SHA-256:

`314f0ece704568faf827011bac498650691b2b5ee06320720830e782416d5a5f`

Both files are kept unchanged from the supplied IEEE/ICDE template files.

## Manuscript rules checked

- Uses IEEEtran conference layout.
- No class/style/margin/font/line-spacing/column-width/caption-spacing/bibliography-spacing hacks.
- No appendix in the main PDF.
- Main body is pages 1--12.
- Acknowledgement and references begin on page 13.
- The compiled PDF has 14 total pages.
- `references.bib` contains 76 real cited entries.
- `main.tex` contains no `\nocite` padding.
- All cited keys exist in `references.bib`; all bibliography entries are cited.
- The paper has seven numbered sections, which keeps the manuscript in conference-paper form rather than a many-section report style.

## Build checks

Build sequence:

1. `pdflatex -interaction=nonstopmode main.tex`
2. `/usr/bin/bibtex.original main` when the `bibtex` alternative is unavailable
3. `pdflatex -interaction=nonstopmode main.tex`
4. `pdflatex -interaction=nonstopmode main.tex`

After this build sequence, `main.log` contains no LaTeX errors, undefined citations, undefined references, rerun warnings, or overfull hbox warnings. Underfull warnings are ordinary IEEE column/table line-breaking warnings.

## Font and render checks

- `pdffonts main.pdf` reports no Type 3 fonts.
- All non-base fonts are embedded.
- Figures are vector PDFs using embedded DejaVu Sans TrueType fonts.
- Visual render inspection was performed from `main.pdf`. The package also includes `tools/layout_audit.py`, which checks page-12 fill and page-13 transition using PDF text bounding boxes.
- A rendered contact sheet was inspected visually.
- No visible text overlap, figure clipping, table corruption, black boxes, or page-boundary spillover was observed.
- Page 13 begins the acknowledgement/reference material.

## Automated preflight

`tools/submission_preflight.py`, `tools/paper_audit.py`, `tools/layout_audit.py`, `tools/results_consistency.py`, `tools/efficiency_scalability_audit.py`, `tools/figure_quality_audit.py`, and `tools/obligation_coverage_audit.py` are wired into both `run_ci.sh` and `run_all.sh`. Together they check citation integrity, reference count, stale documentation labels, LaTeX log problems, PDF page structure, font embedding, section structure, page-12 main-body completion, artifact evidence coverage, claims-to-evidence coverage, paper-number consistency with bundled CSV files, vector/PNG figure hygiene, and obligation vocabulary alignment across manuscript, contract IR, optimizer, and tests.

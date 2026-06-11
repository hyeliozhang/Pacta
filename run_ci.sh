#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export PYTHONDONTWRITEBYTECODE=1
export MPLBACKEND="${MPLBACKEND:-Agg}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
export OPENBLAS_NUM_THREADS="${OPENBLAS_NUM_THREADS:-1}"
export MKL_NUM_THREADS="${MKL_NUM_THREADS:-1}"
PY="${PYTHON:-python3}"
export PYTHONPATH="$(pwd)/prototype:${PYTHONPATH:-}"
cleanup_pycache() {
  find . -type d -name '__pycache__' -prune -exec rm -rf {} +
  find . -type f -name '*.pyc' -delete
}
$PY -m py_compile prototype/pacta.py prototype/pacta_core/*.py
cleanup_pycache
$PY -c "import pacta; pacta.run_tests()"
$PY -m unittest discover -s tests -p 'test_*.py'
cleanup_pycache
if command -v pdflatex >/dev/null 2>&1; then
  $PY prototype/draw_concept_figures.py >/dev/null
  $PY prototype/plot_results.py >/dev/null
  pdflatex -interaction=nonstopmode main.tex >/dev/null
  if command -v bibtex >/dev/null 2>&1 && bibtex --version >/dev/null 2>&1; then
    bibtex main >/dev/null
  else
    /usr/bin/bibtex.original main >/dev/null
  fi
  pdflatex -interaction=nonstopmode main.tex >/dev/null
  pdflatex -interaction=nonstopmode main.tex >/dev/null
fi
$PY tools/submission_preflight.py
$PY tools/paper_audit.py
$PY tools/layout_audit.py
$PY tools/results_consistency.py
$PY tools/efficiency_scalability_audit.py
$PY tools/figure_quality_audit.py
$PY tools/obligation_coverage_audit.py
cleanup_pycache
echo 'quick artifact and submission preflight passed'

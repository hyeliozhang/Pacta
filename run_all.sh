#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export MPLBACKEND="${MPLBACKEND:-Agg}"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
export OPENBLAS_NUM_THREADS="${OPENBLAS_NUM_THREADS:-1}"
export MKL_NUM_THREADS="${MKL_NUM_THREADS:-1}"
PY="${PYTHON:-python3}"
export PYTHONPATH="$(pwd)/prototype:${PYTHONPATH:-}"
cleanup_pycache() {
  find . -type d -name '__pycache__' -prune -exec rm -rf {} +
  find . -type f -name '*.pyc' -delete
}
rm -rf results results_stress_tmp
$PY -c "import pacta; print('[1/8] paper-scale experiments', flush=True); pacta.run_experiments('results', seed=2027, scale='paper'); print('paper experiments complete', flush=True)"
$PY -c "import pacta; print('[2/8] 20K/50K stress experiments', flush=True); pacta.run_experiments('results_stress_tmp', seed=2027, scale='stress'); print('stress experiments complete', flush=True)"
cp results_stress_tmp/pacta_stress.csv results/pacta_stress.csv
cp results_stress_tmp/repro.json results/repro_stress50.json
$PY -c "from pacta_core.page_index import run_large_scale; print('[3/8] page-cube 1M large-scale trend', flush=True); run_large_scale('results/large_scale_page_index.csv'); print('large-scale page-cube complete', flush=True)"
printf '[4/8] catalog/leakage/prefix-cube/star-schema enhancements\n'
$PY prototype/run_system_enhancements.py
printf '[5/8] multi-seed robustness sweep\n'
$PY prototype/run_robustness_sweep.py
$PY -c "import pacta; print('[6/8] verifier and adversarial tests', flush=True); pacta.run_tests()"
$PY -m unittest discover -s tests -p 'test_*.py'
printf '[7/8] regenerate figures and medians\n'
$PY prototype/draw_concept_figures.py >/dev/null
$PY prototype/plot_results.py
printf '[8/8] latex build manuscript\n'
pdflatex -interaction=nonstopmode main.tex >/dev/null
if command -v bibtex >/dev/null 2>&1 && bibtex --version >/dev/null 2>&1; then
  bibtex main >/dev/null
else
  /usr/bin/bibtex.original main >/dev/null
fi
pdflatex -interaction=nonstopmode main.tex >/dev/null
pdflatex -interaction=nonstopmode main.tex >/dev/null
cleanup_pycache
$PY tools/submission_preflight.py
$PY tools/paper_audit.py
$PY tools/layout_audit.py
$PY tools/results_consistency.py
$PY tools/efficiency_scalability_audit.py
$PY tools/figure_quality_audit.py
$PY tools/obligation_coverage_audit.py
cleanup_pycache
echo 'all artifacts reproduced'

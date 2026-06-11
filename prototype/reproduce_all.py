#!/usr/bin/env python3
"""One-process reproduction driver for environments that throttle subprocess chains."""
from __future__ import annotations
import gc
import os
import shutil
import runpy

from pacta import run_tests, run_experiments

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('MPLBACKEND', 'Agg')
os.environ.setdefault('PYTHONHASHSEED', '0')

print('[1/5] verifier and adversarial tests')
run_tests(); gc.collect()
print('[2/5] paper-scale experiments')
for d in ['results', 'results_stress_tmp']:
    shutil.rmtree(os.path.join(ROOT, d), ignore_errors=True)
run_experiments(os.path.join(ROOT, 'results'), seed=2027, scale='paper'); gc.collect()
print('[3/5] 20K/50K stress experiments')
run_experiments(os.path.join(ROOT, 'results_stress_tmp'), seed=2027, scale='stress'); gc.collect()
shutil.copyfile(os.path.join(ROOT, 'results_stress_tmp', 'pacta_stress.csv'), os.path.join(ROOT, 'results', 'pacta_stress.csv'))
shutil.copyfile(os.path.join(ROOT, 'results_stress_tmp', 'repro.json'), os.path.join(ROOT, 'results', 'repro_stress50.json'))
print('[4/5] page-cube large-scale physical-design trend')
from pacta_core.page_index import run_large_scale
run_large_scale(os.path.join(ROOT, 'results', 'large_scale_page_index.csv'))
gc.collect()
print('[5/5] figures and derived tables')
runpy.run_path(os.path.join(ROOT, 'prototype', 'plot_results.py'), run_name='__main__')
print('reproduction data complete')

#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from pacta_core.page_index import run_large_scale
print('[3/6] page-cube 1M large-scale trend', flush=True)
run_large_scale(os.path.join(os.path.dirname(__file__), '..', 'results', 'large_scale_page_index.csv'))
print('large-scale page-cube complete', flush=True)
os._exit(0)

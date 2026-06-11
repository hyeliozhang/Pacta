#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import pacta
print('[2/6] 20K/50K stress experiments', flush=True)
pacta.run_experiments(os.path.join(os.path.dirname(__file__), '..', 'results_stress_tmp'), seed=2027, scale='stress')
print('stress experiments complete', flush=True)
os._exit(0)

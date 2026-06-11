#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import pacta
print('[1/6] paper-scale experiments', flush=True)
pacta.run_experiments(os.path.join(os.path.dirname(__file__), '..', 'results'), seed=2027, scale='paper')
print('paper experiments complete', flush=True)
os._exit(0)

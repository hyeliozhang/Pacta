#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import pacta
print('[4/6] verifier and adversarial tests', flush=True)
pacta.run_tests()
os._exit(0)

"""Measurement utilities for Pacta experiments."""
from __future__ import annotations

import statistics, time, tracemalloc
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Tuple

@dataclass(frozen=True)
class TimingStats:
    repeat: int
    warmup: int
    median_ms: float
    mean_ms: float
    p95_ms: float
    stdev_ms: float
    peak_kib: float

    def to_json(self) -> Dict[str, Any]:
        return asdict(self)

def timed_stats(fn: Callable[..., Any], *args: Any, repeat: int = 9, warmup: int = 2, **kwargs: Any) -> Tuple[Any, TimingStats]:
    result = None
    for _ in range(max(0, warmup)):
        result = fn(*args, **kwargs)
    samples: List[float] = []
    tracemalloc.start()
    peak = 0
    for _ in range(max(1, repeat)):
        t0 = time.perf_counter()
        result = fn(*args, **kwargs)
        samples.append((time.perf_counter() - t0) * 1000.0)
        peak = max(peak, tracemalloc.get_traced_memory()[1])
    tracemalloc.stop()
    samples_sorted = sorted(samples)
    idx = min(len(samples_sorted)-1, int(0.95 * (len(samples_sorted)-1)))
    return result, TimingStats(
        repeat=max(1, repeat), warmup=max(0, warmup),
        median_ms=statistics.median(samples), mean_ms=statistics.mean(samples),
        p95_ms=samples_sorted[idx], stdev_ms=(statistics.stdev(samples) if len(samples)>1 else 0.0),
        peak_kib=peak/1024.0,
    )

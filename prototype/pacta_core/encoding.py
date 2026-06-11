"""Certificate-size accounting utilities.

The paper reports canonical JSON bytes because every scheme in the experiment
uses the same transparent serialization.  This helper also records a simple
logical binary estimate and gzip size for reviewers who want to check that the
observed frontier is not an artifact of pretty printing or field names.
"""
from __future__ import annotations

import gzip, json, os
from typing import Any, Dict, Iterable, List

JSON = Dict[str, Any]

def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

def json_bytes(obj: Any) -> int:
    return len(canonical(obj))

def gzip_bytes(obj: Any) -> int:
    return len(gzip.compress(canonical(obj), compresslevel=6))

def logical_binary_estimate(obj: Any) -> int:
    """Conservative recursive logical-byte estimate for normalized proof objects.

    Hashes are counted as 32 bytes, integers as 8 bytes, floats as 8 bytes,
    booleans as 1 byte, and strings as UTF-8 payload length.  Container tags and
    lengths are counted conservatively.  The estimate is not used to claim a
    deployed binary encoding; it checks whether conclusions survive removal of
    JSON field-name overhead.
    """
    if obj is None:
        return 1
    if isinstance(obj, bool):
        return 1
    if isinstance(obj, int):
        return 8
    if isinstance(obj, float):
        return 8
    if isinstance(obj, str):
        return 32 if len(obj) == 64 and all(c in "0123456789abcdef" for c in obj.lower()) else len(obj.encode("utf-8"))
    if isinstance(obj, list):
        return 4 + sum(logical_binary_estimate(x) for x in obj)
    if isinstance(obj, dict):
        return 4 + sum(len(str(k).encode("utf-8")) + logical_binary_estimate(v) for k, v in obj.items())
    return len(str(obj).encode("utf-8"))

def sample_certificates(sample_dir: str) -> List[JSON]:
    rows: List[JSON] = []
    if not os.path.isdir(sample_dir):
        return rows
    for name in sorted(os.listdir(sample_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(sample_dir, name)
        with open(path, encoding="utf-8") as f:
            obj = json.load(f)
        rows.append({
            "sample": name,
            "json_bytes": json_bytes(obj),
            "gzip_bytes": gzip_bytes(obj),
            "logical_binary_bytes": logical_binary_estimate(obj),
        })
    return rows

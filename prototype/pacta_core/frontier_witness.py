"""Indistinguishability witness for the certifying-evidence frontier."""
from __future__ import annotations
import csv, hashlib, json, os
from typing import Any, Dict, Iterable, List, Tuple

JSON = Dict[str, Any]

def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(tag: str, obj: Any) -> str:
    return hashlib.sha256((tag + "|" + canonical(obj)).encode("utf-8")).hexdigest()

def policy_cube_signature(rows: Iterable[JSON]) -> JSON:
    cells: Dict[str, List[int]] = {}
    for r in rows:
        key = f"{int(r['tenant'])}|{int(r['sensitivity'])}|{int(r['region'])}|{int(r['category'])}"
        old = cells.get(key, [0, 0]); old[0] += 1; old[1] += int(r['amount']); cells[key] = old
    return dict(sorted(cells.items()))

def predicate_answer(rows: Iterable[JSON], threshold: int = 150) -> JSON:
    out: Dict[str, List[int]] = {}
    for r in rows:
        if int(r['amount']) >= threshold:
            key = str(int(r['category'])); old = out.get(key, [0, 0]); old[0] += 1; old[1] += int(r['amount']); out[key] = old
    return dict(sorted(out.items(), key=lambda kv: int(kv[0])))

def witness_pair() -> Tuple[List[JSON], List[JSON]]:
    base = {'tenant': 1, 'sensitivity': 0, 'region': 2, 'category': 7, 'day': 10}
    return [dict(base, id=1, amount=100), dict(base, id=2, amount=200)], [dict(base, id=1, amount=150), dict(base, id=2, amount=150)]

def witness_record() -> JSON:
    a, b = witness_pair(); sig_a, sig_b = policy_cube_signature(a), policy_cube_signature(b); ans_a, ans_b = predicate_answer(a), predicate_answer(b)
    return {
        'case': 'unsummarized_amount_predicate',
        'same_policy_cube_signature': canonical(sig_a) == canonical(sig_b),
        'same_policy_cube_digest': digest('policy_cube_signature', sig_a) == digest('policy_cube_signature', sig_b),
        'different_predicate_answer': canonical(ans_a) != canonical(ans_b),
        'summary_digest': digest('policy_cube_signature', sig_a)[:16],
        'answer_digest_world_a': digest('predicate_answer', ans_a)[:16],
        'answer_digest_world_b': digest('predicate_answer', ans_b)[:16],
        'world_a_amounts': '100,200', 'world_b_amounts': '150,150', 'threshold': 150,
        'required_obligation': 'opened_row_multiset_or_amount_histogram',
    }

def write_witness_csv(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    row = witness_record()
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys())); w.writeheader(); w.writerow(row)

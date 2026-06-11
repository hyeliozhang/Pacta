#!/usr/bin/env python3
"""Structural audit for the Pacta submission package.

This guard is deliberately different from results_consistency.py and
submission_preflight.py.  It checks reviewer-facing polish: compact conference
structure, no stale package labels, no old internal review reports in the
supplement, main-body punctuation before the non-counted acknowledgement page,
figure availability, and a claims-to-evidence map tying paper claims to artifact
files.
"""
from __future__ import annotations

import ast
import csv
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAILURES: list[str] = []
LOCAL_ENV_DIRS = {".venv", "venv", "env", ".codex_tools", ".reference_guard_cache"}


def fail(msg: str) -> None:
    FAILURES.append(msg)


def cleanup_pycache() -> None:
    for cache_dir in list(ROOT.rglob("__pycache__")):
        if cache_dir.relative_to(ROOT).parts[0] in LOCAL_ENV_DIRS:
            continue
        shutil.rmtree(cache_dir, ignore_errors=True)
    for pyc in ROOT.rglob("*.pyc"):
        if pyc.relative_to(ROOT).parts[0] in LOCAL_ENV_DIRS:
            continue
        try:
            pyc.unlink()
        except FileNotFoundError:
            pass


cleanup_pycache()


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def csv_rows(name: str) -> list[dict[str, str]]:
    path = ROOT / "results" / name
    if not path.exists():
        fail(f"missing result CSV for evidence-map audit: {name}")
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def row_by(name: str, col: str, value: str) -> dict[str, str]:
    for row in csv_rows(name):
        if row.get(col) == value:
            return row
    fail(f"missing evidence row in {name}: {col}={value}")
    return {}

def f2(value: str | float) -> str:
    return f"{float(value):.2f}"

def kib(value: str | float) -> str:
    return f"{float(value) / 1024.0:.1f} KiB"

def mib(value: str | float) -> str:
    return f"{float(value) / (1024.0 * 1024.0):.2f} MiB"

tex_path = ROOT / "main.tex"
tex = read(tex_path)

sections = re.findall(r"\\section\{([^}]*)\}", tex)
if sections != [
    "Introduction",
    "Governed Query Contract",
    "Certificate Algebra and Soundness",
    "Physical Design and Verification",
    "Evaluation",
    "Related Work",
    "System Implications and Conclusion",
]:
    fail(f"unexpected numbered section structure: {sections}")

if re.search(r"\\subsubsection\{", tex):
    fail("subsubsections detected; manuscript risks reading like a report")

ack_re = r"\\clearpage\s*\\section\*\{(?:Acknowledgments|AI-Generated Content Acknowledgement)\}"
parts = re.split(ack_re, tex, maxsplit=1)
pre_ack = parts[0].rstrip()
if not pre_ack.endswith("."):
    fail("main body does not end with a period before the non-counted acknowledgement page")

if not re.search(ack_re, tex):
    fail("acknowledgement section is not explicitly placed after the 12-page body")
if "AI-generated content acknowledgement:" not in tex:
    fail("AI-generated content acknowledgement text is missing from acknowledgements")

required_phrases = [
    "request-bound equality over a committed authorized bag",
    "certifying optimizer",
    "descriptor-bound policy-cube indexes",
    "End-to-end governed soundness",
    "SQLite oracle",
    "negative control",
]
for phrase in required_phrases:
    if phrase not in tex:
        fail(f"core framing/evidence phrase missing from manuscript: {phrase}")

for fig in [
    "semantics_pipeline.pdf",
    "index_certificate_flow.pdf",
    "cert_size_selectivity.pdf",
    "time_scalability.pdf",
    "large_scale_page_index.pdf",
    "robustness_sweep.pdf",
    "planner_frontier.pdf",
    "planner_legality_frontier.pdf",
]:
    if not (ROOT / "figs" / fig).exists():
        fail(f"missing required figure PDF: figs/{fig}")
    if not (ROOT / "figs" / fig.replace(".pdf", ".png")).exists():
        fail(f"missing reviewer-friendly figure PNG: figs/{fig.replace('.pdf', '.png')}")

claims = ROOT / "CLAIMS_TO_EVIDENCE.md"
if not claims.exists():
    fail("CLAIMS_TO_EVIDENCE.md is missing")
else:
    claims_text = read(claims)
    pacta = row_by("scheme_medians.csv", "scheme", "pacta")
    prefix = row_by("prefix_cube_medians.csv", "scheme", "authenticated_prefix_cube_view")
    page1m = row_by("large_scale_page_medians.csv", "n", "1000000")
    frontier = {(r["query_kind"], r["plan"]): r for r in csv_rows("planner_frontier_medians.csv")}
    gg = frontier.get(("governed_groupby", "policy_cube_summary"))
    go = frontier.get(("governed_groupby", "open_range_scan_equivalent"))
    required_claim_tokens = [
        "optimizer_trace.csv",
        "range-boundary relabeling",
        "prefix_cube_medians.csv",
        "large_scale_page_medians.csv",
        "results_consistency.py",
        "figs/planner_legality_frontier.pdf",
    ]
    if pacta:
        required_claim_tokens.append(
            f"{kib(pacta['median_certificate_bytes'])} median size, "
            f"{f2(pacta['median_generation_ms'])} ms generation, and "
            f"{f2(pacta['median_verification_ms'])} ms verification"
        )
    if prefix:
        required_claim_tokens.append(
            f"{kib(prefix['median_certificate_bytes'])} proofs and "
            f"{f2(prefix['median_verification_ms'])} ms verification"
        )
    if page1m:
        required_claim_tokens.append(
            f"1M-row page-cube certificate verifies in {f2(page1m['median_verify_ms'])} ms "
            f"and uses {int(float(page1m['pages']))} authenticated pages"
        )
    if gg and go:
        required_claim_tokens.append(f"{round(float(go['median_certificate_bytes']) / float(gg['median_certificate_bytes']))}x")
    for token in required_claim_tokens:
        if token not in claims_text:
            fail(f"claims-to-evidence map missing or stale token: {token}")

# Keep reviewer-facing docs synchronized with the current unittest suite size.
try:
    test_count = 0
    for test_file in (ROOT / "tests").glob("test_*.py"):
        tree = ast.parse(read(test_file))
        test_count += sum(
            isinstance(node, ast.FunctionDef) and node.name.startswith("test")
            for node in ast.walk(tree)
        )
    for doc_name in ["ARTIFACT_README.md", "STATUS.md"]:
        doc = ROOT / doc_name
        if doc.exists() and f"{test_count} unit tests" not in read(doc):
            fail(f"{doc_name} does not state the current unittest count: {test_count} unit tests")
except Exception as exc:
    fail(f"unit-test-count audit failed: {exc}")

# Reviewer-facing package should not include old internal review reports.
for pattern in ["*V17*.md", "*V18*.md", "*V19*.md", "*V20*.md", "*V21*.md", "*V22*.md", "*V23*.md", "*V24*.md", "*V25*.md", "*V26*.md", "*V27*.md", "*V28*.md", "*V29*.md", "*V30*.md", "STRICT_REVIEW*.md", "DEEP_REVIEW*.md", "REVIEW_AND_FIX_REPORT.md"]:
    for path in ROOT.glob(pattern):
        fail(f"old/internal review artifact should not be in final supplement: {path.name}")


# Final package should not contain stale nested submission directories or Python caches.
cleanup_pycache()
for path in ROOT.rglob("*"):
    rel = path.relative_to(ROOT)
    if rel.parts and rel.parts[0] in LOCAL_ENV_DIRS:
        continue
    if "__pycache__" in path.parts:
        fail(f"Python cache directory/file present in final package: {rel}")
    if path.is_dir() and re.search(r"pacta_v(17|18|19|20|21|22|23|24|25|26|27|28|29|30)$", path.name, flags=re.IGNORECASE):
        fail(f"stale nested package directory present in final package: {rel}")

# Reviewer-facing docs should not include acceptance/hype labels.
for name in ["README.txt", "ARTIFACT_README.md", "EVIDENCE.md", "STATUS.md", "FORMAT_CHECK.md", "SUPPLEMENTAL_SUBMISSION.md", "SCOPE_GUARD.md", "CLAIMS_TO_EVIDENCE.md"]:
    path = ROOT / name
    if path.exists():
        text = read(path).lower()
        for hype in ["best-paper", "best paper", "strong accept"]:
            if hype in text:
                fail(f"reviewer-facing hype label '{hype}' remains in {name}")

# Active documentation should not refer to older package versions.
stale_re = re.compile(r"\b[Vv](17|18|19|20|21|22|23|24|25|26|27|28|29|30)\b")
for name in [
    "README.txt",
    "ARTIFACT_README.md",
    "EVIDENCE.md",
    "STATUS.md",
    "FORMAT_CHECK.md",
    "SUPPLEMENTAL_SUBMISSION.md",
    "SCOPE_GUARD.md",
    "CLAIMS_TO_EVIDENCE.md",
]:
    path = ROOT / name
    if path.exists():
        m = stale_re.search(read(path))
        if m:
            fail(f"stale package label {m.group(0)} in {name}")

# Check compiled PDF shape if available.
pdf = ROOT / "main.pdf"
if pdf.exists():
    try:
        if shutil.which("pdfinfo"):
            info = subprocess.check_output(["pdfinfo", str(pdf)], text=True, stderr=subprocess.STDOUT)
            pages_m = re.search(r"Pages:\s+(\d+)", info)
            pages = int(pages_m.group(1)) if pages_m else -1
        else:
            import fitz
            with fitz.open(pdf) as doc:
                pages = doc.page_count
        if pages < 13:
            fail(f"expected at least 13 PDF pages after final compile: 12 body pages plus acknowledgement/references, got {pages}")
        if pages > 18:
            fail(f"unexpectedly long PDF after final compile; non-counted material should remain compact, got {pages}")
    except Exception as exc:
        fail(f"pdfinfo audit failed: {exc}")
else:
    fail("main.pdf missing")

if FAILURES:
    print("paper audit failed:", file=sys.stderr)
    for f in FAILURES:
        print(f" - {f}", file=sys.stderr)
    sys.exit(1)
print("paper audit passed: compact structure, clean supplement, figures, claims map, and PDF shape OK")

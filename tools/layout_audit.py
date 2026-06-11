#!/usr/bin/env python3
"""PDF layout audit for ICDE-style 12-page submissions.

This check complements LaTeX log/preflight tests with a rendered-text bounding
box pass.  It verifies that the main technical body reaches the bottom writing
area of page 12 and that non-counted acknowledgement/references start on page
13.  The goal is not to tune typography; it makes accidental short body pages,
appendix leakage, or margin overflows visible in CI.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
PDF = ROOT / "main.pdf"
FAIL: list[str] = []


def fail(msg: str) -> None:
    FAIL.append(msg)


def check_output_text(cmd: list[str]) -> str:
    return subprocess.check_output(
        cmd,
        encoding="utf-8",
        errors="replace",
        stderr=subprocess.STDOUT,
    )


def pdf_pages() -> int:
    if not shutil.which("pdfinfo"):
        import fitz
        with fitz.open(PDF) as doc:
            return doc.page_count
    info = check_output_text(["pdfinfo", str(PDF)])
    m = re.search(r"Pages:\s+(\d+)", info)
    if not m:
        raise RuntimeError("pdfinfo did not report page count")
    return int(m.group(1))


def bbox_words(page: int) -> list[tuple[float, float, float, float, str]]:
    if not shutil.which("pdftotext"):
        import fitz
        out = []
        with fitz.open(PDF) as doc:
            for x0, y0, x1, y1, text, *_ in doc[page - 1].get_text("words"):
                if text.strip():
                    out.append((float(x0), float(y0), float(x1), float(y1), text.strip()))
        return out
    xml = check_output_text(["pdftotext", "-bbox-layout", "-f", str(page), "-l", str(page), str(PDF), "-"])
    root = ET.fromstring(xml)
    ns = "{http://www.w3.org/1999/xhtml}"
    out = []
    for word in root.iter(ns + "word"):
        text = "".join(word.itertext()).strip()
        if not text:
            continue
        out.append((float(word.attrib["xMin"]), float(word.attrib["yMin"]), float(word.attrib["xMax"]), float(word.attrib["yMax"]), text))
    return out


try:
    pages = pdf_pages()
    if pages < 13:
        fail(f"expected at least 13 pages: 12 counted body pages plus acknowledgement/references, got {pages}")
    if pages > 18:
        fail(f"unexpectedly long PDF; body is capped at 12 pages and non-counted material should remain compact, got {pages}")
    words12 = bbox_words(12)
    if not words12:
        fail("page 12 has no detectable text")
    else:
        max_y = max(y1 for _, _, _, y1, _ in words12)
        min_x = min(x0 for x0, _, _, _, _ in words12)
        max_x = max(x1 for _, _, x1, _, _ in words12)
        # IEEEtran letter two-column text normally spans roughly x=49..563 and
        # y=51..719.  We use conservative margins to catch real problems without
        # failing on harmless renderer differences.
        if max_y < 705:
            fail(f"page 12 appears under-filled; deepest text y={max_y:.1f}")
        if min_x < 35 or max_x > 577:
            fail(f"page 12 text appears outside safe horizontal margins: x=[{min_x:.1f},{max_x:.1f}]")
    if shutil.which("pdftotext"):
        page13_text = check_output_text(["pdftotext", "-f", "13", "-l", "13", str(PDF), "-"])
    else:
        import fitz
        with fitz.open(PDF) as doc:
            page13_text = doc[12].get_text("text")
    compact = re.sub(r"[^a-z]", "", page13_text.lower())
    if not (compact.startswith("acknowledg") or compact.startswith("aigeneratedcontentacknowledg") or compact.startswith("references")):
        fail("page 13 does not start with acknowledgement or references")
except Exception as exc:
    fail(f"layout audit could not run: {exc}")

if FAIL:
    print("layout audit failed:", file=sys.stderr)
    for msg in FAIL:
        print(f" - {msg}", file=sys.stderr)
    sys.exit(1)
print("layout audit passed: page 12 filled, margins safe, page 13 starts acknowledgement/references")

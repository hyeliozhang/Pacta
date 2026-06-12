#!/usr/bin/env python3
"""Check publication-figure hygiene for the Pacta manuscript and source scripts."""
from __future__ import annotations
import pathlib
import re
import shutil
import subprocess
import sys
from PIL import Image

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEX = (ROOT / "main.tex").read_text(encoding="utf-8")
FAIL: list[str] = []


def fail(msg: str) -> None:
    FAIL.append(msg)


def cmd(args: list[str]) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def pdf_page_count(path: pathlib.Path) -> int:
    if shutil.which("pdfinfo"):
        info = cmd(["pdfinfo", str(path)])
        m = re.search(r"Pages:\s+(\d+)", info)
        if not m:
            raise RuntimeError(f"pdfinfo did not report page count for {path.name}")
        return int(m.group(1))
    import fitz  # PyMuPDF fallback for local Windows environments without Poppler.
    with fitz.open(path) as doc:
        return doc.page_count


def pdf_font_report(path: pathlib.Path) -> tuple[str, bool]:
    if shutil.which("pdffonts"):
        return cmd(["pdffonts", str(path)]), True
    import fitz
    lines: list[str] = []
    with fitz.open(path) as doc:
        for page_idx in range(doc.page_count):
            for font in doc.get_page_fonts(page_idx):
                lines.append(" ".join(str(part) for part in font))
    return "\n".join(lines), False

required = sorted(set(re.findall(r"\\includegraphics\[[^\]]*\]\{figs/([^}]+\.pdf)\}", TEX)))
if len(required) < 7:
    fail(f"expected at least seven paper figures, found {len(required)}")

# LaTeX integration: figures should use the full column width.
for inc in re.findall(r"\\includegraphics\[([^\]]*)\]\{figs/[^}]+\.pdf\}", TEX):
    if "width=\\linewidth" not in inc:
        fail(f"figure include is not full-column width: [{inc}]")
for name in required:
    pdf = ROOT / "figs" / name
    png = ROOT / "figs" / name.replace(".pdf", ".png")
    if not pdf.exists():
        fail(f"missing vector figure: figs/{name}")
        continue
    if not png.exists():
        fail(f"missing reviewer-friendly PNG: figs/{png.name}")
    else:
        try:
            w, h = Image.open(png).size
            if w < 900 or h < 550:
                fail(f"figure PNG too low-resolution for visual review: {png.name} {w}x{h}")
        except Exception as exc:
            fail(f"cannot inspect PNG {png.name}: {exc}")
    try:
        if pdf_page_count(pdf) != 1:
            fail(f"figure PDF should be one page: {name}")
        fonts, poppler_fonts = pdf_font_report(pdf)
        font_lines = fonts.splitlines()[2:] if poppler_fonts else fonts.splitlines()
        for line in font_lines:
            cols = line.split()
            if not cols:
                continue
            if "Type 3" in line:
                fail(f"Type 3 font in figure {name}: {line}")
            # Base-14 fonts may report not embedded.  DejaVu/non-base fonts must embed.
            if poppler_fonts and len(cols) >= 6 and cols[-3].lower() == "no" and not any(base in line for base in ["Times", "Helvetica", "Courier", "Symbol", "Zapf"]):
                fail(f"non-base font not embedded in {name}: {line}")
    except Exception as exc:
        fail(f"could not preflight figure {name}: {exc}")

main_fonts = pdf_font_report(ROOT / "main.pdf")[0] if (ROOT / "main.pdf").exists() else ""
if "Type 3" in main_fonts:
    fail("main PDF contains Type 3 fonts")
if "LMRoman" in main_fonts or "LatinModern" in main_fonts:
    fail("main PDF text fell back to Latin Modern instead of the IEEEtran Times-compatible font path")

plot_src = (ROOT / "prototype" / "plot_results.py").read_text(encoding="utf-8")
concept_src = (ROOT / "prototype" / "draw_concept_figures.py").read_text(encoding="utf-8")
for token, label in [
    ("PACTA_FIG_STYLE_PUBLICATION", "plot style marker"),
    ("savefig.pad_inches", "tight vector export"),
    ("pdf.fonttype", "TrueType PDF font export"),
    ("frameon=False", "low-clutter legends"),
    ("stress_x", "explicit stress-point annotation"),
    ("negative controls", "separated negative-control size panel"),
]:
    if token not in plot_src:
        fail(f"plot_results.py missing {label}: {token}")
if "value (log scale)" in plot_src:
    fail("robustness figure still mixes heterogeneous units on one log axis")
if "PACTA_CONCEPT_FIG_STYLE_PUBLICATION" not in concept_src:
    fail("conceptual figure generator missing publication style marker")
if "seaborn" in plot_src.lower() or "plt.style.use" in plot_src:
    fail("plot script uses external/global style state instead of explicit paper style")

ack_match = re.search(r"\\section\*\{(?:Acknowledgments|AI-Generated Content Acknowledgement)\}\s*(.*?)\s*\\bibliographystyle", TEX, flags=re.S)
if not ack_match:
    fail("required acknowledgement section missing")
else:
    ack = " ".join(ack_match.group(1).split())
    if ack.count(".") > 1:
        fail("acknowledgement should remain a single concise sentence")
    if "language and grammar polishing" not in ack:
        fail("acknowledgement should describe language and grammar polishing")

body_before_ack = re.split(r"\\section\*\{(?:Acknowledgments|AI-Generated Content Acknowledgement)\}", TEX, maxsplit=1)[0].lower()
if "orcid" in body_before_ack:
    fail("ORCID should not be printed in the PDF author block/body; it belongs in the submission system")
if "haoyi zhang, huaijin ran" not in body_before_ack or "hyeliozhang" not in body_before_ack or "seventeen17510" not in body_before_ack:
    fail("two-author IEEE author block is missing or stale")
for phrase in ["delve", "seamlessly", "game-changing"]:
    if phrase in body_before_ack:
        fail(f"style-guard phrase in manuscript body: {phrase}")

if FAIL:
    print("figure/style audit failed:", file=sys.stderr)
    for msg in FAIL:
        print(f" - {msg}", file=sys.stderr)
    sys.exit(1)
print("figure/style audit passed: vector/PNG figures, fonts, plot scripts, and acknowledgement are clean")

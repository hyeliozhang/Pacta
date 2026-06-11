#!/usr/bin/env python3
"""Submission preflight checks for the Pacta artifact.

The script is intentionally conservative: it checks citations, obvious stale
package labels, LaTeX log failures, PDF page structure, and embedded-font hygiene
using only standard-library Python plus common TeX utilities when available.
"""
from __future__ import annotations
import pathlib
import re
import subprocess
import sys
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEX = ROOT / "main.tex"
BIB = ROOT / "references.bib"
PDF = ROOT / "main.pdf"
LOG = ROOT / "main.log"

FAILURES: list[str] = []
LOCAL_ENV_DIRS = {".venv", "venv", "env", ".codex_tools", ".reference_guard_cache"}

def fail(msg: str) -> None:
    FAILURES.append(msg)


def check_output_text(cmd: list[str]) -> str:
    return subprocess.check_output(
        cmd,
        encoding="utf-8",
        errors="replace",
        stderr=subprocess.STDOUT,
    )


# Remove Python bytecode caches before scanning the final package. The tests
# intentionally import the artifact, and these caches are not submission
# content. The subsequent scan still fails if any cache remains.
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

tex = TEX.read_text(encoding="utf-8")
bib = BIB.read_text(encoding="utf-8")

if "\\nocite" in tex:
    fail("main.tex contains \\nocite padding")

cite_keys: set[str] = set()
for match in re.finditer(r"\\cite\{([^}]*)\}", tex):
    cite_keys.update(k.strip() for k in match.group(1).split(",") if k.strip())
bib_keys = set(re.findall(r"@\w+\{([^,]+),", bib))
missing = sorted(cite_keys - bib_keys)
uncited = sorted(bib_keys - cite_keys)
if missing:
    fail(f"missing bib entries: {missing}")
if uncited:
    fail(f"uncited bib entries: {uncited}")
if len(cite_keys) < 70:
    fail(f"expected at least 70 real cited references, found {len(cite_keys)}")

if "Appendix" in tex or "appendix" in tex:
    fail("appendix string appears in main.tex; ICDE research submissions do not allow appendices")

stale_labels = ["V" + str(n) for n in range(17, 31)] + ["v" + str(n) for n in range(17, 31)]
for path in ROOT.rglob("*"):
    rel = path.relative_to(ROOT)
    if rel.parts and rel.parts[0] in LOCAL_ENV_DIRS:
        continue
    if "__pycache__" in path.parts:
        fail(f"Python cache directory/file present in package: {rel}")
    if path.is_dir() and re.search(r"pacta_v(17|18|19|20|21|22|23|24|25|26|27|28|29|30)$", path.name, flags=re.IGNORECASE):
        fail(f"nested stale package directory present: {rel}")
    if path.is_file() and path.suffix.lower() in {".md", ".txt"}:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(label in text for label in stale_labels):
            fail(f"stale version label in {rel}")
        upper = path.name.upper()
        if path.parent == ROOT and ("REVIEW" in upper or "ROUND" in upper):
            fail(f"internal review/draft report remains in final package: {path.name}")

if LOG.exists():
    log = LOG.read_text(encoding="utf-8", errors="ignore")
    bad_patterns = [
        "Undefined control sequence",
        "Citation `",
        "undefined references",
        "There were undefined references",
        "Overfull \\hbox",
        "Rerun to get cross-references right",
    ]
    # TeX can emit fatal error markers that are not literally "! LaTeX Error"
    # (for example "! Extra }, or forgotten \endgroup."). Treat any top-level
    # exclamation error line as a preflight failure so CI cannot pass with a
    # malformed build log.
    tex_errors = [line.strip() for line in log.splitlines() if line.startswith("!")]
    if tex_errors:
        fail("LaTeX log contains TeX error marker(s): " + "; ".join(tex_errors[:5]))
    for pat in bad_patterns:
        if pat in log:
            fail(f"LaTeX log contains: {pat}")
else:
    fail("main.log is missing; run LaTeX build first")
if PDF.exists():
    fitz_doc = None
    if not shutil.which("pdfinfo") or not shutil.which("pdftotext") or not shutil.which("pdffonts"):
        try:
            import fitz  # type: ignore
            fitz_doc = fitz.open(PDF)
        except Exception as exc:
            fail(f"PyMuPDF fallback failed: {exc}")

    if shutil.which("pdfinfo"):
        try:
            info = check_output_text(["pdfinfo", str(PDF)])
            pages = re.search(r"Pages:\s+(\d+)", info)
            total_pages = int(pages.group(1)) if pages else None
        except Exception as exc:
            fail(f"pdfinfo failed: {exc}")
            total_pages = None
    elif fitz_doc is not None:
        total_pages = fitz_doc.page_count
    else:
        total_pages = None
    if total_pages is None or total_pages < 13 or total_pages > 18:
        fail(f"unexpected PDF page count; expected 12 content pages plus acknowledgement/references, got {total_pages if total_pages else 'unknown'}")

    try:
        if shutil.which("pdftotext"):
            page13 = check_output_text(["pdftotext", "-f", "13", "-l", "13", str(PDF), "-"])
        elif fitz_doc is not None and fitz_doc.page_count >= 13:
            page13 = fitz_doc[12].get_text("text")
        else:
            page13 = ""
        # IEEEtran small caps can be extracted as spaced letters, e.g.
        # "AI-G ENERATED C ONTENT ACKNOWLEDGMENT" and "R EFERENCES".
        compact13 = re.sub(r"[^a-z]", "", page13.lower())
        starts_with_ack = compact13.startswith("acknowledg") or compact13.startswith("aigeneratedcontentacknowledg")
        starts_with_refs = compact13.startswith("references")
        if not (starts_with_ack or starts_with_refs):
            fail("page 13 does not appear to start acknowledgement/references")
    except Exception as exc:
        fail(f"page-13 text check failed: {exc}")

    if shutil.which("pdffonts"):
        try:
            fonts = check_output_text(["pdffonts", str(PDF)])
            for line in fonts.splitlines()[2:]:
                parts = line.split()
                if not parts:
                    continue
                # pdffonts splits multi-token font types such as "Type 1" and
                # "Type 3" into adjacent fields.  Check only the type field, not
                # later object-number columns that may legitimately contain "3".
                if len(parts) >= 3 and parts[1] == "Type" and parts[2] == "3":
                    fail("Type 3 font detected")
                # With no spaces in font names or encodings used here, the emb
                # column is field 4 for Type/CID fonts.
                if len(parts) >= 5 and parts[4] == "no":
                    fail(f"unembedded font detected: {line}")
        except Exception as exc:
            fail(f"pdffonts failed: {exc}")
    elif fitz_doc is not None:
        for page_index in range(fitz_doc.page_count):
            for font in fitz_doc.get_page_fonts(page_index, full=True):
                if len(font) >= 3 and "Type3" in str(font[2]).replace(" ", ""):
                    fail("Type 3 font detected")
else:
    fail("main.pdf is missing")

if FAILURES:
    print("submission preflight failed:", file=sys.stderr)
    for item in FAILURES:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)
print(f"submission preflight passed: {len(cite_keys)} cited references, PDF/log/font checks OK")

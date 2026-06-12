#!/usr/bin/env python3
"""Generate compact technical schematics for the Pacta paper.

The schematics are bounded paper figures rather than slide layouts: no
in-figure titles, no legend cards, thin evidence lines, compact labels, and
enough white space for IEEE single-column scaling. Captions carry the prose;
the figures encode only the checked flow and authenticated cover.
"""
from __future__ import annotations
import os
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle, Circle

STYLE_VERSION = "PACTA_CONCEPT_FIG_STYLE_PUBLICATION"

plt.rcParams.update({
    "pdf.use14corefonts": False,
    "ps.useafm": False,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Nimbus Roman", "DejaVu Serif"],
    "font.size": 6.2,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.018,
})

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIGS = os.path.join(ROOT, "figs")
os.makedirs(FIGS, exist_ok=True)

INK = "#1f2933"
MUTED = "#59636e"
LINE = "#27313b"
BLUE = "#285f8f"
BLUE_FILL = "#e8f1f8"
GREEN = "#36724f"
GREEN_FILL = "#e8f3ed"
GOLD = "#8a6819"
GOLD_FILL = "#f7efd9"
GRAY = "#69737e"
GRAY_FILL = "#f1f4f7"
TEAL = "#2d7680"
TEAL_FILL = "#e6f3f4"
RED = "#93494c"
RED_FILL = "#f6e8e7"
BG = "#fbfcfd"
BORDER = "#d7dde4"


def setup(ax, xmax: float, ymax: float) -> None:
    ax.set_xlim(0, xmax)
    ax.set_ylim(0, ymax)
    ax.axis("off")


def save(fig, name: str) -> None:
    fig.savefig(os.path.join(FIGS, f"{name}.pdf"))
    fig.savefig(os.path.join(FIGS, f"{name}.png"), dpi=460)
    plt.close(fig)


def panel(ax, x, y, w, h):
    ax.add_patch(Rectangle((x, y), w, h, facecolor=BG, edgecolor=BORDER, linewidth=0.58))


def pill(ax, x, y, w, h, text, face, edge, fontsize=5.0, weight="bold", radius=0.026, lw=0.58):
    box = FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0.025,rounding_size={radius}",
                         facecolor=face, edgecolor=edge, linewidth=lw)
    ax.add_patch(box)
    ax.text(x + w/2, y + h/2, text, ha="center", va="center", fontsize=fontsize,
            color=INK, weight=weight, linespacing=0.98)
    return box


def arrow(ax, x1, y1, x2, y2, color=LINE, lw=0.62, ms=6.0, rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=ms,
                                 linewidth=lw, color=color,
                                 connectionstyle=f"arc3,rad={rad}"))


def small_text(ax, x, y, s, size=4.05, color=MUTED, ha="center", va="center", weight="normal"):
    ax.text(x, y, s, ha=ha, va=va, fontsize=size, color=color, weight=weight, linespacing=1.02)


def edge_label(ax, x, y, s, color=MUTED):
    ax.text(x, y, s, ha="center", va="center", fontsize=3.55, color=color,
            bbox=dict(facecolor=BG, edgecolor="none", boxstyle="round,pad=0.10"))


def semantics() -> None:
    fig, ax = plt.subplots(figsize=(3.47, 1.64))
    setup(ax, 10.0, 3.10)

    panel(ax, 0.28, 0.48, 9.44, 2.22)
    for x in [2.55, 4.88, 7.10]:
        ax.plot([x, x], [0.58, 2.60], color="#e3e8ee", linewidth=0.45)

    pill(ax, 0.63, 2.02, 1.46, 0.40, "relation\ndescriptor", BLUE_FILL, BLUE)
    pill(ax, 0.63, 1.22, 1.46, 0.40, "manifest\nroot", BLUE_FILL, BLUE)

    pill(ax, 3.00, 2.02, 1.42, 0.40, "query\ndigest", GREEN_FILL, GREEN)
    pill(ax, 3.00, 1.22, 1.42, 0.40, "subject\npurpose", GREEN_FILL, GREEN)

    pill(ax, 5.35, 2.02, 1.24, 0.40, "answer", GRAY_FILL, GRAY, fontsize=5.25)
    pill(ax, 5.35, 1.22, 1.24, 0.40, "certificate", GRAY_FILL, GRAY, fontsize=5.25)

    pill(ax, 7.36, 2.02, 1.24, 0.40, "descriptor\nmatch", TEAL_FILL, TEAL)
    pill(ax, 7.36, 1.22, 1.24, 0.40, "bag\nmatch", TEAL_FILL, TEAL)
    pill(ax, 8.98, 1.61, 0.60, 0.42, "valid\nY,C", GOLD_FILL, GOLD, fontsize=4.55, lw=0.62)

    arrow(ax, 2.12, 2.22, 2.97, 2.22, BLUE)
    edge_label(ax, 2.55, 2.38, "bind", BLUE)
    arrow(ax, 2.12, 1.42, 2.97, 1.42, BLUE)
    edge_label(ax, 2.55, 1.58, "scope", BLUE)

    arrow(ax, 4.45, 2.22, 5.32, 2.22, GREEN)
    edge_label(ax, 4.88, 2.38, "run", GREEN)
    arrow(ax, 4.45, 1.42, 5.32, 1.42, GREEN)
    edge_label(ax, 4.88, 1.58, "prove", GREEN)

    arrow(ax, 6.62, 2.22, 7.33, 2.22, GRAY)
    edge_label(ax, 6.98, 2.38, "check", GRAY)
    arrow(ax, 6.62, 1.42, 7.33, 1.42, GRAY)
    edge_label(ax, 6.98, 1.58, "fold", GRAY)

    arrow(ax, 8.63, 2.22, 8.82, 1.85, TEAL, lw=0.56, ms=5.0, rad=-0.08)
    arrow(ax, 8.63, 1.42, 8.82, 1.79, TEAL, lw=0.56, ms=5.0, rad=0.08)
    ax.add_patch(Circle((8.85, 1.82), 0.030, facecolor=TEAL, edgecolor=TEAL, linewidth=0.4))
    arrow(ax, 8.88, 1.82, 8.97, 1.82, TEAL, lw=0.50, ms=4.6)
    save(fig, "semantics_pipeline")


def circle(ax, x, y, label, face, edge, r=0.130, size=4.5):
    ax.add_patch(Circle((x, y), r, facecolor=face, edgecolor=edge, linewidth=0.62))
    ax.text(x, y, label, ha="center", va="center", fontsize=size, color=INK, weight="bold")


def leaf(ax, x, y, text, face, edge, w=0.66):
    ax.add_patch(FancyBboxPatch((x - w/2, y - 0.17), w, 0.34,
                                boxstyle="round,pad=0.020,rounding_size=0.025",
                                facecolor=face, edgecolor=edge, linewidth=0.60))
    ax.text(x, y, text, ha="center", va="center", fontsize=4.05, color=INK, weight="bold")


def key_item(ax, x, y, text, face, edge, w=0.16):
    ax.add_patch(Rectangle((x, y - 0.075), w, 0.15, facecolor=face, edgecolor=edge, linewidth=0.50))
    small_text(ax, x + w + 0.08, y, text, 3.75, INK, ha="left")


def index_flow() -> None:
    fig, ax = plt.subplots(figsize=(3.47, 2.16))
    setup(ax, 10.0, 4.60)

    panel(ax, 0.34, 0.36, 9.32, 3.86)
    ax.plot([1.00, 9.00], [3.92, 3.92], color="#d8dee5", linewidth=0.72, solid_capstyle="round")
    ax.plot([2.36, 7.22], [3.92, 3.92], color=GREEN, linewidth=1.02, solid_capstyle="round")
    for x in [2.36, 7.22]:
        ax.plot([x, x], [3.76, 4.05], color=GREEN, linewidth=0.68)
    small_text(ax, 1.02, 4.10, "query interval", 3.95, MUTED, ha="left")

    pts = {
        "root": (5.0, 3.45),
        "l": (3.05, 2.86), "m": (5.0, 2.86), "r": (6.95, 2.86),
        "o1": (2.12, 2.08), "s1": (3.48, 2.08), "s2": (5.0, 2.08), "o2": (6.52, 2.08), "f": (7.88, 2.08),
    }
    for a, b in [("root","l"),("root","m"),("root","r"),("l","o1"),("l","s1"),("m","s2"),("r","o2"),("r","f")]:
        ax.plot([pts[a][0], pts[b][0]], [pts[a][1], pts[b][1]], color=LINE, linewidth=0.58)
    circle(ax, *pts["root"], "R", GOLD_FILL, GOLD, r=0.145, size=4.7)
    for k in ["l", "m", "r"]:
        circle(ax, *pts[k], "D", BLUE_FILL, BLUE, r=0.125, size=4.35)
    leaf(ax, *pts["o1"], "O", GREEN_FILL, GREEN, w=0.46)
    leaf(ax, *pts["s1"], "S", BLUE_FILL, BLUE, w=0.46)
    leaf(ax, *pts["s2"], "S", BLUE_FILL, BLUE, w=0.46)
    leaf(ax, *pts["o2"], "O", GREEN_FILL, GREEN, w=0.46)
    leaf(ax, *pts["f"], "F", GRAY_FILL, GRAY, w=0.46)

    key_item(ax, 1.10, 0.78, "O opened", GREEN_FILL, GREEN)
    key_item(ax, 2.92, 0.78, "S summary", BLUE_FILL, BLUE)
    key_item(ax, 4.92, 0.78, "F frontier", GRAY_FILL, GRAY)
    key_item(ax, 6.86, 0.78, "R policy root", GOLD_FILL, GOLD)
    save(fig, "index_certificate_flow")


if __name__ == "__main__":
    semantics()
    index_flow()
    print("wrote publication conceptual figures")

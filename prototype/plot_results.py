#!/usr/bin/env python3
"""Generate publication-quality Pacta paper figures from bundled CSV results."""
from __future__ import annotations

import csv
import os
import statistics
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, NullFormatter, ScalarFormatter
try:
    from pacta_core.encoding import sample_certificates
except Exception:
    sample_certificates = None  # type: ignore

STYLE_VERSION = "PACTA_FIG_STYLE_V32_ICDE_READY"

plt.rcParams.update({
    "pdf.use14corefonts": False,
    "ps.useafm": False,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Nimbus Roman", "DejaVu Serif"],
    "font.size": 6.8,
    "axes.labelsize": 7.1,
    "axes.titlesize": 7.0,
    "axes.linewidth": 0.55,
    "xtick.labelsize": 6.05,
    "ytick.labelsize": 6.05,
    "legend.fontsize": 5.3,
    "lines.linewidth": 1.32,
    "lines.markersize": 4.1,
    "patch.linewidth": 0.55,
    "axes.formatter.use_mathtext": False,
    "figure.dpi": 120,
    "savefig.dpi": 320,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.018,
})

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RESULTS = os.path.join(ROOT, 'results')
FIGS = os.path.join(ROOT, 'figs')
os.makedirs(FIGS, exist_ok=True)

INK = "#1f2933"
BLUE = "#285f8f"
ORANGE = "#b65f28"
GREEN = "#3d7f5a"
PURPLE = "#6b5fa7"
RED = "#9a3f44"
GOLD = "#8f722a"
TEAL = "#2a7f86"
GRAY = "#6f7378"
LIGHT = "#e6e8eb"
PALETTE = [BLUE, ORANGE, GREEN, RED, PURPLE, GOLD, TEAL, GRAY, "#4d6273"]


def read_rows(path: str) -> List[Dict[str, str]]:
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def f(row: Dict[str, str], key: str) -> float:
    return float(row[key])


def i(row: Dict[str, str], key: str) -> int:
    return int(float(row[key]))


def median(values: Iterable[float]) -> float:
    vals = [float(v) for v in values]
    return float(statistics.median(vals)) if vals else 0.0


def write_dicts(path: str, rows: List[Dict[str, object]], fields: List[str]) -> None:
    with open(path, 'w', newline='', encoding='utf-8') as out:
        w = csv.DictWriter(out, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, '') for k in fields})


def plain_log_axis(ax, axis='y'):
    def fmt(v, _pos):
        if v >= 1000:
            return f"{int(v):d}"
        if v >= 10:
            return f"{v:g}"
        if v >= 1:
            return f"{v:g}"
        return f"{v:.2g}"
    formatter = FuncFormatter(fmt)
    if axis in ('y', 'both'):
        ax.yaxis.set_major_formatter(formatter)
        ax.yaxis.set_minor_formatter(NullFormatter())
    if axis in ('x', 'both'):
        ax.xaxis.set_major_formatter(formatter)
        ax.xaxis.set_minor_formatter(NullFormatter())


def kfmt(v: float) -> str:
    if v >= 1_000_000:
        return f"{v/1_000_000:g}M"
    if v >= 1000:
        return f"{v/1000:g}K"
    return f"{v:g}"


def polish(ax, grid_axis='y'):
    ax.tick_params(width=0.50, length=2.2, pad=1.35, color=INK, labelcolor=INK)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("bottom", "left"):
        ax.spines[side].set_linewidth(0.52)
        ax.spines[side].set_color(INK)
    if grid_axis:
        ax.grid(True, axis=grid_axis, which='major', linewidth=0.32, color="#c4c9cf", alpha=0.62)
        ax.grid(True, axis=grid_axis, which='minor', linewidth=0.20, color="#e1e4e8", alpha=0.55)
        ax.set_axisbelow(True)


def savefig(fig, name: str, png_dpi: int = 340):
    fig.tight_layout(pad=0.10)
    fig.savefig(os.path.join(FIGS, f"{name}.pdf"))
    fig.savefig(os.path.join(FIGS, f"{name}.png"), dpi=png_dpi)
    plt.close(fig)


def short_scheme(s: str) -> str:
    return {
        'adaptive_planner': 'adaptive',
        'pacta': 'Pacta',
        'tuple_frontier': 'tuple+frontier',
        'tuple_merkle': 'tuple Merkle',
        'range_tree': 'range tree',
        'full_recompute': 'recompute',
        'full_table_hash': 'table hash',
        'policy_oblivious': 'policy-blind',
        'provenance_only': 'provenance',
    }.get(s, s.replace('_', ' '))


# Encoding sanity check for certificate-size accounting.
if sample_certificates is not None:
    enc_rows = sample_certificates(os.path.join(RESULTS, 'cert_samples'))
    if enc_rows:
        write_dicts(os.path.join(RESULTS, 'encoding_estimates.csv'), enc_rows,
                    ['sample', 'json_bytes', 'gzip_bytes', 'logical_binary_bytes'])

summary = read_rows(os.path.join(RESULTS, 'summary.csv'))
updates = read_rows(os.path.join(RESULTS, 'updates.csv'))
stress = read_rows(os.path.join(RESULTS, 'pacta_stress.csv')) if os.path.exists(os.path.join(RESULTS, 'pacta_stress.csv')) else []
workloads = read_rows(os.path.join(RESULTS, 'workload_profiles.csv')) if os.path.exists(os.path.join(RESULTS, 'workload_profiles.csv')) else []
join_complete = read_rows(os.path.join(RESULTS, 'join_complete.csv')) if os.path.exists(os.path.join(RESULTS, 'join_complete.csv')) else []
operators = read_rows(os.path.join(RESULTS, 'operator_contracts.csv')) if os.path.exists(os.path.join(RESULTS, 'operator_contracts.csv')) else []
planner_frontier = read_rows(os.path.join(RESULTS, 'planner_frontier.csv')) if os.path.exists(os.path.join(RESULTS, 'planner_frontier.csv')) else []
large_scale = read_rows(os.path.join(RESULTS, 'large_scale_page_index.csv')) if os.path.exists(os.path.join(RESULTS, 'large_scale_page_index.csv')) else []
prefix_cube = read_rows(os.path.join(RESULTS, 'prefix_cube_medians.csv')) if os.path.exists(os.path.join(RESULTS, 'prefix_cube_medians.csv')) else []
ssb_star = read_rows(os.path.join(RESULTS, 'ssb_star_medians.csv')) if os.path.exists(os.path.join(RESULTS, 'ssb_star_medians.csv')) else []
robustness_summary = read_rows(os.path.join(RESULTS, 'robustness_summary.csv')) if os.path.exists(os.path.join(RESULTS, 'robustness_summary.csv')) else []

# Planner-frontier medians and figures.
frontier_rows: List[Dict[str, object]] = []
if planner_frontier:
    by_qp: Dict[Tuple[str, str], List[Dict[str, str]]] = defaultdict(list)
    for r in planner_frontier:
        by_qp[(r['query_kind'], r['plan'])].append(r)
    for (qkind, plan), rows in sorted(by_qp.items()):
        frontier_rows.append({
            'query_kind': qkind,
            'plan': plan,
            'sound': rows[0].get('sound', ''),
            'median_certificate_bytes': median(f(r, 'certificate_bytes') for r in rows),
            'median_verification_ms': median(f(r, 'client_verification_ms') for r in rows),
            'median_generation_ms': median(f(r, 'server_generation_ms') for r in rows),
        })
    write_dicts(os.path.join(RESULTS, 'planner_frontier_medians.csv'), frontier_rows,
                ['query_kind', 'plan', 'sound', 'median_certificate_bytes', 'median_verification_ms', 'median_generation_ms'])

    # Compact overview retained for artifact readers.
    fig, ax = plt.subplots(figsize=(3.35, 2.20))
    labels = [str(r['plan']).replace('_', '\n') for r in frontier_rows]
    xs = list(range(len(frontier_rows)))
    vals = [float(r['median_certificate_bytes']) / 1024.0 for r in frontier_rows]
    bars = ax.bar(xs, vals, color=BLUE, edgecolor=INK, linewidth=0.45)
    for bar, r in zip(bars, frontier_rows):
        if str(r.get('sound', '')).lower() == 'false':
            bar.set_facecolor("#d9dce0")
            bar.set_hatch('///')
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=35, ha='right', fontsize=4.9)
    ax.set_ylabel('median cert. size (KiB)')
    ax.set_yscale('log')
    plain_log_axis(ax, 'y')
    polish(ax, 'y')
    savefig(fig, 'planner_frontier')

    # Legality frontier rendered for the paper.
    label_map = {
        ('governed_groupby', 'policy_cube_summary'): 'group-by\npolicy cube',
        ('governed_groupby', 'open_range_scan_equivalent'): 'group-by\nopen scan',
        ('row_predicate_groupby', 'policy_cube_summary_without_amount'): 'row predicate\nsummary',
        ('row_predicate_groupby', 'open_range_scan'): 'row predicate\nopen scan',
    }
    order_keys = [
        ('governed_groupby', 'policy_cube_summary'),
        ('governed_groupby', 'open_range_scan_equivalent'),
        ('row_predicate_groupby', 'policy_cube_summary_without_amount'),
        ('row_predicate_groupby', 'open_range_scan'),
    ]
    row_by_key = {(str(r['query_kind']), str(r['plan'])): r for r in frontier_rows}
    plot_rows = [(label_map[k], row_by_key[k]) for k in order_keys if k in row_by_key]
    if plot_rows:
        fig, ax = plt.subplots(figsize=(3.35, 1.95))
        labels = [x[0] for x in plot_rows]
        values = [float(x[1]['median_certificate_bytes']) / 1024.0 for x in plot_rows]
        ys = list(range(len(plot_rows)))
        xmin = max(10, min(values) * 0.72)
        xmax = max(values) * 2.8
        for y, (_, row), value in zip(ys, plot_rows, values):
            sound = str(row.get('sound', '')).lower() == 'true'
            color = BLUE if sound else RED
            marker = 'o' if sound else 'x'
            ax.hlines(y, xmin, value, color="#c8cfd6", linewidth=0.62, zorder=1)
            ax.scatter([value], [y], s=30 if sound else 34, color=color, marker=marker,
                       linewidths=1.05, zorder=3)
            tag = 'accepted' if sound else 'rejected'
            ax.text(value * 1.12, y, f"{tag}\n{value:.1f} KiB", va='center',
                    fontsize=4.85, color=color, linespacing=0.90)
        ax.set_yticks(ys)
        ax.set_yticklabels(labels, fontsize=5.35)
        ax.invert_yaxis()
        ax.set_xscale('log')
        plain_log_axis(ax, 'x')
        ax.set_xlabel('median cert. size (KiB)')
        ax.set_xlim(left=xmin, right=xmax)
        polish(ax, 'x')
        if len(values) >= 2 and values[0] > 0 and values[1] > 0:
            ratio = round(max(values[0], values[1]) / min(values[0], values[1]))
            lo, hi = sorted([values[0], values[1]])
            y_gap = 0.42
            ax.hlines(y_gap, lo, hi, color=INK, linewidth=0.45, zorder=2)
            ax.vlines([lo, hi], y_gap - 0.055, y_gap + 0.055, color=INK, linewidth=0.45, zorder=2)
            ax.text((lo * hi) ** 0.5, y_gap + 0.14, f"{ratio}x",
                    ha='center', va='bottom', fontsize=4.55, color=INK)
        savefig(fig, 'planner_legality_frontier')

    # Physical-design trade-off including the materialized prefix-cube view.
    if prefix_cube:
        vals = []
        for rr in frontier_rows:
            if rr['query_kind'] in ('ordinary_groupby', 'governed_groupby') and rr['plan'] == 'policy_cube_summary':
                vals.append(('policy cube', float(rr['median_certificate_bytes']) / 1024.0))
            if rr['query_kind'] in ('ordinary_groupby', 'governed_groupby') and rr['plan'] in ('complete_open_scan', 'open_range_scan_equivalent'):
                vals.append(('open scan', float(rr['median_certificate_bytes']) / 1024.0))
        vals.append(('prefix cube', float(prefix_cube[0]['median_certificate_bytes']) / 1024.0))
        order = ['prefix cube', 'policy cube', 'open scan']
        vals = sorted(vals, key=lambda x: order.index(x[0]) if x[0] in order else 99)
        fig, ax = plt.subplots(figsize=(3.35, 2.05))
        bars = ax.bar(range(len(vals)), [v for _, v in vals], color=[GREEN, BLUE, GRAY], edgecolor=INK, linewidth=0.55)
        ax.set_xticks(range(len(vals)))
        ax.set_xticklabels([k for k, _ in vals], rotation=12, ha='right', fontsize=6.3)
        ax.set_ylabel('median cert. size (KiB)')
        ax.set_yscale('log')
        plain_log_axis(ax, 'y')
        polish(ax, 'y')
        savefig(fig, 'physical_design_frontier')

# Operator and scheme medians for tables.
if operators:
    by_op: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for r in operators:
        by_op[r['operator']].append(r)
    op_rows: List[Dict[str, object]] = []
    for op, rows in sorted(by_op.items()):
        op_rows.append({
            'operator': op,
            'median_certificate_bytes': median(f(r, 'certificate_bytes') for r in rows),
            'median_verification_ms': median(f(r, 'client_verification_ms') for r in rows),
            'median_generation_ms': median(f(r, 'server_generation_ms') for r in rows),
        })
    write_dicts(os.path.join(RESULTS, 'operator_contract_medians.csv'), op_rows,
                ['operator', 'median_certificate_bytes', 'median_verification_ms', 'median_generation_ms'])

by_scheme: Dict[str, List[Dict[str, str]]] = defaultdict(list)
for r in summary:
    by_scheme[r['scheme']].append(r)
scheme_rows: List[Dict[str, object]] = []
for scheme, rows in by_scheme.items():
    scheme_rows.append({
        'scheme': scheme,
        'median_certificate_bytes': median(f(r, 'certificate_bytes') for r in rows),
        'median_verification_ms': median(f(r, 'client_verification_ms') for r in rows),
        'median_generation_ms': median(f(r, 'server_generation_ms') for r in rows),
        'median_authorized_rows': median(f(r, 'authorized_rows') for r in rows),
    })
scheme_rows.sort(key=lambda r: float(r['median_certificate_bytes']))
write_dicts(os.path.join(RESULTS, 'scheme_medians.csv'), scheme_rows,
            ['scheme', 'median_certificate_bytes', 'median_verification_ms', 'median_generation_ms', 'median_authorized_rows'])

if join_complete:
    by_jn: Dict[int, List[Dict[str, str]]] = defaultdict(list)
    for r in join_complete:
        by_jn[i(r, 'n')].append(r)
    join_complete_rows: List[Dict[str, object]] = []
    for n, rows in sorted(by_jn.items()):
        join_complete_rows.append({
            'n': n,
            'median_certificate_bytes': median(f(r, 'certificate_bytes') for r in rows),
            'median_verification_ms': median(f(r, 'client_verification_ms') for r in rows),
            'median_generation_ms': median(f(r, 'server_generation_ms') for r in rows),
            'median_opened_sales_count': median(f(r, 'opened_sales_count') for r in rows),
        })
    write_dicts(os.path.join(RESULTS, 'join_complete_medians.csv'), join_complete_rows,
                ['n', 'median_certificate_bytes', 'median_verification_ms', 'median_generation_ms', 'median_opened_sales_count'])

planner_rows_raw = [r for r in summary if r['scheme'] == 'adaptive_planner']
planner_counts: Dict[str, int] = defaultdict(int)
for r in planner_rows_raw:
    planner_counts[r.get('selected_evidence', 'unknown')] += 1
planner_rows = [{'selected_evidence': k, 'count': v} for k, v in sorted(planner_counts.items())]
write_dicts(os.path.join(RESULTS, 'planner_choices.csv'), planner_rows, ['selected_evidence', 'count'])

# Large-scale page-cube trend.
if large_scale:
    by_ls: Dict[int, List[Dict[str, str]]] = defaultdict(list)
    for r in large_scale:
        by_ls[i(r, 'n')].append(r)
    large_rows: List[Dict[str, object]] = []
    for n, rows in sorted(by_ls.items()):
        large_rows.append({
            'n': n,
            'median_certificate_bytes': median(f(r, 'certificate_bytes') for r in rows),
            'median_verify_ms': median(f(r, 'client_verification_ms_median') for r in rows),
            'median_generation_ms': median(f(r, 'server_generation_ms') for r in rows),
            'median_build_ms': median(f(r, 'build_ms') for r in rows),
            'pages': median(f(r, 'pages') for r in rows),
        })
    write_dicts(os.path.join(RESULTS, 'large_scale_page_medians.csv'), large_rows,
                ['n', 'median_certificate_bytes', 'median_verify_ms', 'median_generation_ms', 'median_build_ms', 'pages'])
    fig, axes = plt.subplots(1, 2, figsize=(3.35, 2.00), gridspec_kw={"width_ratios": [1.35, 1.0]})
    ax = axes[0]
    xs = [int(r['n']) for r in large_rows]
    ax.plot(xs, [float(r['median_verify_ms']) for r in large_rows], marker='o', color=BLUE, label='verify')
    ax.plot(xs, [float(r['median_generation_ms']) for r in large_rows], marker='s', color=ORANGE, label='proof gen')
    ax.set_xscale('log')
    ax.set_xticks(xs)
    ax.set_xticklabels([kfmt(x) for x in xs])
    ax.set_xlabel('tuples')
    ax.set_ylabel('time (ms)')
    polish(ax, 'both')
    ax.legend(frameon=False, loc='upper left', handlelength=1.20, borderpad=0.05, labelspacing=0.18)
    ax2 = axes[1]
    cert = [float(r['median_certificate_bytes']) / 1024.0 for r in large_rows]
    pages = [float(r['pages']) for r in large_rows]
    ax2.plot(xs, cert, marker='D', color=GREEN, label='cert. KiB')
    ax2.set_xscale('log')
    ax2.set_xticks(xs)
    ax2.set_xticklabels([kfmt(x) for x in xs], rotation=15, ha='right', fontsize=5.75)
    ax2.set_ylabel('cert. size (KiB)', color=GREEN)
    ax2.tick_params(axis='y', labelcolor=GREEN)
    polish(ax2, 'y')
    axp = ax2.twinx()
    axp.plot(xs, pages, marker='o', color=PURPLE, linewidth=1.02, label='pages')
    axp.set_ylabel('pages', color=PURPLE)
    axp.tick_params(axis='y', labelcolor=PURPLE, width=0.50, length=2.2, pad=1.25)
    axp.spines['top'].set_visible(False)
    axp.spines['right'].set_linewidth(0.52)
    axp.spines['right'].set_color(PURPLE)
    ax2.set_xlabel('tuples')
    ax2.text(0.03, 0.93, 'page-cube\ncover', transform=ax2.transAxes, ha='left', va='top',
             fontsize=5.2, color=INK, linespacing=0.95)
    savefig(fig, 'large_scale_page_index')

# Pacta medians by n, combining the separate 20K/50K stress profile if present.
pacta = [r for r in summary if r['scheme'] == 'pacta'] + stress
by_n: Dict[int, List[Dict[str, str]]] = defaultdict(list)
for r in pacta:
    by_n[i(r, 'n')].append(r)
pacta_by_n: List[Dict[str, object]] = []
for n, rows in sorted(by_n.items()):
    pacta_by_n.append({
        'n': n,
        'certificate_bytes': median(f(r, 'certificate_bytes') for r in rows),
        'server_generation_ms': median(f(r, 'server_generation_ms') for r in rows),
        'client_verification_ms': median(f(r, 'client_verification_ms') for r in rows),
        'sqlite_query_ms': median(f(r, 'sqlite_query_ms') for r in rows),
        'authorized_rows': median(f(r, 'authorized_rows') for r in rows),
        'range_rows': median(f(r, 'range_rows') for r in rows),
        'tree_build_ms': median(f(r, 'tree_build_ms') for r in rows),
    })
write_dicts(os.path.join(RESULTS, 'pacta_by_n.csv'), pacta_by_n,
            ['n', 'certificate_bytes', 'server_generation_ms', 'client_verification_ms', 'sqlite_query_ms', 'authorized_rows', 'range_rows', 'tree_build_ms'])

# Certificate size vs selectivity for largest full-baseline slice, medium policy.
max_n = max(i(r, 'n') for r in summary)
large_slice = [r for r in summary if i(r, 'n') == max_n and int(float(r['policy_complexity'])) == 3]
large_by_scheme: Dict[str, List[Dict[str, str]]] = defaultdict(list)
for r in large_slice:
    large_by_scheme[r['scheme']].append(r)
large_rows: List[Dict[str, object]] = []
for scheme, rows in large_by_scheme.items():
    large_rows.append({
        'scheme': scheme,
        'certificate_bytes': median(f(r, 'certificate_bytes') for r in rows),
        'client_verification_ms': median(f(r, 'client_verification_ms') for r in rows),
        'server_generation_ms': median(f(r, 'server_generation_ms') for r in rows),
    })
large_rows.sort(key=lambda r: float(r['certificate_bytes']))
write_dicts(os.path.join(RESULTS, 'largest_medium_policy_medians.csv'), large_rows,
            ['scheme', 'certificate_bytes', 'client_verification_ms', 'server_generation_ms'])

pivot: Dict[Tuple[float, str], List[float]] = defaultdict(list)
for r in large_slice:
    pivot[(f(r, 'selectivity'), r['scheme'])].append(f(r, 'certificate_bytes') / 1024.0)
selectivities = sorted({k[0] for k in pivot})
order = ['adaptive_planner', 'pacta', 'tuple_frontier', 'tuple_merkle', 'range_tree', 'full_recompute', 'full_table_hash', 'policy_oblivious', 'provenance_only']
style = {
    'adaptive_planner': dict(color=INK, marker='o', linewidth=1.35, zorder=5),
    'pacta': dict(color=BLUE, marker='s', linewidth=1.35, zorder=5),
    'tuple_frontier': dict(color=GREEN, marker='^', linewidth=0.95),
    'tuple_merkle': dict(color=RED, marker='v', linewidth=0.95),
    'range_tree': dict(color=PURPLE, marker='D', linewidth=0.95),
    'full_recompute': dict(color=GRAY, marker='o', linewidth=0.8, linestyle='--'),
    'full_table_hash': dict(color="#8d8f93", marker='s', linewidth=0.8, linestyle='--'),
    'policy_oblivious': dict(color=GOLD, marker='P', linewidth=0.8, linestyle=':'),
    'provenance_only': dict(color="#b0a51a", marker='X', linewidth=0.8, linestyle=':'),
}
fig, axes = plt.subplots(1, 2, figsize=(3.35, 2.12), gridspec_kw={"width_ratios": [1.42, 1.0]})
sound_order = ['adaptive_planner', 'pacta', 'tuple_frontier', 'tuple_merkle', 'range_tree', 'full_recompute', 'full_table_hash']
# Keep negative controls in a separate panel so unsound baselines cannot be read
# as peer sound-proof systems.
neg_order = ['pacta', 'policy_oblivious', 'provenance_only']

def draw_selectivity_panel(ax, schemes: List[str], title: str, label_right: bool = True):
    endpoints: Dict[str, Tuple[float, float]] = {}
    for scheme in schemes:
        ys = []
        xs = []
        for sel in selectivities:
            vals = pivot.get((sel, scheme), [])
            if vals:
                xs.append(sel)
                ys.append(median(vals))
        if ys:
            local_style = dict(style.get(scheme, {}))
            if scheme == 'policy_oblivious':
                local_style.update(linestyle='--', linewidth=1.05, marker='P')
            if scheme == 'provenance_only':
                local_style.update(linestyle=':', linewidth=1.05, marker='X')
            ax.plot(xs, ys, label=short_scheme(scheme), **local_style)
            endpoints[scheme] = (xs[-1], ys[-1])
    ax.set_yscale('log')
    plain_log_axis(ax, 'y')
    ax.set_xticks(selectivities)
    ax.set_xticklabels([f"{int(s*100)}%" for s in selectivities])
    ax.set_xlim(min(selectivities) * 0.78, max(selectivities) * 1.28)
    ax.set_xlabel('selectivity')
    ax.set_title(title, pad=1.4, fontsize=5.8, loc='left')
    polish(ax, 'y')
    if label_right:
        label_offsets = {
            'full_table_hash': 1.34,
            'full_recompute': 0.74,
            'tuple_frontier': 0.98,
            'tuple_merkle': 0.58,
            'range_tree': 1.16,
            'pacta': 0.86,
            'adaptive_planner': 1.22,
        }
        for scheme, (x_end, y_end) in endpoints.items():
            if scheme in ('adaptive_planner', 'full_recompute'):
                continue
            ax.text(x_end * 1.025, y_end * label_offsets.get(scheme, 1.0),
                    short_scheme(scheme), ha='left', va='center',
                    fontsize=4.25, color=style.get(scheme, {}).get('color', INK))

draw_selectivity_panel(axes[0], sound_order, '(a) sound plans')
axes[0].set_ylabel('cert. size (KiB)')
draw_selectivity_panel(axes[1], neg_order, '(b) controls', label_right=False)
axes[1].set_ylabel('')
axes[1].set_ylim(0.25, 210)
axes[1].legend(frameon=False, loc='upper left', handlelength=1.0, borderpad=0.05,
               labelspacing=0.16, fontsize=4.8)
savefig(fig, 'cert_size_selectivity')

# Compact proof generation/verification scalability.
fig, ax = plt.subplots(figsize=(3.35, 1.92))
xs = [int(r['n']) for r in pacta_by_n]
ax.plot(xs, [float(r['server_generation_ms']) for r in pacta_by_n], marker='o', color=BLUE, label='proof gen')
ax.plot(xs, [float(r['client_verification_ms']) for r in pacta_by_n], marker='s', color=ORANGE, label='verify')
stress_x = [x for x in xs if x >= 20000]
if stress_x:
    gen_by_x = {int(r['n']): float(r['server_generation_ms']) for r in pacta_by_n}
    ver_by_x = {int(r['n']): float(r['client_verification_ms']) for r in pacta_by_n}
    ax.scatter(stress_x, [gen_by_x[x] for x in stress_x], facecolors='none', edgecolors=BLUE,
               marker='o', s=46, linewidths=0.82, zorder=4)
    ax.scatter(stress_x, [ver_by_x[x] for x in stress_x], facecolors='none', edgecolors=ORANGE,
               marker='s', s=46, linewidths=0.82, zorder=4)
    ax.text(stress_x[0], max(gen_by_x[x] for x in stress_x) * 0.86, 'stress\nprofile',
            ha='center', va='top', fontsize=5.0, color=INK, linespacing=0.92)
ax.set_xscale('log')
ax.set_xticks(xs)
ax.set_xticklabels([kfmt(x) for x in xs])
ax.set_xlabel('tuples')
ax.set_ylabel('time (ms)')
polish(ax, 'y')
ax.legend(frameon=False, loc='upper left', handlelength=1.20, borderpad=0.05, labelspacing=0.18)
savefig(fig, 'time_scalability')

# Cross-profile medians for external-validity table and figure.
if workloads:
    by_profile: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for r in workloads:
        by_profile[r['profile']].append(r)
    workload_medians: List[Dict[str, object]] = []
    for profile, rows in sorted(by_profile.items()):
        workload_medians.append({
            'profile': profile,
            'median_certificate_bytes': median(f(r, 'certificate_bytes') for r in rows),
            'median_verification_ms': median(f(r, 'client_verification_ms') for r in rows),
            'median_generation_ms': median(f(r, 'server_generation_ms') for r in rows),
            'median_authorized_rows': median(f(r, 'authorized_rows') for r in rows),
            'median_range_rows': median(f(r, 'range_rows') for r in rows),
        })
    write_dicts(os.path.join(RESULTS, 'workload_profile_medians.csv'), workload_medians,
                ['profile', 'median_certificate_bytes', 'median_verification_ms', 'median_generation_ms', 'median_authorized_rows', 'median_range_rows'])
    workload_medians.sort(key=lambda r: float(r['median_certificate_bytes']))
    fig, ax = plt.subplots(figsize=(3.35, 2.42))
    ys = list(range(len(workload_medians)))
    labels = [str(r['profile']).replace('public_', 'public ').replace('_', ' ') for r in workload_medians]
    vals = [float(r['median_certificate_bytes']) / 1024.0 for r in workload_medians]
    ax.barh(ys, vals, color=BLUE, edgecolor=INK, linewidth=0.45)
    ax.set_yticks(ys)
    ax.set_yticklabels(labels, fontsize=5.8)
    ax.set_xlabel('median cert. size (KiB)')
    polish(ax, 'x')
    savefig(fig, 'workload_profile_certificates')

# Robustness sweep across fixed seeds/profiles/selectivities/policies.
if robustness_summary:
    def metric_row(name: str):
        for rr in robustness_summary:
            if rr.get('metric') == name:
                return rr
        return None
    cert_r = metric_row('certificate_bytes')
    ver_r = metric_row('client_verification_ms')
    gen_r = metric_row('server_generation_ms')
    rows = []
    if cert_r:
        rows.append(('cert. size\n(KiB)', float(cert_r['median']) / 1024.0, float(cert_r['p95']) / 1024.0))
    if ver_r:
        rows.append(('verify\n(ms)', float(ver_r['median']), float(ver_r['p95'])))
    if gen_r:
        rows.append(('proof gen.\n(ms)', float(gen_r['median']), float(gen_r['p95'])))
    if rows:
        fig, axes = plt.subplots(1, 3, figsize=(3.35, 1.95))
        tags = ['(a) size', '(b) verify', '(c) generation']
        for ax, (label, med, p95), color, tag in zip(axes, rows, [BLUE, ORANGE, GREEN], tags):
            ax.bar([0], [med], width=0.46, color=color, alpha=0.82, edgecolor=INK, linewidth=0.45, label='median')
            ax.scatter([0], [p95], marker='_', s=130, color=RED, linewidths=1.25, label='p95', zorder=4)
            ax.vlines(0, med, p95, color=RED, linewidth=0.74, zorder=3)
            ax.set_xticks([0])
            ax.set_xticklabels(['median\n+p95'], fontsize=5.4)
            ax.set_title(tag, fontsize=5.75, pad=1.5)
            upper = p95 * 1.28 if p95 > 0 else 1
            ax.set_ylim(0, upper)
            polish(ax, 'y')
            ax.text(0, med * 1.04, f"{med:.1f}", ha='center', va='bottom', fontsize=4.25, color=INK)
            ax.text(0.18, p95, f"{p95:.1f}", ha='left', va='center', fontsize=4.25, color=RED)
        axes[0].set_ylabel('KiB')
        axes[1].set_ylabel('ms')
        axes[2].set_ylabel('ms')
        fig.subplots_adjust(top=0.86, bottom=0.23, wspace=0.52)
        savefig(fig, 'robustness_sweep')

# Non-key update cost vs full rebuild.
by_update_n: Dict[int, List[Dict[str, str]]] = defaultdict(list)
for r in updates:
    by_update_n[i(r, 'n')].append(r)
update_rows = []
for n, rows in sorted(by_update_n.items()):
    update_rows.append({
        'n': n,
        'incremental_update_ms': median(f(r, 'incremental_update_ms') for r in rows),
        'rebuild_update_ms': median(f(r, 'rebuild_update_ms') for r in rows),
    })
fig, ax = plt.subplots(figsize=(3.35, 2.10))
ax.plot([r['n'] for r in update_rows], [r['incremental_update_ms'] for r in update_rows], marker='o', color=BLUE, label='repair path')
ax.plot([r['n'] for r in update_rows], [r['rebuild_update_ms'] for r in update_rows], marker='s', color=ORANGE, label='full rebuild')
ax.set_yscale('log')
plain_log_axis(ax, 'y')
ax.set_xticks([r['n'] for r in update_rows])
ax.set_xticklabels([kfmt(r['n']) for r in update_rows])
ax.set_xlabel('tuples')
ax.set_ylabel('update time (ms)')
polish(ax, 'y')
ax.legend(frameon=False, loc='upper left', handlelength=1.20, borderpad=0.05, labelspacing=0.18)
savefig(fig, 'update_cost')

print('wrote publication-quality figures and tables to', FIGS, 'and', RESULTS)

#!/usr/bin/env python3
"""Check that manuscript numeric claims match bundled CSV evidence.

This guard prevents the common artifact-review failure where prose/table numbers
lag behind regenerated CSVs.  It intentionally checks the paper's most visible
claims rather than every raw value in every CSV.
"""
from __future__ import annotations
import csv
import pathlib
import statistics
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEX = (ROOT / "main.tex").read_text(encoding="utf-8")
RESULTS = ROOT / "results"
FAIL: list[str] = []

def fail(msg: str) -> None:
    FAIL.append(msg)

def rows(name: str) -> list[dict[str, str]]:
    path = RESULTS / name
    if not path.exists():
        fail(f"missing result file: {name}")
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def row_by(name: str, col: str, value: str) -> dict[str, str]:
    for r in rows(name):
        if r.get(col) == value:
            return r
    fail(f"missing row in {name}: {col}={value}")
    return {}

def f2(x: float) -> str:
    return f"{x:.2f}"

def kib(x: float) -> str:
    return f"{x / 1024.0:.1f} KiB"

def mib(x: float) -> str:
    return f"{x / (1024.0 * 1024.0):.2f} MiB"

def expect(text: str, label: str) -> None:
    if text not in TEX:
        fail(f"main.tex missing {label}: {text}")

def expect_any(texts: list[str], label: str) -> None:
    if not any(text in TEX for text in texts):
        fail(f"main.tex missing {label}: {texts[0]}")

# Full-baseline matrix.
pacta = row_by("scheme_medians.csv", "scheme", "pacta")
if pacta:
    expect(f"{kib(float(pacta['median_certificate_bytes']))} median size, {f2(float(pacta['median_generation_ms']))} ms generation, and {f2(float(pacta['median_verification_ms']))} ms client verification", "abstract Pacta median")
    expect(f"{kib(float(pacta['median_certificate_bytes']))} with {f2(float(pacta['median_generation_ms']))} ms generation and {f2(float(pacta['median_verification_ms']))} ms verification", "baseline prose Pacta median")

# Scalability by n.
by_n = {int(float(r["n"])): r for r in rows("pacta_by_n.csv")}
if {2000, 5000, 20000, 50000}.issubset(by_n):
    expect_any([
        f"Median verification is {f2(float(by_n[2000]['client_verification_ms']))} ms at 2K rows, {f2(float(by_n[5000]['client_verification_ms']))} ms at 5K, {f2(float(by_n[20000]['client_verification_ms']))} ms at 20K, and {f2(float(by_n[50000]['client_verification_ms']))} ms at 50K; generation rises from {f2(float(by_n[2000]['server_generation_ms']))} ms to {f2(float(by_n[50000]['server_generation_ms']))} ms, and the 50K median certificate remains {kib(float(by_n[50000]['certificate_bytes']))}",
        f"Median verification is {f2(float(by_n[2000]['client_verification_ms']))} ms at 2K rows, {f2(float(by_n[5000]['client_verification_ms']))} ms at 5K, {f2(float(by_n[20000]['client_verification_ms']))} ms at 20K, and {f2(float(by_n[50000]['client_verification_ms']))} ms at 50K. Generation rises from {f2(float(by_n[2000]['server_generation_ms']))} ms to {f2(float(by_n[50000]['server_generation_ms']))} ms, and the 50K median certificate remains {kib(float(by_n[50000]['certificate_bytes']))}.",
    ],
        "compact scalability sentence",
    )

# Page cube, prefix cube, and star-schema prefix profile.
page1m = row_by("large_scale_page_medians.csv", "n", "1000000")
prefix = row_by("prefix_cube_medians.csv", "scheme", "authenticated_prefix_cube_view")
star = row_by("ssb_star_medians.csv", "profile", "ssb_star_lineorder_style")
if page1m and prefix and star:
    expect(f"1M-row page-cube certificate verifies in {f2(float(page1m['median_verify_ms']))} ms", "abstract page-cube")
    expect(f"50K-row authenticated prefix cube verifies range group-by certificates in {f2(float(prefix['median_verification_ms']))} ms with {kib(float(prefix['median_certificate_bytes']))} proofs", "abstract prefix-cube")
    expect_any([
        f"At 1M rows, the median certificate is {kib(float(page1m['median_certificate_bytes']))}, proof generation is {f2(float(page1m['median_generation_ms']))} ms, descriptor-only verification is {f2(float(page1m['median_verify_ms']))} ms, and the {int(float(page1m['pages']))}-page index builds in {float(page1m['median_build_ms'])/1000.0:.2f} s.",
        f"At 1M rows, the median page-cube certificate is {kib(float(page1m['median_certificate_bytes']))}, proof generation is {f2(float(page1m['median_generation_ms']))} ms, and descriptor-only verification is {f2(float(page1m['median_verify_ms']))} ms; the index contains {int(float(page1m['pages']))} authenticated pages and builds in {float(page1m['median_build_ms'])/1000.0:.2f} s.",
    ], "page-cube prose")
    expect_any([
        f"at 50K rows it gives {kib(float(prefix['median_certificate_bytes']))} certificates, {f2(float(prefix['median_generation_ms']))} ms generation, and {f2(float(prefix['median_verification_ms']))} ms verification",
        f"at 50K rows it gives {kib(float(prefix['median_certificate_bytes']))} median certificates, {f2(float(prefix['median_generation_ms']))} ms generation, and {f2(float(prefix['median_verification_ms']))} ms verification",
    ], "prefix-cube prose")
    expect_any([
        f"with a {float(prefix['median_view_build_ms'])/1000.0:.2f} s view-build cost and {int(float(prefix['median_touched_prefixes_insert']))}-prefix median update footprint",
        f"with a {float(prefix['median_view_build_ms'])/1000.0:.2f} s view build and {int(float(prefix['median_touched_prefixes_insert']))}-prefix median update footprint",
        f"while its {float(prefix['median_view_build_ms'])/1000.0:.2f} s view-build cost and {int(float(prefix['median_touched_prefixes_insert']))}-prefix median update footprint",
    ], "prefix-cube view/update prose")
    expect_any([
        f"A 100K star-schema profile verifies {kib(float(star['median_certificate_bytes']))} prefix certificates in {f2(float(star['median_verification_ms']))} ms.",
        f"A 100K star-schema-style profile over skewed lineorder-like facts verifies {kib(float(star['median_certificate_bytes']))} prefix certificates in {f2(float(star['median_verification_ms']))} ms.",
    ], "star prefix prose")
    for token, label in [
        (f"Policy cube & 50K facts & {kib(float(by_n[50000]['certificate_bytes']))} / {f2(float(by_n[50000]['client_verification_ms']))} ms & {f2(float(by_n[50000]['server_generation_ms']))} ms gen.", "scale-table policy cube"),
        (f"Page cube & 1M facts & {kib(float(page1m['median_certificate_bytes']))} / {f2(float(page1m['median_verify_ms']))} ms & {f2(float(page1m['median_generation_ms']))} ms gen.; {float(page1m['median_build_ms'])/1000.0:.2f} s build", "scale-table page cube"),
        (f"Prefix cube & 50K facts & {kib(float(prefix['median_certificate_bytes']))} / {f2(float(prefix['median_verification_ms']))} ms & {f2(float(prefix['median_generation_ms']))} ms gen.; {float(prefix['median_view_build_ms'])/1000.0:.2f} s build", "scale-table prefix cube"),
        (f"Star prefix & 100K facts & {kib(float(star['median_certificate_bytes']))} / {f2(float(star['median_verification_ms']))} ms & {f2(float(star['median_generation_ms']))} ms gen.", "scale-table star prefix"),
    ]:
        expect(token, label)

# Updates and operator extensions.
upd = [r for r in rows("updates.csv") if int(float(r.get("n", 0))) == 5000]
if upd:
    repair = statistics.median(float(r["incremental_update_ms"]) for r in upd)
    rebuild = statistics.median(float(r["rebuild_update_ms"]) for r in upd)
    path_bytes = statistics.median(float(r["incremental_path_bytes"]) for r in upd)
    expect_any([
        f"at 5K rows, median repair is {f2(repair)} ms versus {f2(rebuild)} ms for full rebuild",
        f"At 5K rows, median repair is {f2(repair)} ms versus {f2(rebuild)} ms for full rebuild.",
    ], "update prose")
    expect(f"Update repair & 5K tree & {int(path_bytes)} B path & {f2(repair)} ms vs. {f2(rebuild)} ms rebuild", "scale-table update row")
struct = {r["operation"]: r for r in rows("structural_updates.csv") if int(float(r.get("n", 0))) == 5000}
if {"insert", "delete", "key_update"}.issubset(struct):
    expect_any([
        f"Insert, delete, and key-update version rebuilds cost {f2(float(struct['insert']['version_update_ms']))} ms, {f2(float(struct['delete']['version_update_ms']))} ms, and {f2(float(struct['key_update']['version_update_ms']))} ms.",
        f"Structural version rebuilding costs {f2(float(struct['insert']['version_update_ms']))} ms for insert, {f2(float(struct['delete']['version_update_ms']))} ms for delete, and {f2(float(struct['key_update']['version_update_ms']))} ms for key update at 5K rows.",
    ], "structural update prose")
ops = {r["operator"]: r for r in rows("operator_contract_medians.csv")}
topk = row_by("topk.csv", "n", "5000")
join = row_by("join.csv", "n", "5000")
fk = row_by("join_complete_medians.csv", "n", "5000")
anti = row_by("join_antijoin.csv", "n", "5000")
mm = row_by("join_many_to_many.csv", "n", "5000")
if ops and topk and join and fk and anti and mm:
    expect_any([
        f"complete range projection and count-distinct are {kib(float(ops['complete_range_projection']['median_certificate_bytes']))}/{f2(float(ops['complete_range_projection']['median_verification_ms']))} ms and {kib(float(ops['count_distinct_customer']['median_certificate_bytes']))}/{f2(float(ops['count_distinct_customer']['median_verification_ms']))} ms",
        f"complete range projection is {kib(float(ops['complete_range_projection']['median_certificate_bytes']))} with {f2(float(ops['complete_range_projection']['median_verification_ms']))} ms verification and count-distinct is {kib(float(ops['count_distinct_customer']['median_certificate_bytes']))} with {f2(float(ops['count_distinct_customer']['median_verification_ms']))} ms verification",
    ], "projection/distinct prose")
    expect_any([
        f"row-local predicate fallback is much larger, {mib(float(ops['open_scan_amount_predicate']['median_certificate_bytes']))} with {f2(float(ops['open_scan_amount_predicate']['median_verification_ms']))} ms verification",
        f"open-scan predicate fallback is {mib(float(ops['open_scan_amount_predicate']['median_certificate_bytes']))} with {f2(float(ops['open_scan_amount_predicate']['median_verification_ms']))} ms verification",
    ], "open scan prose")
    expect_any([
        f"Top-k is {kib(float(topk['certificate_bytes']))}/{f2(float(topk['client_verification_ms']))} ms for $k=20$",
        f"Top-k threshold certificates at 5K rows are {kib(float(topk['certificate_bytes']))} with {f2(float(topk['client_verification_ms']))} ms verification",
    ], "top-k prose")
    expect_any([
        f"returned-pair drill-down joins are {kib(float(join['certificate_bytes']))}/{f2(float(join['client_verification_ms']))} ms",
        f"Returned-pair join-authenticity certificates at 5K rows are {kib(float(join['certificate_bytes']))} with {f2(float(join['client_verification_ms']))} ms verification",
    ], "join prose")
    expect_any([
        f"Complete FK, anti-join, and many-to-many contracts are {kib(float(fk['median_certificate_bytes']))}/{f2(float(fk['median_verification_ms']))} ms, {kib(float(anti['certificate_bytes']))}/{f2(float(anti['client_verification_ms']))} ms, and {kib(float(mm['certificate_bytes']))}/{f2(float(mm['client_verification_ms']))} ms",
        f"Complete FK join certificates are larger, {kib(float(fk['median_certificate_bytes']))} at 5K rows with {f2(float(fk['median_verification_ms']))} ms verification and {int(float(fk['median_opened_sales_count']))} opened facts",
    ], "FK join prose")
    expect_any([
        f"Complete FK, anti-join, and many-to-many contracts are {kib(float(fk['median_certificate_bytes']))}/{f2(float(fk['median_verification_ms']))} ms, {kib(float(anti['certificate_bytes']))}/{f2(float(anti['client_verification_ms']))} ms, and {kib(float(mm['certificate_bytes']))}/{f2(float(mm['client_verification_ms']))} ms",
        f"Complete anti-join certificates are {kib(float(anti['certificate_bytes']))} with {f2(float(anti['client_verification_ms']))} ms verification",
    ], "anti join prose")
    expect_any([
        f"Complete FK, anti-join, and many-to-many contracts are {kib(float(fk['median_certificate_bytes']))}/{f2(float(fk['median_verification_ms']))} ms, {kib(float(anti['certificate_bytes']))}/{f2(float(anti['client_verification_ms']))} ms, and {kib(float(mm['certificate_bytes']))}/{f2(float(mm['client_verification_ms']))} ms",
        f"Complete many-to-many certificates are {kib(float(mm['certificate_bytes']))} with {f2(float(mm['client_verification_ms']))} ms verification",
    ], "many-to-many prose")

# Workload robustness and planner frontier.
profiles = [r for r in rows("workload_profile_medians.csv") if not r["profile"].startswith("public_")]
if profiles:
    by_profile = {r["profile"]: r for r in profiles}
    min_r = min(profiles, key=lambda r: float(r["median_certificate_bytes"]))
    max_r = max(profiles, key=lambda r: float(r["median_certificate_bytes"]))
    dash = by_profile.get("dashboard_sales")
    if dash:
        expect_any([
            f"Compact certificates range from {kib(float(min_r['median_certificate_bytes']))} for finance-audit to {kib(float(max_r['median_certificate_bytes']))} for open-data permits; dashboard sales is {kib(float(dash['median_certificate_bytes']))}",
            f"ranges from {kib(float(min_r['median_certificate_bytes']))} for finance-audit to {kib(float(max_r['median_certificate_bytes']))} for open-data permits; dashboard sales sits in the middle at {kib(float(dash['median_certificate_bytes']))}",
        ], "cross-profile prose")
rob = {r["metric"]: r for r in rows("robustness_summary.csv")}
if "certificate_bytes" in rob and "client_verification_ms" in rob:
    expect_any([
        f"compact certificates have median {kib(float(rob['certificate_bytes']['median']))} and p95 {kib(float(rob['certificate_bytes']['p95']))}, and client verification has median {f2(float(rob['client_verification_ms']['median']))} ms and p95 {f2(float(rob['client_verification_ms']['p95']))} ms",
        f"compact certificates have median {kib(float(rob['certificate_bytes']['median']))} and p95 {kib(float(rob['certificate_bytes']['p95']))}, while client verification has median {f2(float(rob['client_verification_ms']['median']))} ms and p95 {f2(float(rob['client_verification_ms']['p95']))} ms",
    ], "robustness prose")
front = {(r["query_kind"], r["plan"]): r for r in rows("planner_frontier_medians.csv")}
gg = front.get(("governed_groupby", "policy_cube_summary"))
go = front.get(("governed_groupby", "open_range_scan_equivalent"))
if gg and go:
    ratio = round(float(go["median_certificate_bytes"]) / float(gg["median_certificate_bytes"]))
    expect_any([
        f"policy-cube summaries are {kib(float(gg['median_certificate_bytes']))} at the planner-frontier median, while an equivalent open-range scan is {mib(float(go['median_certificate_bytes']))}; both are sound, but the summary is {ratio}x smaller",
        f"policy-cube summaries are {kib(float(gg['median_certificate_bytes']))} at the planner-frontier median, whereas an equivalent open-range scan is {mib(float(go['median_certificate_bytes']))}; both are sound, but the summary is {ratio}x smaller",
    ], "planner frontier prose")

if FAIL:
    print("results consistency failed:", file=sys.stderr)
    for item in FAIL:
        print(f" - {item}", file=sys.stderr)
    sys.exit(1)
print("results consistency passed: manuscript numeric anchors match bundled CSVs")

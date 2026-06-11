# External Data Profiles

This directory contains bundled public CSV files used only for deterministic external-tabular workload profiles.

## Files
- `gapminderDataFiveYear.csv`: Plotly public Gapminder five-year dataset.
- `2014_apple_stock.csv`: Plotly public 2014 Apple stock dataset.

## Mapping
The prototype maps each CSV into the common governed-row schema used by the verifier. Gapminder country-year rows are mapped to continent/region/category, year/range, GDP-derived amount, population/sensitivity, and country/customer identifiers. Apple stock rows are mapped to date/range, month/category, price/amount, and sensitivity derived from price movement.

The verifier, manifest compiler, range covers, policy binding, and group-by checks are unchanged for these public profiles; only the row source changes. The files are bundled so the artifact can be reproduced without network access.

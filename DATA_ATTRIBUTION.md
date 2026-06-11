# Bundled External Data Attribution

The artifact includes two small public CSV profiles used only to test that the same governed-row mapping and verifier run on externally sourced tabular data rather than only on synthetic rows.

- Gapminder five-year data: Plotly datasets repository, `gapminderDataFiveYear.csv`
  (`https://raw.githubusercontent.com/plotly/datasets/0c447c47b757ad74edecab31f0d72f849d2e67c2/gapminderDataFiveYear.csv`),
  repository commit `0c447c47b757ad74edecab31f0d72f849d2e67c2`, accessed 2026-06-09.
- 2014 Apple stock data: Plotly datasets repository, `2014_apple_stock.csv`
  (`https://raw.githubusercontent.com/plotly/datasets/0c447c47b757ad74edecab31f0d72f849d2e67c2/2014_apple_stock.csv`),
  repository commit `0c447c47b757ad74edecab31f0d72f849d2e67c2`, accessed 2026-06-09.

The paper reports these as external-tabular profiles, not as production governed-data traces. The deterministic mapping converts each CSV row into the same governed-row schema used by the verifier.

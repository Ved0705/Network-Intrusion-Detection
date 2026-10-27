# Building the Power BI dashboard

Power BI Desktop is the display layer. Python (Pandas) does the analysis and writes CSV files into
`exports/`. You import those CSVs into Power BI Desktop and build three report pages.
No `.pbix` file is supplied; you create it with these steps (about 30–40 minutes the first time).

## 1. Generate the CSV files

```powershell
python src\export_data.py
```

This writes into `exports/`:

| File | One row per | Use it for |
|---|---|---|
| `cleaned_dataset.csv` | connection record (train + test) | **Main table**: KPIs, slicers, any chart that needs filtering |
| `normal_vs_attack.csv` | source × traffic type | Donut chart |
| `attack_distribution.csv` | source × attack label | Attack label bar chart |
| `attack_family_summary.csv` | source × attack family | Family chart |
| `protocol_summary.csv` | source × protocol | Protocol usage |
| `service_summary.csv` | source × service | Service usage |
| `flag_summary.csv` | source × flag | Flag chart |
| `protocol_attack_summary.csv` | source × protocol × family | Attacks by protocol |
| `service_attack_summary.csv` | source × service × family | Attacks by service |
| `numeric_feature_summary.csv` | source × traffic type × feature | Statistics table |
| `data_quality_report.csv` | source | Missing values, duplicates, rows removed |

Every file has a **`dataset_source`** column (`train` or `test`).

### Avoiding misleading totals (read this)

- **Train and test are both in each file.** Without a filter Power BI adds them together (148,517 rows),
  which mixes two different samples. Always add a **`dataset_source` slicer set to single select**, or
  filter each page to one source.
- **Summary files are already aggregated.** Don't add them together or relate them to the main table.
  Use `cleaned_dataset` when visuals must respond to slicers; use summary files for fixed aggregate charts.
- Percentages in summary files are pre-calculated per source. In visuals use **Don't summarize** or
  **Average** for percentage columns, never **Sum**.

## 2. Import the files

1. Open Power BI Desktop → **Home → Get data → Text/CSV**.
2. Select `exports\cleaned_dataset.csv`. Check *File origin* = **65001: Unicode (UTF-8)** and
   *Delimiter* = **Comma**, then click **Load**. The table is called `cleaned_dataset`.
3. Repeat for the summary files you want (at least `attack_distribution`, `protocol_attack_summary`,
   `service_attack_summary`, `numeric_feature_summary`).
4. **Model view**: delete any relationships Power BI created automatically between tables. This design
   uses `cleaned_dataset` as the single main table and stand-alone summary tables, so no relationships are needed.
5. **Data view → cleaned_dataset**: make sure `protocol_type`, `service`, `flag`, `label`,
   `attack_family`, `traffic_type`, `dataset_source` are **Text** and the byte/count/rate columns are numbers.

## 3. Add DAX measures

Select `cleaned_dataset`, then **Modeling → New measure**, and paste each measure from `dax_measures.dax`:
Total Connections, Normal Connections, Attack Connections, Attack Percentage (format as %),
Distinct Attack Labels.

## 4. Slicers (add to every page)

Slicer fields from `cleaned_dataset`: **dataset_source** (single select), **attack_family**, **label**
(attack label), **protocol_type**, **service**, **flag**. To share them across pages: **View → Sync slicers**.

Slicers filter only visuals built on `cleaned_dataset`. Summary-table visuals respond only if you add a
`dataset_source` slicer from that same table, or a page-level filter on `dataset_source`.

## 5. Page 1: Security Overview

| Visual | Fields (table `cleaned_dataset`) | What it tells you |
|---|---|---|
| 4 × **Card** | Total Connections, Normal Connections, Attack Connections, Attack Percentage | Size of the data and how much of it is malicious |
| **Card** | Distinct Attack Labels | How many different attack types appear (22 in train, 37 in test) |
| **Donut chart** | Legend `traffic_type`, Values `Total Connections` | Balance between normal and attack records |
| **Clustered bar chart** | Y `attack_family`, X `Attack Connections`; filter out `Normal` | Which attack family dominates (DoS in this dataset) |
| **Bar chart** | Y `label`, X `Attack Connections`, Top N = 10 by Attack Connections; filter `traffic_type = Attack` | The most frequent individual attacks (neptune leads) |

Colours: Normal green `#34D399`, Attack red `#FB6A5A`.

## 6. Page 2: Attack Analysis

| Visual | Fields | What it tells you |
|---|---|---|
| **Bar chart** | Y `label`, X `Attack Connections`, Legend `attack_family` | Counts for every attack label, grouped by family |
| **Donut chart** | Legend `attack_family`, Values `Attack Connections` | Family shares of all attacks |
| **Stacked column chart** | X `protocol_type`, Y `Attack Connections`, Legend `attack_family` | Which protocols carry which attack families |
| **Bar chart** | Y `service`, X `Attack Connections`, Top N = 15 | Services that appear most often in attack records |
| **Stacked column chart** | X `flag`, Y `Total Connections`, Legend `traffic_type` | Connection status flags for normal vs attack (S0 is common among attacks) |
| **Table** (optional) | `attack_distribution`: attack_label, attack_family, connections, percentage_of_attacks | Exact numbers to quote |

Note: a high attack count for a service reflects this dataset's collection, not proof that the service is vulnerable.

## 7. Page 3: Traffic Analysis

| Visual | Fields | What it tells you |
|---|---|---|
| **100% stacked column** | X `protocol_type`, Y `Total Connections`, Legend `traffic_type` | Share of attacks within each protocol |
| **Bar chart** | Y `service`, X `Total Connections`, Top N = 15 | Overall service usage |
| **Column chart** | X `duration` (create bins: right-click column → New group → Bin size 100), Y `Total Connections` | Duration distribution; most connections last 0 s |
| **Scatter chart** | X `src_bytes`, Y `dst_bytes`, Legend `traffic_type`, Don't summarize; set both axes to **Log** scale | How data volume differs between normal and attack records (zero values are hidden on log axes) |
| **Table / Matrix** | `numeric_feature_summary`: filter `traffic_type`; show feature, mean, median, max, zero_percentage | Statistics for each numeric feature |

Tip: for the scatter chart, a large table can be slow; Power BI samples points automatically.

## 8. Refreshing after new exports

1. Run `python src\export_data.py` again; it overwrites the files in `exports/` with the same names.
2. In Power BI Desktop click **Home → Refresh**.
3. If you moved the project folder: **Transform data → Data source settings → Change source**, point to the new path.

Save your report as `powerbi\NetworkTrafficDashboard.pbix`.

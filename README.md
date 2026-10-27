# AI-Powered Network Traffic Analysis Using PandasAI and Power BI

A data analytics project on the **NSL-KDD** network intrusion dataset:

- **Pandas** loads, cleans and analyses the data, then writes CSV files.
- **PandasAI** lets you ask questions about the data in plain English (optional, needs an LLM API key).
- **Power BI Desktop** displays the CSV files as an interactive dashboard.

```
KDDTrain+.txt / KDDTest+.txt ──► Pandas (src/) ──► exports/*.csv ──► Power BI Desktop
                                       │
                                       └──► PandasAI (questions in English, checked against Pandas)
```

This is descriptive analytics only: no machine learning, no prediction, no live traffic monitoring.
NSL-KDD contains no IP addresses or timestamps, and none are invented.

## Project structure

```
network-security-analysis/
  data/            KDDTrain+.txt, KDDTest+.txt, README.md
  exports/         generated CSV files for Power BI
  src/
    data_loader.py        load files, apply column names, clean, derive traffic_type / attack_family
    analysis.py           all counts, percentages and summaries
    export_data.py        writes the CSV files (run this)
    pandasai_analysis.py  natural-language questions with PandasAI
    safety.py             restrictions on PandasAI-generated code
    attack_families.json  attack label → family mapping (editable)
  notebooks/network_security_analysis.ipynb   full walkthrough (Jupyter or Colab)
  powerbi/         README.md (dashboard guide), dax_measures.dax
  tests/           automated tests (synthetic data only)
  requirements.txt, requirements-pandasai.txt, .env.example, .gitignore
```

## 1. Install Python (or use Google Colab)

**Windows:** install **Python 3.11** from https://www.python.org/downloads/ and tick
*Add python.exe to PATH*. Use 3.11 specifically: PandasAI 3 does not install on Python 3.12 or newer.

**Google Colab:** upload the whole `network-security-analysis` folder to Google Drive
(`MyDrive/network-security-analysis`), open the notebook in Colab, and run the first cell.
It mounts Drive. The Pandas analysis and exports work in Colab. PandasAI usually does **not** install
there, because Colab runs Python 3.12; run the PandasAI part locally with Python 3.11.

## 2. Dataset files

`data\KDDTrain+.txt` and `data\KDDTest+.txt` are already included (see `data/README.md`). If you replace
them, keep these exact names. The files have no header row; the code applies the standard column names.

## 3. Install packages

Open PowerShell in the project folder:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-pandasai.txt     # only needed for PandasAI
```

## 4. Configure PandasAI (optional)

1. Copy `.env.example` to `.env`.
2. Set a model and its key, for example:
   ```ini
   PANDASAI_LLM_MODEL=gpt-4o-mini
   OPENAI_API_KEY=sk-...
   ```
   Other options: `gemini/gemini-3.8-flash` + `GEMINI_API_KEY`, `anthropic/claude-sonnet-4-5` +
   `ANTHROPIC_API_KEY`, `groq/openai/gpt-oss-120b` + `GROQ_API_KEY`, or `ollama/llama3.1` (local, no key).
3. Keys are read from `.env` only; they are never written in the code.

**What is sent to the LLM provider:** your question, the column names and types, the table size, and the
**first 5 rows** of the dataset. The full dataset stays on your computer, and the SQL the LLM writes runs locally.
Do not use an external provider with confidential data; use a local Ollama model instead.

**Safety:** you type only questions, never code. The code PandasAI generates is checked before it runs
(`src/safety.py`): only SELECT queries; no file, network or system access; and an answer that does not
actually query the data is rejected. Every PandasAI answer is labelled as PandasAI and, for the standard
questions, compared with the Pandas result (`MATCH` / `MISMATCH`).

Without a key, everything else works; the scripts show the deterministic Pandas answers instead.

## 5. Run the analysis

- **Notebook (recommended for presentations):**
  ```powershell
  jupyter notebook notebooks\network_security_analysis.ipynb
  ```
  Run all cells. It shows shape, columns, data types, sample rows, missing values and duplicates, then
  normal vs attack, families, labels, protocols, services, flags, distributions, statistics, exports and PandasAI.
- **Ask questions in the terminal:**
  ```powershell
  python src\pandasai_analysis.py train      # or: test
  ```

## 6. Generate the CSV exports

```powershell
python src\export_data.py                   # both train and test
python src\export_data.py --sources train   # only one
```

Files are written to **`exports\`**: `cleaned_dataset.csv`, `normal_vs_attack.csv`,
`attack_distribution.csv`, `attack_family_summary.csv`, `protocol_summary.csv`, `service_summary.csv`,
`flag_summary.csv`, `protocol_attack_summary.csv`, `service_attack_summary.csv`,
`numeric_feature_summary.csv`, plus `data_quality_report.csv`. Every file has a `dataset_source` column.
Train and test are summarised separately, never added together.

## 7–8. Build and refresh the Power BI dashboard

Follow **`powerbi/README.md`**. It covers import, using `cleaned_dataset` as the main table, the DAX
measures, slicers, the three report pages, what each visual shows, and how to refresh after re-running
`export_data.py`.

## Definitions

- `traffic_type`: **Normal** if label is `normal`, otherwise **Attack**. `is_attack` is the same as 1/0.
- `attack_family`: from `src/attack_families.json`:
  - **DoS**: apache2, back, land, mailbomb, neptune, pod, processtable, smurf, teardrop, udpstorm, worm
  - **Probe**: ipsweep, mscan, nmap, portsweep, saint, satan
  - **R2L**: ftp_write, guess_passwd, imap, multihop, named, phf, sendmail, snmpgetattack, snmpguess, spy, warezclient, warezmaster, xlock, xsnoop
  - **U2R**: buffer_overflow, httptunnel, loadmodule, perl, ps, rootkit, sqlattack, xterm
  - Any other attack label becomes **Unknown** (never Normal) and is listed in `data_quality_report.csv`.
- Labels are trimmed and lower-cased; if that changes a value, the original is kept in `original_label`.
- Rows with missing or non-numeric required values are removed and counted in the quality report.
  Duplicates are counted but kept.

## Results on the included files

| | Train | Test |
|---|---|---|
| Connections | 125,973 | 22,544 |
| Normal | 67,343 | 9,711 |
| Attack | 58,630 (46.54%) | 12,833 (56.92%) |
| Distinct attack labels | 22 | 37 |
| Missing values / duplicates / rows removed | 0 / 0 / 0 | 0 / 0 / 0 |

## Tests

```powershell
python -m pytest -q
```

14 tests on small synthetic data: column handling, record counts, normal/attack split, family mapping,
Unknown labels, label normalisation, missing-value handling, aggregation accuracy, export files and
columns, missing-file message, Pandas cross-checks, missing credentials, and the PandasAI pipeline with a
stub model (correct answer accepted; invented number and file access rejected).

## PandasAI web chat (Streamlit)

A small chat page for PandasAI, using the same code as the terminal version (`src/pandasai_analysis.py`).

```powershell
pip install -r requirements-pandasai.txt      # includes streamlit
streamlit run app\streamlit_app.py
```

It opens http://localhost:8501. Choose train or test in the sidebar, then type a question or click an
example. Each answer shows the model used, the result, the Pandas check (MATCH / MISMATCH) and the SQL that
ran locally. Stop it with Ctrl+C in the terminal.

The terminal version still works on its own: `python src\pandasai_analysis.py train`.

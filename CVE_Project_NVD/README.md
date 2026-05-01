# CVE_Project_NVD

Install the **workspace-root** editable package (the folder that **contains** `CVE_Project_NVD/`, `shared_utils/`, and `pyproject.toml` — e.g. Bacongris repo root or your `All_Scripts` copy):

```bash
cd /path/to/workspace_root
pip install -e .
```

Then from **this** directory:

```bash
cd CVE_Project_NVD
python3 main.py
```

This downloads `nvdcve-2.0-*.json.gz` into `NVD_CVE/`, upserts into `../cti_vault.db`, and exports `csv_output/nvd_from_vault.csv` from SQLite (DB is source of truth).

- `python3 main.py --skip-download` — parse existing gz files only (no HTTP).
- Prefer **`pip install -e .` at workspace root** over ad hoc `PYTHONPATH` so `import shared_utils` works from any `cwd`.

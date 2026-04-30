# CVE_Project_NVD

Requires the workspace root package (from Bacongris `cti_vault_bootstrap/ copied to your All_Scripts parent):

```bash
cd /path/to/All_Scripts
pip install -e .
```

Then from this directory or repo root: `python3 main.py` ingests to `../cti_vault.db` and exports `csv_output/nvd_from_vault.csv` from the database.

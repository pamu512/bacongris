# ASM-fetch-main

Scans produce rows that upsert into **`cti_vault.db`** (`asm_assets`), then **`asm_from_vault.csv`** is exported with an **atomic rename** (see `shared_utils/csv_export.py`).

## Host run

```bash
cd /path/to/workspace_root
pip install -e .
python3 ASM-fetch-main/scan_vault.py
```

Set **`CTI_VAULT_PATH`** to an absolute DB path if the vault is not at `<workspace_root>/cti_vault.db`.

## Docker

Merge **`docker-compose.vault.yml`** into your compose file. The service mounts the **monorepo parent** as `/workspace` so `cti_vault.db` is shared with host Python jobs.

On **Linux**, set **`user: "${UID:-1000}:${GID:-1000}"`** so the DB file is not root-owned on the bind mount.

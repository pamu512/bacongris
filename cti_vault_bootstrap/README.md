# CTI vault (`cti_vault_bootstrap`)

**Canonical package in a full Bacongris clone:** use the **repository root** `pyproject.toml` + `shared_utils/` + `tests/` (same layout as this folder’s Python tree — they are kept in sync in git). Prefer **`pip install -e .` from the repo root** when developing here.

**Bacongris app:** When you set a workspace that contains `pyproject.toml` at the root (this package or the repo root copy), the host runs **`pip install -e .` inside every top-level folder that has a `.venv`** once per workspace path, so `import shared_utils` works from each project venv. If the root has no `pyproject.toml`, binding is skipped until you add it.

**Multi-process:** WAL + `busy_timeout=30s` on all connections. Use one `CTIVault` (or `open_cti_vault()` per short task) per **process**; Celery workers get a fresh `open_cti_vault` context so connections are not held across tasks.

Copy **`pyproject.toml`**, **`shared_utils/`**, and **`tests/`** from the **repo root** (or this entire folder) onto your **All_Scripts** (or other CTI) **workspace root** as the installable `shared_utils` package.

## Install (each project venv)

```bash
cd /path/to/All_Scripts
pip install -e .
```

Then `import shared_utils.db_manager` works from `CVE_Project_NVD/`, `IOCs-crawler-main/`, etc.

## Database path

- Default: `<workspace_root>/cti_vault.db`
- Override: set `CTI_VAULT_PATH` to an absolute path (used by Docker and one-off scripts).

## Usage

```python
from pathlib import Path
from shared_utils.db_manager import CTIVault

vault = CTIVault(workspace_root=Path("/path/to/All_Scripts"))
vault.init_schema()
vault.upsert_cve_row(cve_id="CVE-2024-0001", description="…")
vault.export_cve_csv(Path("CVE_Project_NVD/output_result/export.csv"))  # example
```

- **Pipelines:** `from shared_utils.cti_pipelines import run_cve_nvd_update_export, push_ioc_to_vault, run_asm_export`
- **CSV freshness:** `vault.check_sync(csv_path, domain="cve"|"ioc"|"asm")` → `CsvSyncResult.csv_is_stale` is True when `MAX(updated_at)` (or IOC `last_seen` / ASM `last_scan_at`) is newer than the CSV’s file mtime (re-export needed).
- **WAL:** `upsert_cve_batch(..., wal_checkpoint_after=True)` (default) runs `PRAGMA wal_checkpoint(PASSIVE)` after large batch commits. Call `vault.wal_checkpoint("PASSIVE" | "FULL" | ...)` after other big imports to limit `cti_vault.db-wal` growth.
- **Docker (ASM):** merge `docker-compose.asm.snippet.yml` into your compose file (bind mount + `CTI_VAULT_PATH` + `user` on Linux).
- **Wiring:** see `WIRING.md`

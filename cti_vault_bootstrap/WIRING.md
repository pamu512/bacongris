# Wiring `shared_utils` into your All_Scripts tree

The folders `CVE_Project_NVD/`, `IOCs-crawler-main/`, and `ASM-fetch-main/` are **not** in the Bacongris application repository. After copying `cti_vault_bootstrap/` to your **workspace root** (or merging `pyproject.toml` + `shared_utils/`), use the steps below.

## One-time: editable install in each venv

```bash
cd /path/to/All_Scripts
pip install -e .
```

Repeat in `CVE_Project_NVD/.venv`, the Celery worker venv, and any Docker image that runs Python (or set `PYTHONPATH` to the mounted workspace root).

## CVE_Project_NVD

1. In `main.py` (or the module that writes `output_result/` / `csv_output/`), after you build the list of CVE dicts, call:

   ```python
   from pathlib import Path
   from shared_utils.db_manager import CTIVault
   from shared_utils.cti_pipelines import run_cve_nvd_update_export

   REPO = Path(__file__).resolve().parents[1]  # All_Scripts
   vault = CTIVault(workspace_root=REPO)
   vault.init_schema()
   run_cve_nvd_update_export(
       vault,
       parsed_rows,
       csv_path=REPO / "CVE_Project_NVD" / "output_result" / "nvd_export.csv",  # adjust
   )
   ```

2. Keep your existing “Update” / stdin `update` flow; add the calls **after** fetch/parse, **before** the UI moves on. CSV on disk is regenerated from the DB by `run_cve_nvd_update_export`.

## IOCs-crawler (Celery)

In the task that finalizes a parsed IOC (next to the RethinkDB write), add:

```python
from shared_utils.db_manager import CTIVault
from shared_utils.cti_pipelines import push_ioc_to_vault

# Cache vault per process if desired
vault = CTIVault(workspace_root=ALL_SCRIPTS_PATH)
vault.init_schema()
try:
    push_ioc_to_vault(vault, ioc_value=ind, ioc_type=typ, metadata={...})
except Exception as e:
    logger.error("cti_vault: %s", e)
```

Use a **new short transaction per IOC**; do not keep the connection open around RethinkDB calls (open vault per task or use the shared `CTIVault` connection with WAL; avoid nested long work inside `upsert`).

## ASM-fetch (Docker)

1. Copy fields from `docker-compose.asm.snippet.yml` into your `docker-compose`: bind-mount the workspace, set `CTI_VAULT_PATH=/workspace/cti_vault.db`, and on Linux `user: "${UID}:${GID}"` so the host can open the same DB.
2. After a scan, build a list of asset dicts and call `run_asm_export` from `shared_utils.cti_pipelines` with your existing CSV path.

## Where the files live in Bacongris

- Shipped in-repo under `cti_vault_bootstrap/` in the Bacongris repository for copy/paste or future “copy into workspace” automation.

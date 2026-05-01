# IOCs-crawler-main (Celery + vault)

After **`pip install -e .`** at the **workspace root** (folder that contains `shared_utils/` and this directory), each Celery worker process can persist IOCs into the shared **`cti_vault.db`** without holding SQLite across RethinkDB I/O.

## Pattern

1. Finish your existing RethinkDB / pipeline write **first**.
2. Call **`ioc_persist_from_task`** from **`ioc_celery_vault.py`** in a `try`/`except` so vault failures do not fail the primary ingest.

```python
from pathlib import Path
from ioc_celery_vault import ioc_persist_from_task

WORKSPACE = Path(__file__).resolve().parent.parent  # All_Scripts root

@app.task(bind=True, max_retries=3)
def finalize_ioc(self, ioc_value: str, ioc_type: str, **meta):
    # ... rethink insert / business logic ...
    ok = ioc_persist_from_task(
        ioc_value,
        ioc_type,
        meta,
        workspace_root=WORKSPACE,
    )
    if not ok:
        self.retry(countdown=5)  # optional: WAL busy
```

3. Use **`open_cti_vault`** from **`shared_utils.db_manager`** inside short scopes (already wrapped in **`ioc_persist_from_task`**) so workers do not keep idle connections forever.

## Concurrency

`CTIVault` enables **WAL** and **`busy_timeout`** (see `shared_utils/db_manager.py`). Use **one upsert per short connection scope** per task; avoid transactions that span network calls.

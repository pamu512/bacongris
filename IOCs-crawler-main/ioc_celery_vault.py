"""
Drop-in pattern for a Celery task: open vault per task, try/except around writes, no stale handle.

    from ioc_celery_vault import ioc_persist_from_task

    @app.task
    def after_ioc_ingest(ioc_value: str, ioc_type: str, **meta) -> None:
        ioc_persist_from_task(ioc_value, ioc_type, meta, workspace_root=Path("/path/to/All_Scripts"))
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from shared_utils.db_manager import open_cti_vault

log = logging.getLogger(__name__)

_DEFAULT_ROOT = Path(__file__).resolve().parent.parent


def ioc_persist_from_task(
    ioc_value: str,
    ioc_type: str,
    extra: Mapping[str, Any] | None = None,
    *,
    workspace_root: Path | None = None,
) -> bool:
    """
    Returns True on success, False on vault error (RethinkDB or other work should
    have already completed elsewhere).
    """
    root = workspace_root or _DEFAULT_ROOT
    try:
        with open_cti_vault(workspace_root=root) as vault:
            vault.upsert_ioc_row(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source_project="IOCs-crawler-main",
                metadata=dict(extra) if extra else None,
            )
    except (OSError, sqlite3.Error) as e:
        log.exception("cti_vault IOC upsert failed: %s", e)
        return False
    return True

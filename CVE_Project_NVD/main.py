#!/usr/bin/env python3
"""
CVE / NVD ingest: write to workspace `cti_vault.db` first, then export CSV from the DB.

Install once at the All_Scripts root:  pip install -e .
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterator, Mapping

from shared_utils.db_manager import CTIVault

log = logging.getLogger(__name__)

# Workspace root = parent of this project folder (…/All_Scripts)
_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
_CSV_DIR = Path(__file__).resolve().parent / "csv_output"
_CSV_OUT = _CSV_DIR / "nvd_from_vault.csv"


def _iter_nvd_records() -> Iterator[Mapping[str, Any]]:
    """
    Replace with your real NVD API / file parse loop. Each dict should include at least
    `cve_id`; optional: published, last_modified, description, cvss, metadata (dict or str).
    """
    # Placeholder so the pipeline runs; remove when wiring real data.
    yield {
        "cve_id": "CVE-PLACEHOLDER-0001",
        "description": "Replace _iter_nvd_records with your NVD feed.",
    }


def run_ingest_and_export_csv() -> None:
    vault = CTIVault(workspace_root=_WORKSPACE_ROOT)
    vault.init_schema()
    for row in _iter_nvd_records():
        cve_id = str(row.get("cve_id") or row.get("id") or "").strip()
        if not cve_id:
            continue
        vault.upsert_cve_row(
            cve_id=cve_id,
            published=row.get("published") if isinstance(row.get("published"), str) else None,
            last_modified=row.get("last_modified") if isinstance(row.get("last_modified"), str) else None,
            description=row.get("description") if isinstance(row.get("description"), str) else None,
            cvss=row.get("cvss") if isinstance(row.get("cvss"), str) else None,
            metadata=row.get("metadata") if isinstance(row.get("metadata"), dict) else None,
        )
    _CSV_DIR.mkdir(parents=True, exist_ok=True)
    vault.export_cve_csv(_CSV_OUT)
    log.info("Exported CSV from vault: %s", _CSV_OUT)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_ingest_and_export_csv()

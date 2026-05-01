#!/usr/bin/env python3
"""
CVE / NVD: download feeds → upsert ``cti_vault.db`` → export ``csv_output/nvd_from_vault.csv`` from the DB.

Install at the **workspace root** (parent of ``CVE_Project_NVD``):

    pip install -e .

Then from this directory::

    python3 main.py
    python3 main.py --skip-download   # parse existing ``NVD_CVE/nvdcve-2.0-*.json.gz`` only
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

from NVD_CVE.update_nvd_feeds import Update_NVD
from shared_utils.db_manager import CTIVault
from shared_utils.nvd_feed_parse import iter_cve_rows_from_feed_dir

log = logging.getLogger(__name__)

_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
_NVD_DIR = Path(__file__).resolve().parent / "NVD_CVE"
_CSV_DIR = Path(__file__).resolve().parent / "csv_output"
_CSV_OUT = _CSV_DIR / "nvd_from_vault.csv"

_BATCH = 2_000


def run_ingest_and_export_csv(*, skip_download: bool = False) -> None:
    _NVD_DIR.mkdir(parents=True, exist_ok=True)
    if not skip_download:
        log.info("Downloading NVD JSON feeds into %s", _NVD_DIR)
        Update_NVD(output_dir=_NVD_DIR)

    vault = CTIVault(workspace_root=_WORKSPACE_ROOT)
    vault.init_schema()

    batch: list[dict] = []
    total = 0
    for row in iter_cve_rows_from_feed_dir(_NVD_DIR):
        batch.append(dict(row))
        if len(batch) >= _BATCH:
            vault.upsert_cve_batch(batch, source_project="CVE_Project_NVD", wal_checkpoint_after=False)
            total += len(batch)
            batch.clear()
    if batch:
        vault.upsert_cve_batch(batch, source_project="CVE_Project_NVD", wal_checkpoint_after=True)
        total += len(batch)
    elif total == 0:
        log.warning(
            "No rows ingested (no ``%s`` under %s). Run without --skip-download or place feed files.",
            "nvdcve-2.0-*.json.gz",
            _NVD_DIR,
        )
        vault.wal_checkpoint("PASSIVE")
    else:
        vault.wal_checkpoint("PASSIVE")

    _CSV_DIR.mkdir(parents=True, exist_ok=True)
    vault.export_cve_csv(_CSV_OUT)
    log.info("Upserted %s CVE rows; exported CSV from vault: %s", total, _CSV_OUT)


def main() -> None:
    p = argparse.ArgumentParser(description="NVD feeds → cti_vault.db → CSV export.")
    p.add_argument(
        "--skip-download",
        action="store_true",
        help="Do not fetch feeds; only parse existing nvdcve-2.0-*.json.gz under NVD_CVE/.",
    )
    args = p.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    run_ingest_and_export_csv(skip_download=args.skip_download)


if __name__ == "__main__":
    main()

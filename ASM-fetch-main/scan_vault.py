#!/usr/bin/env python3
"""
ASM scan → cti_vault.db, then atomic CSV export.

In Docker, set CTI_VAULT_PATH=/workspace/cti_vault.db (see docker-compose.vault.yml).
Default when unset: workspace root `cti_vault.db` (parent of ASM-fetch-main).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from shared_utils.cti_pipelines import run_asm_export
from shared_utils.db_manager import CTIVault

log = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
# All_Scripts/ (parent of ASM-fetch-main)
_WORKSPACE_ROOT = HERE.parent
_DEFAULT_DB = str(_WORKSPACE_ROOT / "cti_vault.db")
_CSV_OUT = HERE / "csv_output" / "asm_from_vault.csv"


def _vault() -> CTIVault:
    path = os.getenv("CTI_VAULT_PATH", _DEFAULT_DB).strip()
    return CTIVault(db_path=Path(path).resolve())


def run_scan_to_vault(assets: list[dict]) -> None:
    v = _vault()
    v.init_schema()
    _CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    run_asm_export(
        v,
        assets=assets,
        csv_path=_CSV_OUT,
    )
    log.info("ASM snapshot exported: %s", _CSV_OUT)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_scan_to_vault(
        [
            {
                "target": "example.com",
                "port": 443,
                "protocol": "tcp",
            }
        ],
    )

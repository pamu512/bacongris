"""
High-level wiring helpers for CVE, IOC, and ASM projects (import after `pip install -e` at workspace root).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from shared_utils.db_manager import CTIVault


def run_cve_nvd_update_export(
    vault: CTIVault,
    rows: Sequence[Mapping[str, Any]],
    *,
    csv_path: Path,
    source_project: str = "CVE_Project_NVD",
) -> None:
    if rows:
        vault.upsert_cve_batch(list(rows), source_project=source_project)
    vault.export_cve_csv(csv_path)


def push_ioc_to_vault(
    vault: CTIVault,
    *,
    ioc_value: str,
    ioc_type: str,
    metadata: Mapping[str, Any] | None = None,
    source_project: str = "IOCs-crawler-main",
) -> None:
    vault.upsert_ioc_row(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        source_project=source_project,
        metadata=metadata,
    )


def asset_key_for(target: str, port: int | None, protocol: str | None) -> str:
    p = port if port is not None else 0
    pr = (protocol or "").strip().lower() or "default"
    return f"{target.strip().lower()}:{p}:{pr}"


def run_asm_export(
    vault: CTIVault,
    *,
    assets: Sequence[Mapping[str, Any]],
    csv_path: Path,
    source_project: str = "ASM-fetch-main",
) -> None:
    for a in assets:
        k = str(
            a.get("asset_key")
            or asset_key_for(
                str(a.get("asset_target") or a.get("target") or ""),
                _opt_int(a.get("port")),
                _str(a.get("protocol")),
            )
        )
        t = str(a.get("asset_target") or a.get("target") or "")
        if not t:
            continue
        meta = a.get("metadata")
        vault.upsert_asm_asset(
            asset_key=k,
            asset_target=t,
            port=_opt_int(a.get("port")),
            protocol=_str(a.get("protocol")),
            last_scan_at=_str(a.get("last_scan_at")),
            source_project=source_project,
            metadata=meta if isinstance(meta, dict) else None,
        )
    vault.export_asm_csv(csv_path)


def _opt_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None

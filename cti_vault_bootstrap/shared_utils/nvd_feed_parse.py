"""
Parse NVD CVE JSON 2.0 feeds (``nvdcve-2.0-*.json.gz``) into row dicts for ``CTIVault.upsert_cve_batch``.

Supports the modern ``vulnerabilities`` array and legacy ``CVE_Items`` (MITRE 4.0-style blocks).
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any, Iterator, Mapping

NVD_FEED_GLOB = "nvdcve-2.0-*.json.gz"


def _norm_ts(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _cve_id(cve: dict[str, Any]) -> str | None:
    cid = cve.get("id")
    if isinstance(cid, str) and "CVE-" in cid.upper():
        return cid.strip().upper()
    meta = cve.get("CVE_data_meta") or {}
    cid = meta.get("ID")
    if isinstance(cid, str) and cid.strip():
        return cid.strip().upper()
    return None


def _first_en_description(cve: dict[str, Any]) -> str | None:
    for block in cve.get("descriptions") or []:
        if not isinstance(block, dict):
            continue
        if str(block.get("lang", "")).lower() in ("en", "eng", ""):
            val = block.get("value")
            if isinstance(val, str) and val.strip():
                return val.strip()
    desc = cve.get("description")
    if isinstance(desc, dict):
        for block in desc.get("description_data") or []:
            if isinstance(block, dict):
                val = block.get("value")
                if isinstance(val, str) and val.strip():
                    return val.strip()
    return None


def _published_last_modified(cve: dict[str, Any]) -> tuple[str | None, str | None]:
    pub = (
        cve.get("published")
        or cve.get("publishedDate")
        or (cve.get("CVE_data_meta") or {}).get("DATE_PUBLIC")
    )
    lm = (
        cve.get("lastModified")
        or cve.get("last_modified")
        or cve.get("lastModifiedDate")
    )
    return (_norm_ts(pub), _norm_ts(lm))


def _metrics_blob(cve: dict[str, Any]) -> str | None:
    m = cve.get("metrics")
    if not isinstance(m, dict) or not m:
        return None
    try:
        return json.dumps(m, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return None


def iter_cve_dicts_from_nvd_root(data: dict[str, Any]) -> Iterator[Mapping[str, Any]]:
    items = data.get("vulnerabilities")
    if not items and "CVE_Items" in data:
        items = data["CVE_Items"]
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, dict):
            cve = item
        cve_id = _cve_id(cve)
        if not cve_id:
            continue
        published, last_modified = _published_last_modified(cve)
        yield {
            "cve_id": cve_id,
            "published": published,
            "last_modified": last_modified,
            "description": _first_en_description(cve),
            "cvss": _metrics_blob(cve),
        }


def iter_cve_rows_from_gzip(path: Path) -> Iterator[Mapping[str, Any]]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        yield from iter_cve_dicts_from_nvd_root(data)


def iter_cve_rows_from_feed_dir(feed_dir: Path) -> Iterator[Mapping[str, Any]]:
    """Yield every CVE row from each ``nvdcve-2.0-*.json.gz`` under ``feed_dir`` (sorted)."""
    for gz in sorted(feed_dir.glob(NVD_FEED_GLOB)):
        yield from iter_cve_rows_from_gzip(gz)

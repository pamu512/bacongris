"""
Download NVD CVE 2.0 JSON.gz feeds with retries (ChunkedEncodingError / IncompleteRead).

Merge this file into your workspace copy under ``CVE_Project_NVD/NVD_CVE/`` if you maintain
``main.py`` / ``Update_NVD()`` separately.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Iterable

import requests
from requests.exceptions import ChunkedEncodingError, ConnectionError, Timeout
from urllib3.exceptions import ProtocolError

log = logging.getLogger(__name__)

# NVD JSON 2.0 feed base (official)
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"

# Sensible defaults; extend with e.g. ``nvdcve-2.0-2024`` for full year pulls
DEFAULT_FEEDS: tuple[str, ...] = (
    "nvdcve-2.0-modified",
    "nvdcve-2.0-recent",
)


def download_file(
    url: str,
    filename: str | Path,
    *,
    retries: int = 5,
    backoff_factor: float = 2.0,
    connect_timeout: float = 30.0,
    read_timeout: float = 600.0,
    chunk_size: int = 8192,
) -> None:
    """
    Stream ``url`` to ``filename`` with retries on broken chunked streams.

    Uses ``(connect_timeout, read_timeout)`` — large gz feeds need a generous **read** timeout.
    Removes a partial destination file before each attempt so retries never append garbage.
    """
    dest = Path(filename)
    dest.parent.mkdir(parents=True, exist_ok=True)
    timeout = (connect_timeout, read_timeout)
    last_err: BaseException | None = None

    for attempt in range(retries):
        if dest.exists():
            try:
                dest.unlink()
            except OSError as e:
                log.warning("Could not remove partial %s: %s", dest, e)

        try:
            with requests.get(url, stream=True, timeout=timeout) as r:
                r.raise_for_status()
                with dest.open("wb") as f:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        if chunk:
                            f.write(chunk)
            return
        except (
            ChunkedEncodingError,
            ConnectionError,
            Timeout,
            ProtocolError,
            OSError,
        ) as e:
            last_err = e
            if attempt >= retries - 1:
                log.error("Giving up on %s after %s attempts: %s", url, retries, e)
                raise
            wait_s = backoff_factor * (2**attempt)
            log.warning(
                "Download interrupted (%s). Retry %s/%s in %.0fs — %s",
                type(e).__name__,
                attempt + 1,
                retries,
                wait_s,
                url,
            )
            time.sleep(wait_s)

    assert last_err is not None
    raise last_err  # pragma: no cover


def update_feed(feed: str, output_dir: Path) -> None:
    """Download ``{feed}.json.gz`` from NVD into ``output_dir``."""
    json_gz = output_dir / f"{feed}.json.gz"
    url = f"{BASE_URL}/{feed}.json.gz"
    log.info("Fetching %s -> %s", url, json_gz)
    download_file(url, json_gz)


def Update_NVD(
    output_dir: Path | None = None,
    feeds: Iterable[str] | None = None,
) -> None:
    """
    Download each feed under ``output_dir`` (default: this package's parent ``NVD_CVE`` dir).
    """
    root = Path(__file__).resolve().parent
    out = output_dir if output_dir is not None else root
    use_feeds = tuple(feeds) if feeds is not None else DEFAULT_FEEDS
    for feed in use_feeds:
        update_feed(feed.strip(), out)


__all__ = [
    "BASE_URL",
    "DEFAULT_FEEDS",
    "download_file",
    "update_feed",
    "Update_NVD",
]

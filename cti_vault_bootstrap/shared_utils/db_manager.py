from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Iterator, Literal, Mapping, Sequence

from shared_utils.csv_export import atomic_write_csv

CURRENT_SCHEMA_VERSION = 1

# PRAGMA busy_timeout (ms); 30s helps multi-process (Celery workers, Docker) with WAL
_DEFAULT_BUSY_MS = 30_000


def _default_db_path(workspace_root: Path) -> Path:
    return (workspace_root / "cti_vault.db").resolve()


@dataclass(frozen=True)
class CsvSyncResult:
    """`csv_is_stale` is True when the database has a newer max timestamp than the CSV file mtime (re-export)."""

    csv_is_stale: bool
    domain: str
    db_time_column: str
    db_max_value: str | None
    db_max_epoch_ms: float | None
    csv_path: Path
    csv_exists: bool
    csv_mtime_ms: float | None


def _parse_iso_to_epoch_ms(s: str | None) -> float | None:
    if s is None or (isinstance(s, str) and s.strip() == ""):
        return None
    t = str(s).strip()
    if t.endswith("Z"):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp() * 1000.0


def _file_mtime_ms(path: Path) -> float | None:
    try:
        return os.path.getmtime(path) * 1000.0
    except OSError:
        return None


class CTIVault:
    """
    Thread-safe **within one process** (`threading.RLock`). Each OS process (each Celery
    worker, each container) should use its own `CTIVault` instance. SQLite **WAL** mode +
    `busy_timeout` coordinates readers/writers across processes on the same `cti_vault.db` file.
    """

    def __init__(self, workspace_root: Path | None = None, db_path: Path | str | None = None) -> None:
        if db_path is not None:
            self._db_path = Path(db_path).resolve()
        elif workspace_root is not None:
            self._db_path = _default_db_path(Path(workspace_root))
        else:
            w = os.environ.get("CTI_VAULT_PATH")
            if w:
                self._db_path = Path(w).resolve()
            else:
                raise ValueError("Set workspace_root, db_path, or CTI_VAULT_PATH")
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    @property
    def db_path(self) -> Path:
        return self._db_path

    def _get_conn(self) -> sqlite3.Connection:
        with self._lock:
            if self._conn is None:
                self._db_path.parent.mkdir(parents=True, exist_ok=True)
                c = sqlite3.connect(
                    str(self._db_path),
                    timeout=float(_DEFAULT_BUSY_MS) / 1000.0,
                    check_same_thread=False,
                )
                c.row_factory = sqlite3.Row
                c.execute("PRAGMA journal_mode=WAL")
                c.execute(f"PRAGMA busy_timeout={_DEFAULT_BUSY_MS}")
                c.execute("PRAGMA foreign_keys=ON")
                self._conn = c
            return self._conn

    def connect(self) -> sqlite3.Connection:
        """Return the shared connection (re-entrant lock held by callers for transactions)."""
        return self._get_conn()

    def check_sync(
        self,
        csv_path: Path,
        domain: Literal["cve", "ioc", "asm"] = "cve",
    ) -> CsvSyncResult:
        """
        Compare the latest change time in the database for the given domain to the CSV file's
        modification time. If the DB max timestamp is **newer** than the CSV, the file is
        **stale** and should be re-exported.
        """
        p = Path(csv_path).resolve()
        if domain == "cve":
            sql, col = "SELECT MAX(updated_at) FROM cve_data", "updated_at"
        elif domain == "ioc":
            sql, col = "SELECT MAX(last_seen) FROM ioc_records", "last_seen"
        else:
            sql, col = "SELECT MAX(last_scan_at) FROM asm_assets", "last_scan_at"

        with self._lock:
            c = self._get_conn()
            row = c.execute(sql).fetchone()
            max_raw: str | None = row[0] if row else None
            if max_raw is not None and (not str(max_raw).strip()):
                max_raw = None

        db_ms = _parse_iso_to_epoch_ms(str(max_raw) if max_raw is not None else None)
        csv_ms = _file_mtime_ms(p) if p.is_file() else None
        exists = p.is_file()

        if not exists:
            stale = bool(db_ms is not None)
        elif db_ms is None:
            stale = False
        else:
            c_ms = csv_ms if csv_ms is not None else 0.0
            stale = db_ms > c_ms

        return CsvSyncResult(
            csv_is_stale=stale,
            domain=domain,
            db_time_column=col,
            db_max_value=str(max_raw) if max_raw is not None else None,
            db_max_epoch_ms=db_ms,
            csv_path=p,
            csv_exists=exists,
            csv_mtime_ms=csv_ms,
        )

    def wal_checkpoint(
        self, mode: Literal["PASSIVE", "FULL", "RESTART", "TRUNCATE"] = "PASSIVE"
    ) -> tuple[int, int, int] | None:
        """
        Merge WAL pages into the main DB file. Call after large batch imports to limit
        `cti_vault.db-wal` growth. Returns (busy, log, checkpointed) from the pragma, or
        None if not returned.
        """
        m = str(mode).strip().upper()
        if m not in ("PASSIVE", "FULL", "RESTART", "TRUNCATE"):
            m = "PASSIVE"
        statements = (
            f"PRAGMA main.wal_checkpoint({m})",
            f"PRAGMA wal_checkpoint({m})",
            "PRAGMA main.wal_checkpoint",
            "PRAGMA wal_checkpoint",
        )
        with self._lock:
            c = self._get_conn()
            row: tuple[Any, ...] | None = None
            for stmt in statements:
                try:
                    cur = c.execute(stmt)
                    row = cur.fetchone()
                    if row is not None:
                        break
                except sqlite3.OperationalError:
                    continue
        if row and len(row) >= 3:
            return (int(row[0]), int(row[1]), int(row[2]))
        return None

    def init_schema(self) -> int:
        """Create or migrate schema; return current schema version."""
        with self._lock:
            c = self._get_conn()
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            row = c.execute(
                "SELECT value FROM vault_meta WHERE key = ?",
                ("schema_version",),
            ).fetchone()
            ver = int(row[0]) if row else 0
            while ver < CURRENT_SCHEMA_VERSION:
                ver = self._apply_migration(c, ver)
            c.execute(
                "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
                ("schema_version", str(ver)),
            )
            c.commit()
            return ver

    def _apply_migration(self, c: sqlite3.Connection, from_ver: int) -> int:
        if from_ver == 0:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS cve_data (
                    cve_id TEXT PRIMARY KEY,
                    published TEXT,
                    last_modified TEXT,
                    description TEXT,
                    cvss TEXT,
                    first_seen TEXT,
                    updated_at TEXT,
                    source_project TEXT,
                    metadata TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_cve_updated ON cve_data(updated_at);

                CREATE TABLE IF NOT EXISTS ioc_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_value TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    source_project TEXT,
                    metadata TEXT,
                    UNIQUE (ioc_value, ioc_type)
                );
                CREATE INDEX IF NOT EXISTS idx_ioc_last ON ioc_records(last_seen);

                CREATE TABLE IF NOT EXISTS asm_assets (
                    asset_key TEXT PRIMARY KEY,
                    asset_target TEXT NOT NULL,
                    port INTEGER,
                    protocol TEXT,
                    last_scan_at TEXT,
                    source_project TEXT,
                    metadata TEXT
                );
                """
            )
            return 1
        # Future: if from_ver == 1: ALTER TABLE ...; return 2
        raise ValueError(f"Unknown schema version {from_ver}")

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def upsert_cve_row(
        self,
        *,
        cve_id: str,
        published: str | None = None,
        last_modified: str | None = None,
        description: str | None = None,
        cvss: str | None = None,
        first_seen: str | None = None,
        source_project: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        now = _iso_now()
        meta_json = _dump_meta(metadata)
        with self._lock:
            c = self._get_conn()
            c.execute(
                """
                INSERT INTO cve_data (
                    cve_id, published, last_modified, description, cvss,
                    first_seen, updated_at, source_project, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    published = COALESCE(excluded.published, cve_data.published),
                    last_modified = COALESCE(excluded.last_modified, cve_data.last_modified),
                    description = COALESCE(excluded.description, cve_data.description),
                    cvss = COALESCE(excluded.cvss, cve_data.cvss),
                    first_seen = COALESCE(cve_data.first_seen, excluded.first_seen),
                    updated_at = excluded.updated_at,
                    source_project = COALESCE(excluded.source_project, cve_data.source_project),
                    metadata = COALESCE(excluded.metadata, cve_data.metadata)
                """,
                (
                    cve_id,
                    published,
                    last_modified,
                    description,
                    cvss,
                    first_seen or now,
                    now,
                    source_project,
                    meta_json,
                ),
            )
            c.commit()

    def upsert_cve_batch(
        self,
        rows: Sequence[Mapping[str, Any]],
        *,
        source_project: str | None = "CVE_Project_NVD",
        wal_checkpoint_after: bool = True,
    ) -> None:
        """One transaction for many CVE rows (dict keys: cve_id, published, last_modified, ...)."""
        with self._lock:
            c = self._get_conn()
            for m in rows:
                self._upsert_cve_mapping(c, m, source_project=source_project)
            c.commit()
        if rows and wal_checkpoint_after:
            self.wal_checkpoint("PASSIVE")

    def _upsert_cve_mapping(
        self,
        c: sqlite3.Connection,
        m: Mapping[str, Any],
        *,
        source_project: str | None,
    ) -> None:
        cve_id = str(m.get("cve_id") or m.get("id") or "").strip()
        if not cve_id:
            return
        now = _iso_now()
        published = _str_or_none(m.get("published"))
        last_modified = _str_or_none(m.get("last_modified"))
        description = _str_or_none(m.get("description"))
        cvss = _str_or_none(m.get("cvss"))
        first_seen = _str_or_none(m.get("first_seen"))
        extra = m.get("metadata")
        if isinstance(extra, str):
            meta_json = extra
        elif isinstance(extra, Mapping):
            meta_json = _dump_meta(extra)
        else:
            meta_json = _dump_meta(_row_meta(m))
        c.execute(
            """
            INSERT INTO cve_data (
                cve_id, published, last_modified, description, cvss,
                first_seen, updated_at, source_project, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                published = COALESCE(excluded.published, cve_data.published),
                last_modified = COALESCE(excluded.last_modified, cve_data.last_modified),
                description = COALESCE(excluded.description, cve_data.description),
                cvss = COALESCE(excluded.cvss, cve_data.cvss),
                first_seen = COALESCE(cve_data.first_seen, excluded.first_seen),
                updated_at = excluded.updated_at,
                source_project = COALESCE(excluded.source_project, cve_data.source_project),
                metadata = COALESCE(excluded.metadata, cve_data.metadata)
            """,
            (
                cve_id,
                published,
                last_modified,
                description,
                cvss,
                first_seen or now,
                now,
                source_project,
                meta_json,
            ),
        )

    def upsert_ioc_row(
        self,
        *,
        ioc_value: str,
        ioc_type: str,
        first_seen: str | None = None,
        last_seen: str | None = None,
        source_project: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        now = _iso_now()
        with self._lock:
            c = self._get_conn()
            c.execute(
                """
                INSERT INTO ioc_records (
                    ioc_value, ioc_type, first_seen, last_seen, source_project, metadata
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_value, ioc_type) DO UPDATE SET
                    first_seen = COALESCE(ioc_records.first_seen, excluded.first_seen),
                    last_seen = COALESCE(excluded.last_seen, ioc_records.last_seen),
                    source_project = COALESCE(excluded.source_project, ioc_records.source_project),
                    metadata = COALESCE(excluded.metadata, ioc_records.metadata)
                """,
                (
                    ioc_value,
                    ioc_type,
                    first_seen or now,
                    last_seen or now,
                    source_project,
                    _dump_meta(metadata),
                ),
            )
            c.commit()

    def upsert_asm_asset(
        self,
        *,
        asset_key: str,
        asset_target: str,
        port: int | None = None,
        protocol: str | None = None,
        last_scan_at: str | None = None,
        source_project: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        when = last_scan_at or _iso_now()
        with self._lock:
            c = self._get_conn()
            c.execute(
                """
                INSERT INTO asm_assets (
                    asset_key, asset_target, port, protocol, last_scan_at, source_project, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_key) DO UPDATE SET
                    asset_target = excluded.asset_target,
                    port = COALESCE(excluded.port, asm_assets.port),
                    protocol = COALESCE(excluded.protocol, asm_assets.protocol),
                    last_scan_at = excluded.last_scan_at,
                    source_project = COALESCE(excluded.source_project, asm_assets.source_project),
                    metadata = COALESCE(excluded.metadata, asm_assets.metadata)
                """,
                (
                    asset_key,
                    asset_target,
                    port,
                    protocol,
                    when,
                    source_project,
                    _dump_meta(metadata),
                ),
            )
            c.commit()

    def export_cve_csv(self, out_path: Path) -> None:
        self._export_table_sql(
            "SELECT cve_id, published, last_modified, description, cvss, first_seen, updated_at, source_project, metadata FROM cve_data ORDER BY cve_id",
            out_path,
        )

    def export_ioc_csv(self, out_path: Path) -> None:
        self._export_table_sql(
            "SELECT ioc_value, ioc_type, first_seen, last_seen, source_project, metadata FROM ioc_records ORDER BY ioc_type, ioc_value",
            out_path,
        )

    def export_asm_csv(self, out_path: Path) -> None:
        self._export_table_sql(
            "SELECT asset_key, asset_target, port, protocol, last_scan_at, source_project, metadata FROM asm_assets ORDER BY asset_key",
            out_path,
        )

    def _export_table_sql(self, sql: str, out_path: Path) -> None:
        # Separate read connection so we do not hold the write lock for long exports (WAL allows it).
        conn = sqlite3.connect(
            str(self._db_path),
            timeout=float(_DEFAULT_BUSY_MS) / 1000.0,
        )
        try:
            conn.execute(f"PRAGMA busy_timeout={_DEFAULT_BUSY_MS}")
            cur = conn.execute(sql)
            col_names = [d[0] for d in cur.description] if cur.description else []

            def row_iter() -> Iterator[Sequence[Any]]:
                while True:
                    batch = cur.fetchmany(8_000)
                    if not batch:
                        break
                    yield from batch

            atomic_write_csv(Path(out_path), col_names, row_iter())
        finally:
            conn.close()


def _iso_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _dump_meta(metadata: Mapping[str, Any] | None) -> str | None:
    if not metadata:
        return None
    return json.dumps(dict(metadata), ensure_ascii=False, separators=(",", ":"))


def _str_or_none(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _row_meta(m: Mapping[str, Any]) -> dict[str, Any]:
    skip = {
        "cve_id",
        "id",
        "published",
        "last_modified",
        "description",
        "cvss",
        "first_seen",
        "metadata",
    }
    return {k: v for k, v in m.items() if k not in skip}


@contextlib.contextmanager
def open_cti_vault(
    workspace_root: Path | None = None,
    db_path: str | Path | None = None,
) -> Generator[CTIVault, None, None]:
    """
    One connection scope for a **short** unit of work (e.g. a single Celery task).
    Runs `init_schema()`, yields `CTIVault`, then **closes** the connection so
    long-running workers do not keep a stale handle.
    """
    v = CTIVault(workspace_root=workspace_root, db_path=db_path)
    v.init_schema()
    try:
        yield v
    finally:
        v.close()

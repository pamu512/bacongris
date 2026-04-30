from __future__ import annotations

import csv
import os
import uuid
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence


def atomic_write_csv(
    out_path: Path,
    column_names: Sequence[str],
    row_iter: Iterable[Sequence[Any]],
) -> None:
    """
    Write CSV to `out_path` atomically: stream rows to a temp file in the same directory
    and rename over the final name (POSIX: atomic if same filesystem).
    """
    out_path = out_path.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.parent / f".{out_path.name}.{os.getpid()}.{uuid.uuid4().hex}.part"
    try:
        with tmp.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f, lineterminator="\n")
            w.writerow(column_names)
            for row in row_iter:
                w.writerow(row)
        os.replace(str(tmp), str(out_path))
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)  # type: ignore[arg-type]
        except OSError:
            pass
        if Path(tmp).exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise


def rows_from_cursor(
    cur: Any,
) -> tuple[list[str], Iterator[Sequence[Any]]]:
    """
    Return column names and a single-pass iterator of rows (sqlite3 cursor after execute).
    """
    col_names = [d[0] for d in cur.description]
    return col_names, iter(cur.fetchall())

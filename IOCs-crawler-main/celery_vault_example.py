"""
Example Celery task wiring (not wired to a real app — copy into your ``tasks.py``).

Requires: ``pip install -e .`` at workspace root and ``celery`` in your worker venv.
"""
from __future__ import annotations

from pathlib import Path

from ioc_celery_vault import ioc_persist_from_task

_WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def example_finalize_ioc(ioc_value: str, ioc_type: str, source: str | None = None) -> bool:
    """Call after your primary store succeeds."""
    return ioc_persist_from_task(
        ioc_value,
        ioc_type,
        {"upstream": source} if source else None,
        workspace_root=_WORKSPACE_ROOT,
    )

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-platform trusted workflow runner for Bacongris.
Preflight dependencies, then run the documented entrypoint (Docker Compose or Python).

Usage:
  python3 workflow_runner.py --workspace /path/to/All_Scripts --workflow intelx
  python3 workflow_runner.py --workspace /path/to/All_Scripts --workflow cve_nvd
  # CVE: optional --query <keyword> pipes: search, start date, end date, keyword (see --cve-start-date / --cve-end-date)
  python3 workflow_runner.py --workspace /path/to/All_Scripts --workflow intelx --query "user@email.com"
  # Piped mode sends: query, start, end, search_limit (see --intelx-*; INTELX_* envs).
Environment:
  INTELX_COMPOSE_SERVICE — override docker compose service name (default: intelx-scraper).
  INTELX_START_DATE, INTELX_END_DATE, INTELX_SEARCH_LIMIT — defaults for piped IntelX stdin.
  CVE_NVD_SKIP_PIP — if set to 1, do not create .venv or pip install; run main.py with the
    interpreter that launched this script (may fail if deps missing — use for custom setups).

CVE workflow: creates `CVE_Project_NVD/.venv` if missing (avoids Homebrew PEP 668 “externally
managed” errors), then pip installs into that venv and runs main.py with the venv Python.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Canonical workflow ids (match Rust + agent tool).
WORKFLOWS: Dict[str, Dict[str, Any]] = {
    "intelx": {
        "relpath": "Intelx_Crawler",
        "kind": "compose",
        "service": os.environ.get("INTELX_COMPOSE_SERVICE", "intelx-scraper"),
    },
    "cve_nvd": {
        "relpath": "CVE_Project_NVD",
        "kind": "python",
        "entry": "main.py",
    },
}

ALIASES = {
    "cve": "cve_nvd",
    "nvd": "cve_nvd",
    "intel_x": "intelx",
}

# First-line stdin to intelx-scraper (email, domain, etc.); keep bounded.
MAX_INTELX_QUERY_LEN = 2048


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def venv_python_executable(project: Path) -> Path:
    if sys.platform == "win32":
        return project / ".venv" / "Scripts" / "python.exe"
    return project / ".venv" / "bin" / "python"


def ensure_project_venv(project: Path, dry_run: bool) -> int:
    """Create project/.venv with the same interpreter that runs this script (PEP 668–safe installs)."""
    py = venv_python_executable(project)
    if py.is_file():
        return 0
    if dry_run:
        print(
            f"[dry-run] Would create venv: {sys.executable} -m venv .venv (cwd={project})"
        )
        return 0
    eprint(f"→ Creating virtualenv: {sys.executable} -m venv .venv (cwd={project})")
    r = subprocess.run(
        [sys.executable, "-m", "venv", ".venv"],
        cwd=project,
    )
    if r.returncode != 0:
        eprint("ERROR: python -m venv .venv failed.")
        return r.returncode
    if not venv_python_executable(project).is_file():
        eprint("ERROR: venv was created but the Python executable was not found.")
        return 1
    return 0


def require_docker_compose() -> List[str]:
    if not shutil.which("docker"):
        eprint("ERROR: docker is not on PATH. Install Docker Desktop and ensure `docker` is available.")
        sys.exit(1)
    r = subprocess.run(
        ["docker", "compose", "version"],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    eprint("ERROR: `docker compose` and `docker-compose` are not available.")
    sys.exit(1)


def find_compose_file(project: Path) -> Optional[Path]:
    for name in ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"):
        p = project / name
        if p.is_file():
            return p
    return None


def _intelx_piped_stdin(
    q: str,
    start: Optional[str],
    end: Optional[str],
    search_limit: Optional[str],
) -> str:
    """Match intelx-scraper prompts: query, start/end dates, then search limit."""
    s = (start or os.environ.get("INTELX_START_DATE") or "2000-01-01").strip()
    e = (end or os.environ.get("INTELX_END_DATE") or "2099-12-31").strip()
    lim = (search_limit or os.environ.get("INTELX_SEARCH_LIMIT") or "2000").strip()
    if not lim:
        lim = "2000"
    return f"{q}\n{s}\n{e}\n{lim}\n"


def run_intelx(
    project: Path,
    service: str,
    dry_run: bool,
    query: Optional[str] = None,
    intelx_start_date: Optional[str] = None,
    intelx_end_date: Optional[str] = None,
    intelx_search_limit: Optional[str] = None,
) -> int:
    if not project.is_dir():
        eprint(f"ERROR: Project folder not found: {project}")
        eprint("Expected a trusted repo layout with Intelx_Crawler under the workspace root.")
        return 1
    if not find_compose_file(project):
        eprint(f"ERROR: No compose file in {project}")
        return 1
    cc_base = require_docker_compose()
    q = (query or "").strip()
    if len(q) > MAX_INTELX_QUERY_LEN:
        eprint(f"ERROR: --query exceeds {MAX_INTELX_QUERY_LEN} characters.")
        return 1
    if q:
        # Pipe query + start/end dates (-T: no TTY; matches sequential input() in container).
        cmd = [*cc_base, "run", "--rm", "-i", "-T", service]
        stdin_payload = _intelx_piped_stdin(
            q, intelx_start_date, intelx_end_date, intelx_search_limit
        )
        if dry_run:
            print(
                "[dry-run] Would run:",
                " ".join(cmd),
                f"with 4-line stdin: query, dates, search limit (cwd={project})",
            )
            return 0
        eprint(f"→ Running: {' '.join(cmd)} in {project}")
        eprint(
            "→ Piping query + dates + search limit (override: --intelx-start-date, --intelx-end-date, --intelx-search-limit).",
        )
        r = subprocess.run(
            cmd,
            cwd=project,
            input=stdin_payload,
            text=True,
        )
        return r.returncode
    cmd = [*cc_base, "run", "--rm", "-it", service]
    if dry_run:
        print("[dry-run] Would run:", " ".join(cmd), f"(cwd={project})")
        return 0
    eprint(f"→ Running: {' '.join(cmd)} in {project}")
    return subprocess.call(cmd, cwd=project)


def pip_install_requirements(
    project: Path,
    python_exe: Path,
    dry_run: bool,
    skip: bool,
) -> int:
    """Install into the given environment (project venv) — not the system Homebrew python."""
    if skip:
        eprint("Skipping venv + pip install (--skip-pip-install or CVE_NVD_SKIP_PIP=1).")
        return 0
    req = project / "requirements.txt"
    if not req.is_file():
        eprint("Note: no requirements.txt in project; skipping pip install.")
        return 0
    cmd = [
        str(python_exe),
        "-m",
        "pip",
        "install",
        "-r",
        "requirements.txt",
    ]
    if dry_run:
        print("[dry-run] Would run:", " ".join(cmd), f"(cwd={project})")
        return 0
    eprint(f"→ Installing dependencies: {' '.join(cmd)} (cwd={project})")
    r = subprocess.run(cmd, cwd=project)
    if r.returncode != 0:
        eprint("ERROR: pip install failed. Fix requirements or install manually, then retry.")
    return r.returncode


def run_cve_nvd(
    project: Path,
    entry: str,
    dry_run: bool,
    skip_pip: bool,
    search_query: Optional[str] = None,
    cve_start_date: Optional[str] = None,
    cve_end_date: Optional[str] = None,
    cve_cvss: Optional[str] = None,
    cve_cvss_v4: Optional[str] = None,
) -> int:
    if not project.is_dir():
        eprint(f"ERROR: Project folder not found: {project}")
        eprint("Expected CVE_Project_NVD under the workspace root.")
        return 1
    main_py = project / entry
    if not main_py.is_file():
        eprint(f"ERROR: Missing {main_py} — check README for the real entry point.")
        return 1

    q = (search_query or "").strip()
    if q and ("\n" in q or "\r" in q):
        eprint("ERROR: CVE --query must be a single line (no newlines).")
        return 1

    d0 = (cve_start_date or os.environ.get("CVE_SEARCH_START_DATE") or "2000-01-01").strip()
    d1 = (cve_end_date or os.environ.get("CVE_SEARCH_END_DATE") or "2099-12-31").strip()
    cvss = (cve_cvss or os.environ.get("CVE_SEARCH_CVSS", "") or "").strip()
    if cvss and ("\n" in cvss or "\r" in cvss):
        eprint("ERROR: CVE --cve-cvss must be a single line (no newlines).")
        return 1
    cvss_v4 = (cve_cvss_v4 or os.environ.get("CVE_SEARCH_CVSS_V4", "") or "").strip()
    if cvss_v4 and ("\n" in cvss_v4 or "\r" in cvss_v4):
        eprint("ERROR: CVE --cve-cvss-v4 must be a single line (no newlines).")
        return 1

    def cve_stdin() -> str:
        # main.py: search → dates → vendors → CVSS v3 → CVSS v4 (blank = no threshold)
        return f"search\n{d0}\n{d1}\n{q}\n{cvss}\n{cvss_v4}\n"

    if skip_pip:
        if dry_run:
            extra = f" (piped: search, {d0}..{d1}, vendors={q!r}, cvss_v3={cvss!r}, cvss_v4={cvss_v4!r})" if q else ""
            print(
                f"[dry-run] Would run: {sys.executable} {entry} (cwd={project}, no venv){extra}"
            )
            return 0
        eprint(f"→ Running: {sys.executable} {entry} in {project}")
        if q:
            eprint(
                f"→ Piping CVE stdin: search → {d0}..{d1} → vendors {q!r} → CVSSv3 {cvss!r} → CVSSv4 {cvss_v4!r}",
            )
            r = subprocess.run(
                [sys.executable, entry],
                cwd=project,
                input=cve_stdin(),
                text=True,
            )
            return r.returncode
        return subprocess.call([sys.executable, entry], cwd=project)

    ve = ensure_project_venv(project, dry_run)
    if ve != 0:
        return ve
    venv_py = venv_python_executable(project)
    pr = pip_install_requirements(project, venv_py, dry_run, skip=False)
    if pr != 0:
        return pr
    if dry_run:
        extra = f" (piped: search, {d0}..{d1}, vendors={q!r}, cvss_v3={cvss!r}, cvss_v4={cvss_v4!r})" if q else ""
        print(f"[dry-run] Would run: {venv_py} {entry} (cwd={project}){extra}")
        return 0
    eprint(f"→ Running: {venv_py} {entry} in {project}")
    if q:
        eprint(
            f"→ Piping CVE stdin: search → {d0}..{d1} → vendors {q!r} → CVSSv3 {cvss!r} → CVSSv4 {cvss_v4!r}",
        )
        r = subprocess.run(
            [str(venv_py), entry],
            cwd=project,
            input=cve_stdin(),
            text=True,
        )
        return r.returncode
    return subprocess.call([str(venv_py), entry], cwd=project)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--workspace",
        required=True,
        help="CTI monorepo root (e.g. All_Scripts)",
    )
    p.add_argument(
        "--workflow",
        required=True,
        help="intelx | cve | cve_nvd",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the command only",
    )
    p.add_argument(
        "--skip-pip-install",
        action="store_true",
        help="Do not run pip install -r requirements.txt before main.py (CVE workflow).",
    )
    p.add_argument(
        "--query",
        default="",
        help="IntelX: first stdin line in piped mode. "
        "CVE (cve|cve_nvd): target sources / vendors; runner pipes search, dates, vendors, CVSS v3/v4 (see --cve-cvss*, --cve-*-date; main.py).",
    )
    p.add_argument(
        "--cve-start-date",
        default="",
        help="CVE + --query: YYYY-MM-DD for main.py (after search). Default: 2000-01-01 or CVE_SEARCH_START_DATE.",
    )
    p.add_argument(
        "--cve-end-date",
        default="",
        help="CVE + --query: YYYY-MM-DD. Default: 2099-12-31 or CVE_SEARCH_END_DATE.",
    )
    p.add_argument(
        "--cve-cvss",
        default="",
        help="CVE + --query: CVSS v3 input (e.g. >7.0) or omit for no threshold. Default: empty or CVE_SEARCH_CVSS.",
    )
    p.add_argument(
        "--cve-cvss-v4",
        default="",
        help="CVE + --query: CVSS v4 line or omit for no threshold. Default: empty or CVE_SEARCH_CVSS_V4.",
    )
    p.add_argument(
        "--intelx-start-date",
        default="",
        help="IntelX + --query: second stdin line (YYYY-MM-DD). Default: 2000-01-01 or INTELX_START_DATE.",
    )
    p.add_argument(
        "--intelx-end-date",
        default="",
        help="IntelX + --query: third stdin line (YYYY-MM-DD). Default: 2099-12-31 or INTELX_END_DATE.",
    )
    p.add_argument(
        "--intelx-search-limit",
        default="",
        help="IntelX + --query: fourth line (e.g. 2000). Default: 2000 or INTELX_SEARCH_LIMIT.",
    )
    args = p.parse_args()
    skip_pip = args.skip_pip_install or os.environ.get("CVE_NVD_SKIP_PIP", "").strip() in (
        "1",
        "true",
        "yes",
    )

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        eprint("ERROR: --workspace is not a directory:", ws)
        return 1

    key = args.workflow.strip().lower().replace("-", "_")
    key = ALIASES.get(key, key)
    if key not in WORKFLOWS:
        eprint("ERROR: Unknown --workflow. Use: intelx, cve, or cve_nvd")
        return 1

    spec = WORKFLOWS[key]
    rel = spec["relpath"]
    project = ws / rel

    if spec["kind"] == "compose":
        return run_intelx(
            project,
            spec["service"],
            args.dry_run,
            (args.query or "").strip() or None,
            (args.intelx_start_date or "").strip() or None,
            (args.intelx_end_date or "").strip() or None,
            (args.intelx_search_limit or "").strip() or None,
        )
    if spec["kind"] == "python":
        cve_q = (args.query or "").strip() or None
        cve_s = (args.cve_start_date or "").strip() or None
        cve_e = (args.cve_end_date or "").strip() or None
        cve_c = (args.cve_cvss or "").strip() or None
        cve_c4 = (args.cve_cvss_v4 or "").strip() or None
        return run_cve_nvd(
            project,
            spec["entry"],
            args.dry_run,
            skip_pip,
            cve_q,
            cve_s,
            cve_e,
            cve_c,
            cve_c4,
        )
    eprint("ERROR: internal workflow config")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        eprint("\nInterrupted.")
        raise SystemExit(130)

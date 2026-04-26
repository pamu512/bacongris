use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::settings::{load_settings, resolve_workspace_dir, AppSettings};

/// One-shot idempotent Python runner for multi-project workspaces. Written into **scripts/** the
/// first time the workspace is opened so users do not repeat venv+pip+run steps.
const VENV_RUN_SH: &str = r#"#!/usr/bin/env bash
# Per-project venv: creates .venv, pip install -r, runs Python. Safe to run every time.
# Use from the workspace root (parent of this scripts/ directory):
#   ./scripts/venv_run.sh <project_subdir>              # runs main.py
#   ./scripts/venv_run.sh <project_subdir> main.py  --args # runs main with args
#   ./scripts/venv_run.sh <project_subdir> other.py
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJ_RELP="${1:-}"
if [[ -z "$PROJ_RELP" || "$PROJ_RELP" == -* ]]; then
  echo "usage: $(basename "$0") <project_subdir> [script_or_args...]" >&2
  echo "  example: $(basename "$0") CVE_Project_NVD" >&2
  exit 1
fi
shift
PROJ_DIR="$WS_ROOT/$PROJ_RELP"
if [[ ! -d "$PROJ_DIR" ]]; then
  echo "not a directory: $PROJ_DIR" >&2
  exit 1
fi
cd "$PROJ_DIR"
if [[ ! -f requirements.txt ]]; then
  echo "error: $PROJ_RELP/requirements.txt not found" >&2
  exit 1
fi
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
.venv/bin/pip install -q -r requirements.txt
# If the first remaining arg is a file, treat it as the script; else run main.py with these args.
if [[ -n "${1:-}" && -f "$1" ]]; then
  exec .venv/bin/python3 "$@"
fi
exec .venv/bin/python3 main.py "$@"
"#;

/// Ensure the helper script exists in **scripts/**. Does not overwrite; delete the file to
/// regenerate a fresh template after a Bacongris update if needed.
fn ensure_venv_run_script(scripts: &Path) {
    let path = scripts.join("venv_run.sh");
    if path.exists() {
        return;
    }
    if fs::write(&path, VENV_RUN_SH).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&path, perms);
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceInfo {
    pub effective_path: String,
    pub scripts_path: String,
    pub is_custom_location: bool,
}

#[tauri::command]
pub fn get_workspace_info(app: tauri::AppHandle) -> Result<WorkspaceInfo, String> {
    workspace_info_from_settings(&load_settings(&app)?)
}

pub(crate) fn workspace_info_from_settings(settings: &AppSettings) -> Result<WorkspaceInfo, String> {
    let root = resolve_workspace_dir(settings)?;
    std::fs::create_dir_all(&root).map_err(|e| format!("workspace: {e}"))?;
    let scripts = root.join("scripts");
    std::fs::create_dir_all(&scripts).map_err(|e| format!("scripts folder: {e}"))?;
    ensure_venv_run_script(&scripts);
    Ok(WorkspaceInfo {
        effective_path: root.to_string_lossy().into_owned(),
        scripts_path: scripts.to_string_lossy().into_owned(),
        is_custom_location: !settings.workspace_path.trim().is_empty(),
    })
}

/// Creates workspace root, `scripts/`, and a short README if missing.
#[tauri::command]
pub fn prepare_workspace_layout(app: tauri::AppHandle) -> Result<WorkspaceInfo, String> {
    let settings = load_settings(&app)?;
    let root = resolve_workspace_dir(&settings)?;
    std::fs::create_dir_all(&root).map_err(|e| format!("workspace: {e}"))?;
    let scripts = root.join("scripts");
    std::fs::create_dir_all(&scripts).map_err(|e| format!("scripts folder: {e}"))?;
    let readme = root.join("README.txt");
    if !readme.exists() {
        let body = concat!(
            "Bacongris CTI workspace\n\n",
            "Put your scripts in the scripts/ folder. This entire directory is allowlisted for the agent.\n",
            "You can change the workspace location in Settings.\n",
        );
        let _ = std::fs::write(&readme, body);
    }
    workspace_info_from_settings(&settings)
}

#[tauri::command]
pub fn open_workspace_in_os(app: tauri::AppHandle) -> Result<(), String> {
    let settings = load_settings(&app)?;
    let root = resolve_workspace_dir(&settings)?;
    std::fs::create_dir_all(&root).map_err(|e| format!("workspace: {e}"))?;
    open_in_file_manager(&root)
}

fn open_in_file_manager(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(path)
            .spawn()
            .map_err(|e| format!("open: {e}"))?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(path)
            .spawn()
            .map_err(|e| format!("explorer: {e}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(path)
            .spawn()
            .map_err(|e| format!("xdg-open: {e}"))?;
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "linux"
    )))]
    {
        return Err("Opening a folder in the file manager is not supported on this platform.".into());
    }
    Ok(())
}

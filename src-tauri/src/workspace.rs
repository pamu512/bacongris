use dunce;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::app_data::merged_settings_for_runtime;
use crate::app_data::AppStore;
use crate::audit::append_audit;
use crate::settings::{app_config_dir, resolve_workspace_dir, AppSettings};
use tauri::Manager;

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

/// Idempotent Python script to verify **run_command** → JSON in chat (no network). Dropped into `scripts/`
/// on first workspace use; the agent can run: `python3` with args `[ this path, email@example.com ]`, cwd = workspace root.
const BACONGRIS_SMOKE_TEST_PY: &str = r#"#!/usr/bin/env python3
"""Bacongris: dummy “workflow” for testing run_command + chat. No network; prints JSON to stdout, one line to stderr."""
import json
import os
import sys

def main() -> int:
    target = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.environ.get("BACONGRIS_TEST_EMAIL", "no-input@local.test")
    ).strip()
    out = {
        "kind": "bacongris_smoke_test",
        "input": target,
        "findings": [
            f"dummy row for {target!r}",
            "simulated: no real CTI data in this smoke run",
        ],
    }
    print(json.dumps(out, indent=2))
    print("INFO: stderr line (for log analysis test)", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
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

/// Dummy workflow script for agent smoke tests. Does not overwrite.
fn ensure_bacongris_smoke_test(scripts: &Path) {
    let path = scripts.join("bacongris_smoke_test.py");
    if path.exists() {
        return;
    }
    if fs::write(&path, BACONGRIS_SMOKE_TEST_PY).is_err() {
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
    /// **Issue 6:** false if the active profile path is missing or not a directory.
    pub path_accessible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_error: Option<String>,
}

#[tauri::command]
pub fn get_workspace_info(app: tauri::AppHandle) -> Result<WorkspaceInfo, String> {
    workspace_info_for_app(&app)
}

/// Active workspace: SQLite profile path (if any), else legacy `settings.workspace_path` / default.
pub fn workspace_info_for_app(app: &tauri::AppHandle) -> Result<WorkspaceInfo, String> {
    let store = app.state::<AppStore>();
    let root = store.effective_workspace_path(app)?;
    let (path_accessible, path_error) = if !root.exists() {
        (false, Some("path does not exist".to_string()))
    } else if !root.is_dir() {
        (false, Some("not a directory".to_string()))
    } else {
        (true, None)
    };
    let def = app_config_dir()?.join("workspace");
    let is_custom = match (dunce::canonicalize(&root), dunce::canonicalize(&def)) {
        (Ok(a), Ok(b)) => a != b,
        _ => true,
    };
    if !path_accessible {
        return Ok(WorkspaceInfo {
            effective_path: root.to_string_lossy().into_owned(),
            scripts_path: root.join("scripts").to_string_lossy().into_owned(),
            is_custom_location: is_custom,
            path_accessible: false,
            path_error,
        });
    }
    std::fs::create_dir_all(&root).map_err(|e| format!("workspace: {e}"))?;
    let scripts = root.join("scripts");
    std::fs::create_dir_all(&scripts).map_err(|e| format!("scripts folder: {e}"))?;
    ensure_venv_run_script(&scripts);
    ensure_bacongris_smoke_test(&scripts);
    Ok(WorkspaceInfo {
        effective_path: root.to_string_lossy().into_owned(),
        scripts_path: scripts.to_string_lossy().into_owned(),
        is_custom_location: is_custom,
        path_accessible: true,
        path_error: None,
    })
}

#[allow(dead_code)]
/// Used when only legacy `AppSettings` is available (e.g. unit tests without `AppStore`).
pub(crate) fn workspace_info_from_settings(settings: &AppSettings) -> Result<WorkspaceInfo, String> {
    let root = resolve_workspace_dir(settings)?;
    std::fs::create_dir_all(&root).map_err(|e| format!("workspace: {e}"))?;
    let scripts = root.join("scripts");
    std::fs::create_dir_all(&scripts).map_err(|e| format!("scripts folder: {e}"))?;
    ensure_venv_run_script(&scripts);
    ensure_bacongris_smoke_test(&scripts);
    Ok(WorkspaceInfo {
        effective_path: root.to_string_lossy().into_owned(),
        scripts_path: scripts.to_string_lossy().into_owned(),
        is_custom_location: !settings.workspace_path.trim().is_empty(),
        path_accessible: true,
        path_error: None,
    })
}

/// Creates workspace root, `scripts/`, and a short README if missing.
#[tauri::command]
pub fn prepare_workspace_layout(app: tauri::AppHandle) -> Result<WorkspaceInfo, String> {
    let store = app.state::<AppStore>();
    let root = store.effective_workspace_path(&app)?;
    std::fs::create_dir_all(&root).map_err(|e| format!("workspace: {e}"))?;
    let scripts = root.join("scripts");
    std::fs::create_dir_all(&scripts).map_err(|e| format!("scripts folder: {e}"))?;
    let readme = root.join("README.txt");
    if !readme.exists() {
        let body = concat!(
            "Bacongris CTI workspace\n\n",
            "Put your scripts in the scripts/ folder. This entire directory is allowlisted for the agent.\n",
            "You can change the workspace or profiles from the app.\n",
        );
        let _ = std::fs::write(&readme, body);
    }
    workspace_info_for_app(&app)
}

#[tauri::command]
pub fn open_workspace_in_os(app: tauri::AppHandle) -> Result<(), String> {
    let store = app.state::<AppStore>();
    let root = store.effective_workspace_path(&app)?;
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

// --- User file uploads (copied into workspace/uploads/ for read_text_file) ---

/// Result from copying uploads into the workspace; paths are under allowlisted roots.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct IngestedUpload {
    pub path: String,
    /// Final file name on disk in the batch folder
    pub name: String,
    pub size: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InlineUploadPart {
    pub file_name: String,
    /// Standard base64 (e.g. from a browser File)
    pub data_base64: String,
}

/// Copy files the user selected (absolute paths) into `workspace/uploads/<batch>/…`.
/// Max size per file: Settings → max output (same as **read_text_file**).
#[tauri::command]
pub fn ingest_uploads(
    app: tauri::AppHandle,
    source_paths: Vec<String>,
) -> Result<Vec<IngestedUpload>, String> {
    if source_paths.is_empty() {
        return Err("No file paths to ingest.".into());
    }
    let store = app.state::<AppStore>();
    let root = store.effective_workspace_path(&app)?;
    if !root.is_dir() {
        return Err("Workspace is not available. Set an accessible workspace or profile path.".into());
    }
    let settings = merged_settings_for_runtime(&app)?;
    let max: u64 = settings.max_output_bytes.max(1024) as u64;
    let upload_base = root.join("uploads");
    let batch = uuid::Uuid::new_v4().to_string();
    let dest_dir = upload_base.join(&batch);
    fs::create_dir_all(&dest_dir).map_err(|e| format!("create upload dir: {e}"))?;

    let mut out: Vec<IngestedUpload> = Vec::new();
    for src in source_paths {
        let s = src.trim();
        if s.is_empty() {
            continue;
        }
        let p = Path::new(s);
        if !p.is_file() {
            continue;
        }
        let meta = fs::metadata(p).map_err(|e| format!("metadata {}: {e}", p.display()))?;
        if meta.len() > max {
            return Err(format!(
                "“{}” is {} bytes. Max per file is {} (Settings → max output).",
                p.display(),
                meta.len(),
                max
            ));
        }
        let name_raw = p
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("invalid file name")?;
        let final_path = write_unique_in_dir(&dest_dir, name_raw, |d| {
            fs::copy(p, d).map_err(|e| format!("copy: {e}"))?;
            Ok(())
        })?;
        out.push(IngestedUpload {
            name: final_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(name_raw)
                .to_string(),
            path: final_path.to_string_lossy().into_owned(),
            size: meta.len(),
        });
    }
    if out.is_empty() {
        return Err("No readable files to upload (paths may be empty or not files).".into());
    }
    let _ = append_audit(
        &app,
        "ingest_uploads",
        serde_json::json!({ "count": out.len(), "batch": &batch, "byPath": true }),
    );
    Ok(out)
}

/// Ingest from browser/JS (base64); same destination and size limits as [ingest_uploads].
#[tauri::command]
pub fn ingest_files_from_data(
    app: tauri::AppHandle,
    items: Vec<InlineUploadPart>,
) -> Result<Vec<IngestedUpload>, String> {
    if items.is_empty() {
        return Err("No file data to ingest.".into());
    }
    if items.len() > 32 {
        return Err("At most 32 files per batch.".into());
    }
    let store = app.state::<AppStore>();
    let root = store.effective_workspace_path(&app)?;
    if !root.is_dir() {
        return Err("Workspace is not available.".into());
    }
    let settings = merged_settings_for_runtime(&app)?;
    let max: u64 = settings.max_output_bytes.max(1024) as u64;
    use base64::Engine;
    let upload_base = root.join("uploads");
    let batch = uuid::Uuid::new_v4().to_string();
    let dest_dir = upload_base.join(&batch);
    fs::create_dir_all(&dest_dir).map_err(|e| format!("create upload dir: {e}"))?;

    let mut out: Vec<IngestedUpload> = Vec::new();
    for item in items {
        let name_safe = sanitize_upload_file_name(&item.file_name);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(item.data_base64.trim())
            .map_err(|e| format!("base64 decode: {e}"))?;
        let len = bytes.len() as u64;
        if len == 0 {
            continue;
        }
        if len > max {
            return Err(format!(
                "“{}” is {} bytes. Max per file is {} (Settings → max output).",
                name_safe, len, max
            ));
        }
        let final_path = write_unique_in_dir(&dest_dir, &name_safe, |d| {
            let mut f = fs::File::create(d).map_err(|e| e.to_string())?;
            f.write_all(&bytes).map_err(|e| e.to_string())?;
            Ok(())
        })?;
        out.push(IngestedUpload {
            name: final_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string(),
            path: final_path.to_string_lossy().into_owned(),
            size: len,
        });
    }
    if out.is_empty() {
        return Err("All uploads were empty.".into());
    }
    let _ = append_audit(
        &app,
        "ingest_uploads",
        serde_json::json!({ "count": out.len(), "batch": &batch, "byPath": false }),
    );
    Ok(out)
}

/// Writes `dest` using `writer` which creates the file; picks a non-colliding name in `dir`.
fn write_unique_in_dir(
    dir: &Path,
    file_name: &str,
    writer: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<PathBuf, String> {
    let p0 = dir.join(sanitize_file_component(file_name));
    if !p0.exists() {
        writer(&p0)?;
        return Ok(p0);
    }
    let path = Path::new(file_name);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("file");
    let ext = path.extension().and_then(|e| e.to_str());
    for n in 1u32..=999u32 {
        let with_stem = if let Some(ext) = ext {
            format!("{stem} ({n}).{ext}")
        } else {
            format!("{stem} ({n})")
        };
        let cand = dir.join(sanitize_file_component(&with_stem));
        if !cand.exists() {
            writer(&cand)?;
            return Ok(cand);
        }
    }
    let fallback = dir.join(sanitize_file_component(&format!("{stem}-{}", uuid::Uuid::new_v4())));
    writer(&fallback)?;
    Ok(fallback)
}

fn sanitize_upload_file_name(name: &str) -> String {
    let s = name.trim();
    if s.is_empty() {
        return "file.bin".into();
    }
    // Take basename only; strip path tricks
    let base = Path::new(s)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("file.bin");
    sanitize_file_component(base)
}

fn sanitize_file_component(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| *c != '/' && *c != '\\' && *c != '\0' && *c != ':')
        .take(240)
        .collect();
    let t = s.trim();
    if t.is_empty() {
        "file.bin".into()
    } else {
        t.to_string()
    }
}

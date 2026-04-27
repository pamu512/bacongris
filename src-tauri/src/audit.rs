use chrono::Utc;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use tauri::Manager;

const APP_CONFIG_DIR: &str = "BacongrisCTIAgent";

fn audit_file_path() -> Result<std::path::PathBuf, String> {
    let base = dirs::config_dir().ok_or_else(|| "could not resolve config directory".to_string())?;
    let dir = base.join(APP_CONFIG_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create config dir: {e}"))?;
    Ok(dir.join("audit.log"))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditRecord {
    pub ts: String,
    pub tool: String,
    /// Active workspace profile when the event occurred (Issue 7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    pub detail: serde_json::Value,
}

pub(crate) fn append_audit(
    app: &tauri::AppHandle,
    tool: &str,
    detail: serde_json::Value,
) -> Result<(), String> {
    let profile_id = if let Some(store) = app.try_state::<crate::app_data::AppStore>() {
        if let Ok(g) = store.db.lock() {
            g.query_row("SELECT active_profile_id FROM app_state WHERE id = 1", [], |r| {
                r.get::<_, Option<String>>(0)
            })
            .ok()
            .flatten()
        } else {
            None
        }
    } else {
        None
    };
    let path = audit_file_path()?;
    let record = AuditRecord {
        ts: Utc::now().to_rfc3339(),
        tool: tool.to_string(),
        profile_id,
        detail,
    };
    let line = serde_json::to_string(&record).map_err(|e| format!("audit json: {e}"))?;
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("audit open: {e}"))?;
    writeln!(f, "{line}").map_err(|e| format!("audit write: {e}"))?;
    Ok(())
}

#[tauri::command]
pub fn get_recent_audit(_app: tauri::AppHandle, limit: u32) -> Result<Vec<serde_json::Value>, String> {
    let path = audit_file_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read audit: {e}"))?;
    let mut rows: Vec<serde_json::Value> = raw
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let n = limit as usize;
    if rows.len() > n {
        rows = rows.split_off(rows.len() - n);
    }
    Ok(rows)
}

#[tauri::command]
pub fn clear_audit_log(_app: tauri::AppHandle) -> Result<(), String> {
    let path = audit_file_path()?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| format!("remove audit: {e}"))?;
    }
    Ok(())
}

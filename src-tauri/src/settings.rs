use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const APP_CONFIG_DIR: &str = "BacongrisCTIAgent";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    /// Empty string = default folder under app config (`…/BacongrisCTIAgent/workspace`).
    #[serde(default)]
    pub workspace_path: String,
    pub ollama_base_url: String,
    pub model: String,
    pub allowlisted_roots: Vec<String>,
    /// Binaries allowed even when not under `allowlisted_roots` (e.g. `/usr/bin/python3`).
    pub allowed_executables: Vec<String>,
    pub execution_timeout_secs: u64,
    pub max_output_bytes: usize,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            workspace_path: String::new(),
            ollama_base_url: "http://127.0.0.1:11434".to_string(),
            model: "llama3.1".to_string(),
            allowlisted_roots: Vec::new(),
            allowed_executables: Vec::new(),
            execution_timeout_secs: 120,
            max_output_bytes: 512 * 1024,
        }
    }
}

pub(crate) fn app_config_dir() -> Result<PathBuf, String> {
    let base = dirs::config_dir().ok_or_else(|| "could not resolve config directory".to_string())?;
    let dir = base.join(APP_CONFIG_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create config dir: {e}"))?;
    Ok(dir)
}

pub fn settings_path(_app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app_config_dir()?.join("settings.json"))
}

pub fn load_settings(app: &tauri::AppHandle) -> Result<AppSettings, String> {
    let path = settings_path(app)?;
    if !path.exists() {
        return Ok(AppSettings::default());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read settings: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse settings: {e}"))
}

pub fn save_settings(app: &tauri::AppHandle, settings: &AppSettings) -> Result<(), String> {
    let path = settings_path(app)?;
    let raw = serde_json::to_string_pretty(settings).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(&path, raw).map_err(|e| format!("write settings: {e}"))
}

/// Resolved workspace root: custom path if set, otherwise `app_config_dir()/workspace`.
pub fn resolve_workspace_dir(settings: &AppSettings) -> Result<PathBuf, String> {
    let trimmed = settings.workspace_path.trim();
    if trimmed.is_empty() {
        Ok(app_config_dir()?.join("workspace"))
    } else {
        Ok(PathBuf::from(trimmed))
    }
}

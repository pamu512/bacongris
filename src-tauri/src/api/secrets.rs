//! Optional `.api_keys.json` in the app config dir; merged with `settings.json` `apiKeys` (file wins on duplicate keys).
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::settings::app_config_dir;
use crate::settings::AppSettings;

pub fn api_keys_path() -> Result<PathBuf, String> {
    Ok(app_config_dir()?.join(".api_keys.json"))
}

/// Keys from disk only. Missing file → empty map.
pub fn load_file_api_keys() -> Result<HashMap<String, String>, String> {
    let p = api_keys_path()?;
    if !p.exists() {
        return Ok(HashMap::new());
    }
    let raw = fs::read_to_string(&p).map_err(|e| format!("read .api_keys.json: {e}"))?;
    let v: HashMap<String, String> = serde_json::from_str(&raw)
        .map_err(|e| format!("parse .api_keys.json: {e}"))?;
    Ok(v)
}

/// Settings keys first, then file keys (override).
pub fn merge_api_keys(settings: &AppSettings) -> Result<HashMap<String, String>, String> {
    let mut m = settings.api_keys.clone();
    for (k, v) in load_file_api_keys()? {
        m.insert(k, v);
    }
    Ok(m)
}

//! Keep `campaigns` rows in sync with `iocs.campaign_tag` (first/last seen rollups).
use chrono::Utc;
use rusqlite::params;
use sha2::{Digest, Sha256};
use tauri::AppHandle;
use tauri::Manager;

use crate::app_data::AppStore;

fn now() -> i64 {
    Utc::now().timestamp()
}

/// Stable `campaigns.id` from tag text (for joins from `ioc_create` / `ioc_update` sync).
pub fn campaign_stable_id(tag: &str) -> String {
    let t = tag.trim();
    let mut h = Sha256::new();
    h.update(t.as_bytes());
    format!("cmp_{:x}", h.finalize())
}

/// Insert or update **campaigns** for a non-empty **campaign** tag (`first_observed` set once).
pub fn touch_campaign_for_tag(app: &AppHandle, tag: Option<&str>) -> Result<(), String> {
    let Some(t) = tag.map(str::trim) else {
        return Ok(());
    };
    if t.is_empty() {
        return Ok(());
    }
    let id = campaign_stable_id(t);
    let ts = now();
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    g.execute(
        r#"INSERT INTO campaigns (id, name, first_observed, last_observed, description, tags)
           VALUES (?1, ?2, ?3, ?3, NULL, NULL)
           ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             last_observed = excluded.last_observed"#,
        params![&id, t, ts],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

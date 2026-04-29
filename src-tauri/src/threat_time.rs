//! Temporal IOC view: sightings, campaigns, emerging threats.
use chrono::Utc;
use rusqlite::params;
use serde_json::json;
use serde_json::Value;
use rusqlite::OptionalExtension;
use tauri::AppHandle;
use tauri::Manager;
use uuid::Uuid;

use crate::app_data::AppStore;
use crate::campaigns_util::campaign_stable_id;

fn now() -> i64 {
    Utc::now().timestamp()
}

#[tauri::command]
pub fn record_sighting(
    app: AppHandle,
    ioc_id: String,
    source: Option<String>,
    context: Option<String>,
) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    g.execute(
        "INSERT INTO ioc_sightings (id, ioc_id, s_timestamp, s_source, context) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![&id, &ioc_id, &now(), &source, &context],
    )
    .map_err(|e| e.to_string())?;
    Ok(id)
}

#[tauri::command]
pub fn ioc_timeline(app: AppHandle, ioc_id: String) -> Result<Vec<Value>, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut s = g
        .prepare("SELECT id, s_timestamp, s_source, context FROM ioc_sightings WHERE ioc_id = ?1 ORDER BY s_timestamp DESC LIMIT 500")
        .map_err(|e| e.to_string())?;
    let r = s
        .query_map(params![&ioc_id], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "timestamp": r.get::<_, i64>(1)?,
                "source": r.get::<_, Option<String>>(2)?,
                "context": r.get::<_, Option<String>>(3)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    r.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn campaign_track(
    app: AppHandle,
    campaign_name: String,
    recent_days: Option<i64>,
) -> Result<Value, String> {
    let d = recent_days.unwrap_or(7).max(1).min(365);
    let cutoff = now() - d * 86400;
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let pat = format!("%{campaign_name}%");
    let row_id = campaign_stable_id(&campaign_name);
    let campaign_row: Option<Value> = g
        .query_row(
            r#"SELECT id, name, first_observed, last_observed, description, tags FROM campaigns WHERE id = ?1"#,
            [&row_id],
            |r| {
                Ok(json!({
                    "id": r.get::<_, String>(0)?,
                    "name": r.get::<_, String>(1)?,
                    "firstObserved": r.get::<_, Option<i64>>(2)?,
                    "lastObserved": r.get::<_, Option<i64>>(3)?,
                    "description": r.get::<_, Option<String>>(4)?,
                    "tags": r.get::<_, Option<String>>(5)?,
                }))
            },
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let (earliest, latest) = g
        .query_row(
            r#"SELECT MIN(first_seen), MAX(last_seen) FROM iocs WHERE (campaign_tag = ?1 OR campaign_tag LIKE ?2) AND is_false_positive = 0"#,
            params![&campaign_name, &pat],
            |r| Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<i64>>(1)?)),
        )
        .map_err(|e| e.to_string())?;
    let recent_n: i64 = g
        .query_row(
            r#"SELECT COUNT(*) FROM iocs WHERE (campaign_tag = ?1 OR campaign_tag LIKE ?2) AND is_false_positive = 0 AND first_seen >= ?3"#,
            params![&campaign_name, &pat, cutoff],
            |r| r.get(0),
        )
        .unwrap_or(0i64);
    let mut s = g
        .prepare("SELECT id, value, \"type\", first_seen, last_seen FROM iocs WHERE (campaign_tag = ?1 OR campaign_tag LIKE ?2) AND is_false_positive = 0 ORDER BY last_seen DESC LIMIT 2000")
        .map_err(|e| e.to_string())?;
    let r = s
        .query_map(params![&campaign_name, &pat], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "value": r.get::<_, String>(1)?,
                "type": r.get::<_, String>(2)?,
                "firstSeen": r.get::<_, i64>(3)?,
                "lastSeen": r.get::<_, i64>(4)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    let mut rows = vec![];
    for x in r {
        rows.push(x.map_err(|e| e.to_string())?);
    }
    let n = rows.len() as i64;
    Ok(json!({
        "campaign": campaign_name,
        "campaignRow": campaign_row,
        "stats": {
            "iocCount": n,
            "earliestFirstSeen": earliest,
            "latestLastSeen": latest,
            "newFirstSeenInLastNDays": { "days": d, "count": recent_n, "cutoff": cutoff }
        },
        "iocs": rows
    }))
}

#[tauri::command]
pub fn emerging_threats(app: AppHandle, days: Option<i64>) -> Result<Vec<Value>, String> {
    let d = days.unwrap_or(7).max(1).min(365);
    let cutoff = now() - d * 86400;
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut s = g
        .prepare("SELECT id, value, \"type\", first_seen, source FROM iocs WHERE first_seen >= ?1 AND is_false_positive = 0 ORDER BY first_seen DESC LIMIT 500")
        .map_err(|e| e.to_string())?;
    let r = s
        .query_map(params![cutoff], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "value": r.get::<_, String>(1)?,
                "type": r.get::<_, String>(2)?,
                "firstSeen": r.get::<_, i64>(3)?,
                "source": r.get::<_, Option<String>>(4)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    r.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn campaign_compare(
    app: AppHandle,
    campaign_a: String,
    campaign_b: String,
) -> Result<Value, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut a_set = std::collections::HashSet::new();
    let mut b_set = std::collections::HashSet::new();
    {
        let mut s = g
            .prepare("SELECT value FROM iocs WHERE (campaign_tag = ?1 OR campaign_tag LIKE ?2) AND is_false_positive = 0")
            .map_err(|e| e.to_string())?;
        let pat = format!("%{campaign_a}%");
        let r = s
            .query_map(params![&campaign_a, &pat], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        for x in r {
            a_set.insert(x.map_err(|e| e.to_string())?);
        }
    }
    {
        let mut s = g
            .prepare("SELECT value FROM iocs WHERE (campaign_tag = ?1 OR campaign_tag LIKE ?2) AND is_false_positive = 0")
            .map_err(|e| e.to_string())?;
        let pat = format!("%{campaign_b}%");
        let r = s
            .query_map(params![&campaign_b, &pat], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        for x in r {
            b_set.insert(x.map_err(|e| e.to_string())?);
        }
    }
    let inter: Vec<_> = a_set.intersection(&b_set).cloned().collect();
    let only_a: Vec<_> = a_set.difference(&b_set).cloned().collect();
    let only_b: Vec<_> = b_set.difference(&a_set).cloned().collect();
    let _ = app;
    Ok(json!({
        "campaignA": campaign_a,
        "campaignB": campaign_b,
        "intersection": inter,
        "onlyA": only_a,
        "onlyB": only_b,
    }))
}

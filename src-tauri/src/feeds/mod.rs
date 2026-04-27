//! Configured threat feeds (MISP, TAXII, OTX, OpenCTI) and manual poll.
mod misp_cursor;
mod opencti;
pub mod scheduler;

use chrono::Utc;
use rusqlite::params;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;
use tauri::AppHandle;
use tauri::Manager;
use uuid::Uuid;

use crate::api::secrets::merge_api_keys;
use crate::api::HttpApiState;
use crate::app_data::AppStore;
use crate::ioc::extract_from_stix;
use crate::ioc::import_otx_subscribed_pulses;
use crate::ioc::ioc_import_misp;
use crate::ioc::ioc_import_stix;
use crate::settings::load_settings;

use misp_cursor::{misp_next_cursor_json, misp_request_body_with_timestamp, misp_start_timestamp};

fn now() -> i64 {
    Utc::now().timestamp()
}

fn require_http_ok(r: &Value) -> Result<(), String> {
    let st = r
        .get("status")
        .and_then(|s| s.as_u64().or_else(|| s.as_i64().map(|i| i as u64)))
        .ok_or("missing HTTP status in response")?;
    if st < 200 || st > 299 {
        return Err(format!("HTTP {st}"));
    }
    Ok(())
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FeedRow {
    pub id: String,
    pub name: String,
    pub ftype: String,
    pub url: Option<String>,
    pub api_key_ref: Option<String>,
    pub poll_interval_minutes: Option<i32>,
    pub last_poll_time: Option<i64>,
    pub last_error: Option<String>,
    pub enabled: i32,
    pub filter_tags: Option<String>,
    /// JSON blob (e.g. MISP `nextTimestamp` for incremental `restSearch`).
    pub cursor_json: Option<String>,
    pub last_failure_time: Option<i64>,
    pub consecutive_failures: i32,
}

fn row(m: &rusqlite::Connection, id: &str) -> Result<FeedRow, String> {
    m.query_row(
        "SELECT id, name, ftype, url, api_key_ref, poll_interval_minutes, last_poll_time, last_error, enabled, filter_tags, cursor_json, last_failure_time, consecutive_failures FROM feeds WHERE id = ?1",
        [id],
        |r| {
            Ok(FeedRow {
                id: r.get(0)?,
                name: r.get(1)?,
                ftype: r.get(2)?,
                url: r.get(3)?,
                api_key_ref: r.get(4)?,
                poll_interval_minutes: r.get(5)?,
                last_poll_time: r.get(6)?,
                last_error: r.get(7)?,
                enabled: r.get(8)?,
                filter_tags: r.get(9)?,
                cursor_json: r.get(10)?,
                last_failure_time: r.get(11)?,
                consecutive_failures: r.get(12)?,
            })
        },
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn add_feed(
    app: AppHandle,
    name: String,
    ftype: String,
    url: Option<String>,
    api_key_ref: Option<String>,
    poll_interval_minutes: Option<i32>,
    filter_tags: Option<String>,
) -> Result<FeedRow, String> {
    let id = Uuid::new_v4().to_string();
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    g.execute(
        "INSERT INTO feeds (id, name, ftype, url, api_key_ref, poll_interval_minutes, last_error, enabled, filter_tags, cursor_json, last_failure_time, consecutive_failures) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 1, ?7, NULL, NULL, 0)",
        params![&id, &name, &ftype, &url, &api_key_ref, &poll_interval_minutes, &filter_tags],
    )
    .map_err(|e| e.to_string())?;
    row(&g, &id)
}

#[tauri::command]
pub fn list_feeds(app: AppHandle) -> Result<Vec<FeedRow>, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut s = g
        .prepare("SELECT id, name, ftype, url, api_key_ref, poll_interval_minutes, last_poll_time, last_error, enabled, filter_tags, cursor_json, last_failure_time, consecutive_failures FROM feeds ORDER BY name")
        .map_err(|e| e.to_string())?;
    let r = s
        .query_map([], |r| {
            Ok(FeedRow {
                id: r.get(0)?,
                name: r.get(1)?,
                ftype: r.get(2)?,
                url: r.get(3)?,
                api_key_ref: r.get(4)?,
                poll_interval_minutes: r.get(5)?,
                last_poll_time: r.get(6)?,
                last_error: r.get(7)?,
                enabled: r.get(8)?,
                filter_tags: r.get(9)?,
                cursor_json: r.get(10)?,
                last_failure_time: r.get(11)?,
                consecutive_failures: r.get(12)?,
            })
        })
        .map_err(|e| e.to_string())?;
    r.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_feed_status(app: AppHandle, id: String) -> Result<FeedRow, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    row(&g, &id)
}

fn wrap_misp_attributes(body: &Value) -> String {
    if let Some(ev) = body.get("Event") {
        return serde_json::to_string(&json!({ "Event": ev })).unwrap_or_else(|_| "{}".into());
    }
    if let Some(arr) = body.get("response") {
        if let Some(e) = arr.get("Event") {
            return serde_json::to_string(&json!({ "Event": e })).unwrap_or_else(|_| "{}".into());
        }
        if let Some(attr) = arr.get("Attribute") {
            return serde_json::to_string(&json!({ "Event": { "id": "0", "info": "feed", "Attribute": attr } })).unwrap_or_else(|_| "{}".into());
        }
    }
    body.to_string()
}

/// Result of one poll: JSON payload and optional new `cursor_json` (MISP only; `None` = keep existing).
type PollOut = (Value, Option<String>);

async fn run_feed_poll(
    app: AppHandle,
    http: &HttpApiState,
    f: &FeedRow,
    feed_id: &str,
    key: &str,
    base: &str,
    t: i64,
) -> Result<PollOut, String> {
    match f.ftype.to_lowercase().as_str() {
        "misp" => {
            let url = if base.ends_with('/') {
                format!("{}attributes/restSearch", base)
            } else {
                format!("{}/attributes/restSearch", base)
            };
            let start_ts = misp_start_timestamp(f.cursor_json.as_deref(), t);
            let body = misp_request_body_with_timestamp(start_ts);
            let r = http
                .run_request(
                    &app,
                    url,
                    "POST".into(),
                    Some(
                        [
                            ("Authorization".to_string(), key.to_string()),
                            (
                                "Content-Type".to_string(),
                                "application/json".to_string(),
                            ),
                            ("Accept".to_string(), "application/json".to_string()),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                    Some(body),
                    "misp".into(),
                )
                .await?;
            require_http_ok(&r)?;
            let bodyv = r.get("body").cloned().unwrap_or(Value::Null);
            let wrapped = wrap_misp_attributes(&bodyv);
            let imp = ioc_import_misp(app.clone(), wrapped, None, None, None)?;
            let summary = serde_json::to_value(imp).map_err(|e| e.to_string())?;
            let new_cursor = misp_next_cursor_json(f.cursor_json.as_deref(), &bodyv, t);
            Ok((
                json!({ "feedId": feed_id, "format": "misp", "import": summary, "mispStartTimestamp": start_ts }),
                Some(new_cursor),
            ))
        }
        "otx" => {
            let url = format!("{}/api/v1/pulses/subscribed", base.trim_end_matches('/'));
            let mut h = std::collections::HashMap::new();
            h.insert("X-OTX-API-KEY".to_string(), key.to_string());
            let r = http
                .run_request(&app, url, "GET".into(), Some(h), None, "otx".into())
                .await?;
            require_http_ok(&r)?;
            let bodyv = r.get("body").cloned().unwrap_or(Value::Null);
            let source = f.name.trim();
            if source.is_empty() {
                return Err("OTX feed has empty name (used as IOC source)".into());
            }
            let imp = import_otx_subscribed_pulses(&app, &bodyv, source)?;
            let summary = serde_json::to_value(&imp).map_err(|e| e.to_string())?;
            Ok((
                json!({ "feedId": feed_id, "format": "otx", "import": summary, "response": r }),
                None,
            ))
        }
        "taxii2" | "taxii" => {
            let url = if base.contains("/objects") {
                base.to_string()
            } else {
                format!("{}/objects/?limit=100", base.trim_end_matches('/'))
            };
            let mut h = std::collections::HashMap::new();
            h.insert(
                "Accept".to_string(),
                "application/taxii+json;version=2.1".to_string(),
            );
            h.insert("Authorization".to_string(), format!("Bearer {key}"));
            let r = http
                .run_request(&app, url, "GET".into(), Some(h), None, "taxii2".into())
                .await?;
            require_http_ok(&r)?;
            let b = r.get("body").cloned().unwrap_or(Value::Null);
            let s = b.to_string();
            let _e = extract_from_stix(&s).map_err(|e| e.to_string())?;
            let imp = ioc_import_stix(
                app.clone(),
                s,
                Some("taxii2".into()),
                None,
                None,
            )?;
            let summary = serde_json::to_value(imp).map_err(|e| e.to_string())?;
            Ok((
                json!({ "feedId": feed_id, "format": "taxii2", "import": summary }),
                None,
            ))
        }
        "opencti" | "open_cti" => {
            let (out, cur) = opencti::poll_opencti_full(
                &app, http, f, feed_id, base, key,
            )
            .await?;
            Ok((out, cur))
        }
        _ => Err("unknown feed ftype: use misp, otx, taxii2, opencti".into()),
    }
}

/// Shared by the `poll_feed` command and the background feed scheduler.
pub async fn run_poll_feed_work(
    app: &AppHandle,
    http: &HttpApiState,
    feed_id: &str,
) -> Result<Value, String> {
    let st0 = app.state::<AppStore>();
    let f = {
        let g = st0.db.lock().map_err(|e| e.to_string())?;
        row(&g, feed_id)?
    };
    if f.enabled == 0 {
        return Err("feed is disabled".into());
    }
    let base = f.url.as_deref().ok_or("feed has no url")?.trim();
    if base.is_empty() {
        return Err("empty url".into());
    }
    let settings = load_settings(app)?;
    let keys = merge_api_keys(&settings)?;
    let kref = f.api_key_ref.as_deref().unwrap_or("misp");
    let key = keys
        .get(kref)
        .or_else(|| keys.get("opencti"))
        .or_else(|| keys.get("otx"))
        .or_else(|| keys.get("alienvault"))
        .or_else(|| keys.get("misp"))
        .ok_or_else(|| format!("no API key for ref {kref} in settings or .api_keys.json"))?
        .clone();
    let t = now();
    let attempt: Result<PollOut, String> = run_feed_poll(
        app.clone(),
        http,
        &f,
        feed_id,
        &key,
        base,
        t,
    )
    .await;

    {
        let st = app.state::<AppStore>();
        let g = st.db.lock().map_err(|e| e.to_string())?;
        match &attempt {
            Ok((_, new_c)) => {
                let c = new_c.clone().or(f.cursor_json.clone());
                g.execute(
                    "UPDATE feeds SET last_poll_time = ?1, last_error = NULL, last_failure_time = NULL, consecutive_failures = 0, cursor_json = ?2 WHERE id = ?3",
                    params![t, c, feed_id],
                )
                .map_err(|e| e.to_string())?;
            }
            Err(msg) => {
                g.execute(
                    "UPDATE feeds SET last_error = ?1, last_failure_time = ?2, consecutive_failures = consecutive_failures + 1 WHERE id = ?3",
                    params![msg, t, feed_id],
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }

    attempt.map(|(o, _)| o)
}

#[tauri::command]
pub async fn poll_feed(
    app: AppHandle,
    http: tauri::State<'_, HttpApiState>,
    feed_id: String,
) -> Result<Value, String> {
    run_poll_feed_work(&app, &*http, &feed_id).await
}

#[tauri::command]
pub fn feed_search(
    app: AppHandle,
    source: String,
    value_contains: Option<String>,
    limit: Option<i64>,
) -> Result<Vec<serde_json::Value>, String> {
    let lim = limit.unwrap_or(100).min(2_000).max(1);
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let q = "SELECT id, value, \"type\" AS ioc_type, source FROM iocs WHERE source = ?1 OR source LIKE ?2 ORDER BY last_seen DESC LIMIT ?3";
    let pat = value_contains
        .as_deref()
        .map(|s| format!("%{}%", s))
        .unwrap_or_else(|| "%".into());
    let mut stmt = g.prepare(q).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params![&source, &pat, &lim], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?,
                "value": r.get::<_, String>(1)?,
                "iocType": r.get::<_, String>(2)?,
                "source": r.get::<_, Option<String>>(3)?,
            }))
        })
        .map_err(|e| e.to_string())?;
    let mut v = vec![];
    for row in rows {
        v.push(row.map_err(|e| e.to_string())?);
    }
    Ok(v)
}

#[tauri::command]
pub fn feed_stats(app: AppHandle) -> Result<Value, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut stmt = g
        .prepare("SELECT coalesce(source,'(null)'), \"type\", count(*) FROM iocs GROUP BY 1, 2")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok(json!({ "source": r.get::<_, String>(0)?, "type": r.get::<_, String>(1)?, "count": r.get::<_, i64>(2)? }))
        })
        .map_err(|e| e.to_string())?;
    let mut a = vec![];
    for row in rows {
        a.push(row.map_err(|e| e.to_string())?);
    }
    Ok(json!({ "bySourceAndType": a }))
}

/// Per-feed health: last success, failures, and staleness vs. poll interval.
#[tauri::command]
pub fn feed_health(app: AppHandle) -> Result<Value, String> {
    let t = now();
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut stmt = g
        .prepare("SELECT id, name, ftype, enabled, poll_interval_minutes, last_poll_time, last_error, last_failure_time, consecutive_failures FROM feeds ORDER BY name")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            let id: String = r.get(0)?;
            let name: String = r.get(1)?;
            let ftype: String = r.get(2)?;
            let enabled: i32 = r.get(3)?;
            let poll_interval: Option<i32> = r.get(4)?;
            let last_poll: Option<i64> = r.get(5)?;
            let last_error: Option<String> = r.get(6)?;
            let last_fail: Option<i64> = r.get(7)?;
            let cons: i32 = r.get(8)?;
            let staleness = last_poll.map(|lp| t - lp);
            let interval_sec = poll_interval
                .filter(|&i| i > 0)
                .map(|i| i as i64 * 60);
            let is_stale = if enabled == 1 {
                match (interval_sec, last_poll) {
                    (Some(is), Some(lp)) => t - lp > is + (is / 2),
                    _ => false,
                }
            } else {
                false
            };
            let is_unhealthy = last_error.is_some()
                || cons >= 3
                || (enabled == 1 && is_stale);
            Ok(json!({
                "feedId": id,
                "name": name,
                "ftype": ftype,
                "enabled": enabled,
                "pollIntervalMinutes": poll_interval,
                "lastPollTime": last_poll,
                "lastError": last_error,
                "lastFailureTime": last_fail,
                "consecutiveFailures": cons,
                "stalenessSeconds": staleness,
                "isStale": is_stale,
                "isUnhealthy": is_unhealthy
            }))
        })
        .map_err(|e| e.to_string())?;
    let mut a = vec![];
    for row in rows {
        a.push(row.map_err(|e| e.to_string())?);
    }
    Ok(json!({ "asOf": t, "feeds": a }))
}

/// Counts and false-positive share by IOC `source` (feeds, enrichers, user).
#[tauri::command]
pub fn source_reputation(app: AppHandle) -> Result<Value, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut stmt = g
        .prepare(
            r#"SELECT coalesce(source, "(null)"), count(*), 
            sum(CASE WHEN is_false_positive = 1 THEN 1 ELSE 0 END) AS fp
            FROM iocs GROUP BY 1 ORDER BY count(*) DESC LIMIT 200"#,
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            let source: String = r.get(0)?;
            let total: i64 = r.get(1)?;
            let fp: i64 = r.get(2)?; // can be null if no rows? sum returns 0
            let fp = fp.max(0);
            let fp_rate = if total > 0 {
                fp as f64 / (total as f64)
            } else {
                0.0
            };
            let rep = 1.0f64 - fp_rate;
            Ok(json!({
                "source": source,
                "total": total,
                "falsePositives": fp,
                "fpRate": fp_rate,
                "reputationScore": rep
            }))
        })
        .map_err(|e| e.to_string())?;
    let mut a = vec![];
    for row in rows {
        a.push(row.map_err(|e| e.to_string())?);
    }
    Ok(json!({ "bySource": a }))
}

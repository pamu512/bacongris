//! IOC relationships, pivot, path, and simple pivot suggestions.
use std::collections::{HashMap, VecDeque};

use chrono::Utc;
use rusqlite::params;
use serde_json::json;
use serde_json::Value;
use tauri::AppHandle;
use tauri::Manager;
use uuid::Uuid;

use crate::app_data::AppStore;

fn now() -> i64 {
    Utc::now().timestamp()
}

/// Insert a relationship (IDs must be existing iocs).
#[tauri::command]
pub fn add_ioc_relationship(
    app: AppHandle,
    source_ioc: String,
    target_ioc: String,
    relationship_type: String,
    source_data: Option<String>,
    confidence: Option<i32>,
) -> Result<String, String> {
    let id = Uuid::new_v4().to_string();
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    g.execute(
        "INSERT INTO ioc_relationships (id, source_ioc, target_ioc, relationship_type, source_data, confidence, first_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![&id, &source_ioc, &target_ioc, &relationship_type, &source_data, &confidence, now()],
    )
    .map_err(|e| e.to_string())?;
    Ok(id)
}

fn pivot_query(
    g: &rusqlite::Connection,
    ioc_id: &str,
    relationship_type: &Option<String>,
    lim: i64,
) -> Result<Vec<Value>, String> {
    let mut v = vec![];
    if let Some(rt) = relationship_type.as_ref().filter(|s| !s.trim().is_empty()) {
        let mut s = g
            .prepare(
                r#"SELECT id, source_ioc, target_ioc, relationship_type, confidence, first_seen, source_data
               FROM ioc_relationships WHERE
               (source_ioc = ?1 OR target_ioc = ?1) AND relationship_type = ?2 LIMIT ?3"#,
            )
            .map_err(|e| e.to_string())?;
        let rows = s
            .query_map(params![&ioc_id, &rt, &lim], |r| {
                let s0: String = r.get(1)?;
                let t0: String = r.get(2)?;
                let other = if s0 == ioc_id { t0 } else { s0 };
                Ok(json!({
                    "id": r.get::<_, String>(0)?,
                    "otherIocId": other,
                    "relationshipType": r.get::<_, String>(3)?,
                    "confidence": r.get::<_, Option<i32>>(4)?,
                    "firstSeen": r.get::<_, Option<i64>>(5)?,
                    "sourceData": r.get::<_, Option<String>>(6)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for x in rows {
            v.push(x.map_err(|e| e.to_string())?);
        }
    } else {
        let mut s = g
            .prepare(
                r#"SELECT id, source_ioc, target_ioc, relationship_type, confidence, first_seen, source_data
               FROM ioc_relationships WHERE
               (source_ioc = ?1 OR target_ioc = ?1) LIMIT ?2"#,
            )
            .map_err(|e| e.to_string())?;
        let rows = s
            .query_map(params![&ioc_id, &lim], |r| {
                let s0: String = r.get(1)?;
                let t0: String = r.get(2)?;
                let other = if s0 == ioc_id { t0 } else { s0 };
                Ok(json!({
                    "id": r.get::<_, String>(0)?,
                    "otherIocId": other,
                    "relationshipType": r.get::<_, String>(3)?,
                    "confidence": r.get::<_, Option<i32>>(4)?,
                    "firstSeen": r.get::<_, Option<i64>>(5)?,
                    "sourceData": r.get::<_, Option<String>>(6)?,
                }))
            })
            .map_err(|e| e.to_string())?;
        for x in rows {
            v.push(x.map_err(|e| e.to_string())?);
        }
    }
    Ok(v)
}

/// Related IOCs (either direction) with optional type filter.
#[tauri::command]
pub fn ioc_pivot(
    app: AppHandle,
    ioc_id: String,
    relationship_type: Option<String>,
    limit: Option<i64>,
) -> Result<Vec<Value>, String> {
    let lim = limit.unwrap_or(50).min(1_000).max(1);
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    pivot_query(&g, &ioc_id, &relationship_type, lim)
}

/// BFS shortest path between two ioc id nodes (undirected for search).
#[tauri::command]
pub fn find_path(
    app: AppHandle,
    from_ioc: String,
    to_ioc: String,
    max_depth: Option<i64>,
) -> Result<Value, String> {
    let max_d = max_depth.unwrap_or(8).min(20).max(1) as usize;
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    {
        let mut s = g
            .prepare("SELECT source_ioc, target_ioc FROM ioc_relationships")
            .map_err(|e| e.to_string())?;
        let r = s
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| e.to_string())?;
        for e in r {
            let (a, b) = e.map_err(|e| e.to_string())?;
            adj.entry(a.clone()).or_default().push(b.clone());
            adj.entry(b).or_default().push(a);
        }
    }
    if from_ioc == to_ioc {
        return Ok(json!({ "path": [ from_ioc ], "length": 0 }));
    }
    let mut q = VecDeque::new();
    let mut parent: HashMap<String, String> = HashMap::new();
    let mut found = false;
    q.push_back((from_ioc.clone(), 0usize));
    parent.insert(from_ioc.clone(), from_ioc.clone());
    while let Some((u, d)) = q.pop_front() {
        if d > max_d {
            break;
        }
        if u == to_ioc {
            found = true;
            break;
        }
        if let Some(nbrs) = adj.get(&u) {
            for w in nbrs {
                if !parent.contains_key(w) {
                    parent.insert(w.clone(), u.clone());
                    q.push_back((w.clone(), d + 1));
                }
            }
        }
    }
    if !found {
        return Ok(json!({ "path": Value::Null, "length": Value::Null, "message": "no path within depth" }));
    }
    let mut path = vec![];
    let mut cur = to_ioc.clone();
    loop {
        path.push(cur.clone());
        if cur == from_ioc {
            break;
        }
        cur = parent
            .get(&cur)
            .ok_or_else(|| "reconstruct path".to_string())?
            .clone();
    }
    path.reverse();
    Ok(json!({ "path": path, "length": (path.len() as i64) - 1 }))
}

fn pivot_rationale(row: &Value) -> String {
    let rt = row
        .get("relationshipType")
        .and_then(|v| v.as_str())
        .unwrap_or("related");
    let src = row
        .get("sourceData")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let base: &'static str = match rt {
        "resolves_to" => {
            "Direct DNS or resolution link — follow to shared hosting or C2."
        }
        "subdomain_of" => "Subdomain→apex (DNS) — map operator or shared control of the parent zone.",
        "announced_in" => "IP is announced in this ASN (BGP) — expand to AS peers, peers, and prefix policies.",
        "routed_within" | "routed_in" | "contained_in" => {
            "Routed within this prefix — blocklist or geolocate the netblock."
        }
        "presents_cert" | "served_cert" => {
            "Certificate presented on this name — pivot to other hosts reusing the same cert hash."
        }
        "delivered_payload" => "URL or page delivered this file (abuse.ch) — chain download and payload analysis.",
        "submitted_as" | "known_as" => "MalwareBazaar filename for this sample — search related submissions.",
        "same_as" => "Same object under another hash form — treat as one sample across tools.",
        _ => "Graph edge in your case scope — open the related IOC for full context.",
    };
    if src.is_empty() {
        base.to_string()
    } else {
        format!("{base} (source: {src})")
    }
}

/// Ranked next-hop suggestions from relationships + short **rationale** for the model.
#[tauri::command]
pub fn suggest_pivots(
    _app: AppHandle,
    ioc_id: String,
    limit: Option<i64>,
) -> Result<Vec<Value>, String> {
    let lim = limit.unwrap_or(10).min(50).max(1) as i64;
    let st = _app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let rows = pivot_query(&g, &ioc_id, &None, 100)?;
    let mut scored: Vec<(i64, Value)> = vec![];
    for r in rows {
        if r.get("otherIocId").and_then(|x| x.as_str()).is_some() {
            let conf = r.get("confidence").and_then(|c| c.as_i64()).unwrap_or(50);
            let fs = r.get("firstSeen").and_then(|c| c.as_i64()).unwrap_or(0);
            let score = conf * 10 + fs;
            scored.push((score, r));
        }
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    let out: Vec<Value> = scored
        .into_iter()
        .take(lim as usize)
        .map(|(_, v)| {
            let rat = pivot_rationale(&v);
            let mut out = v;
            if let Some(m) = out.as_object_mut() {
                m.insert("rationale".to_string(), json!(rat));
            }
            out
        })
        .collect();
    Ok(out)
}

#[tauri::command]
pub fn campaign_analysis(app: AppHandle, campaign_tag: String) -> Result<Value, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut s = g
        .prepare(r#"SELECT id, value, "type" AS t FROM iocs WHERE (campaign_tag = ?1 OR campaign_tag LIKE ?2) AND is_false_positive = 0 LIMIT 5000"#)
        .map_err(|e| e.to_string())?;
    let pat = format!("%{campaign_tag}%");
    let r = s
        .query_map(params![&campaign_tag, &pat], |r| {
            Ok(json!({ "id": r.get::<_, String>(0)?, "value": r.get::<_, String>(1)?, "type": r.get::<_, String>(2)? }))
        })
        .map_err(|e| e.to_string())?;
    let mut a = vec![];
    for x in r {
        a.push(x.map_err(|e| e.to_string())?);
    }
    let n = a.len() as i64;
    Ok(json!({ "campaign": campaign_tag, "count": n, "iocs": a }))
}

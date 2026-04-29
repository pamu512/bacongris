//! Local IOC table (SQLite): CRUD and STIX / MISP import.
mod maintenance;
mod mitre;
mod misp;
mod otx_import;
mod opencti_import;
mod stix;
mod stix_export;

pub(crate) use otx_import::import_otx_subscribed_pulses;
pub(crate) use opencti_import::import_from_opencti_stix_cyber_observables;
pub use misp::extract_from_misp_event;
pub use stix::extract_from_stix;
pub use maintenance::IocMaintenanceResult;

use chrono::Utc;
use rusqlite::params;
use rusqlite::OptionalExtension;
use serde::Serialize;
use tauri::AppHandle;
use tauri::Manager;
use uuid::Uuid;

use crate::app_data::AppStore;
use crate::campaigns_util::touch_campaign_for_tag;
use crate::audit::append_audit;
use misp::MispSnapshot;
use stix::StixSnapshot;
use mitre::mitre_json_stored_to_vec;

const RAW_JSON_MAX: usize = 512 * 1024;

/// Profile mode for ioc_search WHERE clause: all rows / scoped+global / global-only
const PF_ALL: i64 = 0;
const PF_SCOPED: i64 = 1;
const PF_NULL_ONLY: i64 = 2;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IocRow {
    pub id: String,
    pub value: String,
    pub ioc_type: String,
    pub source: Option<String>,
    pub confidence: Option<i32>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub campaign_tag: Option<String>,
    pub raw_json: Option<String>,
    pub profile_id: Option<String>,
    /// Unix seconds; when set and in the past, row is removed by maintenance.
    pub valid_until: Option<i64>,
    #[serde(default)]
    pub is_false_positive: bool,
    /// MITRE ATT&CK techniques / tactics (e.g. T1059.001, TA0001).
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IocImportResult {
    pub inserted: u32,
    pub updated: u32,
    pub skipped: u32,
    pub source: String,
}

fn now() -> i64 {
    Utc::now().timestamp()
}

fn truncate_raw(s: Option<String>) -> Option<String> {
    s.map(|t| {
        if t.len() > RAW_JSON_MAX {
            t.chars().take(RAW_JSON_MAX).collect()
        } else {
            t
        }
    })
}

/// `explicit` = `profileId` from the request; if missing/empty, use active profile.
fn resolve_profile(
    app: &AppHandle,
    explicit: Option<String>,
) -> Result<Option<String>, String> {
    if let Some(p) = explicit {
        let t = p.trim();
        if t.is_empty() {
            return active_profile_id(app);
        }
        return Ok(Some(t.to_string()));
    }
    active_profile_id(app)
}

fn active_profile_id(app: &AppHandle) -> Result<Option<String>, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    g.query_row("SELECT active_profile_id FROM app_state WHERE id = 1", [], |r| {
        r.get::<_, Option<String>>(0)
    })
    .map_err(|e| e.to_string())
}

fn profile_exists(conn: &rusqlite::Connection, profile: &str) -> Result<bool, String> {
    let c: u32 = conn
        .query_row(
            "SELECT count(*) FROM profiles WHERE id = ?1",
            [profile],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(c > 0)
}

fn ioc_get_by_id(conn: &rusqlite::Connection, id: &str) -> Result<IocRow, String> {
    conn.query_row(
        r#"SELECT id, value, "type" AS ioc_type, source, confidence, first_seen, last_seen, campaign_tag, raw_json, profile_id, valid_until, is_false_positive, mitre_techniques
           FROM iocs WHERE id = ?1"#,
        [id],
        |r| {
            let mts: String = r.get(12)?;
            let ifp: i64 = r.get(11)?;
            Ok(IocRow {
                id: r.get(0)?,
                value: r.get(1)?,
                ioc_type: r.get(2)?,
                source: r.get(3)?,
                confidence: r.get(4)?,
                first_seen: r.get(5)?,
                last_seen: r.get(6)?,
                campaign_tag: r.get(7)?,
                raw_json: r.get(8)?,
                profile_id: r.get(9)?,
                valid_until: r.get(10)?,
                is_false_positive: ifp != 0,
                mitre_techniques: mitre_json_stored_to_vec(&mts),
            })
        },
    )
    .map_err(|e| e.to_string())
}

fn like_substring(s: &str) -> String {
    format!(
        "%{}%",
        s.replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    )
}

/// `None` = leave unchanged in UPDATE; `Some(Err))` = validation error; `Some(Ok(x))` = new value
fn require_nonempty_opt(
    field: &str,
    v: &Option<String>,
) -> Result<Option<String>, String> {
    if v.is_none() {
        return Ok(None);
    }
    let t = v.as_deref().unwrap().trim();
    if t.is_empty() {
        return Err(format!("{field} cannot be set to empty"));
    }
    Ok(Some(t.to_string()))
}

/// Upsert by (value, type, profile). Returns (row, was_update).
fn opt_bool_to_sql_i64(b: Option<bool>) -> Option<i64> {
    b.map(|x| if x { 1i64 } else { 0i64 })
}

/// `mitre_stored` / `is_false_positive` `None` on **update** = no change. On **insert** defaults apply.
pub(crate) fn upsert_ioc(
    conn: &rusqlite::Connection,
    value: &str,
    ioc_type: &str,
    source: &Option<String>,
    confidence: Option<i32>,
    campaign_tag: &Option<String>,
    raw_json: Option<String>,
    prof: &Option<String>,
    valid_until: Option<i64>,
    is_false_positive: Option<bool>,
    mitre_stored: Option<String>,
) -> Result<(IocRow, bool), String> {
    let ts = now();
    let ifp_i = opt_bool_to_sql_i64(is_false_positive);
    let existing: Option<String> = conn
        .query_row(
            r#"SELECT id FROM iocs WHERE value = ?1 AND "type" = ?2
               AND ((profile_id IS NULL AND ?3 IS NULL) OR (profile_id = ?3))"#,
            params![value, ioc_type, prof],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    if let Some(id) = existing {
        conn.execute(
            r#"UPDATE iocs SET last_seen = ?1, source = COALESCE(?2, source),
            confidence = COALESCE(?3, confidence), campaign_tag = COALESCE(?4, campaign_tag),
            raw_json = COALESCE(?5, raw_json),
            valid_until = COALESCE(?6, valid_until),
            is_false_positive = COALESCE(?7, is_false_positive),
            mitre_techniques = COALESCE(?8, mitre_techniques) WHERE id = ?9"#,
            params![
                ts,
                source,
                confidence,
                campaign_tag,
                &raw_json,
                &valid_until,
                &ifp_i,
                &mitre_stored,
                &id
            ],
        )
        .map_err(|e| e.to_string())?;
        return Ok((ioc_get_by_id(conn, &id)?, true));
    }
    let new_id = Uuid::new_v4().to_string();
    let m_ins = mitre_stored
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("[]");
    let ifp_ins: i64 = is_false_positive.unwrap_or(false) as i64;
    conn
        .execute(
            r#"INSERT INTO iocs (id, value, "type", source, confidence, first_seen, last_seen, campaign_tag, raw_json, profile_id, valid_until, is_false_positive, mitre_techniques)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"#,
            params![
                &new_id,
                value,
                ioc_type,
                source,
                &confidence,
                ts,
                ts,
                campaign_tag,
                &raw_json,
                prof,
                &valid_until,
                &ifp_ins,
                m_ins,
            ],
        )
        .map_err(|e| e.to_string())?;
    Ok((ioc_get_by_id(conn, &new_id)?, false))
}

/// Create or re-touch an IOC (upsert on value + type + profile).
#[tauri::command]
pub fn ioc_create(
    app: AppHandle,
    value: String,
    ioc_type: String,
    source: Option<String>,
    confidence: Option<i32>,
    campaign_tag: Option<String>,
    raw_json: Option<String>,
    profile_id: Option<String>,
    valid_until: Option<i64>,
    is_false_positive: Option<bool>,
    mitre_techniques: Option<Vec<String>>,
) -> Result<IocRow, String> {
    let v = value.trim();
    if v.is_empty() {
        return Err("value is required".into());
    }
    let t = ioc_type.trim();
    if t.is_empty() {
        return Err("ioc_type is required".into());
    }
    let prof = resolve_profile(&app, profile_id.clone())?;
    {
        if let Some(ref p) = prof {
            let st = app.state::<AppStore>();
            let g = st.db.lock().map_err(|e| e.to_string())?;
            if !profile_exists(&g, p)? {
                return Err("profile_id is not a valid profile".into());
            }
        }
    }
    let raw = truncate_raw(raw_json);
    let m_stored = mitre::mitre_vec_to_json_stored(mitre_techniques)?;
    let st = app.state::<AppStore>();
    let row = {
        let g = st.db.lock().map_err(|e| e.to_string())?;
        let (row, _) = upsert_ioc(
            &g,
            v,
            t,
            &source,
            confidence,
            &campaign_tag,
            raw,
            &prof,
            valid_until,
            is_false_positive,
            m_stored,
        )?;
        row
    };
    let _ = touch_campaign_for_tag(&app, row.campaign_tag.as_deref());
    let _ = append_audit(
        &app,
        "ioc_create",
        serde_json::json!({ "id": &row.id, "value": v, "iocType": t }),
    );
    Ok(row)
}

#[tauri::command]
pub fn ioc_update(
    app: AppHandle,
    id: String,
    value: Option<String>,
    ioc_type: Option<String>,
    source: Option<String>,
    confidence: Option<i32>,
    campaign_tag: Option<String>,
    first_seen: Option<i64>,
    last_seen: Option<i64>,
    raw_json: Option<String>,
    valid_until: Option<i64>,
    clear_valid_until: Option<bool>,
    is_false_positive: Option<bool>,
    mitre_techniques: Option<Vec<String>>,
) -> Result<IocRow, String> {
    let v_bind = require_nonempty_opt("value", &value)?;
    let t_bind = require_nonempty_opt("ioc_type", &ioc_type)?;
    let m_stored = mitre::mitre_vec_to_json_stored(mitre_techniques)?;
    let ifp = opt_bool_to_sql_i64(is_false_positive);
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    g.query_row("SELECT 1 FROM iocs WHERE id = ?1", [&id], |_| Ok(()))
        .optional()
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "IOC not found".to_string())?;
    if clear_valid_until == Some(true) {
        g.execute(
            r#"UPDATE iocs SET
          value = COALESCE(?1, value),
          "type" = COALESCE(?2, "type"),
          source = COALESCE(?3, source),
          confidence = COALESCE(?4, confidence),
          campaign_tag = COALESCE(?5, campaign_tag),
          first_seen = COALESCE(?6, first_seen),
          last_seen = COALESCE(?7, last_seen),
          raw_json = COALESCE(?8, raw_json),
          valid_until = NULL,
          is_false_positive = COALESCE(?9, is_false_positive),
          mitre_techniques = COALESCE(?10, mitre_techniques)
          WHERE id = ?11"#,
            params![
                v_bind,
                t_bind,
                &source,
                &confidence,
                &campaign_tag,
                first_seen,
                last_seen,
                truncate_raw(raw_json),
                &ifp,
                &m_stored,
                &id
            ],
        )
        .map_err(|e| e.to_string())?;
    } else {
        g.execute(
            r#"UPDATE iocs SET
          value = COALESCE(?1, value),
          "type" = COALESCE(?2, "type"),
          source = COALESCE(?3, source),
          confidence = COALESCE(?4, confidence),
          campaign_tag = COALESCE(?5, campaign_tag),
          first_seen = COALESCE(?6, first_seen),
          last_seen = COALESCE(?7, last_seen),
          raw_json = COALESCE(?8, raw_json),
          valid_until = COALESCE(?9, valid_until),
          is_false_positive = COALESCE(?10, is_false_positive),
          mitre_techniques = COALESCE(?11, mitre_techniques)
          WHERE id = ?12"#,
            params![
                v_bind,
                t_bind,
                &source,
                &confidence,
                &campaign_tag,
                first_seen,
                last_seen,
                truncate_raw(raw_json),
                &valid_until,
                &ifp,
                &m_stored,
                &id
            ],
        )
        .map_err(|e| e.to_string())?;
    }
    let row = ioc_get_by_id(&g, &id)?;
    drop(g);
    let _ = touch_campaign_for_tag(&app, row.campaign_tag.as_deref());
    let _ = append_audit(
        &app,
        "ioc_update",
        serde_json::json!({ "id": &id, "value": &row.value }),
    );
    Ok(row)
}

#[tauri::command]
pub fn ioc_delete(app: AppHandle, id: String) -> Result<(), String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let n = g
        .execute("DELETE FROM iocs WHERE id = ?1", [&id])
        .map_err(|e| e.to_string())?;
    drop(g);
    if n == 0 {
        return Err("IOC not found".into());
    }
    let _ = append_audit(&app, "ioc_delete", serde_json::json!({ "id": &id }));
    Ok(())
}

/// Same filters as [`ioc_search`]; used for STIX export.
fn ioc_run_search(
    app: &AppHandle,
    value_contains: Option<String>,
    ioc_type: Option<String>,
    campaign: Option<String>,
    source: Option<String>,
    profile_id: Option<String>,
    all_profiles: Option<bool>,
    include_false_positives: Option<bool>,
    limit: Option<i64>,
) -> Result<Vec<IocRow>, String> {
    let lim = limit.unwrap_or(100).min(10_000).max(1);
    let fp_mode: i64 = if include_false_positives == Some(true) {
        1
    } else {
        0
    };
    let (pf_mode, pf_arg): (i64, String) = if all_profiles == Some(true) {
        (PF_ALL, String::new())
    } else if let Some(p) = profile_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        (PF_SCOPED, p.to_string())
    } else if let Some(a) = active_profile_id(&app)? {
        (PF_SCOPED, a)
    } else {
        (PF_NULL_ONLY, String::new())
    };

    let (vskip, vpat) = if let Some(ref s) = value_contains {
        if s.trim().is_empty() {
            (1i64, String::new())
        } else {
            (0i64, like_substring(s.trim()))
        }
    } else {
        (1i64, String::new())
    };

    let (tskip, tval) = if let Some(ref t) = ioc_type {
        if t.trim().is_empty() {
            (1i64, String::new())
        } else {
            (0i64, t.trim().to_string())
        }
    } else {
        (1i64, String::new())
    };

    let (cskip, cp) = if let Some(ref c) = campaign {
        if c.trim().is_empty() {
            (1i64, String::new())
        } else {
            (0i64, like_substring(c.trim()))
        }
    } else {
        (1i64, String::new())
    };

    let (sskip, sp) = if let Some(ref s) = source {
        if s.trim().is_empty() {
            (1i64, String::new())
        } else {
            (0i64, like_substring(s.trim()))
        }
    } else {
        (1i64, String::new())
    };

    // ?1-?10 as before; ?11=fp "include all" mode; ?12=limit
    const SQL: &str = r#"
      SELECT id, value, "type" AS ioc_type, source, confidence, first_seen, last_seen, campaign_tag, raw_json, profile_id, valid_until, is_false_positive, mitre_techniques
      FROM iocs
      WHERE
        ( (?1) = 0
          OR ( (?1) = 1 AND (profile_id IS NULL OR profile_id = ?2) )
          OR ( (?1) = 2 AND profile_id IS NULL ) )
        AND ( (?3) = 1 OR value LIKE ?4 ESCAPE '\' )
        AND ( (?5) = 1 OR "type" = ?6 )
        AND ( (?7) = 1 OR campaign_tag LIKE ?8 ESCAPE '\' )
        AND ( (?9) = 1 OR source LIKE ?10 ESCAPE '\' )
        AND ( (?11) = 1 OR (is_false_positive = 0) )
      ORDER BY last_seen DESC
      LIMIT ?12
    "#;

    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut stmt = g.prepare(SQL).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(
            params![
                &pf_mode,
                &pf_arg,
                vskip,
                vpat,
                tskip,
                tval,
                cskip,
                cp,
                sskip,
                sp,
                &fp_mode,
                &lim
            ],
            |r| {
                let mts: String = r.get(12)?;
                let ifp: i64 = r.get(11)?;
                Ok(IocRow {
                    id: r.get(0)?,
                    value: r.get(1)?,
                    ioc_type: r.get(2)?,
                    source: r.get(3)?,
                    confidence: r.get(4)?,
                    first_seen: r.get(5)?,
                    last_seen: r.get(6)?,
                    campaign_tag: r.get(7)?,
                    raw_json: r.get(8)?,
                    profile_id: r.get(9)?,
                    valid_until: r.get(10)?,
                    is_false_positive: ifp != 0,
                    mitre_techniques: mitre_json_stored_to_vec(&mts),
                })
            },
        )
        .map_err(|e| e.to_string())?;
    let mut out = vec![];
    for row in rows {
        out.push(row.map_err(|e| e.to_string())?);
    }
    Ok(out)
}

/// Search: default = global (`profile_id` NULL) **or** active / explicit `profileId`; with `allProfiles: true` search all.
#[tauri::command]
pub fn ioc_search(
    app: AppHandle,
    value_contains: Option<String>,
    ioc_type: Option<String>,
    campaign: Option<String>,
    source: Option<String>,
    profile_id: Option<String>,
    all_profiles: Option<bool>,
    include_false_positives: Option<bool>,
    limit: Option<i64>,
) -> Result<Vec<IocRow>, String> {
    ioc_run_search(
        &app,
        value_contains,
        ioc_type,
        campaign,
        source,
        profile_id,
        all_profiles,
        include_false_positives,
        limit,
    )
}

/// STIX 2.1 `bundle` JSON of IOCs matching the same filters as **ioc_search**.
#[tauri::command]
pub fn ioc_export_stix(
    app: AppHandle,
    value_contains: Option<String>,
    ioc_type: Option<String>,
    campaign: Option<String>,
    source: Option<String>,
    profile_id: Option<String>,
    all_profiles: Option<bool>,
    include_false_positives: Option<bool>,
    limit: Option<i64>,
    producer_label: Option<String>,
) -> Result<String, String> {
    let rows = ioc_run_search(
        &app,
        value_contains,
        ioc_type,
        campaign,
        source,
        profile_id,
        all_profiles,
        include_false_positives,
        limit,
    )?;
    stix_export::rows_to_stix_bundle_json(
        &rows,
        producer_label
            .filter(|s| !s.trim().is_empty())
            .as_deref()
            .unwrap_or("Bacongris CTI"),
    )
}

/// Purge expired IOCs and apply confidence / expiry rules (also runs on app start).
#[tauri::command]
pub fn ioc_maintenance(app: AppHandle) -> Result<IocMaintenanceResult, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let r = maintenance::run_ioc_maintenance(&g)?;
    drop(g);
    let _ = append_audit(
        &app,
        "ioc_maintenance",
        serde_json::to_value(&r).unwrap_or(serde_json::json!({})),
    );
    Ok(r)
}

/// For startup: no audit row (no `AppHandle`).
pub fn run_ioc_maintenance_on_conn(conn: &rusqlite::Connection) -> Result<IocMaintenanceResult, String> {
    maintenance::run_ioc_maintenance(conn)
}

pub(crate) fn import_snapshots(
    app: &AppHandle,
    snapshots: Vec<(String, String, String, serde_json::Value)>, // (value, ioc_type, source, fragment)
    default_source: &str,
    campaign_tag: &Option<String>,
    prof: &Option<String>,
) -> Result<IocImportResult, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut inserted: u32 = 0;
    let mut updated: u32 = 0;
    let mut skipped: u32 = 0;
    {
        let tx = g.unchecked_transaction().map_err(|e| e.to_string())?;
        for (val, itype, src, frag) in snapshots {
            if val.is_empty() || itype.is_empty() {
                skipped = skipped.saturating_add(1);
                continue;
            }
            let raw = truncate_raw(serde_json::to_string(&frag).ok());
            let src_use = if src.is_empty() {
                default_source.to_string()
            } else {
                src
            };
            let source_opt = Some(src_use);
            match upsert_ioc(
                &tx,
                &val,
                &itype,
                &source_opt,
                None,
                campaign_tag,
                raw,
                prof,
                None,
                None,
                None,
            ) {
                Ok((_, is_upd)) => {
                    if is_upd {
                        updated = updated.saturating_add(1);
                    } else {
                        inserted = inserted.saturating_add(1);
                    }
                }
                Err(e) => {
                    let _ = tx.rollback();
                    return Err(e);
                }
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
    }
    drop(g);
    let _ = append_audit(
        app,
        "ioc_import",
        serde_json::json!({ "source": default_source, "inserted": inserted, "updated": updated }),
    );
    Ok(IocImportResult {
        inserted,
        updated,
        skipped,
        source: default_source.to_string(),
    })
}

fn misp_to_quads(
    snaps: Vec<MispSnapshot>,
    default_source: &str,
) -> Vec<(String, String, String, serde_json::Value)> {
    let mut v = vec![];
    for s in snaps {
        v.push((
            s.value,
            s.ioc_type,
            default_source.to_string(),
            s.fragment,
        ));
    }
    v
}

fn stix_to_quads(
    snaps: Vec<StixSnapshot>,
    default_source: &str,
) -> Vec<(String, String, String, serde_json::Value)> {
    let mut v = vec![];
    for s in snaps {
        v.push((
            s.value,
            s.ioc_type,
            default_source.to_string(),
            s.fragment,
        ));
    }
    v
}

/// Parse STIX 2.x JSON and upsert IOCs.
#[tauri::command]
pub fn ioc_import_stix(
    app: AppHandle,
    json: String,
    source: Option<String>,
    campaign_tag: Option<String>,
    profile_id: Option<String>,
) -> Result<IocImportResult, String> {
    let snaps = extract_from_stix(&json)?;
    let def = source.unwrap_or_else(|| "stix".to_string());
    let quads = stix_to_quads(snaps, &def);
    let prof = resolve_profile(&app, profile_id)?;
    if let Some(ref p) = prof {
        let st = app.state::<AppStore>();
        let g = st.db.lock().map_err(|e| e.to_string())?;
        if !profile_exists(&g, p)? {
            return Err("profile_id is not a valid profile".into());
        }
    }
    import_snapshots(&app, quads, &def, &campaign_tag, &prof)
}

/// Parse a MISP Event JSON export and upsert IOCs.
#[tauri::command]
pub fn ioc_import_misp(
    app: AppHandle,
    json: String,
    source: Option<String>,
    campaign_tag: Option<String>,
    profile_id: Option<String>,
) -> Result<IocImportResult, String> {
    let snaps = extract_from_misp_event(&json)?;
    let def = source.unwrap_or_else(|| "misp".to_string());
    let quads = misp_to_quads(snaps, &def);
    let prof = resolve_profile(&app, profile_id)?;
    if let Some(ref p) = prof {
        let st = app.state::<AppStore>();
        let g = st.db.lock().map_err(|e| e.to_string())?;
        if !profile_exists(&g, p)? {
            return Err("profile_id is not a valid profile".into());
        }
    }
    import_snapshots(&app, quads, &def, &campaign_tag, &prof)
}

/// Upsert an IOC and return its id (used by enrichment and feeds).
pub fn ensure_ioc_id(
    app: &AppHandle,
    value: &str,
    ioc_type: &str,
    profile_id: Option<String>,
) -> Result<String, String> {
    let v = value.trim();
    let t = ioc_type.trim();
    if v.is_empty() || t.is_empty() {
        return Err("value and ioc_type are required".into());
    }
    let prof = resolve_profile(app, profile_id)?;
    {
        if let Some(ref p) = prof {
            let st = app.state::<AppStore>();
            let g = st.db.lock().map_err(|e| e.to_string())?;
            if !profile_exists(&g, p)? {
                return Err("profile_id is not a valid profile".into());
            }
        }
    }
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let (row, _) = upsert_ioc(
        &g,
        v,
        t,
        &Some("ensure_ioc_id".to_string()),
        None,
        &None,
        None,
        &prof,
        None,
        None,
        None,
    )?;
    Ok(row.id)
}

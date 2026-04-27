//! IOC enrichment: VirusTotal, Shodan, abuse.ch, OTX. Persists to `enrichment_results`.
mod relationships;

use std::collections::HashMap;

use chrono::Utc;
use rusqlite::params;
use serde::Serialize;
use serde_json::Value;
use tauri::AppHandle;
use tauri::Manager;
use uuid::Uuid;

use crate::api::secrets::merge_api_keys;
use crate::api::HttpApiState;
use crate::app_data::AppStore;
use crate::ioc::ensure_ioc_id;
use crate::settings::load_settings;
use crate::settings::default_limit_for_api;

const RAW_MAX: usize = 512 * 1024;

fn now_ts() -> i64 {
    Utc::now().timestamp()
}

fn truncate(s: &str) -> String {
    if s.len() <= RAW_MAX {
        s.to_string()
    } else {
        s.chars().take(RAW_MAX).collect()
    }
}

fn summarize_json(v: &Value) -> String {
    let t = v.to_string();
    if t.len() > 400 {
        format!("{}…", t.chars().take(400).collect::<String>())
    } else {
        t
    }
}

fn store_result(
    app: &AppHandle,
    ioc_id: &str,
    source: &str,
    body: &Value,
    lim_secs: u64,
) -> Result<String, String> {
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let id = Uuid::new_v4().to_string();
    let t = now_ts();
    let exp = t + lim_secs as i64;
    let raw = truncate(&body.to_string());
    let sum = summarize_json(body);
    g.execute(
        "INSERT INTO enrichment_results (id, ioc_id, source, query_time, raw_response, summary, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![&id, &ioc_id, &source, &t, &raw, &sum, &exp],
    )
    .map_err(|e| e.to_string())?;
    Ok(id)
}

/// Run VT v3 for hash / IP / domain.
pub async fn run_virustotal(
    app: &AppHandle,
    http: &HttpApiState,
    ioc: &str,
    ioc_type: &str,
) -> Result<Value, String> {
    let s = load_settings(app)?;
    let keys = merge_api_keys(&s)?;
    let k = keys
        .get("virustotal")
        .or_else(|| keys.get("vt"))
        .or_else(|| keys.get("VirusTotal"))
        .ok_or_else(|| "No virustotal API key in settings.apiKeys or .api_keys.json".to_string())?;
    let t = ioc_type.to_lowercase();
    let path = match t.as_str() {
        "md5" | "sha1" | "sha256" | "ssdeep" if ioc.len() >= 32 => {
            format!("https://www.virustotal.com/api/v3/files/{}", ioc)
        }
        "ipv4" | "ip" | "ip-dst" | "ip-src" => {
            format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ioc)
        }
        "ipv6" => format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ioc),
        "domain" | "hostname" => format!("https://www.virustotal.com/api/v3/domains/{}", ioc),
        "url" => {
            return Err("VirusTotal URL report needs URL id; use domain/hash enrichment first".into());
        }
        _ => {
            return Err(format!("ioc_type {ioc_type} not supported for VirusTotal in this app"));
        }
    };
    let mut h = HashMap::new();
    h.insert("x-apikey".to_string(), k.clone());
    let r = http
        .run_request(
            app,
            path,
            "GET".into(),
            Some(h),
            None,
            "virustotal".into(),
        )
        .await?;
    Ok(r)
}

/// Shodan host (IP) or DNS domain.
pub async fn run_shodan(
    app: &AppHandle,
    http: &HttpApiState,
    ioc: &str,
    ioc_type: &str,
) -> Result<Value, String> {
    let s = load_settings(app)?;
    let keys = merge_api_keys(&s)?;
    let k = keys
        .get("shodan")
        .ok_or_else(|| "No shodan API key in settings or .api_keys.json".to_string())?;
    let t = ioc_type.to_lowercase();
    let url = match t.as_str() {
        "ipv4" | "ipv6" | "ip" | "ip-dst" | "ip-src" => {
            format!("https://api.shodan.io/shodan/host/{}?key={}", ioc, urlencoding::encode(k))
        }
        "domain" | "hostname" => {
            format!(
                "https://api.shodan.io/dns/domain/{}?key={}",
                ioc,
                urlencoding::encode(k)
            )
        }
        _ => {
            return Err("Shodan: use ipv4/ipv6 or domain/hostname for this tool".into());
        }
    };
    http.run_request(app, url, "GET".into(), None, None, "shodan".into())
        .await
}

/// MalwareBazaar (hash) and URLhaus (url).
pub async fn run_abusech(
    app: &AppHandle,
    http: &HttpApiState,
    ioc: &str,
    ioc_type: &str,
) -> Result<Value, String> {
    let t = ioc_type.to_lowercase();
    if matches!(t.as_str(), "md5" | "sha1" | "sha256") {
        let body = format!("query=get_info&hash={}", ioc);
        return http
            .run_request(
                app,
                "https://mb-api.abuse.ch/api/v1/".to_string(),
                "POST".into(),
                Some(HashMap::from([(
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                )])),
                Some(body),
                "abusech".into(),
            )
            .await;
    }
    if t == "url" {
        let body = format!("url={}", urlencoding::encode(ioc));
        return http
            .run_request(
                app,
                "https://urlhaus-api.abuse.ch/v1/url/".to_string(),
                "POST".into(),
                Some(HashMap::from([(
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                )])),
                Some(body),
                "abusech".into(),
            )
            .await;
    }
    Err("abuse.ch: use md5/sha1/sha256 for MalwareBazaar or url for URLhaus".into())
}

/// Map our ioc type to OTX type segment.
fn otx_type_segment(ioc: &str, ioc_type: &str) -> Result<(&'static str, String), String> {
    let t = ioc_type.to_lowercase();
    let seg = match t.as_str() {
        "md5" | "sha1" | "sha256" => "file",
        "ipv4" | "ip" | "ip-dst" | "ip-src" => "IPv4",
        "ipv6" => "IPv6",
        "domain" | "hostname" => "domain",
        "url" => "url",
        "email" => "email",
        _ => "general",
    };
    if seg == "email" {
        // OTX has limited email support
        return Err("OTX: try domain part of email as domain type".into());
    }
    if seg == "general" {
        return Err("unsupported ioc_type for OTX".into());
    }
    Ok((seg, ioc.to_string()))
}

/// Second OTX call only for types that expose the passive-DNS section (saves quota vs. file/url).
fn otx_indicator_has_passive_dns_api(seg: &str) -> bool {
    matches!(seg, "IPv4" | "IPv6" | "domain")
}

/// Merge `GET .../passive_dns` `body` into the general `body` so enrichment + graph use the full list.
fn merge_otx_passive_into_general_body(general_body: &mut Value, passive_api_body: &Value) {
    let Some(g) = general_body.as_object_mut() else {
        return;
    };
    if let Some(pd) = passive_api_body.get("passive_dns") {
        g.insert("passive_dns".to_string(), pd.clone());
    } else if passive_api_body.is_array() {
        g.insert("passive_dns".to_string(), passive_api_body.clone());
    }
}

/// AlienVault OTX: `general` plus optional `passive_dns` merge for IP/domain (full passive list for `ioc_relationships`).
pub async fn run_otx(
    app: &AppHandle,
    http: &HttpApiState,
    ioc: &str,
    ioc_type: &str,
) -> Result<Value, String> {
    let s = load_settings(app)?;
    let keys = merge_api_keys(&s)?;
    let k = keys
        .get("otx")
        .or_else(|| keys.get("alienvault"))
        .or_else(|| keys.get("OTX"))
        .ok_or_else(|| "No otx API key in settings or .api_keys.json".to_string())?;
    let (seg, path_val) = otx_type_segment(ioc, ioc_type)?;
    let enc = urlencoding::encode(&path_val);
    let u = format!(
        "https://otx.alienvault.com/api/v1/indicators/{}/{}/general",
        seg, enc
    );
    let mut h = HashMap::new();
    h.insert("X-OTX-API-KEY".to_string(), k.clone());
    let mut r = http
        .run_request(app, u, "GET".into(), Some(h.clone()), None, "otx".into())
        .await?;

    let general_ok = r
        .get("status")
        .and_then(|s| s.as_u64())
        .map(|c| c == 200)
        .unwrap_or(false);
    if general_ok && otx_indicator_has_passive_dns_api(seg) {
        let u_pd = format!(
            "https://otx.alienvault.com/api/v1/indicators/{}/{}/passive_dns",
            seg, enc
        );
        if let Ok(r_pd) = http
            .run_request(
                app,
                u_pd,
                "GET".into(),
                Some(h),
                None,
                "otx".into(),
            )
            .await
        {
            let pd_ok = r_pd
                .get("status")
                .and_then(|s| s.as_u64())
                .map(|c| c == 200)
                .unwrap_or(false);
            if pd_ok {
                if let (Some(b_gen), Some(b_pd)) = (r.get_mut("body"), r_pd.get("body")) {
                    merge_otx_passive_into_general_body(b_gen, b_pd);
                }
            }
        }
    }
    Ok(r)
}

// --- Tauri commands ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrichOut {
    ioc_id: String,
    source: String,
    enrichment_id: String,
    api: Value,
}

#[tauri::command]
pub async fn enrich_virustotal(
    app: AppHandle,
    http: tauri::State<'_, HttpApiState>,
    ioc: String,
    ioc_type: String,
    profile_id: Option<String>,
) -> Result<EnrichOut, String> {
    let ioc_id = ensure_ioc_id(&app, &ioc, &ioc_type, profile_id.clone())?;
    let r = run_virustotal(&app, &http, &ioc, &ioc_type).await?;
    let b = r.get("body").cloned().unwrap_or(Value::Null);
    let lim = default_limit_for_api("virustotal").cache_ttl_secs;
    let eid = store_result(&app, &ioc_id, "virustotal", &b, lim)?;
    let _ = relationships::apply_virustotal_graph_edges(
        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
    );
    let _ = relationships::apply_virustotal_infrastructure_edges(
        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
    );
    Ok(EnrichOut {
        ioc_id,
        source: "virustotal".into(),
        enrichment_id: eid,
        api: r,
    })
}

#[tauri::command]
pub async fn enrich_shodan(
    app: AppHandle,
    http: tauri::State<'_, HttpApiState>,
    ioc: String,
    ioc_type: String,
    profile_id: Option<String>,
) -> Result<EnrichOut, String> {
    let ioc_id = ensure_ioc_id(&app, &ioc, &ioc_type, profile_id.clone())?;
    let r = run_shodan(&app, &http, &ioc, &ioc_type).await?;
    let b = r.get("body").cloned().unwrap_or(Value::Null);
    let lim = default_limit_for_api("shodan").cache_ttl_secs;
    let eid = store_result(&app, &ioc_id, "shodan", &b, lim)?;
    let _ = relationships::apply_shodan_graph_edges(
        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
    );
    let _ = relationships::apply_shodan_infrastructure_edges(
        &app, &ioc_type, &ioc_id, &b, profile_id.clone(),
    );
    Ok(EnrichOut {
        ioc_id,
        source: "shodan".into(),
        enrichment_id: eid,
        api: r,
    })
}

#[tauri::command]
pub async fn enrich_abusech(
    app: AppHandle,
    http: tauri::State<'_, HttpApiState>,
    ioc: String,
    ioc_type: String,
    profile_id: Option<String>,
) -> Result<EnrichOut, String> {
    let ioc_id = ensure_ioc_id(&app, &ioc, &ioc_type, profile_id.clone())?;
    let r = run_abusech(&app, &http, &ioc, &ioc_type).await?;
    let b = r.get("body").cloned().unwrap_or(Value::Null);
    let lim = default_limit_for_api("abusech").cache_ttl_secs;
    let eid = store_result(&app, &ioc_id, "abusech", &b, lim)?;
    let _ = relationships::apply_abusech_graph_edges(
        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
    );
    Ok(EnrichOut {
        ioc_id,
        source: "abusech".into(),
        enrichment_id: eid,
        api: r,
    })
}

#[tauri::command]
pub async fn enrich_otx(
    app: AppHandle,
    http: tauri::State<'_, HttpApiState>,
    ioc: String,
    ioc_type: String,
    profile_id: Option<String>,
) -> Result<EnrichOut, String> {
    let ioc_id = ensure_ioc_id(&app, &ioc, &ioc_type, profile_id.clone())?;
    let r = run_otx(&app, &http, &ioc, &ioc_type).await?;
    let b = r.get("body").cloned().unwrap_or(Value::Null);
    let lim = default_limit_for_api("otx").cache_ttl_secs;
    let eid = store_result(&app, &ioc_id, "otx", &b, lim)?;
    let _ = relationships::apply_otx_graph_edges(
        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
    );
    Ok(EnrichOut {
        ioc_id,
        source: "otx".into(),
        enrichment_id: eid,
        api: r,
    })
}

#[tauri::command]
pub async fn enrich_ioc(
    app: AppHandle,
    http: tauri::State<'_, HttpApiState>,
    ioc: String,
    ioc_type: String,
    profile_id: Option<String>,
) -> Result<Value, String> {
    let s = load_settings(&app)?;
    let keys = merge_api_keys(&s)?;
    let ioc_id = ensure_ioc_id(&app, &ioc, &ioc_type, profile_id.clone())?;
    let t = ioc_type.to_lowercase();
    let mut out = serde_json::json!({ "iocId": &ioc_id, "results": [] });
    let results = out
        .get_mut("results")
        .and_then(|x| x.as_array_mut())
        .unwrap();
    if keys.contains_key("virustotal")
        || keys.contains_key("vt")
        || keys.contains_key("VirusTotal")
    {
        if !matches!(t.as_str(), "url" | "email" | "other") {
            if let Ok(r) = run_virustotal(&app, &http, &ioc, &ioc_type).await {
                let b = r.get("body").cloned().unwrap_or(Value::Null);
                if let Ok(eid) = store_result(
                    &app,
                    &ioc_id,
                    "virustotal",
                    &b,
                    default_limit_for_api("virustotal").cache_ttl_secs,
                ) {
                    let _ = relationships::apply_virustotal_graph_edges(
                        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
                    );
                    let _ = relationships::apply_virustotal_infrastructure_edges(
                        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
                    );
                    results.push(serde_json::json!({ "source": "virustotal", "enrichmentId": eid, "response": r }));
                }
            }
        }
    }
    if keys.contains_key("shodan")
        && matches!(t.as_str(), "ipv4" | "ipv6" | "ip" | "domain" | "hostname" | "ip-dst" | "ip-src")
    {
        if let Ok(r) = run_shodan(&app, &http, &ioc, &ioc_type).await {
            let b = r.get("body").cloned().unwrap_or(Value::Null);
                if let Ok(eid) = store_result(
                    &app,
                    &ioc_id,
                    "shodan",
                    &b,
                    default_limit_for_api("shodan").cache_ttl_secs,
                ) {
                    let _ = relationships::apply_shodan_graph_edges(
                        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
                    );
                    let _ = relationships::apply_shodan_infrastructure_edges(
                        &app, &ioc_type, &ioc_id, &b, profile_id.clone(),
                    );
                    results.push(serde_json::json!({ "source": "shodan", "enrichmentId": eid, "response": r }));
                }
        }
    }
    if matches!(t.as_str(), "md5" | "sha1" | "sha256" | "url") {
        if let Ok(r) = run_abusech(&app, &http, &ioc, &ioc_type).await {
            let b = r.get("body").cloned().unwrap_or(Value::Null);
                if let Ok(eid) = store_result(
                    &app,
                    &ioc_id,
                    "abusech",
                    &b,
                    default_limit_for_api("abusech").cache_ttl_secs,
                ) {
                    let _ = relationships::apply_abusech_graph_edges(
                        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
                    );
                    results.push(serde_json::json!({ "source": "abusech", "enrichmentId": eid, "response": r }));
                }
        }
    }
    if keys.contains_key("otx")
        || keys.contains_key("alienvault")
        || keys.contains_key("OTX")
    {
        if otx_type_segment(&ioc, &ioc_type).is_ok() {
            if let Ok(r) = run_otx(&app, &http, &ioc, &ioc_type).await {
                let b = r.get("body").cloned().unwrap_or(Value::Null);
                if let Ok(eid) = store_result(
                    &app,
                    &ioc_id,
                    "otx",
                    &b,
                    default_limit_for_api("otx").cache_ttl_secs,
                ) {
                    let _ = relationships::apply_otx_graph_edges(
                        &app, &ioc, &ioc_type, &ioc_id, &b, profile_id.clone(),
                    );
                    results.push(serde_json::json!({ "source": "otx", "enrichmentId": eid, "response": r }));
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod otx_merge_tests {
    use super::merge_otx_passive_into_general_body;
    use serde_json::json;

    #[test]
    fn merge_passive_dns_array_into_general() {
        let mut general = json!({ "indicator": "1.2.3.4", "type": "IPv4" });
        let pd = json!({ "passive_dns": [ { "hostname": "a.com", "address": "1.2.3.4" } ] });
        merge_otx_passive_into_general_body(&mut general, &pd);
        assert_eq!(general["passive_dns"][0]["hostname"], "a.com");
    }
}

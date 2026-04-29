//! Reqwest + in-memory rate limits + response cache for external CTI HTTP APIs.
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::Datelike;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use sha2::Digest;

use crate::api::ssrf::assert_public_http_url;
use crate::settings::{default_limit_for_api, load_settings, ApiRateLimitConfig, AppSettings};

const CACHE_MAX_ENTRIES: usize = 2_000;

/// Managed Tauri state: shared HTTP client, rate limit counters, and response cache.
pub struct HttpApiState {
    inner: Mutex<Inner>,
}

struct Inner {
    per_min: HashMap<String, VecDeque<Instant>>,
    per_day: HashMap<String, (u32, u32)>, // (day id, count)
    cache: HashMap<String, (Instant, String)>, // key → (expires, cached json string of body)
    client: reqwest::Client,
}

impl Default for HttpApiState {
    fn default() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest");
        Self {
            inner: Mutex::new(Inner {
                per_min: HashMap::new(),
                per_day: HashMap::new(),
                cache: HashMap::new(),
                client,
            }),
        }
    }
}

fn day_bucket() -> u32 {
    let d = chrono::Utc::now().date_naive();
    d.year() as u32 * 1_000 + d.ordinal()
}

fn limit_for_name(settings: &AppSettings, api_name: &str) -> ApiRateLimitConfig {
    let k = api_name.to_lowercase();
    settings
        .api_rate_limits
        .get(&k)
        .or_else(|| settings.api_rate_limits.get(api_name))
        .cloned()
        .unwrap_or_else(|| default_limit_for_api(&k))
}

fn body_hash(b: &Option<String>) -> String {
    match b {
        None => "0".into(),
        Some(s) => {
            let mut h = sha2::Sha256::new();
            h.update(s.as_bytes());
            hex::encode(h.finalize())
        }
    }
}

fn cache_key(api_name: &str, method: &str, url: &str, body: &Option<String>) -> String {
    let m = method.to_uppercase();
    let h = body_hash(body);
    format!("{api_name}|{m}|{url}|{h}")
}

fn build_body_value(raw: String) -> Value {
    if raw.is_empty() {
        return Value::Null;
    }
    serde_json::from_str(&raw).unwrap_or(Value::String(raw))
}

impl HttpApiState {
    /// Used by the `api_request` tool and by enrichment/feed code.
    pub async fn run_request(
        &self,
        app: &tauri::AppHandle,
        url: String,
        method: String,
        headers: Option<HashMap<String, String>>,
        body: Option<String>,
        api_name: String,
    ) -> Result<Value, String> {
    if url.is_empty() {
        return Err("url is required".into());
    }
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("url must be http or https".into());
    }
    assert_public_http_url(&url)?;
    let m = method.to_uppercase();
    if m != "GET" && m != "POST" && m != "PUT" && m != "PATCH" && m != "DELETE" {
        return Err("method must be GET, POST, PUT, PATCH, or DELETE".into());
    }
    if api_name.trim().is_empty() {
        return Err("api_name is required (e.g. virustotal) for rate limiting".into());
    }
    let settings = load_settings(app)?;
    let lim = limit_for_name(&settings, &api_name);
    let cache_key_s = cache_key(&api_name, &m, &url, &body);
    let t0 = Instant::now();

    {
        let g = self.inner.lock().map_err(|e| e.to_string())?;
        if let Some((exp, json)) = g.cache.get(&cache_key_s) {
            if *exp > t0 {
                if let Ok(v) = serde_json::from_str::<Value>(json) {
                    return Ok(serde_json::json!({
                        "status": 200,
                        "fromCache": true,
                        "body": v
                    }));
                }
            }
        }
    }

    {
        let mut g = self.inner.lock().map_err(|e| e.to_string())?;
        let db = day_bucket();
        let e = g.per_day.entry(api_name.to_lowercase()).or_insert((0, 0));
        if e.0 != db {
            e.0 = db;
            e.1 = 0;
        }
        if e.1 >= lim.requests_per_day {
            return Err(format!(
                "Daily quota {} reached for {}; try again tomorrow or raise apiRateLimits in settings",
                lim.requests_per_day, api_name
            ));
        }
    }
    wait_for_per_minute_slot(self, &api_name, &lim).await?;

    let client = {
        let g = self.inner.lock().map_err(|e| e.to_string())?;
        g.client.clone()
    };
    let mut res = do_http(&client, &m, &url, &headers, &body).await;
    for attempt in 0..2u32 {
        if let Ok(r) = &res {
            let st = r.status();
            if st == reqwest::StatusCode::TOO_MANY_REQUESTS
                || st == reqwest::StatusCode::SERVICE_UNAVAILABLE
            {
                tokio::time::sleep(Duration::from_millis(500u64 + u64::from(attempt) * 1_000)).await;
                res = do_http(&client, &m, &url, &headers, &body).await;
                continue;
            }
        }
        break;
    }
    let res = res.map_err(|e| e.to_string())?;
    let status = res.status();
    let raw = res
        .text()
        .await
        .map_err(|e| format!("read body: {e}"))?;
    let body_value = build_body_value(raw);
    {
        let mut g = self.inner.lock().map_err(|e| e.to_string())?;
        g.per_min
            .entry(api_name.to_lowercase())
            .or_default()
            .push_back(Instant::now());
        let e = g.per_day.entry(api_name.to_lowercase()).or_insert((0, 0));
        let db = day_bucket();
        if e.0 != db {
            e.0 = db;
            e.1 = 0;
        }
        e.1 = e.1.saturating_add(1);
    }
    if status.is_success() && lim.cache_ttl_secs > 0 {
        if let Ok(s) = serde_json::to_string(&body_value) {
            let exp = t0 + Duration::from_secs(lim.cache_ttl_secs);
            let mut g = self.inner.lock().map_err(|e| e.to_string())?;
            if g.cache.len() > CACHE_MAX_ENTRIES {
                g.cache.clear();
            }
            g.cache.insert(cache_key_s, (exp, s));
        }
    }
    Ok(serde_json::json!({
        "status": status.as_u16(),
        "fromCache": false,
        "body": body_value
    }))
    }
}

/// Generic HTTP to external API (path + rate limit + short cache for identical calls).
#[tauri::command]
pub async fn api_request(
    app: tauri::AppHandle,
    state: tauri::State<'_, HttpApiState>,
    url: String,
    method: String,
    headers: Option<HashMap<String, String>>,
    body: Option<String>,
    api_name: String,
) -> Result<Value, String> {
    state
        .run_request(&app, url, method, headers, body, api_name)
        .await
}

async fn wait_for_per_minute_slot(
    state: &HttpApiState,
    api_name: &str,
    lim: &ApiRateLimitConfig,
) -> Result<(), String> {
    for _ in 0..60 {
        let (sleep_for, at_cap) = {
            let mut g = state.inner.lock().map_err(|e| e.to_string())?;
            let now = Instant::now();
            let q = g.per_min.entry(api_name.to_lowercase()).or_default();
            let cutoff = now - Duration::from_secs(60);
            while let Some(front) = q.front() {
                if *front < cutoff {
                    q.pop_front();
                } else {
                    break;
                }
            }
            if (q.len() as u32) < lim.requests_per_minute {
                return Ok(());
            }
            if let Some(oldest) = q.front() {
                let w = *oldest + Duration::from_secs(60) - now;
                (w.min(Duration::from_secs(5)), true)
            } else {
                (Duration::from_millis(0), true)
            }
        };
        if !at_cap {
            return Ok(());
        }
        if sleep_for == Duration::ZERO {
            return Ok(());
        }
        tokio::time::sleep(sleep_for).await;
    }
    Err("Could not get a per-minute request slot in time; try again".into())
}

async fn do_http(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &Option<HashMap<String, String>>,
    body: &Option<String>,
) -> Result<reqwest::Response, String> {
    let m = method.to_uppercase();
    let mut req = match m.as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "PATCH" => client.patch(url),
        "DELETE" => client.delete(url),
        _ => return Err("method".into()),
    };
    if let Some(hm) = headers {
        let mut map = HeaderMap::new();
        for (k, v) in hm {
            let name = HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| format!("header name: {e}"))?;
            let val = HeaderValue::from_str(v).map_err(|e| format!("header value: {e}"))?;
            map.insert(name, val);
        }
        req = req.headers(map);
    }
    if m != "GET" {
        if let Some(b) = body {
            req = req.body(b.clone());
        }
    }
    req.send()
        .await
        .map_err(|e| format!("http error: {e}"))
}

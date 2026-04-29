use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

const APP_CONFIG_DIR: &str = "BacongrisCTIAgent";

/// How `run_command` is executed. Distinct from the integrated terminal (always host).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RunCommandMode {
    /// Spawn the resolved program on the host with normal process isolation only.
    #[default]
    Host,
    /// `docker run` with bind-mounted workspace, **`--network=none`**, memory cap.
    DockerNoNetwork,
    /// `docker run` on default **bridge** (egress allowed) with **CPU / memory / pids** caps; still no host shell.
    DockerEgressCapped,
}

impl RunCommandMode {
    /// For LLM / UI one-liners.
    pub fn short_description(self) -> &'static str {
        match self {
            RunCommandMode::Host => "Host: `run_command` uses the allowlisted program on the machine (full host environment; no extra container isolation).",
            RunCommandMode::DockerNoNetwork => "Docker (no network): `run_command` runs inside a container with the workspace at `/workspace`, no outbound network, memory-capped.",
            RunCommandMode::DockerEgressCapped => "Docker (egress-capped): same bind-mount, **outbound network allowed** with tight CPU, memory, and process limits; global **timeout** and **max output** still apply.",
        }
    }
}

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
    /// When true, `run_command` runs inside `docker run` with no network, memory cap, and cwd as `/workspace`.
    #[serde(default)]
    pub use_docker_sandbox: bool,
    /// e.g. `python:3.12-slim`. Used when `use_docker_sandbox` is true. Empty uses the built-in default in executor.
    #[serde(default)]
    pub docker_sandbox_image: String,
    /// API key names (e.g. `virustotal`, `shodan`) for CTI tools. **Plaintext in settings** — prefer `api_keys` from `.api_keys.json` (merged; file keys override). Kept in sync in UI.
    #[serde(default)]
    pub api_keys: HashMap<String, String>,
    /// Per-API `apiName` (lowercase) rate limits; defaults apply when an entry is missing.
    #[serde(default)]
    pub api_rate_limits: HashMap<String, ApiRateLimitConfig>,
}

/// Rate limits and cache TTL for a named API (`virustotal`, `shodan`, …) used by `api_request` and enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiRateLimitConfig {
    #[serde(default = "default_rpm_60")]
    pub requests_per_minute: u32,
    #[serde(default = "default_rpd_10k")]
    pub requests_per_day: u32,
    /// HTTP response cache time for identical requests (enrichment re-queries).
    #[serde(default = "default_cache_300")]
    pub cache_ttl_secs: u64,
}

fn default_rpm_60() -> u32 {
    60
}
fn default_rpd_10k() -> u32 {
    10_000
}
fn default_cache_300() -> u64 {
    300
}

impl Default for ApiRateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            requests_per_day: 10_000,
            cache_ttl_secs: 300,
        }
    }
}

/// Defaults from the product plan; merged when `api_rate_limits` has no key for a name.
pub fn default_limit_for_api(name: &str) -> ApiRateLimitConfig {
    let n = name.to_lowercase();
    let (rpm, rpd) = match n.as_str() {
        "virustotal" | "vt" => (4, 1_000),
        "shodan" => (1, 100),
        "otx" | "alienvault" => (60, 2_000),
        "abusech" | "abuse" | "malwarebazaar" | "urlhaus" => (30, 5_000),
        "misp" | "opencti" | "taxii" | "taxii2" => (30, 5_000),
        _ => (60, 10_000),
    };
    ApiRateLimitConfig {
        requests_per_minute: rpm,
        requests_per_day: rpd,
        cache_ttl_secs: 300,
    }
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
            use_docker_sandbox: false,
            docker_sandbox_image: "python:3.12-slim".to_string(),
            api_keys: HashMap::new(),
            api_rate_limits: HashMap::new(),
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
    crate::persist_io::write_with_backup(&path, &raw)
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

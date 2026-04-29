//! SQLite-backed workspace profiles, agents, and app state (Issues 1,3,5,9).
//! Conversations live as JSONL under `conversations/<profile_id>/<agent_id>.jsonl` (Issue 4).
use crate::settings::{app_config_dir, load_settings, AppSettings};
use crate::settings::resolve_workspace_dir;
use rusqlite::OptionalExtension;
use rusqlite::{params, Connection};
use tauri::Manager;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tauri::AppHandle;
use uuid::Uuid;

use crate::persist_io::write_with_backup;

/// Global DB + helpers (Tauri `State`).
pub struct AppStore {
    pub db: Mutex<Connection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceProfileDto {
    pub id: String,
    pub name: String,
    pub path: String,
    pub last_opened: i64,
    /// JSON arrays merged with global allowlists (add-only).
    pub extra_roots: Vec<String>,
    pub extra_executables: Vec<String>,
    /// L1: inline user rules (optional). Superseded by `USER_RULES.md` in workspace if present.
    pub user_rules: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDto {
    pub id: String,
    pub profile_id: String,
    pub title: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateDto {
    pub active_profile_id: Option<String>,
    pub active_agent_id: Option<String>,
}

fn db_path() -> Result<PathBuf, String> {
    Ok(app_config_dir()?.join("app.db"))
}

fn conversations_dir() -> Result<PathBuf, String> {
    Ok(app_config_dir()?.join("conversations"))
}

fn conversation_path(profile_id: &str, agent_id: &str) -> Result<PathBuf, String> {
    Ok(conversations_dir()?.join(profile_id).join(format!("{agent_id}.jsonl")))
}

pub fn run_migrations(conn: &Connection) -> Result<(), String> {
    conn.execute("PRAGMA foreign_keys = ON", [])
        .map_err(|e| format!("pragma: {e}"))?;
    let v: i32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap_or(0);
    if v < 1 {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT NOT NULL UNIQUE,
                last_opened INTEGER NOT NULL DEFAULT 0,
                extra_roots TEXT NOT NULL DEFAULT '[]',
                extra_executables TEXT NOT NULL DEFAULT '[]',
                user_rules TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS app_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                active_profile_id TEXT,
                active_agent_id TEXT
            );
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                profile_id TEXT NOT NULL,
                title TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE
            );
            INSERT OR IGNORE INTO app_state (id, active_profile_id, active_agent_id) VALUES (1, NULL, NULL);
            "#,
        )
        .map_err(|e| format!("migrate v1: {e}"))?;
        conn.pragma_update(None, "user_version", 1)
            .map_err(|e| format!("set user_version: {e}"))?;
    }
    if v < 2 {
        conn.execute_batch(
            r#"
            CREATE TABLE iocs (
                id TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                type TEXT NOT NULL,
                source TEXT,
                confidence INTEGER,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                campaign_tag TEXT,
                raw_json TEXT,
                profile_id TEXT,
                FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE SET NULL
            );
            CREATE INDEX idx_iocs_value ON iocs(value);
            CREATE INDEX idx_iocs_type ON iocs(type);
            CREATE INDEX idx_iocs_campaign ON iocs(campaign_tag);
            CREATE INDEX idx_iocs_profile ON iocs(profile_id);
            "#,
        )
        .map_err(|e| format!("migrate v2: {e}"))?;
        conn.pragma_update(None, "user_version", 2)
            .map_err(|e| format!("set user_version: {e}"))?;
    }
    if v < 3 {
        conn.execute_batch(
            r#"
            CREATE TABLE enrichment_results (
                id TEXT PRIMARY KEY,
                ioc_id TEXT,
                source TEXT NOT NULL,
                query_time INTEGER NOT NULL,
                raw_response TEXT,
                summary TEXT,
                expires_at INTEGER,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
            );
            CREATE INDEX idx_enrich_ioc ON enrichment_results(ioc_id);
            CREATE INDEX idx_enrich_source ON enrichment_results(source);
            CREATE TABLE feeds (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                ftype TEXT NOT NULL,
                url TEXT,
                api_key_ref TEXT,
                poll_interval_minutes INTEGER,
                last_poll_time INTEGER,
                last_error TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                filter_tags TEXT
            );
            CREATE TABLE ioc_relationships (
                id TEXT PRIMARY KEY,
                source_ioc TEXT,
                target_ioc TEXT,
                relationship_type TEXT,
                source_data TEXT,
                confidence INTEGER,
                first_seen INTEGER,
                FOREIGN KEY (source_ioc) REFERENCES iocs(id) ON DELETE CASCADE,
                FOREIGN KEY (target_ioc) REFERENCES iocs(id) ON DELETE CASCADE
            );
            CREATE INDEX idx_rel_src ON ioc_relationships(source_ioc);
            CREATE INDEX idx_rel_tgt ON ioc_relationships(target_ioc);
            CREATE TABLE ioc_sightings (
                id TEXT PRIMARY KEY,
                ioc_id TEXT,
                s_timestamp INTEGER NOT NULL,
                s_source TEXT,
                context TEXT,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
            );
            CREATE INDEX idx_sight_ioc ON ioc_sightings(ioc_id);
            CREATE TABLE campaigns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                first_observed INTEGER,
                last_observed INTEGER,
                description TEXT,
                tags TEXT
            );
            "#,
        )
        .map_err(|e| format!("migrate v3: {e}"))?;
        conn.pragma_update(None, "user_version", 3)
            .map_err(|e| format!("set user_version: {e}"))?;
    }
    if v < 4 {
        conn.execute(
            "ALTER TABLE iocs ADD COLUMN valid_until INTEGER",
            [],
        )
        .map_err(|e| format!("migrate v4 add valid_until: {e}"))?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_iocs_valid_until ON iocs(valid_until) WHERE valid_until IS NOT NULL;",
        )
        .map_err(|e| format!("migrate v4 index: {e}"))?;
        conn.pragma_update(None, "user_version", 4)
            .map_err(|e| format!("set user_version: {e}"))?;
    }
    if v < 5 {
        conn.execute(
            "ALTER TABLE iocs ADD COLUMN is_false_positive INTEGER NOT NULL DEFAULT 0",
            [],
        )
        .map_err(|e| format!("migrate v5 is_false_positive: {e}"))?;
        conn.execute(
            "ALTER TABLE iocs ADD COLUMN mitre_techniques TEXT NOT NULL DEFAULT '[]'",
            [],
        )
        .map_err(|e| format!("migrate v5 mitre: {e}"))?;
        conn.pragma_update(None, "user_version", 5)
            .map_err(|e| format!("set user_version: {e}"))?;
    }
    if v < 6 {
        conn.execute("ALTER TABLE feeds ADD COLUMN cursor_json TEXT", [])
            .map_err(|e| format!("migrate v6 feeds cursor: {e}"))?;
        conn
            .execute("ALTER TABLE feeds ADD COLUMN last_failure_time INTEGER", [])
            .map_err(|e| format!("migrate v6 last_failure: {e}"))?;
        conn
            .execute(
                "ALTER TABLE feeds ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0",
                [],
            )
            .map_err(|e| format!("migrate v6 consecutive_failures: {e}"))?;
        conn.pragma_update(None, "user_version", 6)
            .map_err(|e| format!("set user_version: {e}"))?;
    }
    Ok(())
}

fn all_profile_ids(conn: &Connection) -> Result<Vec<String>, String> {
    let mut s = conn
        .prepare("SELECT id FROM profiles ORDER BY last_opened DESC")
        .map_err(|e| e.to_string())?;
    let rows = s
        .query_map([], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<String>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(rows)
}

/// Issue 1: fix dangling active profile/agent.
pub fn repair_state(conn: &Connection) -> Result<(), String> {
    let (pid, aid): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT active_profile_id, active_agent_id FROM app_state WHERE id = 1",
            [],
            |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .map_err(|e| e.to_string())?;
    let pids = all_profile_ids(conn)?;
    if pids.is_empty() {
        conn.execute(
            "UPDATE app_state SET active_profile_id = NULL, active_agent_id = NULL WHERE id = 1",
            [],
        )
        .map_err(|e| e.to_string())?;
        return Ok(());
    }
    let valid_pid = pid
        .clone()
        .filter(|p| pids.contains(p))
        .or_else(|| pids.first().cloned());
    if valid_pid != pid {
        if let Some(ref p) = valid_pid {
            conn.execute(
                "UPDATE app_state SET active_profile_id = ?1, active_agent_id = NULL WHERE id = 1",
                params![p],
            )
            .map_err(|e| e.to_string())?;
        }
    } else {
        if let (Some(ref pr), Some(ref ag)) = (pid, aid) {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM agents WHERE id = ?1 AND profile_id = ?2",
                    params![ag, pr],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if n == 0 {
                conn.execute(
                    "UPDATE app_state SET active_agent_id = NULL WHERE id = 1",
                    [],
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    // If a profile is active but no agent, pick the most recently updated one.
    let (pid2, aid2): (Option<String>, Option<String>) = conn
        .query_row(
            "SELECT active_profile_id, active_agent_id FROM app_state WHERE id = 1",
            [],
            |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .map_err(|e| e.to_string())?;
    if pid2.is_some() && aid2.is_none() {
        if let Some(ref pr) = pid2 {
            if let Ok(first) = conn.query_row(
                "SELECT id FROM agents WHERE profile_id = ?1 ORDER BY updated_at DESC LIMIT 1",
                params![pr],
                |r| r.get::<_, String>(0),
            ) {
                conn.execute(
                    "UPDATE app_state SET active_agent_id = ?1 WHERE id = 1",
                    params![&first],
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

/// Issue 9: one-time import from `settings.json` `workspacePath` (legacy).
fn migrate_from_legacy_settings(conn: &Connection, app: &AppHandle) -> Result<(), String> {
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM profiles", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if n > 0 {
        return Ok(());
    }
    let settings = load_settings(app)?;
    let root: PathBuf = if settings.workspace_path.trim().is_empty() {
        app_config_dir()?.join("workspace")
    } else {
        PathBuf::from(settings.workspace_path.trim())
    };
    let id = Uuid::new_v4().to_string();
    let name = root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("Workspace")
        .to_string();
    let now = chrono::Utc::now().timestamp();
    let path_str = root.to_string_lossy().to_string();
    conn.execute(
        "INSERT INTO profiles (id, name, path, last_opened, extra_roots, extra_executables, user_rules) VALUES (?1, ?2, ?3, ?4, '[]', '[]', '')",
        params![&id, &name, &path_str, &now],
    )
    .map_err(|e| e.to_string())?;
    let agent_id = Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO agents (id, profile_id, title, created_at, updated_at) VALUES (?1, ?2, 'Main', ?3, ?3)",
        params![&agent_id, &id, &now],
    )
    .map_err(|e| e.to_string())?;
    conn.execute(
        "UPDATE app_state SET active_profile_id = ?1, active_agent_id = ?2 WHERE id = 1",
        params![&id, &agent_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

impl AppStore {
    pub fn initialize(app: &AppHandle) -> Result<Self, String> {
        let path = db_path()?;
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(&path).map_err(|e| e.to_string())?;
        run_migrations(&conn)?;
        migrate_from_legacy_settings(&conn, app)?;
        repair_state(&conn)?;
        Ok(Self {
            db: Mutex::new(conn),
        })
    }

    pub fn merge_effective_settings(
        &self,
        _app: &AppHandle,
        base: &AppSettings,
    ) -> Result<AppSettings, String> {
        let g = self.db.lock().map_err(|e| e.to_string())?;
        let active: Option<String> = g
            .query_row(
                "SELECT active_profile_id FROM app_state WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        let Some(pid) = active else {
            return Ok(base.clone());
        };
        let extra_roots_s: String = g
            .query_row("SELECT extra_roots FROM profiles WHERE id = ?1", params![&pid], |r| {
                r.get(0)
            })
            .unwrap_or_else(|_| "[]".to_string());
        let extra_ex_s: String = g
            .query_row("SELECT extra_executables FROM profiles WHERE id = ?1", params![&pid], |r| {
                r.get(0)
            })
            .unwrap_or_else(|_| "[]".to_string());
        let mut r: Vec<String> = serde_json::from_str(&extra_roots_s).unwrap_or_default();
        let mut e: Vec<String> = serde_json::from_str(&extra_ex_s).unwrap_or_default();
        let mut s = base.clone();
        s.allowlisted_roots.extend(r.drain(..));
        s.allowed_executables.extend(e.drain(..));
        s.allowlisted_roots = dedup_strings(s.allowlisted_roots);
        s.allowed_executables = dedup_strings(s.allowed_executables);
        drop(g);
        Ok(s)
    }

    /// Resolved workspace root for tools: active profile `path` if any, else legacy
    /// `resolve_workspace_dir(&settings)`.
    pub fn effective_workspace_path(&self, app: &AppHandle) -> Result<PathBuf, String> {
        let base = load_settings(app)?;
        let g = self.db.lock().map_err(|e| e.to_string())?;
        let active: Option<String> = g
            .query_row(
                "SELECT active_profile_id FROM app_state WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if let Some(pid) = active {
            let p: String = g
                .query_row("SELECT path FROM profiles WHERE id = ?1", params![pid], |r| r.get(0))
                .map_err(|_| "no profile".to_string())?;
            return Ok(PathBuf::from(p));
        }
        drop(g);
        resolve_workspace_dir(&base)
    }
}

/// Effective `AppSettings` (global + active profile allowlist add-ons) for `paths` and `executor`.
pub fn merged_settings_for_runtime(app: &AppHandle) -> Result<AppSettings, String> {
    let st = app.state::<AppStore>();
    let base = load_settings(app)?;
    st.merge_effective_settings(app, &base)
}

fn dedup_strings(v: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for s in v {
        let t = s.trim().to_string();
        if t.is_empty() {
            continue;
        }
        if seen.insert(t.clone()) {
            out.push(t);
        }
    }
    out
}

// --- Tauri commands ---

fn row_to_profile(row: &rusqlite::Row<'_>) -> Result<WorkspaceProfileDto, rusqlite::Error> {
    let extra_roots: String = row.get(4)?;
    let extra_exec: String = row.get(5)?;
    Ok(WorkspaceProfileDto {
        id: row.get(0)?,
        name: row.get(1)?,
        path: row.get(2)?,
        last_opened: row.get(3)?,
        extra_roots: serde_json::from_str(&extra_roots).unwrap_or_default(),
        extra_executables: serde_json::from_str(&extra_exec).unwrap_or_default(),
        user_rules: row.get(6)?,
    })
}

#[tauri::command]
pub fn list_workspace_profiles(
    app: tauri::AppHandle,
) -> Result<Vec<WorkspaceProfileDto>, String> {
    let s = app.state::<AppStore>();
    let g = s.db.lock().map_err(|e| e.to_string())?;
    let mut stmt = g
        .prepare("SELECT id, name, path, last_opened, extra_roots, extra_executables, user_rules FROM profiles ORDER BY last_opened DESC")
        .map_err(|e| e.to_string())?;
    let out = stmt
        .query_map([], row_to_profile)
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[tauri::command]
pub fn get_app_state(app: tauri::AppHandle) -> Result<AppStateDto, String> {
    let s = app.state::<AppStore>();
    let g = s.db.lock().map_err(|e| e.to_string())?;
    g.query_row("SELECT active_profile_id, active_agent_id FROM app_state WHERE id = 1", [], |r| {
        Ok(AppStateDto {
            active_profile_id: r.get::<_, Option<String>>(0)?,
            active_agent_id: r.get::<_, Option<String>>(1)?,
        })
    })
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_active_profile_id(app: tauri::AppHandle, profile_id: String) -> Result<(), String> {
    let s = app.state::<AppStore>();
    let g = s.db.lock().map_err(|e| e.to_string())?;
    let n: i32 = g
        .query_row("SELECT COUNT(*) FROM profiles WHERE id = ?1", params![&profile_id], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("profile not found".to_string());
    }
    g.execute(
        "UPDATE app_state SET active_profile_id = ?1, active_agent_id = NULL WHERE id = 1",
        params![&profile_id],
    )
    .map_err(|e| e.to_string())?;
    repair_state(&g)?;
    // bump last opened
    let now = chrono::Utc::now().timestamp();
    g.execute(
        "UPDATE profiles SET last_opened = ?1 WHERE id = ?2",
        params![&now, &profile_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn create_workspace_profile(
    app: tauri::AppHandle,
    name: String,
    path: String,
) -> Result<WorkspaceProfileDto, String> {
    let p = PathBuf::from(path.trim());
    if !p.is_dir() {
        return Err("path must be an existing directory".to_string());
    }
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let canon = p
        .canonicalize()
        .map_err(|e| format!("canonicalize: {e}"))?
        .to_string_lossy()
        .to_string();
    let s = app.state::<AppStore>();
    let g = s.db.lock().map_err(|e| e.to_string())?;
    g.execute(
        "INSERT INTO profiles (id, name, path, last_opened, extra_roots, extra_executables, user_rules) VALUES (?1, ?2, ?3, ?4, '[]', '[]', '')",
        params![&id, &name, &canon, &now],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            "that path is already a workspace".to_string()
        } else {
            e.to_string()
        }
    })?;
    let agent_id = Uuid::new_v4().to_string();
    g.execute(
        "INSERT INTO agents (id, profile_id, title, created_at, updated_at) VALUES (?1, ?2, 'Main', ?3, ?3)",
        params![&agent_id, &id, &now],
    )
    .map_err(|e| e.to_string())?;
    g.execute(
        "UPDATE app_state SET active_profile_id = ?1, active_agent_id = ?2 WHERE id = 1",
        params![&id, &agent_id],
    )
    .map_err(|e| e.to_string())?;
    drop(g);
    list_workspace_profiles(app).and_then(|v| v.into_iter().find(|p| p.id == id).ok_or_else(|| "create failed".to_string()))
}

#[tauri::command]
pub fn list_agents(app: tauri::AppHandle) -> Result<Vec<AgentDto>, String> {
    let s = app.state::<AppStore>();
    let g = s.db.lock().map_err(|e| e.to_string())?;
    let profile_id: Option<String> = g
        .query_row(
            "SELECT active_profile_id FROM app_state WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let profile_id = profile_id.ok_or_else(|| "no active profile".to_string())?;
    let mut stmt = g
        .prepare("SELECT id, profile_id, title, created_at, updated_at FROM agents WHERE profile_id = ?1 ORDER BY updated_at DESC")
        .map_err(|e| e.to_string())?;
    let out = stmt
        .query_map(params![&profile_id], |r| {
            Ok(AgentDto {
                id: r.get(0)?,
                profile_id: r.get(1)?,
                title: r.get(2)?,
                created_at: r.get(3)?,
                updated_at: r.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(out)
}

#[tauri::command]
pub fn set_active_agent_id(app: tauri::AppHandle, agent_id: String) -> Result<(), String> {
    let s = app.state::<AppStore>();
    let g = s.db.lock().map_err(|e| e.to_string())?;
    let pid: Option<String> = g
        .query_row(
            "SELECT active_profile_id FROM app_state WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let pid = pid.ok_or_else(|| "no active profile".to_string())?;
    let n: i32 = g
        .query_row(
            "SELECT COUNT(*) FROM agents WHERE id = ?1 AND profile_id = ?2",
            params![&agent_id, &pid],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("agent not in active profile".to_string());
    }
    g.execute(
        "UPDATE app_state SET active_agent_id = ?1 WHERE id = 1",
        params![&agent_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn create_agent(app: tauri::AppHandle, title: Option<String>) -> Result<AgentDto, String> {
    let s = app.state::<AppStore>();
    let g = s.db.lock().map_err(|e| e.to_string())?;
    let pid: Option<String> = g
        .query_row(
            "SELECT active_profile_id FROM app_state WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let pid = pid.ok_or_else(|| "no active profile".to_string())?;
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().timestamp();
    let t = title
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Chat".to_string());
    g.execute(
        "INSERT INTO agents (id, profile_id, title, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)",
        params![&id, &pid, &t, &now],
    )
    .map_err(|e| e.to_string())?;
    g.execute(
        "UPDATE app_state SET active_agent_id = ?1 WHERE id = 1",
        params![&id],
    )
    .map_err(|e| e.to_string())?;
    Ok(AgentDto {
        id,
        profile_id: pid,
        title: t,
        created_at: now,
        updated_at: now,
    })
}

/// Load messages JSON array from the active profile's active agent.
#[tauri::command]
pub fn load_conversation(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let s = app.state::<AppStore>();
    let (pid, aid): (Option<String>, Option<String>) = {
        let g = s.db.lock().map_err(|e| e.to_string())?;
        g.query_row("SELECT active_profile_id, active_agent_id FROM app_state WHERE id = 1", [], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
            ))
        })
        .map_err(|e| e.to_string())?
    };
    let (pid, aid) = (pid.ok_or("no active profile")?, aid.ok_or("no active agent")?);
    let cpath = conversation_path(&pid, &aid)?;
    if !cpath.is_file() {
        return Ok(serde_json::json!([]));
    }
    read_jsonl(&cpath)
}

/// Save full conversation (replace) for the active profile/agent.
#[tauri::command]
pub fn save_conversation(
    app: tauri::AppHandle,
    messages: serde_json::Value,
) -> Result<(), String> {
    let s = app.state::<AppStore>();
    let (pid, aid): (Option<String>, Option<String>) = {
        let g = s.db.lock().map_err(|e| e.to_string())?;
        g.query_row("SELECT active_profile_id, active_agent_id FROM app_state WHERE id = 1", [], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
            ))
        })
        .map_err(|e| e.to_string())?
    };
    let (pid, aid) = (pid.ok_or("no active profile")?, aid.ok_or("no active agent")?);
    let arr = messages
        .as_array()
        .ok_or_else(|| "messages must be an array".to_string())?;
    let cpath = conversation_path(&pid, &aid)?;
    if let Some(p) = cpath.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let now = chrono::Utc::now().timestamp();
    {
        let g = s.db.lock().map_err(|e| e.to_string())?;
        g.execute(
            "UPDATE agents SET updated_at = ?1 WHERE id = ?2",
            params![&now, &aid],
        )
        .map_err(|e| e.to_string())?;
    }
    let mut buf = String::new();
    for m in arr {
        let line = serde_json::to_string(m).map_err(|e| e.to_string())?;
        buf.push_str(&line);
        buf.push('\n');
    }
    write_with_backup(&cpath, &buf)?;
    Ok(())
}

fn read_jsonl(path: &Path) -> Result<serde_json::Value, String> {
    let f = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut items = Vec::new();
    for line in std::io::BufReader::new(f).lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        items.push(v);
    }
    Ok(serde_json::Value::Array(items))
}

/// Import a legacy `localStorage` dump from the client (array of messages).
#[tauri::command]
pub fn import_local_storage_conversation(
    app: tauri::AppHandle,
    messages: serde_json::Value,
) -> Result<(), String> {
    let arr = messages
        .as_array()
        .ok_or_else(|| "messages must be an array".to_string())?
        .clone();
    if arr.is_empty() {
        return Ok(());
    }
    {
        let s = app.state::<AppStore>();
        let c = s.db.lock().map_err(|e| e.to_string())?;
        migrate_from_legacy_settings(&c, &app)?;
        repair_state(&c)?;
    }
    {
        let s = app.state::<AppStore>();
        let c = s.db.lock().map_err(|e| e.to_string())?;
        let has_agent: Option<String> = c
            .query_row("SELECT active_agent_id FROM app_state WHERE id = 1", [], |r| {
                r.get(0)
            })
            .map_err(|e| e.to_string())?;
        if has_agent.is_none() {
            if let Some(pid) = c
                .query_row("SELECT active_profile_id FROM app_state WHERE id = 1", [], |r| {
                    r.get::<_, Option<String>>(0)
                })
                .map_err(|e| e.to_string())?
            {
                let first: Option<String> = c
                    .query_row("SELECT id FROM agents WHERE profile_id = ?1 LIMIT 1", params![pid], |r| {
                        r.get(0)
                    })
                    .optional()
                    .map_err(|e| e.to_string())?;
                if let Some(aid) = first {
                    c.execute(
                        "UPDATE app_state SET active_agent_id = ?1 WHERE id = 1",
                        params![&aid],
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
    }
    save_conversation(app, serde_json::Value::Array(arr))
}

/// **Issue 6:** Profile path validity for active profile.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PathHealth {
    pub accessible: bool,
    pub reason: Option<String>,
}

#[tauri::command]
pub fn check_active_workspace_path(app: tauri::AppHandle) -> Result<PathHealth, String> {
    let s = app.state::<AppStore>();
    let p = s.effective_workspace_path(&app)?;
    if !p.exists() {
        return Ok(PathHealth {
            accessible: false,
            reason: Some("path does not exist".to_string()),
        });
    }
    if !p.is_dir() {
        return Ok(PathHealth {
            accessible: false,
            reason: Some("not a directory".to_string()),
        });
    }
    Ok(PathHealth {
        accessible: true,
        reason: None,
    })
}

const MAX_L2_BYTES: usize = 16 * 1024;
const MAX_PREFERENCES_BYTES: usize = 8 * 1024;
const MAX_USER_RULES: usize = 8 * 1024;

/// **L1/L2 + preferences:** `USER_RULES.md` in workspace wins over inline profile rules; optional
/// `NOTES.md` (long-term notes) and `PREFERENCES.md` (stable preferences, past mistakes, context).
#[tauri::command]
pub fn get_llm_context_extras(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let store = app.state::<AppStore>();
    let root = store.effective_workspace_path(&app)?;
    let file_rules = root.join("USER_RULES.md");
    let file_notes = root.join("NOTES.md");
    let file_preferences = root.join("PREFERENCES.md");
    let (mut user_rules, from_file) = if file_rules.is_file() {
        let t = fs::read_to_string(&file_rules).unwrap_or_default();
        (t, true)
    } else {
        (String::new(), false)
    };
    if from_file {
        if user_rules.len() > MAX_USER_RULES {
            user_rules = user_rules.chars().take(MAX_USER_RULES).collect();
        }
    } else {
        let g = store.db.lock().map_err(|e| e.to_string())?;
        if let Ok(pid) = g.query_row("SELECT active_profile_id FROM app_state WHERE id = 1", [], |r| {
            r.get::<_, Option<String>>(0)
        }) {
            if let Some(pid) = pid {
                if let Ok(ur) =
                    g.query_row("SELECT user_rules FROM profiles WHERE id = ?1", params![pid], |r| {
                        r.get::<_, String>(0)
                    })
                {
                    user_rules = ur;
                }
            }
        }
        if user_rules.len() > MAX_USER_RULES {
            user_rules = user_rules.chars().take(MAX_USER_RULES).collect();
        }
    }
    let memory_excerpt = if file_notes.is_file() {
        let t = fs::read_to_string(&file_notes).unwrap_or_default();
        t.chars().take(MAX_L2_BYTES).collect::<String>()
    } else {
        String::new()
    };
    let preferences_excerpt = if file_preferences.is_file() {
        let t = fs::read_to_string(&file_preferences).unwrap_or_default();
        t.chars()
            .take(MAX_PREFERENCES_BYTES)
            .collect::<String>()
    } else {
        String::new()
    };
    Ok(serde_json::json!({
        "userRules": user_rules,
        "userRulesFromFile": from_file,
        "memoryExcerpt": memory_excerpt,
        "preferencesExcerpt": preferences_excerpt,
    }))
}

//! Merge workspace `cti_vault.db` `cve_data` rows into the app `iocs` table (global profile).
//!
//! CVE runs from chat use `run_trusted_workflow` → terminal only; Python updates the vault DB
//! on disk. This path keeps **ioc_search** / the graph in sync with that vault.

use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags};
use serde::Serialize;
use tauri::AppHandle;
use tauri::Manager;

use crate::app_data::AppStore;
use crate::audit::append_audit;

use super::{truncate_raw, upsert_ioc};

const DEFAULT_ROW_CAP: u64 = 100_000;
const MAX_ROW_CAP: u64 = 500_000;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CtiVaultCveSyncResult {
    pub ok: bool,
    pub vault_path: String,
    pub scanned: u64,
    pub inserted: u32,
    pub updated: u32,
    pub skipped: u32,
    pub message: Option<String>,
}

fn cve_table_exists(vault: &Connection) -> Result<bool, String> {
    let n: i64 = vault
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cve_data'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| format!("vault schema probe: {e}"))?;
    Ok(n > 0)
}

/// Reads `cve_data` from `{workspaceRoot}/cti_vault.db` and upserts into app `iocs` as
/// `ioc_type = "cve"`, `profile_id` NULL (visible with default ioc_search scope).
#[tauri::command]
pub fn sync_cti_vault_cves_to_iocs(
    app: AppHandle,
    limit: Option<u64>,
) -> Result<CtiVaultCveSyncResult, String> {
    let store = app.state::<AppStore>();
    let root = store.effective_workspace_path(&app)?;
    let vault_path = root.join("cti_vault.db");
    let vault_display = vault_path.to_string_lossy().into_owned();

    if !vault_path.is_file() {
        return Ok(CtiVaultCveSyncResult {
            ok: true,
            vault_path: vault_display,
            scanned: 0,
            inserted: 0,
            updated: 0,
            skipped: 0,
            message: Some("cti_vault.db not found under workspace root — nothing to sync.".into()),
        });
    }

    let cap = limit.unwrap_or(DEFAULT_ROW_CAP).min(MAX_ROW_CAP);

    let vault = Connection::open_with_flags(&vault_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("open vault read-only: {e}"))?;
    vault
        .busy_timeout(Duration::from_secs(30))
        .map_err(|e| format!("vault busy_timeout: {e}"))?;

    if !cve_table_exists(&vault)? {
        return Ok(CtiVaultCveSyncResult {
            ok: true,
            vault_path: vault_display,
            scanned: 0,
            inserted: 0,
            updated: 0,
            skipped: 0,
            message: Some("cti_vault.db has no cve_data table yet.".into()),
        });
    }

    let mut stmt = vault
        .prepare(
            r#"SELECT cve_id, description, published, last_modified, cvss, metadata, updated_at, source_project
               FROM cve_data
               LIMIT ?1"#,
        )
        .map_err(|e| format!("vault prepare: {e}"))?;

    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let tx = g.unchecked_transaction().map_err(|e| e.to_string())?;

    let mut scanned: u64 = 0;
    let mut inserted: u32 = 0;
    let mut updated: u32 = 0;
    let mut skipped: u32 = 0;

    let mut rows = stmt
        .query(params![cap as i64])
        .map_err(|e| format!("vault query: {e}"))?;

    while let Some(row) = rows.next().map_err(|e| format!("vault row: {e}"))? {
        let cve_id: String = row.get(0).map_err(|e| format!("cve_id: {e}"))?;
        let cve_trim = cve_id.trim();
        if cve_trim.is_empty() {
            skipped = skipped.saturating_add(1);
            continue;
        }
        let description: Option<String> = row.get(1).ok();
        let published: Option<String> = row.get(2).ok();
        let last_modified: Option<String> = row.get(3).ok();
        let cvss: Option<String> = row.get(4).ok();
        let metadata: Option<String> = row.get(5).ok();
        let updated_at: Option<String> = row.get(6).ok();
        let source_project: Option<String> = row.get(7).ok();

        let meta_parsed: serde_json::Value = metadata
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Null);

        let frag = serde_json::json!({
            "vault": "cti_vault",
            "cve_id": cve_trim,
            "description": description,
            "published": published,
            "lastModified": last_modified,
            "cvss": cvss,
            "metadata": meta_parsed,
            "updatedAt": updated_at,
            "sourceProject": source_project,
        });
        let raw = truncate_raw(serde_json::to_string(&frag).ok());
        let src_proj = source_project
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("CVE_Project_NVD");
        let source = format!("cti_vault/{src_proj}");

        match upsert_ioc(
            &tx,
            cve_trim,
            "cve",
            &Some(source),
            None,
            &None,
            raw,
            &None,
            None,
            None,
            None,
        ) {
            Ok((_, is_upd)) => {
                scanned = scanned.saturating_add(1);
                if is_upd {
                    updated = updated.saturating_add(1);
                } else {
                    inserted = inserted.saturating_add(1);
                }
            }
            Err(e) => {
                let _ = tx.rollback();
                return Err(format!("upsert CVE {cve_trim}: {e}"));
            }
        }
    }

    tx.commit().map_err(|e| e.to_string())?;
    drop(g);

    let _ = append_audit(
        &app,
        "sync_cti_vault_cves_to_iocs",
        serde_json::json!({
            "vaultPath": vault_display,
            "scanned": scanned,
            "inserted": inserted,
            "updated": updated,
            "skipped": skipped,
        }),
    );

    Ok(CtiVaultCveSyncResult {
        ok: true,
        vault_path: vault_display,
        scanned,
        inserted,
        updated,
        skipped,
        message: None,
    })
}

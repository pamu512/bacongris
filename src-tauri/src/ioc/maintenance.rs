//! Auto-purge expired IOCs and cap confidence for stale records (solo analyst hygiene).
use rusqlite::Connection;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IocMaintenanceResult {
    pub purged: u32,
    pub confidence_capped_mid_bucket: u32,
    pub confidence_capped_very_stale: u32,
    pub expiring_grace_set: u32,
}

const DAY: i64 = 86400;

/// Delete expired, cap confidence in the 30–90d and >90d buckets, and set `valid_until` grace for very stale rows.
pub fn run_ioc_maintenance(conn: &Connection) -> Result<IocMaintenanceResult, String> {
    let now = chrono::Utc::now().timestamp();
    let t30 = now - 30 * DAY;
    let t90 = now - 90 * DAY;
    let grace = now + 7 * DAY;

    let purged = conn
        .execute(
            "DELETE FROM iocs WHERE valid_until IS NOT NULL AND valid_until < ?1",
            [now],
        )
        .map_err(|e| e.to_string())? as u32;

    // Between ~90d and ~30d old: cap at 60 (treats NULL confidence as high until capped).
    let confidence_capped_mid_bucket = conn
        .execute(
            r#"UPDATE iocs SET confidence = 60
               WHERE last_seen < ?1 AND last_seen >= ?2
                 AND (confidence IS NULL OR confidence > 60)"#,
            rusqlite::params![&t30, &t90],
        )
        .map_err(|e| e.to_string())? as u32;

    // Older than ~90d: cap at 20.
    let confidence_capped_very_stale = conn
        .execute(
            r#"UPDATE iocs SET confidence = 20
               WHERE last_seen < ?1
                 AND (confidence IS NULL OR confidence > 20)"#,
            [t90],
        )
        .map_err(|e| e.to_string())? as u32;

    // >90d with no valid_until: schedule delete after grace window.
    let expiring_grace_set = conn
        .execute(
            "UPDATE iocs SET valid_until = ?1 WHERE last_seen < ?2 AND valid_until IS NULL",
            rusqlite::params![&grace, &t90],
        )
        .map_err(|e| e.to_string())? as u32;

    Ok(IocMaintenanceResult {
        purged,
        confidence_capped_mid_bucket,
        confidence_capped_very_stale,
        expiring_grace_set,
    })
}

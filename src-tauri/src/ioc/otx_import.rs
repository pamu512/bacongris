//! OTX `GET /api/v1/pulses/subscribed` (JSON `results[]` with `indicators[]`).

use serde_json::Value;
use tauri::AppHandle;
use tauri::Manager;

use crate::app_data::AppStore;
use super::{append_audit, resolve_profile, truncate_raw, upsert_ioc, IocImportResult};

const MAX_VALUE_LEN: usize = 4 * 1024;
const MAX_INDICATORS: usize = 5_000;

/// Normalizes an OTX `indicator` type string to our iocs.`type` column.
fn otx_type_to_ours(otx: &str) -> &'static str {
    let t = otx.trim().to_ascii_lowercase();
    match t.as_str() {
        "ssdeep" => "other",
        "ipv4" | "ip" | "ip address" | "ip_address" => "ipv4",
        "ipv6" => "ipv6",
        "domain" | "hostname" | "cname" | "host" => "domain",
        "url" | "uri" => "url",
        "filehash-md5" | "filehash-sslcert-md5" => "md5",
        "filehash-sha1" | "filehash-sslcert-sha1" | "filehash-sslcert-sha-1" => "sha1",
        "filehash-sha256" | "filehash-sslcert-sha256" | "filehash-sslcert-sha-256" => "sha256",
        "email" | "e-mail" | "emails" => "email",
        "yara" | "snort" | "pcre" | "mutex" | "vulnerability" | "cve" | "cidr" | "pehash" | "imphash" => "other",
        s if s.starts_with("filehash-") => "other",
        _ => "other",
    }
}

/// Ingests `body` (OTX `pulses/subscribed` JSON) into the IOC table.
pub fn import_otx_subscribed_pulses(
    app: &AppHandle,
    body: &Value,
    default_source: &str,
) -> Result<IocImportResult, String> {
    let prof = resolve_profile(app, None)?;
    let default_src = default_source.trim();
    if default_src.is_empty() {
        return Err("OTX import: empty feed source name".into());
    }
    let source_opt = Some(default_src.to_string());
    let results: &[Value] = body
        .get("results")
        .and_then(|a| a.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    let mut inserted: u32 = 0;
    let mut updated: u32 = 0;
    let mut skipped: u32 = 0;
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    let mut seen = 0u32;
    {
        let tx = g.unchecked_transaction().map_err(|e| e.to_string())?;
        for pulse in results {
            let camp: Option<String> = pulse
                .get("name")
                .or_else(|| pulse.get("id"))
                .and_then(|v| v.as_str().map(|s| s.to_string().chars().take(200).collect()));
            if let Some(indicators) = pulse.get("indicators").and_then(|a| a.as_array()) {
                for ind in indicators {
                    if seen as usize >= MAX_INDICATORS {
                        let _ = tx.rollback();
                        return Err("OTX import: exceeded cap (try again after filtering)".into());
                    }
                    let otype = ind.get("type").and_then(|t| t.as_str()).unwrap_or("").trim();
                    let ival = ind
                        .get("indicator")
                        .and_then(|i| i.as_str())
                        .or_else(|| ind.get("content").and_then(|c| c.as_str()));
                    let Some(ival) = ival else {
                        skipped = skipped.saturating_add(1);
                        continue;
                    };
                    if ival.len() > MAX_VALUE_LEN {
                        skipped = skipped.saturating_add(1);
                        continue;
                    }
                    let ival = ival.trim();
                    if ival.is_empty() {
                        skipped = skipped.saturating_add(1);
                        continue;
                    }
                    if otype.is_empty() {
                        skipped = skipped.saturating_add(1);
                        continue;
                    }
                    let itype = otx_type_to_ours(otype);
                    let raw = truncate_raw(serde_json::to_string(ind).ok());
                    match upsert_ioc(
                        &tx,
                        ival,
                        itype,
                        &source_opt,
                        None,
                        &camp,
                        raw,
                        &prof,
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
                            seen = seen.saturating_add(1);
                        }
                        Err(e) => {
                            let _ = tx.rollback();
                            return Err(e);
                        }
                    }
                }
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
    }
    drop(g);
    let res = IocImportResult {
        inserted,
        updated,
        skipped,
        source: default_src.to_string(),
    };
    let _ = append_audit(
        app,
        "ioc_import",
        serde_json::json!({
            "source": default_src, "otxPulses": true, "inserted": inserted, "updated": updated, "skipped": skipped
        }),
    );
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::otx_type_to_ours;

    #[test]
    fn type_map() {
        assert_eq!(otx_type_to_ours("IPv4"), "ipv4");
        assert_eq!(otx_type_to_ours("FileHash-MD5"), "md5");
    }
}

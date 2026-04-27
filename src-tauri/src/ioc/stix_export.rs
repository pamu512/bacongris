//! Serialize IOC rows to a STIX 2.1 `bundle` (observables + identity).
use serde_json::{json, Value};
use uuid::Uuid;

use super::IocRow;

pub fn rows_to_stix_bundle_json(
    rows: &[IocRow],
    producer_label: &str,
) -> Result<String, String> {
    if rows.is_empty() {
        return Err("no IOCs to export".to_string());
    }
    let bundle_id = format!("bundle--{}", Uuid::new_v4());
    let now = stix_time_now();
    let identity_id = format!("identity--{}", Uuid::new_v4());
    let mut objects: Vec<Value> = vec![json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": &now,
        "modified": &now,
        "name": producer_label,
        "identity_class": "organization"
    })];

    for row in rows {
        if row.value.trim().is_empty() {
            continue;
        }
        let created = ts_to_stix_time(row.first_seen);
        let modified = ts_to_stix_time(row.last_seen);
        let ext = format!(
            "Bacongris export; iocType={}; dbSource={}; campaign={:?}; confidence={:?}; validUntil={:?}; falsePositive={}; mitre={}",
            row.ioc_type,
            row.source.as_deref().unwrap_or("-"),
            row.campaign_tag,
            row.confidence,
            row.valid_until,
            row.is_false_positive,
            row.mitre_techniques.join(",")
        );
        objects.push(row_to_stix_object(row, &created, &modified, &ext));
    }

    if objects.len() <= 1 {
        return Err("no non-empty IOC values to export".to_string());
    }

    let bundle = json!({
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    });
    serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())
}

fn stix_time_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn ts_to_stix_time(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(stix_time_now)
}

fn row_to_stix_object(row: &IocRow, created: &str, modified: &str, description: &str) -> Value {
    let t = row.ioc_type.to_lowercase();
    let v = &row.value;
    let id = format!("{}--{}", stix_id_prefix(&t), Uuid::new_v4());
    match t.as_str() {
        "ipv4" => json!({
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": id,
            "created": created,
            "modified": modified,
            "value": v
        }),
        "ipv6" => json!({
            "type": "ipv6-addr",
            "spec_version": "2.1",
            "id": id,
            "created": created,
            "modified": modified,
            "value": v
        }),
        "domain" => json!({
            "type": "domain-name",
            "spec_version": "2.1",
            "id": id,
            "created": created,
            "modified": modified,
            "value": v
        }),
        "url" => json!({
            "type": "url",
            "spec_version": "2.1",
            "id": id,
            "created": created,
            "modified": modified,
            "value": v
        }),
        "email" => json!({
            "type": "email-addr",
            "spec_version": "2.1",
            "id": id,
            "created": created,
            "modified": modified,
            "value": v
        }),
        "md5" | "sha1" | "sha256" | "sha512" | "ssdeep" => {
            let hk = match t.as_str() {
                "md5" => "MD5",
                "sha1" => "SHA-1",
                "sha256" => "SHA-256",
                "sha512" => "SHA-512",
                "ssdeep" => "SSDEEP",
                _ => "SHA-256",
            };
            json!({
                "type": "file",
                "spec_version": "2.1",
                "id": id,
                "created": created,
                "modified": modified,
                "hashes": { hk: v }
            })
        }
        _ => json!({
            "type": "note",
            "spec_version": "2.1",
            "id": id,
            "created": created,
            "modified": modified,
            "content": v,
            "abstract": description,
            "object_refs": []
        }),
    }
}

fn stix_id_prefix(t: &str) -> &'static str {
    match t {
        "ipv4" => "ipv4-addr",
        "ipv6" => "ipv6-addr",
        "domain" => "domain-name",
        "url" => "url",
        "email" => "email-addr",
        "md5" | "sha1" | "sha256" | "sha512" | "ssdeep" => "file",
        _ => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::IocRow;

    #[test]
    fn export_bundle_is_json() {
        let row = IocRow {
            id: "i1".into(),
            value: "198.51.100.1".into(),
            ioc_type: "ipv4".into(),
            source: Some("t".into()),
            confidence: Some(80),
            first_seen: 0,
            last_seen: 0,
            campaign_tag: None,
            raw_json: None,
            profile_id: None,
            valid_until: None,
            is_false_positive: false,
            mitre_techniques: vec![],
        };
        let j = rows_to_stix_bundle_json(&[row], "test").unwrap();
        assert!(j.contains("ipv4-addr"));
        let v: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v.get("type"), Some(&json!("bundle")));
    }
}

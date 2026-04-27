//! OpenCTI GraphQL `stixCyberObservables` edge nodes → local IOC quads.
use serde_json::{json, Value};

use super::import_snapshots;
use super::resolve_profile;
use super::IocImportResult;
use tauri::AppHandle;

const MAX_LEN: usize = 4 * 1024;

/// Map OpenCTI `entity_type` (any casing) to our ioc `type` column, or "other".
fn map_entity_type(et: &str) -> Option<&'static str> {
    let e = et.to_ascii_lowercase();
    if e == "ipv4-addr" || e == "ipv4addr" {
        return Some("ipv4");
    }
    if e == "ipv6-addr" {
        return Some("ipv6");
    }
    if e == "domain-name" {
        return Some("domain");
    }
    if e == "url" {
        return Some("url");
    }
    if e == "email-addr" {
        return Some("email");
    }
    if e == "stixfile" || e == "file" {
        return None;
    }
    if matches!(
        e.as_str(),
        "text"
            | "mutex"
            | "yara"
            | "autonomous-system"
            | "windows-registry-key"
            | "process"
            | "x509-certificate"
            | "user-account"
            | "mac-addr"
            | "software"
    ) {
        return Some("other");
    }
    None
}

/// From one OpenCTI `stixCyberObservables` edge `node` JSON, emit (value, ioc_type) pairs
/// (files may produce multiple for different hashes).
fn node_to_value_types(node: &Value) -> Vec<(String, &'static str, Value)> {
    let mut out = vec![];
    let et = node
        .get("entity_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let frag = node.clone();
    if let Some(v) = node.get("x_opencti_value").and_then(|s| s.as_str()) {
        if !v.trim().is_empty() {
            if let Some(t) = map_entity_type(&et) {
                if v.len() <= MAX_LEN {
                    out.push((v.to_string().trim().to_string(), t, frag.clone()));
                }
            } else {
                if v.len() <= MAX_LEN {
                    out.push((v.to_string().trim().to_string(), "other", frag.clone()));
                }
            }
        }
    }
    let el = et.to_ascii_lowercase();
    if el == "stixfile" || el == "file" {
        if let Some(h) = node.get("hashes") {
            if let Some(arr) = h.as_array() {
                for item in arr {
                    let alg = item
                        .get("algorithm")
                        .or_else(|| item.get("name"))
                        .and_then(|a| a.as_str());
                    let hv = item.get("hash").and_then(|x| x.as_str());
                    if let (Some(alg_s), Some(hash)) = (alg, hv) {
                        if hash.is_empty() || hash.len() > 128 {
                            continue;
                        }
                        let t = match alg_s.to_uppercase().as_str() {
                            "MD5" if hash.len() == 32 => "md5",
                            "SHA-1" | "SHA1" if hash.len() == 40 => "sha1",
                            "SHA-256" | "SHA256" if hash.len() == 64 => "sha256",
                            "SSDEEP" => "other",
                            _ => "other",
                        };
                        out.push((hash.to_string(), t, node.clone()));
                    }
                }
            } else if let Some(obj) = h.as_object() {
                for (k, v) in obj {
                    if let Some(hash) = v.as_str() {
                        if hash.is_empty() {
                            continue;
                        }
                        let t = match k.to_uppercase().as_str() {
                            "MD5" => "md5",
                            "SHA-1" | "SHA1" => "sha1",
                            "SHA-256" | "SHA256" => "sha256",
                            _ => continue,
                        };
                        if hash.len() <= 128 {
                            out.push((hash.to_string(), t, node.clone()));
                        }
                    }
                }
            }
        }
    }
    if out.is_empty() {
        if let Some(n) = node.get("number") {
            if let Some(anon) = n.as_i64() {
                let s = format!("{anon}");
                out.push((s, "other", frag));
            } else if let Some(s) = n.as_str() {
                if !s.is_empty() {
                    out.push((s.to_string(), "other", frag));
                }
            }
        }
    }
    // Dedup same (value, type) in this node
    use std::collections::HashSet;
    let mut seen: HashSet<(String, String)> = HashSet::new();
    out
        .into_iter()
        .filter(|(v, t, _)| seen.insert((v.clone(), (*t).to_string())))
        .collect()
}

/// `edges` is the array from `stixCyberObservables.edges`.
pub fn import_from_opencti_stix_cyber_observables(
    app: &AppHandle,
    edges: &[Value],
    default_source: &str,
) -> Result<IocImportResult, String> {
    let def = default_source.trim();
    if def.is_empty() {
        return Err("OpenCTI import: empty source (feed name)".into());
    }
    let prof = resolve_profile(app, None)?;
    let mut quads: Vec<(String, String, String, Value)> = vec![];
    for e in edges {
        let node = e.get("node");
        if node.is_none() {
            continue;
        }
        for (val, it, frag) in node_to_value_types(node.as_ref().unwrap()) {
            quads.push((
                val,
                it.to_string(),
                String::new(),
                json!({ "opencti": frag }),
            ));
        }
    }
    if quads.is_empty() {
        return Ok(IocImportResult {
            inserted: 0,
            updated: 0,
            skipped: 0,
            source: def.to_string(),
        });
    }
    import_snapshots(app, quads, def, &None, &prof)
}

#[cfg(test)]
mod tests {
    use super::node_to_value_types;
    use serde_json::json;

    #[test]
    fn ipv4_observable() {
        let n = json!({
            "entity_type": "IPv4-Addr",
            "x_opencti_value": "198.51.100.1"
        });
        let v = node_to_value_types(&n);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "198.51.100.1");
        assert_eq!(v[0].1, "ipv4");
    }

    #[test]
    fn file_hashes() {
        let n = json!({
            "entity_type": "StixFile",
            "hashes": [
                {"algorithm": "SHA-256", "hash": "abababababababababababababababababababababababababababababababab"}
            ]
        });
        let v = node_to_value_types(&n);
        assert!(!v.is_empty());
    }
}

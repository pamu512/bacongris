//! Extract IOC-like values from STIX 2.0/2.1 JSON (bundle or single object).
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct StixSnapshot {
    pub value: String,
    pub ioc_type: String,
    pub fragment: Value,
}

/// Returns normalized snapshots with types: ipv4, ipv6, domain, url, md5, sha1, sha256, email, other.
pub fn extract_from_stix(json_str: &str) -> Result<Vec<StixSnapshot>, String> {
    let root: Value = serde_json::from_str(json_str.trim())
        .map_err(|e| format!("STIX parse: invalid JSON: {e}"))?;
    let objects: Vec<Value> = if let Some(arr) = root.get("objects").and_then(|o| o.as_array()) {
        arr.clone()
    } else {
        vec![root]
    };
    if objects.is_empty() {
        return Ok(vec![]);
    }
    let mut out: Vec<StixSnapshot> = vec![];
    for obj in objects {
        extract_from_stix_object(&obj, &mut out)?;
    }
    // Dedupe (value+type) within batch
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert((s.value.clone(), s.ioc_type.clone())));
    Ok(out)
}

fn extract_from_stix_object(obj: &Value, out: &mut Vec<StixSnapshot>) -> Result<(), String> {
    let t = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match t {
        "ipv4-addr" => {
            if let Some(v) = obj.get("value").and_then(|x| x.as_str()) {
                if !v.is_empty() {
                    out.push(StixSnapshot {
                        value: v.to_string(),
                        ioc_type: "ipv4".to_string(),
                        fragment: obj.clone(),
                    });
                }
            }
        }
        "ipv6-addr" => {
            if let Some(v) = obj.get("value").and_then(|x| x.as_str()) {
                if !v.is_empty() {
                    out.push(StixSnapshot {
                        value: v.to_string(),
                        ioc_type: "ipv6".to_string(),
                        fragment: obj.clone(),
                    });
                }
            }
        }
        "domain-name" => {
            if let Some(v) = obj.get("value").and_then(|x| x.as_str()) {
                if !v.is_empty() {
                    out.push(StixSnapshot {
                        value: v.to_string(),
                        ioc_type: "domain".to_string(),
                        fragment: obj.clone(),
                    });
                }
            }
        }
        "url" => {
            if let Some(v) = obj.get("value").and_then(|x| x.as_str()) {
                if !v.is_empty() {
                    out.push(StixSnapshot {
                        value: v.to_string(),
                        ioc_type: "url".to_string(),
                        fragment: obj.clone(),
                    });
                }
            }
        }
        "email-addr" => {
            if let Some(v) = obj.get("value").and_then(|x| x.as_str()) {
                if !v.is_empty() {
                    out.push(StixSnapshot {
                        value: v.to_string(),
                        ioc_type: "email".to_string(),
                        fragment: obj.clone(),
                    });
                }
            }
        }
        "file" => {
            if let Some(h) = obj.get("hashes").and_then(|x| x.as_object()) {
                for (hk, val) in h {
                    let Some(s) = val.as_str() else { continue };
                    if s.is_empty() {
                        continue;
                    }
                    let ioc_type = match hk.to_uppercase().as_str() {
                        "MD5" => Some("md5"),
                        "SHA-1" | "SHA1" => Some("sha1"),
                        "SHA-256" | "SHA256" => Some("sha256"),
                        "SHA-512" | "SHA512" => Some("sha512"),
                        "SSDEEP" => Some("ssdeep"),
                        _ => None,
                    };
                    if let Some(ty) = ioc_type {
                        out.push(StixSnapshot {
                            value: s.to_string(),
                            ioc_type: ty.to_string(),
                            fragment: obj.clone(),
                        });
                    }
                }
            }
        }
        "indicator" => {
            if let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) {
                extract_from_stix_pattern(pattern, obj, out);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Extract from STIX [observable:field = 'value'] style patterns.
fn extract_from_stix_pattern(pattern: &str, ind_obj: &Value, out: &mut Vec<StixSnapshot>) {
    if let Ok(re) = regex::Regex::new(r"=\s*'([^']+)'") {
        for cap in re.captures_iter(pattern) {
            if let Some(m) = cap.get(1) {
                let val = m.as_str().trim();
                    if (2..=512).contains(&val.len()) {
                    let low = pattern.to_lowercase();
                    if low.contains("md5") && val.len() == 32 {
                        out.push(mk(val, "md5", ind_obj));
                    } else if (low.contains("sha-1") || low.contains("sha1")) && val.len() == 40
                    {
                        out.push(mk(val, "sha1", ind_obj));
                    } else if (low.contains("sha-256") || low.contains("sha256")) && val.len() == 64
                    {
                        out.push(mk(val, "sha256", ind_obj));
                    } else if low.contains("ipv4-addr")
                        && val
                            .chars()
                            .all(|c| c.is_ascii_digit() || c == '.')
                    {
                        out.push(mk(val, "ipv4", ind_obj));
                    } else if low.contains("ipv6-addr") {
                        out.push(mk(val, "ipv6", ind_obj));
                    } else if low.contains("domain-name") {
                        out.push(mk(val, "domain", ind_obj));
                    } else if low.contains("url") {
                        out.push(mk(val, "url", ind_obj));
                    }
                }
            }
        }
    }
    if let Ok(re) = regex::Regex::new(r#"\s*=\s*\"([^\"]+)\""#) {
        for cap in re.captures_iter(pattern) {
            if let Some(m) = cap.get(1) {
                let val = m.as_str();
                if val.is_empty() {
                    continue;
                }
                let lowp = pattern.to_lowercase();
                if lowp.contains("ipv4")
                    || lowp.contains("md5")
                    || lowp.contains("sha-256")
                    || lowp.contains("domain")
                    || lowp.contains("url")
                {
                    out.push(mk(val, "other", ind_obj));
                }
            }
        }
    }
    // Last resort: a single-quoted string in a one-line pattern
    if out.is_empty() {
        for seg in pattern.split('[') {
            if let Some(quote) = seg.find('\'') {
                let after = &seg[quote + 1..];
                if let Some(end) = after.find('\'') {
                    let s = &after[..end];
                    if s.len() >= 4 && s.len() <= 512 {
                        out.push(mk(s, "other", &json!({ "pattern": pattern })));
                        return;
                    }
                }
            }
        }
    }
}

fn mk(val: &str, ioc: &str, fragment: &Value) -> StixSnapshot {
    StixSnapshot {
        value: val.to_string(),
        ioc_type: ioc.to_string(),
        fragment: fragment.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stix_file_hash() {
        let j = r#"{"type":"bundle","id":"bundle-1","objects":[
        {"type":"file","id":"f1","hashes":{"MD5":"d41d8cd98f00b204e9800998ecf8427e"}}
        ]}"#;
        let v = extract_from_stix(j).unwrap();
        assert_eq!(v[0].ioc_type, "md5");
    }

    #[test]
    fn stix_ip() {
        let j = r#"{"type":"ipv4-addr","id":"a","value":"198.51.100.3"}"#;
        let v = extract_from_stix(j).unwrap();
        assert_eq!(v[0].value, "198.51.100.3");
        assert_eq!(v[0].ioc_type, "ipv4");
    }
}

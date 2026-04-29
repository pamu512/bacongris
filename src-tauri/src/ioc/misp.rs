//! Extract observables from a MISP event JSON (export format with `Event` root).
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct MispSnapshot {
    pub value: String,
    pub ioc_type: String,
    /// Original MISP type string (e.g. `ip-dst`); useful for display / debugging.
    #[allow(dead_code)]
    pub misp_type: String,
    pub fragment: Value,
}

pub fn extract_from_misp_event(json_str: &str) -> Result<Vec<MispSnapshot>, String> {
    let v: Value = serde_json::from_str(json_str.trim())
        .map_err(|e| format!("MISP parse: invalid JSON: {e}"))?;
    let event = v
        .get("Event")
        .or_else(|| v.get("event"))
        .ok_or("MISP: missing Event object")?;
    let mut out: Vec<MispSnapshot> = vec![];

    if let Some(arr) = event.get("Attribute").and_then(|a| a.as_array()) {
        for a in arr {
            push_misp_attr(a, &mut out);
        }
    }
    if let Some(objs) = event.get("Object").and_then(|a| a.as_array()) {
        for o in objs {
            if let Some(attrs) = o.get("Attribute").and_then(|a| a.as_array()) {
                for a in attrs {
                    push_misp_attr(a, &mut out);
                }
            }
        }
    }

    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert((s.value.clone(), s.ioc_type.clone())));
    Ok(out)
}

fn push_misp_attr(a: &Value, out: &mut Vec<MispSnapshot>) {
    let Some(misp_type) = a.get("type").and_then(|t| t.as_str()) else {
        return;
    };
    let Some(value) = a.get("value").and_then(|v| v.as_str()) else {
        return;
    };
    if value.is_empty() {
        return;
    }
    if let Some(ioc) = misp_type_to_ioc(misp_type, value) {
        out.push(MispSnapshot {
            value: value.to_string(),
            ioc_type: ioc.to_string(),
            misp_type: misp_type.to_string(),
            fragment: a.clone(),
        });
    }
}

fn misp_type_to_ioc(misp_type: &str, value: &str) -> Option<&'static str> {
    let t = misp_type.to_lowercase();
    match t.as_str() {
        "md5" | "md5|filename" | "filename|md5" | "imphash" if value.len() == 32
            && value.chars().all(|c| c.is_ascii_hexdigit()) =>
        {
            Some("md5")
        }
        "sha1" | "sha1|filename" | "filename|sha1" if value.len() == 40
            && value.chars().all(|c| c.is_ascii_hexdigit()) =>
        {
            Some("sha1")
        }
        "sha256" | "sha256|filename" | "filename|sha256" if value.len() == 64
            && value.chars().all(|c| c.is_ascii_hexdigit()) =>
        {
            Some("sha256")
        }
        "ssdeep" | "fuzzy-hash" => Some("ssdeep"),
        "domain" | "hostname" => Some("domain"),
        "domain|ip" => {
            if let Some(d) = value.split('|').next() {
                if d.contains('.') {
                    return Some("domain");
                }
            }
            None
        }
        "url" | "uri" => Some("url"),
        "http-method" | "user-agent" => None,
        "email-src" | "email-dst" | "target-email" => Some("email"),
        "as" | "x509" | "port" | "pdb" | "whois" | "vulnerability" | "yara" | "snort" | "eppn" => {
            None
        }
        "ip-src" | "ip-dst" | "ip-src|port" | "ip-dst|port" => {
            let part = value.split('|').next().unwrap_or(value);
            if part.contains('.') && part.chars().filter(|c| *c == '.').count() == 3 {
                Some("ipv4")
            } else if part.contains(':') {
                Some("ipv6")
            } else {
                None
            }
        }
        "comment" | "other" | "regkey" | "mutex" | "btc" | "filename" => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misp_event_ip() {
        let j = r#"{"Event":{"id":"1","info":"test","Attribute":[
        {"type":"ip-dst","value":"1.1.1.1","to_ids":true,"category":"Network activity"}
        ]}}"#;
        let v = extract_from_misp_event(j).unwrap();
        assert_eq!(v[0].value, "1.1.1.1");
        assert_eq!(v[0].ioc_type, "ipv4");
    }
}

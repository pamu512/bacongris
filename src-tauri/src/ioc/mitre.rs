//! Normalize and validate MITRE ATT&CK technique / tactic id strings.
use regex::Regex;
use std::sync::OnceLock;

static RE_TECHNIQUE: OnceLock<Regex> = OnceLock::new();
static RE_TACTIC: OnceLock<Regex> = OnceLock::new();

fn re_technique() -> &'static Regex {
    RE_TECHNIQUE.get_or_init(|| Regex::new(r"^(?i)T\d{4}(\.\d{3})?$").expect("re"))
}
fn re_tactic() -> &'static Regex {
    RE_TACTIC.get_or_init(|| Regex::new(r"^(?i)TA\d{4}$").expect("re"))
}

/// Case-normalizes valid MITRE ATT&CK technique (T#### / T####.###) or tactic (TA####) ids.
pub fn validate_and_normalize_mitre_id(s: &str) -> Result<String, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err("empty MITRE id".into());
    }
    if re_tactic().is_match(t) {
        return Ok(t.to_uppercase());
    }
    if re_technique().is_match(t) {
        return Ok(t.to_uppercase());
    }
    Err(format!(
        "Invalid MITRE id: {t} (use T####, T####.###, or TA####)"
    ))
}

/// Validate list, de-dupe, sort; returns JSON array string.
pub fn mitre_vec_to_json_stored(v: Option<Vec<String>>) -> Result<Option<String>, String> {
    let Some(v) = v else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for s in v {
        if s.trim().is_empty() {
            continue;
        }
        let n = validate_and_normalize_mitre_id(&s)?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out.sort();
    let j = serde_json::to_string(&out).map_err(|e| e.to_string())?;
    Ok(Some(j))
}

/// Parse `mitre_techniques` column into a vec.
pub fn mitre_json_stored_to_vec(mts: &str) -> Vec<String> {
    if mts.is_empty() {
        return vec![];
    }
    match serde_json::from_str::<Vec<String>>(mts) {
        Ok(v) => v,
        Err(_) => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_subtechnique() {
        let v = validate_and_normalize_mitre_id("t1059.001").unwrap();
        assert_eq!(v, "T1059.001");
    }

    #[test]
    fn accepts_ta() {
        let v = validate_and_normalize_mitre_id("ta0001").unwrap();
        assert_eq!(v, "TA0001");
    }
}

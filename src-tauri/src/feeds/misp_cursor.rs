//! MISP `restSearch` cursor: optional `timestamp` (Unix) for incremental polling.
use serde_json::{json, Value};

/// Initial window when no cursor is stored (7 days of history).
const MISP_LOOKBACK_SEC: i64 = 7 * 24 * 3600;

fn max_timestamp_in_value(v: &Value) -> Option<i64> {
    let mut m: Option<i64> = None;
    let mut visit = |t: i64| {
        m = Some(m.map_or(t, |c| c.max(t)));
    };
    walk(v, &mut visit);
    m
}

fn walk(v: &Value, visit: &mut impl FnMut(i64)) {
    match v {
        Value::Object(map) => {
            if let Some(t) = map.get("timestamp") {
                if let Some(n) = t.as_i64() {
                    visit(n);
                } else if let Some(f) = t.as_f64() {
                    visit(f as i64);
                } else if let Some(s) = t.as_str() {
                    if let Ok(n) = s.parse::<i64>() {
                        visit(n);
                    }
                }
            }
            for x in map.values() {
                walk(x, visit);
            }
        }
        Value::Array(a) => {
            for x in a {
                walk(x, visit);
            }
        }
        _ => {}
    }
}

/// Returns the max `timestamp` field found anywhere in the MISP JSON (attributes, event-level, etc.).
pub fn max_misp_attr_timestamp(v: &Value) -> Option<i64> {
    max_timestamp_in_value(v)
}

fn parse_misp_next_ts(cursor_json: Option<&str>) -> Option<i64> {
    let s = cursor_json?;
    let v: Value = serde_json::from_str(s).ok()?;
    let n = v
        .get("misp")
        .and_then(|m| m.get("nextTimestamp"))
        .and_then(|x| {
            x.as_i64()
                .or_else(|| x.as_f64().map(|f| f as i64))
                .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
        });
    n
}

/// Next `timestamp` to send in `restSearch` (attributes with timestamp *greater* than this value).
pub fn misp_start_timestamp(cursor_json: Option<&str>, now: i64) -> i64 {
    parse_misp_next_ts(cursor_json)
        .unwrap_or_else(|| now - MISP_LOOKBACK_SEC)
}

/// After a successful poll, persist the high-water mark for the next run.
pub fn misp_next_cursor_json(prev: Option<&str>, body: &Value, now: i64) -> String {
    let high = max_misp_attr_timestamp(body).unwrap_or(now);
    // Merge only `misp` to leave room for other keys later.
    let base: Value = prev
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| json!({}));
    let mut m = base.as_object().cloned().unwrap_or_default();
    m.insert(
        "misp".to_string(),
        json!({ "nextTimestamp": high }),
    );
    Value::Object(m).to_string()
}

pub fn misp_request_body_with_timestamp(start_ts: i64) -> String {
    json!({
        "returnFormat": "json",
        "limit": 200,
        "timestamp": start_ts
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn max_nested_timestamps() {
        let v = json!({ "response": { "Attribute": [ { "timestamp": "10" }, { "timestamp": 5 } ] } });
        assert_eq!(max_misp_attr_timestamp(&v), Some(10));
    }
}

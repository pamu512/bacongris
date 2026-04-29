//! OpenCTI GraphQL: paginated `stixCyberObservables` import.
use chrono::Utc;
use serde_json::{json, Value};

use crate::api::HttpApiState;
use crate::ioc::import_from_opencti_stix_cyber_observables;
use tauri::AppHandle;

use super::FeedRow;

const PAGE_SIZE: i64 = 100;
const MAX_PAGES_PER_POLL: usize = 50;

fn build_query() -> &'static str {
    r#"query OpenCTIStixCyberObservables($first: Int!, $after: String) {
  stixCyberObservables(first: $first, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        id
        entity_type
        x_opencti_value
        number
        hashes {
          algorithm
          hash
        }
      }
    }
  }
}"#
}

fn graphql_body(first: i64, after: Option<&str>) -> String {
    json!({
        "query": build_query(),
        "operationName": "OpenCTIStixCyberObservables",
        "variables": {
            "first": first,
            "after": after
        }
    })
    .to_string()
}

fn get_errors(body: &Value) -> Option<String> {
    let err = body.get("errors");
    if let Some(arr) = err.and_then(|a| a.as_array()) {
        if arr.is_empty() {
            return None;
        }
        let msgs: Vec<String> = arr
            .iter()
            .map(|e| e.get("message").and_then(|m| m.as_str()).unwrap_or("?").to_string())
            .collect();
        if msgs.is_empty() {
            return None;
        }
        return Some(msgs.join("; "));
    }
    None
}

/// Poll OpenCTI: pages until end or cap; import STIX cyber observables into IOC table.
pub async fn poll_opencti_full(
    app: &AppHandle,
    http: &HttpApiState,
    f: &FeedRow,
    feed_id: &str,
    base: &str,
    key: &str,
) -> Result<(Value, Option<String>), String> {
    let source = f.name.trim();
    if source.is_empty() {
        return Err("OpenCTI feed has empty name (used as IOC source)".into());
    }
    let url = format!("{}/graphql", base.trim_end_matches('/'));
    let mut h = std::collections::HashMap::new();
    h.insert("Authorization".to_string(), format!("Bearer {key}"));
    h.insert("Content-Type".to_string(), "application/json".to_string());

    let mut after: Option<String> = f
        .cursor_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| {
            v.get("opencti")
                .and_then(|o| o.get("endCursor").and_then(|c| c.as_str()).map(|s| s.to_string()))
        });

    let mut all_edges: Vec<Value> = vec![];
    let mut last_page_info: Option<Value> = None;
    let mut pages = 0usize;
    let mut has_next = true;
    let mut end_cursor: Option<String> = None;
    let mut any_edges = false;

    while has_next && pages < MAX_PAGES_PER_POLL {
        let body = graphql_body(PAGE_SIZE, after.as_deref());
        let r = http
            .run_request(
                app,
                url.clone(),
                "POST".into(),
                Some(h.clone()),
                Some(body),
                "opencti".into(),
            )
            .await
            .map_err(|e| e.to_string())?;
        let st = r
            .get("status")
            .and_then(|s| s.as_u64().or_else(|| s.as_i64().map(|i| i as u64)))
            .ok_or("OpenCTI: missing HTTP status")?;
        if st < 200 || st > 299 {
            return Err(format!("OpenCTI: HTTP {st}"));
        }
        let b = r.get("body").cloned().unwrap_or(Value::Null);
        if !b.is_object() {
            return Err("OpenCTI: empty or invalid GraphQL body".into());
        }
        if let Some(geo) = get_errors(&b) {
            return Err(format!("OpenCTI GraphQL: {geo}"));
        }
        let data = b
            .get("data")
            .ok_or("OpenCTI: missing data in response")?;
        let sc = data
            .get("stixCyberObservables")
            .ok_or("OpenCTI: stixCyberObservables not available — check OpenCTI version and API path")?;
        let edges = sc
            .get("edges")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();
        if !edges.is_empty() {
            any_edges = true;
            for e in edges {
                all_edges.push(e);
            }
        }
        if let Some(pi) = sc.get("pageInfo") {
            has_next = pi
                .get("hasNextPage")
                .and_then(|h| h.as_bool())
                .unwrap_or(false);
            end_cursor = pi
                .get("endCursor")
                .and_then(|c| c.as_str())
                .map(|s| s.to_string());
            after = end_cursor.clone();
            last_page_info = Some(pi.clone());
        } else {
            has_next = false;
        }
        pages = pages.saturating_add(1);
        if !has_next {
            break;
        }
    }

    let (total_ins, total_upd, total_skip) = if all_edges.is_empty() {
        (0u32, 0u32, 0u32)
    } else {
        let imp = import_from_opencti_stix_cyber_observables(app, &all_edges, source)?;
        (imp.inserted, imp.updated, imp.skipped)
    };

    let cursor_to_store = if has_next {
        if let Some(ref c) = end_cursor {
            json!({ "opencti": { "endCursor": c, "incomplete": true } }).to_string()
        } else {
            f.cursor_json
                .clone()
                .unwrap_or_else(|| json!({ "opencti": {} }).to_string())
        }
    } else {
        json!({ "opencti": { "lastCompletedAt": Utc::now().timestamp() } }).to_string()
    };

    let out = json!({
        "feedId": feed_id,
        "format": "opencti",
        "import": {
            "inserted": total_ins,
            "updated": total_upd,
            "skipped": total_skip,
            "source": source,
        },
        "opencti": {
            "pagesFetched": pages,
            "reachedEnd": !has_next,
            "hadAnyEdges": any_edges,
            "pageInfo": last_page_info
        }
    });
    Ok((out, Some(cursor_to_store)))
}

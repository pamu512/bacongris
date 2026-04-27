//! Build `ioc_relationships` from enrichment API responses (VirusTotal, Shodan, OTX, abuse.ch).
use rusqlite::params;
use serde_json::Value;
use std::collections::HashSet;
use tauri::AppHandle;
use tauri::Manager;
use uuid::Uuid;

use crate::app_data::AppStore;
use crate::ioc::ensure_ioc_id;
use chrono::Utc;

const MAX_EDGES_PER_ENRICH: u32 = 100;
const MAX_PAIR_CANDIDATES: usize = 200;

fn now() -> i64 {
    Utc::now().timestamp()
}

fn rel_exists(
    g: &rusqlite::Connection,
    a: &str,
    b: &str,
    rt: &str,
) -> Result<bool, String> {
    let n: i64 = g
        .query_row(
            "SELECT COUNT(*) FROM ioc_relationships WHERE source_ioc = ?1 AND target_ioc = ?2 AND relationship_type = ?3",
            params![a, b, rt],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(n > 0)
}

fn insert_rel(
    g: &rusqlite::Connection,
    source_id: &str,
    target_id: &str,
    rel: &str,
    source_data: &str,
) -> Result<(), String> {
    if rel_exists(g, source_id, target_id, rel)? {
        return Ok(());
    }
    let id = Uuid::new_v4().to_string();
    g.execute(
        "INSERT INTO ioc_relationships (id, source_ioc, target_ioc, relationship_type, source_data, confidence, first_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![&id, source_id, target_id, rel, source_data, 60i32, now()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Parse VT domain/IP report: each resolution row links **domain (host_name) → IP**.
pub fn apply_virustotal_graph_edges(
    app: &AppHandle,
    _ioc: &str,
    ioc_type: &str,
    _seed_id: &str,
    report: &Value,
    profile_id: Option<String>,
) -> Result<u32, String> {
    let t = ioc_type.to_lowercase();
    if !matches!(
        t.as_str(),
        "domain" | "hostname" | "ipv4" | "ip" | "ip-dst" | "ip-src" | "ipv6"
    ) {
        return Ok(0);
    }
    let attrs = report
        .get("data")
        .and_then(|d| d.get("attributes"))
        .or_else(|| report.get("attributes"));
    let Some(a) = attrs else {
        return Ok(0);
    };
    let res = a.get("resolutions").and_then(|x| x.as_array());
    let Some(res) = res else {
        return Ok(0);
    };
    let mut pairs: Vec<(String, String, &'static str)> = vec![]; // host, ip, ip ioc type
    for item in res {
        let ip = item
            .get("ip_address")
            .and_then(|v| v.as_str())
            .or_else(|| {
                item
                    .get("attributes")
                    .and_then(|a| a.get("ip_address"))
                    .and_then(|v| v.as_str())
            });
        let host = item
            .get("host_name")
            .and_then(|v| v.as_str())
            .or_else(|| {
                item
                    .get("attributes")
                    .and_then(|a| a.get("host_name"))
                    .and_then(|v| v.as_str())
            });
        let (Some(ip_s), Some(host_s)) = (ip, host) else {
            continue;
        };
        let ip_s = ip_s.trim();
        let host_s = host_s.trim();
        if ip_s.is_empty() || host_s.is_empty() {
            continue;
        }
        let it = if ip_s.contains(':') { "ipv6" } else { "ipv4" };
        if pairs.len() < MAX_PAIR_CANDIDATES {
            pairs.push((host_s.to_string(), ip_s.to_string(), it));
        }
    }
    let mut n = 0u32;
    for (host, ip, itype) in pairs {
        if n >= MAX_EDGES_PER_ENRICH {
            break;
        }
        let id_dom = ensure_ioc_id(app, &host, "domain", profile_id.clone())?;
        let id_ip = ensure_ioc_id(app, &ip, itype, profile_id.clone())?;
        let st = app.state::<AppStore>();
        let g = st.db.lock().map_err(|e| e.to_string())?;
        insert_rel(&g, &id_dom, &id_ip, "resolves_to", "enrichment:virustotal:resolutions")?;
        n = n.saturating_add(1);
    }
    Ok(n)
}

fn push_pair(
    host: &str,
    ip: &str,
    out: &mut Vec<(String, String, &'static str)>,
) {
    let host_s = host.trim();
    let ip_s = ip.trim();
    if host_s.is_empty() || ip_s.is_empty() {
        return;
    }
    if out.len() >= MAX_PAIR_CANDIDATES {
        return;
    }
    let it = if ip_s.contains(':') { "ipv6" } else { "ipv4" };
    out.push((host_s.to_string(), ip_s.to_string(), it));
}

/// OTX `passive_dns`: array of `{ hostname, address }` or wrapper with `records`, or single object.
fn collect_otx_passive_dns_pairs(body: &Value) -> Vec<(String, String, &'static str)> {
    let mut out = vec![];
    let mut visit = |node: &Value| {
        let recs: Option<&Vec<Value>> = node
            .as_array()
            .or_else(|| node.get("records").and_then(|r| r.as_array()));
        let Some(recs) = recs else {
            return;
        };
        for r in recs {
            let host = r
                .get("hostname")
                .and_then(|v| v.as_str())
                .or_else(|| r.get("record_name").and_then(|v| v.as_str()));
            let ip = r
                .get("address")
                .and_then(|v| v.as_str())
                .or_else(|| r.get("ip").and_then(|v| v.as_str()));
            if let (Some(h), Some(i)) = (host, ip) {
                let rt = r
                    .get("record_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("A");
                if matches!(rt.to_uppercase().as_str(), "A" | "AAAA") {
                    push_pair(h, i, &mut out);
                }
            }
        }
    };
    if let Some(p) = body.get("passive_dns") {
        if p.is_array() {
            visit(p);
        } else if p.is_object() {
            if let Some(a) = p.as_object().and_then(|m| m.get("records")) {
                if a.is_array() {
                    visit(a);
                }
            } else if p
                .get("hostname")
                .or_else(|| p.get("record_name"))
                .is_some()
                && p.get("address").or_else(|| p.get("ip")).is_some()
            {
                // Single object { hostname, address } without a records array
                let rec = p;
                let host = rec
                    .get("hostname")
                    .and_then(|v| v.as_str())
                    .or_else(|| rec.get("record_name").and_then(|v| v.as_str()));
                let ip = rec
                    .get("address")
                    .and_then(|v| v.as_str())
                    .or_else(|| rec.get("ip").and_then(|v| v.as_str()));
                if let (Some(h), Some(i)) = (host, ip) {
                    let rt = rec
                        .get("record_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("A");
                    if matches!(rt.to_uppercase().as_str(), "A" | "AAAA") {
                        push_pair(h, i, &mut out);
                    }
                }
            }
        }
    }
    out
}

enum ShodanEdge {
    Resolves {
        host: String,
        ip: String,
        ip_type: &'static str,
    },
    Subdomain {
        fqdn: String,
        apex: String,
    },
}

fn collect_shodan_edges(ioc: &str, ioc_type: &str, body: &Value) -> Vec<ShodanEdge> {
    let t = ioc_type.to_lowercase();
    let mut out = vec![];
    if matches!(t.as_str(), "ipv4" | "ipv6" | "ip" | "ip-dst" | "ip-src") {
        let ip = body
            .get("ip_str")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| ioc.trim());
        let mut seen: HashSet<String> = HashSet::new();
        if let Some(arr) = body.get("hostnames").and_then(|a| a.as_array()) {
            for h in arr {
                if let Some(s) = h.as_str() {
                    let s = s.trim();
                    if !s.is_empty() {
                        seen.insert(s.to_string());
                    }
                }
            }
        }
        if let Some(data) = body.get("data").and_then(|d| d.as_array()) {
            for row in data {
                for key in &["hostnames", "domains"] {
                    if let Some(arr) = row.get(*key).and_then(|a| a.as_array()) {
                        for h in arr {
                            if let Some(s) = h.as_str() {
                                let s = s.trim();
                                if !s.is_empty() {
                                    seen.insert(s.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        for host in seen {
            if out.len() >= MAX_PAIR_CANDIDATES {
                break;
            }
            let ip_s = ip.trim();
            if ip_s.is_empty() {
                continue;
            }
            let it = if ip_s.contains(':') { "ipv6" } else { "ipv4" };
            out.push(ShodanEdge::Resolves {
                host,
                ip: ip_s.to_string(),
                ip_type: it,
            });
        }
    } else if matches!(t.as_str(), "domain" | "hostname") {
        let base = ioc.trim().to_lowercase();
        if let Some(subs) = body.get("subdomains").and_then(|a| a.as_array()) {
            for s in subs {
                let sub = s.as_str().map(str::trim).unwrap_or("");
                if sub.is_empty() {
                    continue;
                }
                if out.len() >= MAX_PAIR_CANDIDATES {
                    break;
                }
                let fqdn = if sub.contains('.') {
                    sub.to_string()
                } else {
                    format!("{sub}.{base}")
                };
                if !fqdn.eq_ignore_ascii_case(&base) {
                    out.push(ShodanEdge::Subdomain {
                        fqdn,
                        apex: base.clone(),
                    });
                }
            }
        }
    }
    out
}

/// OTX passive DNS → `resolves_to` (hostname → IP), up to [MAX_EDGES_PER_ENRICH] edges.
pub fn apply_otx_graph_edges(
    app: &AppHandle,
    _ioc: &str,
    ioc_type: &str,
    _seed_id: &str,
    report: &Value,
    profile_id: Option<String>,
) -> Result<u32, String> {
    let t = ioc_type.to_lowercase();
    if !matches!(
        t.as_str(),
        "domain" | "hostname" | "ipv4" | "ip" | "ip-dst" | "ip-src" | "ipv6"
    ) {
        return Ok(0);
    }
    let pairs = collect_otx_passive_dns_pairs(report);
    let mut n = 0u32;
    for (host, ip, itype) in pairs {
        if n >= MAX_EDGES_PER_ENRICH {
            break;
        }
        let id_dom = ensure_ioc_id(app, &host, "domain", profile_id.clone())?;
        let id_ip = ensure_ioc_id(app, &ip, itype, profile_id.clone())?;
        let st = app.state::<AppStore>();
        let g = st.db.lock().map_err(|e| e.to_string())?;
        insert_rel(
            &g,
            &id_dom,
            &id_ip,
            "resolves_to",
            "enrichment:otx:passive_dns",
        )?;
        n = n.saturating_add(1);
    }
    Ok(n)
}

/// Shodan host / dns.domain → `resolves_to` or `subdomain_of` edges.
pub fn apply_shodan_graph_edges(
    app: &AppHandle,
    ioc: &str,
    ioc_type: &str,
    _seed_id: &str,
    report: &Value,
    profile_id: Option<String>,
) -> Result<u32, String> {
    let mut n = 0u32;
    for edge in collect_shodan_edges(ioc, ioc_type, report) {
        if n >= MAX_EDGES_PER_ENRICH {
            break;
        }
        match edge {
            ShodanEdge::Subdomain { fqdn, apex } => {
                let id_sub = ensure_ioc_id(app, &fqdn, "domain", profile_id.clone())?;
                let id_apex = ensure_ioc_id(app, &apex, "domain", profile_id.clone())?;
                let st = app.state::<AppStore>();
                let g = st.db.lock().map_err(|e| e.to_string())?;
                insert_rel(
                    &g,
                    &id_sub,
                    &id_apex,
                    "subdomain_of",
                    "enrichment:shodan:dns_domain",
                )?;
                n = n.saturating_add(1);
            }
            ShodanEdge::Resolves { host, ip, ip_type } => {
                let id_dom = ensure_ioc_id(app, &host, "domain", profile_id.clone())?;
                let id_ip = ensure_ioc_id(app, &ip, ip_type, profile_id.clone())?;
                let st = app.state::<AppStore>();
                let g = st.db.lock().map_err(|e| e.to_string())?;
                insert_rel(
                    &g,
                    &id_dom,
                    &id_ip,
                    "resolves_to",
                    "enrichment:shodan:hostnames",
                )?;
                n = n.saturating_add(1);
            }
        }
    }
    Ok(n)
}

const MAX_INFRA_EDGES: u32 = 20;

/// VT IP: **ASN** + optional **network**; domain: **HTTPS cert** sha256.
pub fn apply_virustotal_infrastructure_edges(
    app: &AppHandle,
    _ioc: &str,
    ioc_type: &str,
    seed_id: &str,
    report: &Value,
    profile_id: Option<String>,
) -> Result<u32, String> {
    let t = ioc_type.to_lowercase();
    let attrs = report
        .get("data")
        .and_then(|d| d.get("attributes"))
        .or_else(|| report.get("attributes"));
    let Some(a) = attrs else {
        return Ok(0);
    };
    let mut n = 0u32;

    if matches!(
        t.as_str(),
        "ipv4" | "ipv6" | "ip" | "ip-dst" | "ip-src"
    ) {
        if n < MAX_INFRA_EDGES {
            if let Some(asn) = a
                .get("asn")
                .and_then(|v| v.as_u64())
                .or_else(|| a.get("asn").and_then(|v| v.as_i64()).map(|x| x as u64))
            {
                let as_val = format!("AS{asn}");
                let id_as = ensure_ioc_id(app, &as_val, "asn", profile_id.clone())?;
                let st = app.state::<AppStore>();
                let g = st.db.lock().map_err(|e| e.to_string())?;
                insert_rel(
                    &g,
                    seed_id,
                    &id_as,
                    "announced_in",
                    "enrichment:virustotal:asn",
                )?;
                n += 1;
            }
        }
        if n < MAX_INFRA_EDGES {
            if let Some(net) = a
                .get("network")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| {
                    !s.is_empty()
                        && *s != "0.0.0.0/0"
                        && *s != "::/0"
                        && s.contains('/')
                })
            {
                let id_net = ensure_ioc_id(app, net, "cidr", profile_id.clone())?;
                let st = app.state::<AppStore>();
                let g = st.db.lock().map_err(|e| e.to_string())?;
                insert_rel(
                    &g,
                    seed_id,
                    &id_net,
                    "routed_within",
                    "enrichment:virustotal:network",
                )?;
                n += 1;
            }
        }
    }

    if matches!(t.as_str(), "domain" | "hostname") {
        if n < MAX_INFRA_EDGES {
            if let Some(cert) = a.get("last_https_certificate") {
                if let Some(h) = cert
                    .get("sha256")
                    .or_else(|| cert.get("thumbprint_sha256"))
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    let hlow = h.to_lowercase();
                    let id_cert = ensure_ioc_id(app, &hlow, "sha256", profile_id.clone())?;
                    let st = app.state::<AppStore>();
                    let g = st.db.lock().map_err(|e| e.to_string())?;
                    insert_rel(
                        &g,
                        seed_id,
                        &id_cert,
                        "presents_cert",
                        "enrichment:virustotal:https_cert",
                    )?;
                    n += 1;
                }
            }
        }
    }

    Ok(n)
}

/// Shodan **asn** on host lookup.
pub fn apply_shodan_infrastructure_edges(
    app: &AppHandle,
    ioc_type: &str,
    seed_id: &str,
    body: &Value,
    profile_id: Option<String>,
) -> Result<u32, String> {
    let t = ioc_type.to_lowercase();
    if !matches!(t.as_str(), "ipv4" | "ipv6" | "ip" | "ip-dst" | "ip-src") {
        return Ok(0);
    }
    let asn = body
        .get("asn")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            body.get("asn")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
        });
    let Some(asn) = asn else {
        return Ok(0);
    };
    let as_val = format!("AS{asn}");
    let id_as = ensure_ioc_id(app, &as_val, "asn", profile_id.clone())?;
    let st = app.state::<AppStore>();
    let g = st.db.lock().map_err(|e| e.to_string())?;
    insert_rel(
        &g,
        seed_id,
        &id_as,
        "announced_in",
        "enrichment:shodan:asn",
    )?;
    Ok(1)
}

fn insert_rel_same(
    g: &rusqlite::Connection,
    a: &str,
    b: &str,
    source_data: &str,
) -> Result<(), String> {
    if rel_exists(g, a, b, "same_as")? || rel_exists(g, b, a, "same_as")? {
        return Ok(());
    }
    let id = Uuid::new_v4().to_string();
    g.execute(
        "INSERT INTO ioc_relationships (id, source_ioc, target_ioc, relationship_type, source_data, confidence, first_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![&id, a, b, "same_as", source_data, 90i32, now()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// MalwareBazaar alternate hashes (`same_as`); URLhaus URL → `sha256` / `md5` (`delivered_payload`).
pub fn apply_abusech_graph_edges(
    app: &AppHandle,
    ioc: &str,
    ioc_type: &str,
    _seed_id: &str,
    report: &Value,
    profile_id: Option<String>,
) -> Result<u32, String> {
    let t = ioc_type.to_lowercase();
    let mut n = 0u32;
    if t == "url" {
        let mut found: Vec<(&'static str, String)> = Vec::new();
        for (k, typ) in [("md5", "md5"), ("sha256", "sha256"), ("sha1", "sha1")] {
            if let Some(s) = report
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                found.push((typ, s.to_string()));
            }
        }
        if found.is_empty() {
            if let Some(arr) = report
                .get("urls")
                .or_else(|| report.get("urlhaus"))
                .and_then(|a| a.as_array())
            {
                for u in arr {
                    for (key, typ) in [("md5", "md5"), ("sha256", "sha256"), ("sha1", "sha1")] {
                        if n >= MAX_EDGES_PER_ENRICH {
                            return Ok(n);
                        }
                        if let Some(h) = u.get(key).and_then(|v| v.as_str()) {
                            let h = h.trim();
                            if h.is_empty() {
                                continue;
                            }
                            let id_url = ensure_ioc_id(app, ioc, "url", profile_id.clone())?;
                            let id_h = ensure_ioc_id(app, h, typ, profile_id.clone())?;
                            let st = app.state::<AppStore>();
                            let g = st.db.lock().map_err(|e| e.to_string())?;
                            insert_rel(
                                &g,
                                &id_url,
                                &id_h,
                                "delivered_payload",
                                "enrichment:abusech:urlhaus",
                            )?;
                            n = n.saturating_add(1);
                        }
                    }
                }
            }
            return Ok(n);
        }
        for (typ, h) in found {
            if n >= MAX_EDGES_PER_ENRICH {
                break;
            }
            let id_url = ensure_ioc_id(app, ioc, "url", profile_id.clone())?;
            let id_h = ensure_ioc_id(app, &h, typ, profile_id.clone())?;
            let st = app.state::<AppStore>();
            let g = st.db.lock().map_err(|e| e.to_string())?;
            insert_rel(
                &g,
                &id_url,
                &id_h,
                "delivered_payload",
                "enrichment:abusech:urlhaus",
            )?;
            n = n.saturating_add(1);
        }
        return Ok(n);
    }
    if matches!(t.as_str(), "md5" | "sha1" | "sha256") {
        let data = report.get("data").and_then(|d| d.as_array());
        let Some(data) = data else {
            return Ok(0);
        };
        let Some(f) = data.first() else {
            return Ok(0);
        };
        let mut values: Vec<(&'static str, String)> = vec![];
        if let Some(s) = f
            .get("md5_hash")
            .or_else(|| f.get("md5"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            values.push(("md5", s.to_string()));
        }
        if let Some(s) = f
            .get("sha1_hash")
            .or_else(|| f.get("sha1"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            values.push(("sha1", s.to_string()));
        }
        if let Some(s) = f
            .get("sha256_hash")
            .or_else(|| f.get("sha256"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            values.push(("sha256", s.to_string()));
        }
        for i in 0..values.len() {
            for j in (i + 1)..values.len() {
                if n >= MAX_EDGES_PER_ENRICH {
                    return Ok(n);
                }
                let (ta, va) = &values[i];
                let (tb, vb) = &values[j];
                let id_a = ensure_ioc_id(app, va, ta, profile_id.clone())?;
                let id_b = ensure_ioc_id(app, vb, tb, profile_id.clone())?;
                let st = app.state::<AppStore>();
                let g = st.db.lock().map_err(|e| e.to_string())?;
                insert_rel_same(
                    &g,
                    &id_a,
                    &id_b,
                    "enrichment:abusech:malwarebazaar",
                )?;
                n = n.saturating_add(1);
            }
        }
        if n < MAX_EDGES_PER_ENRICH {
            if let Some(fname) = f
                .get("file_name")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty() && s.len() <= 2048)
            {
                let id_h = ensure_ioc_id(app, ioc, t.as_str(), profile_id.clone())?;
                let id_fn = ensure_ioc_id(app, fname, "filename", profile_id.clone())?;
                let st = app.state::<AppStore>();
                let g = st.db.lock().map_err(|e| e.to_string())?;
                insert_rel(
                    &g,
                    &id_h,
                    &id_fn,
                    "submitted_as",
                    "enrichment:abusech:malwarebazaar:filename",
                )?;
                n = n.saturating_add(1);
            }
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::collect_otx_passive_dns_pairs;
    use super::collect_shodan_edges;
    use super::ShodanEdge;
    use serde_json::json;

    #[test]
    fn otx_passive_dns_array() {
        let body = json!({
            "passive_dns": [
                { "hostname": "a.example.com", "address": "1.2.3.4", "record_type": "A" }
            ]
        });
        let p = collect_otx_passive_dns_pairs(&body);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "a.example.com");
        assert_eq!(p[0].1, "1.2.3.4");
    }

    #[test]
    fn otx_passive_dns_records_wrapper() {
        let body = json!({
            "passive_dns": { "records": [
                { "hostname": "b.test", "address": "::1", "record_type": "AAAA" }
            ]}
        });
        let p = collect_otx_passive_dns_pairs(&body);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].2, "ipv6");
    }

    #[test]
    fn shodan_host_resolves() {
        let body = json!({
            "ip_str": "8.8.8.8",
            "hostnames": ["dns.google"]
        });
        let e = collect_shodan_edges("8.8.8.8", "ipv4", &body);
        assert_eq!(e.len(), 1);
        match &e[0] {
            ShodanEdge::Resolves { host, ip, ip_type } => {
                assert_eq!(host, "dns.google");
                assert_eq!(ip, "8.8.8.8");
                assert_eq!(*ip_type, "ipv4");
            }
            _ => panic!("expected Resolves"),
        }
    }

    #[test]
    fn shodan_dns_subdomain() {
        let body = json!({
            "subdomains": ["mail", "www"]
        });
        let e = collect_shodan_edges("example.com", "domain", &body);
        assert_eq!(e.len(), 2);
    }
}

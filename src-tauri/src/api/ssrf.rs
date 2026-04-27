//! Block common SSRF targets in explicit URLs (literal hosts only; DNS is not resolved).
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use url::Url;

const METADATA_AWS: &str = "169.254.169.254";
const METADATA_AWS_2: &str = "fd00:ec2::254";

/// Returns `Ok(())` only for URLs the agent may `GET`/`POST` to the public internet.
/// Local/private/link-local/ULA IPs, localhost, and obvious metadata hosts are rejected.
pub fn assert_public_http_url(url_in: &str) -> Result<(), String> {
    let u = Url::parse(url_in).map_err(|e| format!("Invalid URL: {e}"))?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err("Only http: and https: are allowed for api_request.".into());
    }
    let host = u.host_str().ok_or("URL has no host (e.g. missing authority).")?;
    if host.is_empty() {
        return Err("URL host is empty.".into());
    }
    if host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host == "0.0.0.0"
    {
        return Err("Host blocked (local/management): use a public service hostname or IP."
            .into());
    }
    if host
        .to_ascii_lowercase()
        .as_str()
        .ends_with(".local")
    {
        return Err("Host blocked: .local names are not allowed.".into());
    }
    if host.eq_ignore_ascii_case("metadata.google.internal")
        || host.eq_ignore_ascii_case(METADATA_AWS)
        || host.eq_ignore_ascii_case(METADATA_AWS_2)
    {
        return Err("Host blocked (known metadata / internal).".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_forbidden_ip(ip) {
            return Err("IP blocked: not a routable public address (private, loopback, link-local, or reserved).".into());
        }
        return Ok(());
    }
    if host
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.')
        && host
            .parse::<Ipv4Addr>()
            .map(|a| is_forbidden_ip(IpAddr::V4(a)))
            .unwrap_or(false)
    {
        return Err("IP blocked (dotted string).".into());
    }
    Ok(())
}

fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => ipv4_forbidden(&a),
        IpAddr::V6(a) => ipv6_forbidden(&a),
    }
}

fn ipv4_forbidden(a: &Ipv4Addr) -> bool {
    if a.is_loopback() || a.is_private() || a.is_link_local() {
        return true;
    }
    if a.is_broadcast() || a.is_unspecified() || a.is_documentation() {
        return true;
    }
    // CGNAT / "shared" space 100.64.0.0/10
    let o = a.octets();
    if o[0] == 100 && o[1] >= 64 && o[1] <= 127 {
        return true;
    }
    o[0] == 0
}

/// Stable subset of "not a routable public IPv6 unicast" (avoids `is_unicast_global` which is unstable on some toolchains).
fn ipv6_forbidden(a: &Ipv6Addr) -> bool {
    if a.is_multicast() || a.is_loopback() || a.is_unicast_link_local() || a.is_unspecified() {
        return true;
    }
    let s = a.segments();
    if (s[0] & 0xfe00) == 0xfc00 {
        return true; // ULA
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return true; // documentation
    }
    if let Some(v4) = a.to_ipv4() {
        return ipv4_forbidden(&v4);
    }
    (s[0] & 0xe000) != 0x2000
}

#[cfg(test)]
mod tests {
    use super::assert_public_http_url;

    #[test]
    fn allows_public_v4() {
        assert!(assert_public_http_url("https://1.1.1.1/path").is_ok());
    }

    #[test]
    fn blocks_loopback() {
        assert!(assert_public_http_url("https://127.0.0.1/x").is_err());
    }
}

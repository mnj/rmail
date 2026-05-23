use anyhow::Result;
use std::net::IpAddr;
use sha2::{Sha256, Digest};
use base64;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use ipnet::IpNet;

/// Analyze an email message and produce simple DKIM/SPF/DMARC status strings.
///
/// This is an initial, pragmatic implementation:
/// - DKIM: verifies only the body hash (bh=) for available DKIM-Signature headers using
///   a simple canonicalization. If the bh matches the body SHA256 -> "pass" else "fail".
/// - SPF: performs a TXT lookup for "v=spf1" records on the envelope-from domain and
///   checks ip4/ip6 mechanisms only (basic support). Returns pass/softfail/fail/neutral/none.
/// - DMARC: performs a TXT lookup for _dmarc.<from-domain> and applies simple alignment rules:
///   DKIM relaxed (d==From) or SPF aligned (envelope-from domain == From domain). Returns pass/fail/none.

pub fn analyze_message(data: &[u8], peer_ip: Option<IpAddr>, mail_from: Option<&str>) -> Result<(Option<String>, Option<String>, Option<String>)> {
    let (headers, body) = parse_headers_body(data);
    let dkim = verify_dkim(&headers, body)?;
    let spf = verify_spf(peer_ip, mail_from)?;
    let dmarc = verify_dmarc(&headers, dkim.as_deref(), spf.as_deref(), mail_from)?;
    Ok((dkim, spf, dmarc))
}

fn parse_headers_body<'a>(data: &'a [u8]) -> (Vec<(String, String)>, &'a [u8]) {
    // find header/body separator (prefer CRLFCRLF)
    let mut split_at: Option<usize> = None;
    if let Some(pos) = twoway::find_bytes(data, b"\r\n\r\n") {
        split_at = Some(pos + 4);
    } else if let Some(pos) = twoway::find_bytes(data, b"\n\n") {
        split_at = Some(pos + 2);
    }
    let (hdr_bytes, body) = if let Some(idx) = split_at { (&data[..idx], &data[idx..]) } else { (data, &data[data.len()..]) };

    // convert headers region to string for simple parsing; invalid UTF-8 is tolerated via lossy conversion
    let hdr_str = String::from_utf8_lossy(hdr_bytes);
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in hdr_str.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // continuation line: append to last header value
            if let Some((_k, v)) = headers.last_mut() {
                v.push(' ');
                v.push_str(line.trim());
            }
        } else {
            if let Some(colon) = line.find(':') {
                let name = line[..colon].trim().to_string();
                let val = line[colon+1..].trim().to_string();
                headers.push((name, val));
            }
        }
    }
    (headers, body)
}

fn get_header_value<'a>(headers: &'a [(String,String)], name: &str) -> Option<String> {
    for (k, v) in headers.iter() {
        if k.eq_ignore_ascii_case(name) {
            return Some(v.clone());
        }
    }
    None
}

fn verify_dkim(headers: &[(String,String)], body: &[u8]) -> Result<Option<String>> {
    // Find all DKIM-Signature headers (if any) and try to validate the body hash (bh=)
    let mut found = false;
    for (k, v) in headers.iter() {
        if k.eq_ignore_ascii_case("DKIM-Signature") {
            found = true;
            // parse semicolon-separated tag=value pairs
            let mut bh: Option<String> = None;
            let mut d: Option<String> = None;
            for part in v.split(';') {
                let p = part.trim();
                if p.starts_with("bh=") {
                    bh = Some(p[3..].trim().to_string());
                } else if p.starts_with("d=") {
                    d = Some(p[2..].trim().to_string());
                }
            }
            if let Some(bh_val) = bh {
                // compute SHA256 of body (simple canonicalization approximation)
                let mut hasher = Sha256::new();
                hasher.update(body);
                let digest = hasher.finalize();
                let computed = base64::engine::general_purpose::STANDARD.encode(digest);
                if computed.trim_end_matches('\n') == bh_val.trim() {
                    let dpart = d.unwrap_or_else(|| "".to_string());
                    return Ok(Some(format!("pass; d={}", dpart)));
                } else {
                    return Ok(Some(format!("fail; bh_mismatch (computed={} expected={})", computed, bh_val)));
                }
            } else {
                // DKIM header present but no bh field — treat as failure
                return Ok(Some("fail; missing_bh".to_string()));
            }
        }
    }
    if !found {
        Ok(None)
    } else {
        Ok(None)
    }
}

fn resolver() -> Result<Resolver> {
    // Use system-configured resolvers
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    Ok(resolver)
}

fn verify_spf(peer_ip: Option<IpAddr>, mail_from: Option<&str>) -> Result<Option<String>> {
    // Minimal SPF: lookup TXT records for the envelope-from domain and evaluate ip4/ip6 mechanisms only.
    let mf = match mail_from { Some(s) => s, None => return Ok(None) };
    let at = mf.rfind('@');
    let domain = if let Some(i) = at { &mf[i+1..] } else { mf };
    let resolver = match resolver() { Ok(r) => r, Err(_) => return Ok(None) };
    let lookup = match resolver.txt_lookup(domain) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };

    // iterate TXT records and find an spf record
    use trust_dns_resolver::proto::rr::rdata::TXT;
    for txt in lookup.iter() {
        // try to obtain a string from TXT record
        let txt_str = txt.to_string();
        if txt_str.to_ascii_lowercase().starts_with("v=spf1") {
            // split tokens
            let tokens = txt_str.split_whitespace().skip(1);
            let mut matched = false;
            let mut seen_all: Option<&str> = None;
            for tok in tokens {
                if tok.starts_with("ip4:") || tok.starts_with("ip6:") {
                    let net = &tok[4..];
                    if let Ok(ipnet) = net.parse::<IpNet>() {
                        if let Some(peer) = peer_ip {
                            if ipnet.contains(&peer) {
                                matched = true;
                                return Ok(Some("pass".to_string()));
                            }
                        }
                    }
                } else if tok.ends_with("all") {
                    // could be -all, ~all, ?all
                    seen_all = Some(tok);
                }
            }
            if matched { return Ok(Some("pass".to_string())); }
            if let Some(a) = seen_all {
                if a.starts_with("-") { return Ok(Some("fail".to_string())); }
                if a.starts_with("~") { return Ok(Some("softfail".to_string())); }
                return Ok(Some("neutral".to_string()));
            }
            return Ok(Some("neutral".to_string()));
        }
    }
    Ok(None)
}

fn verify_dmarc(headers: &[(String,String)], dkim: Option<&str>, spf: Option<&str>, mail_from: Option<&str>) -> Result<Option<String>> {
    // Parse From header to obtain the header-from domain
    let from_hdr = match get_header_value(headers, "From") { Some(s) => s, None => return Ok(None) };
    let from_addr = extract_addr_from_header(&from_hdr);
    let from_domain = match from_addr.as_deref().and_then(|s| s.rfind('@').map(|i| s[i+1..].to_string())) {
        Some(d) => d,
        None => return Ok(None),
    };

    // lookup _dmarc.<from_domain>
    let name = format!("_dmarc.{}", from_domain);
    let resolver = match resolver() { Ok(r) => r, Err(_) => return Ok(None) };
    let lookup = match resolver.txt_lookup(name.as_str()) { Ok(r) => r, Err(_) => return Ok(None) };
    let mut policy: Option<String> = None;
    for txt in lookup.iter() {
        let txt_str = txt.to_string();
        if txt_str.to_ascii_lowercase().contains("p=") {
            // find p= value
            for part in txt_str.split(';') {
                let p = part.trim();
                if p.starts_with('p') && p.contains('=') {
                    if let Some(eq) = p.find('=') {
                        policy = Some(p[eq+1..].trim().to_string());
                    }
                }
            }
        }
    }
    if policy.is_none() { return Ok(None); }

    // DMARC alignment: prefer DKIM then SPF
    if let Some(dkim_s) = dkim {
        if dkim_s.starts_with("pass") {
            // try to extract d= from any DKIM-Signature header we have
            for (k, v) in headers.iter() {
                if k.eq_ignore_ascii_case("DKIM-Signature") {
                    for part in v.split(';') {
                        let p = part.trim();
                        if p.starts_with("d=") {
                            let d = p[2..].trim();
                            if d == from_domain || d.ends_with(&format!(".{}", from_domain)) {
                                return Ok(Some("pass".to_string()));
                            }
                        }
                    }
                }
            }
        }
    }

    if let Some(spf_s) = spf {
        if spf_s == "pass" {
            // envelope-from domain alignment
            if let Some(mf) = mail_from {
                if let Some(idx) = mf.rfind('@') {
                    let ef_domain = &mf[idx+1..];
                    if ef_domain == from_domain || ef_domain.ends_with(&format!(".{}", from_domain)) {
                        return Ok(Some("pass".to_string()));
                    }
                }
            }
        }
    }

    Ok(Some("fail".to_string()))
}

fn extract_addr_from_header(s: &str) -> Option<String> {
    // crude extraction: look for an @ and take surrounding token with optional <>
    if let Some(at) = s.find('@') {
        // find start
        let before = &s[..at];
        let start = before.rfind('<').map(|i| i+1).unwrap_or_else(|| before.rfind(' ').map(|i| i+1).unwrap_or(0));
        let after = &s[at..];
        let end = after.find('>').map(|i| at + i).unwrap_or_else(|| after.find(' ').map(|i| at + i).unwrap_or(s.len()));
        let addr = s[start..end].trim().trim_matches('<').trim_matches('>').to_string();
        return Some(addr);
    }
    None
}

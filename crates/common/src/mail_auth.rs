use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

/// Analyze an email message and produce simple DKIM/SPF/DMARC status strings.
///
/// This is an initial, pragmatic implementation:
/// - DKIM: verifies only the body hash (bh=) for available DKIM-Signature headers using
///   a simple canonicalization. If the bh matches the body SHA256 -> "pass" else "fail".
/// - SPF: performs a TXT lookup for "v=spf1" records on the envelope-from domain and
///   checks ip4/ip6 mechanisms only (basic support). Returns pass/softfail/fail/neutral/none.
/// - DMARC: performs a TXT lookup for _dmarc.<from-domain> and applies simple alignment rules:
///   DKIM relaxed (d==From) or SPF aligned (envelope-from domain == From domain). Returns pass/fail/none.

pub fn analyze_message(
    data: &[u8],
    peer_ip: Option<IpAddr>,
    mail_from: Option<&str>,
) -> Result<(
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
)> {
    let (headers, header_bytes, body) = parse_headers_body(data);
    let dkim = verify_dkim(&headers, header_bytes, body)?;
    let spf = verify_spf(peer_ip, mail_from)?;
    let dmarc = verify_dmarc(&headers, dkim.as_deref(), spf.as_deref(), mail_from)?;
    // extract header-from address for reporting purposes
    let header_from = get_header_value(&headers, "From").and_then(|s| extract_addr_from_header(&s));
    Ok((dkim, spf, dmarc, header_from))
}

fn parse_headers_body<'a>(data: &'a [u8]) -> (Vec<(String, String)>, &'a [u8], &'a [u8]) {
    // find header/body separator (prefer CRLFCRLF)
    let mut split_at: Option<usize> = None;
    let mut sep_len: usize = 0;
    if let Some(pos) = twoway::find_bytes(data, b"\r\n\r\n") {
        split_at = Some(pos);
        sep_len = 4;
    } else if let Some(pos) = twoway::find_bytes(data, b"\n\n") {
        split_at = Some(pos);
        sep_len = 2;
    }
    let (hdr_bytes, body) = if let Some(idx) = split_at {
        (&data[..idx + sep_len], &data[idx + sep_len..])
    } else {
        (&data[..0], &data[..0])
    };

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
                let val = line[colon + 1..].trim().to_string();
                headers.push((name, val));
            }
        }
    }
    (headers, hdr_bytes, body)
}

fn get_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<String> {
    for (k, v) in headers.iter() {
        if k.eq_ignore_ascii_case(name) {
            return Some(v.clone());
        }
    }
    None
}

fn verify_dkim(
    headers: &[(String, String)],
    header_bytes: &[u8],
    body: &[u8],
) -> Result<Option<String>> {
    // Improved DKIM verification: support simple/relaxed header+body canonicalization
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Verifier;

    let mut found_any = false;
    let mut tried_any = false;

    // build header records grouped by unfolded header (preserve original bytes)
    let mut records: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < header_bytes.len() {
        if let Some(rel) = header_bytes[i..].iter().position(|&b| b == b'\n') {
            let end = i + rel + 1;
            let slice = &header_bytes[i..end];
            if slice.starts_with(b" ") || slice.starts_with(b"\t") {
                cur.extend_from_slice(slice);
            } else {
                if !cur.is_empty() {
                    records.push(cur);
                    cur = Vec::new();
                }
                cur.extend_from_slice(slice);
            }
            i = end;
        } else {
            break;
        }
    }
    if !cur.is_empty() {
        records.push(cur);
    }

    // Helper to find a DKIM-Signature record matching selector+domain (or first DKIM header if not found)
    let find_dkim_rec = |selector: &str, domain: &str| -> Option<Vec<u8>> {
        for rec in records.iter() {
            // check header name
            if let Some(pos) = rec.iter().position(|&b| b == b':') {
                let name = String::from_utf8_lossy(&rec[..pos]).to_string();
                if !name.eq_ignore_ascii_case("DKIM-Signature") {
                    continue;
                }
                // parse tags in the header value to find s= and d=
                let val = String::from_utf8_lossy(&rec[pos + 1..]).to_string();
                let mut has_s = false;
                let mut has_d = false;
                for part in val.split(';') {
                    let p = part.trim();
                    if p.to_ascii_lowercase().starts_with("s=") {
                        if p[2..].trim() == selector {
                            has_s = true;
                        }
                    }
                    if p.to_ascii_lowercase().starts_with("d=") {
                        if p[2..].trim() == domain {
                            has_d = true;
                        }
                    }
                }
                if has_s && has_d {
                    return Some(rec.clone());
                }
            }
        }
        // fallback: return first DKIM-Signature header if specific match not found
        for rec in records.iter() {
            if let Some(pos) = rec.iter().position(|&b| b == b':') {
                let name = String::from_utf8_lossy(&rec[..pos]).to_string();
                if name.eq_ignore_ascii_case("DKIM-Signature") {
                    return Some(rec.clone());
                }
            }
        }
        None
    };

    // iterate over structured headers to find DKIM-Signature occurrences and attempt verification
    for (k, v) in headers.iter() {
        if !k.eq_ignore_ascii_case("DKIM-Signature") {
            continue;
        }
        found_any = true;

        // parse semicolon-separated tag=value pairs into a small map
        let mut bh: Option<String> = None;
        let mut d: Option<String> = None;
        let mut s: Option<String> = None;
        let mut b_sig: Option<String> = None;
        let mut a_alg: Option<String> = None;
        let mut h_list: Option<String> = None;
        let mut canon: Option<String> = None;
        for part in v.split(';') {
            let p = part.trim();
            if p.len() == 0 {
                continue;
            }
            let lower = p.to_ascii_lowercase();
            if lower.starts_with("bh=") {
                bh = Some(p[3..].trim().to_string());
            } else if lower.starts_with("d=") {
                d = Some(p[2..].trim().to_string());
            } else if lower.starts_with("s=") {
                s = Some(p[2..].trim().to_string());
            } else if lower.starts_with("b=") {
                b_sig = Some(p[2..].trim().to_string());
            } else if lower.starts_with("a=") {
                a_alg = Some(p[2..].trim().to_string());
            } else if lower.starts_with("h=") {
                h_list = Some(p[2..].trim().to_string());
            } else if lower.starts_with("c=") {
                canon = Some(p[2..].trim().to_string());
            }
        }

        // determine canonicalization pair
        let (header_canon, body_canon) = if let Some(cstr) = canon.clone() {
            let mut sp = cstr.splitn(2, '/');
            let h = sp.next().unwrap_or("simple").trim().to_ascii_lowercase();
            let b = sp.next().unwrap_or("simple").trim().to_ascii_lowercase();
            (h, b)
        } else {
            ("simple".to_string(), "simple".to_string())
        };

        // If bh present, verify body hash first
        if let Some(bh_val) = bh.clone() {
            let body_to_hash = if body_canon.starts_with("relaxed") {
                canonicalize_body_relaxed(body)
            } else {
                canonicalize_body_simple(body)
            };
            let mut hasher = Sha256::new();
            hasher.update(&body_to_hash);
            let digest = hasher.finalize();
            let computed = BASE64.encode(digest);
            if computed.trim_end_matches('\n') != bh_val.trim() {
                // body hash mismatch for this signature; mark that we tried and continue to next signature
                tried_any = true;
                continue;
            }
        }

        // If signature is present and algorithm is supported, attempt verification
        if let (Some(sig_b64), Some(selector), Some(domain)) = (b_sig.clone(), s.clone(), d.clone())
        {
            if let Some(a) = a_alg.clone() {
                if !a.to_ascii_lowercase().contains("rsa-sha256") {
                    // unsupported algorithm -> treat as tried but skip
                    tried_any = true;
                    continue;
                }
            }

            // Build list of signed header bytes according to h= list
            let mut signed_parts: Vec<Vec<u8>> = Vec::new();
            if let Some(hs) = h_list.clone() {
                let mut used = vec![false; records.len()];
                let fields: Vec<String> = hs.split(':').map(|s| s.trim().to_string()).collect();
                for fname in fields.iter().rev() {
                    for idx in (0..records.len()).rev() {
                        if used[idx] {
                            continue;
                        }
                        if let Some(pos) = records[idx].iter().position(|&b| b == b':') {
                            let name_slice = &records[idx][..pos];
                            let name = String::from_utf8_lossy(name_slice).to_string();
                            if name.eq_ignore_ascii_case(fname) {
                                signed_parts.push(records[idx].clone());
                                used[idx] = true;
                                break;
                            }
                        }
                    }
                }
                signed_parts.reverse();
            }

            // find matching DKIM-Signature record to use (selector+domain), fallback to first DKIM header
            if let Some(rec) = find_dkim_rec(&selector, &domain) {
                let dkim_hdr = remove_b_from_dkim_header(&rec);
                signed_parts.push(dkim_hdr);
            } else {
                // no matching DKIM header found; mark tried and continue
                tried_any = true;
                continue;
            }

            // concatenate canonicalized headers
            let mut header_data: Vec<u8> = Vec::new();
            for part in signed_parts.iter() {
                if header_canon.starts_with("relaxed") {
                    let ch = canonicalize_header_relaxed(part);
                    header_data.extend_from_slice(&ch);
                } else {
                    // simple: use the header as-is (preserve bytes)
                    header_data.extend_from_slice(part);
                }
            }

            // fetch public key via DNS TXT at selector._domainkey.domain
            let resolver = match resolver() {
                Ok(r) => r,
                Err(_) => {
                    tried_any = true;
                    continue;
                }
            };
            let lookup_name = format!("{}._domainkey.{}", selector, domain);
            let txt_lookup = match resolver.txt_lookup(lookup_name.as_str()) {
                Ok(t) => t,
                Err(_) => {
                    tried_any = true;
                    continue;
                }
            };

            let mut pubkey_b64: Option<String> = None;
            for txt in txt_lookup.iter() {
                let txt_str = txt.to_string();
                for part in txt_str.split(';') {
                    let p = part.trim();
                    if p.to_ascii_lowercase().starts_with("p=") {
                        pubkey_b64 = Some(p[2..].trim().to_string());
                    }
                }
            }
            if pubkey_b64.is_none() {
                tried_any = true;
                continue;
            }
            let pubkey_b64 = pubkey_b64.unwrap();
            let pubkey_der = match BASE64.decode(pubkey_b64.as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    tried_any = true;
                    continue;
                }
            };

            // try to build PKey from DER, falling back to PEM wrapper
            let pkey = PKey::public_key_from_der(&pubkey_der).or_else(|_| {
                let pem = format!(
                    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                    base64::engine::general_purpose::STANDARD.encode(&pubkey_der)
                );
                PKey::public_key_from_pem(pem.as_bytes())
            });
            let pkey = match pkey {
                Ok(pk) => pk,
                Err(_) => {
                    tried_any = true;
                    continue;
                }
            };

            let sig_bytes = match BASE64.decode(sig_b64.as_bytes()) {
                Ok(b) => b,
                Err(_) => {
                    tried_any = true;
                    continue;
                }
            };

            // verify signature (rsa-sha256)
            let mut verifier = match Verifier::new(MessageDigest::sha256(), &pkey) {
                Ok(v) => v,
                Err(_) => {
                    tried_any = true;
                    continue;
                }
            };
            if verifier.update(&header_data).is_err() {
                tried_any = true;
                continue;
            }
            match verifier.verify(&sig_bytes) {
                Ok(true) => return Ok(Some(format!("pass; d={}", domain))),
                Ok(false) => {
                    tried_any = true;
                    continue;
                }
                Err(_) => {
                    tried_any = true;
                    continue;
                }
            }
        } else {
            // no b/d/s tags found — mark that we observed a DKIM header but couldn't process it
            tried_any = true;
            continue;
        }
    }

    if found_any {
        if tried_any {
            return Ok(Some("fail; dkim_unverified".to_string()));
        } else {
            // found DKIM-Signature headers but none were parseable/usable
            return Ok(Some("fail; dkim_unverified".to_string()));
        }
    }
    Ok(None)
}

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn resolver() -> Result<Resolver> {
    // Use system-configured resolvers
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    Ok(resolver)
}

// Simple DNS caches to avoid repeated lookups during message analysis
static TXT_CACHE: Lazy<Mutex<HashMap<String, (Instant, Vec<String>)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static A_CACHE: Lazy<Mutex<HashMap<String, (Instant, Vec<std::net::IpAddr>)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

fn cached_txt_lookup(name: &str) -> Option<Vec<String>> {
    let cache = TXT_CACHE.lock().unwrap();
    if let Some((ts, val)) = cache.get(name) {
        if ts.elapsed() < DNS_CACHE_TTL {
            return Some(val.clone());
        }
    }
    drop(cache);
    if let Ok(res) = resolver() {
        if let Ok(lookup) = res.txt_lookup(name) {
            let mut vals: Vec<String> = Vec::new();
            for txt in lookup.iter() {
                vals.push(txt.to_string());
            }
            let mut cache = TXT_CACHE.lock().unwrap();
            cache.insert(name.to_string(), (Instant::now(), vals.clone()));
            return Some(vals);
        }
    }
    None
}

fn cached_lookup_ip(name: &str) -> Option<Vec<std::net::IpAddr>> {
    let cache = A_CACHE.lock().unwrap();
    if let Some((ts, val)) = cache.get(name) {
        if ts.elapsed() < DNS_CACHE_TTL {
            return Some(val.clone());
        }
    }
    drop(cache);
    if let Ok(res) = resolver() {
        if let Ok(lookup) = res.lookup_ip(name) {
            let ips: Vec<std::net::IpAddr> = lookup.iter().collect();
            let mut cache = A_CACHE.lock().unwrap();
            cache.insert(name.to_string(), (Instant::now(), ips.clone()));
            return Some(ips);
        }
    }
    None
}

fn expand_spf_macros(s: &str, peer: IpAddr, mail_from: &str, current_domain: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(next) = chars.next() {
                match next {
                    '%' => out.push('%'),
                    '_' => out.push(' '),
                    '-' => out.push_str("%20"),
                    '{' => {
                        let mut mac = String::new();
                        while let Some(n) = chars.next() {
                            if n == '}' {
                                break;
                            }
                            mac.push(n);
                        }
                        let replacement = match mac.as_str() {
                            "i" => peer.to_string(),
                            "s" => mail_from.to_string(),
                            "l" => mail_from
                                .split('@')
                                .next()
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "".to_string()),
                            "d" => current_domain.to_string(),
                            _ => "".to_string(),
                        };
                        out.push_str(&replacement);
                    }
                    _ => {
                        out.push('%');
                        out.push(next);
                    }
                }
            } else {
                out.push('%');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn verify_spf(peer_ip: Option<IpAddr>, mail_from: Option<&str>) -> Result<Option<String>> {
    // Improved SPF: support ip4/ip6, a, mx, and include mechanisms (best-effort).
    use std::collections::HashSet;

    let mf = match mail_from {
        Some(s) => s,
        None => return Ok(None),
    };
    let at = mf.rfind('@');
    let domain = if let Some(i) = at { &mf[i + 1..] } else { mf };
    let domain = match crate::domain::canonicalize_domain(domain) {
        Ok(domain) => domain,
        Err(_) => return Ok(Some("permerror".to_string())),
    };
    if peer_ip.is_none() {
        return Ok(None);
    }
    let peer = peer_ip.unwrap();

    fn map_qual(q: char) -> &'static str {
        match q {
            '-' => "fail",
            '~' => "softfail",
            '?' => "neutral",
            _ => "pass",
        }
    }

    fn eval_spf_for_domain(
        domain: &str,
        peer: IpAddr,
        depth: u8,
        visited: &mut HashSet<String>,
        mail_from: &str,
    ) -> Option<String> {
        if depth > 10 {
            return None;
        }
        if visited.contains(domain) {
            return None;
        }
        visited.insert(domain.to_string());
        // try cached TXT lookup first
        let txts = cached_txt_lookup(domain)?;
        for txt in txts.iter() {
            let txt_str = txt.to_string();
            if !txt_str.to_ascii_lowercase().starts_with("v=spf1") {
                continue;
            }
            let mut seen_all: Option<char> = None;
            for tok in txt_str.split_whitespace().skip(1) {
                let mut chars = tok.chars();
                let first = chars.next().unwrap_or('\0');
                let (qual, mech) = if matches!(first, '+' | '-' | '~' | '?') {
                    (first, chars.as_str())
                } else {
                    ('+', tok)
                };
                // ip4/ip6
                if mech.starts_with("ip4:") || mech.starts_with("ip6:") {
                    let cid = &mech[4..];
                    if let Ok(net) = cid.parse::<IpNet>() {
                        if net.contains(&peer) {
                            return Some(map_qual(qual).to_string());
                        }
                    }
                } else if mech.starts_with("a") {
                    // a or a:domain
                    let target = if mech == "a" {
                        domain.to_string()
                    } else if mech.starts_with("a:") {
                        expand_spf_macros(&mech[2..], peer, mail_from, domain)
                    } else {
                        domain.to_string()
                    };
                    if let Some(ips) = cached_lookup_ip(target.as_str()) {
                        for ip in ips.iter() {
                            if *ip == peer {
                                return Some(map_qual(qual).to_string());
                            }
                        }
                    }
                } else if mech.starts_with("mx") {
                    // mx or mx:domain
                    let target = if mech == "mx" {
                        domain.to_string()
                    } else if mech.starts_with("mx:") {
                        mech[3..].to_string()
                    } else {
                        domain.to_string()
                    };
                    if let Ok(resolver) = resolver() {
                        if let Ok(mxlookup) = resolver.mx_lookup(target.as_str()) {
                            for mx in mxlookup.iter() {
                                let host = mx.exchange().to_utf8();
                                if let Some(ips) = cached_lookup_ip(host.as_str()) {
                                    for ip in ips.iter() {
                                        if *ip == peer {
                                            return Some(map_qual(qual).to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if mech.starts_with("include:") {
                    let inc_raw = &mech[8..];
                    let inc = expand_spf_macros(inc_raw, peer, mail_from, domain);
                    let mut v2 = visited.clone();
                    if let Some(res) =
                        eval_spf_for_domain(&inc, peer, depth.saturating_add(1), &mut v2, mail_from)
                    {
                        if res == "pass" {
                            return Some("pass".to_string());
                        }
                        // otherwise continue
                    }
                } else if mech.ends_with("all") {
                    // like -all, ~all, ?all, +all
                    let q = mech.chars().next().unwrap_or('+');
                    seen_all = Some(q);
                }
            }
            if let Some(q) = seen_all {
                return Some(map_qual(q).to_string());
            }
            return Some("neutral".to_string());
        }
        None
    }

    let mut visited = HashSet::new();
    if let Some(res) = eval_spf_for_domain(&domain, peer, 0, &mut visited, mf) {
        return Ok(Some(res));
    }
    Ok(None)
}

fn verify_dmarc(
    headers: &[(String, String)],
    dkim: Option<&str>,
    spf: Option<&str>,
    mail_from: Option<&str>,
) -> Result<Option<String>> {
    // Parse From header to obtain the header-from domain
    let from_hdr = match get_header_value(headers, "From") {
        Some(s) => s,
        None => return Ok(None),
    };
    let from_addr = extract_addr_from_header(&from_hdr);
    let from_domain = match from_addr
        .as_deref()
        .and_then(|s| s.rfind('@').map(|i| s[i + 1..].to_string()))
        .and_then(|domain| crate::domain::canonicalize_domain(&domain).ok())
    {
        Some(d) => d,
        None => return Ok(None),
    };

    // lookup _dmarc.<from_domain>
    let name = format!("_dmarc.{}", from_domain);
    let resolver = match resolver() {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let lookup = match resolver.txt_lookup(name.as_str()) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let mut policy: Option<String> = None;
    for txt in lookup.iter() {
        let txt_str = txt.to_string();
        if txt_str.to_ascii_lowercase().contains("p=") {
            // find p= value
            for part in txt_str.split(';') {
                let p = part.trim();
                if p.starts_with('p') && p.contains('=') {
                    if let Some(eq) = p.find('=') {
                        policy = Some(p[eq + 1..].trim().to_string());
                    }
                }
            }
        }
    }
    let policy = policy.unwrap_or_else(|| "none".to_string());

    // DMARC alignment: prefer DKIM then SPF
    if let Some(dkim_s) = dkim {
        if dkim_s.starts_with("pass") {
            // attempt to extract d= from DKIM result or headers
            if let Some(pos) = dkim_s.find("d=") {
                let rem = &dkim_s[pos + 2..];
                let dval = rem.split_whitespace().next().unwrap_or("");
                let dval = crate::domain::canonicalize_domain(dval).unwrap_or_default();
                if dval == from_domain || dval.ends_with(&format!(".{}", from_domain)) {
                    return Ok(Some("pass".to_string()));
                }
            }
            // fallback: inspect DKIM-Signature headers for d= tag
            for (k, v) in headers.iter() {
                if k.eq_ignore_ascii_case("DKIM-Signature") {
                    for part in v.split(';') {
                        let p = part.trim();
                        if p.starts_with("d=") {
                            let d = crate::domain::canonicalize_domain(p[2..].trim())
                                .unwrap_or_default();
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
                    let ef_domain = crate::domain::canonicalize_domain(&mf[idx + 1..])
                        .unwrap_or_default();
                    if ef_domain == from_domain || ef_domain.ends_with(&format!(".{}", from_domain))
                    {
                        return Ok(Some("pass".to_string()));
                    }
                }
            }
        }
    }

    // If alignment failed, return policy decision (reject/quarantine/none)
    if policy == "reject" {
        return Ok(Some("reject".to_string()));
    }
    if policy == "quarantine" {
        return Ok(Some("quarantine".to_string()));
    }
    Ok(Some("none".to_string()))
}

fn extract_addr_from_header(s: &str) -> Option<String> {
    // crude extraction: look for an @ and take surrounding token with optional <>
    if let Some(at) = s.find('@') {
        // find start
        let before = &s[..at];
        let start = before
            .rfind('<')
            .map(|i| i + 1)
            .unwrap_or_else(|| before.rfind(' ').map(|i| i + 1).unwrap_or(0));
        let after = &s[at..];
        let end = after
            .find('>')
            .map(|i| at + i)
            .unwrap_or_else(|| after.find(' ').map(|i| at + i).unwrap_or(s.len()));
        let addr = s[start..end]
            .trim()
            .trim_matches('<')
            .trim_matches('>')
            .to_string();
        return Some(addr);
    }
    None
}

/// Parse the DMARC _dmarc TXT record for rua= addresses and return mailto: recipients.
pub fn get_dmarc_rua(domain: &str) -> Result<Vec<String>> {
    let domain = crate::domain::canonicalize_domain(domain)?;
    let name = format!("_dmarc.{}", domain);
    if let Some(txts) = cached_txt_lookup(&name) {
        let mut out: Vec<String> = Vec::new();
        for txt in txts.iter() {
            for part in txt.split(';') {
                let p = part.trim();
                if p.starts_with("rua=") {
                    let list = p[4..].trim();
                    for addr in list.split(',') {
                        let a = addr.trim();
                        if a.to_ascii_lowercase().starts_with("mailto:") {
                            out.push(a[7..].to_string());
                        }
                    }
                }
            }
        }
        return Ok(out);
    }
    Ok(Vec::new())
}

/// Retrieve the published DMARC policy (p=) for a domain, if any.
pub fn get_dmarc_policy(domain: &str) -> Result<Option<String>> {
    let domain = crate::domain::canonicalize_domain(domain)?;
    let name = format!("_dmarc.{}", domain);
    if let Some(txts) = cached_txt_lookup(&name) {
        for txt in txts.iter() {
            for part in txt.split(';') {
                let p = part.trim();
                if p.starts_with("p=") {
                    return Ok(Some(p[2..].trim().to_string()));
                }
            }
        }
    }
    Ok(None)
}

// Canonicalization helpers (simplified implementations)
fn canonicalize_body_simple(body: &[u8]) -> Vec<u8> {
    // Remove trailing CRLFs and ensure a single CRLF at the end
    let mut v = body.to_vec();
    while v.ends_with(b"\r\n") || v.ends_with(b"\n") {
        if v.ends_with(b"\r\n") {
            v.truncate(v.len() - 2);
        } else {
            v.truncate(v.len() - 1);
        }
    }
    v.extend_from_slice(b"\r\n");
    v
}

fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    // Trim trailing empty lines, collapse WSP to single SP and trim WSP at line ends
    let s = String::from_utf8_lossy(body).to_string();
    // normalize line endings
    let s = s.replace("\r\n", "\n");
    let mut lines: Vec<String> = s
        .split('\n')
        .map(|ln| {
            // collapse WSP sequences to a single space and trim
            let mut out = String::new();
            let mut last_ws = false;
            for ch in ln.chars() {
                if ch == ' ' || ch == '\t' {
                    if !last_ws {
                        out.push(' ');
                        last_ws = true;
                    }
                } else {
                    out.push(ch);
                    last_ws = false;
                }
            }
            out.trim().to_string()
        })
        .collect();
    // remove trailing empty lines
    while let Some(last) = lines.last() {
        if last.is_empty() {
            lines.pop();
        } else {
            break;
        }
    }
    let mut out = lines.join("\r\n");
    out.push_str("\r\n");
    out.into_bytes()
}

fn canonicalize_header_relaxed(rec: &[u8]) -> Vec<u8> {
    // Convert to string, split name/value, lowercase name, unfold WSP, collapse runs
    let s = String::from_utf8_lossy(rec).to_string();
    // remove trailing CRLF if present
    let s = s.trim_end_matches('\r').trim_end_matches('\n');
    // find first colon
    if let Some(colon) = s.find(':') {
        let name = s[..colon].trim().to_ascii_lowercase();
        let mut value = s[colon + 1..].to_string();
        // unfold: replace CRLF + WSP with single SP and replace any LF with space
        value = value.replace("\r\n", "\n").replace('\n', " ");
        // collapse WSP sequences
        let mut out = String::new();
        let mut last_ws = false;
        for ch in value.chars() {
            if ch == ' ' || ch == '\t' {
                if !last_ws {
                    out.push(' ');
                    last_ws = true;
                }
            } else {
                out.push(ch);
                last_ws = false;
            }
        }
        let value_norm = out.trim();
        let canon = format!("{}:{}\r\n", name, value_norm);
        canon.into_bytes()
    } else {
        rec.to_vec()
    }
}

fn remove_b_from_dkim_header(rec: &[u8]) -> Vec<u8> {
    // Remove the b= tag value while preserving the original header formatting as much as possible.
    // This works on the raw header bytes and removes everything between the 'b=' and the next
    // semicolon or the end-of-line (preserving CRLF).
    let s = String::from_utf8_lossy(rec).to_string();
    if let Some(colon_pos) = s.find(':') {
        let rest = &s[colon_pos + 1..];
        let rest_lower = rest.to_ascii_lowercase();
        if let Some(rel) = rest_lower.find("b=") {
            // absolute start index of the 'b=' value in the original string
            let val_start = colon_pos + 1 + rel + 2; // position after 'b='
            let suffix = &s[val_start..];
            // find end: semicolon or CRLF or LF or end of string
            let end_idx = if let Some(semi) = suffix.find(';') {
                val_start + semi
            } else if let Some(crlf) = suffix.find("\r\n") {
                val_start + crlf
            } else if let Some(lf) = suffix.find('\n') {
                val_start + lf
            } else {
                s.len()
            };
            // Rebuild string preserving everything except the b= value bytes
            let mut out = String::new();
            out.push_str(&s[..val_start]);
            out.push_str(&s[end_idx..]);
            return out.into_bytes();
        }
    }
    // fallback: return original bytes
    rec.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_body_relaxed() {
        let input = b"  Hello   \r\nWorld\r\n\r\n\r\n";
        let out = canonicalize_body_relaxed(input);
        assert_eq!(String::from_utf8_lossy(&out), "Hello\r\nWorld\r\n");
    }

    #[test]
    fn test_canonicalize_body_simple() {
        let input = b"Line1\r\nLine2\r\n\r\n\r\n";
        let out = canonicalize_body_simple(input);
        assert_eq!(String::from_utf8_lossy(&out), "Line1\r\nLine2\r\n");
    }

    #[test]
    fn test_canonicalize_header_relaxed() {
        let input = b"From:   Alice <alice@example.com>\r\n";
        let out = canonicalize_header_relaxed(input);
        assert_eq!(
            String::from_utf8_lossy(&out),
            "from:Alice <alice@example.com>\r\n"
        );
    }

    #[test]
    fn test_expand_spf_macros() {
        use std::net::IpAddr;
        let peer: IpAddr = "1.2.3.4".parse().unwrap();
        let res = expand_spf_macros("%{i}.spf.%{d}", peer, "local@example.com", "example.com");
        assert_eq!(res, "1.2.3.4.spf.example.com");
    }

    #[test]
    fn test_remove_b_from_dkim_header() {
        let hdr = "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=brisbane; h=from:to:subject; bh=xyz; b=AbCdEfGhIjKlMnOpQrStUvWxY1234567890+/==\r\n";
        let out = remove_b_from_dkim_header(hdr.as_bytes());
        let out_s = String::from_utf8_lossy(&out).to_string();
        // should contain an empty b= tag and should not contain the original long b= value
        assert!(out_s.contains("b="));
        assert!(!out_s.contains("b=AbCdEfGhIjKlMnOpQrStUvWxY1234567890+/=="));
    }
}

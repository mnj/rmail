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
    let (headers, header_bytes, body) = parse_headers_body(data);
    let dkim = verify_dkim(&headers, header_bytes, body)?;
    let spf = verify_spf(peer_ip, mail_from)?;
    let dmarc = verify_dmarc(&headers, dkim.as_deref(), spf.as_deref(), mail_from)?;
    Ok((dkim, spf, dmarc))
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
    let (hdr_bytes, body) = if let Some(idx) = split_at { (&data[..idx+sep_len], &data[idx+sep_len..]) } else { (&data[..0], &data[..0]) };

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
    (headers, hdr_bytes, body)
}

fn get_header_value<'a>(headers: &'a [(String,String)], name: &str) -> Option<String> {
    for (k, v) in headers.iter() {
        if k.eq_ignore_ascii_case(name) {
            return Some(v.clone());
        }
    }
    None
}

fn verify_dkim(headers: &[(String,String)], header_bytes: &[u8], body: &[u8]) -> Result<Option<String>> {
    // Find all DKIM-Signature headers (if any) and try to validate the body hash (bh=) and signature when possible
    use openssl::pkey::PKey;
    use openssl::sign::Verifier;
    use openssl::hash::MessageDigest;

    let mut found = false;

    // build header records grouped by unfolded header (preserve original bytes)
    let mut records: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < header_bytes.len() {
        // find next LF
        if let Some(rel) = header_bytes[i..].iter().position(|&b| b == b'\n') {
            let end = i + rel + 1;
            let slice = &header_bytes[i..end];
            // continuation lines start with space or tab
            if slice.starts_with(b" ") || slice.starts_with(b"\t") {
                cur.extend_from_slice(slice);
            } else {
                if !cur.is_empty() { records.push(cur); cur = Vec::new(); }
                cur.extend_from_slice(slice);
            }
            i = end;
        } else {
            break;
        }
    }
    if !cur.is_empty() { records.push(cur); }

    for (k, v) in headers.iter() {
        if k.eq_ignore_ascii_case("DKIM-Signature") {
            found = true;
            // parse semicolon-separated tag=value pairs
            let mut bh: Option<String> = None;
            let mut d: Option<String> = None;
            let mut s: Option<String> = None;
            let mut b_sig: Option<String> = None;
            let mut a_alg: Option<String> = None;
            let mut h_list: Option<String> = None;
            for part in v.split(';') {
                let p = part.trim();
                if p.starts_with("bh=") { bh = Some(p[3..].trim().to_string()); }
                else if p.starts_with("d=") { d = Some(p[2..].trim().to_string()); }
                else if p.starts_with("s=") { s = Some(p[2..].trim().to_string()); }
                else if p.starts_with("b=") { b_sig = Some(p[2..].trim().to_string()); }
                else if p.starts_with("a=") { a_alg = Some(p[2..].trim().to_string()); }
                else if p.starts_with("h=") { h_list = Some(p[2..].trim().to_string()); }
            }

            // Determine canonicalization (c=)
            let mut canon: Option<String> = None;
            for part in v.split(';') {
                let p = part.trim();
                if p.starts_with("c=") { canon = Some(p[2..].trim().to_string()); }
            }

            // Verify body hash if present (apply canonicalization if requested)
            if let Some(bh_val) = bh.clone() {
                let body_to_hash = if let Some(c) = canon.as_deref() {
                    if c.starts_with("relaxed") {
                        canonicalize_body_relaxed(body)
                    } else {
                        canonicalize_body_simple(body)
                    }
                } else {
                    canonicalize_body_simple(body)
                };
                let mut hasher = Sha256::new();
                hasher.update(&body_to_hash);
                let digest = hasher.finalize();
                let computed = base64::engine::general_purpose::STANDARD.encode(digest);
                if computed.trim_end_matches('\n') != bh_val.trim() {
                    return Ok(Some(format!("fail; bh_mismatch (computed={} expected={})", computed, bh_val)));
                }
            }

            // If signature (b) present and algorithm is rsa-sha256, attempt full verification
            if let (Some(sig_b64), Some(selector), Some(domain)) = (b_sig.clone(), s.clone(), d.clone()) {
                // only support rsa-sha256 for now
                if let Some(a) = a_alg.clone() {
                    if !a.to_ascii_lowercase().contains("rsa-sha256") {
                        return Ok(Some(format!("fail; unsupported_algo {}", a)));
                    }
                }

                // construct signed header block by selecting headers listed in h= (best-effort)
                let mut signed_parts: Vec<Vec<u8>> = Vec::new();
                if let Some(hs) = h_list.clone() {
                    let mut used = vec![false; records.len()];
                    let fields: Vec<String> = hs.split(':').map(|s| s.trim().to_string()).collect();
                    // iterate fields from last to first and pick the rightmost unused occurrence
                    for fname in fields.iter().rev() {
                        for idx in (0..records.len()).rev() {
                            if used[idx] { continue; }
                            // find colon position
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

                // find DKIM-Signature record and create a version with b= emptied
                let mut dkim_header_bytes: Option<Vec<u8>> = None;
                for rec in records.iter() {
                    if let Some(pos) = rec.iter().position(|&b| b == b':') {
                        let name = String::from_utf8_lossy(&rec[..pos]).to_string();
                        if name.eq_ignore_ascii_case("DKIM-Signature") {
                            // remove the b= value (best-effort)
                            let s = String::from_utf8_lossy(rec).to_string();
                            if let Some(bpos) = s.rfind("b=") {
                                // find end of b value (semicolon or end)
                                let after = &s[bpos+2..];
                                if let Some(semi) = after.find(';') {
                                    let new_hdr = format!("{}b={};", &s[..bpos+2], &after[semi..]);
                                    dkim_header_bytes = Some(new_hdr.into_bytes());
                                } else {
                                    // no semicolon, trim until CRLF
                                    let up_to = s.trim_end_matches('\r').trim_end_matches('\n').to_string();
                                    let base = &s[..bpos+2];
                                    let new_hdr = format!("{}", base);
                                    dkim_header_bytes = Some(new_hdr.into_bytes());
                                }
                            } else {
                                dkim_header_bytes = Some(rec.clone());
                            }
                            break;
                        }
                    }
                }

                if let Some(mut dk) = dkim_header_bytes {
                    // append DKIM header as the last signed header
                    signed_parts.push(dk);
                }

                // concatenate all signed parts into a single byte vector applying header canonicalization as requested
                let mut header_data: Vec<u8> = Vec::new();
                for part in signed_parts.iter() {
                    if let Some(c) = canon.as_deref() {
                        if c.starts_with("relaxed") {
                            let ch = canonicalize_header_relaxed(part);
                            header_data.extend_from_slice(&ch);
                        } else {
                            header_data.extend_from_slice(part);
                        }
                    } else {
                        header_data.extend_from_slice(part);
                    }
                }

                // fetch public key via DNS TXT at selector._domainkey.domain
                let resolver = match resolver() { Ok(r) => r, Err(_) => return Ok(Some("fail; dns_error".to_string())) };
                let lookup_name = format!("{}.{}_domainkey.{}", selector, "", domain); // temporary
                // Correct name: selector + "._domainkey." + domain
                let lookup_name = format!("{}._domainkey.{}", selector, domain);

                let txt_lookup = match resolver.txt_lookup(lookup_name.as_str()) { Ok(t) => t, Err(_) => return Ok(Some("fail; missing_pubkey".to_string())) };

                let mut pubkey_b64: Option<String> = None;
                for txt in txt_lookup.iter() {
                    let txt_str = txt.to_string();
                    for part in txt_str.split(';') {
                        let p = part.trim();
                        if p.starts_with("p=") {
                            pubkey_b64 = Some(p[2..].trim().to_string());
                        }
                    }
                }

                if pubkey_b64.is_none() { return Ok(Some("fail; no_p_in_dns".to_string())); }
                let pubkey_b64 = pubkey_b64.unwrap();
                let pubkey_der = match base64::engine::general_purpose::STANDARD.decode(pubkey_b64.as_bytes()) { Ok(b) => b, Err(_) => return Ok(Some("fail; pubkey_decode_error".to_string())) };

                // try to build PKey from DER, falling back to PEM wrapper
                let pkey = PKey::public_key_from_der(&pubkey_der).or_else(|_| {
                    let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", base64::engine::general_purpose::STANDARD.encode(&pubkey_der));
                    PKey::public_key_from_pem(pem.as_bytes())
                });

                let pkey = match pkey {
                    Ok(pk) => pk,
                    Err(_) => return Ok(Some("fail; invalid_pubkey".to_string())),
                };

                let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(sig_b64.as_bytes()) { Ok(b) => b, Err(_) => return Ok(Some("fail; signature_decode_error".to_string())) };

                // verify signature (rsa-sha256)
                let mut verifier = match Verifier::new(MessageDigest::sha256(), &pkey) { Ok(v) => v, Err(_) => return Ok(Some("fail; verifier_init".to_string())) };
                if verifier.update(&header_data).is_err() { return Ok(Some("fail; verifier_update".to_string())); }
                match verifier.verify(&sig_bytes) {
                    Ok(true) => return Ok(Some(format!("pass; d={}", domain))),
                    Ok(false) => return Ok(Some("fail; signature_mismatch".to_string())),
                    Err(_) => return Ok(Some("fail; signature_error".to_string())),
                }
            }

            // if we get here, we had DKIM headers but couldn't verify signature; treat as none/fail depending on bh
            return Ok(Some("fail; dkim_unverified".to_string()));
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
    // Improved SPF: support ip4/ip6, a, mx, and include mechanisms (best-effort).
    use std::collections::HashSet;

    let mf = match mail_from { Some(s) => s, None => return Ok(None) };
    let at = mf.rfind('@');
    let domain = if let Some(i) = at { &mf[i+1..] } else { mf };
    if peer_ip.is_none() { return Ok(None); }
    let peer = peer_ip.unwrap();

    fn map_qual(q: char) -> &'static str {
        match q {
            '-' => "fail",
            '~' => "softfail",
            '?' => "neutral",
            _ => "pass",
        }
    }

    fn eval_spf_for_domain(domain: &str, peer: IpAddr, depth: u8, visited: &mut HashSet<String>) -> Option<String> {
        if depth > 10 { return None; }
        if visited.contains(domain) { return None; }
        visited.insert(domain.to_string());
        let resolver = resolver().ok()?;
        let lookup = resolver.txt_lookup(domain).ok()?;
        for txt in lookup.iter() {
            let txt_str = txt.to_string();
            if !txt_str.to_ascii_lowercase().starts_with("v=spf1") { continue; }
            let mut seen_all: Option<char> = None;
            for tok in txt_str.split_whitespace().skip(1) {
                let mut chars = tok.chars();
                let first = chars.next().unwrap_or('\0');
                let (qual, mech) = if matches!(first, '+'|'-'|'~'|'?') { (first, chars.as_str()) } else { ('+', tok) };
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
                    let target = if mech == "a" { domain.to_string() } else if mech.starts_with("a:") { mech[2..].to_string() } else { domain.to_string() };
                    if let Ok(ips) = resolver.lookup_ip(target.as_str()) {
                        for ip in ips.iter() {
                            if ip == peer { return Some(map_qual(qual).to_string()); }
                        }
                    }
                } else if mech.starts_with("mx") {
                    // mx or mx:domain
                    let target = if mech == "mx" { domain.to_string() } else if mech.starts_with("mx:") { mech[3..].to_string() } else { domain.to_string() };
                    if let Ok(mxlookup) = resolver.mx_lookup(target.as_str()) {
                        for mx in mxlookup.iter() {
                            let host = mx.exchange().to_utf8();
                            if let Ok(ips) = resolver.lookup_ip(host.as_str()) {
                                for ip in ips.iter() {
                                    if ip == peer { return Some(map_qual(qual).to_string()); }
                                }
                            }
                        }
                    }
                } else if mech.starts_with("include:") {
                    let inc = &mech[8..];
                    let mut v2 = visited.clone();
                    if let Some(res) = eval_spf_for_domain(inc, peer, depth.saturating_add(1), &mut v2) {
                        if res == "pass" { return Some("pass".to_string()); }
                        // otherwise continue
                    }
                } else if mech.ends_with("all") {
                    // like -all, ~all, ?all, +all
                    let q = mech.chars().next().unwrap_or('+');
                    seen_all = Some(q);
                }
            }
            if let Some(q) = seen_all { return Some(map_qual(q).to_string()); }
            return Some("neutral".to_string());
        }
        None
    }

    let mut visited = HashSet::new();
    if let Some(res) = eval_spf_for_domain(domain, peer, 0, &mut visited) {
        return Ok(Some(res));
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
    let policy = policy.unwrap_or_else(|| "none".to_string());

    // DMARC alignment: prefer DKIM then SPF
    if let Some(dkim_s) = dkim {
        if dkim_s.starts_with("pass") {
            // attempt to extract d= from DKIM result or headers
            if let Some(pos) = dkim_s.find("d=") {
                let rem = &dkim_s[pos+2..];
                let dval = rem.split_whitespace().next().unwrap_or("");
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

    // If alignment failed, return policy decision (reject/quarantine/none)
    if policy == "reject" { return Ok(Some("reject".to_string())); }
    if policy == "quarantine" { return Ok(Some("quarantine".to_string())); }
    Ok(Some("none".to_string()))
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

// Canonicalization helpers (simplified implementations)
fn canonicalize_body_simple(body: &[u8]) -> Vec<u8> {
    // Remove trailing CRLFs and ensure a single CRLF at the end
    let mut v = body.to_vec();
    while v.ends_with(b"\r\n") || v.ends_with(b"\n") {
        if v.ends_with(b"\r\n") { v.truncate(v.len()-2); }
        else { v.truncate(v.len()-1); }
    }
    v.extend_from_slice(b"\r\n");
    v
}

fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    // Trim trailing empty lines, collapse WSP to single SP and trim WSP at line ends
    let s = String::from_utf8_lossy(body).to_string();
    // normalize line endings
    let s = s.replace("\r\n", "\n");
    let mut lines: Vec<String> = s.split('\n').map(|ln| {
        // collapse WSP sequences to a single space and trim
        let mut out = String::new();
        let mut last_ws = false;
        for ch in ln.chars() {
            if ch == ' ' || ch == '\t' {
                if !last_ws { out.push(' '); last_ws = true; }
            } else {
                out.push(ch);
                last_ws = false;
            }
        }
        out.trim().to_string()
    }).collect();
    // remove trailing empty lines
    while let Some(last) = lines.last() {
        if last.is_empty() { lines.pop(); } else { break; }
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
        let mut value = s[colon+1..].to_string();
        // unfold: replace CRLF + WSP with single SP and replace any LF with space
        value = value.replace("\r\n", "\n").replace('\n', " ");
        // collapse WSP sequences
        let mut out = String::new();
        let mut last_ws = false;
        for ch in value.chars() {
            if ch == ' ' || ch == '\t' {
                if !last_ws { out.push(' '); last_ws = true; }
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

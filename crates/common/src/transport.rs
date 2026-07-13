use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub enum Transport {
    Smtp(Option<String>),
    /// Implicit TLS (smtps) next-hop
    Smtps(Option<String>),
    Error(String),
}

#[derive(serde::Deserialize)]
struct RawTransportConfig {
    transport: Option<HashMap<String, String>>,
}

/// Load transport map from <mail_root>/transport.toml
/// Example:
/// [transport]
/// example.com = "smtp:mail.example.net"
/// bad.example = "error:550 No such domain"
pub fn load_transport_map<P: AsRef<Path>>(
    mail_root: P,
) -> anyhow::Result<HashMap<String, Transport>> {
    let path = mail_root.as_ref().join("transport.toml");
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let s = std::fs::read_to_string(&path)?;
    let cfg: RawTransportConfig = toml::from_str(&s)?;
    let mut out = HashMap::new();
    if let Some(map) = cfg.transport {
        for (k, v) in map {
            let key = k.to_ascii_lowercase();
            if let Some(next_hop) = v.strip_prefix("smtp:") {
                let nh = next_hop.to_string();
                if nh.is_empty() {
                    out.insert(key, Transport::Smtp(None));
                } else {
                    out.insert(key, Transport::Smtp(Some(nh)));
                }
            } else if let Some(next_hop) = v.strip_prefix("smtps:") {
                let nh = next_hop.to_string();
                if nh.is_empty() {
                    out.insert(key, Transport::Smtps(None));
                } else {
                    out.insert(key, Transport::Smtps(Some(nh)));
                }
            } else if let Some(message) = v.strip_prefix("error:") {
                let msg = message.to_string();
                out.insert(key, Transport::Error(msg));
            } else if v == "smtp" {
                out.insert(key, Transport::Smtp(None));
            } else {
                // unknown; default to smtp
                out.insert(key, Transport::Smtp(None));
            }
        }
    }
    Ok(out)
}

/// Lookup transport for a domain. Returns Transport::Smtp(None) to indicate use MX by default.
pub fn lookup_transport<P: AsRef<Path>>(mail_root: P, domain: &str) -> anyhow::Result<Transport> {
    let map = load_transport_map(mail_root)?;
    let domain_l = domain.to_ascii_lowercase();
    if let Some(t) = map.get(&domain_l) {
        return Ok(t.clone());
    }
    // fallback wildcard
    if let Some(t) = map.get("*") {
        return Ok(t.clone());
    }
    Ok(Transport::Smtp(None))
}

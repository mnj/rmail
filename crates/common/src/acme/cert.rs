//! Inspection of installed certificates: names, issuer and validity.

use std::io::Cursor;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Clone, Serialize)]
pub struct CertificateInfo {
    pub subject: String,
    /// DNS names from the subjectAltName extension, lowercased.
    pub names: Vec<String>,
    pub issuer: String,
    /// Unix timestamps.
    pub not_before: i64,
    pub not_after: i64,
    pub serial: String,
    pub self_signed: bool,
}

impl CertificateInfo {
    pub fn lifetime_secs(&self) -> i64 {
        (self.not_after - self.not_before).max(0)
    }

    /// Whether every name in `wanted` is on the certificate (case-insensitive,
    /// exact match; a wildcard only covers itself).
    pub fn covers(&self, wanted: &[String]) -> bool {
        wanted.iter().all(|name| {
            self.names
                .iter()
                .any(|have| have.eq_ignore_ascii_case(name))
        })
    }
}

/// DER of the first certificate in a PEM bundle.
pub fn leaf_der(pem: &[u8]) -> Result<Vec<u8>> {
    rustls_pemfile::certs(&mut Cursor::new(pem))
        .context("reading PEM certificates")?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no certificate found"))
}

pub fn inspect_pem(pem: &[u8]) -> Result<CertificateInfo> {
    inspect_der(&leaf_der(pem)?)
}

pub fn inspect_file(path: impl AsRef<Path>) -> Result<CertificateInfo> {
    let path = path.as_ref();
    let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    inspect_pem(&pem).with_context(|| format!("parsing {}", path.display()))
}

pub fn inspect_der(der: &[u8]) -> Result<CertificateInfo> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|error| anyhow!("{error}"))?;
    let mut names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                names.push(dns.to_ascii_lowercase());
            }
        }
    }
    let subject = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| cert.subject().to_string());
    Ok(CertificateInfo {
        subject,
        names,
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        serial: cert.raw_serial_as_string(),
        self_signed: cert.subject() == cert.issuer(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects_a_generated_certificate() {
        let (cert_path, _) = crate::test_support::localhost_cert();
        let info = inspect_file(cert_path).unwrap();
        assert!(info.names.contains(&"localhost".to_string()));
        assert!(info.not_after > info.not_before);
        assert!(info.covers(&["LOCALHOST".to_string()]));
        assert!(!info.covers(&["mail.example.com".to_string()]));
    }
}

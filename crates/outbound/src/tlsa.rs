use openssl::sha::{sha256, sha512};

pub struct TlsaRecord {
    pub usage: u8,
    pub selector: u8,
    pub mtype: u8,
    pub data: Vec<u8>,
}

/// Return true if any TLSA record matches the provided certificate (DER) or SPKI (DER).
/// This function performs the selector (0=cert, 1=SPKI) and matching type (0=exact,1=sha256,2=sha512)
/// comparisons. It intentionally does NOT interpret cert-usage semantics (0..3); callers should
/// handle usage-based policy (PKIX verification, trust-anchor semantics) as appropriate.
pub fn match_tlsa_records(recs: &[TlsaRecord], cert_der: &[u8], spki_der: &[u8]) -> bool {
    for r in recs {
        let target = if r.selector == 0 { cert_der } else { spki_der };
        let ok = match r.mtype {
            0 => target == r.data.as_slice(),
            1 => {
                let dg = sha256(target);
                dg.as_slice() == r.data.as_slice()
            }
            2 => {
                let dg = sha512(target);
                dg.as_slice() == r.data.as_slice()
            }
            _ => false,
        };
        if ok { return true; }
    }
    false
}

/// Return a vector of certUsage values from records that match the provided cert/SPKI.
/// This lets callers know which usage types matched so they can apply DANE policy (PKIX
/// validation requirements, trust-anchor behavior) accordingly.
pub fn match_tlsa_usages(recs: &[TlsaRecord], cert_der: &[u8], spki_der: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for r in recs {
        let target = if r.selector == 0 { cert_der } else { spki_der };
        let ok = match r.mtype {
            0 => target == r.data.as_slice(),
            1 => {
                let dg = sha256(target);
                dg.as_slice() == r.data.as_slice()
            }
            2 => {
                let dg = sha512(target);
                dg.as_slice() == r.data.as_slice()
            }
            _ => false,
        };
        if ok { out.push(r.usage); }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_tlsa_sha256() {
        let cert = b"certdata";
        let spki = b"spkibytes";
        let dg = sha256(cert);
        let rec = TlsaRecord { usage: 3, selector: 0, mtype: 1, data: dg.to_vec() };
        assert!(match_tlsa_records(&[rec], cert, spki));
    }

    #[test]
    fn test_match_tlsa_direct() {
        let cert = b"mycert";
        let spki = b"spk";
        let rec = TlsaRecord { usage: 3, selector: 0, mtype: 0, data: cert.to_vec() };
        assert!(match_tlsa_records(&[rec], cert, spki));
    }
}

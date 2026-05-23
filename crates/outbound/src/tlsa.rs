use openssl::sha::{sha256, sha512};

pub struct TlsaRecord {
    pub usage: u8,
    pub selector: u8,
    pub mtype: u8,
    pub data: Vec<u8>,
}

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

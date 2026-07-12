use std::net::{Ipv4Addr, Ipv6Addr};

pub fn canonicalize_domain(domain: &str) -> anyhow::Result<String> {
    if domain.is_empty() || domain.ends_with('.') {
        anyhow::bail!("domain is empty or has a trailing root label");
    }
    let ascii = idna::domain_to_ascii(domain)
        .map_err(|error| anyhow::anyhow!("invalid internationalized domain: {error}"))?
        .to_ascii_lowercase();
    if ascii.len() > 255 {
        anyhow::bail!("domain exceeds 255 octets");
    }
    for label in ascii.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            anyhow::bail!("invalid DNS label");
        }
    }
    Ok(ascii)
}

pub fn canonicalize_address_literal(literal: &str) -> anyhow::Result<String> {
    let inner = literal
        .strip_prefix('[')
        .and_then(|literal| literal.strip_suffix(']'))
        .ok_or_else(|| anyhow::anyhow!("address literal must be bracketed"))?;
    if let Some((tag, address)) = inner.split_once(':') {
        if tag.eq_ignore_ascii_case("IPv6") {
            return Ok(format!("[IPv6:{}]", address.parse::<Ipv6Addr>()?));
        }
        if tag.is_empty()
            || tag.starts_with('-')
            || tag.ends_with('-')
            || !tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || address.is_empty()
            || !address
                .bytes()
                .all(|byte| (33..=90).contains(&byte) || (94..=126).contains(&byte))
        {
            anyhow::bail!("invalid general address literal");
        }
        return Ok(format!("[{}:{address}]", tag.to_ascii_lowercase()));
    }
    Ok(format!("[{}]", inner.parse::<Ipv4Addr>()?))
}

pub fn canonicalize_mailbox_address(address: &str) -> anyhow::Result<String> {
    let separator = address
        .rfind('@')
        .ok_or_else(|| anyhow::anyhow!("mailbox address is missing a domain"))?;
    let (localpart, domain_with_at) = address.split_at(separator);
    if localpart.is_empty() {
        anyhow::bail!("mailbox local-part is empty");
    }
    let domain = canonicalize_domain(&domain_with_at[1..])?;
    Ok(format!("{localpart}@{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_canonicalize_to_stable_idna_alabels() {
        assert_eq!(
            canonicalize_domain("BÜCHER.Example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            canonicalize_domain("xn--bcher-kva.EXAMPLE").unwrap(),
            "xn--bcher-kva.example"
        );
        assert!(canonicalize_domain("bad..example").is_err());
        assert!(canonicalize_domain("-bad.example").is_err());
        assert!(canonicalize_domain("example.test.").is_err());
    }

    #[test]
    fn address_literals_are_validated_and_canonicalized() {
        assert_eq!(
            canonicalize_address_literal("[IPv6:2001:0db8::1]").unwrap(),
            "[IPv6:2001:db8::1]"
        );
        assert_eq!(
            canonicalize_address_literal("[192.0.2.1]").unwrap(),
            "[192.0.2.1]"
        );
        assert!(canonicalize_address_literal("[IPv6:not-an-ip]").is_err());
    }

    #[test]
    fn mailbox_addresses_preserve_localpart_and_canonicalize_domain() {
        assert_eq!(
            canonicalize_mailbox_address("User@BÜCHER.example").unwrap(),
            "User@xn--bcher-kva.example"
        );
    }
}

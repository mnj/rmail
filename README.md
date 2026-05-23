# rMail

rMail — inbound-only SMTP and IMAP servers in Rust (2024 edition).

Repository layout:
- crates/common — shared utilities and config parsing
- crates/smtpd — SMTP inbound server (Maildir delivery)
- crates/imapd — IMAP server exposing Maildir
- crates/ctl — CLI for account management

See config/example.toml for configuration examples. Test TLS certs are generated in config/certs/ and are ignored by git.

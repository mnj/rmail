# Warning
This is not a serious project, just testing smaller AI models, and how far they can be pushed.

# rMail

rMail — inbound-only SMTP and IMAP servers in Rust.

Repository layout:
- crates/common — shared utilities and config parsing
- crates/smtpd — SMTP inbound server (Maildir delivery)
- crates/imapd — IMAP server exposing Maildir
- crates/webmail — user-facing webmail server and React/Vite SPA
- crates/ctl — CLI for account management

See config/example.toml for configuration examples. Test TLS certs are generated in config/certs/ and are ignored by git.

Webmail frontend dependencies and builds use Bun:

```bash
cd crates/webmail/frontend
bun install
bun run build
```

Deployment and packaging guidance lives in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

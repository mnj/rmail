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

## IMAP standards support

rMail advertises `IMAP4rev1` and implements the core mailbox, message, search,
state-transition, literal, and response behavior required by RFC 3501. Its IMAP
implementation also includes the extensions listed below. Capabilities are
phase-aware: authentication mechanisms, `STARTTLS`, and post-authentication
extensions are advertised only when they are usable in the current session.

The percentages are engineering coverage estimates, not certification results.
They measure implemented and automated-tested server-side requirements that are
applicable to rMail; client-only requirements and optional behavior outside the
advertised capability are excluded. A value below 100% identifies known scope
or conformance-validation gaps.

| RFC | Feature | Estimated compliance | Remaining limitation |
| --- | --- | ---: | --- |
| RFC 3501 | IMAP4rev1 core | 95% | No formal protocol test-suite certification or exhaustive live-client matrix yet. |
| RFC 2595 | IMAP `STARTTLS` and `LOGINDISABLED` | 95% | A real TLS upgrade and resumed IMAP session are integration-tested, but not yet against an external conformance harness. |
| RFC 2177 | `IDLE` | 100% | Implemented with mailbox synchronization, keepalives, fragmented `DONE`, and bounded input. |
| RFC 2342 | `NAMESPACE` | 100% | Complete for rMail's single personal Maildir namespace. |
| RFC 2971 | `ID` | 100% | Includes strict argument and size validation. |
| RFC 4315 | `UIDPLUS` | 100% | `APPENDUID`, `COPYUID`, and `UID EXPUNGE` are implemented. |
| RFC 5161 | `ENABLE` | 100% | Enabled features are tracked per session and validated. |
| RFC 5256 | `SORT` and `THREAD` | 90% | Advertised algorithms are implemented; international collation coverage is not exhaustive. |
| RFC 4731 | `ESEARCH` | 95% | Core and UID result forms are implemented; no external conformance certification. |
| RFC 5182 | `SEARCHRES` | 100% | Saved search results and `$` sequence-set use are implemented. |
| RFC 5032 | `WITHIN` | 100% | `OLDER` and `YOUNGER` search keys are implemented. |
| RFC 5258 | `LIST-EXTENDED` | 95% | Selection/return options and hierarchy attributes are implemented; exotic namespace combinations are not applicable. |
| RFC 5819 | `LIST-STATUS` | 100% | STATUS return data is supported in extended LIST responses. |
| RFC 6154 | `SPECIAL-USE` | 100% | Discovery and requested special-use mailbox attributes are implemented. |
| RFC 7162 | `CONDSTORE` and `QRESYNC` | 90% | Mod-sequences, `CHANGEDSINCE`, `VANISHED`, and QRESYNC SELECT are implemented; no multi-server replication validation. |
| RFC 6851 | `MOVE` | 100% | Sequence and UID forms include UIDPLUS response data. |
| RFC 6855 | `UTF8=ACCEPT` | 85% | UTF-8 mailbox/message operation is implemented; `UTF8=ONLY` is not advertised or implemented. |
| RFC 3516 | `BINARY` | 95% | Binary FETCH sections and sizes are implemented; exhaustive MIME corpus validation remains. |
| RFC 4466 | Collected extension grammar | 95% | Extension argument/response forms used by advertised capabilities are implemented. |
| RFC 4469 | `CATENATE` | 0% | Not implemented or advertised. |
| RFC 2088 / RFC 7888 | `LITERAL+` / `LITERAL-` | 100% | Synchronizing and bounded non-synchronizing literals are implemented. |
| RFC 4978 | `COMPRESS=DEFLATE` | 100% | Compression negotiation and post-negotiation command transport are implemented. |
| RFC 4959 | SASL initial response | 100% | Initial, empty, continuation, and cancellation responses are supported. |
| RFC 4616 | SASL `PLAIN` | 100% | Available only under the configured encrypted-transport policy. |
| RFC 5802 / RFC 7677 | `SCRAM-SHA-256` | 100% | Includes stored SCRAM credentials and verifier checks. |
| RFC 5929 | `SCRAM-SHA-256-PLUS` channel binding | 100% | Uses TLS server-end-point channel binding. |

IMAP4rev2 (RFC 9051), OAuth mechanisms, `MULTIAPPEND`, `CATENATE`, `PREVIEW`,
and `SNIPPET` are not currently advertised.

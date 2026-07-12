# Warning
This is not a serious project, just testing smaller AI models, and how far they can be pushed.

# rMail

rMail - SMTP, authenticated submission, outbound relay, and IMAP servers in Rust.

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

## SMTP standards support

rMail implements an ESMTP receiver and authenticated submission path with
phase-aware `EHLO` extensions. SMTP commands are parsed through bounded
streaming input, transaction and authentication state are validated before
dispatch, and unsupported envelope extensions are rejected rather than
silently accepted. The percentages use the same server-applicable engineering
coverage methodology described in the IMAP section below; they are not formal
certification results.

| RFC | Feature | Estimated compliance | Remaining limitation |
| --- | --- | ---: | --- |
| RFC 5321 | SMTP transport and transactions | 95% | Strict command/reply framing, path grammar, Postmaster handling, DATA transparency, sequencing, limits, one-reply transaction behavior, and relay policy are implemented; multi-destination storage is not yet one cross-backend atomic commit and external conformance testing remains. |
| RFC 1869 | ESMTP framework | 95% | EHLO negotiation and extension parameters are implemented; no external conformance certification. |
| RFC 1870 | `SIZE` | 100% | The fixed maximum is advertised and declared or received oversized messages are rejected while preserving stream synchronization. |
| RFC 6152 | `8BITMIME` | 100% | BODY declarations are parsed and retained, undeclared 8-bit content is rejected after safe DATA draining, and outbound relay negotiates and declares 8BITMIME. |
| RFC 2920 | `PIPELINING` | 100% | Command pipelining is supported with ordered replies and guarded STARTTLS transitions. |
| RFC 3207 | `STARTTLS` | 95% | A real TLS upgrade, state reset, fresh EHLO requirement, timeout, and plaintext-pipelining rejection are integration-tested; external conformance testing remains. |
| RFC 4954 | SMTP AUTH | 95% | Configurable TLS-gated mechanisms, strict grammar, initial responses, bounded continuations, cancellation, state restrictions, and enhanced replies are implemented; external conformance testing remains. |
| RFC 4616 | SASL `PLAIN` | 100% | Initial and continuation forms, authzid policy, UTF-8 validation, and shared credential verification are implemented under TLS. |
| RFC 5802 / RFC 7677 | `SCRAM-SHA-256` | 100% | Strict SCRAM grammar, stored verifiers, nonce/channel-binding downgrade checks, client proof validation, and server-final data are implemented and integration-tested. |
| RFC 6531 | `SMTPUTF8` | 95% | UTF-8 envelope/header use is declaration-gated and outbound relay negotiates SMTPUTF8; full IDNA canonicalization and downgrade behavior are not implemented. |
| RFC 3463 | Enhanced status codes | 70% | Main policy, sequencing, size, scanner, and authentication failures use enhanced codes; some legacy replies still need conversion. |
| RFC 3848 | Received trace protocol identifiers | 100% | Generated trace fields distinguish SMTP, ESMTP, TLS, and authenticated submission with the appropriate protocol token. |
| RFC 3461 | Delivery Status Notifications | 0% | `DSN` is not advertised; `NOTIFY` and `ORCPT` are rejected. |
| RFC 3030 | `CHUNKING`/`BINARYMIME` | 0% | Not implemented or advertised. |
| RFC 7208 | SPF receiver checks | 85% | SPF evaluation and result accounting are implemented; broad DNS/interoperability corpus validation remains. |
| RFC 6376 | DKIM verification | 85% | DKIM verification and result accounting are implemented; exhaustive algorithm/canonicalization corpus validation remains. |
| RFC 7489 | DMARC policy | 80% | Alignment, policy outcomes, quarantine, and optional rejection are implemented; aggregate/forensic reporting is not implemented. |

SMTP AUTH mechanisms are configured independently with
`security.smtp_sasl_mechanisms`. OAuth mechanisms, DSN, CHUNKING, BINARYMIME,
and REQUIRETLS are not currently advertised.

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

# rMail

rMail - SMTP, authenticated submission, outbound relay, IMAP, POP3 and ManageSieve servers in Rust, with a web admin
console and webmail.

**Project site: [mnj.github.io/rmail](https://mnj.github.io/rmail/)**. It has a feature overview,
screenshots of every page, and a quick start.

![Admin console overview](site/assets/screenshots/admin-overview.webp)

## Features

- **SMTP, submission and LMTP**: phase-aware ESMTP with STARTTLS, PIPELINING, 8BITMIME, SMTPUTF8,
  CHUNKING/BINARYMIME, DSN and REQUIRETLS; AUTH PLAIN, SCRAM-SHA-256 and optional OAUTHBEARER/XOAUTH2.
- **IMAP4rev1 and IMAP4rev2** over Maildir: IDLE, CONDSTORE/QRESYNC, MOVE, SORT/THREAD, PREVIEW,
  QUOTA, METADATA, NOTIFY, UIDONLY, REPLACE, COMPRESS and SCRAM-SHA-256-PLUS.
- **Mail authentication**: inbound SPF, DKIM, DMARC (with aggregate reports) and ARC; outbound DKIM
  and ARC signing; optional ClamAV and rspamd filtering.
- **POP3 and Sieve**: POP3 with STLS, server-side Sieve filtering with vacation replies, and
  ManageSieve for clients to edit scripts.
- **Outbound relay queue** with retries, per-destination limits, connection reuse, MTA-STS, opt-in
  DANE, Null MX handling, daily SMTP TLS reports (TLS-RPT), and delivery routes (smarthost with
  AUTH, per-domain relays).
- **Anti-abuse**: greylisting, DNSBL checks for unauthenticated clients, and per-account and
  per-domain submission caps.
- **Domains & DNS**: DKIM keys (RSA and Ed25519) generated in the console, and the DNS records to
  publish per domain (MX, SPF, DKIM, DMARC, SRV, `_mta-sts`, `_smtp._tls`); MTA-STS policy hosting,
  Thunderbird autoconfig and Outlook autodiscover.
- **Load balancers**: HAProxy PROXY protocol v1/v2 on the mail listeners.
- **Admin console** for mailboxes, quotas, aliases, catchalls, the outbound queue, database-stored
  settings, logs, Prometheus metrics and readiness checks.
- **Webmail** with folders, search, sandboxed HTML rendering, blocked remote images and a mobile
  layout.
- **JMAP** (RFC 8620, RFC 8621) for mail clients, served by webmail: mailboxes, email, threads,
  search, sending, vacation response and push.
- **Operations**: structured JSON logs, live `rmail_ctl watch`, per-message tracking, built-in
  ACME certificates (Let's Encrypt over HTTP or DNS, renewed and hot-reloaded), and `.deb`
  packages for amd64 and arm64 published on every merge.

## Screenshots

| Admin console | Webmail |
| --- | --- |
| ![Mailboxes](site/assets/screenshots/admin-mailboxes.webp) | ![Webmail inbox](site/assets/screenshots/webmail-inbox.webp) |
| ![Settings](site/assets/screenshots/admin-settings.webp) | ![Remote images blocked](site/assets/screenshots/webmail-remote-blocked.webp) |

More on the [screenshots page](https://mnj.github.io/rmail/screenshots.html). To regenerate them
after a UI change, run `scripts/screenshots/capture.sh`. It builds everything, starts a throwaway
demo instance on loopback ports, fills it with sample data and captures both apps with Playwright.

## Repository layout

- crates/common — shared protocol, storage, settings, HTTP and auth helpers
- crates/smtpd — SMTP/LMTP receiver and authenticated submission (Maildir delivery)
- crates/imapd — IMAP server exposing Maildir
- crates/outbound — outbound relay worker
- crates/queue-manager, crates/queuectl — outbound spool management
- crates/webui — admin console (`rmail_web`) and its React/Vite frontend
- crates/webmail — user-facing webmail server and React/Vite SPA
- crates/classifier — `rmail_classifier`, optional folder suggestions from local GGUF models (llama.cpp in-process) or hosted providers (OpenRouter, TypeSafe Jev), with per-user consent
- crates/ctl — `rmail_ctl` CLI for accounts, settings, certificates and services
- crates/bench — live performance workloads
- site — the GitHub Pages project site, deployed by `.github/workflows/pages.yml`
- scripts/screenshots — demo instance and Playwright capture for the site's screenshots

## Configuration

The configuration file only needs to bootstrap the storage locations:

```toml
[global]
mail_root = "/var/lib/rmail"
db_path = "/var/lib/rmail/rmail.db"
```

Everything else (listeners, TLS, SASL mechanisms, rate limits, content filtering, OAuth, DKIM keys,
delivery routes) is stored in the SQLite database and edited in the admin console or with
`rmail_ctl settings`, `rmail_ctl dkim` and `rmail_ctl transport`. Other keys in the file are
ignored. Services pick up changes on restart; the console shows which services are waiting for
one. `scripts/dev-settings.sh` stores the settings of the local test instance (`config/test.toml`).

Set the admin console password with `rmail_ctl admin-password`, or open the console on its loopback
address and create the admin account in the browser.

Test TLS certificates for local runs go in config/certs/ (ignored by git); the test suite generates
its own.

Both frontends (webmail and admin console) use Bun:

```bash
cd crates/webmail/frontend   # or crates/webui/frontend
bun install
bun run typecheck
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
| RFC 5321 | SMTP transport and transactions | 95% | Strict command/reply framing, path grammar (256-octet path limit, extension-aware MAIL/RCPT line limits), Postmaster handling, DATA transparency with strict `<CRLF>.<CRLF>` termination (non-canonical terminators close the connection to prevent SMTP smuggling), nested-MAIL rejection, a configurable server hostname for greetings, EHLO and trace fields, sequencing, limits, and relay policy are implemented; multi-destination storage is not yet one cross-backend atomic commit and external conformance testing remains. |
| RFC 1869 | ESMTP framework | 95% | EHLO negotiation and extension parameters are implemented; no external conformance certification. |
| RFC 1870 | `SIZE` | 100% | The fixed maximum is advertised and declared or received oversized messages are rejected while preserving stream synchronization. |
| RFC 6152 | `8BITMIME` | 100% | BODY declarations are parsed and retained, undeclared 8-bit content is rejected after safe DATA draining, and outbound relay negotiates and declares 8BITMIME. |
| RFC 2920 | `PIPELINING` | 100% | Command pipelining is supported with ordered replies and guarded STARTTLS transitions. |
| RFC 3207 | `STARTTLS` | 95% | A real TLS upgrade, state reset, fresh EHLO requirement, timeout, and plaintext-pipelining rejection are integration-tested; external conformance testing remains. |
| RFC 4954 | SMTP AUTH | 95% | Configurable TLS-gated mechanisms, strict grammar, initial responses, bounded continuations, cancellation, state restrictions, the `AUTH=` MAIL parameter, and enhanced replies are implemented; external conformance testing remains. |
| RFC 4616 | SASL `PLAIN` | 100% | Initial and continuation forms, authzid policy, UTF-8 validation, and shared credential verification are implemented under TLS. |
| RFC 5802 / RFC 7677 | `SCRAM-SHA-256` and `SCRAM-SHA-256-PLUS` | 100% | Strict SCRAM grammar, stored verifiers, `y`-flag downgrade detection when -PLUS is offered, fake challenges for unknown users, client proof validation, and server-final data are implemented and integration-tested. -PLUS supports `tls-server-end-point` (RFC 5929) and `tls-exporter` on TLS 1.3 (RFC 9266). |
| RFC 6531 | `SMTPUTF8` | 100% | UTF-8 envelope/header use is declaration-gated, outbound relay negotiates and declares SMTPUTF8, and internationalized envelope domains are canonicalized to IDNA A-labels at persistence, routing, DNS, and authentication boundaries. RFC 6531 does not require downgrade support. |
| RFC 5890 / RFC 5891 | IDNA2008 domain handling | 95% | SMTP envelope domains, mailbox/alias/catchall identities, outbound DNS routes, and SPF/DKIM/DMARC alignment inputs share validated U-label-to-A-label canonicalization with DNS length checks; broad multilingual interoperability corpus testing remains. |
| RFC 3463 / RFC 2034 | Enhanced status codes | 100% | `ENHANCEDSTATUSCODES` is advertised and command, transaction, policy, delivery, TLS, and authentication replies carry class-appropriate enhanced codes. |
| RFC 2033 | LMTP | 95% | `LHLO` and per-recipient DATA replies over a dedicated local listener that never authenticates or relays; no external conformance testing. |
| RFC 8314 | Implicit TLS submission (port 465) | 100% | SMTPS listeners run TLS from the first byte; STARTTLS is not offered inside them. |
| RFC 9422 | `LIMITS` | 100% | `RCPTMAX` advertises the per-transaction recipient limit already enforced at RCPT; the relay honors a next hop's `MAILMAX` by closing pooled sessions that reached it. rMail sets no `MAILMAX` or `RCPTDOMAINMAX` of its own. |
| RFC 3848 | Received trace protocol identifiers | 100% | Generated trace fields distinguish SMTP, ESMTP, TLS, and authenticated submission with the appropriate protocol token. |
| SRS (draft) | Sender Rewriting Scheme | 100% | With `security.srs_domain`, forwarded mail gets an `SRS0`/`SRS1` envelope sender keyed with a generated secret; bounces to it within 21 days are verified and returned to the original sender. Hosted and null senders are not rewritten. |
| RFC 3461 | Delivery Status Notifications | 100% | `DSN`, `RET`, `ENVID`, `NOTIFY`, and `ORCPT` are implemented with private queue metadata and loop-safe success/failure reports. |
| RFC 8689 | `REQUIRETLS` | 100% | Advertised and accepted only on TLS sessions; submission, durable queue metadata, relay advertisement checks, and downgrade-resistant TLS enforcement are implemented. |
| RFC 3030 | `CHUNKING`/`BINARYMIME` | 95% | Both extensions are advertised together. The receiver supports exact-octet, multi-command BDAT transactions, LAST and zero-length chunks, cumulative SIZE enforcement with stream-preserving drains, DATA/BDAT state exclusion, and BODY=BINARYMIME validation. Relay capability negotiation selects binary-safe BDAT and requires both extensions for binary content; external conformance corpus testing remains. |
| RFC 7208 | SPF receiver checks | 85% | SPF evaluation and result accounting are implemented; broad DNS/interoperability corpus validation remains. |
| RFC 6376 | DKIM verification | 85% | DKIM verification and result accounting are implemented; exhaustive algorithm/canonicalization corpus validation remains. |
| RFC 7489 / RFC 6591 | DMARC policy and reports | 90% | Alignment, policy outcomes, quarantine and optional rejection are implemented. Every unauthenticated inbound evaluation for a domain that asks for reports is recorded for aggregate (`rua`) reports, and opt-in failure reports (`security.dmarc_failure_reports`, honoring `fo` and `ruf` size limits) carry the headers but never the body, at most 10 per domain per hour. External report destinations must authorize themselves (section 7.1); organizational domains are approximated without a public suffix list. |
| RFC 8617 | ARC verification and sealing | 85% | Inbound ARC chains are verified and forwarded mail (aliases, catchalls) is sealed once per message; sealing uses `rsa-sha256` keys only. |
| RFC 3464 / RFC 6522 | DSN message format | 95% | Success, delay, and failure reports from the receiver and the relay are `multipart/report` with `message/delivery-status`; corpus testing against other MTAs' parsers remains. |
| RFC 5782 | DNSBL client | 90% | Unauthenticated inbound clients are checked against configured blocklists with cached results; lookups fail open on timeouts. IPv6 lookups follow the RFC's nibble format; per-list return-code filtering is basic. |

Greylisting (RFC 6647 practice, persisted to SQLite) and rspamd greylist verdicts defer unknown
senders with `451 4.7.1`; it is not an RFC requirement and has no compliance figure.

SMTP AUTH mechanisms are configured independently with
`security.smtp_sasl_mechanisms`. `OAUTHBEARER` and `XOAUTH2` can be enabled when
an OAuth token-introspection authority is configured under `security.oauth`.

## Outbound relay and DNS publishing support

The relay (`rmail_outbound`) delivers queued mail to remote MX hosts, and the admin console
publishes the HTTP and DNS material other servers and clients look up. Percentages use the same
methodology as the tables above.

| RFC | Feature | Estimated compliance | Remaining limitation |
| --- | --- | ---: | --- |
| RFC 5321 | SMTP client | 90% | MX preference ordering, implicit-MX fallback only when no MX exists, EHLO with a configured FQDN, connection reuse, transient/permanent reply classification, and delivery routes (smarthost or per-domain relay with AUTH PLAIN only over TLS with a verified certificate) are implemented. Opportunistic STARTTLS accepts any certificate (RFC 7435). With `PIPELINING` (RFC 2920), MAIL and RCPT go out as one group. |
| RFC 7505 | Null MX | 100% | A domain publishing `MX 0 .` fails immediately with a permanent error and a failure DSN. |
| RFC 3461 | DSN client parameters | 100% | `RET`, `ENVID`, `NOTIFY` and `ORCPT` are passed on when the next hop advertises `DSN`, which then owns success reports; a next hop without DSN gets an `Action: relayed` report naming the Remote-MTA. Delay and failure reports are generated locally. |
| RFC 6152 / RFC 6531 / RFC 3030 | `8BITMIME`, `SMTPUTF8`, `CHUNKING`/`BINARYMIME` | 95% | Declared when the next hop advertises them; BDAT is used when CHUNKING is offered and binary content requires both extensions. No 8-bit-to-7-bit downgrade. |
| RFC 8689 | `REQUIRETLS` (client) | 95% | Messages marked REQUIRETLS are delivered only over verified TLS to a host advertising REQUIRETLS, and bounce otherwise. |
| RFC 8461 | MTA-STS (sending) | 90% | Policies are fetched over HTTPS, size-bounded and cached; `enforce` requires a matching MX and verified TLS, `testing` logs mismatches and delivers. Cache is in memory, so policies are refetched after a restart. |
| RFC 8461 | MTA-STS (publishing) | 95% | `mta-sts.<domain>/.well-known/mta-sts.txt` is served from the admin console's HTTP listener with a content-derived `_mta-sts` policy id. |
| RFC 8460 | SMTP TLS reporting | 95% | Delivery TLS successes and failures are aggregated per policy domain (`sts` and `tlsa`) and sent daily as gzipped JSON (`application/tlsrpt+gzip`), by mail to `mailto:` targets and by HTTPS POST to `https:` targets. |
| RFC 7672 | DANE for SMTP | 85% | Opt-in with `security.dane_enabled`. DNSSEC status comes from the AD bit of a validating recursive resolver. DANE-TA(2) and DANE-EE(3) are verified, unusable-only TLSA RRsets make TLS mandatory, failed TLSA lookups rule the host out, and DANE takes precedence over MTA-STS. MX hosts behind CNAMEs use the original name as TLSA base. |
| RFC 6376 / RFC 8463 | DKIM signing | 100% | Every key of a sender domain signs, so RSA (`rsa-sha256`) and Ed25519 (`ed25519-sha256`) signatures go out side by side. Keys live in the database. |
| RFC 6186 | SRV service discovery | 90% | One IMAP and one submission SRV record (`_imaps`/`_submissions` when implicit TLS listeners exist, otherwise `_imap`/`_submission`) are included in the suggested DNS records; the opposite variant is not offered, and records are suggestions the operator must publish. |
| RFC 8314 | Implicit TLS preference | 100% | Autoconfig, autodiscover and SRV suggestions prefer implicit TLS (465/993) when those listeners exist. |
| RFC 1939 / RFC 2449 / RFC 5034 | POP3 | 95% | USER/PASS, AUTH PLAIN, CAPA, UIDL, TOP and STLS (RFC 2595) on the INBOX, with exclusive access per account. |
| RFC 5228 / RFC 5230 | Sieve and vacation | 85% | `fileinto`, `envelope`, `imap4flags`, `copy`, `body`, `relational` and `vacation` at local delivery; header values are not RFC 2047-decoded. |
| RFC 5804 | ManageSieve | 95% | Script upload, activation, CHECKSCRIPT and STARTTLS; SASL PLAIN only. |
| HAProxy spec | PROXY protocol v1/v2 | 100% | Connections from `security.proxy_protocol_trusted_networks` must start with a PROXY header; others are never parsed for one. |
| RFC 8555 | ACME certificates | 95% | `http-01` and `dns-01` challenges, optional External Account Binding, renewal, and hot reload are implemented. |

Thunderbird autoconfig (`config-v1.1.xml`) and Outlook POX autodiscover are served for
`autoconfig.<domain>` and `autodiscover.<domain>`. They are vendor formats, not RFCs.

## Not yet supported

- **IMAP `UTF8=ONLY`** (RFC 6855, deliberately: it locks out non-UTF-8 clients) and `URLAUTH`
  (RFC 4467) with BURL (RFC 4468).
- **SMTP `MT-PRIORITY`** (RFC 6710), `DELIVERBY` (RFC 2852),
  `FUTURERELEASE` (RFC 4865) and `ETRN` (RFC 1985).
- **ARF abuse feedback** (RFC 5965) beyond DMARC failure reports.

## IMAP standards support

rMail advertises `IMAP4rev1` and `IMAP4rev2` and implements the core mailbox, message, search,
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
| RFC 3501 | IMAP4rev1 core | 95% | Includes sequence-number stability: EXPUNGE is never sent during FETCH, STORE or SEARCH, and messages expunged by other sessions keep their slot (`EXPUNGEISSUED`) until the next allowed point; an inactivity autologout (3 minutes before login, 30 minutes after, including IDLE) is enforced. No formal protocol test-suite certification or exhaustive live-client matrix yet. |
| RFC 9051 | IMAP4rev2 core | 90% | Dual-advertised; after `ENABLE IMAP4rev2` the session uses UTF-8, omits `RECENT`/`\Recent`, answers SEARCH with ESEARCH, and includes the mailbox LIST line in SELECT. `STATUS DELETED` is supported, and RENAME returns LIST responses with `OLDNAME` for the renamed mailbox and its children. No external rev2 conformance certification yet. |
| RFC 2595 | IMAP `STARTTLS` and `LOGINDISABLED` | 95% | A real TLS upgrade and resumed IMAP session are integration-tested, but not yet against an external conformance harness. |
| RFC 2177 | `IDLE` | 100% | Implemented with mailbox synchronization, keepalives, fragmented `DONE`, and bounded input. |
| RFC 2342 | `NAMESPACE` | 100% | The personal namespace and an `Other Users/` namespace holding mailboxes other accounts share with the user. |
| RFC 4314 | `ACL` and `RIGHTS=kxte` | 90% | `SETACL` (with `+`/`-` changes), `DELETEACL`, `GETACL`, `LISTRIGHTS` and `MYRIGHTS`. Every command checks the rights it needs; a mailbox the user may neither list nor read answers like a missing one. Grants follow a RENAME and are inherited by child mailboxes created inside a shared one. Identifiers are accounts on the server only: no `anyone`, no negative rights; `p` is recorded but unused. Flags, including `\Seen`, are shared by everyone with access. METADATA, NOTIFY and REPLACE work within the user's own account only. |
| RFC 2971 | `ID` | 100% | Includes strict argument and size validation. |
| RFC 4315 | `UIDPLUS` | 100% | `APPENDUID`, `COPYUID`, and `UID EXPUNGE` are implemented. |
| RFC 3502 | `MULTIAPPEND` | 100% | Streamed literal and CATENATE messages publish atomically with ordered `APPENDUID` sets and rollback on any failure. |
| RFC 5161 | `ENABLE` | 100% | Enabled features are tracked per session and validated. |
| RFC 5256 | `SORT` and `THREAD` | 90% | Advertised algorithms are implemented; international collation coverage is not exhaustive. |
| RFC 4731 | `ESEARCH` | 95% | Core and UID result forms are implemented; no external conformance certification. |
| RFC 5182 | `SEARCHRES` | 100% | Saved search results and `$` sequence-set use are implemented. |
| RFC 9394 | `PARTIAL` | 100% | `SEARCH`/`UID SEARCH RETURN (PARTIAL first:last)` pages ESEARCH results, counting from the end for negative ranges and answering `NIL` for a page past the results; it combines with `MIN`/`MAX`/`COUNT` and saves `$` as RFC 9394 Table 1 specifies. The `UID FETCH` `PARTIAL` modifier picks the page before `CHANGEDSINCE` filters it. |
| RFC 5032 | `WITHIN` | 100% | `OLDER` and `YOUNGER` search keys are implemented. |
| RFC 5258 | `LIST-EXTENDED` | 95% | Selection/return options and hierarchy attributes are implemented; exotic namespace combinations are not applicable. |
| RFC 5819 | `LIST-STATUS` | 100% | STATUS return data is supported in extended LIST responses. |
| RFC 6154 | `SPECIAL-USE` and `CREATE-SPECIAL-USE` | 100% | Discovery, requested special-use mailbox attributes, and CREATE with `USE` are implemented. |
| RFC 7162 | `CONDSTORE` and `QRESYNC` | 90% | Mod-sequences, `CHANGEDSINCE`, `UNCHANGEDSINCE`, `VANISHED`, QRESYNC SELECT, implicit CONDSTORE enabling, and UID/MODSEQ in every untagged FETCH are implemented; no multi-server replication validation. |
| RFC 6851 | `MOVE` | 100% | Sequence and UID forms include UIDPLUS response data. |
| RFC 6855 | `UTF8=ACCEPT` | 85% | UTF-8 mailbox/message operation is implemented; `UTF8=ONLY` is not advertised or implemented. |
| RFC 3516 | `BINARY` | 95% | Binary FETCH sections and sizes are implemented; exhaustive MIME corpus validation remains. |
| RFC 4466 | Collected extension grammar | 95% | Extension argument/response forms used by advertised capabilities are implemented. |
| RFC 4469 | `CATENATE` | 100% | Streaming `TEXT`, relative same-session message/section `URL`, URL literals, `BADURL`, `TOOBIG`, and `APPENDUID` are implemented. |
| RFC 8970 | `PREVIEW` | 100% | MIME-aware UTF-8 previews and the `LAZY` priority modifier are implemented with bounded output. |
| RFC 9208 | `QUOTA` | 95% | `QUOTA=RES-STORAGE`, account-wide STORAGE limits, GETQUOTA/GETQUOTAROOT, `STATUS DELETED-STORAGE`, atomic APPEND/COPY and SMTP enforcement, and `OVERQUOTA` are implemented; unlimited accounts have no quota root. Users cannot change limits, so `QUOTASET` is not offered. |
| RFC 3348 | `CHILDREN` | 100% | `\HasChildren`/`\HasNoChildren` are returned in LIST responses. |
| RFC 3691 | `UNSELECT` | 100% | Closes the mailbox without expunging. |
| RFC 8438 | `STATUS=SIZE` | 100% | `STATUS (SIZE)` returns the mailbox size in octets. |
| RFC 8514 | `SAVEDATE` | 100% | `FETCH SAVEDATE` and the `SAVEDBEFORE`, `SAVEDON`, `SAVEDSINCE` and `SAVEDATESUPPORTED` search keys use the time the message was stored. |
| RFC 5957 | `SORT=DISPLAY` | 100% | `DISPLAYFROM` and `DISPLAYTO` sort on the display name, or the address when there is none. |
| RFC 9590 | `LIST-METADATA` | 100% | `LIST ... RETURN (METADATA (...))` follows each mailbox with its requested entries, NIL when unset. |
| RFC 9585 | `INPROGRESS` | 90% | SEARCH, SORT, THREAD, STORE, COPY and MOVE send keepalives every 10 seconds; progress is not counted (both details NIL, which the RFC allows). |
| RFC 9738 | `MESSAGELIMIT` (Experimental) | 90% | Opt-in with `security.imap_message_limit`. FETCH, STORE, SEARCH, MOVE and UID EXPUNGE handle the newest messages and name where to continue; COPY, MULTIAPPEND and oversized PARTIAL pages are refused. `SAVELIMIT` is not offered. |
| draft-ietf-extra-imap-thread-refs | `THREAD=REFS` | 90% | Implemented alongside `ORDEREDSUBJECT` and `REFERENCES`; tracks a draft, not a published RFC. |
| RFC 2088 / RFC 7888 | `LITERAL+` / `LITERAL-` | 100% | Synchronizing and bounded non-synchronizing literals are implemented. |
| RFC 4978 | `COMPRESS=DEFLATE` | 100% | Compression negotiation and post-negotiation command transport are implemented. |
| RFC 4959 | SASL initial response | 100% | Initial, empty, continuation, and cancellation responses are supported. |
| RFC 4616 | SASL `PLAIN` | 100% | Available only under the configured encrypted-transport policy. |
| RFC 5802 / RFC 7677 | `SCRAM-SHA-256` | 100% | Includes stored SCRAM credentials, verifier checks, `y`-flag downgrade detection, and fake challenges for unknown users. |
| RFC 5929 / RFC 9266 | `SCRAM-SHA-256-PLUS` channel binding | 100% | Supports `tls-server-end-point`, and `tls-exporter` on TLS 1.3. |
| RFC 4013 | SASLprep | 100% | Usernames and SCRAM passwords are prepared with full SASLprep (mapping, NFKC, prohibited characters, bidi checks). |
| RFC 7889 | `APPENDLIMIT` | 100% | The server-wide APPEND size limit is advertised. |
| RFC 8474 | `OBJECTID` | 95% | Permanent `MAILBOXID` (kept across RENAME) and `EMAILID` (kept across COPY and MOVE) come from random IDs stored in the index, never reused. They are reported by CREATE, SELECT/EXAMINE, STATUS, LIST-STATUS and FETCH, and `SEARCH EMAILID` works. `THREADID` is the email's JMAP thread (Message-ID, In-Reply-To and References), the same ID JMAP clients see; `SEARCH THREADID` works in SEARCH but matches nothing inside SORT and THREAD. |
| RFC 5464 | `METADATA` | 90% | `GETMETADATA` (with `MAXSIZE`/`LONGENTRIES` and `DEPTH`) and atomic `SETMETADATA` for server (`""`) and mailbox entries under `/private` and `/shared`. Entries are stored in the account index, follow a mailbox across RENAME and are removed with it. Limits: 64 KiB per value (`MAXSIZE`) and 512 entries per account (`TOOMANY`); `/shared/admin` is read-only. Values must be UTF-8 text (no `literal8`); unsolicited METADATA change notifications are sent only through `NOTIFY`. |
| RFC 5465 | `NOTIFY` | 85% | `NOTIFY SET [STATUS]` and `NOTIFY NONE` with the `SELECTED`, `SELECTED-DELAYED`, `INBOXES`, `PERSONAL`, `SUBSCRIBED`, `SUBTREE` and `MAILBOXES` filters. Events: `MessageNew` (with fetch attributes for the selected mailbox), `MessageExpunge`, `FlagChange`, `MailboxName`, `SubscriptionChange`, `MailboxMetadataChange` and `ServerMetadataChange`; `AnnotationChange` is refused with `BADEVENT`. Changes are found by polling storage between commands and during IDLE (every second for the selected mailbox, every two seconds for the others), so they arrive with that delay; the session's own changes are reported too. More than 1000 changes in one scan end notifications with `NOTIFICATIONOVERFLOW`. |
| RFC 9586 | `UIDONLY` | 100% | After `ENABLE UIDONLY`, FETCH, STORE, SEARCH, SORT, THREAD, COPY and MOVE, a sequence-set search key in the UID forms, and the QRESYNC message sequence match data are refused with `BAD [UIDREQUIRED]`. Message data goes out as `UIDFETCH` and expunges as `VANISHED` in command responses, unsolicited updates, IDLE and NOTIFY; SELECT leaves out the sequence-numbered `UNSEEN` code. |
| RFC 5267 | `ESORT`, `CONTEXT=SEARCH` and `CONTEXT=SORT` | 90% | `SORT`/`UID SORT RETURN (...)` answers with ESEARCH in sort order (`MIN`/`MAX` are the first and last sorted results; `SAVE` works as for SEARCH). `CONTEXT` (a hint) and `UPDATE` are accepted by SEARCH and SORT, and SORT also takes RFC 9394 `PARTIAL` (paging by sort position); `CANCELUPDATE` ends updates. Updating contexts send `ADDTO`/`REMOVEFROM` (with context positions for SORT, position 0 for SEARCH) whenever the session's view changes: its own STORE/EXPUNGE/MOVE, synchronization before commands, IDLE and NOTIFY. `REMOVEFROM` precedes the causing `EXPUNGE` and `ADDTO` follows `EXISTS`. Message numbers and `$` in the search program are resolved when the command runs. Up to 16 contexts per session (then `NO [NOUPDATE]`); they end when the mailbox is deselected. Time-relative keys (`YOUNGER`, `OLDER`) are re-evaluated only when a message changes, and other sessions' changes are seen only when the session synchronizes (between commands, during IDLE, or on NOTIFY polls). |
| RFC 8437 | `UNAUTHENTICATE` | 100% | Returns the session to the not-authenticated state while keeping TLS and compression. |
| RFC 8508 | `REPLACE` | 95% | `REPLACE` and `UID REPLACE` store the new message and expunge the old one in one index transaction, so a failed append leaves the old message in place. The message takes the same forms as APPEND (flags, date-time, synchronizing and non-synchronizing literals, `literal8`/UTF8, `CATENATE`, `APPENDLIMIT`/`TOOBIG`). Replies follow MOVE: `OK [APPENDUID]`, `EXISTS` when the target is the selected mailbox, then `EXPUNGE` or `VANISHED` (QRESYNC). A missing target gets `TRYCREATE`, a read-only mailbox `READ-ONLY`. The UTF8 data item uses the same framing as APPEND (closing parenthesis on the command line). |

IMAP4rev2 is dual-advertised with IMAP4rev1 for compatibility; clients enable
rev2 UTF-8 behavior with `ENABLE IMAP4rev2`. OAuth mechanisms can be enabled
with a configured token-introspection authority. The
deprecated draft `SNIPPET=FUZZY` dialect is available as a compatibility alias
for RFC 8970 previews. RFC 3502 `MULTIAPPEND` provides atomic streamed batch appends and
ordered `APPENDUID` sets. RFC 8970 `PREVIEW`, including its `LAZY` priority
modifier, is supported.

## JMAP standards support

Webmail serves JMAP next to its own API, on the same listener: the session resource at
`/.well-known/jmap`, requests at `/jmap/api/`. Clients sign in with HTTP Basic (the account
address and password) or, with OAuth introspection configured, a Bearer token. The suggested DNS
records include `_jmap._tcp` for discovery.

| RFC | Feature | Estimated compliance | Remaining limitation |
| --- | --- | ---: | --- |
| RFC 8620 | JMAP core | 90% | Session resource, `Core/echo`, result references (with `*`), creation ids across calls, request and method errors, blob upload and download, and push over an event source (with `ping` and `closeafter`). State strings come from a per-account change log, so `/changes` sees every change, whatever made it (IMAP, delivery, webmail, Sieve). `/queryChanges` always answers `cannotCalculateChanges` and clients query again. Push subscriptions (`PushSubscription`, web push) and `Blob/copy` are not implemented. Destroyed objects are remembered for 60 days; older states must resynchronize. |
| RFC 8621 | JMAP mail and submission | 90% | `Mailbox`, `Email`, `Thread`, `SearchSnippet`, `Identity` and `EmailSubmission` with their `get`, `changes`, `query` and `set` methods, plus `Email/import`, `Email/copy` and `Email/parse`. Emails with one EMAILID in several folders are one Email, keywords are the IMAP flags, threads follow Message-ID, In-Reply-To and References. Mail is sent at once through the submission service (`maxDelayedSend` 0, so nothing can be cancelled); delivery status is what that service reports, not later DSNs. `VacationResponse` (RFC 8621 section 8) is answered at delivery next to the account's own Sieve script, with Sieve vacation's rules (one reply per sender per week, none to lists or automated mail). Mailbox `sortOrder` follows the role and is not stored. Shared mailboxes (RFC 4314 grants) appear as one more account per owner, limited to the user's rights. |

Repeatable storage and queue performance workloads are documented in
[docs/PERFORMANCE.md](docs/PERFORMANCE.md); `rmail_bench` provides live IMAP, SMTP, BDAT, IDLE,
and outbound queue-drain workloads.

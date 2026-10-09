# Deployment Guide

This document covers:

- installing `rmail_*` daemons as systemd services on Ubuntu 24.04 or newer
- building a `.deb` package from this repository, even if your development host is not Debian-based

## Overview

The daemons are:

- `rmail_smtpd`: inbound SMTP
- `rmail_imapd`: IMAP
- `rmail_web`: admin/status web UI
- `rmail_webmail`: user-facing mailbox webmail UI
- `rmail_outbound`: outbound queue worker
- `rmail_classifier`: optional folder suggestions from local or hosted models (see [Mail organization](#mail-organization))

Administrative tools:

- `rmail_ctl`: mailbox/password/cert/service management CLI
- `rmail_queuectl`: queue and alias management CLI

The runtime model is:

- `/etc/rmail/config.toml` names `mail_root` and `db_path`; every other setting lives in that
  database and is edited in the admin console or with `rmail_ctl settings`
- service environment lives in `/etc/default/rmail`
- mail and queue state live under `/var/lib/rmail`
- logs can be read from `journalctl`; the units also allow `/var/log/rmail` if you later add file logging

## Manual Install On Ubuntu 24.04+

### 1. Build the binaries

From the repository root:

```bash
cargo build --release
```

### 2. Create the service user and directories

```bash
sudo addgroup --system rmail
sudo adduser --system --ingroup rmail --home /var/lib/rmail --no-create-home --disabled-login rmail
sudo install -d -o rmail -g rmail /var/lib/rmail /var/log/rmail /etc/rmail
```

### 3. Install binaries

```bash
sudo install -m 0755 target/release/rmail_smtpd /usr/bin/rmail_smtpd
sudo install -m 0755 target/release/rmail_imapd /usr/bin/rmail_imapd
sudo install -m 0755 target/release/rmail_web /usr/bin/rmail_web
sudo install -m 0755 target/release/rmail_webmail /usr/bin/rmail_webmail
sudo install -m 0755 target/release/rmail_outbound /usr/bin/rmail_outbound
sudo install -m 0755 target/release/rmail_classifier /usr/bin/rmail_classifier
sudo install -m 0755 target/release/rmail_ctl /usr/bin/rmail_ctl
sudo install -m 0755 target/release/rmail_queuectl /usr/bin/rmail_queuectl
```

### 4. Install config and environment files

```bash
sudo install -m 0644 config/example.toml /etc/rmail/config.toml
sudo install -m 0644 packaging/systemd/rmail.env /etc/default/rmail
```

Then:

- check `mail_root` and `db_path` in `/etc/rmail/config.toml` (the only two keys it holds)
- set `RMAIL_CONFIG=/etc/rmail/config.toml` and `RMAIL_MAIL_ROOT` (the same directory as
  `mail_root`) in `/etc/default/rmail`
- create the database with `rmail_ctl init-db`, then store the rest, for example:

```bash
rmail_ctl settings set global.hostname mail.example.com
rmail_ctl settings set global.listeners.smtp '["[::]:25"]'
rmail_ctl settings set global.listeners.submission '["[::]:587"]'
rmail_ctl settings set global.listeners.imaps '["[::]:993"]'
rmail_ctl settings set global.tls_cert /etc/rmail/tls/fullchain.pem
rmail_ctl settings set global.tls_key /etc/rmail/tls/privkey.pem
rmail_ctl settings list      # every setting with its default
```

  or open the admin console on its loopback address and use the **Settings** page.

Important:

- `rmail_outbound` reads `RMAIL_MAIL_ROOT` for spool placement and, when `RMAIL_CONFIG` is set,
  reads the shared tracking-retention policy from the configuration
- `rmail_web` binds to `127.0.0.1` by default and refuses non-loopback addresses until admin
  credentials exist
- port 25 listeners use MTA policy; port 587 and implicit-TLS port 465 use submission policy
- submission requires TLS, authentication, and an envelope sender matching the authenticated mailbox
- optional `global.listeners.lmtp` endpoints provide RFC 2033 local delivery; bind them only to
  loopback or a private service network because LMTP deliberately has no authentication or relay

Mail-protocol resource limits are the `security.*` settings:

- `imap_max_concurrent_sessions` — process-wide concurrent IMAP/IMAPS sessions (default: `1000`)
- `imap_max_connections_per_minute` — accepted IMAP/IMAPS connections per source IP in a rolling minute (default: `60`)
- `imap_max_commands_per_minute` — per-session rolling IMAP command limit (default: `300`)

- `smtp_max_concurrent_sessions` — process-wide concurrent SMTP sessions (default: `1000`)
- `smtp_max_connections_per_minute` — accepted TCP connections per source IP in a rolling minute (default: `60`)
- `smtp_max_commands_per_minute` — per-session rolling command limit (default: `120`)
- `smtp_max_recipients` — recipients per port-25 transaction (default: `100`)
- `submission_max_recipients` — recipients per authenticated submission transaction (default: `50`)
- `submission_max_messages_per_minute` — accepted messages per authenticated account in a rolling minute (default: `30`)
- `submission_require_from_alignment` — when `true`, every parsed RFC 5322 `From` mailbox on authenticated submission must equal the authenticated mailbox; missing, malformed, or mismatched author fields are rejected (default: `false`)
- `admin_password_policy` — rules for the admin console password, applied when it is set or changed: `min_length` (default `10`), `max_length` (`128`), `require_lowercase`, `require_uppercase`, `require_digit`, `require_symbol` (all `false`) and `forbid_username` (`true`). Also editable in the console under Settings → Authentication.

OAuth bearer authentication uses an RFC 7662 token-introspection authority configured under
`[security.oauth]`. The endpoint must use HTTPS unless `allow_insecure_http = true` is explicitly
set for a trusted development environment. Configure `client_id` and `client_secret` together,
select the claim (`username`, `sub`, or `email`) that contains the local mailbox address, and use
`required_scopes`, `issuer`, and `audience` to constrain accepted tokens. Client secrets and access
tokens are redacted from diagnostics. Adding `OAUTHBEARER` or `XOAUTH2` to an IMAP or SMTP SASL
mechanism list without valid OAuth settings is a startup error.

## Delivery routes and smarthost

Outbound mail goes to each recipient domain's MX hosts unless a delivery route says otherwise.
Routes are stored in the database and managed on the console's **Routing** page or with
`rmail_ctl transport`:

```bash
# Send everything through a provider's submission port (a smarthost).
rmail_ctl transport relay '*' smtp.provider.example:587 --user relay@example.com
# A route for one domain wins over '*'; --implicit-tls uses TLS from the first byte (465).
rmail_ctl transport relay partner.example mx.partner.example:25
# Refuse a domain: 5xx bounces at once, 4xx keeps the message queued.
rmail_ctl transport reject old.example "550 5.1.2 This domain no longer accepts mail"
rmail_ctl transport list
```

Relay credentials are sent with AUTH PLAIN and only over TLS; a relay that offers no TLS is not
used. MTA-STS and DANE apply to MX delivery only, while REQUIRETLS messages still need TLS to the
relay.

## Forwarding and SRS

Aliases, catchalls and Sieve `redirect` that point at other servers forward mail with ARC sealing.
The next hop still checks SPF against the original envelope sender, which fails for most senders.
Set an SRS domain to rewrite that sender (Sender Rewriting Scheme):

```bash
rmail_ctl settings set security.srs_domain fwd.example.com
```

Forwarded mail then leaves with a sender like `SRS0=HHHH=TT=example.org=alice@fwd.example.com`,
and bounces to it within 21 days go back to `alice@example.org`. The SRS domain needs an MX
pointing at this server and an SPF record that authorizes it (for example `v=spf1 mx -all`).
Senders in hosted domains and null senders are not rewritten. The signing key is generated on
first start and kept in the settings database.

## LMTP local delivery

LMTP is disabled by default. Enable a TCP endpoint with, for example,
`rmail_ctl settings set global.listeners.lmtp '["127.0.0.1:24"]'`. The service requires `LHLO`, rejects SMTP
`HELO`/`EHLO`, does not offer `AUTH` or `STARTTLS`, and never queues remote delivery. Exact local
mailboxes, local catchalls, and aliases resolving to one local mailbox are accepted. Multi-target
or remote aliases are rejected during `RCPT` to prevent partial delivery and duplicate mail when an
upstream retries.

After `DATA` or the final `BDAT`, rMail returns one enhanced-status reply for every accepted `RCPT`.
This allows one mailbox to succeed while another reports a temporary condition such as quota
exhaustion. LMTP deliveries use the same scanners, indexed Maildir publication, quota enforcement,
tracking, and graceful shutdown as SMTP delivery.

## DKIM signing and inbound authentication

Inbound SMTP verifies SPF, DKIM, DMARC, and ARC with the system asynchronous DNS resolver. DNS
failures remain authentication temporary errors and do not turn into DMARC policy rejections.

Outbound messages are signed immediately before their atomic queue publication, with the keys
stored in the database. Create them with `rmail_ctl dkim` (or the admin console's **DKIM** page),
which prints the TXT record to publish:

```bash
rmail_ctl dkim add example.com mail2026                       # 2048-bit RSA
rmail_ctl dkim add example.com ed2026 --algorithm ed25519     # optional, RFC 8463
rmail_ctl dkim add example.com old --private-key key.pem      # import an existing key
rmail_ctl dkim list
```

Every key of a sender domain signs its mail, so RSA and Ed25519 signatures go out side by side;
keep an RSA key, since many verifiers still ignore Ed25519. Signatures cover From, To, Subject,
Date, Message-ID, MIME-Version and Content-Type. A domain without keys is sent unsigned; a key that
fails to sign stops the message from entering the queue.

`rmail_ctl dkim set-arc example.com mail2026` makes an RSA key the ARC identity. rMail then verifies
the incoming ARC chain of mail it forwards to remote targets (aliases, catchalls and Sieve
redirects) and adds an ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal set. A
chain with invalid continuity is forwarded unchanged rather than being extended with a misleading
local seal. `rmail_ctl dkim clear-arc` turns sealing off.

Optional outbound-worker tuning in `/etc/default/rmail`:

- `RMAIL_OUTBOUND_CONCURRENCY` — maximum simultaneous delivery tasks (default: `20`)
- `RMAIL_PER_DEST_LIMIT` — maximum simultaneous deliveries for one recipient domain (default: `5`)
- `RMAIL_IDLE_CONNECTIONS_PER_DEST` — reusable idle SMTP sessions retained for one MX host (default: `2`)
- `RMAIL_MAX_IDLE_CONNECTIONS` — total reusable idle SMTP sessions (default: outbound concurrency)

SQLite access uses shared, path-keyed connection pools. Each database is limited to eight open
connections with a five-second acquisition/busy timeout. Idle connections are retired after five
minutes; inactive database pools are evicted after fifteen minutes, and at most 1,024 mailbox
database pools are retained. This bounds file descriptors and prevents concurrent IMAP, SMTP, and
admin requests from creating a new connection for every command.

## Account storage quotas

Storage quotas are optional and account-wide across every IMAP folder. Configure them from the
admin portal's Accounts page or while provisioning from the CLI:

```bash
rmail_ctl add-mailbox user@example.com --quota-mib 10240
```

Use `--quota-mib 0` to remove an existing limit. Quota admission and message-index publication
share one immediate SQLite transaction, so concurrent SMTP deliveries and IMAP APPEND/COPY
operations cannot overrun a limit through a check-then-write race. SMTP reports `452 4.2.2` and
IMAP reports `[OVERQUOTA]`; IMAP clients can inspect usage with GETQUOTA/GETQUOTAROOT. MOVE does
not consume additional quota.

## Live SMTP watch and message tracking

`rmail_smtpd` and `rmail_outbound` publish protocol events over Unix datagram sockets beneath the
mail root. Events are also stored in `_tracking/events.sqlite`; watch mode consumes the IPC feed
directly and does not tail text logs.

The outbound worker, IMAP, SMTP/LMTP, admin web, and webmail services write one JSON object per
operational log event. Every record includes
`timestamp_unix_ms`, `level`, `component`, `event`, and a `fields` object. Delivery-related records
include stable `connection_id` and `message_id` fields where available, so operators can filter and
join events without parsing human-readable messages. IMAP events separately expose peer, transport,
command, tag, and session-state context while redacting authentication payloads. SMTP session events
include the same connection IDs used by live tracking, plus message IDs when a transaction has one;
low-frequency subsystem diagnostics retain their original message under a structured `message` field.
HTTP completion events expose a request ID, peer, method, path, status, and response size.

```bash
sudo rmail_ctl watch
sudo rmail_ctl watch --plain
sudo rmail_ctl track message-19abc123
```

The full-screen SSH-friendly view shows active inbound/outbound connections, reverse-DNS names,
SMTP phases and commands, reply codes, message IDs, and cumulative RX/TX bytes. `--plain` provides
a streaming format for pipes and minimal terminals. AUTH payloads and message bodies are not
recorded.

Durable history is bounded through the `global.tracking.*` settings: `retention_days` and `max_events` set the
age and count limits, while `prune_interval_seconds` and `prune_batch_size` control incremental
cleanup. Setting either retention limit to zero disables that individual limit.

Outbound transport security:

- rMail advertises and relays RFC 8689 `REQUIRETLS`; such messages are never sent over plaintext, and the next hop must advertise `REQUIRETLS`
- rMail advertises RFC 3461 `DSN`, validates `ENVID`, `RET`, `NOTIFY`, and `ORCPT`, preserves those parameters through aliases and the private queue, and relays them to DSN-capable next hops. Requested success, delayed-delivery, and terminal-failure notifications use a null reverse path and `multipart/report; report-type=delivery-status`; `NOTIFY=NEVER` suppresses local bounces.
- MTA-STS policies are discovered through `_mta-sts.<domain>` TXT records, fetched over authenticated HTTPS, cached for `max_age`, and enforced against MX names and TLS certificate validation
- TLS failures are reported to valid `mailto:` destinations in `_smtp._tls.<domain>` RFC 8460 records as daily gzipped JSON (`application/tlsrpt+gzip`); reports themselves use a null reverse path to prevent loops

TLS policy is configured once with the `global.tls.*` settings. `minimum_version` accepts
`"1.2"` (the default, enabling TLS 1.2 and 1.3) or `"1.3"`. `cipher_suites` may be left empty for
Rustls safe defaults or set to an allow-list of Rustls cipher-suite names. Unknown suites, a suite
set incompatible with the selected protocol versions, partial cert/key configuration, and invalid
replacement certificates fail validation.

Set `ocsp_response` to a DER-encoded OCSP response file to staple it on every TLS service. The file
must be non-empty and no larger than 1 MiB. SMTP, IMAP, admin web, and webmail load the same
certificate, private key, policy, and optional OCSP response.

When `tls_cert` and `tls_key` are configured, SMTP, IMAP, admin web, and webmail share those
credentials and the web services serve HTTPS. Set `web_http_only = true` when a reverse proxy
terminates TLS; this affects only admin web and webmail and leaves mail-protocol TLS enabled.
Without configured credentials, admin web and webmail serve HTTPS with a self-signed certificate that
is generated once and kept in `<mail_root>/tls/selfsigned.pem` (browsers will warn); configure
`tls_cert`/`tls_key` or automatic certificates to replace it. SMTP and IMAP stay without TLS.

Each TLS daemon reloads its certificate when the certificate, key or OCSP file changes on disk
(checked every 30 seconds, after the files have stopped changing) and on SIGHUP
(`systemctl reload rmail_smtpd rmail_imapd rmail_web rmail_webmail`). The replacement certificate,
private key, version policy, and cipher policy are parsed and validated before the context used by
new connections is swapped atomically. Existing TLS sessions continue uninterrupted; a failed reload
keeps the previous context. Validation also requires a configured OCSP response to remain readable
and structurally usable. An external ACME client therefore only needs to replace the files.

### Automatic certificates (ACME / Let's Encrypt)

rMail requests and renews certificates itself; no certbot or other ACME client is needed. Configure
it on the admin console's **Certificates** page, or with `rmail_ctl settings set acme.<key> ...`
(settings database required). Changes apply to the next request without a restart.

- `acme.domains` lists the certificate names (empty uses `global.hostname`); `acme.email` is the
  optional account contact.
- `acme.ca` is `letsencrypt` (default), `letsencrypt-staging`, `zerossl` (needs `acme.eab_kid` and
  `acme.eab_hmac_key`), or `custom` with `acme.directory_url` (for example step-ca).
- `acme.challenge = "http-01"` needs the names to reach this server on port 80. Add
  `global.listeners.http = ["[::]:80"]`: `rmail_web` then answers challenges there and redirects every
  other request to HTTPS (to `global.http_redirect_url` when set, otherwise the requested host). The
  packaged unit grants `rmail_web` `CAP_NET_BIND_SERVICE` for this. If another web server owns port 80,
  forward `/.well-known/acme-challenge/` to the admin listener instead, which answers the same paths.
- `acme.challenge = "dns-01"` publishes `_acme-challenge` TXT records through `acme.dns.provider`:
  `cloudflare` (API token with Zone:Read and DNS:Edit), `digitalocean`, `desec`, `gandi` (personal
  access token) — all via `acme.dns.api_token` — `route53` (`acme.dns.aws_access_key_id` /
  `aws_secret_access_key`, allowed `route53:ListHostedZonesByName` and
  `route53:ChangeResourceRecordSets`), or `rfc2136` (`acme.dns.rfc2136_server`, `tsig_key_name`,
  base64 `tsig_secret`, `tsig_algorithm`) for BIND, PowerDNS, Knot and other servers accepting dynamic
  updates. The zone is found from DNS unless `acme.dns.zone` is set. Before asking the CA to validate,
  rMail waits (up to `acme.dns.propagation_timeout_seconds`) until every authoritative name server
  serves the records. DNS validation is required for wildcard names.

The certificate is written with atomic renames to `global.tls_cert` / `global.tls_key`. When those are
unset, it goes to `<mail_root>/tls/fullchain.pem` and `privkey.pem` (key mode 0600) and the settings
are pointed there automatically. The services need one restart to start serving TLS: the Certificates
page offers a **Restart** button once the settings change, and `rmail_ctl acme issue` asks interactively.
Later renewals are picked up by the file watch above. The key is ECDSA P-256. OCSP stapling (`global.tls.ocsp_response`) cannot
be combined with ACME certificates.

The services run sandboxed and can only write under their mail root, so certificates live in
`<mail_root>/tls` by default. If `global.tls_cert`/`global.tls_key` point somewhere rMail cannot write
(for example a leftover certbot path under `/etc/letsencrypt`), issuing installs into `<mail_root>/tls`
instead and points both settings there; the old certificate keeps serving until the services are
restarted once. To keep a custom directory, add `ReadWritePaths=<dir>` to `rmail_web.service` with a
drop-in and make the directory writable by the `rmail` user. The directory is checked before the CA is
asked for a certificate, so a failure never wastes an issuance.

`rmail_web` checks hourly and renews when the CA's ACME Renewal Information (RFC 9773) window opens,
or after two thirds of the certificate's lifetime when the CA offers none; renewal orders name the
certificate they replace. Failed attempts are retried after one hour, doubling up to a day. Account
keys, pending challenges and the last run's log live in the settings database, so the Certificates
page and `rmail_ctl acme status` show exactly what happened.

- `rmail_ctl acme issue` requests a certificate now (`--test` issues from Let's Encrypt staging and
  installs nothing). When run as root, installed files are handed to the owner of their directory.
- `rmail_ctl acme renew` renews only if due; `rmail_ctl acme status` shows the certificate and last run.

Health probes are exposed by `rmail_web` without authentication so an orchestrator can use them:

- `GET /healthz` (also `/health`) is a process-liveness check and returns `200` while the HTTP service is responsive.
- `GET /readyz` (also `/ready`) returns JSON and `200` only when every configured dependency is ready. It verifies queue writability, SQLite access, asynchronous DNS resolution, the complete TLS certificate/key/policy/OCSP bundle, and connectivity to enabled ClamAV and Rspamd services. Unconfigured optional dependencies are reported as `skipped`; failures return `503` with per-component details.

The web listener binds to loopback by default. If it is exposed on a public address, restrict these
probe paths at the reverse proxy or firewall because readiness details are intentionally useful to
operators.

The admin console uses dedicated browser routes for its main operating areas: `/` (overview),
`/accounts`, `/routing`, `/delivery`, `/settings`, `/certificates`, `/observability`, and `/system`. These routes are
served through the same single-page frontend, so a reverse proxy should pass unknown non-API paths to
`rmail_web` rather than returning its own 404 page.

### Settings and admin access

The configuration file only bootstraps `mail_root` and `db_path`. Every other setting lives in the
`settings` table of that database:

- Settings are edited on the console's **Settings** page or with
  `rmail_ctl settings list|get|set|unset`. Other keys left in the file are ignored, and each daemon
  logs their names at startup.
- Daemons read settings at startup and record the revision they loaded. The Settings and System
  pages show which services must be restarted (for example
  `rmail_ctl service restart --unit smtpd`) and which changed keys each one is waiting for.
- The Settings page's **Restart** button queues `<mail_root>/restart-request`; the root-owned
  `rmail_restart.path` unit (enabled by the package) runs `rmail_ctl service apply-request`, which
  restarts only the services waiting on saved changes. The packaged units watch `/opt/rmail/mail`;
  edit `rmail_restart.path` and `rmail_restart.service` if `mail_root` differs. Without the unit the
  page shows the `rmail_ctl service restart` command instead.
- Secrets (admin password hash, OAuth client secret, session signing keys) are stored in the same
  database and are never returned by the API.

Admin access uses a session cookie after signing in on the console; `/metrics` and the JSON API also
accept HTTP Basic authentication for scripts and Prometheus. State-changing API requests must send an
`X-Rmail-Admin: 1` header (CSRF protection). Repeated failed sign-ins lock the client out for 30
minutes.

Set the admin credentials with `rmail_ctl admin-password` (or on the System page). Without
credentials, `rmail_web` refuses to listen on non-loopback addresses; on loopback it starts in
first-run setup mode, where the first visitor creates the admin account.

Prometheus metrics are available from authenticated `GET /metrics`. Each daemon publishes an
atomic snapshot every 15 seconds, and the web service aggregates them with a bounded `component`
label (`smtpd`, `outbound`, `imapd`, or `web`). In addition to counters, rMail exports cumulative
histograms for:

- `rmail_dns_duration_seconds`
- `rmail_tls_handshake_duration_seconds`
- `rmail_scanner_duration_seconds`
- `rmail_queue_delay_seconds`
- `rmail_imap_command_duration_seconds`
- `rmail_database_wait_duration_seconds`

SMTP reply counts are exported as `rmail_smtp_responses_total` with bounded `direction` and `code`
labels. No hostname, address, mailbox, message ID, or command label is used in Prometheus metrics;
those high-cardinality details belong in message tracking instead.

### 5. Install systemd units

```bash
sudo install -m 0644 packaging/systemd/rmail_smtpd.service /usr/lib/systemd/system/rmail_smtpd.service
sudo install -m 0644 packaging/systemd/rmail_imapd.service /usr/lib/systemd/system/rmail_imapd.service
sudo install -m 0644 packaging/systemd/rmail_web.service /usr/lib/systemd/system/rmail_web.service
sudo install -m 0644 packaging/systemd/rmail_webmail.service /usr/lib/systemd/system/rmail_webmail.service
sudo install -m 0644 packaging/systemd/rmail_outbound.service /usr/lib/systemd/system/rmail_outbound.service
sudo install -m 0644 packaging/systemd/rmail_classifier.service /usr/lib/systemd/system/rmail_classifier.service
sudo systemctl daemon-reload
```

### 6. Enable and start services

```bash
sudo systemctl enable --now rmail_smtpd.service
sudo systemctl enable --now rmail_imapd.service
sudo systemctl enable --now rmail_web.service
sudo systemctl enable --now rmail_webmail.service
sudo systemctl enable --now rmail_outbound.service
sudo systemctl enable --now rmail_classifier.service   # optional
```

After the units are enabled, `rmail_ctl` can control the whole service set:

```bash
sudo rmail_ctl service start
sudo rmail_ctl service stop
sudo rmail_ctl service restart
sudo rmail_ctl service reload
sudo rmail_ctl service status
```

To operate on a subset, pass short names or full unit names:

```bash
sudo rmail_ctl service restart --unit smtpd --unit imapd
sudo rmail_ctl service stop --unit rmail_web.service
```

### 7. Verify

```bash
sudo rmail_ctl service status
journalctl -u rmail_smtpd.service -u rmail_imapd.service -u rmail_web.service -u rmail_webmail.service -u rmail_outbound.service -u rmail_classifier.service -n 200 --no-pager
```

## Webmail

`rmail_webmail` is the users' mail client: folders (create, rename, delete, nest with `/`), search,
paging, stars, move, archive, junk and delete (also in bulk), keyboard shortcuts, attachments
(downloaded under a sandbox; PNG, JPEG, GIF and WebP previewed inline), the raw source of any message
with its headers (**View source**, or download as `.eml`), light and dark themes, and a phone layout.
When mail organization is enabled with a fallback model, messages also offer **Summarize** and
**Suggest labels**.

### Sending

Compose, reply, reply all and forward (with attachments up to 10 MB in total) go through this
server's own submission service. Webmail does not hold users' passwords, so it signs in to submission
over loopback with SASL `X-RMAIL-WEBMAIL`, presenting a shared secret and acting as the signed-in user:

- The secret is `<mail_root>/run/webmail-submission.key`, created on first use with mode `0600`.
  Webmail and SMTP run as the same `rmail` user; no other local user can read it.
- `rmail_smtpd` accepts the mechanism only on the submission service and only from a loopback
  address, never advertises it, and counts failures towards the usual authentication lockout.
- After that the session is an ordinary authenticated submission for that user: the sender must be
  the user's own address, and rate limits, content scanning, DKIM signing and local, alias and
  remote routing all apply as for any mail client.
- Webmail needs a submission listener it can reach on loopback: a wildcard (`0.0.0.0:587`,
  `[::]:587`) or loopback address in `listeners.submission`. Without one, sending is off and webmail
  hides Compose. Restart webmail after changing the submission listeners.

A copy of each sent message (including Bcc) is saved to Sent; replies mark the original
`\Answered` and forwards `$Forwarded`. Drafts are saved to Drafts and can be reopened and sent.

## Mail organization

`rmail_classifier` suggests folders for new INBOX mail. It learns from how each user files their mail.
By default it runs small GGUF models in-process with llama.cpp: no external model server, and mail
never leaves the machine. Hosted providers are optional (see [Hosted providers](#hosted-providers)).
It never runs in the SMTP path; mail always lands in INBOX first.

1. On the admin console **Organization** page, download an embedding model (required) and, if you want,
   a chat model (optional fallback for uncertain messages). Models are stored in `<mail_root>/models`.
   Every download records its SHA-256. A model added by URL can require a specific checksum.
2. Click **Use** on each model and turn on **Enabled**. The console saves the `classifier.*` settings and
   tells the daemon to reload over its control socket (`<mail_root>/run/classifier.sock`), so no
   restart is needed. `systemctl reload rmail_classifier` does the same.
3. Users opt in from webmail (**Organize my mail**). Each opted-in account gets
   `Maildir/classifier.sqlite` next to its IMAP state. That file holds the learned examples,
   suggestions and preferences, and it only exists once the account opts in.
4. Use **Try it** on the Organization page to check an embedding and a chat answer and their timings.

How it decides:

- The daemon learns from messages in the user's own folders, excluding special-use folders (Sent,
  Drafts, Trash, Junk, Archive) and anything the user excludes. Mail filed from any IMAP client counts.
- New INBOX mail gets a suggestion when earlier mail from the same sender or list went to one folder,
  or when the embedding vote among similar filed messages is confident. Otherwise the chat model (if
  configured) picks from the user's folder list, and a grammar keeps it from inventing a folder.
- Suggestions show in webmail with Move and Dismiss buttons, and IMAP clients see the `$Suggested`
  keyword. A message is moved automatically only when the user turned on auto-move for that folder,
  the confidence is at least `classifier.autofile_confidence`, and the vote came from the user's own
  filing (never from the chat model alone).

### Labels

Users can also have new INBOX mail labeled automatically. This is a separate switch in
**Organize my mail**: it works without folder suggestions, and folder suggestions work without it.

- Turning it on seeds common labels (Action needed, Receipts, Shipping, Travel, Finance, Events,
  Security, Newsletters, Promotions, Notifications, Social, Work, Personal). The fallback model
  (local chat model, OpenRouter or Jev) then decides which labels apply to each new message. A label
  is applied when its probability reaches `classifier.label_confidence` (70% by default), with at
  most three labels per message.
- When no label fits, the local and OpenRouter chat models may create a new label: one to three
  words, with a short description, applied to that message and offered for later mail. Set
  `classifier.label_discovery` to `false` to turn this off. Jev only picks from existing labels; it
  gets one yes/no question per label in a single request.
- Each account has at most 30 labels, at most 15 of them created by the AI. A starter or AI label
  the user removes is never created again. Users can add their own labels and reword descriptions
  to steer the model; webmail marks the labels the AI created.
- Labels are stored as IMAP keywords, so IMAP clients that show keywords (Thunderbird, for example)
  see them too. Keywords must be ASCII atoms, so "Action needed" becomes `Action_needed` and
  letters such as "Ø" become `_`. Webmail always shows the label's name. Removing a label in webmail
  or any IMAP client removes the keyword.
- Labels need a fallback model. With a cloud fallback, every new INBOX message of a user who turned
  labels on goes to that provider, so the same per-user consent applies (see above).
- When a label has been applied to 10 or more messages and the user has no folder with that name,
  webmail suggests creating one, at the top level or inside an existing folder.

Resource notes: embedding models cost roughly 100–900 MB RAM and milliseconds per message on CPU.
Chat models (1–2 GB) take seconds per uncertain message. The unit runs at `Nice=10` with a reduced
CPU weight so inference yields to the mail daemons. Building `rmail_classifier` needs cmake and a C/C++
compiler. Build with `--no-default-features` to leave out llama.cpp (and with it the libgomp and C++
runtime dependencies); only hosted providers work then. For GPU inference, pass the `cuda`, `vulkan`
or `metal` feature.

### Hosted providers

Each model role can use a hosted provider instead of a local model, under **Providers** on the
Organization page (or the `classifier.*` settings):

| Role | Setting | Options |
| --- | --- | --- |
| Embeddings (required) | `classifier.embed_provider` | `local`, `openrouter` |
| Fallback for uncertain mail | `classifier.chat_provider` | `local`, `openrouter`, `jev` |

- **OpenRouter** (`classifier.openrouter_api_key`, `openrouter_embed_model`, `openrouter_chat_model`)
  uses the OpenAI-compatible `/embeddings` and `/chat/completions` APIs. `classifier.openrouter_base_url`
  can point at any compatible endpoint, such as a self-hosted vLLM or Ollama. Chat answers are
  constrained to the folder list with a JSON schema, and answers naming other folders are discarded.
- **Jev** (`classifier.typesafe_api_key`, `classifier.jev_model`) is TypeSafe's decision model. It
  gets one choice question whose options are the user's folders (described by example subjects) plus
  "none", and returns the chosen option with a confidence instead of generated text.

Hosted providers receive message text: the sender, subject and the first
`classifier.max_input_bytes` of the body. A cloud embedder receives every message learned or
classified, including the backfill when an account opts in. A cloud fallback receives only
messages the vote is unsure about. So mail only goes to a provider whose name the user saw and
agreed to in webmail's **Organize my mail** dialog:

- Consent is per account and per provider, and is stored in `classifier.sqlite`. Accounts that
  opted in before hosted providers were configured start without consent.
- Without consent, a cloud embedder skips the account entirely. With a cloud fallback, the account
  still gets sender and embedding suggestions from this server, without the fallback.
- Adding or switching to another provider requires consent again. Users can withdraw at any time.
- The Organization page shows how many opted-in mailboxes have agreed. API keys are never returned
  to the browser.

Suggestions from either fallback never move mail automatically, same as the local chat model.

## Notes On Privileged Ports

The service units use:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

That allows binding privileged ports like `25`, `143`, `465`, and `993` without running the daemons as root.

## Why There Are No `.socket` Units

Older packaging in this repository included systemd socket units, but the daemons do not currently implement socket activation. Shipping `.socket` units would be misleading and would not work correctly. If socket activation is wanted later, the daemons need explicit support for inherited listeners.

## Prebuilt Releases

Every merge to `main` runs CI and, when it passes, publishes packages for `amd64` and `arm64`
(`.deb`, a plain `.tar.gz` of the same payload, and `SHA256SUMS`) to two GitHub releases:

- `vX.Y.Z`: an immutable SemVer release, marked as the repository's latest release.
- `latest`: a rolling release that always points at the newest build, with version-less asset
  names such as `rmail_latest_amd64.deb`, so download URLs stay stable.

The `.deb` pulls in its runtime libraries. When installing from the `.tar.gz`, make sure
`rmail_classifier`'s are present too: the C++ runtime and OpenMP (`libstdc++6` and `libgomp1`
on Debian and Ubuntu, `libstdc++` and `libgomp` on Fedora and RHEL). Without libgomp the
classifier exits with `libgomp.so.1: cannot open shared object file`.

The version is the last `vX.Y.Z` tag plus a bump chosen from the merged PR:

- label `release:major`, `release:minor` or `release:patch`, otherwise
- the PR title: `feat!:` (or `BREAKING CHANGE`) is major, `feat:` is minor, anything else is patch.

Label a PR `release:skip`, or put `[skip release]` in the merge commit message, to merge without
releasing. To jump to a specific version, set it in the crates' `Cargo.toml` files with
`scripts/set-rust-version.sh`; a version ahead of the last tag is released as-is. A release can
also be started by hand from the Actions tab (Release workflow, "Run workflow").

## Building A Debian Package

This repository includes:

```text
packaging/debian/build-deb.sh
```

### 1. Ensure `dpkg-deb` is available

On Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y dpkg-dev
```

On Arch, install the Debian packaging toolchain:

```bash
sudo pacman -S dpkg
```

You also need a working Rust toolchain with `cargo`.

### 2. Build the package

```bash
./packaging/debian/build-deb.sh 0.1.0 amd64
```

That script now:

- runs `cargo build --release`
- assembles the package payload
- emits the final `.deb`

Optional third argument:

```bash
./packaging/debian/build-deb.sh 0.1.0 amd64 x86_64-unknown-linux-gnu
```

Use that if you want to package from a specific Cargo target directory.

That emits:

```text
target/debian/rmail_0.1.0_amd64.deb
```

### 3. Install on Ubuntu

```bash
sudo apt install ./target/debian/rmail_0.1.0_amd64.deb
```

Avoid installing a local `.deb` from `/root/...` with `apt install` if possible. Put it in a world-readable path like your normal home directory or `/tmp`, otherwise `apt` may warn that download/acquire ran unsandboxed because the `_apt` user cannot read the file.

Then check `/etc/default/rmail` and store the server's settings with `rmail_ctl settings set` (or
in the admin console); `/etc/rmail/config.toml` already points at `/opt/rmail`.

On first package install, the maintainer script will also try to:

- create the `rmail` system user/group if missing
- `enable` the four systemd services

After editing the config, start them:

```bash
sudo systemctl start rmail_smtpd.service
sudo systemctl start rmail_imapd.service
sudo systemctl start rmail_web.service
sudo systemctl start rmail_outbound.service
```

## Upgrading The Debian Package

If you installed `0.1.0` and build `0.2.0`, upgrade with:

```bash
sudo apt install ./target/debian/rmail_0.2.0_amd64.deb
```

or:

```bash
sudo dpkg -i ./target/debian/rmail_0.2.0_amd64.deb
```

`apt install ./...deb` is preferred on Ubuntu.

If you see:

```text
Download is performed unsandboxed as root as file '/root/...' couldn't be accessed by user '_apt'
```

that is not a package bug. It means the `.deb` file is stored somewhere `_apt` cannot read, typically `/root`. Move it to a readable path before installing, for example:

```bash
cp target/debian/rmail_0.2.0_amd64.deb /tmp/
sudo apt install /tmp/rmail_0.2.0_amd64.deb
```

The package now marks these as Debian conffiles:

- `/etc/rmail/config.toml`
- `/etc/default/rmail`

That means your local edits are preserved across upgrades unless you explicitly replace them.

On upgrades, the package does not auto-enable services again; it only does `enable` on the initial install path.

## Current Limits

- The generated `.deb` is simple and does not yet declare library/runtime dependencies beyond `systemd`.
- The package installs a sample config; you still need to provision real TLS certs, mailbox config, and any DNS/MX records yourself.

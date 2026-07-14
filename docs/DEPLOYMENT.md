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

Administrative tools:

- `rmail_ctl`: mailbox/password/cert/service management CLI
- `rmail_queuectl`: queue and alias management CLI

The runtime model is:

- configuration lives in `/etc/rmail/config.toml`
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
sudo install -m 0755 target/release/rmail_ctl /usr/bin/rmail_ctl
sudo install -m 0755 target/release/rmail_queuectl /usr/bin/rmail_queuectl
```

### 4. Install config and environment files

```bash
sudo install -m 0644 config/example.toml /etc/rmail/config.toml
sudo install -m 0644 packaging/systemd/rmail.env /etc/default/rmail
```

Then edit both files:

- set real domains, passwords, cert paths, and ports in `/etc/rmail/config.toml`
- set `RMAIL_CONFIG=/etc/rmail/config.toml` in `/etc/default/rmail`
- set `RMAIL_MAIL_ROOT=/var/lib/rmail` in `/etc/default/rmail`

Important:

- `rmail_outbound` reads `RMAIL_MAIL_ROOT` for spool placement and, when `RMAIL_CONFIG` is set,
  reads the shared tracking-retention policy from the TOML file
- `rmail_web` currently binds to `127.0.0.1` by default, which is a safer default for admin access
- port 25 listeners use MTA policy; port 587 and implicit-TLS port 465 use submission policy
- submission requires TLS, authentication, and an envelope sender matching the authenticated mailbox
- optional `global.listeners.lmtp` endpoints provide RFC 2033 local delivery; bind them only to
  loopback or a private service network because LMTP deliberately has no authentication or relay

Mail-protocol resource limits are configured in the `[security]` section:

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

OAuth bearer authentication uses an RFC 7662 token-introspection authority configured under
`[security.oauth]`. The endpoint must use HTTPS unless `allow_insecure_http = true` is explicitly
set for a trusted development environment. Configure `client_id` and `client_secret` together,
select the claim (`username`, `sub`, or `email`) that contains the local mailbox address, and use
`required_scopes`, `issuer`, and `audience` to constrain accepted tokens. Client secrets and access
tokens are redacted from diagnostics. Adding `OAUTHBEARER` or `XOAUTH2` to an IMAP or SMTP SASL
mechanism list without valid OAuth settings is a startup error.

## LMTP local delivery

LMTP is disabled by default. Enable a TCP endpoint with, for example,
`lmtp = ["127.0.0.1:24"]` under `[global.listeners]`. The service requires `LHLO`, rejects SMTP
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

Outbound messages are signed immediately before their atomic queue publication. Create
`<mail_root>/dkim.toml` with one or more sender-domain entries:

```toml
[[signer]]
domain = "example.com"
selector = "mail2026"
private_key = "/etc/rmail/dkim/example.com-mail2026.pem"
# Optional; these are the defaults.
headers = ["From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type"]

# Optional local ARC identity. This is used only for remote targets reached
# through a local alias or catchall, never for ordinary authenticated relay.
[arc_signer]
domain = "example.com"
selector = "mail2026"
private_key = "/etc/rmail/dkim/example.com-mail2026.pem"
headers = ["From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "DKIM-Signature"]
```

The private key may be PKCS#1 or PKCS#8 PEM and must have no group/other permission bits (for
example, mode `0600`). Publish the corresponding RSA public key at
`mail2026._domainkey.example.com`. A missing `dkim.toml`, or a sender domain without a matching
entry, leaves the message unsigned; an invalid matching entry prevents the message from entering
the queue. When `arc_signer` is present, rMail verifies the incoming ARC chain and adds an
ARC-Authentication-Results, ARC-Message-Signature, and ARC-Seal set before publishing a forwarded
message. A chain with invalid continuity is forwarded unchanged rather than being extended with a
misleading local seal. The ARC key has the same `0600` permission requirement as DKIM keys.

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

The outbound worker and IMAP service write one JSON object per operational log event. Every record includes
`timestamp_unix_ms`, `level`, `component`, `event`, and a `fields` object. Delivery-related records
include stable `connection_id` and `message_id` fields where available, so operators can filter and
join events without parsing human-readable messages. IMAP events separately expose peer, transport,
command, tag, and session-state context while redacting authentication payloads. Other daemons retain
their existing logs while they are migrated; live SMTP tracking already uses the structured IPC stream.

```bash
sudo rmail_ctl watch
sudo rmail_ctl watch --plain
sudo rmail_ctl track message-19abc123
```

The full-screen SSH-friendly view shows active inbound/outbound connections, reverse-DNS names,
SMTP phases and commands, reply codes, message IDs, and cumulative RX/TX bytes. `--plain` provides
a streaming format for pipes and minimal terminals. AUTH payloads and message bodies are not
recorded.

Durable history is bounded through `[global.tracking]`: `retention_days` and `max_events` set the
age and count limits, while `prune_interval_seconds` and `prune_batch_size` control incremental
cleanup. Setting either retention limit to zero disables that individual limit.

Outbound transport security:

- rMail advertises and relays RFC 8689 `REQUIRETLS`; such messages are never sent over plaintext, and the next hop must advertise `REQUIRETLS`
- rMail advertises RFC 3461 `DSN`, validates `ENVID`, `RET`, `NOTIFY`, and `ORCPT`, preserves those parameters through aliases and the private queue, and relays them to DSN-capable next hops. Requested success, delayed-delivery, and terminal-failure notifications use a null reverse path and `multipart/report; report-type=delivery-status`; `NOTIFY=NEVER` suppresses local bounces.
- MTA-STS policies are discovered through `_mta-sts.<domain>` TXT records, fetched over authenticated HTTPS, cached for `max_age`, and enforced against MX names and TLS certificate validation
- TLS failures are reported to valid `mailto:` destinations in `_smtp._tls.<domain>` RFC 8460 records using `application/tlsrpt+json`; reports themselves use a null reverse path to prevent loops

TLS policy is configured once under `[global.tls]`. `minimum_version` accepts
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
Without configured credentials, the web services remain available over HTTP.

`systemctl reload rmail_smtpd rmail_imapd rmail_web rmail_webmail` sends SIGHUP. Each daemon parses and validates the
replacement certificate, private key, version policy, and cipher policy before atomically swapping
the context used by new connections. Existing TLS sessions continue uninterrupted; a failed reload
keeps the previous context. Validation also requires a configured OCSP response to remain readable
and structurally usable.

`rmail_ctl obtain-cert` and `rmail_ctl renew` validate the certificate/key bundle before installing
each file with a same-filesystem atomic rename, then reload the services. When OCSP stapling is
configured, the renewal hook must fetch the response for the renewed certificate, write it to a
temporary file, and atomically rename it to `ocsp_response` before reloading. This ordering prevents
new connections from observing a partially written certificate or staple. The built-in renewal
command does not fetch an OCSP response itself.

Health probes are exposed by `rmail_web` without authentication so an orchestrator can use them:

- `GET /healthz` (also `/health`) is a process-liveness check and returns `200` while the HTTP service is responsive.
- `GET /readyz` (also `/ready`) returns JSON and `200` only when every configured dependency is ready. It verifies queue writability, SQLite access, asynchronous DNS resolution, the complete TLS certificate/key/policy/OCSP bundle, and connectivity to enabled ClamAV and Rspamd services. Unconfigured optional dependencies are reported as `skipped`; failures return `503` with per-component details.

The web listener binds to loopback by default. If it is exposed on a public address, restrict these
probe paths at the reverse proxy or firewall because readiness details are intentionally useful to
operators.

The admin console uses dedicated browser routes for its main operating areas: `/` (overview),
`/accounts`, `/routing`, `/delivery`, `/observability`, and `/system`. Navigation is grouped into
mail-management and operations areas; the system page exposes live readiness for the storage, DNS,
TLS, and filtering dependencies used by all rMail services. These routes are served through the same
single-page frontend, so a reverse proxy should pass unknown non-API paths to `rmail_web` rather than
returning its own 404 page.

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
sudo systemctl daemon-reload
```

### 6. Enable and start services

```bash
sudo systemctl enable --now rmail_smtpd.service
sudo systemctl enable --now rmail_imapd.service
sudo systemctl enable --now rmail_web.service
sudo systemctl enable --now rmail_webmail.service
sudo systemctl enable --now rmail_outbound.service
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
journalctl -u rmail_smtpd.service -u rmail_imapd.service -u rmail_web.service -u rmail_webmail.service -u rmail_outbound.service -n 200 --no-pager
```

## Notes On Privileged Ports

The service units use:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

That allows binding privileged ports like `25`, `143`, `465`, and `993` without running the daemons as root.

## Why There Are No `.socket` Units

Older packaging in this repository included systemd socket units, but the daemons do not currently implement socket activation. Shipping `.socket` units would be misleading and would not work correctly. If socket activation is wanted later, the daemons need explicit support for inherited listeners.

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

Then edit:

- `/etc/rmail/config.toml`
- `/etc/default/rmail`

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

# Performance Benchmarks

rMail uses Criterion benchmarks for repeatable storage and queue measurements. Run benchmarks on
an otherwise idle host with the same filesystem and build profile when comparing revisions; the
absolute results are not portable between machines or storage devices.

## Mailbox index

```bash
cargo bench -p rmail_common --bench mail_storage
```

The default fixture contains 10,000 messages of 4 KiB each and measures:

- loading an unchanged INBOX through the authoritative SQLite index;
- producing summaries for every account folder;
- calculating account-wide storage quota usage.

Use a larger corpus without editing the benchmark:

```bash
RMAIL_BENCH_MESSAGES=100000 cargo bench -p rmail_common --bench mail_storage
```

Fixture creation and the initial Maildir reconciliation happen before measurement. This keeps the
benchmark focused on steady-state operations rather than mixing setup cost into every sample.

## Atomic queue publication

```bash
cargo bench -p rmail_common --bench queue_publication
```

This measures complete message and control-sidecar publication into a fresh spool at 4 KiB, 1 MiB,
and 16 MiB. Each iteration uses a separate temporary mail root, so old spool entries cannot make
later samples cheaper or more expensive.

## Smoke validation

For a quick harness check rather than a baseline run:

```bash
RMAIL_BENCH_MESSAGES=100 cargo bench -p rmail_common --bench mail_storage -- --quick
cargo bench -p rmail_common --bench queue_publication -- --quick
```

Criterion writes comparison data beneath `target/criterion`. Preserve that directory between two
revisions when using Criterion's statistical regression comparison.

Protocol-level concurrent IDLE, SEARCH/FETCH, SMTP fanout, BDAT relay, and end-to-end queue-drain
measurements use the `rmail_bench` live-daemon client. Run them against an isolated deployment:

```bash
# SEARCH and metadata FETCH latency over a verified IMAPS connection
cargo run --release -p rmail_bench -- imap-commands \
  --address 127.0.0.1:993 --server-name mail.example.test \
  --ca-cert /etc/rmail/benchmark-ca.pem \
  --username bench@example.test \
  --iterations 1000 --search UNSEEN --fetch '1:* (FLAGS RFC822.SIZE)'

# Delivery-to-notification latency across 500 simultaneous IDLE sessions
cargo run --release -p rmail_bench -- imap-idle \
  --address 127.0.0.1:993 --server-name mail.example.test \
  --ca-cert /etc/rmail/benchmark-ca.pem \
  --username bench@example.test \
  --connections 500 --rounds 50

# DATA recipient fanout and one-chunk BDAT throughput
cargo run --release -p rmail_bench -- smtp \
  --address 127.0.0.1:25 --recipients a@example.test,b@example.test \
  --iterations 1000 --payload-bytes 1048576
cargo run --release -p rmail_bench -- smtp \
  --address 127.0.0.1:25 --recipients a@example.test \
  --iterations 1000 --payload-bytes 16777216 --bdat

# Observe a preloaded spool until queue and inflight are empty
cargo run --release -p rmail_bench -- queue-drain \
  --mail-root /var/lib/rmail --timeout-seconds 900
```

Use the global `--json` flag for machine-readable result rows. IMAP authentication is deliberately
available only over certificate-verified TLS; the benchmark client does not add an insecure
certificate or plaintext-password shortcut. For an isolated self-signed listener, replace
`--ca-cert` with `--pinned-cert /path/to/exact-leaf.pem`; pin mode accepts only a byte-for-byte
match of that leaf certificate and is not a trust-all verifier. The password is read from
`RMAIL_BENCH_PASSWORD` by default; `--password-env NAME` selects another environment variable, so
the secret does not appear in the process argument list. SMTP workloads expect an isolated MTA
listener whose test recipients are valid and whose downstream delivery cannot affect real users. Queue-drain mode
does not enqueue or delete messages itself—it observes a spool that the operator prepared, so the
measurement includes the real worker, DNS, connection-pool, and remote-peer behavior.

Do not replace these workloads with timing-sensitive unit-test assertions. Their fake-daemon unit
tests validate protocol framing, while performance numbers come only from controlled live runs.

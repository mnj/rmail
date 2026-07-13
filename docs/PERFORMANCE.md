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
load generators are tracked separately from these storage microbenchmarks because they require
live daemons, stable port allocation, and controlled DNS/MX peers. Do not replace those workloads
with timing-sensitive unit-test assertions.

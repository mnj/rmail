use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rmail_common::imap_state;
use std::fs;

fn seeded_account(message_count: usize, message_size: usize) -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("benchmark tempdir");
    imap_state::init_account(temp.path(), "example.test", "bench").expect("initialize account");
    let inbox = imap_state::account_maildir(temp.path(), "example.test", "bench").join("new");
    let message = vec![b'x'; message_size];
    for index in 0..message_count {
        fs::write(inbox.join(format!("benchmark-{index}")), &message).expect("seed message");
    }
    // Reconcile once so steady-state measurements exercise the authoritative index fast path.
    imap_state::load_folder(temp.path(), "example.test", "bench", "INBOX")
        .expect("initial reconciliation");
    temp
}

fn mailbox_index_benchmarks(criterion: &mut Criterion) {
    let message_count = std::env::var("RMAIL_BENCH_MESSAGES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000usize);
    let message_size = 4 * 1024usize;
    let account = seeded_account(message_count, message_size);
    let mut group = criterion.benchmark_group("mailbox_index");
    group.sample_size(20);
    group.throughput(Throughput::Elements(message_count as u64));
    group.bench_with_input(
        BenchmarkId::new("load_unchanged_inbox", message_count),
        &message_count,
        |bencher, _| {
            bencher.iter(|| {
                imap_state::load_folder(account.path(), "example.test", "bench", "INBOX")
                    .expect("load inbox")
            });
        },
    );
    group.bench_with_input(
        BenchmarkId::new("list_folder_summaries", message_count),
        &message_count,
        |bencher, _| {
            bencher.iter(|| {
                imap_state::list_folder_summaries(account.path(), "example.test", "bench")
                    .expect("folder summaries")
            });
        },
    );
    group.bench_with_input(
        BenchmarkId::new("account_storage_usage", message_count),
        &message_count,
        |bencher, _| {
            bencher.iter(|| {
                imap_state::storage_quota(account.path(), "example.test", "bench")
                    .expect("storage usage")
            });
        },
    );
    group.finish();
}

criterion_group!(benches, mailbox_index_benchmarks);
criterion_main!(benches);

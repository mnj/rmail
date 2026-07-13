use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rmail_common::outbound;

fn queue_publication_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("queue_publication");
    group.sample_size(20);
    for message_size in [4 * 1024usize, 1024 * 1024, 16 * 1024 * 1024] {
        let message = vec![b'x'; message_size];
        group.throughput(Throughput::Bytes(message_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(message_size),
            &message,
            |bencher, message| {
                bencher.iter_batched(
                    || tempfile::tempdir().expect("benchmark tempdir"),
                    |temp| {
                        outbound::queue_outbound(
                            temp.path(),
                            "recipient@example.test",
                            message,
                            Some("sender@example.test"),
                        )
                        .expect("queue publication")
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, queue_publication_benchmarks);
criterion_main!(benches);

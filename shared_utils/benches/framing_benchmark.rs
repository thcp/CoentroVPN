use criterion::{Criterion, black_box, criterion_group, criterion_main};
use shared_utils::proto::framing::{Frame, FrameDecoder, FrameEncoder, FrameFlags, FrameType};
use tokio::runtime::Runtime;

fn framing_benchmark(c: &mut Criterion) {
    let data = vec![0u8; 1024]; // 1KB of data
    let encoder = FrameEncoder::new();

    c.bench_function("frame_data", |b| {
        b.iter(|| {
            let frame =
                Frame::new(FrameType::Data, FrameFlags::new(), black_box(data.clone())).unwrap();
            encoder.encode(&frame);
        })
    });

    let frame = Frame::new(FrameType::Data, FrameFlags::new(), data.clone()).unwrap();
    let framed_data = encoder.encode(&frame);

    c.bench_function("deframe_data", |b| {
        // Each iteration will get its own FrameDecoder
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || framed_data.clone(), // Setup: clone the data for this batch
            |data_for_iteration| async move {
                // Routine: receives cloned data
                let mut decoder = FrameDecoder::new();
                decoder.decode(black_box(&data_for_iteration)).unwrap();
            },
            criterion::BatchSize::SmallInput, // Or PerIteration if cloning is very cheap / part of the bench
        );
    });
}

criterion_group!(benches, framing_benchmark);
criterion_main!(benches);

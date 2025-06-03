use criterion::{black_box, criterion_group, criterion_main, Criterion};
use shared_utils::crypto::aes_gcm::AesGcmCipher;
use rand::rngs::OsRng;
use rand::RngCore;

fn aes_gcm_benchmark(c: &mut Criterion) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = AesGcmCipher::new(&key).expect("Failed to create cipher"); // Handle potential error
    let data = vec![0u8; 1024]; // 1KB of data

    c.bench_function("encrypt_data", |b| {
        b.iter(|| {
            cipher.encrypt(black_box(&data)).unwrap();
        })
    });

    // It's good practice to re-encrypt for the decrypt benchmark if the data or key could change,
    // or if the encryption itself is part of what you want to benchmark in a combined scenario.
    // For a pure decryption benchmark, using a pre-encrypted payload is fine.
    let encrypted_data = cipher.encrypt(&data).unwrap();

    c.bench_function("decrypt_data", |b| {
        b.iter(|| {
            // Clone encrypted_data if it's consumed or modified by decrypt,
            // or ensure decrypt takes a slice if it doesn't modify.
            cipher.decrypt(black_box(&encrypted_data)).unwrap();
        })
    });
}

criterion_group!(benches, aes_gcm_benchmark);
criterion_main!(benches);

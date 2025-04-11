use coentrovpn::packet_utils::{compress_data, decompress_data};
use tokio::runtime::Runtime;

#[test]
fn test_lz4_compression_roundtrip() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let original = b"The quick brown fox jumps over the lazy dog.".repeat(10);
        let compressed = compress_data(&original, "lz4")
            .await
            .expect("compression failed");
        assert!(compressed.len() < original.len(), "lz4 should compress");
        let decompressed = decompress_data(&compressed, "lz4")
            .await
            .expect("decompression failed");
        assert_eq!(original, decompressed);
    });
}

#[test]
fn test_zstd_compression_roundtrip() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let original = b"Rustaceans are fearless and fast.".repeat(10);
        let compressed = compress_data(&original, "zstd")
            .await
            .expect("compression failed");
        assert!(compressed.len() < original.len(), "zstd should compress");
        let decompressed = decompress_data(&compressed, "zstd")
            .await
            .expect("decompression failed");
        assert_eq!(original, decompressed);
    });
}

#[test]
fn test_invalid_algorithm_fails() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let original = b"invalid algorithm test";
        let compressed = compress_data(original, "unsupported_algo").await;
        assert!(compressed.is_err(), "Should fail with unknown algorithm");

        let decompressed = decompress_data(original, "unsupported_algo").await;
        assert!(decompressed.is_err(), "Should fail with unknown algorithm");
    });
}

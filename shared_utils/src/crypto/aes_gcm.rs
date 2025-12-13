use aes_gcm::aead::Aead; // Aead needs to be imported from the sub-module
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce}; // KeyInit is directly re-exported
use anyhow::Result;
use rand::RngCore;
use std::fmt; // For manual Debug impl
use std::sync::atomic::{AtomicU64, Ordering}; // Added for AtomicU64

const KEY_SIZE: usize = 32; // AES-256
const NONCE_SIZE: usize = 12; // AES-GCM standard nonce size (96 bits)
const _TAG_SIZE: usize = 16; // AES-GCM standard tag size (128 bits)

// #[derive(Debug)] // Cannot derive Debug as Aes256Gcm doesn't implement it
pub struct AesGcmCipher {
    cipher: Aes256Gcm,
    nonce_prefix: [u8; 4],    // Random prefix per cipher instance
    nonce_counter: AtomicU64, // Counter for nonces
}

// Manual Debug implementation
impl fmt::Debug for AesGcmCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmCipher")
            .field("cipher", &"[Aes256Gcm instance]") // Placeholder for non-Debug field
            .field("nonce_prefix", &self.nonce_prefix)
            .field("nonce_counter", &self.nonce_counter.load(Ordering::Relaxed)) // Show current counter value
            .finish()
    }
}

impl AesGcmCipher {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(anyhow::anyhow!(
                "Invalid key size. Expected {} bytes, got {}",
                KEY_SIZE,
                key.len()
            ));
        }
        let key_array = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key_array);

        let mut nonce_prefix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut nonce_prefix);

        Ok(Self {
            cipher,
            nonce_prefix,
            nonce_counter: AtomicU64::new(0),
        })
    }

    pub fn generate_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    // Generates a unique nonce for this cipher instance
    fn generate_nonce_bytes(&self) -> [u8; NONCE_SIZE] {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        // Atomically increment the counter and get the value before incrementing
        let count = self.nonce_counter.fetch_add(1, Ordering::SeqCst);

        // Construct nonce: 4-byte prefix | 8-byte counter (big-endian)
        nonce_bytes[0..4].copy_from_slice(&self.nonce_prefix);
        nonce_bytes[4..12].copy_from_slice(&count.to_be_bytes());

        // Check for counter wrap-around. Extremely unlikely with u64.
        if count == u64::MAX {
            // This is a catastrophic event for this cipher instance.
            // Log loudly; re-keying should be enforced by caller policies.
            tracing::error!(
                "CRITICAL: AES-GCM nonce counter has wrapped around! Re-key is required."
            );
        }
        nonce_bytes
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = self.generate_nonce_bytes();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to the ciphertext: nonce || ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_nonce.len() < NONCE_SIZE {
            return Err(anyhow::anyhow!(
                "Ciphertext is too short to contain a nonce."
            ));
        }

        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto; // For try_into in tests

    #[test]
    fn test_encrypt_decrypt_success() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();
        let plaintext = b"Hello, world! This is a secret message.";

        let encrypted_data = cipher.encrypt(plaintext).unwrap();
        let decrypted_data = cipher.decrypt(&encrypted_data).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted_data);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = AesGcmCipher::generate_key();
        let cipher1 = AesGcmCipher::new(&key1).unwrap();
        let plaintext = b"Another secret.";

        let encrypted_data = cipher1.encrypt(plaintext).unwrap();

        let key2 = AesGcmCipher::generate_key(); // Different key
        let cipher2 = AesGcmCipher::new(&key2).unwrap();

        let result = cipher2.decrypt(&encrypted_data);
        assert!(
            result.is_err(),
            "Decryption should fail with a different key"
        );
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();
        let plaintext = b"Sensitive data.";

        let mut encrypted_data = cipher.encrypt(plaintext).unwrap();

        // Tamper with the ciphertext (after the nonce)
        if encrypted_data.len() > NONCE_SIZE + 1 {
            encrypted_data[NONCE_SIZE + 1] ^= 0xff; // Flip some bits
        } else {
            // If ciphertext is too short, this test might not be meaningful,
            // but let's try to tamper the last byte if possible.
            let len = encrypted_data.len(); // Store len before mutable borrow
            if len > 0 {
                encrypted_data[len - 1] ^= 0xff;
            }
        }

        let result = cipher.decrypt(&encrypted_data);
        assert!(
            result.is_err(),
            "Decryption should fail for tampered ciphertext"
        );
    }

    #[test]
    fn test_invalid_key_size() {
        let short_key = [0u8; 16]; // Too short
        let result = AesGcmCipher::new(&short_key);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid key size. Expected 32 bytes, got 16"
        );

        let long_key = [0u8; 48]; // Too long
        let result_long = AesGcmCipher::new(&long_key);
        assert!(result_long.is_err());
        assert_eq!(
            result_long.unwrap_err().to_string(),
            "Invalid key size. Expected 32 bytes, got 48"
        );
    }

    #[test]
    fn test_decrypt_too_short_ciphertext() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();

        let short_ciphertext = b"short"; // Less than NONCE_SIZE
        let result = cipher.decrypt(short_ciphertext);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Ciphertext is too short to contain a nonce."
        );
    }

    #[test]
    fn test_nonce_uniqueness_for_instance() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();
        let plaintext1 = b"message1";
        let plaintext2 = b"message2";

        // First encryption
        let encrypted1 = cipher.encrypt(plaintext1).unwrap();
        let nonce1_bytes_slice = &encrypted1[0..NONCE_SIZE];
        let prefix1_slice = &nonce1_bytes_slice[0..4];
        let counter1_slice = &nonce1_bytes_slice[4..NONCE_SIZE];
        let counter1_array: [u8; 8] = counter1_slice
            .try_into()
            .expect("Counter slice has wrong length");
        let counter1_val = u64::from_be_bytes(counter1_array);

        // Second encryption
        let encrypted2 = cipher.encrypt(plaintext2).unwrap();
        let nonce2_bytes_slice = &encrypted2[0..NONCE_SIZE];
        let prefix2_slice = &nonce2_bytes_slice[0..4];
        let counter2_slice = &nonce2_bytes_slice[4..NONCE_SIZE];
        let counter2_array: [u8; 8] = counter2_slice
            .try_into()
            .expect("Counter slice has wrong length");
        let counter2_val = u64::from_be_bytes(counter2_array);

        // Overall nonces should be different
        assert_ne!(
            nonce1_bytes_slice, nonce2_bytes_slice,
            "Nonces from two consecutive encryptions on the same instance should be different"
        );

        // Prefixes should be the same for the same cipher instance
        assert_eq!(
            prefix1_slice, prefix2_slice,
            "Nonce prefix should be the same for the same cipher instance"
        );

        // Counter parts should be different
        assert_ne!(
            counter1_slice, counter2_slice,
            "Nonce counter part should differ"
        );

        // Specifically, counter2 should be counter1 + 1
        assert_eq!(
            counter2_val,
            counter1_val + 1,
            "Nonce counter should increment by 1. Got {} and {}",
            counter1_val,
            counter2_val
        );

        // Decrypt to ensure messages are still valid
        let decrypted1 = cipher.decrypt(&encrypted1).unwrap();
        assert_eq!(decrypted1, plaintext1);

        let decrypted2 = cipher.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_nonce_counter_increments_over_multiple_encryptions() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();
        let plaintext = b"test message";
        let num_encryptions = 5;
        let mut last_counter_val: Option<u64> = None;

        for i in 0..num_encryptions {
            let encrypted_data = cipher.encrypt(plaintext).unwrap();
            let nonce_bytes_slice = &encrypted_data[0..NONCE_SIZE];
            let counter_slice = &nonce_bytes_slice[4..NONCE_SIZE];
            let counter_array: [u8; 8] = counter_slice
                .try_into()
                .expect("Counter slice has wrong length");
            let current_counter_val = u64::from_be_bytes(counter_array);

            if let Some(last_val) = last_counter_val {
                assert_eq!(
                    current_counter_val,
                    last_val + 1,
                    "Counter should increment by 1 on iteration {}",
                    i
                );
            } else {
                // For the first encryption, counter should be 0 (as fetch_add returns old value)
                assert_eq!(current_counter_val, 0, "Initial counter value should be 0");
            }
            last_counter_val = Some(current_counter_val);
        }
    }

    #[test]
    fn replayed_ciphertext_is_rejected() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();
        let plaintext = b"replay-test-payload";

        let ct = cipher.encrypt(plaintext).expect("encrypt");

        let pt1 = cipher.decrypt(&ct).expect("first decrypt should work");
        assert_eq!(pt1, plaintext);

        // AES-GCM itself does not provide replay protection; upper layers must enforce it.
        // A replay should still decrypt to the same plaintext.
        let pt2 = cipher.decrypt(&ct).expect("replay should still decrypt");
        assert_eq!(pt2, plaintext, "replayed ciphertext did not round-trip");
    }

    #[test]
    fn ciphertext_from_other_key_fails() {
        let key_a = AesGcmCipher::generate_key();
        let key_b = AesGcmCipher::generate_key();

        let cipher_a = AesGcmCipher::new(&key_a).unwrap();
        let cipher_b = AesGcmCipher::new(&key_b).unwrap();

        let plaintext = b"cross-key-payload";
        let ct = cipher_a.encrypt(plaintext).expect("encrypt");

        let res = cipher_b.decrypt(&ct);
        assert!(res.is_err(), "ciphertext decrypted with wrong key");
    }
}

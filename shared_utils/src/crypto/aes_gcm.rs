use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit}; // KeyInit is directly re-exported
use aes_gcm::aead::Aead; // Aead needs to be imported from the sub-module
use rand::RngCore;
use anyhow::Result;
use std::fmt; // For manual Debug impl

const KEY_SIZE: usize = 32; // AES-256
const NONCE_SIZE: usize = 12; // AES-GCM standard nonce size (96 bits)
const TAG_SIZE: usize = 16; // AES-GCM standard tag size (128 bits)

// #[derive(Debug)] // Cannot derive Debug as Aes256Gcm doesn't implement it
pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

// Manual Debug implementation
impl fmt::Debug for AesGcmCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmCipher")
         .field("cipher", &"[Aes256Gcm instance]") // Placeholder for non-Debug field
         .finish()
    }
}

impl AesGcmCipher {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(anyhow::anyhow!("Invalid key size. Expected {} bytes, got {}", KEY_SIZE, key.len()));
        }
        let key_array = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key_array);
        Ok(Self { cipher })
    }

    pub fn generate_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    fn generate_nonce() -> [u8; NONCE_SIZE] {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        nonce_bytes
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = Self::generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self.cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to the ciphertext: nonce || ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
        if ciphertext_with_nonce.len() < NONCE_SIZE {
            return Err(anyhow::anyhow!("Ciphertext is too short to contain a nonce."));
        }

        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self.cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(result.is_err(), "Decryption should fail with a different key");
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
                 encrypted_data[len-1] ^=0xff;
            }
        }


        let result = cipher.decrypt(&encrypted_data);
        assert!(result.is_err(), "Decryption should fail for tampered ciphertext");
    }

    #[test]
    fn test_invalid_key_size() {
        let short_key = [0u8; 16]; // Too short
        let result = AesGcmCipher::new(&short_key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid key size. Expected 32 bytes, got 16");


        let long_key = [0u8; 48]; // Too long
        let result_long = AesGcmCipher::new(&long_key);
        assert!(result_long.is_err());
        assert_eq!(result_long.unwrap_err().to_string(), "Invalid key size. Expected 32 bytes, got 48");
    }

     #[test]
    fn test_decrypt_too_short_ciphertext() {
        let key = AesGcmCipher::generate_key();
        let cipher = AesGcmCipher::new(&key).unwrap();
        
        let short_ciphertext = b"short"; // Less than NONCE_SIZE
        let result = cipher.decrypt(short_ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Ciphertext is too short to contain a nonce.");
    }
}

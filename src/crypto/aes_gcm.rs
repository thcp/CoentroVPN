use aes_gcm::aead::{rand_core::RngCore, Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce}; // Or `Aes128Gcm`

pub struct AesGcmEncryptor {
    cipher: Aes256Gcm,
}

impl AesGcmEncryptor {
    pub fn new(key_bytes: &[u8; 32]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12]), aes_gcm::Error> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes); // 96-bits; unique per message
        let ciphertext = self.cipher.encrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )?;
        Ok((ciphertext, nonce_bytes))
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce_bytes: &[u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self.cipher.decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )?;
        Ok(plaintext)
    }
}

use coentrovpn::crypto::aes_gcm::AesGcmEncryptor;

#[test]
fn test_aes_gcm_encrypt_decrypt_roundtrip() {
    let key = [0u8; 32];
    let encryptor = AesGcmEncryptor::new(&key);

    let plaintext = b"The quick brown fox jumps over the lazy dog";
    let aad = b"associated data";

    let (ciphertext, nonce) = encryptor.encrypt(plaintext, aad).expect("encryption failed");
    let decrypted = encryptor.decrypt(&ciphertext, &nonce, aad).expect("decryption failed");

    assert_eq!(plaintext.to_vec(), decrypted);
}

#[test]
fn test_aes_gcm_decrypt_with_wrong_key_fails() {
    let key1 = [0u8; 32];
    let key2 = [1u8; 32];
    let enc1 = AesGcmEncryptor::new(&key1);
    let enc2 = AesGcmEncryptor::new(&key2);

    let plaintext = b"secret message";
    let aad = b"metadata";

    let (ciphertext, nonce) = enc1.encrypt(plaintext, aad).unwrap();
    let result = enc2.decrypt(&ciphertext, &nonce, aad);

    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn test_aes_gcm_decrypt_with_wrong_aad_fails() {
    let key = [7u8; 32];
    let encryptor = AesGcmEncryptor::new(&key);

    let plaintext = b"auth-tag-sensitive";
    let aad_good = b"correct-aad";
    let aad_bad = b"wrong-aad";

    let (ciphertext, nonce) = encryptor.encrypt(plaintext, aad_good).unwrap();
    let result = encryptor.decrypt(&ciphertext, &nonce, aad_bad);

    assert!(result.is_err(), "Decryption with incorrect AAD should fail");
}

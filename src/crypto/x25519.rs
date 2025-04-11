use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use rand_core::OsRng;

pub struct X25519KeyPair {
    pub private_key: EphemeralSecret,
    pub public_key: PublicKey,
}

impl X25519KeyPair {
    pub fn generate() -> Self {
        let private_key = EphemeralSecret::new(OsRng);
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    pub fn derive_shared_secret(
        &self,
        peer_public_key: &PublicKey,
    ) -> SharedSecret {
        self.private_key.diffie_hellman(peer_public_key)
    }
}

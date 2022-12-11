use std::ops::{Deref, DerefMut};

use crate::common::*;

use ed25519_dalek;
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};


#[derive(Serialize, Deserialize)]
pub struct PublicKey (ed25519_dalek::PublicKey);

#[derive(Deserialize, Serialize)]
pub struct Signature (ed25519_dalek::Signature);

pub type Identity = PublicKey;

#[derive(Deserialize, Serialize)]
pub struct MyIdentity (ed25519_dalek::Keypair);



impl Identity {
    pub fn generate_address(&self) -> IdType {
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        let buffer: [u8; 32] = hasher.finalize().into();
        buffer.into()
    }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(other: ed25519_dalek::PublicKey) -> Self {
        Self (other)
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        Self (ed25519_dalek::PublicKey::from_bytes(self.0.as_bytes()).unwrap())
    }
}

impl Deref for PublicKey {
    type Target = ed25519_dalek::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PublicKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

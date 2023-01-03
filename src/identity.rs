use std::ops::{Deref, DerefMut};

use crate::common::*;

//use ed25519;
use ed25519_dalek::{
	self,
	ed25519::{
		signature::{
			Signature as SignatureTrait,
			Signer,
			Verifier
		}
	}
};
use rand_core::{OsRng, RngCore};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256};


#[derive(Serialize, Deserialize)]
pub struct PublicKey (ed25519_dalek::PublicKey);

#[derive(Clone, Serialize, Deserialize)]
pub struct Signature (ed25519_dalek::Signature);

pub type Identity = PublicKey;

#[derive(Deserialize, Serialize)]
pub struct Keypair (ed25519_dalek::Keypair);



impl PublicKey {

	pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
		ed25519_dalek::PublicKey::from_bytes(&bytes).ok().map(|k| Self(k))
	}

	pub fn generate_address(&self) -> IdType {
		let mut hasher = Sha256::new();
		hasher.update(self.to_bytes());
		let buffer: [u8; 32] = hasher.finalize().into();
		buffer.into()
	}

	pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
		self.0.verify(message, &signature.0).is_ok()
	}
}

impl Keypair {
	pub fn from_bytes(bytes: &[u8]) -> Result<Self, ed25519_dalek::SignatureError> {
		Ok(Self(ed25519_dalek::Keypair::from_bytes(bytes)?))
	}

	pub fn generate() -> Self {
		let mut rng = OsRng {};
		Self (ed25519_dalek::Keypair::generate(&mut rng))
	}

	pub fn public(&self) -> PublicKey {
		PublicKey (self.0.public)
	}

	pub fn sign(&self, message: &[u8]) -> Signature {
		Signature (
			self.0.sign(message)
		)
	}
}

impl Clone for Keypair {
	fn clone(&self) -> Self {
		Self (ed25519_dalek::Keypair::from_bytes(&self.0.to_bytes()).unwrap())
	}
}

impl Signature {

	pub fn as_bytes(&self) -> &[u8; 64] {
		self.0.as_bytes().try_into().unwrap()
	}

	pub fn from_bytes(bytes: [u8; 64]) -> Self {
		Self (ed25519_dalek::Signature::from_bytes(&bytes).unwrap())
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


#[test]
fn test_signature() {
	let mut buffer = vec![0u8; 1024];
	OsRng.fill_bytes(&mut buffer);

	let keypair = Keypair::generate();
	let signature = keypair.sign(&buffer);
	assert!(keypair.public().verify(&buffer, &signature), "can't verify own signature");

	let signature_bytes = signature.as_bytes();
	let signature2 = Signature::from_bytes(signature_bytes.clone());
	assert!(keypair.public().verify(&buffer, &signature2), "can't verify own signature after encoding+decoding it");
}

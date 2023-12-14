use std::{
	fmt,
	ops::{Deref, DerefMut},
};

use ed25519_dalek::{
	self,
	ed25519::signature::{Signature as SignatureTrait, Signer, Verifier},
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::common::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct PublicKey(ed25519_dalek::PublicKey);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature(ed25519_dalek::Signature);
pub type SignatureError = ed25519_dalek::SignatureError;

pub type Identity = PublicKey;
#[derive(Debug)]
pub struct PublicKeyError(ed25519_dalek::SignatureError);

#[derive(Serialize)]
pub struct Keypair {
	inner: ed25519_dalek::Keypair,
	//#[serde(serialize_with = "<[_]>::serialize")]
	#[serde(skip_serializing)]
	copy: KeypairCopy,
}
pub type KeypairError = ed25519_dalek::SignatureError;

#[derive(Zeroize)]
#[zeroize(drop)]
struct KeypairCopy([u8; ed25519_dalek::KEYPAIR_LENGTH]);

impl PublicKey {
	pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PublicKeyError> {
		Ok(Self(
			ed25519_dalek::PublicKey::from_bytes(&bytes).map_err(|e| PublicKeyError(e))?,
		))
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
	pub fn as_bytes(&self) -> &[u8; 64] { &self.copy.0 }

	pub fn to_bytes(&self) -> [u8; 64] { self.inner.to_bytes() }

	pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeypairError> {
		Ok(Self::new(ed25519_dalek::Keypair::from_bytes(bytes)?))
	}

	pub fn generate() -> Self {
		let mut rng = OsRng {};
		Self::new(ed25519_dalek::Keypair::generate(&mut rng))
	}

	fn new(inner: ed25519_dalek::Keypair) -> Self {
		Self {
			copy: KeypairCopy(inner.to_bytes()),
			inner,
		}
	}

	pub fn public(&self) -> PublicKey { PublicKey(self.inner.public) }

	pub fn sign(&self, message: &[u8]) -> Signature { Signature(self.inner.sign(message)) }
}

impl fmt::Display for PublicKeyError {
	fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		write!(fmt, "{}", self.0)
	}
}

impl Clone for Keypair {
	fn clone(&self) -> Self {
		Self::new(ed25519_dalek::Keypair::from_bytes(&self.inner.to_bytes()).unwrap())
	}
}

impl Signature {
	pub fn as_bytes(&self) -> &[u8; 64] { self.0.as_bytes().try_into().unwrap() }

	pub fn from_bytes(bytes: [u8; 64]) -> Self {
		Self(ed25519_dalek::Signature::from_bytes(&bytes).unwrap())
	}

	pub fn hash(&self) -> IdType { IdType::hash(self.as_bytes()) }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
	fn from(other: ed25519_dalek::PublicKey) -> Self { Self(other) }
}

impl Clone for PublicKey {
	fn clone(&self) -> Self {
		Self(ed25519_dalek::PublicKey::from_bytes(self.0.as_bytes()).unwrap())
	}
}

impl Deref for PublicKey {
	type Target = ed25519_dalek::PublicKey;

	fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for PublicKey {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

#[cfg(test)]
mod tests {
	use rand_core::RngCore;

	use super::*;

	#[test]
	fn test_signature() {
		let mut buffer = vec![0u8; 1024];
		OsRng.fill_bytes(&mut buffer);

		let keypair = Keypair::generate();
		let signature = keypair.sign(&buffer);
		assert!(
			keypair.public().verify(&buffer, &signature),
			"can't verify own signature"
		);

		let signature_bytes = signature.as_bytes();
		let signature2 = Signature::from_bytes(signature_bytes.clone());
		assert!(
			keypair.public().verify(&buffer, &signature2),
			"can't verify own signature after encoding+decoding it"
		);
	}
}

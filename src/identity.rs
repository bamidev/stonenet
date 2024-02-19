use std::{
	error::Error,
	fmt,
	ops::{Deref, DerefMut},
};

use ed25519_dalek::{self, Signer};
use rand::{prelude::*, rngs::OsRng};
use rusqlite::{types::*, ToSql};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::common::*;

#[derive(Debug, PartialEq)]
pub struct NodePublicKey(ed25519_dalek::VerifyingKey);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSignature(ed25519_dalek::Signature);
pub type NodeSignatureError = ed25519_dalek::SignatureError;

#[derive(Debug)]
pub struct NodePublicKeyError(ed25519_dalek::SignatureError);

#[derive(Debug, Serialize)]
pub struct NodePrivateKey {
	inner: ed25519_dalek::SigningKey,
	#[serde(skip_serializing)]
	copy: NodePrivateKeyCopy,
}
pub type NodeKeypairError = ed25519_dalek::SignatureError;

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
struct NodePrivateKeyCopy([u8; ed25519_dalek::SECRET_KEY_LENGTH]);


impl NodePublicKey {
	pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, NodePublicKeyError> {
		Ok(Self(
			ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|e| NodePublicKeyError(e))?,
		))
	}

	pub fn generate_address(&self) -> IdType {
		let mut hasher = Sha256::new();
		hasher.update(self.0.to_bytes());
		let buffer: [u8; 32] = hasher.finalize().into();
		buffer.into()
	}

	pub fn verify(&self, message: &[u8], signature: &NodeSignature) -> bool {
		self.0.verify_strict(message, &signature.0).is_ok()
	}
}

impl NodePrivateKey {
	pub fn as_bytes(&self) -> &[u8; 32] { &self.copy.0 }

	pub fn to_bytes(&self) -> [u8; 32] { self.inner.to_bytes() }

	pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
		let this = Self::new(ed25519_dalek::SigningKey::from_bytes(&bytes));
		bytes.zeroize();
		this
	}

	pub fn generate() -> Self {
		let mut rng = OsRng {};
		Self::generate_with_rng(&mut rng)
	}

	pub fn generate_with_rng<R>(rng: &mut R) -> Self
	where
		R: CryptoRng + RngCore,
	{
		Self::new(ed25519_dalek::SigningKey::generate(rng))
	}

	fn new(inner: ed25519_dalek::SigningKey) -> Self {
		Self {
			copy: NodePrivateKeyCopy(inner.to_bytes()),
			inner,
		}
	}

	pub fn public(&self) -> NodePublicKey { NodePublicKey(self.inner.verifying_key()) }

	pub fn sign(&self, message: &[u8]) -> NodeSignature { NodeSignature(self.inner.sign(message)) }
}

impl FromSql for NodePrivateKey {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Blob(bytes) =>
				if bytes.len() >= ed25519_dalek::SECRET_KEY_LENGTH {
					FromSqlResult::Ok(NodePrivateKey::from_bytes(
						bytes[..ed25519_dalek::SECRET_KEY_LENGTH]
							.try_into()
							.unwrap(),
					))
				} else {
					FromSqlResult::Err(FromSqlError::InvalidBlobSize {
						expected_size: ed25519_dalek::SECRET_KEY_LENGTH,
						blob_size: bytes.len(),
					})
				},
			_ => FromSqlResult::Err(FromSqlError::InvalidType),
		}
	}
}

impl ToSql for NodePrivateKey {
	fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
		Ok(ToSqlOutput::Borrowed(ValueRef::Blob(self.as_bytes())))
	}
}

impl Error for NodePublicKeyError {}

impl fmt::Display for NodePublicKeyError {
	fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
		write!(fmt, "{}", self.0)
	}
}

impl Clone for NodePrivateKey {
	fn clone(&self) -> Self {
		Self::new(ed25519_dalek::SigningKey::from_bytes(
			&self.inner.to_bytes(),
		))
	}
}

impl NodeSignature {
	pub fn to_bytes(&self) -> [u8; 64] { self.0.to_bytes() }

	pub fn from_bytes(bytes: [u8; 64]) -> Self {
		Self(ed25519_dalek::Signature::from_bytes(&bytes))
	}

	pub fn hash(&self) -> IdType { IdType::hash(&self.to_bytes()) }
}

impl From<ed25519_dalek::VerifyingKey> for NodePublicKey {
	fn from(other: ed25519_dalek::VerifyingKey) -> Self { Self(other) }
}

impl Clone for NodePublicKey {
	fn clone(&self) -> Self {
		Self(ed25519_dalek::VerifyingKey::from_bytes(self.0.as_bytes()).unwrap())
	}
}

impl Deref for NodePublicKey {
	type Target = ed25519_dalek::VerifyingKey;

	fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for NodePublicKey {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl<'de> Deserialize<'de> for NodePublicKey {
	fn deserialize<D>(d: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		//let mut bytes = [0u8; 32];
		let bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = Deserialize::deserialize(d)?;
		Ok(Self(
			ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap(),
		))
	}
}

impl Serialize for NodePublicKey {
	fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.0.to_bytes().serialize(s)
	}
}


#[cfg(test)]
mod tests {
	use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
	use rand::RngCore;

	use super::*;
	use crate::{net::binserde, test};

	#[test]
	fn test_type_sizes() {
		let public_key = NodePublicKey::from_bytes([0u8; PUBLIC_KEY_LENGTH]).unwrap();
		assert_eq!(
			binserde::serialized_size(&public_key).unwrap(),
			PUBLIC_KEY_LENGTH
		);

		let signature = NodeSignature::from_bytes([0u8; SIGNATURE_LENGTH]);
		assert_eq!(
			binserde::serialized_size(&signature).unwrap(),
			SIGNATURE_LENGTH
		);

		let dh_public_key = x25519_dalek::PublicKey::from([0u8; 32]);
		assert_eq!(binserde::serialized_size(&dh_public_key).unwrap(), 32);
	}

	#[test]
	fn test_signature() {
		let mut rng = test::initialize_rng();
		let mut buffer = vec![0u8; 1024];
		rng.fill_bytes(&mut buffer);

		let keypair = NodePrivateKey::generate();
		let signature = keypair.sign(&buffer);
		assert!(
			keypair.public().verify(&buffer, &signature),
			"can't verify own signature"
		);

		let signature_bytes = signature.to_bytes();
		let signature2 = NodeSignature::from_bytes(signature_bytes);
		assert!(
			keypair.public().verify(&buffer, &signature2),
			"can't verify own signature after encoding+decoding it"
		);
	}
}

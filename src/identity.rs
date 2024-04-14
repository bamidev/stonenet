use std::{
	error::Error,
	fmt,
	ops::{Deref, DerefMut},
};

use ed25519_dalek::{self as ed25519, Signer};
use ed448_rust as ed448;
use rand::{prelude::*, rngs::OsRng};
use rusqlite::{types::*, ToSql};
use sea_orm::{prelude::*, ColIdx, TryGetError};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::common::*;


#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActorPublicKeyV1(#[serde(with = "BigArray")] [u8; 57]);
pub type ActorPublicKeyV1Error = ();

pub struct ActorPrivateKeyV1(ed448::PrivateKey);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActorSignatureV1(#[serde(with = "BigArray")] [u8; 114]);

#[derive(Debug, PartialEq)]
pub struct NodePublicKey(ed25519::VerifyingKey);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeSignature(ed25519::Signature);
pub type NodeSignatureError = ed25519::SignatureError;

#[derive(Debug)]
pub struct NodePublicKeyError(ed25519::SignatureError);

#[derive(Debug, Serialize)]
pub struct NodePrivateKey {
	inner: ed25519::SigningKey,
	#[serde(skip_serializing)]
	copy: NodePrivateKeyCopy,
}

#[derive(Debug, Zeroize)]
#[zeroize(drop)]
struct NodePrivateKeyCopy([u8; ed25519::SECRET_KEY_LENGTH]);


impl ActorPublicKeyV1 {
	pub fn from_bytes(bytes: [u8; 57]) -> Result<Self, ActorPublicKeyV1Error> { Ok(Self(bytes)) }

	pub fn generate_address(&self) -> IdType {
		let mut hasher = Sha3_256::new();
		hasher.update(&self.0);
		let buffer: [u8; 32] = hasher.finalize().into();
		buffer.into()
	}

	pub fn to_bytes(self) -> [u8; 57] { self.0 }

	pub fn verify(&self, message: &[u8], signature: &ActorSignatureV1) -> bool {
		let inner = ed448::PublicKey::from(self.0.clone());
		inner.verify(message, &signature.0, None).is_ok()
	}
}

impl ActorPrivateKeyV1 {
	pub fn as_bytes(&self) -> &[u8; ed448::KEY_LENGTH] { self.0.as_bytes() }

	pub fn from_bytes(bytes: [u8; ed448::KEY_LENGTH]) -> Self {
		Self(ed448::PrivateKey::from(bytes))
	}

	pub fn generate_with_rng<R>(rng: &mut R) -> Self
	where
		R: CryptoRng + RngCore,
	{
		Self(ed448::PrivateKey::new(rng))
	}

	pub fn public(&self) -> ActorPublicKeyV1 {
		ActorPublicKeyV1(ed448::PublicKey::from(&self.0).as_byte())
	}

	pub fn sign(&self, message: &[u8]) -> ActorSignatureV1 {
		ActorSignatureV1(self.0.sign(message, None).expect("sign error"))
	}
}

impl ActorSignatureV1 {
	pub fn as_bytes(&self) -> &[u8; ed448::SIG_LENGTH] { &self.0 }

	pub fn from_bytes(bytes: [u8; ed448::SIG_LENGTH]) -> Self { Self(bytes) }

	pub fn hash(&self) -> IdType { IdType::hash(self.as_bytes()) }

	pub fn to_bytes(self) -> [u8; ed448::SIG_LENGTH] { self.0 }
}

impl sea_orm::TryGetable for ActorSignatureV1 {
	fn try_get_by<I: ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
		let buffer = <Vec<u8> as sea_orm::TryGetable>::try_get_by(res, index)?;
		Ok(Self::from_bytes(buffer.try_into().map_err(
			|b: Vec<u8>| {
				/*TryGetError::DbErr(DbErr::TryIntoErr {
					from: "Vec<u8>",
					into: "ActorSignatureV1",
					source: Box::new(e),
				})*/
				TryGetError::Null(format!(
					"wrong number of bytes: {}, expected: {}",
					b.len(),
					ed448::SIG_LENGTH
				))
			},
		)?))
	}
}

impl Into<sea_orm::Value> for ActorSignatureV1 {
	fn into(self) -> sea_orm::Value {
		sea_orm::Value::Bytes(Some(Box::new(self.to_bytes().to_vec())))
	}
}

impl sea_orm::sea_query::Nullable for ActorSignatureV1 {
	fn null() -> sea_orm::Value { sea_orm::Value::Bytes(None) }
}

impl sea_orm::sea_query::ValueType for ActorSignatureV1 {
	fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
		match v {
			sea_orm::Value::Bytes(ob) =>
				if let Some(bytes) = ob {
					match (*bytes).try_into() {
						Err(_) => Err(sea_orm::sea_query::ValueTypeErr),
						Ok(array) => Ok(Self::from_bytes(array)),
					}
				} else {
					Err(sea_orm::sea_query::ValueTypeErr)
				},
			_ => Err(sea_orm::sea_query::ValueTypeErr),
		}
	}

	fn type_name() -> String { "IdType".to_owned() }

	fn array_type() -> sea_orm::sea_query::ArrayType { sea_orm::sea_query::ArrayType::String }

	fn column_type() -> sea_orm::ColumnType { sea_orm::ColumnType::String(Some(45)) }
}

impl NodePublicKey {
	pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, NodePublicKeyError> {
		Ok(Self(
			ed25519::VerifyingKey::from_bytes(&bytes).map_err(|e| NodePublicKeyError(e))?,
		))
	}

	pub fn generate_address(&self) -> IdType {
		let mut hasher = Sha3_256::new();
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
		let this = Self::new(ed25519::SigningKey::from_bytes(&bytes));
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
		Self::new(ed25519::SigningKey::generate(rng))
	}

	fn new(inner: ed25519::SigningKey) -> Self {
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
				if bytes.len() >= ed25519::SECRET_KEY_LENGTH {
					FromSqlResult::Ok(NodePrivateKey::from_bytes(
						bytes[..ed25519::SECRET_KEY_LENGTH].try_into().unwrap(),
					))
				} else {
					FromSqlResult::Err(FromSqlError::InvalidBlobSize {
						expected_size: ed25519::SECRET_KEY_LENGTH,
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
	fn clone(&self) -> Self { Self::new(ed25519::SigningKey::from_bytes(&self.inner.to_bytes())) }
}

impl NodeSignature {
	pub fn to_bytes(&self) -> [u8; 64] { self.0.to_bytes() }

	pub fn from_bytes(bytes: [u8; 64]) -> Self { Self(ed25519::Signature::from_bytes(&bytes)) }

	pub fn hash(&self) -> IdType { IdType::hash(&self.to_bytes()) }
}

impl From<ed25519::VerifyingKey> for NodePublicKey {
	fn from(other: ed25519::VerifyingKey) -> Self { Self(other) }
}

impl Clone for NodePublicKey {
	fn clone(&self) -> Self { Self(ed25519::VerifyingKey::from_bytes(self.0.as_bytes()).unwrap()) }
}

impl Deref for NodePublicKey {
	type Target = ed25519::VerifyingKey;

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
		let bytes: [u8; ed25519::PUBLIC_KEY_LENGTH] = Deserialize::deserialize(d)?;
		Ok(Self(ed25519::VerifyingKey::from_bytes(&bytes).unwrap()))
	}
}

impl Serialize for NodePublicKey {
	fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		Serialize::serialize(&self.0.to_bytes(), s)
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
		let actor_public_key = ActorPublicKeyV1::from_bytes([0u8; ed448::KEY_LENGTH]).unwrap();
		assert_eq!(
			binserde::serialized_size(&actor_public_key).unwrap(),
			ed448::KEY_LENGTH
		);

		let signature = ActorSignatureV1::from_bytes([0u8; ed448::SIG_LENGTH]);
		assert_eq!(
			binserde::serialized_size(&signature).unwrap(),
			ed448::SIG_LENGTH
		);

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

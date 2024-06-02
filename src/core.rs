use std::{
	borrow::Cow,
	fmt::Display,
	ops::{Deref, DerefMut},
	str::{self, FromStr},
	sync::Arc,
};

use base58::{FromBase58, FromBase58Error, ToBase58};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{common::*, identity::*};
use crate::net::binserde;


pub const ACTOR_TYPE_BLOGCHAIN: &str = "blogchain";


#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize)]
pub enum ActorAddress {
	/// The first version of the actor address is a SHA256 hash of ActorInfoV1.
	V1(IdType),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ActorInfo {
	V1(ActorInfoV1),
}

///
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Address {
	Node(NodeAddress),
	Actor(ActorAddress),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ActorInfoV1 {
	pub flags: u8,
	pub public_key: ActorPublicKeyV1,
	pub first_object: IdType,
	pub actor_type: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Block {
	pub hash: IdType,
	pub data: Arc<Vec<u8>>,
}

#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
pub enum CompressionType {
	None   = 0,
	Brotli = 1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ShareObject {
	pub actor_address: ActorAddress,
	pub object_hash: IdType,
}

#[derive(Default)]
pub struct FileData {
	pub mime_type: String,
	pub data: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct File {
	pub plain_hash: IdType,
	pub mime_type: String,
	pub compression_type: u8,
	pub blocks: Vec<IdType>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileHeader {
	pub hash: IdType,
	pub mime_type: String,
	pub block_count: u32,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize)]
pub enum NodeAddress {
	/// The first version of the node address refers to a ed448 keypair.
	V1(IdType),
}

#[derive(Debug, Error)]
pub enum ParseAddressError {
	#[error("empty string")]
	Empty,
	#[error("invalid base58")]
	FromBase58(FromBase58Error),
	#[error("{0}")]
	FromBytes(#[from] FromBytesAddressError),
	#[error("unknown prefix: {0}")]
	InvalidPrefix(char),
}

#[derive(Debug, Error)]
pub enum FromBytesAddressError {
	#[error("buffer is empty")]
	Empty,
	#[error("unknown type: {0}")]
	UnknownType(u8),
	#[error("invalid version: {0}")]
	InvalidVersion(u8),
	#[error("invalid size: {0}")]
	InvalidSize(usize),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PostObject {
	/// If this post is a reply, a tuple of the actor's ID and the post.
	pub in_reply_to: Option<(ActorAddress, IdType)>,
	pub data: PostObjectCryptedData,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PostObjectCryptedData {
	Plain(PostObjectDataPlain),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PostObjectDataPlain {
	/// Searchable keywords
	pub tags: Vec<String>,
	/// A list of (mime-type, hash) tuples.
	pub files: Vec<IdType>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PostObjectInfo {
	base: PostObject,
	in_reply_to: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProfileObject {
	pub name: String,
	pub avatar: Option<IdType>,
	pub wallpaper: Option<IdType>,
	pub description: Option<IdType>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlogchainObject {
	pub signature: ActorSignatureV1,
	pub sequence: u64,
	pub previous_hash: IdType,
	pub created: u64,
	pub payload: ObjectPayload,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObjectSignData<'a> {
	pub sequence: u64,
	pub previous_hash: IdType,
	pub created: u64,
	pub payload: &'a ObjectPayload,
}

pub const OBJECT_TYPE_PROFILE: u8 = 0;
pub const OBJECT_TYPE_POST: u8 = 1;
pub const OBJECT_TYPE_SHARE: u8 = 2;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ObjectPayload {
	Profile(ProfileObject),
	Post(PostObject),
	Share(ShareObject),
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ObjectHeader {
	pub index: u64,
	pub signature: ActorSignatureV1,
}


impl ActorAddress {
	pub fn as_id<'a>(&'a self) -> Cow<'a, IdType> {
		match self {
			Self::V1(id) => Cow::Borrowed(id),
		}
	}

	pub fn from_bytes(buffer: &[u8]) -> Result<Self, FromBytesAddressError> {
		if buffer.len() != 33 {
			return Err(FromBytesAddressError::InvalidSize(buffer.len() - 1));
		}
		let version = buffer[0];
		if version != 0 {
			return Err(FromBytesAddressError::InvalidVersion(version));
		}
		Ok(Self::V1(IdType::from_bytes(array_ref![buffer, 1, 32])))
	}

	pub fn new(version: u8, buffer: Vec<u8>) -> Result<Self, FromBytesAddressError> {
		if version != 0 {
			return Err(FromBytesAddressError::InvalidVersion(version));
		}
		if buffer.len() != 32 {
			return Err(FromBytesAddressError::InvalidSize(buffer.len()));
		}
		Ok(Self::V1(IdType::from_bytes(array_ref![buffer, 0, 32])))
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		match self {
			Self::V1(this) => {
				let mut buffer = vec![0u8; 33];
				buffer[1..33].copy_from_slice(&this.0);
				buffer
			}
		}
	}

	#[allow(dead_code)]
	pub fn to_id(self) -> IdType {
		match self {
			Self::V1(this) => this,
		}
	}

	pub fn version(&self) -> u8 { 0 }
}

impl ToBase58 for ActorAddress {
	fn to_base58(&self) -> String { self.to_bytes().to_base58() }
}

impl Display for ActorAddress {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let addr = Address::Actor(self.clone());
		addr.fmt(f)
	}
}

impl Into<sea_orm::Value> for &ActorAddress {
	fn into(self) -> sea_orm::Value { sea_orm::Value::Bytes(Some(Box::new(self.to_bytes()))) }
}

impl sea_orm::sea_query::Nullable for ActorAddress {
	fn null() -> sea_orm::Value { sea_orm::Value::Bytes(None) }
}

impl sea_orm::TryGetable for ActorAddress {
	fn try_get_by<I: sea_orm::ColIdx>(
		res: &sea_orm::QueryResult, index: I,
	) -> Result<Self, sea_orm::TryGetError> {
		let bytes = <Vec<u8> as sea_orm::TryGetable>::try_get_by(res, index)?;
		Ok(Self::from_bytes(&bytes).map_err(|e| {
			sea_orm::TryGetError::DbErr(sea_orm::DbErr::TryIntoErr {
				from: "Vec<u8>",
				into: "ActorAddress",
				source: Box::new(e),
			})
		})?)
	}
}

impl Into<sea_orm::Value> for ActorAddress {
	fn into(self) -> sea_orm::Value { sea_orm::Value::Bytes(Some(Box::new(self.to_bytes()))) }
}

impl sea_orm::sea_query::ValueType for ActorAddress {
	fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
		match v {
			sea_orm::Value::Bytes(b) =>
				if let Some(bytes) = b {
					Ok(Self::from_bytes(&bytes).map_err(|_| sea_orm::sea_query::ValueTypeErr)?)
				} else {
					Err(sea_orm::sea_query::ValueTypeErr)
				},
			_ => Err(sea_orm::sea_query::ValueTypeErr),
		}
	}

	fn type_name() -> String { "ActorAddress".to_owned() }

	fn array_type() -> sea_orm::sea_query::ArrayType { sea_orm::sea_query::ArrayType::Bytes }

	fn column_type() -> sea_orm::ColumnType {
		sea_orm::ColumnType::Binary(sea_orm::sea_query::BlobSize::Blob(None))
	}
}

impl Address {
	pub fn from_bytes(buffer: &[u8]) -> Result<Self, FromBytesAddressError> {
		if buffer.len() == 0 {
			return Err(FromBytesAddressError::Empty);
		}

		let type_id = buffer[0];
		match type_id {
			0 => Ok(Address::Node(NodeAddress::from_bytes(&buffer[1..])?)),
			1 => Ok(Address::Actor(ActorAddress::from_bytes(&buffer[1..])?)),
			_ => Err(FromBytesAddressError::UnknownType(type_id)),
		}
	}

	pub fn parse_new(string: &str) -> Result<Self, ParseAddressError> {
		if string.len() == 0 {
			return Err(ParseAddressError::Empty);
		}

		let first_char = string.chars().next().unwrap();
		let address = match first_char {
			'a' => Address::Actor(ActorAddress::from_bytes(&string[1..].from_base58()?)?),
			'n' => Address::Node(NodeAddress::from_bytes(&string[1..].from_base58()?)?),
			other => return Err(ParseAddressError::InvalidPrefix(other)),
		};
		Ok(address)
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		match self {
			Self::Node(address) => {
				let mut buffer = vec![0; 1];
				buffer.extend(address.to_bytes());
				buffer
			}
			Self::Actor(address) => {
				let mut buffer = vec![1; 1];
				buffer.extend(address.to_bytes());
				buffer
			}
		}
	}

	pub fn to_base58(&self) -> String {
		let buffer = self.to_bytes();
		buffer.to_base58()
	}
}

impl Display for Address {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Actor(addr) => write!(f, "a{}", addr.to_base58()),
			Self::Node(addr) => write!(f, "n{}", addr.to_base58()),
		}
	}
}

impl FromStr for Address {
	type Err = ParseAddressError;

	fn from_str(string: &str) -> Result<Self, ParseAddressError> {
		if string.len() == 0 {
			return Err(ParseAddressError::Empty);
		}

		// Old-style addresses
		let first_char = string.chars().next().unwrap();
		if first_char == '1' || first_char == '2' {
			let buffer = string.from_base58()?;
			Ok(Self::from_bytes(&buffer)?)
		// New-style addresses
		} else {
			Self::parse_new(string)
		}
	}
}

impl ActorInfo {
	pub fn generate_address(&self) -> ActorAddress {
		match self {
			Self::V1(this) => ActorAddress::V1(this.generate_id()),
		}
	}
}

impl Deref for ActorInfo {
	type Target = ActorInfoV1;

	fn deref(&self) -> &Self::Target {
		match self {
			Self::V1(this) => this,
		}
	}
}

impl DerefMut for ActorInfo {
	fn deref_mut(&mut self) -> &mut Self::Target {
		match self {
			Self::V1(this) => this,
		}
	}
}

impl ActorInfoV1 {
	pub fn generate_id(&self) -> IdType {
		let buffer = binserde::serialize(self).unwrap();
		IdType::hash(&buffer)
	}
}

impl CompressionType {
	pub fn from_u8(code: u8) -> Option<Self> {
		match code {
			0 => Some(Self::None),
			1 => Some(Self::Brotli),
			_ => None,
		}
	}
}

impl NodeAddress {
	pub fn as_id<'a>(&'a self) -> Cow<'a, IdType> {
		match self {
			Self::V1(id) => Cow::Borrowed(id),
		}
	}

	pub fn to_bytes(&self) -> Vec<u8> { binserde::serialize(&self).unwrap() }

	pub fn from_bytes(buffer: &[u8]) -> Result<Self, FromBytesAddressError> {
		let version = buffer[0];
		if version != 0 {
			return Err(FromBytesAddressError::InvalidVersion(version));
		}
		if buffer.len() != 33 {
			return Err(FromBytesAddressError::InvalidSize(buffer.len() - 1));
		}
		Ok(Self::V1(IdType::from_bytes(array_ref![buffer, 1, 32])))
	}
}

impl ToBase58 for NodeAddress {
	fn to_base58(&self) -> String { self.to_bytes().to_base58() }
}

impl Display for NodeAddress {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let addr = Address::Node(self.clone());
		addr.fmt(f)
	}
}

impl Into<sea_orm::Value> for NodeAddress {
	fn into(self) -> sea_orm::Value { sea_orm::Value::Bytes(Some(Box::new(self.to_bytes()))) }
}

impl Into<sea_orm::Value> for &NodeAddress {
	fn into(self) -> sea_orm::Value { sea_orm::Value::Bytes(Some(Box::new(self.to_bytes()))) }
}

impl sea_orm::sea_query::Nullable for NodeAddress {
	fn null() -> sea_orm::Value { sea_orm::Value::Bytes(None) }
}

impl sea_orm::TryGetable for NodeAddress {
	fn try_get_by<I: sea_orm::ColIdx>(
		res: &sea_orm::QueryResult, index: I,
	) -> Result<Self, sea_orm::TryGetError> {
		let bytes = <Vec<u8> as sea_orm::TryGetable>::try_get_by(res, index)?;
		Ok(Self::from_bytes(&bytes).map_err(|e| {
			sea_orm::TryGetError::DbErr(sea_orm::DbErr::TryIntoErr {
				from: "Vec<u8>",
				into: "NodeAddress",
				source: Box::new(e),
			})
		})?)
	}
}

impl sea_orm::sea_query::ValueType for NodeAddress {
	fn try_from(v: sea_orm::Value) -> Result<Self, sea_orm::sea_query::ValueTypeErr> {
		match v {
			sea_orm::Value::Bytes(b) =>
				if let Some(bytes) = b {
					Ok(Self::from_bytes(&bytes).map_err(|_| sea_orm::sea_query::ValueTypeErr)?)
				} else {
					Err(sea_orm::sea_query::ValueTypeErr)
				},
			_ => Err(sea_orm::sea_query::ValueTypeErr),
		}
	}

	fn type_name() -> String { "NodeAddress".to_owned() }

	fn array_type() -> sea_orm::sea_query::ArrayType { sea_orm::sea_query::ArrayType::Bytes }

	fn column_type() -> sea_orm::ColumnType {
		sea_orm::ColumnType::Binary(sea_orm::sea_query::BlobSize::Blob(None))
	}
}

impl ObjectPayload {
	pub fn type_id(&self) -> u8 {
		match self {
			Self::Profile(_) => OBJECT_TYPE_PROFILE,
			Self::Post(_) => OBJECT_TYPE_POST,
			Self::Share(_) => OBJECT_TYPE_SHARE,
		}
	}
}

impl From<FromBase58Error> for ParseAddressError {
	fn from(other: FromBase58Error) -> Self { Self::FromBase58(other) }
}

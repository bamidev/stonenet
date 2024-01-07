use std::{error::Error, fmt, ops, str};

use async_trait::async_trait;
use base58::*;
use num::bigint::BigUint;
use rusqlite::types::*;
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};


#[async_trait]
pub trait AsyncIterator {
	type Item;

	async fn next(&mut self) -> Option<Self::Item>;

	async fn count(&mut self) -> usize {
		let mut i = 0;
		while let Some(_) = self.next().await {
			i += 1;
		}
		i
	}
}

#[derive(Clone, Default, Deserialize, Eq, Hash, PartialEq)]
pub struct IdType(pub(crate) [u8; 32]);

#[derive(Debug)]
pub enum IdFromBase58Error {
	FromBase58Error(FromBase58Error),
	TooLong,
	TooShort,
}


/// If the bytes differ, returns the index of the bit (little endian),
/// otherwise, returns 0xFF indicating no change
fn differs_at_bit_u8(a: u8, b: u8) -> u8 {
	let x = a ^ b;
	for i in 0..8 {
		if ((x >> i) & 0x1) != 0 {
			return i;
		}
	}
	return 0xFF;
}


impl IdType {
	pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

	/// Returns the index of the bit at which this ID differs with another.
	/// The first bit, at index 0, is the least significant bit at the first
	/// byte. Useful to get an approximation of the distance between ID's.
	pub fn differs_at_bit(&self, other: &IdType) -> Option<u8> {
		for i in 0..32 {
			let x = differs_at_bit_u8(self.0[i] as _, other.0[i] as _) as usize;
			if x < 8 {
				return Some((i * 8 + x) as u8);
			}
		}
		None
	}

	pub fn distance(&self, other: &IdType) -> BigUint {
		// Calculating this is a bit weird, because the first bit (0x01) of the first
		// byte is the most significant. In big-endian encoding, the last bit (0x80) of
		// the first byte would be the most significant.
		let mut c = IdType::default();
		for i in 0..32 {
			let ci = &mut c.0[i];
			*ci = self.0[i] ^ other.0[i];
			// Mirror the bits
			*ci = (*ci << 7)
				| ((*ci & 0x02) << 5)
				| ((*ci & 0x04) << 3)
				| ((*ci & 0x08) << 1)
				| ((*ci & 0x10) >> 1)
				| ((*ci & 0x20) >> 3)
				| ((*ci & 0x40) >> 5)
				| (*ci >> 7)
		}
		BigUint::from_bytes_be(&c.0)
	}

	pub fn from_base58(string: &str) -> Result<Self, IdFromBase58Error> {
		let buffer = string.from_base58()?;
		if buffer.len() > 32 {
			Err(IdFromBase58Error::TooLong)
		} else if buffer.len() < 32 {
			Err(IdFromBase58Error::TooShort)
		} else {
			Ok(Self(buffer.try_into().unwrap()))
		}
	}

	pub fn from_bytes(bytes: &[u8; 32]) -> Self { Self(bytes.clone()) }

	pub fn from_slice(bytes: &[u8]) -> Option<Self> {
		if bytes.len() < 32 {
			None
		} else {
			Some(Self(bytes[..32].try_into().unwrap()))
		}
	}

	pub fn hash(bytes: &[u8]) -> Self {
		let mut hasher = Sha256::new();
		hasher.update(bytes);
		let buffer: [u8; 32] = hasher.finalize().into();
		buffer.into()
	}

	pub fn new(bytes: [u8; 32]) -> Self { Self(bytes.into()) }
}

impl ops::BitXor<&IdType> for IdType {
	type Output = Self;

	fn bitxor(self, other: &Self) -> Self::Output {
		let mut result = Self::default();
		for i in 0..32 {
			result.0[i] = self.0[i] ^ other.0[i];
		}
		result
	}
}

impl ops::BitXorAssign for IdType {
	fn bitxor_assign(&mut self, other: Self) {
		for i in 0..32 {
			self.0[i] ^= other.0[i];
		}
	}
}

impl fmt::Debug for IdType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.to_base58()) }
}

impl From<[u8; 32]> for IdType {
	fn from(other: [u8; 32]) -> Self { Self(other) }
}

impl FromSql for IdType {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Text(data) => {
				let string = str::from_utf8(data).map_err(|e| FromSqlError::Other(Box::new(e)))?;
				IdType::from_base58(string.as_ref()).map_err(|e| FromSqlError::Other(Box::new(e)))
			}
			_ => FromSqlResult::Err(FromSqlError::InvalidType),
		}
	}
}

impl fmt::Display for IdType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.to_base58()) }
}

impl Serialize for IdType {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		if serializer.is_human_readable() {
			self.to_base58().serialize(serializer)
		} else {
			self.0.serialize(serializer)
		}
	}
}

impl ToBase58 for IdType {
	fn to_base58(&self) -> String { self.0.to_base58() }
}

impl ToSql for IdType {
	fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
		Ok(ToSqlOutput::Owned(Value::Text(self.to_string())))
	}
}

impl From<FromBase58Error> for IdFromBase58Error {
	fn from(other: FromBase58Error) -> Self { Self::FromBase58Error(other) }
}

impl fmt::Display for IdFromBase58Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::FromBase58Error(e) => match e {
				FromBase58Error::InvalidBase58Character(c, s) => {
					write!(f, "invalid base58 character {} at index {}", c, s)
				}
				FromBase58Error::InvalidBase58Length => {
					write!(f, "invalid length for a base58 string")
				}
			},
			Self::TooLong => write!(f, "string to long"),
			Self::TooShort => write!(f, "string to short"),
		}
	}
}

impl Error for IdFromBase58Error {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_eq() {
		let a = IdType::from_base58("6iAN6tcmd7DxXie3kXnaFFvge7U3WHCEjJLC4gB269No").unwrap();
		let b = IdType::from_base58("6iAN6tcmd7DxXie3kXnaFFvge7U3WHCEjJLC4gB269No").unwrap();
		assert!(a == b);
	}
}

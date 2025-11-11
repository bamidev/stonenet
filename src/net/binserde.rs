use std::io::Write;

use bincode::Options;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::sstp;
use crate::trace::Traced;

pub type Error = bincode::Error;

pub fn deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> bincode::Result<T> {
	let options = bincode::options()
		.with_varint_encoding()
		.reject_trailing_bytes();

	options.deserialize(bytes)
}

pub fn deserialize_sstp<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> sstp::Result<T> {
	deserialize(bytes).map_err(|e| Traced::capture(e.into()))
}

pub fn deserialize_owned<T: DeserializeOwned>(bytes: &[u8]) -> bincode::Result<T> {
	let options = bincode::options()
		.with_varint_encoding()
		.reject_trailing_bytes();

	options.deserialize_from(bytes)
}

pub fn deserialize_with_trailing<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> bincode::Result<T> {
	let options = bincode::options()
		.with_varint_encoding()
		.allow_trailing_bytes();

	options.deserialize(bytes)
}

pub fn serialize<S: ?Sized + Serialize>(t: &S) -> bincode::Result<Vec<u8>> {
	let options = bincode::options()
		.with_varint_encoding()
		.reject_trailing_bytes();

	options.serialize(t)
}

pub fn serialize_into<S: ?Sized + Serialize, W: Write>(w: W, t: &S) -> bincode::Result<()> {
	let options = bincode::options()
		.with_varint_encoding()
		.reject_trailing_bytes();

	options.serialize_into(w, t)
}

pub fn serialized_size<T: ?Sized>(value: &T) -> bincode::Result<usize>
where
	T: Serialize,
{
	let options = bincode::options()
		.with_varint_encoding()
		.reject_trailing_bytes();

	options.serialized_size(value).map(|s| s as _)
}

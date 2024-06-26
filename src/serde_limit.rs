use std::{
	collections::VecDeque,
	fmt,
	marker::PhantomData,
	ops::{Deref, DerefMut},
};

use concat_idents::concat_idents;
use serde::{
	de::{Error, SeqAccess, Visitor},
	Deserialize, Deserializer, Serialize, Serializer,
};


const N_KILO: usize = 1 << 10;
const N_MEGA: usize = 1 << 20;


#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct LimVec<T, L>
where
	T: Serialize,
	L: Limit,
{
	inner: Vec<T>,
	#[serde(skip_serializing)]
	_phantom: PhantomData<L>,
}

struct LimVecVisitor<T, L>(PhantomData<(T, L)>);

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LimString<L>(LimVec<u8, L>)
where
	L: Limit;

pub trait Limit {
	fn limit() -> usize;
}


#[allow(unused)]
impl<T, L> LimVec<T, L>
where
	T: Serialize,
	L: Limit,
{
	pub fn empty() -> Self {
		Self {
			inner: Vec::new(),
			_phantom: PhantomData,
		}
	}

	pub fn new(inner: Vec<T>) -> Option<Self> {
		if inner.len() > L::limit() {
			return None;
		}
		Some(Self {
			inner,
			_phantom: PhantomData,
		})
	}
}

impl<T, L> LimVec<T, L>
where
	T: Clone + Serialize,
	L: Limit,
{
	pub fn new_limitted(mut inner: Vec<T>) -> Self {
		if inner.len() > L::limit() {
			// TODO: Resize without cloning the first element, which isn't needed as it
			// always shrinks in this scenario
			inner.resize(L::limit(), inner.get(0).unwrap().clone());
		}
		Self {
			inner,
			_phantom: PhantomData,
		}
	}
}

impl<T, L> Deref for LimVec<T, L>
where
	T: Serialize,
	L: Limit,
{
	type Target = Vec<T>;

	fn deref(&self) -> &Self::Target { &self.inner }
}

impl<T, L> DerefMut for LimVec<T, L>
where
	T: Serialize,
	L: Limit,
{
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner }
}

impl<'de, T, L> Deserialize<'de> for LimVec<T, L>
where
	T: Deserialize<'de> + Serialize,
	L: Limit,
{
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let inner = deserializer.deserialize_seq(LimVecVisitor::<T, L>(PhantomData))?;
		Ok(Self {
			inner,
			_phantom: PhantomData,
		})
	}
}

impl<'de, T, L> Visitor<'de> for LimVecVisitor<T, L>
where
	T: Deserialize<'de>,
	L: Limit,
{
	type Value = Vec<T>;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str(&format!("a sequence with limit {}", L::limit()))
	}

	fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
	where
		A: SeqAccess<'de>,
	{
		let size = seq.size_hint().expect("no size hint");
		if size > L::limit() {
			return Err(A::Error::custom(format!(
				"sequence with size {} went over limit {}",
				size,
				L::limit()
			)));
		}
		let mut values = Vec::<T>::with_capacity(size);

		while let Some(value) = seq.next_element()? {
			values.push(value);
		}

		Ok(values)
	}
}

impl<T, L> From<Vec<T>> for LimVec<T, L>
where
	T: Clone + Serialize,
	L: Limit,
{
	fn from(inner: Vec<T>) -> Self { Self::new_limitted(inner) }
}

impl<T, L> From<VecDeque<T>> for LimVec<T, L>
where
	T: Clone + Serialize,
	L: Limit,
{
	fn from(vec: VecDeque<T>) -> Self { Self::new_limitted(vec.into()) }
}

impl<T, L> Into<Vec<T>> for LimVec<T, L>
where
	T: Serialize,
	L: Limit,
{
	fn into(self) -> Vec<T> { self.inner }
}

impl<T, L> IntoIterator for LimVec<T, L>
where
	T: Serialize,
	L: Limit,
{
	type IntoIter = <Vec<T> as IntoIterator>::IntoIter;
	type Item = T;

	fn into_iter(self) -> Self::IntoIter { self.inner.into_iter() }
}

impl<'a, T, L> IntoIterator for &'a LimVec<T, L>
where
	T: Serialize,
	L: Limit,
{
	type IntoIter = <&'a Vec<T> as IntoIterator>::IntoIter;
	type Item = &'a T;

	fn into_iter(self) -> Self::IntoIter { (&self.inner).into_iter() }
}

#[allow(unused)]
impl<L> LimString<L>
where
	L: Limit,
{
	pub fn as_str(&self) -> &str { unsafe { std::str::from_utf8_unchecked(&self.0.inner) } }

	pub fn empty(&self) -> Self { Self(LimVec::empty()) }

	pub fn into_string(self) -> String { unsafe { String::from_utf8_unchecked(self.0.inner) } }

	pub fn new(inner: String) -> Option<Self> { LimVec::new(inner.into_bytes()).map(|r| Self(r)) }

	pub fn to_string(&self) -> String {
		unsafe { String::from_utf8_unchecked(self.0.inner.clone()) }
	}
}

impl<L> Deref for LimString<L>
where
	L: Limit,
{
	type Target = Vec<u8>;

	fn deref(&self) -> &Self::Target { &self.0.inner }
}

impl<'de, L> Deserialize<'de> for LimString<L>
where
	L: Limit,
{
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		let inner = deserializer.deserialize_seq(LimVecVisitor::<u8, L>(PhantomData))?;
		Ok(Self(LimVec {
			inner,
			_phantom: PhantomData,
		}))
	}
}

impl<L> DerefMut for LimString<L>
where
	L: Limit,
{
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0.inner }
}

impl<L> From<String> for LimString<L>
where
	L: Limit,
{
	fn from(inner: String) -> Self { Self(LimVec::from(inner.into_bytes())) }
}

impl<L> From<&String> for LimString<L>
where
	L: Limit,
{
	fn from(string: &String) -> Self { Self(LimVec::from(string.clone().into_bytes())) }
}

impl<L> From<&str> for LimString<L>
where
	L: Limit,
{
	fn from(inner: &str) -> Self { Self(LimVec::from(inner.as_bytes().to_vec())) }
}

impl<L> Into<String> for LimString<L>
where
	L: Limit,
{
	fn into(self) -> String { String::from_utf8_lossy(&self.0.inner).to_string() }
}

impl<L> Serialize for LimString<L>
where
	L: Limit,
{
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		debug_assert!(self.len() <= L::limit());
		serializer.serialize_bytes(&self.0.inner)
	}
}


macro_rules! def_limit {
    ( $name:expr, $l:expr ) => {
        concat_idents!(struct_name = Limit, $name {
            #[derive(Clone, Debug, Default, PartialEq)]
            pub struct struct_name;

            impl Limit for struct_name {
                fn limit() -> usize { $l }
            }
        });
    }
}

def_limit!(4, 4);
def_limit!(32, 32);
def_limit!(64, 64);
def_limit!(255, 255);
def_limit!(256, 256);
def_limit!(10K, 10 * N_KILO);
def_limit!(1M, N_MEGA);
def_limit!(10M, 10 * N_MEGA);


pub type LimitMimeType = Limit255;


#[cfg(test)]
mod tests {
	use super::*;
	use crate::net::binserde;

	#[test]
	fn test_serde_limit() {
		let info: Vec<u32> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
		let lim_info: LimVec<u32, Limit256> = info.clone().into();
		assert_eq!(info, lim_info.to_vec());
		let string: String = "This is a string...".into();
		let lim_string: LimString<Limit256> = string.clone().into();
		assert_eq!(string, lim_string.to_string());

		// Check if serialization creates the exact same data as the original type
		let original_data = binserde::serialize(&string).unwrap();
		let limitted_data = binserde::serialize(&lim_string).unwrap();
		assert_eq!(original_data, limitted_data);
		let original_data = binserde::serialize(&info).unwrap();
		let limitted_data = binserde::serialize(&lim_info).unwrap();
		assert_eq!(original_data, limitted_data);

		// Check if the limit is applied
		let this: LimString<Limit4> = string.into();
		assert_eq!(this.to_string(), "This".to_string());
	}
}

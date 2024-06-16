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


#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone)]
pub struct LimString<L>(LimVec<u8, L>)
where
	L: Limit;

pub trait Limit {
	fn limit() -> usize;
}


impl<T, L> LimVec<T, L>
where
	T: Serialize,
	L: Limit,
{
	pub fn new() -> Self {
		Self {
			inner: Vec::new(),
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
	T: Serialize,
	L: Limit,
{
	fn from(inner: Vec<T>) -> Self {
		Self {
			inner,
			_phantom: PhantomData,
		}
	}
}

impl<T, L> From<VecDeque<T>> for LimVec<T, L>
where
	T: Serialize,
	L: Limit,
{
	fn from(vec: VecDeque<T>) -> Self {
		Self {
			inner: vec.into(),
			_phantom: PhantomData,
		}
	}
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

impl<L> LimString<L>
where
	L: Limit,
{
	pub fn new() -> Self { Self(LimVec::new()) }
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
		serializer.serialize_bytes(&self.0.inner)
	}
}


macro_rules! def_limit {
    ( $name:expr, $l:expr ) => {
        concat_idents!(struct_name = Limit, $name {
            #[derive(Debug)]
            pub struct struct_name;

            impl Limit for struct_name {
                fn limit() -> usize { $l }
            }
        });
    }
}

def_limit!(4, 4);
def_limit!(256, 256);
def_limit!(255, 255);
def_limit!(10K, 10 * N_KILO);
def_limit!(1M, N_MEGA);
def_limit!(10M, 10 * N_MEGA);


pub type LimitMimeType = Limit255;

#![allow(dead_code)]

use std::{
	backtrace::Backtrace,
	error::Error,
	fmt::{Debug, Display},
	ops::{Deref, DerefMut},
	result::Result as StdResult,
};


pub type Result<T, E> = StdResult<T, Traced<E>>;

pub trait Traceable<E> {
	fn trace(self) -> Traced<E>;
}

pub trait TraceableResult<T, E> {
	fn trace_result(self) -> self::Result<T, E>;
}

pub struct Traced<E> {
	inner: E,
	#[cfg(debug_assertions)]
	backtrace: Backtrace,
}


/// Encapsulates the given error into a `Traced` struct, which includes tracing
/// information.
pub fn err<T, E>(inner: E) -> Result<T, E> {
	Err(Traced {
		inner,
		#[cfg(debug_assertions)]
		backtrace: Backtrace::force_capture(),
	})
}


impl<E> Traceable<E> for E {
	fn trace(self) -> Traced<E> { Traced::new(self) }
}

impl<T, E> TraceableResult<T, E> for StdResult<T, E> {
	fn trace_result(self) -> self::Result<T, E> { self.map_err(|e| Traced::new(e)) }
}

impl<T> Traced<T> {
	pub fn new(inner: T) -> Self {
		Self {
			inner,
			#[cfg(debug_assertions)]
			backtrace: Backtrace::force_capture(),
		}
	}

	#[cfg(debug_assertions)]
	pub fn backtrace(&self) -> Option<&Backtrace> { Some(&self.backtrace) }

	#[cfg(not(debug_assertions))]
	pub fn backtrace(&self) -> Option<&Backtrace> { None }

	#[cfg(debug_assertions)]
	pub fn unwrap(self) -> (T, Option<Backtrace>) { (self.inner, Some(self.backtrace)) }

	#[cfg(not(debug_assertions))]
	pub fn unwrap(self) -> (T, Option<Backtrace>) { (self.inner, None) }
}

impl<E> From<E> for Traced<E> {
	fn from(other: E) -> Self { Self::new(other) }
}

impl<E> Clone for Traced<E>
where
	E: Clone,
{
	fn clone(&self) -> Self { Self::new(self.inner.clone()) }
}

impl<E> Deref for Traced<E> {
	type Target = E;

	fn deref(&self) -> &Self::Target { &self.inner }
}

impl<E> DerefMut for Traced<E> {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner }
}

impl<E> Debug for Traced<E>
where
	E: Debug,
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(f, "{:?}", &self.inner)?;
		if let Some(b) = self.backtrace() {
			write!(f, "{}", b)?;
		}
		Ok(())
	}
}

impl<E> Display for Traced<E>
where
	E: Display,
{
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", &self.inner)
	}
}

impl<E> Error for Traced<E>
where
	E: Error,
{
	fn source(&self) -> Option<&(dyn Error + 'static)> { self.inner.source() }
}

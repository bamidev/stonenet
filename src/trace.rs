use std::{
	backtrace::Backtrace,
	error::Error,
	fmt::{Debug, Display},
	ops::{Deref, DerefMut},
};


pub type Result<T, E> = std::result::Result<T, Traced<E>>;

pub trait Traceable<E> {
	fn trace(self) -> Traced<E>;
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


impl<E> Traceable<E> for E
where
	E: Error,
{
	fn trace(self) -> Traced<E> { Traced::new(self) }
}

#[cfg(debug_assertions)]
impl<E> Traced<E> {
	pub fn new(inner: E) -> Self {
		Self {
			inner,
			#[cfg(debug_assertions)]
			backtrace: Backtrace::force_capture(),
		}
	}
}

#[cfg(debug_assertions)]
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
		write!(f, "{}", self.backtrace)
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

	fn description(&self) -> &str { self.inner.description() }

	fn cause(&self) -> Option<&dyn Error> { self.inner.cause() }
}

#![allow(dead_code)]

#[cfg(debug_assertions)]
use std::sync::{
	atomic::{AtomicBool, Ordering},
	Arc,
};
use std::{
	backtrace::Backtrace,
	error::Error,
	fmt::{Debug, Display},
	ops::{Deref, DerefMut},
	result::Result as StdResult,
	time::Duration,
};

#[cfg(debug_assertions)]
use log::warn;
#[cfg(debug_assertions)]
use tokio::{spawn, time::sleep};

const DEADLOCK_TIMEOUT: Duration = Duration::from_secs(1);


pub struct Mutex<T>(tokio::sync::Mutex<T>);

pub struct MutexGuard<'a, T> {
	inner: tokio::sync::MutexGuard<'a, T>,
	#[cfg(debug_assertions)]
	locked: Arc<AtomicBool>,
}

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


impl<T> Mutex<T> {
	#[cfg(debug_assertions)]
	pub async fn lock(&self) -> MutexGuard<'_, T> {
		let locked = Arc::new(AtomicBool::new(true));

		let backtrace = Backtrace::force_capture();
		let locked2 = locked.clone();
		spawn(async move {
			sleep(DEADLOCK_TIMEOUT).await;
			if locked2.load(Ordering::Relaxed) {
				warn!("Deadlock detected: {:?}", &backtrace);
			}
		});

		MutexGuard {
			inner: self.0.lock().await,
			locked,
		}
	}

	pub fn new(t: T) -> Self { Self(tokio::sync::Mutex::new(t)) }

	#[cfg(not(debug_assertions))]
	pub async fn lock(&self) -> MutexGuard<'_, T> {
		MutexGuard {
			inner: self.0.lock().await,
		}
	}
}

#[cfg(debug_assertions)]
impl<'a, T> Drop for MutexGuard<'a, T> {
	fn drop(&mut self) { self.locked.store(false, Ordering::Relaxed); }
}

impl<'a, T> Deref for MutexGuard<'a, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target { &*self.inner }
}

impl<'a, T> DerefMut for MutexGuard<'a, T> {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut *self.inner }
}

impl<E> Traceable<E> for E {
	fn trace(self) -> Traced<E> { Traced::capture(self) }
}

impl<T, E> TraceableResult<T, E> for StdResult<T, E> {
	fn trace_result(self) -> self::Result<T, E> { self.map_err(|e| Traced::capture(e)) }
}

impl<T> Traced<T> {
	#[cfg(debug_assertions)]
	pub fn new_debug(inner: T, backtrace: Backtrace) -> Self { Self { inner, backtrace } }

	#[cfg(not(debug_assertions))]
	pub fn new_release(inner: T) -> Self { Self { inner } }

	#[cfg(debug_assertions)]
	pub fn capture(inner: T) -> Self { Self::new_debug(inner, Backtrace::force_capture()) }

	#[cfg(not(debug_assertions))]
	pub fn capture(inner: T) -> Self { Self { inner } }

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
	fn from(other: E) -> Self { Self::capture(other) }
}

impl<E> Clone for Traced<E>
where
	E: Clone,
{
	fn clone(&self) -> Self { Self::capture(self.inner.clone()) }
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

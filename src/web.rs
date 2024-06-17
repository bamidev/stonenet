pub mod activity_pub;
pub mod consolidated_feed;
pub mod info;
pub mod json;
pub mod server;
pub mod webfinger;


use std::borrow::Cow;

use server::{AppState, ServerInfo};
use tokio::sync::Mutex;

use crate::{
	api::Api,
	config::Config,
	trace::{self, Traced},
};


#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("database error: {0}")]
	Database(#[from] crate::db::Error),
	#[error("ActivityPub network issue while {1}: {0}")]
	Network(reqwest::Error, Cow<'static, str>),
	#[error("JSON parsing error while {1}: {0}")]
	Deserialization(serde_json::Error, Cow<'static, str>),
	#[error("unexpected JSON type while {1}: expected {0}")]
	UnexpectedJsonType(&'static str, Cow<'static, str>),
	#[error("Unexpected AcitivityPub implementation behavior for {1}: {0}")]
	UnexpectedBehavior(Cow<'static, str>, Cow<'static, str>),
}

pub struct Global {
	pub config: Config,
	pub state: Mutex<AppState>,
	pub server_info: ServerInfo,
	pub api: Api,
}

pub type Result<T> = trace::Result<T, Error>;

impl crate::db::Error {
	fn to_web(self) -> Traced<Error> { Traced::capture(Error::Database(self)) }
}

impl Traced<crate::db::Error> {
	#[cfg(debug_assertions)]
	fn to_web(self) -> Traced<Error> {
		let (inner, backtrace) = self.unwrap();
		let error = Error::Database(inner);
		if let Some(b) = backtrace {
			Traced::new_debug(error, b)
		} else {
			Traced::capture(error)
		}
	}

	#[cfg(not(debug_assertions))]
	fn to_web(self) -> Traced<Error> {
		let (inner, _) = self.unwrap();
		let error = Error::Database(inner);
		Traced::new_release(error)
	}
}

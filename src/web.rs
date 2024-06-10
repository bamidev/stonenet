pub mod activity_pub;
pub mod common;
pub mod json;
pub mod server;
pub mod webfinger;


use std::borrow::Cow;

use server::{AppState, ServerInfo};
use tokio::sync::Mutex;

use crate::{api::Api, config::Config, db, trace};


#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("database error: {0}")]
	Database(#[from] db::Error),
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

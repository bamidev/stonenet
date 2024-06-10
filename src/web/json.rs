use std::borrow::Cow;

use reqwest::Url;

use crate::web::{Error, Result};


#[allow(unused)]
pub fn expect_object<'a>(
	value: &'a serde_json::Value, when: &impl Fn() -> Cow<'static, str>,
) -> Result<&'a serde_json::Map<String, serde_json::Value>> {
	match value {
		serde_json::Value::Object(r) => Ok(r),
		_ => Err(Error::UnexpectedJsonType("object", when()))?,
	}
}

pub fn expect_string<'a>(
	value: &'a serde_json::Value, when: &impl Fn() -> Cow<'static, str>,
) -> Result<&'a String> {
	match value {
		serde_json::Value::String(s) => Ok(s),
		_ => Err(Error::UnexpectedJsonType("string", when()))?,
	}
}

pub fn expect_url<'a>(
	value: &'a serde_json::Value, when: &impl Fn() -> Cow<'static, str>,
) -> Result<Url> {
	let string = expect_string(value, when)?;

	// Parse value as an URL
	let url = match Url::parse(string) {
		Ok(r) => r,
		Err(e) =>
			return Err(Error::UnexpectedBehavior(
				format!("actor id is not a valid URL: {}", e).into(),
				when(),
			))?,
	};

	// Ensure that host is set
	if url.host_str().is_none() {
		return Err(Error::UnexpectedBehavior(
			"actor id URL has no host".into(),
			when(),
		))?;
	}
	Ok(url)
}

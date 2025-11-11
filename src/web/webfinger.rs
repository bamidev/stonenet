use std::{borrow::Cow, str::FromStr};

use axum::http::HeaderMap;
use email_address_parser::EmailAddress;
use lazy_static::lazy_static;
use log::*;
use reqwest::Url;

use super::json::{expect_string, expect_url};
use crate::web::{Error, Result};

lazy_static! {
	pub static ref HTTP_CLIENT: reqwest::Client = {
		let mut headers = HeaderMap::new();
		headers.append(
			"Accept",
			"application/jrd+json,application/json".parse().unwrap(),
		);
		reqwest::Client::builder()
			.default_headers(headers)
			.build()
			.unwrap()
	};
}

/// Extracts all webfinger addresses that can be found in the given string.
/// Each address has to start with an "@" sign in order to be found.
pub fn find_from_content(content: &str) -> Vec<EmailAddress> {
	let mut results = Vec::with_capacity(16);
	let mut i = 0;

	while let Some(at_pos) = content[i..].find("@") {
		let substring = &content[(at_pos + 1)..];
		let address_to_check = if let Some(end_pos) = substring.find(char::is_whitespace) {
			i += at_pos + 1 + end_pos + 1;
			&substring[..end_pos]
		} else {
			i += at_pos + 1;
			substring
		};
		match EmailAddress::parse(address_to_check, None) {
			None => {}
			Some(addr) => results.push(addr),
		}
	}
	results
}

pub fn parse_link(
	link: &serde_json::Value, when: &impl Fn() -> Cow<'static, str>,
) -> Result<Option<Url>> {
	if let Some(rel_val) = link.get("rel") {
		let rel = expect_string(rel_val, when)?;
		if rel != "self" {
			return Ok(None);
		}

		if let Some(link_type_val) = link.get("type") {
			let mime_type = expect_string(link_type_val, when)?;

			if mime_type.starts_with("application/activity+json")
				|| mime_type.starts_with("application/jd+json")
			{
				if let Some(href_val) = link.get("href") {
					return Ok(Some(expect_url(href_val, when)?));
				}
			}
		}
	}
	Ok(None)
}

pub async fn resolve(address: &EmailAddress) -> Result<Option<Url>> {
	let when = || format!("fetching actor {} from webfinger", address).into();
	let response = HTTP_CLIENT
		.get(format!(
			"https://{}/.well-known/webfinger?resource=acct:{}",
			address.get_domain(),
			address
		))
		.send()
		.await
		.map_err(|e| Error::Network(e, when()))?;
	let body = response
		.text()
		.await
		.map_err(|e| Error::Network(e, when()))?;
	let json = serde_json::Value::from_str(&body).map_err(|e| Error::Deserialization(e, when()))?;

	if let Some(links) = json.get("links") {
		match links {
			serde_json::Value::Array(array) => {
				for item in array {
					if let Some(url) = parse_link(&item, &when)? {
						return Ok(Some(url));
					}
				}
				Ok(None)
			}
			_ => {
				warn!(
					"Unable to parse webfinger response for ActivityPub address {}: links \
					 property is not an array",
					address
				);
				return Ok(None);
			}
		}
	} else {
		warn!(
			"Unable to parse webfinger response for ActivityPub address {}: links property not \
			 found",
			address
		);
		Ok(None)
	}
}

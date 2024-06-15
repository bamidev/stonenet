use std::{borrow::Cow, str::FromStr};

use email_address_parser::EmailAddress;
use futures::future::join_all;
use log::*;
use reqwest::Url;
use sea_orm::{prelude::*, NotSet, Set};

use super::{expect_string, expect_url, Error, Result, HTTP_CLIENT};
use crate::{
	db::{Database, PersistenceHandle},
	entity::activity_pub_actor,
	web::webfinger::resolve,
};


pub async fn ensure(
	db: &Database, url: &Url, address: Option<&EmailAddress>, when: &impl Fn() -> Cow<'static, str>,
) -> Result<activity_pub_actor::Model> {
	let host = url.host_str().unwrap();
	let path = url.path();

	if let Some(record) = activity_pub_actor::Entity::find()
		.filter(activity_pub_actor::Column::Host.eq(host.to_string()))
		.filter(activity_pub_actor::Column::Path.eq(path.to_string()))
		.one(db.inner())
		.await
		.map_err(|e| Error::from(e))?
	{
		return Ok(record);
	}

	// If the AP actor isn't known yet, retrieve it
	let json = fetch(url).await?;
	if let Some(id_val) = json.get("id") {
		let url = expect_url(id_val, when)?;
		let host = url.host_str().unwrap();
		let path = url.path();

		// Get inbox and outbox as well&
		let name = if let Some(r) = json.get("name") {
			Some(expect_string(r, when)?.to_string())
		} else {
			None
		};
		let inbox = if let Some(r) = json.get("inbox") {
			Some(expect_url(r, when)?.to_string())
		} else {
			None
		};
		let outbox = if let Some(r) = json.get("outbox") {
			Some(expect_url(r, when)?.to_string())
		} else {
			None
		};
		let icon_url = if let Some(icon_val) = json.get("icon") {
			if let Some(url_val) = icon_val.get("url") {
				Some(expect_url(url_val, when)?.to_string())
			} else {
				None
			}
		} else {
			None
		};

		// Store the actor
		let model = activity_pub_actor::ActiveModel {
			id: NotSet,
			host: Set(host.to_string()),
			path: Set(path.to_string()),
			address: Set(address.map(|s| s.to_string())),
			name: Set(name.clone()),
			inbox: Set(inbox.clone()),
			outbox: Set(outbox.clone()),
			icon_url: Set(icon_url.clone()),
		};
		let result = activity_pub_actor::Entity::insert(model)
			.exec(db.inner())
			.await
			.map_err(|e| Error::from(e))?;
		Ok(activity_pub_actor::Model {
			id: result.last_insert_id,
			host: host.to_string(),
			path: path.to_string(),
			address: address.map(|s| s.to_string()),
			name,
			inbox,
			outbox,
			icon_url,
		})
	} else {
		return Err(Error::UnexpectedBehavior(
			"missing id property on actor object".into(),
			when(),
		))?;
	}
}


pub async fn fetch(url: &Url) -> Result<serde_json::Value> {
	let when = || format!("fetching actor {}", url).into();
	let response = HTTP_CLIENT
		.get(url.clone())
		.send()
		.await
		.map_err(|e| Error::Network(e, when()))?;

	// Test content type
	let content_type = if let Some(value) = response.headers().get("content-type") {
		value.to_str().map_err(|e| {
			Error::UnexpectedBehavior(
				format!("Content-Type header is not a string: {}", e).into(),
				when(),
			)
		})?
	} else {
		return Err(Error::UnexpectedBehavior(
			"Content-Type header is missing".into(),
			when(),
		))?;
	};
	if !content_type.starts_with("application/ld+json")
		&& !content_type.starts_with("application/activity+json")
	{
		return Err(Error::UnexpectedBehavior(
			"unexpected content-type".into(),
			when(),
		))?;
	}

	// Parse JSON
	let response_body = response.text().await.unwrap();
	let response_json =
		serde_json::from_str(&response_body).map_err(|e| Error::Deserialization(e, when()))?;
	Ok(response_json)
}

/// Like `fetch`, but for when you have a seperate server and path components of
/// the URL. Will return None in the case where the components didn't make up a
/// valid URL
pub async fn fetch2(server: &str, actor_path: &str) -> Result<Option<serde_json::Value>> {
	let actor_url = server.to_string() + actor_path;
	let url = match Url::from_str(&actor_url) {
		Ok(r) => r,
		Err(e) => {
			error!("Constructed invalid actor URL {}: {}", actor_url, e);
			return Ok(None);
		}
	};
	Ok(Some(fetch(&url).await?))
}

pub async fn fetch_from_webfinger(address: &EmailAddress) -> Result<Option<serde_json::Value>> {
	if let Some(url) = resolve(address).await? {
		Ok(Some(fetch(&url).await?))
	} else {
		Ok(None)
	}
}

pub async fn resolve_url_from_webfinger(
	db: &Database, address: &EmailAddress,
) -> Result<Option<Url>> {
	let when = || format!("resolving URL from webfinger address {}", address).into();
	// If we have the actor stored already, get the URL from the DB
	if let Some(record) = activity_pub_actor::Entity::find()
		.filter(activity_pub_actor::Column::Address.eq(address.to_string()))
		.one(db.inner())
		.await
		.map_err(|e| Error::from(e))?
	{
		let full_url = format!("https://{}{}", &record.host, &record.path);

		// Parse the url, and if it fails, delete the corrupted record
		match Url::from_str(&full_url) {
			Ok(url) => return Ok(Some(url)),
			Err(e) => {
				warn!(
					"URL \"{}\" loaded from ActivtyPub actor {} is an invalid URL: {}",
					&full_url, record.id, e
				);
				activity_pub_actor::Entity::delete_by_id(record.id)
					.exec(db.inner())
					.await
					.map_err(|e| Error::from(e))?;
			}
		}
	}

	// Otherwise, just resolve the webfinger and store the actor for next time
	if let Some(url) = resolve(address).await? {
		ensure(db, &url, Some(address), &when).await?;
		Ok(Some(url))
	} else {
		Ok(None)
	}
}

pub async fn resolve_urls_from_webfingers(db: &Database, addresses: &[EmailAddress]) -> Vec<Url> {
	let bulk = addresses
		.iter()
		.map(|a| async { (a.clone(), resolve_url_from_webfinger(db, a).await) });
	let webfinger_results = join_all(bulk).await;

	let mut results = Vec::with_capacity(addresses.len());
	for (addr, result) in webfinger_results {
		match result {
			Ok(r) =>
				if let Some(url) = r {
					results.push(url)
				},
			Err(e) => warn!("Unable to resolve webfinger address {}: {:?}", addr, e),
		}
	}
	results
}

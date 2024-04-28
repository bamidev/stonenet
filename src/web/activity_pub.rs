use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
	body::Body,
	extract::{Query, State},
	http::HeaderMap,
	response::Response,
	Extension,
};
use chrono::SecondsFormat;
use sea_orm::prelude::*;
use serde::*;

use super::{common::*, ActorAddress, Address, IdType};
use crate::{
	db::{ObjectPayloadInfo, PersistenceHandle},
	entity::file,
	web::Global,
};


const DEFAULT_CONTEXT: ActivityPubDocumentContext = ActivityPubDocumentContext(&[
	"https://www.w3.org/ns/activitystreams",
	"https://w3id.org/security/v1",
]);

// The public and private keys that the activity pub specification wants. We
// don't actually keep one for every user.
const PUBLIC_KEY: &'static str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuisC4+iNmaASpAfQHS+Q
rm22bSCIrzZViIVz8NgHIHD2nudJ7JVzIgtDk3dX6V39CvvMr0mkMrTQHdGXwnBs
aOBYJ/j9tE5MngV9s1B1GPdj2hDBZF0w30h/Aqn/UCaWLtitrllOECbrCV+ZN0jV
fNxD6lXW7gvbBQUDgxPNREjp3idJ/H2gFtDEZcf8BLzl90vUFcdXrWGN43lmENPO
SomG7QsKp7MutQEtoz+UeBI/cOZ5sxsDEa4mLeeGsWfBfwmnvDCnU6Z1VooONo+q
AXUgNJdM2qiaB/sxPJsX8HSCdf2LeB8JjogqD/+zGJFyS2kB8obTZRghLQJsMthY
jwIDAQAB
-----END PUBLIC KEY-----"#;
const PRIVATE_KEY: &'static str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6KwLj6I2ZoBKk
B9AdL5CubbZtIIivNlWIhXPw2AcgcPae50nslXMiC0OTd1fpXf0K+8yvSaQytNAd
0ZfCcGxo4Fgn+P20TkyeBX2zUHUY92PaEMFkXTDfSH8Cqf9QJpYu2K2uWU4QJusJ
X5k3SNV83EPqVdbuC9sFBQODE81ESOneJ0n8faAW0MRlx/wEvOX3S9QVx1etYY3j
eWYQ085KiYbtCwqnsy61AS2jP5R4Ej9w5nmzGwMRriYt54axZ8F/Cae8MKdTpnVW
ig42j6oBdSA0l0zaqJoH+zE8mxfwdIJ1/Yt4HwmOiCoP/7MYkXJLaQHyhtNlGCEt
Amwy2FiPAgMBAAECggEAVX4LBb51yGbKKKmt2LlPJ8saS2L1YgEBpoAijiemni9C
EhcEy7CV/rxNfBsCNBkFa1XW2WhoDyEZsZfeqVwXbNIZqcGeQH70kFzVLNN18tEo
+atYJE7ncqJIMWD/7j7KGRlIKRi50JEOvm84XTsFTyGXzrU8znSDT/rNchRV31US
yj3vFbMobwQO716QYqqDCXibFI8zW3rH19zjuyDKcFWnEXfDIZBwoGTHoSAcjbHW
3SWQEofR9knMzPjbCiTGcchI7gQgv9/HQoAC37OtRQMzxnyzx7/zGtfZNOzaLhrf
cyGu6J/yzaIqrcaWMHX1kiyvzdk7AhREyCFX5BpBAQKBgQD0SXHX2qbeFm37qinX
xDGmKZcTUqIUQKtIG5+iEP8jTPpu2lGumCR+EZs4XXjhttMSj6VzKkvz9H/X/QBS
FgSR+cBZrh1p91hXZYRDelJ4539P3NcYahSCojQETvcDDJEJZL2X7OJHAZwvTfd1
/z0VHld8M9BptbEu6Y2LzthRmQKBgQDDGCxQ5LY/DpHkMgtLTT6T4Mv8q2CI4TpC
WxF3lIwUl8HLqWTwmaqSSAfYpExdtl9kR8Qcg28SZXwgimhLT09ySfVgpZO5/fwg
GYSW4m1ClYhz2ZWE1fCLq13v++Eyd2AoyWFp/1aoTd3BMGWRa23mKEkrbCkRZceE
dpPFQsYkZwKBgBE0uxgBBo/N9KEtMxVHdFfHxiRORaw3gdjqWSwJFm9eFKWKKwap
IKjghJZLvx/myKceBwE9kWv1ZKvJ3iPp+RhvBuVKJjg4e7hsJgy6qORrKcRuQZgu
oJMy6YcEKNHGKNEIj3IL9UQbEO0kCLH+8EZ0hKTy4VMQwRIU0StvvjzBAoGAaMwf
YgS5cP3emHnZX0XLC5yBduSIIn750JMiut1ssdMjIseHlUa2PYW70T/QVbaVX0S9
r6NaksM4/jHa/DlKL9ZSnOvUguBQAt4yPuq6Tj4M4k5K5uQVJrGS8EqZGYbOfJpQ
XaPvZNEPAauBo6/VhQC27UBYfyPxHNKlZh0MWpkCgYEAm1rC5typagkiNUl1XwRV
70AbI/Vx8UMA63/tHXePuR/x9uFu4zqPr7VViWmCQrDqcf6F1I0prU9JETsoKiRD
EFzCSxvsK9TM47WxntIAUmciHe+PvoJfV4Wsc2hhnPhszrkenxSA0kMj9dwg1Yyq
yKNOge1KpLZ2M6dMVrhqvE0=
-----END PRIVATE KEY-----"#;


#[derive(Serialize)]
enum ActivityObjectType {
	Note,
}

#[derive(Serialize)]
struct ActivityObject {
	id: String,
	r#type: ActivityObjectType,
	content: String,
	source: ActivityObjectSource,
	published: DateTime,
}

#[derive(Serialize)]
struct ActivityPubDocumentContext(pub &'static [&'static str]);

#[allow(non_snake_case)]
#[derive(Serialize)]
struct ActorDocument {
	#[serde(rename(serialize = "@context"), default)]
	context: ActivityPubDocumentContext,
	id: String,
	r#type: &'static str,
	name: String,
	preferredUsername: String,
	url: String,
	//inbox: String,
	outbox: String,
	summary: String,

	publicKey: ActorDocumentPublicKey,
	icon: Option<ActorDocumentIcon>,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct ActorDocumentIcon {
	r#type: &'static str,
	mediaType: String,
	url: String,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct ActorDocumentPublicKey {
	id: String,
	owner: String,
	publicKeyPem: String,
}

struct CreateActivityType;

struct DateTime(u64);


#[allow(non_snake_case)]
#[derive(Serialize)]
struct ActivityObjectSource {
	content: String,
	mediaType: MediaType,
}

#[derive(Serialize)]
struct CreateActivity {
	#[serde(rename(serialize = "@context"), default)]
	context: ActivityPubDocumentContext,
	r#type: CreateActivityType,
	id: String,
	actor: String,
	object: ActivityObject,
	published: DateTime,
}

enum MediaType {
	Markdown,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct OrderedCollection {
	#[serde(rename(serialize = "@context"), default)]
	context: ActivityPubDocumentContext,
	summary: &'static str,
	r#type: OrderedCollectionType,
	totalItems: usize,
	orderedItems: Vec<serde_json::Value>,
}

struct OrderedCollectionType;

#[derive(Serialize)]
struct WebFingerDocument {
	subject: String,
	aliases: Vec<String>,
	links: Vec<WebFingerDocumentLink>,
}

#[derive(Serialize)]
struct WebFingerDocumentLink {
	rel: &'static str,
	r#type: &'static str,
	href: String,
}


impl ActivityObject {
	pub fn new(
		url_base: &str, actor: &ActorAddress, object_hash: &IdType, created: u64, content: String,
	) -> Self {
		Self {
			id: format!("{}/actor/{}/object/{}", url_base, actor, object_hash),
			r#type: ActivityObjectType::Note,
			content: content.clone(),
			source: ActivityObjectSource {
				content,
				mediaType: MediaType::Markdown,
			},
			published: DateTime(created),
		}
	}
}

impl Default for ActivityPubDocumentContext {
	fn default() -> Self { DEFAULT_CONTEXT }
}

impl CreateActivity {
	pub fn new(
		url_base: &str, actor: &ActorAddress, object_hash: &IdType, created: u64, content: String,
	) -> Self {
		Self {
			context: ActivityPubDocumentContext::default(),
			r#type: CreateActivityType,
			id: format!(
				"{}/actor/{}/object/{}/activity-pub/activity",
				url_base, &actor, &object_hash
			),
			actor: format!("{}/actor/{}/activity-pub", url_base, &actor),
			object: ActivityObject::new(url_base, actor, object_hash, created, content),
			published: DateTime(created),
		}
	}
}

impl ActorDocument {
	fn new(
		url_base: &str, address: &ActorAddress, name: String,
		avatar_hash: Option<(&IdType, String)>, summary: String,
	) -> Self {
		let id = format!("{}/actor/{}", url_base, address);
		Self {
			context: DEFAULT_CONTEXT,
			id: id.clone(),
			url: id.clone(),
			r#type: "Person",
			name,
			preferredUsername: address.to_string(),
			//inbox: format!("{}/actor/{}/activity-pub/inbox", url_base, address),
			outbox: format!("{}/actor/{}/activity-pub/outbox", url_base, address),
			publicKey: ActorDocumentPublicKey {
				id: format!("{}#main-key", &id),
				owner: id.clone(),
				publicKeyPem: PUBLIC_KEY.replace("\n", "\\n"),
			},
			summary,
			icon: avatar_hash.map(|(hash, mime_type)| ActorDocumentIcon {
				r#type: "Image",
				mediaType: mime_type,
				url: format!("{}/file/{}", &id, hash),
			}),
		}
	}
}

impl Serialize for CreateActivityType {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str("Create")
	}
}

impl Serialize for DateTime {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let dt = chrono::DateTime::from_timestamp_millis(self.0 as _).unwrap();
		serializer.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Millis, true))
	}
}

impl Serialize for MediaType {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match self {
			Self::Markdown => serializer.serialize_str("text/markdown"),
		}
	}
}

impl Serialize for OrderedCollectionType {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str("OrderedCollection")
	}
}

impl WebFingerDocument {
	fn new(domain: &str, url_base: &str, type_: &str, address: &Address) -> Self {
		Self {
			subject: format!("acct:{}@{}", address, domain),
			aliases: vec![format!("{}/{}/{}", url_base, type_, address)],
			links: vec![
				WebFingerDocumentLink {
					rel: "self",
					r#type: "application/activity+json",
					href: format!("{}/{}/{}/activity-pub", url_base, type_, address),
				},
				WebFingerDocumentLink {
					rel: "http://webfinger.net/rel/profile-page",
					r#type: "text/html",
					href: format!("{}/{}/{}", url_base, type_, address),
				},
			],
		}
	}
}


fn compose_object_payload(payload: &ObjectPayloadInfo) -> String {
	match payload {
		ObjectPayloadInfo::Post(post) => {
			let mut content = String::new();
			if let Some(irt) = &post.in_reply_to {
				let actor_name: &str = if let Some(name) = irt.actor_name.as_ref() {
					name
				} else {
					"Someone"
				};
				content = format!("{} wrote:\n\n", actor_name);
			}

			if let Some(message) = &post.message {
				content += message;
			}
			content
		}
		ObjectPayloadInfo::Share(share) =>
			if let Some(original_post) = &share.original_post {
				let actor_name: &str = if let Some(name) = &original_post.actor_name {
					name
				} else {
					"Someone"
				};
				format!(
					"{} wrote:\n\n{}",
					actor_name,
					original_post
						.message
						.as_ref()
						.map(|(_, m)| m)
						.unwrap_or(&"[Unable to load post message]".to_string())
				)
			} else {
				"[Unable to load shared post]".to_string()
			},
		ObjectPayloadInfo::Profile(_) => {
			format!("[Updated my profile]")
		}
	}
}

fn parse_account_name(resource: &str) -> Option<&str> {
	if !resource.starts_with("acct:") {
		return None;
	}

	if let Some(i) = resource.find('@') {
		return Some(&resource[5..i]);
	}
	None
}

pub async fn webfinger(
	State(g): State<Arc<Global>>, Query(params): Query<HashMap<String, String>>,
) -> Response {
	if let Some(resource) = params.get("resource") {
		let account_name = match parse_account_name(resource) {
			Some(n) => n,
			None => return server_error_response2("invalid resource syntax"),
		};

		let address = match Address::from_str(account_name) {
			Err(e) => return server_error_response(e, "invalid address"),
			Ok(a) => a,
		};

		let webfinger = match &address {
			Address::Actor(actor_address) => match g.api.db.connect_old() {
				Err(e) => return server_error_response(e, "DB issue"),
				Ok(c) => {
					let result = match c.fetch_identity(actor_address) {
						Err(e) => return server_error_response(e, "DB issue"),
						Ok(r) => r,
					};

					if result.is_some() {
						WebFingerDocument::new(
							&g.server_info.federation_domain,
							&g.server_info.url_base,
							"actor",
							&address,
						)
					} else {
						return not_found_error_response("actor doesn't exist");
					}
				}
			},
			Address::Node(_) => WebFingerDocument::new(
				&g.server_info.federation_domain,
				&g.server_info.url_base,
				"node",
				&address,
			),
		};

		json_response(&webfinger, Some("application/ld+json"))
	} else {
		server_error_response2("Missing parameter \"resource\".")
	}
}

pub async fn actor(
	State(g): State<Arc<Global>>, Extension(address): Extension<ActorAddress>, headers: HeaderMap,
) -> Response {
	let profile = match g.api.db.connect_old() {
		Err(e) => return server_error_response(e, "DB issue"),
		Ok(c) => c.fetch_profile_info(&address).unwrap().unwrap(),
	};

	// Workaround for Mastodon, because they don't use the `id` or `url` params of
	// the actor to redirecting to the actor's profile page.
	if let Some(accept) = headers.get("Accept") {
		if let Ok(accept_string) = accept.to_str() {
			if !accept_string.contains("application/ld+json")
				&& !accept_string.contains("application/activity+json")
			{
				return Response::builder()
					.status(303)
					.header("Location", format!("/actor/{}", address))
					.body(Body::empty())
					.unwrap();
			}
		}
	}

	// Load avatar file mime-type if available
	let avatar_mime_type = if let Some(hash) = &profile.actor.avatar_id {
		match file::Entity::find()
			.filter(file::Column::Hash.eq(hash))
			.one(g.api.db.inner())
			.await
		{
			Err(e) => return server_error_response(e, "unable to load file"),
			Ok(r) => r.map(|file| file.mime_type),
		}
	} else {
		None
	};

	let description = profile.description.clone().unwrap_or_default();
	let actor = ActorDocument::new(
		&g.server_info.url_base,
		&address,
		profile.actor.name,
		profile
			.actor
			.avatar_id
			.as_ref()
			.map(|hash| (hash, avatar_mime_type.unwrap())),
		description,
	);
	json_response(&actor, Some("application/ld+json"))
}

pub async fn actor_outbox(
	State(g): State<Arc<Global>>, Extension(address): Extension<ActorAddress>,
) -> Response {
	let objects = match g.api.db.load_actor_feed(&address, 1000, 0).await {
		Err(e) => return server_error_response(e, "DB issue"),
		Ok(r) => r,
	};

	let feed = OrderedCollection {
		context: ActivityPubDocumentContext::default(),
		summary: "Actor Feed",
		r#type: OrderedCollectionType,
		totalItems: objects.len(),
		orderedItems: objects
			.iter()
			.map(|object| {
				serde_json::to_value(CreateActivity::new(
					&g.server_info.url_base,
					&address,
					&object.hash,
					object.created,
					compose_object_payload(&object.payload),
				))
				.unwrap()
			})
			.collect(),
	};
	json_response(&feed, Some("application/ld+json"))
}

use std::{
	collections::HashMap,
	str::FromStr,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
	body::Body,
	extract::{Query, State},
	http::HeaderMap,
	response::Response,
	Extension,
};
use base64::prelude::*;
use chrono::{Local, SecondsFormat};
use lazy_static::lazy_static;
use log::{error, warn};
use rand::rngs::OsRng;
use reqwest::Url;
use rsa::{
	pkcs1v15::SigningKey,
	pkcs8::DecodePrivateKey,
	sha2::{Digest, Sha256},
	signature::{RandomizedSigner, SignatureEncoding},
	RsaPrivateKey,
};
use sea_orm::{
	prelude::*,
	sea_query::{self, Alias},
	ActiveValue::NotSet,
	JoinType, Order, QueryOrder, QuerySelect, Set, Statement,
};
use serde::*;
use stonenetd::core::OBJECT_TYPE_PROFILE;
use tokio::{spawn, time::sleep};

use super::{common::*, ActorAddress, Address, IdType};
use crate::{
	db::{self, ObjectPayloadInfo, PersistenceHandle},
	entity::*,
	web::Global,
};


const DEFAULT_CONTEXT: ActivityPubDocumentContext = ActivityPubDocumentContext(&[
	"https://www.w3.org/ns/activitystreams",
	"https://w3id.org/security/v1",
]);
const SEND_QUEUE_DEFAULT_CAPACITY: u64 = 100000;

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
struct AcceptActivity {
	#[serde(rename(serialize = "@context"), default)]
	context: ActivityPubDocumentContext,
	r#type: AcceptActivityType,
	actor: String,
	to: Vec<String>,
	object: serde_json::Value,
}
struct AcceptActivityType;

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

#[derive(PartialEq)]
enum ActivitySendState {
	Send,
	Failed,
	Impossible,
}

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
	inbox: String,
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
	to: Vec<String>,
	cc: Option<Vec<String>>,
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


lazy_static! {
	static ref HTTP_CLIENT: reqwest::Client = {
		let mut headers = HeaderMap::new();
		headers.append(
			"Accept",
			"application/ld+json,application/activity+json"
				.parse()
				.unwrap(),
		);
		reqwest::Client::builder()
			.default_headers(headers)
			.build()
			.unwrap()
	};
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
	pub fn new_public_note(
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
			to: vec![format!(
				"{}/actor/{}/activity-pub/followers",
				url_base, actor
			)],
			cc: Some(vec![
				"https://www.w3.org/ns/activitystreams#Public".to_string(),
			]),
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
			inbox: format!("{}/actor/{}/activity-pub/inbox", url_base, address),
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

impl Serialize for AcceptActivityType {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str("Accept")
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
					r#type:
						"application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
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

		json_response(&webfinger, Some("application/jrd+json"))
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
	json_response(
		&actor,
		Some("application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""),
	)
}

pub async fn actor_inbox_post(
	State(g): State<Arc<Global>>, Extension(address): Extension<ActorAddress>,
	Extension(actor_opt): Extension<Option<identity::Model>>, body: String,
) -> Response {
	if body.len() > 20480 {
		return error_response(406, "JSON object too big.");
	}
	let actor = if let Some(a) = actor_opt {
		a
	} else {
		return error_response(404, "Actor not found");
	};

	let object_json = serde_json::Value::from_str(&body).unwrap();
	let result = if let Some(object_type) = object_json.get("type") {
		let type_string = match object_type {
			serde_json::Value::String(s) => s,
			_ => return error_response(406, "Activity object type field has invalid type"),
		};
		match type_string.as_str() {
			"Create" => actor_inbox_store_object(&g, &address, &actor, object_json).await,
			"Like" => actor_inbox_store_object(&g, &address, &actor, object_json).await,
			"Follow" => actor_inbox_register_follow(&g, &actor, object_json).await,
			//"Undo" => actor_inbox_process_undo(&g, &address, &actor, object_json).await,
			other =>
				return error_response(406, &format!("Object type \"{}\" not supported.", other)),
		}
	} else {
		return error_response(400, "Missing type parameter.");
	};

	match result {
		Err(e) => server_error_response(e, "Database error"),
		Ok(r) => match r {
			None => error_response(404, "Couldn't find actor"),
			Some(response) => response,
		},
	}
}

async fn actor_inbox_register_follow(
	g: &Global, actor: &identity::Model, object: serde_json::Value,
) -> db::Result<Option<Response>> {
	if let Some(follower) = object.get("actor") {
		let follower_string = match follower {
			serde_json::Value::String(s) => s,
			_ => return Ok(Some(error_response(400, "Actor field not a string"))),
		};

		// Store follower
		match Url::parse(&follower_string) {
			Err(e) =>
				return Ok(Some(error_response(
					400,
					&format!("Invalid URL for follower {}: {}", &follower_string, e),
				))),
			Ok(url) => {
				let domain = if let Some(d) = url.domain() {
					d
				} else {
					return Ok(Some(error_response(
						400,
						&format!("No domain in follower URL"),
					)));
				};
				let server = format!("{}://{}", url.scheme(), domain);
				let path = url.path().to_string();

				let record = activity_pub_follow::ActiveModel {
					id: NotSet,
					actor_id: Set(actor.id),
					path: Set(path.clone()),
					server: Set(server.clone()),
				};
				activity_pub_follow::Entity::insert(record)
					.exec(g.api.db.inner())
					.await?;

				// Send an Accept object back
				let accept_activity = AcceptActivity {
					context: ActivityPubDocumentContext::default(),
					r#type: AcceptActivityType,
					actor: format!("{}/actor/{}", &g.server_info.url_base, &actor.address),
					to: vec![follower_string.clone()],
					object,
				};
				queue_activity(g, actor.id, server, Some(path), &accept_activity).await?;
			}
		};

		return Ok(Some(
			Response::builder().status(201).body(Body::empty()).unwrap(),
		));
	} else {
		Ok(None)
	}
}

async fn actor_inbox_store_object(
	g: &Global, actor_address: &ActorAddress, actor: &identity::Model, json: serde_json::Value,
) -> db::Result<Option<Response>> {
	let record = activity_pub_object::ActiveModel {
		id: NotSet,
		actor_id: Set(actor.id),
		data: Set(json.to_string()),
	};
	let result = activity_pub_object::Entity::insert(record)
		.exec(g.api.db.inner())
		.await?;
	let object_id = result.last_insert_id;

	// Immediately clean up old objects in inbox
	activity_pub_object::Entity::delete_many()
		.filter(
			activity_pub_object::Column::Id.in_subquery(
				sea_query::Query::select()
					.column(activity_pub_object::Column::Id)
					.from(Alias::new(
						activity_pub_object::Entity::default().table_name(),
					))
					.and_where(activity_pub_object::Column::ActorId.eq(actor.id))
					.order_by(activity_pub_object::Column::Id, Order::Desc)
					.offset(g.config.activity_pub_inbox_size.unwrap_or(1000) as _)
					.take(),
			),
		)
		.exec(g.api.db.inner())
		.await?;

	return Ok(Some(
		Response::builder()
			.status(201)
			.header(
				"Location",
				&format!(
					"{}/actor/{}/activity-pub/inbox/{}",
					&g.server_info.url_base, actor_address, object_id
				),
			)
			.body(Body::empty())
			.unwrap(),
	));
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
				serde_json::to_value(CreateActivity::new_public_note(
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
	json_response(
		&feed,
		Some("application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""),
	)
}

fn current_timestamp() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_millis() as _
}

/// Puts the activity in the send queue for each following server, that will be
/// processed somewhere in the future
async fn populate_send_queue_from_new_object(
	g: &Global, actor_address: &ActorAddress, object: object::Model, payload: ObjectPayloadInfo,
) -> db::Result<()> {
	// Create the activity
	let activity_json = serde_json::to_value(CreateActivity::new_public_note(
		&g.server_info.url_base,
		&actor_address,
		&object.hash,
		object.created as _,
		compose_object_payload(&payload),
	))
	.unwrap();

	// Send the activity to each recipient on the fediverse
	let follower_servers = g
		.api
		.db
		.load_activity_pub_follower_servers(object.actor_id)
		.await?;

	let tx = g.api.db.transaction().await?;

	for server in follower_servers {
		queue_activity(g, object.actor_id, server, None, &activity_json).await?;
	}

	// Mark object as 'published on the fediverse'.
	let mut record = <object::ActiveModel as std::default::Default>::default();
	record.id = Set(object.id);
	record.published_on_fediverse = Set(true);
	object::Entity::update(record).exec(tx.inner()).await?;

	tx.commit().await?;
	Ok(())
}

async fn populate_send_queue_from_new_objects(g: &Global, limit: u64) -> db::Result<()> {
	let mut objects = object::Entity::find()
		.join(JoinType::InnerJoin, object::Relation::Identity.def())
		.filter(object::Column::PublishedOnFediverse.eq(false))
		.filter(object::Column::Type.ne(OBJECT_TYPE_PROFILE))
		.order_by_asc(object::Column::Id)
		.all(g.api.db.inner())
		.await?;
	// FIXME: If a lot of objects remain incomplete (without their main content
	// downloaded too), then this could load many objects into memory which will not
	// be used. It is better to add another column (e.g. has_main_content) to the
	// object model so that we don't have to load them into memory and then execute
	// another query just to find out if the object can be published on the
	// fediverse.

	let mut i = 0;
	for object in objects {
		// Ignore profile update objects
		if let Some(payload_info) = g
			.api
			.db
			.load_object_payload_info(object.id, object.r#type)
			.await?
		{
			// Ignore objects that don't have enough info on them yet to display them yet
			if payload_info.has_main_content() {
				// TODO: Don't query for the address for each object.
				if let Some(actor) = identity::Entity::find_by_id(object.actor_id)
					.one(g.api.db.inner())
					.await?
				{
					populate_send_queue_from_new_object(g, &actor.address, object, payload_info)
						.await?;

					// Enforce max limit on number of objects being put in the send queue
					i += 1;
					if i >= limit {
						break;
					}
				}
			}
		}
	}
	Ok(())
}


/// Queues the given ActivitySteams object to be sent to the recipient at
/// somewhere in the future.
/// If `recipient_path` is `None`, the activity will be send to the server's
/// shared inbox, otherwise it will be send to the actor's inbox.
async fn queue_activity(
	g: &Global, actor_id: i64, recipient_server: String, recipient_path: Option<String>,
	object: &impl Serialize,
) -> db::Result<bool> {
	// FIXME: Check if the queue is over capacity, in which case nothing will be
	// done.
	let (query, vals) = sea_query::Query::select()
		.expr(Expr::col(activity_pub_send_queue::Column::Id).count())
		.from(Alias::new(
			activity_pub_object::Entity::default().table_name(),
		))
		.build_any(&*g.api.db.backend().get_query_builder());
	let result = g
		.api
		.db
		.inner()
		.query_one(Statement::from_sql_and_values(
			g.api.db.backend(),
			query,
			vals,
		))
		.await?
		.expect("count query returned 0 rows");
	let count: i64 = result.try_get_by_index(0)?;

	// If send queue isn't overloaded, add to queue
	if (count as u64)
		< g.config
			.activity_pub_send_queue_capacity
			.unwrap_or(SEND_QUEUE_DEFAULT_CAPACITY)
	{
		let record = activity_pub_send_queue::ActiveModel {
			id: NotSet,
			actor_id: Set(actor_id),
			recipient_server: Set(recipient_server),
			recipient_path: Set(recipient_path),
			object: Set(serde_json::to_string(object).unwrap()),
			last_fail: Set(None),
			failures: Set(0),
		};
		activity_pub_send_queue::Entity::insert(record)
			.exec(g.api.db.inner())
			.await?;
		Ok(true)
	} else {
		warn!("Send queue is full, dropping activity.");
		Ok(false)
	}
}
/// Runs the loop that continually processes the ActivityPub send-queue, sending
/// activities to their intended recipients.
///
/// The sending of activities is being rate limited, in case the server is being
/// overloaded. This may happen because there is no real limit on the number of
/// instances that can follow an actor. So if this causes too many activities to
/// be sent out, at least it is limited so that the network doesn't get
/// constipated.
pub async fn loop_send_queue(stop_flag: Arc<AtomicBool>, g: Arc<Global>) {
	let mut last_iteration = current_timestamp();
	while !stop_flag.load(Ordering::Relaxed) {
		// Generate queue items for any new objects not published on the fediverse yet.
		let g2 = g.clone();
		let join_handle = spawn(async move {
			match populate_send_queue_from_new_objects(&g2, 100).await {
				Ok(()) => {}
				Err(e) => {
					warn!(
						"Database error while populating AtivityPub send queue for new objects: \
						 {:?}",
						e
					);
				}
			}
		});

		// Not very proud of it, but wanted to make a rate-limiter pretty quick
		// TODO: Make the rate limit configurable
		let next_iteration = last_iteration + 10000;
		let now = current_timestamp();
		if now < next_iteration {
			sleep(Duration::from_millis(next_iteration - now)).await;
		}
		last_iteration = now;

		// Get the first 100 queue items that have not already failed somewhere in the
		// last hour TODO: Get the actor address in this query as well
		let mut result =
			activity_pub_send_queue::Entity::find()
				.filter(activity_pub_send_queue::Column::LastFail.is_null().or(
					activity_pub_send_queue::Column::LastFail.lt(current_timestamp() - 3600000),
				))
				.order_by_asc(activity_pub_send_queue::Column::Id)
				.limit(100)
				.all(g.api.db.inner())
				.await;
		match result {
			Err(e) => error!(
				"Database error while trying to query the ActivityPub send-queue: {:?}",
				e
			),
			Ok(records) =>
				for record in records {
					let g2 = g.clone();
					spawn(async move {
						let item_id = record.id;
						if let Err(e) = process_next_send_queue_item(&g2, record).await {
							error!(
								"Unable to process ActivityPub send-queue activity {}: {:?}",
								item_id, e
							);
						}
					});
					sleep(Duration::from_millis(100)).await;
				},
		}

		join_handle.await;
	}
}

/// Attempts to send the given send-queue activity.
async fn process_next_send_queue_item(
	g: &Global, record: activity_pub_send_queue::Model,
) -> db::Result<()> {
	let mut send_state = ActivitySendState::Impossible;
	if let Some(actor_record) = identity::Entity::find_by_id(record.actor_id)
		.one(g.api.db.inner())
		.await?
	{
		let actor_address = actor_record.address;
		send_state = match send_activity(
			g,
			&actor_address,
			&record.recipient_server,
			record.recipient_path.as_ref().map(|p| p.as_str()),
			record.object.clone(),
		)
		.await
		{
			Ok(r) => r,
			Err(e) => {
				warn!(
					"Unable to contact {} to sent activity object to: {}",
					&record.recipient_server, e
				);
				return Ok(());
			}
		};
	}

	if send_state == ActivitySendState::Send || send_state == ActivitySendState::Impossible {
		activity_pub_send_queue::Entity::delete_by_id(record.id)
			.exec(g.api.db.inner())
			.await?;
	} else {
		if record.failures < 24 {
			warn!(
				"Failed to sent ActivityPub activity {} (attempt {}).",
				record.id,
				record.failures + 1
			);
			let updated = activity_pub_send_queue::ActiveModel {
				id: Set(record.id),
				actor_id: NotSet,
				object: NotSet,
				recipient_server: NotSet,
				recipient_path: NotSet,
				last_fail: Set(Some(current_timestamp() as _)),
				failures: Set(record.failures + 1),
			};
			activity_pub_send_queue::Entity::update(updated)
				.exec(g.api.db.inner())
				.await?;
		} else {
			warn!(
				"Failed to sent ActitityPub activity {} after 5 retries. Dropping activity from \
				 send-queue.",
				record.id
			);
			activity_pub_send_queue::Entity::delete_by_id(record.id)
				.exec(g.api.db.inner())
				.await?;
		}
	}
	Ok(())
}

async fn fetch_actor(
	server: &str, actor_path: &str,
) -> Result<Option<serde_json::Value>, reqwest::Error> {
	let actor_url = server.to_string() + actor_path;
	let response = HTTP_CLIENT.get(&actor_url).send().await?;

	// Test content type
	let content_type = if let Some(value) = response.headers().get("content-type") {
		match value.to_str() {
			Ok(v) => v,
			Err(e) => {
				warn!(
					"Content-Type header is not a string for {}: {}",
					&actor_url, e
				);
				return Ok(None);
			}
		}
	} else {
		return Ok(None);
	};
	if !content_type.starts_with("application/ld+json")
		&& !content_type.starts_with("application/activity+json")
	{
		warn!(
			"Unexpected Content-Type header received for {}: {}",
			&actor_url, content_type
		);
		return Ok(None);
	}

	// Parse JSON
	let response_body = response.text().await.unwrap();
	let response_json = match serde_json::from_str(&response_body) {
		Ok(r) => r,
		Err(e) => {
			warn!("Malformed JSON response for {}: {}", &actor_url, e);
			return Ok(None);
		}
	};
	Ok(response_json)
}

// Tries to find the relevant inbox
async fn find_inbox(
	g: &Global, recipient_server: &str, recipient_path: Option<&str>,
) -> db::Result<Option<String>> {
	// Check if we know it already
	if let Some(path) = recipient_path {
		let result = activity_pub_actor_inbox::Entity::find()
			.filter(activity_pub_actor_inbox::Column::Server.eq(recipient_server))
			.filter(activity_pub_actor_inbox::Column::Server.eq(path))
			.one(g.api.db.inner())
			.await?;
		if let Some(record) = result {
			return Ok(Some(record.inbox));
		}
	} else {
		let result = activity_pub_shared_inbox::Entity::find_by_id(recipient_server)
			.one(g.api.db.inner())
			.await?;
		if let Some(record) = result {
			return Ok(record.shared_inbox);
		}
	}

	// Otherwise, find the relevant inbox from the actor
	let result = activity_pub_follow::Entity::find()
		.filter(activity_pub_follow::Column::Server.eq(recipient_server))
		.one(g.api.db.inner())
		.await?;
	if let Some(record) = result {
		let result2 = match fetch_actor(recipient_server, &record.path).await {
			Ok(r) => r,
			Err(e) => {
				warn!(
					"Unable to fetch actor {}{}: {}",
					recipient_server, &record.path, e
				);
				return Ok(None);
			}
		};
		if let Some(json) = result2 {
			// Parse inbox URLs
			let inbox = if recipient_path.is_some() {
				if let Some(v) = json.get("inbox") {
					match v {
						serde_json::Value::String(url) => Some(url.clone()),
						_ => None,
					}
				} else {
					None
				}
			} else {
				if let Some(e) = json.get("endpoints") {
					if let Some(v) = e.get("sharedInbox") {
						match v {
							serde_json::Value::String(url) => Some(url.clone()),
							_ => None,
						}
					} else {
						None
					}
				} else {
					None
				}
			};
			Ok(inbox)
		} else {
			Ok(None)
		}
	} else {
		Ok(None)
	}
}

fn hash_activity(activity: &str) -> String {
	let mut hashes = Sha256::new();
	hashes.update(activity);
	let hash = hashes.finalize();
	BASE64_STANDARD.encode(&hash)
}

fn sign_activity(shared_inbox_url: &Url, date_header: &str) -> String {
	// Prepare sign data
	let sign_data = format!(
		"(request-target): post {}\nhost: {}\ndate: {}",
		shared_inbox_url.path(),
		shared_inbox_url.domain().unwrap(),
		date_header
	);

	// Sign data
	let private_key = RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY).unwrap();
	let signing_key = SigningKey::<Sha256>::new(private_key);
	let signature = signing_key.sign_with_rng(&mut OsRng, sign_data.as_bytes());
	BASE64_STANDARD.encode(&signature.to_bytes())
}

async fn send_activity(
	g: &Global, actor_address: &ActorAddress, recipient_server: &str, recipient_path: Option<&str>,
	activity: String,
) -> db::Result<ActivitySendState> {
	// Get & parse the shared inbox url
	let (inbox_url_raw) = if let Some(si) = find_inbox(g, recipient_server, recipient_path).await? {
		si
	} else {
		return Ok(ActivitySendState::Impossible);
	};
	let inbox_url = match Url::parse(&inbox_url_raw) {
		Ok(r) => r,
		Err(e) => {
			warn!("Invalid shared inbox URL {}: {}", &inbox_url_raw, e);
			return Ok(ActivitySendState::Impossible);
		}
	};
	if inbox_url.domain().is_none() {
		warn!("No domain in shared inbox URL {}", &inbox_url_raw);
		return Ok(ActivitySendState::Impossible);
	}

	// Sign the activity
	let date_header = Local::now().to_rfc2822();
	let body_digest = hash_activity(&activity);
	let digest_header = format!("sha-256={}", BASE64_STANDARD.encode(&body_digest));
	let signature = sign_activity(&inbox_url, &date_header);
	let signature_header = format!(
		"keyId=\"{}/actor/{}#main-key\",headers=\"(request-target) host date \
		 digest\",signature=\"{}\"",
		&g.server_info.url_base, actor_address, signature
	);

	// Exchange request/response
	let result = HTTP_CLIENT
		.post(inbox_url)
		.header(
			"Content-Type",
			"application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
		)
		.header("Date", date_header)
		.header("Digest", digest_header)
		.header("Signature", signature_header)
		.body(activity)
		.send()
		.await;
	let response = match result {
		Ok(r) => r,
		Err(e) => {
			warn!(
				"Unable to post activity object at {}: {}",
				&inbox_url_raw, e
			);
			return Ok(ActivitySendState::Failed);
		}
	};

	if response.status() == 201 || response.status() == 200 {
		return Ok(ActivitySendState::Send);
	}
	warn!(
		"Unable to post activity object at {}: response status {}",
		inbox_url_raw,
		response.status()
	);
	Ok(ActivitySendState::Failed)
}

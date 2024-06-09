pub mod actor;


use std::{
	borrow::Cow,
	io,
	result::Result as StdResult,
	str::FromStr,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc, OnceLock,
	},
	time::Duration,
};

use axum::http::HeaderMap;
use base64::prelude::*;
use chrono::{SecondsFormat, Utc};
use lazy_static::lazy_static;
use log::*;
use reqwest::Url;
use rsa::{
	pkcs1v15::{SigningKey, VerifyingKey},
	pkcs8::{DecodePrivateKey, DecodePublicKey},
	sha2::{Digest, Sha256},
	signature::{SignatureEncoding, Signer, Verifier},
	RsaPrivateKey, RsaPublicKey,
};
use sea_orm::{
	prelude::*,
	sea_query::{self, Alias},
	JoinType, NotSet, Order, QueryOrder, QuerySelect, QueryTrait, Set, Statement,
};
use serde::{Serialize, Serializer};
use tokio::{spawn, time::sleep};
use zeroize::Zeroizing;

use crate::{
	activity_pub,
	api::OtherObjectInfo,
	common::{current_timestamp, IdType},
	config::Config,
	core::{ActorAddress, Address, OBJECT_TYPE_PROFILE},
	db::{self, Database, ObjectPayloadInfo, PersistenceHandle},
	entity::{self, *},
	trace,
	util::read_text_file,
	web::Global,
};


pub const DEFAULT_CONTEXT: ActivityPubDocumentContext = ActivityPubDocumentContext(&[
	"https://www.w3.org/ns/activitystreams",
	"https://w3id.org/security/v1",
]);
const SEND_QUEUE_DEFAULT_CAPACITY: u64 = 100000;


#[derive(Serialize)]
pub struct AcceptActivity {
	#[serde(rename(serialize = "@context"), default)]
	pub context: ActivityPubDocumentContext,
	pub r#type: AcceptActivityType,
	pub id: String,
	pub actor: String,
	pub to: Vec<String>,
	pub object: serde_json::Value,
}
pub struct AcceptActivityType;

#[derive(Serialize)]
pub struct ActivityObject {
	id: String,
	r#type: ActivityObjectType,
	content: String,
	source: ActivityObjectSource,
	published: DateTime,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct ActivityObjectSource {
	content: String,
	mediaType: MediaType,
}

#[derive(Serialize)]
pub enum ActivityObjectType {
	Note,
}

#[derive(Serialize)]
pub struct ActivityPubDocumentContext(pub &'static [&'static str]);

#[derive(PartialEq)]
pub enum ActivitySendState {
	Send,
	Failed,
	Impossible,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct ActorObject {
	#[serde(rename(serialize = "@context"), default)]
	context: ActivityPubDocumentContext,
	id: String,
	r#type: &'static str,
	name: String,
	preferredUsername: String,
	url: String,
	inbox: String,
	outbox: String,
	followers: String,
	summary: String,

	publicKey: Option<ActorPublicKey>,
	icon: Option<ActorObjectIcon>,

	nodeInfo2Url: String,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct ActorObjectIcon {
	r#type: &'static str,
	url: String,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct ActorPublicKey {
	id: String,
	owner: String,
	publicKeyPem: String,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct ActorPublicKeyWithContext {
	#[serde(rename(serialize = "@context"), default)]
	pub context: ActivityPubDocumentContext,
	pub id: String,
	pub owner: String,
	pub publicKeyPem: String,
}

#[derive(Serialize)]
pub struct CreateActivity {
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

pub struct CreateActivityType;

pub struct DateTime(u64);

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

pub enum MediaType {
	Markdown,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
pub struct OrderedCollection {
	#[serde(rename(serialize = "@context"), default)]
	pub context: ActivityPubDocumentContext,
	pub summary: &'static str,
	pub r#type: OrderedCollectionType,
	pub totalItems: usize,
	pub orderedItems: Vec<serde_json::Value>,
}

pub struct OrderedCollectionType;

pub type Result<T> = trace::Result<T, Error>;

#[derive(Serialize)]
pub struct WebFingerDocument {
	subject: String,
	aliases: Vec<String>,
	links: Vec<WebFingerDocumentLink>,
}

#[derive(Serialize)]
pub struct WebFingerDocumentLink {
	rel: &'static str,
	r#type: &'static str,
	href: String,
}


lazy_static! {
	pub static ref HTTP_CLIENT: reqwest::Client = {
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
	pub static ref PUBLIC_KEY: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
}


async fn collect_activity(db: &Database, item: &serde_json::Value, page_url: &str) -> Result<()> {
	let when = || format!("collecting activity for page {}", page_url).into();

	// Verify activity type first: only use Create activities
	if let Some(object_type) = item.get("type") {
		match expect_string(&object_type, &when)?.as_str() {
			"Create" => {}
			_ => return Ok(()),
		}
	} else {
		Err(Error::UnexpectedBehavior(
			"missing type property in activity object".into(),
			when(),
		))?;
	}
	let object = match item.get("object") {
		Some(o) => o,
		None =>
			return Err(Error::UnexpectedBehavior(
				"missing object property in activity object".into(),
				when(),
			))?,
	};

	// Collect actor if needed
	let actor = if let Some(actor_val) = item.get("actor") {
		let actor_url = expect_url(actor_val, &when)?;
		actor::ensure(db, &actor_url, None, &when).await?
	} else {
		return Err(Error::UnexpectedBehavior(
			"missing actor property in activity object".into(),
			when(),
		))?;
	};

	// Parse publish date
	let published = if let Some(published_val) = item.get("published") {
		let string = expect_string(published_val, &when)?;
		match chrono::DateTime::parse_from_rfc3339(string) {
			Ok(dt) => dt.timestamp_millis() as u64,
			Err(e) => {
				warn!(
					"Couldn't parse published date \"{}\" of ActivityPub object: {}",
					string, e
				);
				current_timestamp()
			}
		}
	} else {
		current_timestamp()
	};

	// Collect object property
	store_object(db, actor.id, published, object, &when).await?;
	Ok(())
}

async fn collect_activities(db: &Database, json: &serde_json::Value, url: &str) -> Result<()> {
	if let Some(ordered_items_val) = json.get("orderedItems") {
		let items = expect_array(&ordered_items_val, &|| {
			format!("parsing ordered list on {}", url).into()
		})?;
		for item in items {
			collect_activity(db, item, url).await?;
		}
	}
	Ok(())
}

pub fn compose_object_payload(payload: &ObjectPayloadInfo) -> String {
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

fn expect_array<'a>(
	value: &'a serde_json::Value, when: &impl Fn() -> Cow<'static, str>,
) -> Result<&'a Vec<serde_json::Value>> {
	match value {
		serde_json::Value::Array(r) => Ok(r),
		_ => Err(Error::UnexpectedJsonType("array", when()))?,
	}
}

#[allow(unused)]
fn expect_object<'a>(
	value: &'a serde_json::Value, when: &impl Fn() -> Cow<'static, str>,
) -> Result<&'a serde_json::Map<String, serde_json::Value>> {
	match value {
		serde_json::Value::Object(r) => Ok(r),
		_ => Err(Error::UnexpectedJsonType("object", when()))?,
	}
}

fn expect_string<'a>(
	value: &'a serde_json::Value, when: &impl Fn() -> Cow<'static, str>,
) -> Result<&'a String> {
	match value {
		serde_json::Value::String(s) => Ok(s),
		_ => Err(Error::UnexpectedJsonType("string", when()))?,
	}
}

fn expect_url<'a>(
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

// Tries to find the relevant inbox
async fn find_inbox(
	g: &Global, recipient_server: &str, recipient_path: Option<&str>,
) -> db::Result<Option<String>> {
	// Check if we know it already
	if let Some(path) = recipient_path {
		let result = activity_pub_actor::Entity::find()
			.filter(activity_pub_actor::Column::Host.eq(recipient_server))
			.filter(activity_pub_actor::Column::Path.eq(path))
			.one(g.api.db.inner())
			.await?;
		if let Some(record) = result {
			return Ok(record.inbox);
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
	let result = activity_pub_follower::Entity::find()
		.filter(activity_pub_follower::Column::Host.eq(recipient_server))
		.one(g.api.db.inner())
		.await?;
	if let Some(record) = result {
		let result2 = match activity_pub::actor::fetch2(recipient_server, &record.path).await {
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

pub async fn init(stop_flag: Arc<AtomicBool>, global: Arc<Global>) {
	if let Err(e) = init_public_key(&global.config.activity_pub_public_key).await {
		error!("Unable to load public key for ActivityPub: {}", e);
	}

	if let Some(p) = &global.config.activity_pub_private_key {
		let private_key_path = p.clone();
		spawn(loop_send_queue(stop_flag, global, private_key_path));
	}
}

async fn init_public_key(config: &Option<String>) -> io::Result<()> {
	if let Some(public_key_filename) = &config {
		let key = read_text_file(public_key_filename).await?;
		PUBLIC_KEY.set(key).unwrap();
	}
	Ok(())
}

async fn loop_box_polls(
	stop_flag: Arc<AtomicBool>, db: Database,
	activity_pub_inbox_opt: Option<(String, ActorAddress)>,
) {
	while !stop_flag.load(Ordering::Relaxed) {
		if let Some((activity_pub_inbox_server, actor_address)) = &activity_pub_inbox_opt {
			poll_inbox(&db, &activity_pub_inbox_server, &actor_address).await;
		}
		if let Err(e) = poll_outboxes(stop_flag.clone(), &db).await {
			error!("Database error while polling outboxes: {:?}", e);
		}

		for _ in 0..3600 {
			if !stop_flag.load(Ordering::Relaxed) {
				sleep(Duration::from_secs(1)).await;
			}
		}
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
pub async fn loop_send_queue(stop_flag: Arc<AtomicBool>, g: Arc<Global>, private_key_path: String) {
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
		let result =
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
				if records.len() > 0 {
					let private_key = match read_text_file(&private_key_path).await {
						Ok(pk) => Arc::new(Zeroizing::<String>::new(pk)),
						Err(e) => {
							error!("Unable to load private key file for ActivityPub: {}", e);
							continue;
						}
					};
					let mut i = 0;
					let len = records.len();
					for record in records {
						let g2 = g.clone();
						let pk = private_key.clone();
						spawn(async move {
							let item_id = record.id;
							if let Err(e) = process_next_send_queue_item(&g2, record, pk).await {
								error!(
									"Unable to process ActivityPub send-queue activity {}: {:?}",
									item_id, e
								);
							}
						});
						if i < (len - 1) {
							sleep(Duration::from_millis(100)).await;
						}
						i += 1;
					}
				},
		}

		if let Err(e) = join_handle.await {
			error!("Send queue join error: {}", e);
		}
	}
}

pub fn maintain_outbox_polls(stop_flag: Arc<AtomicBool>, db: Database, config: &Config) {
	let inbox_info = if let Some(inbox_server) = &config.activity_pub_inbox_server {
		if let Some(address_string) = &config.activity_pub_inbox_actor {
			match Address::from_str(address_string)
				.expect("Invalid actor address for activity_pub_inbox_actor")
			{
				Address::Actor(a) => Some((inbox_server.to_string(), a)),
				_ => {
					warn!(
						"ActivityPub inbox actor {} is not an actor address.",
						address_string
					);
					None
				}
			}
		} else {
			warn!(
				"Polling the ActivityPub inbox on {} doesn't work because config \
				 \"activity_pub_inbox_server\" isn't set.",
				inbox_server
			);
			None
		}
	} else {
		None
	};

	spawn(loop_box_polls(stop_flag, db, inbox_info));
}

pub fn parse_account_name(resource: &str) -> Option<&str> {
	if !resource.starts_with("acct:") {
		return None;
	}

	if let Some(i) = resource.find('@') {
		return Some(&resource[5..i]);
	}
	None
}

pub fn parse_post_object(raw_json: &str) -> Result<OtherObjectInfo> {
	let json = serde_json::Value::from_str(raw_json)
		.map_err(|e| Error::Deserialization(e, format!("parsing object").into()))?;

	let activity_type = if let Some(activity_type_val) = json.get("type") {
		expect_string(activity_type_val, &|| {
			format!("parsing activity type").into()
		})?
	} else {
		return Err(Error::UnexpectedBehavior(
			"missing type property".into(),
			"...".into(),
		))?;
	};
	if activity_type != "Note" {
		return Err(Error::UnexpectedBehavior(
			format!("unknown activity type: {}", activity_type).into(),
			"...".into(),
		))?;
	}

	let content = if let Some(content_val) = json.get("content") {
		expect_string(content_val, &|| format!("parsing activity content").into())?
	} else {
		return Err(Error::UnexpectedBehavior(
			"missing content property".into(),
			"...".into(),
		))?;
	};

	Ok(OtherObjectInfo {
		mime_type: "text/html".to_string(),
		content: content.clone(),
	})
}

pub fn parse_webfinger_link(
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

pub async fn poll_box(db: &Database, box_url: &str) -> Result<()> {
	let response = match HTTP_CLIENT.get(box_url).send().await {
		Ok(r) => match r.text().await {
			Ok(r) => r,
			Err(e) => Err(Error::Network(
				e,
				format!("collecting outbox body for {}", box_url).into(),
			))?,
		},
		Err(e) => Err(Error::Network(
			e,
			format!("reaching outbox {}", box_url).into(),
		))?,
	};
	let box_json = match serde_json::Value::from_str(&response) {
		Ok(r) => r,
		Err(e) => Err(Error::Deserialization(
			e,
			format!("parsing JSON for outbox {}", box_url).into(),
		))?,
	};

	if let Some(page_url_value) = box_json.get("first") {
		let first_page_url = expect_string(page_url_value, &|| {
			format!("parsing first outbox page of {}", box_url).into()
		})?;

		let response = match HTTP_CLIENT.get(first_page_url).send().await {
			Ok(r) => match r.text().await {
				Ok(r) => r,
				Err(e) => Err(Error::Network(
					e,
					format!("collecting activities on {}", first_page_url).into(),
				))?,
			},
			Err(e) => Err(Error::Network(
				e,
				format!("reaching outbox page on {}", first_page_url).into(),
			))?,
		};
		let first_page_json = match serde_json::Value::from_str(&response) {
			Ok(r) => r,
			Err(e) => Err(Error::Deserialization(
				e,
				format!("parsing JSON for outbox {}", first_page_url).into(),
			))?,
		};

		collect_activities(db, &first_page_json, &first_page_url).await
	} else {
		collect_activities(db, &box_json, box_url).await
	}
}

async fn poll_inbox(db: &Database, inbox_server: &str, inbox_actor_address: &ActorAddress) {
	let inbox_url = format!(
		"https://{}/actor/{}/activity-pub/inbox",
		inbox_server, inbox_actor_address
	);
	if let Err(e) = poll_box(db, &inbox_url).await {
		warn!("Error while polling outbox {}: {:?}", &inbox_url, e);
	}
}

async fn poll_outboxes(stop_flag: Arc<AtomicBool>, db: &Database) -> db::Result<()> {
	let following_actors = activity_pub_actor::Entity::find()
		.filter(
			activity_pub_actor::Column::Id.in_subquery(
				activity_pub_following::Entity::find()
					.select_only()
					.column(activity_pub_following::Column::ActorId)
					.into_query(),
			),
		)
		.all(db.inner())
		.await?;

	for following in following_actors {
		if !stop_flag.load(Ordering::Relaxed) {
			if let Some(outbox_url) = &following.outbox {
				if let Err(e) = poll_box(db, outbox_url).await {
					warn!("Error while polling outbox {}: {:?}", outbox_url, e);
				}
			}
		}
	}
	Ok(())
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
		queue_activity(g, &tx, object.actor_id, server, None, &activity_json).await?;
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
	let objects = object::Entity::find()
		.join(JoinType::InnerJoin, object::Relation::Actor.def())
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
				if let Some(actor) = entity::actor::Entity::find_by_id(object.actor_id)
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

/// Attempts to send the given send-queue activity.
async fn process_next_send_queue_item(
	g: &Global, record: activity_pub_send_queue::Model, private_key: Arc<Zeroizing<String>>,
) -> db::Result<()> {
	let mut send_state = ActivitySendState::Impossible;
	if let Some(actor_record) = entity::actor::Entity::find_by_id(record.actor_id)
		.one(g.api.db.inner())
		.await?
	{
		let actor_address = actor_record.address;
		info!(
			"Sending activity {} to {}...",
			record.id, &record.recipient_server
		);
		send_state = match send_activity(
			g,
			&actor_address,
			&record.recipient_server,
			record.recipient_path.as_ref().map(|p| p.as_str()),
			record.object.clone(),
			private_key.as_ref(),
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

	let mut recipient = record.recipient_server.clone();
	if let Some(path) = &record.recipient_path {
		recipient += path;
	}
	match send_state {
		ActivitySendState::Send => {
			info!("Sent activity {} to {}.", record.id, recipient);
			activity_pub_send_queue::Entity::delete_by_id(record.id)
				.exec(g.api.db.inner())
				.await?;
		}
		ActivitySendState::Impossible => {
			warn!(
				"Impossible to send activity {} to {}.",
				record.id, recipient
			);
			activity_pub_send_queue::Entity::delete_by_id(record.id)
				.exec(g.api.db.inner())
				.await?;
		}
		ActivitySendState::Failed => {
			if record.failures < 7 * 24 {
				let attempt = record.failures + 1;
				warn!(
					"Failed to send activity {} to {} this time. (Attempt #{})",
					record.id, recipient, attempt
				);
				let mut updated =
					<activity_pub_send_queue::ActiveModel as std::default::Default>::default();
				updated.id = Set(record.id);
				updated.last_fail = Set(Some(current_timestamp() as _));
				updated.failures = Set(attempt);
				activity_pub_send_queue::Entity::update(updated)
					.exec(g.api.db.inner())
					.await?;
			} else {
				warn!(
					"Failed to sent activity {} to {} after {} retries. Dropping activity from \
					 send-queue.",
					record.id,
					recipient,
					7 * 24
				);
				activity_pub_send_queue::Entity::delete_by_id(record.id)
					.exec(g.api.db.inner())
					.await?;
				// Delete all followers of the recipient server, because the server is deemed to
				// be unresponsive after not responding for a week.
				let mut delete =
					<activity_pub_follower::ActiveModel as std::default::Default>::default();
				delete.actor_id = Set(record.actor_id);
				delete.host = Set(record.recipient_server);
				activity_pub_follower::Entity::delete(delete)
					.exec(g.api.db.inner())
					.await?;
			}
		}
	}
	if send_state == ActivitySendState::Send || send_state == ActivitySendState::Impossible {
		activity_pub_send_queue::Entity::delete_by_id(record.id)
			.exec(g.api.db.inner())
			.await?;
	} else {
	}
	Ok(())
}

/// Queues the given ActivitySteams object to be sent to the recipient at
/// somewhere in the future.
/// If `recipient_path` is `None`, the activity will be send to the server's
/// shared inbox, otherwise it will be send to the actor's inbox.
pub async fn queue_activity(
	g: &Global, db: &impl PersistenceHandle, actor_id: i64, recipient_server: String,
	recipient_path: Option<String>, object: &impl Serialize,
) -> db::Result<bool> {
	// FIXME: Check if the queue is over capacity, in which case nothing will be
	// done.
	let (query, vals) = sea_query::Query::select()
		.expr(Expr::col(activity_pub_send_queue::Column::Id).count())
		.from(Alias::new(
			activity_pub_object::Entity::default().table_name(),
		))
		.build_any(&*db.backend().get_query_builder());
	let result = db
		.inner()
		.query_one(Statement::from_sql_and_values(db.backend(), query, vals))
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
			.exec(db.inner())
			.await?;
		Ok(true)
	} else {
		warn!("Send queue is full, dropping activity.");
		Ok(false)
	}
}

async fn send_activity(
	g: &Global, actor_address: &ActorAddress, recipient_server: &str, recipient_path: Option<&str>,
	activity: String, private_key: &str,
) -> db::Result<ActivitySendState> {
	// Get & parse the shared inbox url
	let inbox_url_raw = if let Some(si) = find_inbox(g, recipient_server, recipient_path).await? {
		si
	} else {
		warn!(
			"Couldn't find the inbox for: {}{}",
			recipient_server,
			recipient_path.unwrap_or("")
		);
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
	let date_header = format!("{}", Utc::now().format("%a, %d %b %Y %T GMT"));
	let body_digest = hash_activity(&activity);
	let digest_header = format!("SHA-256={}", body_digest);
	let signature = sign_activity(&inbox_url, &date_header, &digest_header, private_key);
	let signature_header = format!(
		"keyId=\"{}/actor/{}/activity-pub#main-key\", algorithm=\"rsa-sha256\", \
		 headers=\"(request-target) host date digest content-type\", signature=\"{}\"",
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

	if response.status().as_u16() >= 200 || response.status().as_u16() <= 202 {
		return Ok(ActivitySendState::Send);
	}
	warn!(
		"Unable to post activity object at {}: response status {}",
		inbox_url_raw,
		response.status()
	);
	Ok(ActivitySendState::Failed)
}

fn sign_activity(
	inbox_url: &Url, date_header: &str, digest_header: &str, private_key: &str,
) -> String {
	// Prepare sign data
	let data = format!(
		"(request-target): post {}\nhost: {}\ndate: {}\ndigest: {}\ncontent-type: application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
		inbox_url.path(),
		inbox_url.domain().unwrap(),
		date_header,
		digest_header
	);

	sign_data(&data, private_key)
}

fn sign_data(data: &str, key_pem: &str) -> String {
	// Load key
	let private_key = RsaPrivateKey::from_pkcs8_pem(key_pem).unwrap();
	let signing_key = SigningKey::<Sha256>::new(private_key);

	// Sign
	let signature = signing_key.sign(data.as_bytes());

	// Format with base64
	BASE64_STANDARD.encode(&signature.to_bytes())
}

pub async fn store_inbox_object(
	db: &Database, actor_id: i64, json: &serde_json::Value, when: &impl Fn() -> Cow<'static, str>,
) -> Result<i64> {
	let object_id = match json.get("id") {
		Some(r) => expect_string(r, when)?,
		None =>
			return Err(Error::UnexpectedBehavior(
				"missing an id property on the activity".into(),
				when(),
			))?,
	};

	let record = activity_pub_inbox_object::ActiveModel {
		id: NotSet,
		actor_id: Set(actor_id),
		object_id: Set(object_id.clone()),
		data: Set(json.to_string()),
	};
	let object_id = activity_pub_inbox_object::Entity::insert(record)
		.exec(db.inner())
		.await
		.map_err(|e| Error::from(e))?
		.last_insert_id;

	// Immediately clean up old objects in inbox
	activity_pub_inbox_object::Entity::delete_many()
		.filter(
			activity_pub_object::Column::Id.in_subquery(
				sea_query::Query::select()
					.column(activity_pub_object::Column::Id)
					.from(Alias::new(
						activity_pub_object::Entity::default().table_name(),
					))
					.and_where(activity_pub_object::Column::ActorId.eq(actor_id))
					.order_by(activity_pub_object::Column::Id, Order::Desc)
					.limit(1000)
					.offset(1000)
					.take(),
			),
		)
		.exec(db.inner())
		.await
		.map_err(|e| Error::from(e))?;
	Ok(object_id)
}

/// Stores the object if it hasn't been stored yet, otherwise it returns the
/// record id of the existing record.
pub async fn store_object(
	db: &Database, actor_id: i64, published: u64, json: &serde_json::Value,
	when: &impl Fn() -> Cow<'static, str>,
) -> Result<i64> {
	let object_id = match json.get("id") {
		Some(r) => expect_string(r, when)?,
		None =>
			return Err(Error::UnexpectedBehavior(
				"missing an id property on the activity".into(),
				when(),
			))?,
	};

	if let Some(record) = activity_pub_object::Entity::find()
		.filter(activity_pub_object::Column::ObjectId.eq(object_id))
		.one(db.inner())
		.await
		.map_err(|e| Error::from(e))?
	{
		return Ok(record.id);
	}

	let record = activity_pub_object::ActiveModel {
		id: NotSet,
		actor_id: Set(actor_id),
		published: Set(published as _),
		object_id: Set(object_id.clone()),
		data: Set(json.to_string()),
	};
	let object_id = activity_pub_object::Entity::insert(record)
		.exec(db.inner())
		.await
		.map_err(|e| Error::from(e))?
		.last_insert_id;

	// Immediately clean up old objects in inbox
	activity_pub_object::Entity::delete_many()
		.filter(
			activity_pub_object::Column::Id.in_subquery(
				sea_query::Query::select()
					.column(activity_pub_object::Column::Id)
					.from(Alias::new(
						activity_pub_object::Entity::default().table_name(),
					))
					.and_where(activity_pub_object::Column::ActorId.eq(actor_id))
					.order_by(activity_pub_object::Column::Id, Order::Desc)
					.limit(1000)
					.offset(1000)
					.take(),
			),
		)
		.exec(db.inner())
		.await
		.map_err(|e| Error::from(e))?;
	Ok(object_id)
}

impl Serialize for AcceptActivityType {
	fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str("Accept")
	}
}

impl ActivityObject {
	pub fn new(
		url_base: &str, actor: &ActorAddress, object_hash: &IdType, created: u64, content: String,
	) -> Self {
		Self {
			id: format!(
				"{}/actor/{}/object/{}/activity-pub",
				url_base, actor, object_hash
			),
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

impl ActorObject {
	pub fn new(
		url_base: &str, address: &ActorAddress, name: String, avatar_hash: Option<&IdType>,
		summary: String, public_key: Option<&str>,
	) -> Self {
		let url = format!("{}/actor/{}", url_base, address);
		let id = format!("{}/activity-pub", &url);
		Self {
			context: DEFAULT_CONTEXT,
			id: id.clone(),
			nodeInfo2Url: format!("{}/.well-known/x-nodeinfo2", url_base),
			url,
			r#type: "Person",
			name,
			preferredUsername: address.to_string(),
			inbox: format!("{}/inbox", &id),
			outbox: format!("{}/outbox", &id),
			followers: format!("{}/follower", &id),
			publicKey: public_key.map(|pk| ActorPublicKey {
				id: format!("{}#main-key", &id),
				owner: id.clone(),
				publicKeyPem: pk.to_string(),
			}),
			summary,
			icon: avatar_hash.map(|hash| ActorObjectIcon {
				r#type: "Image",
				url: format!("{}/file/{}", &id, hash),
			}),
		}
	}
}

impl CreateActivity {
	pub fn new_public_note(
		url_base: &str, actor: &ActorAddress, object_hash: &IdType, created: u64, content: String,
	) -> Self {
		Self {
			context: ActivityPubDocumentContext::default(),
			r#type: CreateActivityType,
			id: format!(
				"{}/actor/{}/object/{}/activity-pub",
				url_base, &actor, &object_hash
			),
			actor: format!("{}/actor/{}/activity-pub", url_base, &actor),
			object: ActivityObject::new(url_base, actor, object_hash, created, content),
			published: DateTime(created),
			to: vec![format!(
				"{}/actor/{}/activity-pub/follower",
				url_base, actor
			)],
			cc: Some(vec![
				"https://www.w3.org/ns/activitystreams#Public".to_string(),
			]),
		}
	}
}

impl Serialize for CreateActivityType {
	fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str("Create")
	}
}

impl Serialize for DateTime {
	fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let dt = chrono::DateTime::from_timestamp_millis(self.0 as _).unwrap();
		serializer.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Millis, true))
	}
}

impl From<sea_orm::DbErr> for self::Error {
	fn from(value: sea_orm::DbErr) -> Self { Self::Database(db::Error::OrmError(value)) }
}

impl Serialize for MediaType {
	fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match self {
			Self::Markdown => serializer.serialize_str("text/markdown"),
		}
	}
}

impl Serialize for OrderedCollectionType {
	fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str("OrderedCollection")
	}
}

impl WebFingerDocument {
	pub fn new(domain: &str, url_base: &str, type_: &str, address: &Address) -> Self {
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


mod tests {
	#[allow(unused_imports)]
	use rsa::{
		pkcs1::DecodeRsaPrivateKey,
		pkcs8::{EncodePrivateKey, LineEnding},
		RsaPrivateKey,
	};

	use super::*;

	#[allow(dead_code)]
	fn verify_data(data: &str, signature: &str, public_key: &str) -> bool {
		let raw_signature = BASE64_STANDARD.decode(signature).unwrap();
		let signature = rsa::pkcs1v15::Signature::try_from(raw_signature.as_slice()).unwrap();
		let public_key = RsaPublicKey::from_public_key_pem(public_key).unwrap();
		let verifying_key = VerifyingKey::<Sha256>::new(public_key);
		verifying_key.verify(data.as_bytes(), &signature).is_ok()
	}

	#[test]
	fn test_signature() {
		// All test data is taken from: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures#appendix-C.3
		let public_key_pem = r#"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----"#;
		let private_key_pem = r#"-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF
NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F
UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB
AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA
QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK
kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg
f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u
412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc
mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7
kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA
gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW
G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI
7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==
-----END RSA PRIVATE KEY-----"#;
		let private_key_pem_pkcs8 = RsaPrivateKey::from_pkcs1_pem(private_key_pem)
			.unwrap()
			.to_pkcs8_pem(LineEnding::LF)
			.unwrap();

		let data = r#"(request-target): post /foo?param=value&pet=dog
host: example.com
date: Sun, 05 Jan 2014 21:31:40 GMT
content-type: application/json
digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
content-length: 18"#;

		let signature = sign_data(data, &*private_key_pem_pkcs8);
		assert_eq!(
			signature,
			"vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="
		);
		assert!(verify_data(data, &signature, public_key_pem));
	}
}

use std::{
	collections::HashMap,
	io,
	result::Result as StdResult,
	str::FromStr,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc, OnceLock,
	},
	time::Duration,
};

use axum::{
	body::Body,
	extract::{Query, State},
	response::Response,
	routing::*,
	*,
};
use axum_extra::extract::CookieJar;
use email_address_parser::EmailAddress;
use extract::{Multipart, Path};
use lazy_static::lazy_static;
use log::*;
use reqwest::Url;
use sea_orm::{prelude::*, NotSet, QueryOrder, QuerySelect, Set};
use serde::*;
use tera::Context;
use tokio::{spawn, time::sleep};
use zeroize::Zeroizing;

use super::{
	common::*, current_timestamp, translate_special_mime_types_for_object, ActorAddress, Address,
	IdType, ServerGlobal,
};
use crate::{
	db::{self, PersistenceHandle},
	entity::*,
	trace::Traceable,
	util::read_text_file,
	web::{
		self,
		activity_pub::{
			self, compose_activity_from_object_info, AcceptActivity, AcceptActivityType,
			ActivityNoteObject, ActorObject, ActorPublicKey, OrderedCollection,
			OrderedCollectionType, WebFingerDocument, DEFAULT_CONTEXT, SECURE_CONTEXT,
		},
		info::{find_profile_info, load_actor_feed, ProfileObjectInfo, TargetedActorInfo},
		json::expect_url,
		server::Global,
		Error, Result,
	},
};

#[derive(Deserialize)]
struct ActorActions {
	follow: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct NodeInfo2 {
	version: NodeInfoVersion,
	server: NodeInfoServer,
	organization: NodeInfoOrganization,
	protocols: Vec<String>,
	openRegistrations: bool,
	usage: NodeInfoUsage,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct NodeInfoOrganization {
	name: Option<String>,
	contact: Option<String>,
	account: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct NodeInfoServer {
	baseUrl: String,
	name: String,
	software: &'static str,
	version: String,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct NodeInfoUsage {
	users: NodeInfoUsageUsers,
	//totalPosts: u64,
}

#[allow(non_snake_case)]
#[derive(Serialize)]
struct NodeInfoUsageUsers {
	total: u64,
	//activeHalfyear: u64,
	//activeWeek: u64,
}

struct NodeInfoVersion;

lazy_static! {
	pub static ref PUBLIC_KEY: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
}

impl Serialize for NodeInfoVersion {
	fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str("1.0")
	}
}

async fn activity_pub_actor_post(
	State(g): State<Arc<ServerGlobal>>, Path(address): Path<String>,
	Form(form_data): Form<ActorActions>,
) -> Response {
	let webfinger_addr = match EmailAddress::parse(&address[1..], None) {
		Some(r) => r,
		None => return server_error_response2("Invalid webfinger address"),
	};

	if let Some(follow) = &form_data.follow {
		// Follow
		if follow == "1" {
			let actor_url = match web::webfinger::resolve(&webfinger_addr).await {
				Ok(r) => {
					if let Some(url) = r {
						url
					} else {
						return server_error_response2(
							"Webfinger address doesn't have an ActivityPub actor URL",
						);
					}
				}
				Err(e) => {
					return server_error_response(
						e,
						&format!("Error while resolving webfinger {}", &webfinger_addr),
					);
				}
			};
			let actor = match activity_pub::actor::ensure(
				&g.base.api.db,
				&actor_url,
				Some(&webfinger_addr),
				&|| {
					format!(
						"following ActivityPub actor with webfinger address {}",
						&webfinger_addr
					)
					.into()
				},
			)
			.await
			{
				Ok(r) => r,
				Err(e) => return server_error_response(e, "Error"),
			};
			let model = activity_pub_following::ActiveModel {
				actor_id: Set(actor.id),
			};
			if let Err(e) = activity_pub_following::Entity::insert(model)
				.exec(g.base.api.db.inner())
				.await
			{
				return server_error_response(e, "Database error while storing following");
			}

			// Poll the outbox
			if let Some(outbox_url) = actor.outbox {
				let db = g.base.api.db.clone();
				spawn(async move {
					if let Err(e) = activity_pub::poll_box(&db, &outbox_url).await {
						warn!(
							"Unable to poll outbox {} for newly followed actor: {:?}",
							&outbox_url, e
						);
					}
				});
			}
		// Unfollow
		} else {
			let result = match activity_pub_actor::Entity::find()
				.filter(activity_pub_actor::Column::Address.eq(webfinger_addr.to_string()))
				.one(g.base.api.db.inner())
				.await
			{
				Ok(r) => r,
				Err(e) => {
					return server_error_response(
						e,
						&format!(
							"Database error while looking up actor with webfinger address {}",
							&webfinger_addr
						),
					);
				}
			};
			if let Some(record) = result {
				if let Err(e) = activity_pub_following::Entity::delete_many()
					.filter(activity_pub_following::Column::ActorId.eq(record.id))
					.exec(g.base.api.db.inner())
					.await
				{
					return server_error_response(
						e,
						&format!(
							"Database error while unfollowing actor with webfinger address {}",
							&webfinger_addr
						),
					);
				}
			} else {
				return server_error_response2(&format!(
					"Actor with webfinger address {} not found",
					webfinger_addr
				));
			}
		}
	}

	activity_pub_actor_get(State(g), Path(address)).await
}

async fn activity_pub_actor_get(
	State(g): State<Arc<ServerGlobal>>, Path(address): Path<String>,
) -> Response {
	let webfinger_addr = match EmailAddress::parse(&address[1..], None) {
		Some(r) => r,
		None => return server_error_response2("Invalid webfinger address"),
	};
	let actor_json_result = match activity_pub::actor::fetch_from_webfinger(&webfinger_addr).await {
		Ok(r) => r,
		Err(e) => {
			return server_error_response(e, "Unable to fetch actor URL from webfinger");
		}
	};
	// TODO: Update our activity_pub_actor record or create it if it isn't there yet
	let actor_json = if let Some(r) = actor_json_result {
		r
	} else {
		return server_error_response2("Actor URL not found from webfinger");
	};

	let is_following = match g.base.api.db.load_is_following(&address[1..]).await {
		Ok(r) => r,
		Err(e) => return server_error_response(e, "Database error while checking follow status"),
	};

	let url = match actor_json.get("url") {
		Some(r) => match expect_url(r, &|| "...".into()) {
			Ok(r) => r,
			Err(e) => {
				return server_error_response(
					e,
					"Unable to parse URL from ActivityPub actor object",
				);
			}
		},
		None => match actor_json.get("id") {
			Some(r) => match expect_url(r, &|| "...".into()) {
				Ok(r) => r,
				Err(e) => {
					return server_error_response(
						e,
						"Unable to parse ID from ActivityPub actor object",
					);
				}
			},
			None => {
				return server_error_response2(
					"Unable to find URL or ID on ActivityPub actor object",
				);
			}
		},
	};
	// FIXME: Clean up this mess with activity_pub::expect_string & expect_object
	let name = if let Some(v) = actor_json.get("name") {
		match v {
			serde_json::Value::String(s) => s.clone(),
			_ => String::new(),
		}
	} else {
		String::new()
	};
	let summary = if let Some(v) = actor_json.get("summary") {
		match v {
			serde_json::Value::String(s) => Some(s.clone()),
			_ => None,
		}
	} else {
		None
	};
	let avatar_url = if let Some(v) = actor_json.get("icon") {
		match v {
			serde_json::Value::Object(o) => {
				if let Some(p) = o.get("url") {
					match p {
						serde_json::Value::String(s) => Some(s.clone()),
						_ => None,
					}
				} else {
					None
				}
			}
			_ => None,
		}
	} else {
		None
	};
	let wallpaper_url = if let Some(v) = actor_json.get("image") {
		match v {
			serde_json::Value::Object(o) => {
				if let Some(p) = o.get("url") {
					match p {
						serde_json::Value::String(s) => Some(s.clone()),
						_ => None,
					}
				} else {
					None
				}
			}
			_ => None,
		}
	} else {
		None
	};

	let profile = ProfileObjectInfo {
		actor: TargetedActorInfo {
			address: address.clone(),
			url: url.to_string(),
			name,
			avatar_url: None,
			wallpaper_url: None,
		},
		description: summary,
	};

	let mut context = Context::new();
	context.insert("address", &address);
	context.insert("profile", &profile);
	context.insert("is_following", &is_following);
	context.insert("avatar_url", &avatar_url);
	context.insert("wallpaper_url", &wallpaper_url);
	g.render("activity_pub/actor.html.tera", context).await
}

fn activity_pub_response(mut json: serde_json::Value, context: &[&str]) -> Response {
	// Insert context into json object
	json.as_object_mut()
		.expect("ActivityPub response is not an object")
		.insert("@context".into(), serde_json::to_value(context).unwrap());

	json_response(&json, Some("application/activity+json"))
}

pub async fn actor_followers(
	State(g): State<Arc<ServerGlobal>>, Extension(actor): Extension<actor::Model>,
) -> Response {
	let objects = match activity_pub_follower::Entity::find()
		.filter(activity_pub_follower::Column::ActorId.eq(actor.id))
		.all(g.base.api.db.inner())
		.await
	{
		Ok(o) => o,
		Err(e) => return server_error_response(e, "Database issue"),
	};

	let feed = OrderedCollection {
		summary: "Actor Followers",
		r#type: OrderedCollectionType,
		totalItems: objects.len(),
		orderedItems: objects
			.iter()
			.map(|record| serde_json::Value::String(record.host.clone() + &record.path))
			.collect(),
	};
	activity_pub_response(serde_json::to_value(feed).unwrap(), DEFAULT_CONTEXT)
}

pub async fn actor_get(
	State(g): State<Arc<ServerGlobal>>, Extension(address): Extension<ActorAddress>,
) -> Response {
	let public_key = PUBLIC_KEY.get().map(|s| s.as_str());

	let profile =
		match find_profile_info(&g.base.api.db, &g.base.server_info.url_base, &address).await {
			Err(e) => return server_error_response(e, "DB issue"),
			Ok(r) => match r {
				None => return not_found_error_response("actor profile not found"),
				Some(p) => p,
			},
		};

	let description = profile.description.clone().unwrap_or_default();
	let actor = ActorObject::new(
		&g.base.server_info.url_base,
		&address,
		profile.actor.name,
		profile.actor.avatar_url,
		description,
		public_key,
	);
	activity_pub_response(serde_json::to_value(actor).unwrap(), SECURE_CONTEXT)
}

pub async fn actor_inbox_get(
	State(g): State<Arc<ServerGlobal>>, Extension(actor): Extension<actor::Model>,
) -> Response {
	let objects = match activity_pub_inbox_object::Entity::find()
		.filter(activity_pub_object::Column::ActorId.eq(actor.id))
		.all(g.base.api.db.inner())
		.await
	{
		Ok(o) => o,
		Err(e) => return server_error_response(e, "Database issue"),
	};

	let feed = OrderedCollection {
		summary: "Actor Inbox",
		r#type: OrderedCollectionType,
		totalItems: objects.len(),
		orderedItems: objects
			.iter()
			.map(|record| serde_json::to_value(&record.data).unwrap())
			.collect(),
	};
	activity_pub_response(serde_json::to_value(feed).unwrap(), DEFAULT_CONTEXT)
}

pub async fn actor_inbox_post(
	State(g): State<Arc<ServerGlobal>>, Extension(actor): Extension<actor::Model>, body: String,
) -> Response {
	if body.len() > 20480 {
		return error_response(406, "JSON object too big.");
	}

	let object_json = serde_json::Value::from_str(&body).unwrap();
	let result = if let Some(object_type) = object_json.get("type") {
		let type_string = match object_type {
			serde_json::Value::String(s) => s,
			_ => return error_response(406, "Activity object type field has invalid type"),
		};
		match type_string.as_str() {
			"Create" => actor_inbox_store_object(&g, &actor, object_json).await,
			"Like" => actor_inbox_store_object(&g, &actor, object_json).await,
			"Announce" => actor_inbox_store_object(&g, &actor, object_json).await,
			// TODO: Convert db::Error to activity_pub::Error while maintaining the trace
			"Follow" => actor_inbox_register_follow(&g, &actor, object_json)
				.await
				.map_err(|e| Error::from(e.unwrap().0).trace()),
			"Undo" => actor_inbox_process_undo(&g, &actor, object_json)
				.await
				.map_err(|e| Error::from(e.unwrap().0).trace()),
			other => {
				return error_response(406, &format!("Object type \"{}\" not supported.", other));
			}
		}
	} else {
		return error_response(400, "Missing type parameter.");
	};

	match result {
		Ok(r) => r,
		Err(e) => server_error_response(e, "Error"),
	}
}

async fn actor_inbox_process_undo(
	g: &ServerGlobal, actor: &actor::Model, object: serde_json::Value,
) -> db::Result<Response> {
	// Check if sender of request is owner of domain

	let actor_url = format!(
		"{}/actor/{}/activity-pub",
		&g.base.server_info.url_base, &actor.address
	);
	let object_field = if let Some(o) = object.get("object") {
		o
	} else {
		return Ok(error_response(406, "Missing \"object\" field."));
	};
	Ok(match object_field {
		serde_json::Value::String(_) => {
			return Ok(error_response(
				406,
				"Undoing object by only their ID in the \"object\" parameter not yet supported.",
			));
		}
		serde_json::Value::Object(object_to_undo) => {
			let object_type_opt = object_to_undo.get("type");
			if let Some(object_type) = object_type_opt {
				if object_type != "Follow" {
					return Ok(error_response(
						406,
						"Undoing objects of other type than Follow not supported.",
					));
				}
			// TODO: For the other types, check if the object exists in
			// activity_pub_object, and delete it if it does
			} else {
				return Ok(error_response(406, "Object has no type field."));
			}

			if let Some(our_actor) = object_to_undo.get("object") {
				let has_actor = match our_actor {
					serde_json::Value::String(our_actor_string) => our_actor_string == &actor_url,
					_ => {
						return Ok(error_response(
							406,
							"Invalid type for \"to\" field in Follow activity.",
						));
					}
				};

				if has_actor {
					// Get actor's host and path
					let other_actor = if let Some(a) = object_to_undo.get("actor") {
						match a {
							serde_json::Value::String(s) => s.clone(),
							_ => return Ok(error_response(406, "Field \"actor\" not a string")),
						}
					} else {
						return Ok(error_response(406, "No actor on Follow activity."));
					};
					let (host, path) = match Url::parse(&other_actor) {
						Err(e) => {
							return Ok(error_response(406, format!("Invalid actor URL: {}", e)));
						}
						Ok(url) => {
							let host = if let Some(h) = url.host_str() {
								h
							} else {
								return Ok(error_response(406, "No host in actor URL"));
							};
							let path = url.path();
							(url.scheme().to_string() + "://" + host, path.to_string())
						}
					};

					let deleted = activity_pub_follower::Entity::delete_many()
						.filter(activity_pub_follower::Column::ActorId.eq(actor.id))
						.filter(activity_pub_follower::Column::Host.eq(host))
						.filter(activity_pub_follower::Column::Path.eq(path))
						.exec(g.base.api.db.inner())
						.await?
						.rows_affected;
					if deleted > 0 {
						error_response(200, "Actor has been removed from follower list")
					} else {
						error_response(404, "Actor was not in the follower list")
					}
				} else {
					error_response(404, "Posted undo at wrong inbox")
				}
			} else {
				error_response(406, "Missing \"object\" field on Follow activity.")
			}
		}
		_ => error_response(406, "Object to undo has invalid type"),
	})
}

async fn actor_inbox_register_follow(
	g: &ServerGlobal, actor: &actor::Model, object: serde_json::Value,
) -> db::Result<Response> {
	let follower_string = if let Some(follower) = object.get("actor") {
		match follower {
			serde_json::Value::String(s) => s.clone(),
			_ => return Ok(error_response(400, "Actor field not a string")),
		}
	} else {
		return Ok(error_response(
			400,
			&format!("No actor in Register activity"),
		));
	};

	// Store follower
	match Url::parse(&follower_string) {
		Err(e) => {
			return Ok(error_response(
				400,
				&format!("Invalid URL for follower {}: {}", &follower_string, e),
			));
		}
		Ok(url) => {
			let domain = if let Some(d) = url.domain() {
				d
			} else {
				return Ok(error_response(400, "No domain in follower URL"));
			};
			let server = format!("{}://{}", url.scheme(), domain);
			let path = url.path().to_string();

			let record = activity_pub_follower::ActiveModel {
				id: NotSet,
				actor_id: Set(actor.id),
				host: Set(server.clone()),
				path: Set(path.clone()),
			};
			let follow_id = activity_pub_follower::Entity::insert(record)
				.exec(g.base.api.db.inner())
				.await?
				.last_insert_id;

			// Send an Accept object back
			let accept_activity = AcceptActivity {
				id: format!(
					"{}/actor/{}/activity_pub/follower/{}",
					&g.base.server_info.url_base, &actor.address, follow_id
				),
				r#type: AcceptActivityType,
				actor: format!(
					"{}/actor/{}/activity-pub",
					&g.base.server_info.url_base, &actor.address
				),
				to: vec![follower_string.clone()],
				object,
			};
			activity_pub::queue_activity(
				&g.base,
				&g.base.api.db,
				actor.id,
				server,
				Some(path),
				&accept_activity,
			)
			.await?;
		}
	};

	// Response
	return Ok(Response::builder().status(202).body(Body::empty()).unwrap());
}

async fn actor_inbox_store_object(
	g: &ServerGlobal, actor: &actor::Model, json: serde_json::Value,
) -> Result<Response> {
	let when = || format!("storing object for actor {}", actor.id).into();
	let object_id =
		activity_pub::store_inbox_object(&g.base.api.db, actor.id, &json, &when).await?;

	return Ok(Response::builder()
		.status(201)
		.header(
			"Location",
			&format!(
				"{}/actor/{}/activity-pub/inbox/{}",
				&g.base.server_info.url_base, actor.address, object_id
			),
		)
		.body(Body::empty())
		.unwrap());
}

pub async fn actor_outbox(
	State(g): State<Arc<ServerGlobal>>, Extension(address): Extension<ActorAddress>,
) -> Response {
	let objects = match load_actor_feed(
		&g.base.api.db,
		&g.base.server_info.url_base,
		&address,
		1000,
		0,
	)
	.await
	{
		Err(e) => return server_error_response(e, "DB issue"),
		Ok(r) => r,
	};

	// Convert all the objects infos to AP json format.
	let mut activities = Vec::with_capacity(objects.len());
	for object in objects {
		match compose_activity_from_object_info(
			&g.base.api.db,
			&g.base.server_info.url_base,
			&object,
		)
		.await
		{
			Ok(result) => {
				if let Some((json, _)) = result {
					activities.push(json);
				}
			}
			Err(e) => return server_error_response(e, "Unable to compose object activity"),
		};
	}

	let feed = OrderedCollection {
		summary: "Actor Feed",
		r#type: OrderedCollectionType,
		totalItems: activities.len(),
		orderedItems: activities,
	};
	activity_pub_response(serde_json::to_value(feed).unwrap(), DEFAULT_CONTEXT)
}

pub async fn actor_public_key(
	State(g): State<Arc<ServerGlobal>>, Extension(address): Extension<ActorAddress>,
) -> Response {
	if let Some(public_key) = PUBLIC_KEY.get() {
		let actor_id = format!(
			"{}/actor/{}/activity-pub",
			&g.base.server_info.url_base, &address
		);
		let key = ActorPublicKey {
			id: format!("{}#main-key", &actor_id),
			owner: actor_id,
			publicKeyPem: public_key.clone(),
		};
		activity_pub_response(serde_json::to_value(key).unwrap(), DEFAULT_CONTEXT)
	} else {
		not_found_error_response("No public key has been configured.")
	}
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
			match web::activity_pub::populate_send_queue_from_new_objects(&g2, 100).await {
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
			Ok(records) => {
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
							if let Err(e) =
								web::activity_pub::process_next_send_queue_item(&g2, record, pk)
									.await
							{
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
				}
			}
		}

		if let Err(e) = join_handle.await {
			error!("Send queue join error: {}", e);
		}
	}
}

pub async fn nodeinfo(State(g): State<Arc<ServerGlobal>>) -> Response {
	let info = NodeInfo2 {
		version: NodeInfoVersion,
		server: NodeInfoServer {
			baseUrl: g.base.server_info.url_base.clone(),
			name: g
				.base
				.config
				.federation_server_name
				.clone()
				.unwrap_or("Just another Stonenet bridge".to_string()),
			software: "stonenet",
			version: env!("CARGO_PKG_VERSION").to_string(),
		},
		organization: NodeInfoOrganization {
			name: g.base.config.federation_organization.clone(),
			contact: g.base.config.federation_contact_info.clone(),
			account: g.base.config.federation_server_account.clone(),
		},
		protocols: vec!["activitypub".to_string()],
		openRegistrations: false,
		// TODO: Compute the following information:
		usage: NodeInfoUsage {
			users: NodeInfoUsageUsers {
				total: g.base.config.track.as_ref().map(|t| t.len()).unwrap_or(0) as _,
				//activeHalfyear: todo!(),
				//activeWeek: todo!(),
			},
			//totalPosts:
		},
	};
	json_response(&info, Some("application/json"))
}

async fn object_get(State(g): State<Arc<ServerGlobal>>, Path(object_id): Path<i64>) -> Response {
	let mut object_info = match web::activity_pub::load_object_info(&g.base.api.db, object_id).await
	{
		Ok(result) => {
			if let Some(r) = result {
				r
			} else {
				return not_found_error_response("Object not found");
			}
		}
		Err(e) => return server_error_response(e, "Unable to load object"),
	};

	// Load actor's webfinger
	let ap_object = match activity_pub_object::Entity::find_by_id(object_id)
		.one(g.base.api.db.inner())
		.await
	{
		Ok(result) => {
			if let Some(r) = result {
				r
			} else {
				return server_error_response2("ActivityPub object record not found");
			}
		}
		Err(e) => return server_error_response(e, "Database issue"),
	};
	let actor = match activity_pub_actor::Entity::find_by_id(ap_object.actor_id)
		.one(g.base.api.db.inner())
		.await
	{
		Ok(result) => {
			if let Some(r) = result {
				r
			} else {
				return server_error_response2("ActivityPub actor record not found");
			}
		}
		Err(e) => return server_error_response(e, "Database issue"),
	};
	let irt_webfinger = if let Some(w) = actor.address {
		w
	} else {
		return not_found_error_response("No webfinger available for actor");
	};

	translate_special_mime_types_for_object(&mut object_info);

	let mut context = Context::new();
	context.insert("object", &object_info);
	context.insert("irt_webfinger", &irt_webfinger);
	g.render("actor/object.html.tera", context).await
}

pub async fn object_get_stonenet(
	State(g): State<Arc<ServerGlobal>>, Path(hash): Path<IdType>,
) -> Response {
	let object_info = match web::info::load_object_info(
		&g.base.api.db,
		&g.base.server_info.url_base,
		&hash,
	)
	.await
	{
		Ok(result) => {
			if let Some(r) = result {
				r
			} else {
				return not_found_error_response("Object not found");
			}
		}
		Err(e) => return server_error_response(e, "Unable to load object"),
	};

	let (json, _) = match compose_activity_from_object_info(
		&g.base.api.db,
		&g.base.server_info.url_base,
		&object_info,
	)
	.await
	{
		Ok(result) => match result {
			Some(r) => r,
			None => return not_found_error_response("Unable to load object"),
		},
		Err(e) => return server_error_response(e, "Unable to load object"),
	};

	activity_pub_response(json, DEFAULT_CONTEXT)
}

async fn object_post(
	State(g): State<Arc<ServerGlobal>>, Path(object_id): Path<i64>, cookies: CookieJar,
	multipart: Multipart,
) -> Response {
	let (private_key, actor_address) = match load_private_key(&g.base, &cookies).await {
		Ok(r) => r,
		Err(r) => return r,
	};

	// Load the AP object
	// TODO: Remove .unwrap():
	let tx = g.base.api.db.transaction().await.unwrap();
	let ap_object = match activity_pub_object::Entity::find_by_id(object_id)
		.one(tx.inner())
		.await
	{
		Ok(result) => {
			if let Some(r) = result {
				r
			} else {
				return not_found_error_response("Unable to find object");
			}
		}
		Err(e) => return server_error_response(e, "Unable to load object"),
	};

	// Parse the request data, and pre-create the attachments so that we can deduce
	// the URLs they will have
	let (message, attachment_datas) = match parse_post_message(multipart).await {
		Ok(r) => r,
		Err(e) => return e,
	};
	let mut attachments = Vec::with_capacity(attachment_datas.len());
	for attachment_data in &attachment_datas {
		let (_, file_hash, _) = tx.create_file(&attachment_data).await.unwrap();
		attachments.push((attachment_data.mime_type.as_str(), file_hash));
	}
	tx.commit().await.unwrap();

	// Construct the Note object
	let mut note = ActivityNoteObject::create_markdown_note(
		&g.base.server_info.url_base,
		&actor_address,
		message,
		&attachments,
	);
	note.inReplyTo = Some(ap_object.object_id);
	let activity_object_json = serde_json::to_value(note).unwrap();

	// Create a post object on Stonenet with the activity json of the Note object as
	// its main file
	g.base
		.api
		.publish_post(
			&actor_address,
			&private_key,
			"application/activity+json",
			&activity_object_json.to_string(),
			Vec::new(),
			&attachment_datas,
			None,
		)
		.await
		.unwrap();

	Response::builder()
		.status(303)
		.header("Location", "/")
		.body(Body::empty())
		.unwrap()
}

pub fn router(_: Arc<ServerGlobal>) -> Router<Arc<ServerGlobal>> {
	Router::new()
		.route(
			"/actor/:address",
			get(activity_pub_actor_get).post(activity_pub_actor_post),
		)
		.route("/object/:id", get(object_get).post(object_post))
}

pub fn actor_router(_: Arc<ServerGlobal>) -> Router<Arc<ServerGlobal>> {
	Router::new()
		.route("/follower", get(actor_followers))
		.route("/inbox", get(actor_inbox_get).post(actor_inbox_post))
		.route("/outbox", get(actor_outbox))
		.route("/public-key", get(actor_public_key))
}

pub async fn webfinger(
	State(g): State<Arc<ServerGlobal>>, Query(params): Query<HashMap<String, String>>,
) -> Response {
	if let Some(resource) = params.get("resource") {
		let account_name = match activity_pub::parse_account_name(resource) {
			Some(n) => n,
			None => return server_error_response2("invalid resource syntax"),
		};

		let address = match Address::from_str(account_name) {
			Err(e) => return server_error_response(e, "invalid address"),
			Ok(a) => a,
		};

		let webfinger = match &address {
			Address::Actor(actor_address) => match g.base.api.db.connect_old() {
				Err(e) => return server_error_response(e, "DB issue"),
				Ok(c) => {
					let result = match c.fetch_identity(actor_address) {
						Err(e) => return server_error_response(e, "DB issue"),
						Ok(r) => r,
					};

					if result.is_some() {
						WebFingerDocument::new(
							&g.base.server_info.federation_domain,
							&g.base.server_info.url_base,
							"actor",
							&address,
						)
					} else {
						return not_found_error_response("actor doesn't exist");
					}
				}
			},
			Address::Node(_) => WebFingerDocument::new(
				&g.base.server_info.federation_domain,
				&g.base.server_info.url_base,
				"node",
				&address,
			),
		};

		json_response(&webfinger, Some("application/jrd+json"))
	} else {
		server_error_response2("Missing parameter \"resource\".")
	}
}

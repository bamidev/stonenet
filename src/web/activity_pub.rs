use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
	body::Body,
	extract::{Query, State},
	response::Response,
	routing::*,
	*,
};
use email_address_parser::EmailAddress;
use extract::Path;
use log::*;
use reqwest::Url;
use sea_orm::{prelude::*, NotSet, Set};
use serde::*;
use tera::Context;
use tokio::spawn;

use super::{common::*, ActorAddress, Address};
use crate::{
	activity_pub::{
		self, AcceptActivity, AcceptActivityType, ActivityPubDocumentContext, ActorObject,
		ActorPublicKeyWithContext, CreateActivity, OrderedCollection, OrderedCollectionType,
		WebFingerDocument,
	},
	db::{self, PersistenceHandle, ProfileObjectInfo, TargetedActorInfo},
	entity::*,
	trace::Traceable,
	web::Global,
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

impl Serialize for NodeInfoVersion {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str("1.0")
	}
}


async fn activity_pub_actor_post(
	State(g): State<Arc<Global>>, Path(address): Path<String>, Form(form_data): Form<ActorActions>,
) -> Response {
	let webfinger_addr = match EmailAddress::parse(&address[1..], None) {
		Some(r) => r,
		None => return server_error_response2("Invalid webfinger address"),
	};

	if let Some(follow) = &form_data.follow {
		// Follow
		if follow == "1" {
			let actor_url = match activity_pub::actor::resolve_webfinger(&webfinger_addr).await {
				Ok(r) =>
					if let Some(url) = r {
						url
					} else {
						return server_error_response2(
							"Webfinger address doesn't have an ActivityPub actor URL",
						);
					},
				Err(e) =>
					return server_error_response(
						e,
						&format!("Error while resolving webfinger {}", &webfinger_addr),
					),
			};
			let actor = match activity_pub::actor::ensure(
				&g.api.db,
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
				.exec(g.api.db.inner())
				.await
			{
				return server_error_response(e, "Database error while storing following");
			}

			// Poll the outbox
			if let Some(outbox_url) = actor.outbox {
				let db = g.api.db.clone();
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
				.one(g.api.db.inner())
				.await
			{
				Ok(r) => r,
				Err(e) =>
					return server_error_response(
						e,
						&format!(
							"Database error while looking up actor with webfinger address {}",
							&webfinger_addr
						),
					),
			};
			if let Some(record) = result {
				if let Err(e) = activity_pub_following::Entity::delete_many()
					.filter(activity_pub_following::Column::ActorId.eq(record.id))
					.exec(g.api.db.inner())
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
	State(g): State<Arc<Global>>, Path(address): Path<String>,
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

	let is_following = match g.api.db.load_is_following(&address[1..]).await {
		Ok(r) => r,
		Err(e) => return server_error_response(e, "Database error while checking follow status"),
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
			serde_json::Value::Object(o) =>
				if let Some(p) = o.get("url") {
					match p {
						serde_json::Value::String(s) => Some(s.clone()),
						_ => None,
					}
				} else {
					None
				},
			_ => None,
		}
	} else {
		None
	};
	let wallpaper_url = if let Some(v) = actor_json.get("image") {
		match v {
			serde_json::Value::Object(o) =>
				if let Some(p) = o.get("url") {
					match p {
						serde_json::Value::String(s) => Some(s.clone()),
						_ => None,
					}
				} else {
					None
				},
			_ => None,
		}
	} else {
		None
	};

	let profile = ProfileObjectInfo {
		actor: TargetedActorInfo {
			address: address.clone(),
			name,
			avatar_id: None,
			wallpaper_id: None,
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

pub async fn actor_followers(
	State(g): State<Arc<Global>>, Extension(actor): Extension<actor::Model>,
) -> Response {
	let objects = match activity_pub_follower::Entity::find()
		.filter(activity_pub_follower::Column::ActorId.eq(actor.id))
		.all(g.api.db.inner())
		.await
	{
		Ok(o) => o,
		Err(e) => return server_error_response(e, "Database issue"),
	};

	let feed = OrderedCollection {
		context: ActivityPubDocumentContext::default(),
		summary: "Actor Followers",
		r#type: OrderedCollectionType,
		totalItems: objects.len(),
		orderedItems: objects
			.iter()
			.map(|record| serde_json::Value::String(record.host.clone() + &record.path))
			.collect(),
	};
	json_response(
		&feed,
		Some("application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""),
	)
}

pub async fn actor_get(
	State(g): State<Arc<Global>>, Extension(address): Extension<ActorAddress>,
) -> Response {
	let public_key = activity_pub::PUBLIC_KEY.get().map(|s| s.as_str());

	let profile = match g.api.db.find_profile_info(&address).await {
		Err(e) => return server_error_response(e, "DB issue"),
		Ok(r) => match r {
			None => return not_found_error_response("actor profile not found"),
			Some(p) => p,
		},
	};

	let description = profile.description.clone().unwrap_or_default();
	let actor = ActorObject::new(
		&g.server_info.url_base,
		&address,
		profile.actor.name,
		profile.actor.avatar_id.as_ref(),
		description,
		public_key,
	);
	json_response(
		&actor,
		Some("application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""),
	)
}

pub async fn actor_inbox_get(
	State(g): State<Arc<Global>>, Extension(actor): Extension<actor::Model>,
) -> Response {
	let objects = match activity_pub_inbox_object::Entity::find()
		.filter(activity_pub_object::Column::ActorId.eq(actor.id))
		.all(g.api.db.inner())
		.await
	{
		Ok(o) => o,
		Err(e) => return server_error_response(e, "Database issue"),
	};

	let feed = OrderedCollection {
		context: ActivityPubDocumentContext::default(),
		summary: "Actor Inbox",
		r#type: OrderedCollectionType,
		totalItems: objects.len(),
		orderedItems: objects
			.iter()
			.map(|record| serde_json::to_value(&record.data).unwrap())
			.collect(),
	};
	json_response(
		&feed,
		Some("application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""),
	)
}

pub async fn actor_inbox_post(
	State(g): State<Arc<Global>>, Extension(actor): Extension<actor::Model>, body: String,
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
				.map_err(|e| activity_pub::Error::from(e.unwrap().0).trace()),
			"Undo" => actor_inbox_process_undo(&g, &actor, object_json)
				.await
				.map_err(|e| activity_pub::Error::from(e.unwrap().0).trace()),
			other =>
				return error_response(406, &format!("Object type \"{}\" not supported.", other)),
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
	g: &Global, actor: &actor::Model, object: serde_json::Value,
) -> db::Result<Response> {
	// Check if sender of request is owner of domain

	let actor_url = format!(
		"{}/actor/{}/activity-pub",
		&g.server_info.url_base, &actor.address
	);
	let object_field = if let Some(o) = object.get("object") {
		o
	} else {
		return Ok(error_response(406, "Missing \"object\" field."));
	};
	Ok(match object_field {
		serde_json::Value::String(_) =>
			return Ok(error_response(
				406,
				"Undoing object by only their ID in the \"object\" parameter not yet supported.",
			)),
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
					_ =>
						return Ok(error_response(
							406,
							"Invalid type for \"to\" field in Follow activity.",
						)),
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
						Err(e) =>
							return Ok(error_response(406, format!("Invalid actor URL: {}", e))),
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
						.exec(g.api.db.inner())
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
	g: &Global, actor: &actor::Model, object: serde_json::Value,
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
		Err(e) =>
			return Ok(error_response(
				400,
				&format!("Invalid URL for follower {}: {}", &follower_string, e),
			)),
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
				.exec(g.api.db.inner())
				.await?
				.last_insert_id;

			// Send an Accept object back
			let accept_activity = AcceptActivity {
				context: ActivityPubDocumentContext::default(),
				id: format!(
					"{}/actor/{}/activity_pub/follower/{}",
					&g.server_info.url_base, &actor.address, follow_id
				),
				r#type: AcceptActivityType,
				actor: format!(
					"{}/actor/{}/activity-pub",
					&g.server_info.url_base, &actor.address
				),
				to: vec![follower_string.clone()],
				object,
			};
			activity_pub::queue_activity(
				g,
				&g.api.db,
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
	g: &Global, actor: &actor::Model, json: serde_json::Value,
) -> activity_pub::Result<Response> {
	let when = || format!("storing object for actor {}", actor.id).into();
	let object_id = activity_pub::store_inbox_object(&g.api.db, actor.id, &json, &when).await?;

	return Ok(Response::builder()
		.status(201)
		.header(
			"Location",
			&format!(
				"{}/actor/{}/activity-pub/inbox/{}",
				&g.server_info.url_base, actor.address, object_id
			),
		)
		.body(Body::empty())
		.unwrap());
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
					activity_pub::compose_object_payload(&object.payload),
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

pub async fn actor_public_key(
	State(g): State<Arc<Global>>, Extension(address): Extension<ActorAddress>,
) -> Response {
	if let Some(public_key) = activity_pub::PUBLIC_KEY.get() {
		let actor_id = format!(
			"{}/actor/{}/activity-pub",
			&g.server_info.url_base, &address
		);
		let key = ActorPublicKeyWithContext {
			context: activity_pub::DEFAULT_CONTEXT,
			id: format!("{}#main-key", &actor_id),
			owner: actor_id,
			publicKeyPem: public_key.clone(),
		};
		json_response(
			&key,
			Some("application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\""),
		)
	} else {
		not_found_error_response("No public key has been configured.")
	}
}

pub async fn nodeinfo(State(g): State<Arc<Global>>) -> Response {
	let info = NodeInfo2 {
		version: NodeInfoVersion,
		server: NodeInfoServer {
			baseUrl: g.server_info.url_base.clone(),
			name: g
				.config
				.federation_server_name
				.clone()
				.unwrap_or("Just another Stonenet bridge".to_string()),
			software: "stonenet",
			version: env!("CARGO_PKG_VERSION").to_string(),
		},
		organization: NodeInfoOrganization {
			name: g.config.federation_organization.clone(),
			contact: g.config.federation_contact_info.clone(),
			account: g.config.federation_server_account.clone(),
		},
		protocols: vec!["activitypub".to_string()],
		openRegistrations: false,
		// TODO: Compute the following information:
		usage: NodeInfoUsage {
			users: NodeInfoUsageUsers {
				total: g.config.track.as_ref().map(|t| t.len()).unwrap_or(0) as _,
				//activeHalfyear: todo!(),
				//activeWeek: todo!(),
			},
			//totalPosts:
		},
	};
	json_response(&info, Some("application/json"))
}

pub fn router(_: Arc<Global>) -> Router<Arc<Global>> {
	Router::new().route(
		"/actor/:address",
		get(activity_pub_actor_get).post(activity_pub_actor_post),
	)
}

pub fn actor_router(_: Arc<Global>) -> Router<Arc<Global>> {
	Router::new()
		.route("/follower", get(actor_followers))
		.route("/inbox", get(actor_inbox_get).post(actor_inbox_post))
		.route("/outbox", get(actor_outbox))
		.route("/public-key", get(actor_public_key))
}

pub async fn webfinger(
	State(g): State<Arc<Global>>, Query(params): Query<HashMap<String, String>>,
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

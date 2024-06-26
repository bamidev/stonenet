mod file;
mod object;


use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
	extract::{Path, Query, Request, State},
	middleware::{from_fn_with_state, Next},
	response::Response,
	routing::get,
	Extension, Form, RequestExt, Router,
};
use sea_orm::prelude::*;
use serde::Deserialize;
use tera::Context;

use super::{
	activity_pub, error_response, server_error_response, server_error_response2,
	translate_special_mime_types_for_objects, ActorAddress, Address, PaginationQuery, ServerGlobal,
};
use crate::{
	db::PersistenceHandle,
	entity::*,
	web::info::{find_profile_info, load_actor_feed, ObjectInfo},
};


#[derive(Deserialize)]
struct ActorActions {
	follow: Option<String>,
}


pub fn router(g: Arc<ServerGlobal>) -> Router<Arc<ServerGlobal>> {
	let mut actor_methods = get(actor_get);
	if !g.base.server_info.is_exposed {
		actor_methods = actor_methods.post(actor_post);
	}

	Router::new()
		.route("/:actor-address", actor_methods)
		.route("/:actor-address/activity-pub", get(activity_pub::actor_get))
		.nest("/:actor-address/activity-pub", activity_pub::actor_router(g.clone()))
		.nest("/:actor-address/file", file::router(g.clone()))
		// A workaround for Mastodon's behavior:
		.nest("/:actor-address/activity-pub/file", file::router(g.clone()))
		.nest("/:actor-address/object", object::router(g.clone()))
		.route_layer(from_fn_with_state(g, actor_middleware))
}

async fn actor_middleware(
	State(g): State<Arc<ServerGlobal>>, mut request: Request, next: Next,
) -> Response {
	let params = request
		.extract_parts::<Path<HashMap<String, String>>>()
		.await
		.unwrap()
		.0;
	let hash = params.get("actor-address").unwrap();

	let address = match parse_actor_address(&hash) {
		Err(r) => return r,
		Ok(a) => a,
	};
	let actor_opt = match actor::Entity::find()
		.filter(actor::Column::Address.eq(&address))
		.one(g.base.api.db.inner())
		.await
	{
		Err(e) => return server_error_response(e, "Unable to load actor"),
		Ok(a) => a,
	};

	if let Some(actor) = actor_opt {
		request.extensions_mut().insert(address);
		request.extensions_mut().insert(actor);
	} else {
		return error_response(404, "Unknown actor");
	}

	next.run(request).await
}

async fn actor_get(
	State(g): State<Arc<ServerGlobal>>, Extension(address): Extension<ActorAddress>,
	Query(query): Query<PaginationQuery>,
) -> Response {
	let result = if g.base.server_info.is_exposed {
		find_profile_info(&g.base.api.db, &g.base.server_info.url_base, &address).await
	} else {
		g.base
			.api
			.find_profile_info(&g.base.server_info.url_base, &address)
			.await
	};
	let profile = match result {
		Ok(p) => p,
		Err(e) => return server_error_response(e, "Unable to fetch profile"),
	};
	let is_following: bool = match g.base.api.is_following(&address) {
		Ok(f) => f,
		Err(e) => return server_error_response(e, "Unable to fetch follow status"),
	};
	// TODO: Check if public key is available, if so, following is still possible.

	let p = query.page.unwrap_or(0);
	let start = p * 5;
	let mut objects: Vec<ObjectInfo> = match load_actor_feed(
		&g.base.api.db,
		&g.base.server_info.url_base,
		&address,
		5,
		start,
	)
	.await
	{
		Ok(f) => f,
		Err(e) => return server_error_response(e, "unable to fetch home feed"),
	};

	translate_special_mime_types_for_objects(&mut objects);

	let mut context = Context::new();
	context.insert("address", &address.to_string());
	context.insert("profile", &profile);
	context.insert("is_following", &is_following);
	context.insert("page", &p);
	context.insert("objects", &objects);
	g.render("actor.html.tera", context).await
}

async fn actor_post(
	State(g): State<Arc<ServerGlobal>>, Extension(address): Extension<ActorAddress>,
	Form(form_data): Form<ActorActions>,
) -> Response {
	if let Some(follow) = &form_data.follow {
		// Follow
		if follow == "1" {
			match g.base.api.follow(&address, true).await {
				Ok(success) =>
					if !success {
						return server_error_response2(
							"Unable to follow this actor: couldn't find its public key",
						);
					},
				Err(e) => return server_error_response(e, "Unable to follow this actor: {}"),
			}
		// Unfollow
		} else {
			match g.base.api.unfollow(&address).await {
				Ok(_) => {}
				Err(e) => return server_error_response(e, "Unable to unfollow this actor"),
			}
		}
	}

	actor_get(
		State(g),
		Extension(address),
		Query(PaginationQuery::default()),
	)
	.await
}

pub fn parse_actor_address(string: &str) -> Result<ActorAddress, Response> {
	let address = match Address::from_str(string) {
		Ok(a) => a,
		Err(e) => return Err(server_error_response(e, "Malformed address")),
	};
	let actor_address = match address {
		Address::Actor(aa) => aa,
		_ => return Err(server_error_response2("Not an actor address")),
	};
	Ok(actor_address)
}

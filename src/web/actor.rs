mod file;
mod object;

use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{extract::*, middleware::*, response::Response, routing::*, *};
use sea_orm::*;
use serde::Deserialize;
use tera::Context;

use super::*;
use crate::entity::{identity, Identity};


#[derive(Deserialize)]
struct ActorActions {
	follow: Option<String>,
}


pub fn router(g: Arc<Global>) -> Router<Arc<Global>> {
	Router::new()
		.route("/:actor-address", get(actor_get).post(actor_post))
		.route(
			"/:actor-address/activity-pub",
			get(activity_pub::actor_activitypub),
		)
		.nest("/:actor-address/file", file::router(g.clone()))
		.nest("/:actor-address/object", object::router(g.clone()))
		.route_layer(from_fn_with_state(g, actor_middleware))
}

async fn actor_middleware(
	State(g): State<Arc<Global>>, mut request: Request, next: Next,
) -> Response {
	let params = request
		.extract_parts::<Path<HashMap<String, String>>>()
		.await
		.unwrap()
		.0;
	let hash = params.get("actor-address").unwrap();

	match parse_actor_address(&hash) {
		Err(r) => return r,
		Ok(address) => {
			request.extensions_mut().insert(address);
		}
	}

	match Identity::find()
		.filter(identity::Column::Address.contains(hash))
		.one(&g.api.orm)
		.await
	{
		Err(e) => return server_error_response(e, "Unable to load actor"),
		Ok(actor) => {
			request.extensions_mut().insert(actor);
		}
	}

	next.run(request).await
}

async fn actor_get(
	State(g): State<Arc<Global>>, Extension(address): Extension<ActorAddress>,
) -> Response {
	let profile = match g.api.fetch_profile_info(&address).await {
		Ok(p) => p,
		Err(e) => return server_error_response(e, "Unable to fetch profile"),
	};
	let is_following: bool = match g.api.is_following(&address) {
		Ok(f) => f,
		Err(e) => return server_error_response(e, "Unable to fetch follow status"),
	};
	// TODO: Check if public key is available, if so, following is still possible.

	let mut context = Context::new();
	context.insert("address", &address.to_string());
	context.insert("profile", &profile);
	context.insert("is_following", &is_following);
	g.render("actor.html.tera", context)
}

async fn actor_post(
	State(g): State<Arc<Global>>, Extension(address): Extension<ActorAddress>,
	Form(form_data): Form<ActorActions>,
) -> Response {
	if let Some(follow) = &form_data.follow {
		// Follow
		if follow == "1" {
			match g.api.follow(&address, true).await {
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
			match g.api.unfollow(&address).await {
				Ok(_) => {}
				Err(e) => return server_error_response(e, "Unable to unfollow this actor"),
			}
		}
	}

	actor_get(State(g), Extension(address)).await
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

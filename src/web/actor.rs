mod file;

use std::{str::FromStr, sync::Arc};

use axum::{extract::*, middleware::*, response::*, routing::*, *};
use sea_orm::*;
use serde::Deserialize;
use tera::Context;

use super::{server_error_response, ActorAddress, Address, Global};
use crate::entity::{identity, Identity};


#[derive(Deserialize)]
struct ActorActions {
	follow: Option<String>,
}


pub fn router(g: Arc<Global>) -> Router<Arc<Global>> {
	Router::new()
		.route("/:hash", get(actor_get).post(actor_post))
		.nest("/:hash/file", file::router(g.clone()))
		.route_layer(from_fn_with_state(g, actor_middleware))
}

async fn actor_middleware(State(g): State<Arc<Global>>, mut request: Request, next: Next) -> Response {
	let hash = request.extract_parts::<Path<String>>().await.unwrap().0;

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
		Err(e) => return server_error_response(format!("Unable to load actor: {}", e)),
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
		Err(e) => return server_error_response(format!("Unable to fetch profile: {}", e)),
	};
	let is_following: bool = match g.api.is_following(&address) {
		Ok(f) => f,
		Err(e) => return server_error_response(format!("Unable to fetch follow status: {}", e)),
	};
	// TODO: Check if public key is available, if so, following is still possible.

	let mut context = Context::new();
	context.insert("address", &address.to_string());
	context.insert("profile", &profile);
	context.insert("is_following", &is_following);
	g.render("actor", context)
}

async fn actor_post(
	State(g): State<Arc<Global>>, Extension(address): Extension<ActorAddress>, Form(form_data): Form<ActorActions>
) -> Response {
	if let Some(follow) = &form_data.follow {
		// Follow
		if follow == "1" {
			match g.api.follow(&address, true).await {
				Ok(success) =>
					if !success {
						return server_error_response("Unable to follow this actor: couldn't find its public key".to_string());
					},
				Err(e) => return server_error_response(format!("Unable to follow this actor: {}", e)),
			}
		// Unfollow
		} else {
			match g.api.unfollow(&address).await {
				Ok(_) => {}
				Err(e) =>
				return server_error_response(format!("Unable to unfollow this actor: {}", e))
			}
		}
	}

	actor_get(State(g), Extension(address)).await
}

pub fn parse_actor_address(string: &str) -> Result<ActorAddress, Response> {
	let address = match Address::from_str(string) {
		Ok(a) => a,
		Err(e) => return Err(server_error_response(format!("Malformed address: {}", e))),
	};
	let actor_address = match address {
		Address::Actor(aa) => aa,
		_ => return Err(server_error_response("Not an actor address".to_string())),
	};
	Ok(actor_address)
}

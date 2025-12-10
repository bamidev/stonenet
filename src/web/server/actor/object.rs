use std::{collections::HashMap, sync::Arc};

use axum::{
	body::Body,
	extract::{Multipart, Path, Request, State},
	middleware::{from_fn_with_state, Next},
	response::Response,
	routing::{get, post},
	Extension, RequestExt, Router,
};
use axum_extra::extract::CookieJar;
use sea_orm::prelude::*;
use tera::Context;

use crate::{
	common::*,
	core::*,
	db::PersistenceHandle,
	entity::object,
	web::{
		info::find_object_info,
		server::{
			activity_pub, common::load_private_key, not_found_error_response, post_message,
			server_error_response, translate_special_mime_types_for_object, ServerGlobal,
		},
	},
};

pub fn router(g: Arc<ServerGlobal>) -> Router<Arc<ServerGlobal>> {
	let mut object_methods = get(object_get);
	if !g.base.server_info.is_exposed {
		object_methods = object_methods.post(object_post);
	}

	let mut router = Router::new().route("/:hash", object_methods).route(
		"/:hash/activity-pub",
		get(activity_pub::object_get_stonenet),
	);
	if !g.base.server_info.is_exposed {
		router = router.route("/:object-hash/share", post(object_share));
	}

	router.route_layer(from_fn_with_state(g, object_middleware))
}

async fn object_middleware(
	State(g): State<Arc<ServerGlobal>>, mut request: Request, next: Next,
) -> Response {
	let params = request
		.extract_parts::<Path<HashMap<String, String>>>()
		.await
		.unwrap()
		.0;
	let hash_str = params.get("hash").unwrap();

	match IdType::from_base58(&hash_str) {
		Ok(id) => request.extensions_mut().insert(id),
		Err(e) => return server_error_response(e, "This is not a valid hash string"),
	};

	{
		match object::Entity::find()
			.filter(object::Column::Hash.contains(hash_str))
			.one(g.base.api.db.inner())
			.await
		{
			Err(e) => return server_error_response(e, "Unable to load file"),
			Ok(actor) => {
				request.extensions_mut().insert(actor);
			}
		}
	}

	next.run(request).await
}

async fn object_get(
	State(g): State<Arc<ServerGlobal>>, Extension(actor_address): Extension<ActorAddress>,
	Extension(object_hash): Extension<IdType>,
) -> Response {
	let mut object_info = match find_object_info(
		&g.base.api.db,
		&g.base.server_info.url_base,
		&actor_address,
		&object_hash,
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

	translate_special_mime_types_for_object(&mut object_info);

	let mut context = Context::new();
	context.insert("address", &actor_address);
	context.insert("object", &object_info);
	g.render("actor/object.html.tera", context).await
}

async fn object_post(
	State(g): State<Arc<ServerGlobal>>, Extension(actor_address): Extension<ActorAddress>,
	Extension(object_hash): Extension<IdType>, cookies: CookieJar, multipart: Multipart,
) -> Response {
	if let Err(e) = post_message(
		&g.base,
		&cookies,
		multipart,
		Some((actor_address, object_hash)),
	)
	.await
	{
		return e;
	}

	Response::builder()
		.status(303)
		.header("Location", "/")
		.body(Body::empty())
		.unwrap()
}

async fn object_share(
	State(g): State<Arc<ServerGlobal>>, Extension(actor_address): Extension<ActorAddress>,
	Extension(object_hash): Extension<IdType>, cookies: CookieJar,
) -> Response {
	let (private_key, identity_actor_address) = match load_private_key(&g.base, &cookies).await {
		Ok(r) => r,
		Err(r) => return r,
	};

	let share = ShareObject {
		actor_address,
		object_hash,
	};
	if let Err(e) = g
		.base
		.api
		.publish_share(&identity_actor_address, &private_key, &share)
		.await
	{
		return server_error_response(e, "unable to publish share");
	}

	Response::builder()
		.status(303)
		.header("Location", "/")
		.body(Body::empty())
		.unwrap()
}

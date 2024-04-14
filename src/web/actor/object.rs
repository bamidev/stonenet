use std::collections::HashMap;

use axum::{extract::*, middleware::*, response::Response, routing::*, *};
use sea_orm::*;

use crate::{
	entity::{object, Object},
	web::*,
};


pub fn router(g: Arc<Global>) -> Router<Arc<Global>> {
	Router::new()
		.route("/:object-hash", get(object_get))
		.route("/:object-hash/share", post(object_share))
		.route_layer(from_fn_with_state(g, object_middleware))
}

async fn object_middleware(
	State(g): State<Arc<Global>>, mut request: Request, next: Next,
) -> Response {
	let params = request
		.extract_parts::<Path<HashMap<String, String>>>()
		.await
		.unwrap()
		.0;
	let hash_str = params.get("object-hash").unwrap();

	match IdType::from_base58(&hash_str) {
		Ok(id) => request.extensions_mut().insert(id),
		Err(e) => return server_error_response(e, "This is not a valid hash string"),
	};

	match Object::find()
		.filter(object::Column::Hash.contains(hash_str))
		.one(&g.api.orm)
		.await
	{
		Err(e) => return server_error_response(e, "Unable to load file"),
		Ok(actor) => {
			request.extensions_mut().insert(actor);
		}
	}

	next.run(request).await
}

async fn object_get(
	State(g): State<Arc<Global>>, Extension(actor_address): Extension<ActorAddress>,
	Extension(object_hash): Extension<IdType>,
) -> Response {
	let object_info = match g.api.fetch_object_info(&actor_address, &object_hash).await {
		Ok(r) => r,
		Err(e) => return server_error_response(e, "Unable to load object"),
	};
	if object_info.is_none() {
		return not_found_error_response("Object not found");
	}

	let mut context = Context::new();
	context.insert("address", &actor_address);
	context.insert("object", &into_object_display_info(object_info.unwrap()));
	g.render("actor/object.html.tera", context)
}

async fn object_share(
	State(g): State<Arc<Global>>, Extension(actor_address): Extension<ActorAddress>,
	Extension(object_hash): Extension<IdType>,
) -> Response {
	println!("OBJECCT_SHAE");
	let identity = g.state.active_identity.as_ref().unwrap().1.clone();
	let private_key = match g.api.db.perform(|c| c.fetch_my_identity(&identity)) {
		Ok(r) =>
			if let Some((_, pk)) = r {
				pk
			} else {
				return server_error_response2("unable to load identity");
			},
		Err(e) => return server_error_response(e, "unable to load identity"),
	};

	let share = ShareObject {
		actor_address,
		object_hash,
	};
	if let Err(e) = g.api.publish_share(&identity, &private_key, &share).await {
		return server_error_response(e, "unable to ");
	}

	Response::builder()
		.status(303)
		.header("Location", "/")
		.body(Body::empty())
		.unwrap()
}

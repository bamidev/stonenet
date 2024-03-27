use axum::{extract::*, middleware::*, response::Response, routing::*, *};
use sea_orm::*;

use self::common::*;
use crate::{
	entity::{object, Object},
	web::*,
};


pub fn router(g: Arc<Global>) -> Router<Arc<Global>> {
	Router::new()
		.route("/:hash", get(object_get))
		.route_layer(from_fn_with_state(g, object_middleware))
}

async fn object_middleware(
	State(g): State<Arc<Global>>, mut request: Request, next: Next,
) -> Response {
	let hash_str = request.extract_parts::<Path<String>>().await.unwrap().0;

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
	g.render("actor/object", context)
}
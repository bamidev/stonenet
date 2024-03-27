use axum::{extract::*, middleware::*, response::Response, routing::*, *};

use crate::web::*;


pub fn router(g: Arc<Global>) -> Router<Arc<Global>> {
	Router::new()
		.route("/:hash", get(file_get))
		.route_layer(from_fn_with_state(g, file_middleware))
}

async fn file_middleware(mut request: Request, next: Next) -> Response {
	let hash_str = request.extract_parts::<Path<String>>().await.unwrap().0;

	match IdType::from_base58(&hash_str) {
		Ok(id) => request.extensions_mut().insert(id),
		Err(_) => return server_error_response("This is not a valid hash string".to_string()),
	};

	/*match File::find()
		.filter(file::Column::Hash.contains(hash))
		.one(&g.api.orm)
		.await
	{
		Err(e) => return server_error_response(format!("Unable to load file: {}", e)),
		Ok(actor) => {
			request.extensions_mut().insert(actor);
		}
	}*/

	next.run(request).await
}

async fn file_get(
	State(g): State<Arc<Global>>, Extension(actor_address): Extension<ActorAddress>,
	Extension(file_hash): Extension<IdType>,
) -> Response {
	let (mime_type, loader) = match g.api.stream_file(actor_address, file_hash).await {
		Ok(x) => match x {
			Some(r) => r,
			None => return server_error_response("File doesn't exist".to_string()),
		},
		Err(e) => return server_error_response(format!("database issue: {}", e)),
	};

	let body = Body::from_stream(loader);
	Response::builder()
		.header("Content-Type", mime_type)
		.body(body)
		.unwrap()

	/*Ok((
		ContentType(media_type),
		ByteStream! {
			while let Some(result) = loader.next().await {
				match result {
					Ok(block) => yield block,
					Err(e) => {
						warn!("Unable to load file block: {}", e);
						break;
					}
				}
			}
		},
	))*/
}

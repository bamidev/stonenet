use std::collections::HashMap;

use axum::{extract::*, middleware::*, routing::*, *};

use crate::{api::PossibleFileStream, web::*};


pub fn router(g: Arc<Global>) -> Router<Arc<Global>> {
	Router::new()
		.route("/:file-hash", get(file_get))
		.route_layer(from_fn_with_state(g, file_middleware))
}

async fn file_middleware(mut request: Request, next: Next) -> Response {
	let params = request
		.extract_parts::<Path<HashMap<String, String>>>()
		.await
		.unwrap()
		.0;
	let hash_str = params.get("file-hash").unwrap();

	match IdType::from_base58(&hash_str) {
		Ok(id) => request.extensions_mut().insert(id),
		Err(e) => return server_error_response(e, "This is not a valid hash string"),
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
	match g.api.stream_file(actor_address, file_hash).await {
		Ok(x) => match x {
			/*PossibleFileStream::Full(FileData { mime_type, data }) => {
				let body = Body::from(data);
				(mime_type, body)
			}*/
			PossibleFileStream::Stream((mime_type, compression_type, loader)) => {
				let body = Body::from_stream(loader);
				let mut response = Response::builder().header("Content-Type", mime_type);
				match compression_type {
					CompressionType::None => {}
					CompressionType::Brotli => {
						response = response.header("Content-Encoding", "bz");
					}
				}
				response.body(body).unwrap()
			}
			PossibleFileStream::None => server_error_response2("File doesn't exist"),
		},
		Err(e) => server_error_response(e, "database issue"),
	}
}

use std::sync::Arc;

use axum::{body::*, extract::*, response::Response, routing::*};
use log::*;
use serde::Serialize;
use tera::Context;

use super::{server_error_response, FileData, Global};


#[derive(Serialize)]
struct IdentityData {
	label: String,
	address: String,
}


pub fn router(g: Arc<Global>) -> Router<Arc<Global>> {
	let mut new_methods = get(new);
	if !g.server_info.is_exposed {
		new_methods = new_methods.post(new_post);
	}

	Router::new()
		.route("/", get(index))
		.route("/new", new_methods)
}


async fn index(State(g): State<Arc<Global>>) -> Response {
	let identities = match g.api.fetch_my_identities() {
		Ok(i) => i,
		Err(e) => return server_error_response(e, "unable to fetch identities:"),
	};
	let identities_data: Vec<IdentityData> = identities
		.iter()
		.map(|i| {
			let (label, address, ..) = i;
			IdentityData {
				label: label.clone(),
				address: address.to_string(),
			}
		})
		.collect();

	let mut context = Context::new();
	context.insert("identities", &identities_data);
	g.render("identity/overview.html.tera", context)
}

async fn new(State(g): State<Arc<Global>>) -> Response {
	g.render("identity/new.html.tera", Context::new())
}

async fn new_post(State(g): State<Arc<Global>>, mut multipart: Multipart) -> Response {
	// Collect all data from the multipart post request
	let mut label_buf = Vec::new();
	let mut name_buf = Vec::new();
	let mut avatar_buf = Vec::new();
	let mut avatar_mime_type: Option<String> = None;
	let mut wallpaper_buf = Vec::new();
	let mut wallpaper_mime_type: Option<String> = None;
	let mut description_buf = Vec::new();
	while let Some(field) = multipart.next_field().await.unwrap() {
		let name = field.name().unwrap().to_string();

		match name.as_str() {
			"label" => label_buf = field.bytes().await.unwrap().to_vec(),
			"name" => name_buf = field.bytes().await.unwrap().to_vec(),
			"avatar" => {
				avatar_mime_type = field.content_type().map(|s| s.to_string());
				avatar_buf = field.bytes().await.unwrap().to_vec();
			}
			"wallpaper" => {
				wallpaper_mime_type = field.content_type().map(|s| s.to_string());
				wallpaper_buf = field.bytes().await.unwrap().to_vec();
			}
			"description" => description_buf = field.bytes().await.unwrap().to_vec(),
			other => warn!("Unrecognized profile form field: {}", other),
		}
	}

	// Construct the multipart data into something useful
	let label = String::from_utf8_lossy(&label_buf).to_string();
	let name = String::from_utf8_lossy(&name_buf).to_string();
	let avatar = if avatar_buf.len() > 0 {
		avatar_mime_type.map(|mime_type| FileData {
			mime_type,
			data: avatar_buf.into(),
		})
	} else {
		None
	};
	let wallpaper = if wallpaper_buf.len() > 0 {
		wallpaper_mime_type.map(|mime_type| FileData {
			mime_type,
			data: wallpaper_buf.into(),
		})
	} else {
		None
	};
	let description = if description_buf.len() > 0 {
		Some(FileData {
			mime_type: "text/markdown".to_string(),
			data: description_buf.into(),
		})
	} else {
		None
	};

	// Create the identity
	match g.api.create_my_identity(
		&label,
		&name,
		avatar.as_ref(),
		wallpaper.as_ref(),
		description.as_ref(),
	) {
		Ok(_) => Response::builder()
			.status(303)
			.header("Location", "/my-identity")
			.body(Body::empty())
			.unwrap(),
		Err(e) => server_error_response(e, "Unable to create your new identity:"),
	}
}

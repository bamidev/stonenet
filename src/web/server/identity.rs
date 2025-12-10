use std::{collections::HashMap, sync::Arc};

use axum::{
	body::*,
	extract::*,
	middleware::{from_fn_with_state, Next},
	response::Response,
	routing::*,
	RequestExt,
};
use axum_extra::extract::CookieJar;
use log::*;
use sea_orm::{prelude::*, QuerySelect, QueryTrait};
use serde::{Deserialize, Serialize};
use tera::Context;

use super::{
	not_found_error_response, server_error_response, server_error_response2, FileData, ServerGlobal,
};
use crate::{
	db::{self, Database, PersistenceHandle},
	entity::*,
	web::{info::find_profile_info2, server::common::*},
};

#[derive(Serialize)]
struct IdentityData {
	label: String,
	address: String,
}

#[derive(Deserialize)]
struct SelectFormData {
	identity: String,
}

pub fn router(g: Arc<ServerGlobal>) -> Router<Arc<ServerGlobal>> {
	if g.base.server_info.is_exposed {
		return Router::new();
	}

	Router::new()
		.route("/:label", get(profile_get).post(profile_post))
		.route_layer(from_fn_with_state(g, identity_middleware))
		.route("/", get(index))
		.route("/new", get(new).post(new_post))
		.route("/select", post(select_post))
}

async fn identity_middleware(
	State(g): State<Arc<ServerGlobal>>, mut request: Request, next: Next,
) -> Response {
	let params = request
		.extract_parts::<Path<HashMap<String, String>>>()
		.await
		.unwrap()
		.0;
	let label = params.get("label").unwrap();

	let identity_opt = match identity::Entity::find()
		.filter(identity::Column::Label.eq(label))
		.one(g.base.api.db.inner())
		.await
	{
		Err(e) => return server_error_response(e, "Unable to load identity"),
		Ok(a) => a,
	};

	if let Some(identity) = identity_opt {
		request.extensions_mut().insert(label.clone());
		request.extensions_mut().insert(identity);
	} else {
		return not_found_error_response("Unknown identity");
	}

	next.run(request).await
}

async fn profile_get(
	State(g): State<Arc<ServerGlobal>>, Extension(label): Extension<String>,
	Extension(identity): Extension<identity::Model>,
) -> Response {
	let profile = match find_profile_info2(
		&g.base.api.db,
		&g.base.server_info.url_base,
		identity.actor_id,
	)
	.await
	{
		Ok(p) => p,
		Err(e) => return server_error_response(e, "Unable to fetch profile"),
	};

	let mut context = Context::new();
	context.insert("label", &label);
	context.insert("profile", &profile);
	context.insert("is_following", &true);
	g.render("identity/profile.html.tera", context).await
}

async fn profile_post(
	State(g): State<Arc<ServerGlobal>>, Extension(old_label): Extension<String>,
	Extension(identity): Extension<identity::Model>, cookies: CookieJar, multipart: Multipart,
) -> Response {
	let (new_label, name, avatar, wallpaper, description) = parse_identity_form(multipart).await;
	if name.len() == 0 {
		return server_error_response2("Display name can not be empty");
	}

	let (private_key, _) = match load_private_key(&g.base, &cookies).await {
		Ok(k) => k,
		Err(r) => return r,
	};
	if let Err(e) = g
		.base
		.api
		.update_profile(
			&private_key,
			identity.actor_id,
			&old_label,
			&new_label,
			&name,
			avatar,
			wallpaper,
			description,
		)
		.await
	{
		return server_error_response(e, "Unable to update profile");
	}
	Response::builder()
		.status(303)
		.header("Location", "/identity")
		.body(Body::empty())
		.unwrap()
}

async fn index(State(g): State<Arc<ServerGlobal>>, mut request: Request) -> Response {
	let system_user: Option<String>;
	match request.extract_parts::<CookieJar>().await {
		Ok(cookies) => {
			system_user = cookies.get("system-user").map(|c| c.value().to_string());
		}
		Err(e) => return server_error_response(e, "unable to load cookie jar"),
	}

	let identities = match g.base.api.fetch_identities(system_user.as_deref()).await {
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
	g.render("identity/overview.html.tera", context).await
}

async fn new(State(g): State<Arc<ServerGlobal>>) -> Response {
	g.render("identity/profile.html.tera", Context::new()).await
}

async fn parse_identity_form(
	mut multipart: Multipart,
) -> (
	String,
	String,
	Option<FileData>,
	Option<FileData>,
	Option<FileData>,
) {
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
				match field.bytes().await {
					Ok(b) => avatar_buf = b.to_vec(),
					Err(_) => panic!("Uploaded avatar is too large."),
				}
			}
			"wallpaper" => {
				wallpaper_mime_type = field.content_type().map(|s| s.to_string());
				match field.bytes().await {
					Ok(b) => wallpaper_buf = b.to_vec(),
					Err(_) => panic!("Uploaded wallpaper is too large."),
				}
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
			mime_type: mime_type.into(),
			data: avatar_buf.into(),
		})
	} else {
		None
	};
	let wallpaper = if wallpaper_buf.len() > 0 {
		wallpaper_mime_type.map(|mime_type| FileData {
			mime_type: mime_type.into(),
			data: wallpaper_buf.into(),
		})
	} else {
		None
	};
	let description = if description_buf.len() > 0 {
		Some(FileData {
			mime_type: "text/markdown".into(),
			data: description_buf.into(),
		})
	} else {
		None
	};

	(label, name, avatar, wallpaper, description)
}

async fn new_post(
	State(g): State<Arc<ServerGlobal>>, cookies: CookieJar, multipart: Multipart,
) -> Response {
	let system_user: Option<String> = cookies.get("system-user").map(|c| c.value().to_string());
	let (label, name, avatar, wallpaper, description) = parse_identity_form(multipart).await;

	// Create the identity
	match g
		.base
		.api
		.create_identity(
			system_user,
			&label,
			&name,
			avatar.as_ref(),
			wallpaper.as_ref(),
			description.as_ref(),
		)
		.await
	{
		Ok(_) => Response::builder()
			.status(303)
			.header("Location", "/identity")
			.body(Body::empty())
			.unwrap(),
		Err(e) => server_error_response(e, "Unable to create your new identity:"),
	}
}

async fn find_actor_by_label(db: &Database, label: &str) -> db::Result<Option<actor::Model>> {
	let r = actor::Entity::find()
		.filter(
			actor::Column::Id.in_subquery(
				identity::Entity::find()
					.select_only()
					.column(identity::Column::ActorId)
					.filter(identity::Column::Label.eq(label))
					.into_query(),
			),
		)
		.one(db.inner())
		.await?;
	Ok(r)
}

async fn select_post(
	State(g): State<Arc<ServerGlobal>>, Form(form): Form<SelectFormData>,
) -> Response {
	match find_actor_by_label(&g.base.api.db, &form.identity).await {
		Err(e) => server_error_response(e, "Unable to find selected identity"),
		Ok(resultset) => {
			if let Some(record) = resultset {
				g.base.state.lock().await.active_identity = Some((form.identity, record.address));
				Response::builder()
					.status(303)
					.header("Location", "/")
					.body(Body::empty())
					.unwrap()
			} else {
				server_error_response2("Unable to find selected identity")
			}
		}
	}
}

use std::{
	//error::Error as StdError,
	path::{Path, PathBuf}
};

use crate::{
	common::*,
	api::Api,
	db,
	identity::*,
	model::*
};

use base58::FromBase58;
use futures::future::join_all;
use rocket::*;
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket::serde::Serialize;
use rocket_dyn_templates::{Template, context};


fn render_db_error(error: db::Error, message: &str) -> Template {
	error!("Database error: {}: {}", message, error);
	Template::render("error", context! {
		title: "Database error",
		message
	})
}

fn render_error<E>(error: E, title: &str, message: &str) -> Template {
	Template::render("error", context! {
		title,
		message
	})
}

#[derive(Serialize)]
struct IdentityData {
	label: String,
	address: String
}

#[get("/")]
async fn index(api: &State<Api>) -> Template {
	let identities = match api.fetch_my_identities() {
		Ok(i) => i,
		Err(e) => return render_db_error(e, "unable to fetch my identities")
	};
	let identities_data: Vec<IdentityData> = identities.iter().map(|i| {
		let (label, address, _) = i;
		IdentityData {
			label: label.clone(),
			address: address.to_string()
		}
	}).collect();

	Template::render("home", context! {
		identities: identities_data
	})
}

#[derive(FromForm)]
struct PostPostData {
	message: String,
	identity: String,
}

#[post("/", data = "<form_data>")]
async fn index_post(
	form_data: Form<PostPostData>,
	api: &State<Api>
) -> Template {
	let identity_address = IdType::from_base58(&form_data.identity).expect("unable to parse post identity");
	let (_label, keypair) = match api.fetch_my_identity(&identity_address) {
		Ok(k) => k.expect("my identity not found"),
		Err(e) => return render_db_error(e, "unable to fetch my identity")
	};
	// TODO: Parse tags from post.
	match api.publish_post(
		&identity_address,
		&keypair,
		&form_data.message,
		Vec::new(),
		&Vec::new()
	).await {
		Ok(()) => {},
		Err(e) => return render_db_error(e, "unable to publish post")
	}

	index(api).await
}

pub async fn main(g: Api) {
	let _ = rocket::build()
		.attach(Template::fairing())
		.manage(g)
		.mount("/", routes![
			feed,
			static_,
			index,
			index_post,
			my_identities,
			my_identities_post,
			search
		])
		.launch().await
		.expect("Rocket runtime failed");
}

#[get("/feed/<address_str>")]
async fn feed(address_str: &str, g: &State<Api>) -> Template {
	#[derive(rocket::serde::Serialize)]
	struct Object {
		body: String
	}

	let address = match IdType::from_base58(address_str) {
		Err(e) => return render_error(&e, "Database error", &format!("This is not a valid address: {}", e)),
		Ok(a) => a
	};
	let latest_objects = match g.fetch_latest_objects(&address, 5, 0).await {
		Err(e) => return render_error(&e, "Database error", &format!("Database error while trying to fetch latest objects: {}", e)),
		Ok(a) => a
	};
	let mut futs = Vec::with_capacity(latest_objects.len());
	for i in 0..latest_objects.len() {
		let object = latest_objects[i].clone();
		futs.push(async {
			match object {
				None => "Unable to locate this feed object...",
				Some(header) => {
					/*let payload = match g.fetch_object_payload(header.index).await {
						Err(e) => return render_error(e,
							"Database error",
							&format!("Database error while trying to fetch latest object payloads: {}", e)
						),
						Ok(p) => p
					};
					render_object_payload(payload)*/
					"test"
				}
			}
		})
	}
	let object_htmls = join_all(futs).await;

	Template::render("feed", context! {
		address: address.to_string(),
		posts: Vec::<PostObject>::new()
	})
}

#[get("/my-identities")]
async fn my_identities(api: &State<Api>) -> Template {
	#[derive(rocket::serde::Serialize)]
	struct Object {
		id: u64,
		label: String,
		address: String
	}
	
	let identities = match api.fetch_my_identities() {
		Ok(i) => i,
		Err(e) => return render_db_error(e, "unable to fetch identities")
	};
	let identities_data: Vec<IdentityData> = identities.iter().map(|i| {
		let (label, address, _) = i;
		IdentityData {
			label: label.clone(),
			address: address.to_string()
		}
	}).collect();

	Template::render("my_identities", context! {
		identities: identities_data
	})
}

#[derive(FromForm)]
struct MyIdentitiesPostData {
	label: String
}

#[post("/my-identities", data = "<form_data>")]
async fn my_identities_post(form_data: Form<MyIdentitiesPostData>, api: &State<Api>) -> Template {
	assert!(form_data.label.len() > 0, "Invalid label received");
	
	let keypair = Keypair::generate();
	let identity: Identity = keypair.public().into();
	let address = identity.generate_address();
	
	match api.create_my_identity(&form_data.label, &address, &keypair) {
		Ok(()) => {},
		Err(e) => return render_db_error(e, "unable to create my identity")
	}

	my_identities(api).await
}

#[get("/static/<file..>")]
async fn static_(file: PathBuf) -> Option<NamedFile> {
	NamedFile::open(Path::new("static/").join(file)).await.ok()
}

#[get("/search?<query>")]
async fn search(query: &str, g: &State<Api>) -> Template {
	#[derive(rocket::serde::Serialize)]
	struct SearchResult {
		
	}

	let mut error_message: Option<String> = None;
	let result = match query.from_base58() {
		Err(_) => {
			error_message = Some("not a valid base58 encoded string".into()); None
		},
		Ok(data) => {
			if data.len() < 32 {
				error_message = Some("address too short".into()); None
			}
			else if data.len() > 32 {
				error_message = Some("address too long".into()); None
			}
			else {
				let actor_id = IdType::from_slice(&data).unwrap();
				g.node.find_actor(
					&actor_id,
					100,
					false
				).await
			}
		}
	};

	Template::render("search", context! {
		query,
		posts: Vec::<SearchResult>::new(),
		error_message,
		result
	})
}
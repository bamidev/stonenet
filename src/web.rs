mod common;

use std::{
	io,
	path::{Path, PathBuf},
	str::FromStr,
};

use base58::FromBase58;
use multipart::server::Multipart;
use rocket::{
	form::Form,
	fs::NamedFile,
	http::{ContentType, MediaType},
	response::{stream::ByteStream, Redirect},
	serde::Serialize,
	Data, *,
};
use rocket_dyn_templates::{context, Template};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;

use self::common::*;
use crate::{api::Api, common::*, db, model::*};


fn render_db_error(error: db::Error, message: &str) -> Template {
	error!("Database error: {}: {}", message, error);
	Template::render(
		"error",
		context! {
			title: "Database error",
			message
		},
	)
}

fn render_error(title: &str, message: &str) -> Template {
	Template::render(
		"error",
		context! {
			title,
			message
		},
	)
}

#[derive(Serialize)]
struct IdentityData {
	label: String,
	address: String,
}

#[get("/?<page>")]
async fn index(page: Option<u64>, api: &State<Api>) -> Template {
	let identities = match api.fetch_my_identities() {
		Ok(i) => i,
		Err(e) => return render_db_error(e, "unable to fetch my identities"),
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

	let p = page.unwrap_or(0);
	let start = p * 5;
	let objects: Vec<ObjectDisplayInfo> = match api.fetch_home_feed(5, start) {
		Ok(f) => f.into_iter().map(|o| into_object_display_info(o)).collect(),
		Err(e) => return render_db_error(e, "unable to fetch home feed"),
	};

	Template::render(
		"home",
		context! {
			identities: identities_data,
			objects,
			page: p
		},
	)
}

#[derive(FromForm)]
struct PostPostData {
	message: String,
	identity: String,
}

#[post("/", data = "<data>")]
async fn index_post(
	api: &State<Api>, content_type: &ContentType, data: Data<'_>,
) -> Result<Template, Template> {
	let (_, boundary) = content_type
		.params()
		.find(|&(k, _)| k == "boundary")
		.ok_or_else(|| {
			render_error(
				"bad request",
				"`Content-Type: multipart/form-data` boundary param not provided",
			)
		})?;

	let (message, attachments, identity) =
		process_message_form(data, boundary).await.map_err(|e| {
			error!("Unable to process form input: {}", e);
			render_error("Input error", "Unable to process form input")
		})?;

	if message.len() == 0 {
		return Ok(index(None, api).await);
	}

	let identity_address = IdType::from_base58(&identity).expect("unable to parse post identity");
	let (_label, keypair) = match api.fetch_my_identity(&identity_address) {
		Ok(k) => k.expect("my identity not found"),
		Err(e) => return Err(render_db_error(e, "unable to fetch my identity")),
	};

	// TODO: Parse tags from post.
	api.publish_post(
		&identity_address,
		&keypair,
		&message,
		Vec::new(),
		&attachments,
		None,
	)
	.await
	.map_err(|e| render_db_error(e, "unable to publish post"))?;

	Ok(index(None, api).await)
}

pub async fn spawn(g: Api) -> (Shutdown, JoinHandle<()>) {
	// Set up rocket's config to not detect ctrlc itself
	let mut config = rocket::Config::default();
	config.port = 37338;
	config.shutdown.ctrlc = false;
	#[cfg(unix)]
	config.shutdown.signals.clear();

	let r = rocket::custom(&config)
		.attach(Template::fairing())
		.manage(g)
		.mount(
			"/",
			routes![
				actor,
				actor_file,
				actor_object,
				actor_object_post,
				actor_post,
				static_,
				index,
				index_post,
				my_identity,
				my_identity_new,
				my_identity_new_post,
				search
			],
		)
		.ignite()
		.await
		.expect("Rocket ignition failed");
	let handle = r.shutdown();
	let task = tokio::spawn(async move {
		let _ = r.launch().await.expect("Rocket runtime failed");
	});
	(handle, task)
}

#[get("/actor/<address_str>")]
async fn actor(address_str: &str, g: &State<Api>) -> Template {
	#[derive(rocket::serde::Serialize)]
	struct Object {
		body: String,
	}

	let address = match IdType::from_base58(address_str) {
		Ok(a) => a,
		Err(_) => return render_error("Error", &format!("This is not a valid address")),
	};
	let profile = match g.fetch_profile_info(&address).await {
		Ok(p) => p,
		Err(e) => return render_db_error(e, "Unable to fetch profile"),
	};
	let is_following: bool = match g.is_following(&address) {
		Ok(f) => f,
		Err(e) => return render_db_error(e, "Unable to fetch follow status"),
	};
	// TODO: Check if public key is available, if so, following is still possible.

	/*let latest_objects = match g.fetch_home_feed(&address, 5, 0) {
		Err(e) => return render_error(&e, "Database error", &format!("Database error while trying to fetch latest objects: {}", e)),
		Ok(a) => a
	};
	let mut futs = Vec::with_capacity(latest_objects.len());
	for i in 0..latest_objects.len() {
		let object = latest_objects[i];

	}*/

	Template::render(
		"actor",
		context! {
			address: address.to_string(),
			profile,
			is_following
		},
	)
}

#[get("/actor/<address_str>/file/<hash_str>")]
async fn actor_file(
	address_str: &str, hash_str: &str, g: &State<Api>,
) -> Result<(ContentType, ByteStream![Vec<u8>]), Template> {
	let address = match IdType::from_base58(address_str) {
		Ok(a) => a,
		Err(_) =>
			return Err(render_error(
				"Error",
				&format!("This is not a valid address"),
			)),
	};
	let hash = match IdType::from_base58(hash_str) {
		Ok(a) => a,
		Err(_) => return Err(render_error("Error", &format!("This is not a valid hash"))),
	};

	let (mime_type, mut loader) = match g.stream_file(address, hash).await {
		Ok(x) => match x {
			Some(r) => r,
			None => return Err(render_error("Error", &format!("File doesn't exist"))),
		},
		Err(e) => return Err(render_db_error(e, "database issue")),
	};
	let media_type = if let Ok(m) = MediaType::from_str(&mime_type) {
		m
	} else {
		return Err(render_error(
			"Error",
			&format!("Invalid media type for file: {}", &mime_type),
		));
	};

	Ok((
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
	))
}

#[get("/actor/<address_str>/object/<sequence>")]
async fn actor_object(
	api: &State<Api>, address_str: &str, sequence: u64,
) -> Result<Template, Template> {
	let address = IdType::from_base58(address_str)
		.map_err(|_e| render_error("Input error", "Invalid address"))?;
	let object_info = api
		.fetch_object_info(&address, sequence)
		.await
		.map_err(|e| render_db_error(e, "Unable to load object"))?;
	if object_info.is_none() {
		return Err(render_error("Not found", "Object not found"));
	}
	let identities = api
		.fetch_my_identities()
		.map_err(|e| render_db_error(e, "Unable to load my identities"))?;
	let identities_data: Vec<IdentityData> = identities
		.iter()
		.map(|(label, address, ..)| IdentityData {
			label: label.clone(),
			address: address.to_string(),
		})
		.collect();

	Ok(Template::render(
		"actor/object",
		context! {
			address: address.to_string(),
			identities: identities_data,
			object: into_object_display_info(object_info.unwrap())
		},
	))
}

#[post("/actor/<address_str>/object/<hash_str>", data = "<form_data>")]
async fn actor_object_post(
	api: &State<Api>, address_str: &str, hash_str: &str, form_data: Form<PostPostData>,
) -> Result<Redirect, Template> {
	let address = IdType::from_base58(address_str)
		.map_err(|_e| render_error("Input error", "Invalid actor address"))?;
	let hash = IdType::from_base58(hash_str)
		.map_err(|_e| render_error("Input error", "Invalid object hash"))?;
	let identity_address = IdType::from_base58(&form_data.identity)
		.map_err(|_e| render_error("Input error", "Invalid identity address"))?;
	let (_label, keypair) = api
		.fetch_my_identity(&identity_address)
		.map_err(|e| render_db_error(e, "unable to fetch my identity"))?
		.expect("my identity not found");

	// TODO: Parse tags from post.
	api.publish_post(
		&identity_address,
		&keypair,
		&form_data.message,
		Vec::new(),
		&Vec::new(),
		Some((address, hash)),
	)
	.await
	.map_err(|e| render_db_error(e, "Unable to publish post"))?;
	Ok(Redirect::to("/"))
}

#[derive(FromForm)]
struct ActorActions {
	follow: Option<String>,
}

#[post("/actor/<address_str>", data = "<form_data>")]
async fn actor_post(address_str: &str, g: &State<Api>, form_data: Form<ActorActions>) -> Template {
	match form_data.follow.as_ref() {
		None => {}
		Some(follow) => {
			let address = match IdType::from_base58(address_str) {
				Ok(a) => a,
				Err(_) => return render_error("Error", &format!("This is not a valid address")),
			};

			// Follow
			if follow == "1" {
				match g.follow(&address, true).await {
					Ok(success) =>
						if !success {
							return render_error(
								"Not found",
								"Coulnd't find the public key from this public key for this \
								 person. None of his/her followers, neither him-/herself were \
								 online.",
							);
						},
					Err(e) => return render_db_error(e, &format!("Unable to follow person")),
				}
			// Unfollow
			} else {
				match g.unfollow(&address).await {
					Ok(_) => {}
					Err(e) => return render_db_error(e, &format!("Unable to unfollow person")),
				}
			}
		}
	}

	actor(address_str, g).await
}

#[get("/my-identity")]
async fn my_identity(api: &State<Api>) -> Template {
	#[derive(rocket::serde::Serialize)]
	struct Object {
		id: u64,
		label: String,
		address: String,
	}

	let identities = match api.fetch_my_identities() {
		Ok(i) => i,
		Err(e) => return render_db_error(e, "unable to fetch identities"),
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

	Template::render(
		"identity/overview",
		context! {
			identities: identities_data
		},
	)
}

#[get("/my-identity/new")]
async fn my_identity_new() -> Template { Template::render("identity/new", context! {}) }

#[post("/my-identity/new", data = "<data>")]
async fn my_identity_new_post(
	api: &State<Api>, content_type: &ContentType, data: Data<'_>,
) -> Result<Redirect, Template> {
	if !content_type.is_form_data() {
		return Err(render_error("bad request", "invalid content type header"));
	}

	let (_, boundary) = content_type
		.params()
		.find(|&(k, _)| k == "boundary")
		.ok_or_else(|| {
			render_error(
				"bad request",
				"`Content-Type: multipart/form-data` boundary param not provided",
			)
		})?;

	let (label, name, avatar_file_data, wallpaper_file_data, description) =
		process_profile_form(data, boundary).await.or_else(|e| {
			Err(render_error(
				"I/O error",
				&format!("Form data issue: {}", e),
			))
		})?;

	match api.create_my_identity(
		&label,
		&name,
		avatar_file_data.as_ref(),
		wallpaper_file_data.as_ref(),
		&description,
	) {
		Ok(_) => Ok(Redirect::to("/my-identity")),
		Err(e) => Err(render_db_error(e, "unable to create my identity")),
	}
}

const UPLOAD_FILE_LIMIT: &str = "10MiB";

async fn process_message_form(
	data: Data<'_>, boundary: &str,
) -> io::Result<(String, Vec<FileData>, String)> {
	let data_stream = data.open(UPLOAD_FILE_LIMIT.parse().unwrap());
	let raw_data = data_stream.into_bytes().await?;

	let mut mp = Multipart::with_body(raw_data.as_slice(), boundary);
	let mut message_buf = Vec::new();
	let mut attachments = Vec::new();
	let mut identity_buf = Vec::new();

	while let Some(mut field) = mp.read_entry()? {
		match &*field.headers.name {
			"identity" => {
				let _ = field
					.data
					.save()
					.write_to(&mut identity_buf)
					.into_result_strict()?;
			}
			"message" => {
				let _ = field
					.data
					.save()
					.write_to(&mut message_buf)
					.into_result_strict()?;
			}
			"attachments" => {
				let mut attachment_buf = Vec::new();
				let _ = field
					.data
					.save()
					.write_to(&mut attachment_buf)
					.into_result_strict()?;
				let mime_type = field
					.headers
					.content_type
					.map(|m| m.essence_str().to_string())
					.ok_or(io::Error::from(io::ErrorKind::Other))?; // FIXME: Raise a proper error

				if attachment_buf.len() > 0 {
					attachments.push(FileData {
						mime_type,
						data: attachment_buf,
					});
				}
			}
			_ => {}
		}
	}

	Ok((
		String::from_utf8_lossy(&message_buf).to_string(),
		attachments,
		String::from_utf8_lossy(&identity_buf).to_string(),
	))
}

async fn process_profile_form(
	data: Data<'_>, boundary: &str,
) -> io::Result<(String, String, Option<FileData>, Option<FileData>, String)> {
	let data_stream = data.open(UPLOAD_FILE_LIMIT.parse().unwrap());
	let raw_data = data_stream.into_bytes().await?;

	let mut mp = Multipart::with_body(raw_data.as_slice(), boundary);
	let mut label_buf = Vec::new();
	let mut name_buf = Vec::new();
	let mut avatar_buf = Vec::default();
	let mut avatar_mime_type: Option<String> = None;
	let mut wallpaper_buf = Vec::default();
	let mut wallpaper_mime_type: Option<String> = None;
	let mut description_buf = Vec::new();

	while let Some(mut field) = mp.read_entry()? {
		match &*field.headers.name {
			"label" => {
				let _ = field
					.data
					.save()
					.write_to(&mut label_buf)
					.into_result_strict()?;
			}
			"name" => {
				let _ = field
					.data
					.save()
					.write_to(&mut name_buf)
					.into_result_strict()?;
			}
			"avatar" => {
				let _ = field
					.data
					.save()
					.write_to(&mut avatar_buf)
					.into_result_strict()?;
				avatar_mime_type = field
					.headers
					.content_type
					.map(|m| m.essence_str().to_string());
			}
			"wallpaper" => {
				let _ = field
					.data
					.save()
					.write_to(&mut wallpaper_buf)
					.into_result_strict()?;
				wallpaper_mime_type = field
					.headers
					.content_type
					.map(|m| m.essence_str().to_string());
			}
			"description" => {
				let _ = field
					.data
					.save()
					.write_to(&mut description_buf)
					.into_result_strict()?;
			}
			_ => {}
		}
	}

	Ok((
		String::from_utf8_lossy(&label_buf).to_string(),
		String::from_utf8_lossy(&name_buf).to_string(),
		match avatar_mime_type {
			Some(m) =>
				if avatar_buf.len() > 0 {
					Some(FileData {
						mime_type: m,
						data: avatar_buf,
					})
				} else {
					None
				},
			None => None,
		},
		match wallpaper_mime_type {
			Some(m) =>
				if wallpaper_buf.len() > 0 {
					Some(FileData {
						mime_type: m,
						data: wallpaper_buf,
					})
				} else {
					None
				},
			None => None,
		},
		String::from_utf8_lossy(&description_buf).to_string(),
	))
}

#[get("/static/<file..>")]
async fn static_(file: PathBuf) -> Option<NamedFile> {
	NamedFile::open(Path::new("static/").join(file)).await.ok()
}

#[get("/search?<query>")]
async fn search(query: &str, _g: &State<Api>) -> Result<Redirect, Template> {
	match query.from_base58() {
		Err(_) => Err(render_error(
			"Query error",
			"not a valid base58 encoded string",
		)),
		Ok(data) =>
			if data.len() < 32 {
				Err(render_error("Query error", "address too short"))
			} else if data.len() > 32 {
				Err(render_error("Query error", "address too long"))
			} else {
				let id = IdType::from_bytes(data.as_slice().try_into().unwrap());
				Ok(Redirect::to(format!("/actor/{}", id.to_string())))
			},
	}
}

mod activity_pub;
mod actor;
mod common;
mod my_identity;

use std::{
	net::*,
	str::FromStr,
	sync::{atomic::*, Arc},
	time::Duration,
};

use ::serde::*;
use axum::{body::Body, extract::*, response::Response, routing::get, Router};
use tera::{Context, Tera};
use tokio::{spawn, time::sleep};
use tower_http::services::ServeDir;

use self::common::*;
use crate::{
	api::Api,
	common::*,
	config::Config,
	core::*,
	db::{self, Database},
};


#[derive(Clone, Serialize)]
pub struct IdentityData {
	label: String,
	address: String,
}

#[derive(Clone, Default, Serialize)]
pub struct AppState {
	active_identity: Option<(String, ActorAddress)>,
	identities: Vec<IdentityData>,
}

#[derive(Clone)]
pub struct Global {
	pub config: Config,
	pub state: AppState,
	pub server_info: ServerInfo,
	pub api: Api,
	pub template_engine: Tera,
}

#[derive(Clone, Serialize)]
pub struct ServerInfo {
	pub is_exposed: bool,
	pub federation_domain: String,
	pub url_base: String,
	pub update_message: Option<String>,
}


impl AppState {
	pub async fn load(db: &Database) -> db::Result<Self> {
		let identities = db.perform(|c| c.fetch_my_identities())?;

		Ok(Self {
			active_identity: identities
				.get(0)
				.map(|(label, address, ..)| (label.clone(), address.clone())),
			identities: identities
				.into_iter()
				.map(|(label, address, ..)| IdentityData {
					label,
					address: address.to_string(),
				})
				.collect(),
		})
	}
}

impl Global {
	pub fn render(&self, template_name: &str, context: Context) -> Response {
		let mut complete_context = Context::new();
		complete_context.insert("app", &self.state);
		complete_context.insert("server", &self.server_info);
		complete_context.extend(context);

		match self
			.template_engine
			.render(template_name, &complete_context)
		{
			Err(e) => server_error_response(
				e,
				&format!("Unable to render template \"{}\"", template_name),
			),
			Ok(html) => Response::builder()
				.header("Content-Type", "text/html")
				.body(Body::from(html))
				.unwrap(),
		}
	}
}

/*async fn index(page: Option<u64>, g: &State<GlobalState>) -> Template {
	let identities = match g.api.fetch_my_identities() {
		Ok(i) => i,
		Err(e) => return render_db_error(e, "unable to fetch my identities"),
	};
	let identities_data: Vec<IdentityData> = identities
		.iter()
		.map(|i| {
			let (label, address, ..) = i;
			let address2 = Address::Actor(address.clone());
			IdentityData {
				label: label.clone(),
				address: address2.to_string(),
			}
		})
		.collect();

	let p = page.unwrap_or(0);
	let start = p * 5;
	let objects: Vec<ObjectDisplayInfo> = match g.api.fetch_home_feed(5, start) {
		Ok(f) => f.into_iter().map(|o| into_object_display_info(o)).collect(),
		Err(e) => return render_db_error(e, "unable to fetch home feed"),
	};

	Template::render(
		"home",
		context! {
			global: g.context.clone(),
			identities: identities_data,
			objects,
			page: p,
		},
	)
}

struct PostPostData {
	message: String,
	identity: String,
}

async fn index_post(
	g: &State<GlobalState>, content_type: &ContentType, data: Data<'_>,
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

	let (message, attachments, address_str) =
		process_message_form(data, boundary).await.map_err(|e| {
			error!("Unable to process form input: {}", e);
			render_error("Input error", "Unable to process form input")
		})?;

	if message.len() == 0 {
		return Ok(index(None, g).await);
	}
	let actor_address = parse_actor_address(&address_str)?;

	let (_label, keypair) = match g.api.fetch_my_identity(&actor_address) {
		Ok(k) => k.expect("my identity not found"),
		Err(e) => return Err(render_db_error(e, "unable to fetch my identity")),
	};

	// TODO: Parse tags from post.
	g.api
		.publish_post(
			&actor_address,
			&keypair,
			&message,
			Vec::new(),
			&attachments,
			None,
		)
		.await
		.map_err(|e| render_db_error(e, "unable to publish post"))?;

	Ok(index(None, g).await)
}*/

pub async fn serve(
	stop_flag: Arc<AtomicBool>, port: u16, _workers: Option<usize>, api: Api,
	server_info: ServerInfo, config: Config,
) -> db::Result<()> {
	let global = Arc::new(Global {
		state: AppState::load(&api.db).await?,
		api,
		server_info,
		template_engine: Tera::new("templates/**/*.tera").unwrap(),
		config,
	});

	// TODO: Only turn this on via a config option that is off by default.
	if global.server_info.is_exposed {
		spawn(activity_pub::loop_send_queue(
			stop_flag.clone(),
			global.clone(),
		));
	}

	let ip = if global.server_info.is_exposed {
		Ipv4Addr::LOCALHOST
	} else {
		Ipv4Addr::UNSPECIFIED
	};
	let addr = SocketAddrV4::new(ip, port);

	let app = Router::new()
		.route("/", get(home).post(home_post))
		.nest_service("/static", ServeDir::new("static"))
		.nest("/actor", actor::router(global.clone()))
		.nest("/my-identity", my_identity::router(global.clone()))
		.route("/search", get(search))
		.route("/.well-known/webfinger", get(activity_pub::webfinger))
		.with_state(global);

	let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
	axum::serve(listener, app)
		.with_graceful_shutdown(async move {
			while !stop_flag.load(Ordering::Relaxed) {
				sleep(Duration::from_secs(1)).await;
			}
		})
		.await
		.unwrap();
	Ok(())
}

#[derive(Default, Deserialize)]
struct PaginationQuery {
	page: Option<u64>,
}

async fn home(State(g): State<Arc<Global>>, Query(query): Query<PaginationQuery>) -> Response {
	let p = query.page.unwrap_or(0);
	let start = p * 5;
	let objects: Vec<ObjectDisplayInfo> = match g.api.load_home_feed(5, start).await {
		Ok(f) => f.into_iter().map(|o| into_object_display_info(o)).collect(),
		Err(e) => return server_error_response(e, "unable to fetch home feed"),
	};

	let mut context = Context::new();
	context.insert("objects", &objects);
	context.insert("page", &p);
	g.render("home.html.tera", context)
}

async fn home_post(State(g): State<Arc<Global>>, form: Multipart) -> Response {
	if let Err(e) = post_message(&g, form, None).await {
		return e;
	}

	home(State(g), Query(PaginationQuery::default())).await
}

#[derive(Deserialize)]
struct SearchQuery {
	address: String,
}

async fn search(Query(query): Query<SearchQuery>) -> Response {
	match Address::from_str(&query.address) {
		Err(e) => server_error_response(e, "Invalid address"),
		Ok(address) => Response::builder()
			.status(303)
			.header("Location", format!("/actor/{}", address))
			.body(Body::empty())
			.unwrap(),
	}
}

/*

#[get("/actor/<address_str>/file/<hash_str>")]
async fn actor_file(
	address_str: &str, hash_str: &str, g: &State<GlobalState>,
) -> Result<(ContentType, ByteStream![Vec<u8>]), Template> {
	let address = parse_actor_address(address_str)?;
	let hash = match IdType::from_base58(hash_str) {
		Ok(a) => a,
		Err(_) => return Err(render_error("Error", &format!("This is not a valid hash"))),
	};

	let (mime_type, mut loader) = match g.api.stream_file(address, hash).await {
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

#[get("/actor/<address_str>/object/<hash_str>")]
async fn actor_object(
	g: &State<GlobalState>, address_str: &str, hash_str: &str,
) -> Result<Template, Template> {
	let address = parse_actor_address(address_str)?;
	let hash = IdType::from_base58(hash_str)
		.map_err(|_e| render_error("Input error", "Invalid object hash"))?;
	let object_info = g
		.api
		.fetch_object_info(&address, &hash)
		.await
		.map_err(|e| render_db_error(e, "Unable to load object"))?;
	if object_info.is_none() {
		return Err(render_error("Not found", "Object not found"));
	}
	let identities = g
		.api
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
	g: &State<GlobalState>, address_str: &str, hash_str: &str, form_data: Form<PostPostData>,
) -> Result<Redirect, Template> {
	let address = parse_actor_address(address_str)?;
	let hash = IdType::from_base58(hash_str)
		.map_err(|_e| render_error("Input error", "Invalid object hash"))?;
	let actor_address = parse_actor_address(&form_data.identity)?;
	let (_label, keypair) = g
		.api
		.fetch_my_identity(&actor_address)
		.map_err(|e| render_db_error(e, "unable to fetch my identity"))?
		.expect("my identity not found");

	// TODO: Parse tags from post.
	g.api
		.publish_post(
			&actor_address,
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

#[post("/actor/<address_str>/object/<hash_str>/share")]
async fn actor_object_share(
	g: &State<GlobalState>, address_str: &str, hash_str: &str,
) -> Result<Redirect, Template> {
	let _address = parse_actor_address(address_str)?;
	let _hash = IdType::from_base58(hash_str)
		.map_err(|_e| render_error("Input error", "Invalid object hash"))?;

	todo!();
	//g.api.publish_share()
}

#[derive(FromForm)]
struct ActorActions {
	follow: Option<String>,
}

#[post("/actor/<address_str>", data = "<form_data>")]
async fn actor_post(
	address_str: &str, g: &State<GlobalState>, form_data: Form<ActorActions>,
) -> Result<Template, Template> {
	match form_data.follow.as_ref() {
		None => {}
		Some(follow) => {
			let address = parse_actor_address(address_str)?;

			// Follow
			if follow == "1" {
				match g.api.follow(&address, true).await {
					Ok(success) =>
						if !success {
							return Err(render_error(
								"Not found",
								"Coulnd't find the public key from this public key for this \
								 person. None of his/her followers, neither him-/herself were \
								 online.",
							));
						},
					Err(e) => return Err(render_db_error(e, &format!("Unable to follow person"))),
				}
			// Unfollow
			} else {
				match g.api.unfollow(&address).await {
					Ok(_) => {}
					Err(e) =>
						return Err(render_db_error(e, &format!("Unable to unfollow person"))),
				}
			}
		}
	}

	actor(address_str, g).await
}

#[get("/my-identity")]
async fn my_identity(g: &State<GlobalState>) -> Template {
	#[derive(rocket::serde::Serialize)]
	struct Object {
		id: u64,
		label: String,
		address: String,
	}

	let identities = match g.api.fetch_my_identities() {
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
	g: &State<GlobalState>, content_type: &ContentType, data: Data<'_>,
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

	match g.api.create_my_identity(
		&label,
		&name,
		avatar_file_data.as_ref(),
		wallpaper_file_data.as_ref(),
		description.as_ref(),
	) {
		Ok(_) => Ok(Redirect::to("/my-identity")),
		Err(e) => {
			let error_string = format!("unable to create my identity: {}", &e);
			Err(render_db_error(e, &error_string))
		}
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
) -> io::Result<(
	String,
	String,
	Option<FileData>,
	Option<FileData>,
	Option<FileData>,
)> {
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
		if description_buf.len() > 0 {
			Some(FileData {
				mime_type: "text/markdown".to_string(),
				data: description_buf,
			})
		} else {
			None
		},
	))
}

#[get("/static/<file..>")]
async fn static_(file: PathBuf) -> Option<NamedFile> {
	NamedFile::open(Path::new("static/").join(file)).await.ok()
}

#[get("/search?<query>")]
async fn search(query: &str, _g: &State<GlobalState>) -> Result<Redirect, Template> {
	match Address::from_str(query) {
		Err(e) => Err(render_error(
			"Address parse error",
			&format!("Not a valid address: {}", e),
		)),
		Ok(address) => Ok(Redirect::to(format!("/actor/{}", address.to_string()))),
	}
}*/

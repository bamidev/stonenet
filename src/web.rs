mod activity_pub;
mod actor;
mod common;
mod identity;

use std::{
	net::*,
	str::FromStr,
	sync::{atomic::*, Arc},
	time::Duration,
};

use ::serde::*;
use axum::{body::Body, extract::*, response::Response, routing::get, Router};
#[cfg(debug_assertions)]
use rss::validation::Validate;
use rss::{ChannelBuilder, ItemBuilder};
use tera::{Context, Tera};
use tokio::{sync::Mutex, time::sleep};
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

pub struct Global {
	pub config: Config,
	pub state: Mutex<AppState>,
	pub server_info: ServerInfo,
	pub api: Api,
	pub template_engine: Tera,
}

#[derive(Clone, Serialize)]
pub struct ServerInfo {
	pub is_exposed: bool,
	pub federation_domain: String,
	pub url_base: String,
	pub update_message: Option<(String, bool)>,
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
	pub async fn render(&self, template_name: &str, context: Context) -> Response {
		let mut complete_context = Context::new();
		let state = self.state.lock().await.clone();
		complete_context.insert("app", &state);
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

pub async fn serve(
	stop_flag: Arc<AtomicBool>, port: u16, _workers: Option<usize>, api: Api,
	server_info: ServerInfo, config: Config,
) -> db::Result<()> {
	let global = Arc::new(Global {
		state: Mutex::new(AppState::load(&api.db).await?),
		api,
		server_info,
		template_engine: Tera::new("templates/**/*.tera").unwrap(),
		config,
	});

	// TODO: Only turn this on via a config option that is off by default.
	if global.server_info.is_exposed {
		activity_pub::init(stop_flag.clone(), global.clone()).await;
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
		.nest("/activity-pub", activity_pub::router(global.clone()))
		.nest("/actor", actor::router(global.clone()))
		.nest("/identity", identity::router(global.clone()))
		.route("/rss", get(rss_feed))
		.route("/search", get(search))
		.route("/.well-known/webfinger", get(activity_pub::webfinger))
		.route("/.well-known/x-nodeinfo2", get(activity_pub::nodeinfo))
		.with_state(global);

	let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
	axum::serve(
		listener,
		app.into_make_service_with_connect_info::<SocketAddr>(),
	)
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
	g.render("home.html.tera", context).await
}

async fn home_post(State(g): State<Arc<Global>>, form: Multipart) -> Response {
	if let Err(e) = post_message(&g, form, None).await {
		return e;
	}

	home(State(g), Query(PaginationQuery::default())).await
}

async fn rss_feed(State(g): State<Arc<Global>>) -> Response {
	let objects: Vec<ObjectDisplayInfo> = match g.api.load_home_feed(20, 0).await {
		Ok(f) => f.into_iter().map(|o| into_object_display_info(o)).collect(),
		Err(e) => return server_error_response(e, "unable to fetch home feed"),
	};

	let mut channel_builder = ChannelBuilder::default();
	channel_builder
		.title("Stonenet RSS feed")
		.link(&g.server_info.url_base);
	if g.server_info.is_exposed {
		channel_builder.description("An RSS feed of this Stonenet bridge.");
	} else {
		channel_builder.description("An RSS feed of your Stonenet home feed.");
	}

	// Prepare RSS feed items
	let mut items = Vec::with_capacity(objects.len());
	for object in objects {
		if object.payload.has_main_content() {
			let item = ItemBuilder::default()
				.title(object.type_title())
				.link(format!(
					"{}/actor/{}/object/{}",
					&g.server_info.url_base, &object.actor_address, &object.hash
				))
				.description(object.payload.to_text())
				.build();
			items.push(item);
		}
	}
	channel_builder.items(items);
	let channel = channel_builder.build();

	#[cfg(debug_assertions)]
	channel.validate().expect("RSS feed validation error");

	Response::builder()
		.header("Content-Type", "application/rss+xml")
		.body(Body::from(channel.to_string()))
		.unwrap()
}

#[derive(Deserialize)]
struct SearchQuery {
	query: String,
}

async fn search(Query(query): Query<SearchQuery>) -> Response {
	if let Some(first_char) = query.query.chars().next() {
		if first_char == '@' {
			return Response::builder()
				.status(303)
				.header("Location", format!("/activity-pub/actor/{}", query.query))
				.body(Body::empty())
				.unwrap();
		}
	}

	match Address::from_str(&query.query) {
		Err(e) => server_error_response(e, "Invalid address"),
		Ok(address) => Response::builder()
			.status(303)
			.header("Location", format!("/actor/{}", address))
			.body(Body::empty())
			.unwrap(),
	}
}

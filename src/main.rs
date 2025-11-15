#![windows_subsystem = "windows"]

#[macro_use]
extern crate arrayref;

mod api;
mod common;
mod compression;
mod config;
mod core;
mod db;
mod entity;
mod identity;
mod limited_store;
mod migration;
mod net;
mod serde_limit;
#[cfg(test)]
mod test;
mod trace;
mod util;
mod web;

#[cfg(target_family = "windows")]
use std::fs;
use std::{
	env, fmt,
	fs::File,
	io::{self, prelude::*},
	net::SocketAddr,
	path::{Path, PathBuf},
	process,
	str::FromStr,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
	time::Duration,
};

use api::Api;
use config::Config;
use db::Database;
use log::*;
use net::{overlay::OverlayNode, resolve_bootstrap_addresses, Openness};
use semver::Version;
use signal_hook::flag;
use tokio::{spawn, time::sleep};

use crate::{config::CONFIG, core::Address, db::PersistenceHandle, migration::Migrations};

/// Gets the latest version, and whether it is required or not
#[allow(dead_code)]
async fn check_version() -> Option<(String, bool)> {
	info!("Checking version...");

	let url = "https://get.stonenet.org/version.txt";
	let response = match reqwest::get(url).await {
		Ok(r) => r,
		Err(e) => {
			error!("Unable to complete get request for version file: {}", e);
			return None;
		}
	};

	let versions_str = match response.text().await {
		Ok(r) => r,
		Err(e) => {
			error!("Unable to download latest version file: {}", e);
			return None;
		}
	};
	let (latest_version_str, min_required_version_str) = parse_versions(&versions_str);
	let latest_version = match Version::parse(&latest_version_str) {
		Ok(v) => v,
		Err(e) => {
			error!("Unable to parse latest version string: {}", e);
			return None;
		}
	};

	let current_version_str = env!("CARGO_PKG_VERSION");
	let current_version = match Version::parse(&current_version_str) {
		Ok(v) => v,
		Err(e) => {
			error!("Unable to parse minimum required version string: {}", e);
			return None;
		}
	};

	if let Some(string) = min_required_version_str {
		let required_version = match Version::parse(string) {
			Ok(v) => v,
			Err(e) => {
				error!("Unable to parse latest version string: {}", e);
				return None;
			}
		};

		if required_version > current_version {
			warn!("Stonenet is out of date!");
			return Some((latest_version_str.to_owned(), true));
		}
	}
	error!(
		"HOI {:?} {:?} {}",
		&latest_version,
		&current_version,
		latest_version > current_version
	);
	if latest_version > current_version {
		info!("New version available!");
		return Some((latest_version_str.to_owned(), false));
	}
	None
}

#[cfg(not(target_family = "windows"))]
fn config_path(_install_dir: PathBuf) -> PathBuf {
	let user_path = PathBuf::from_str(config::CONFIG_FILE_USER_PATH).unwrap();
	if user_path.exists() {
		return user_path;
	}
	PathBuf::from_str(config::CONFIG_FILE_PATH).unwrap()
}

#[cfg(target_family = "windows")]
fn config_path(install_dir: PathBuf) -> PathBuf {
	let mut path = install_dir;
	path.push("config.toml");
	path
}

fn initialize_logging() {
	#[cfg(target_family = "windows")]
	let result = env::var_os("APPDATA").map(|os| {
		let mut p = PathBuf::from(os);
		p.push("Stonenet");
		let _ = fs::create_dir(&p);
		p.push("stonenet.log");
		p
	});
	#[cfg(not(target_family = "windows"))]
	let result = env::var_os("SYSTEM_LOG_FILE").map(|os| PathBuf::from(os));

	if let Some(filename) = result {
		simple_logging::log_to_file(filename, LevelFilter::Debug)
			.expect("unable to unitialize logger")
	} else {
		env_logger::init()
	}
}

fn load_config<P>(path: P) -> Option<Config>
where
	P: AsRef<Path> + fmt::Debug,
{
	let mut file = match File::open(&path) {
		Err(e) => match e.kind() {
			io::ErrorKind::NotFound => {
				error!("Config file {:?} not found!", path);
				return None;
			}
			_ => {
				error!("Unable to open config file {:?}: {}", path, e);
				return None;
			}
		},
		Ok(f) => f,
	};

	let mut content = String::new();
	match file.read_to_string(&mut content) {
		Err(e) => {
			error!("Unable to read config file {:?}: {}", path, e);
			return None;
		}
		Ok(_) => {}
	}

	match toml::from_str(&content) {
		Err(e) => {
			error!("Unable to parse config file {:?}: {}", path, e);
			None
		}
		Ok(c) => Some(c),
	}
}

#[cfg(not(target_family = "windows"))]
async fn load_database(config: &Config, _install_dir: PathBuf) -> io::Result<Database> {
	// If the path doesn' exist yet, create it
	let db_path = PathBuf::from_str(&config.database_path)
		.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
	tokio::fs::create_dir_all(
		db_path
			.parent()
			.expect("database path doesn't have a folder"),
	)
	.await?;

	let db = Database::load(db_path)
		.await
		.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
	Ok(db)
}

#[cfg(target_family = "windows")]
async fn load_database(_config: &Config, install_dir: PathBuf) -> io::Result<Database> {
	let mut db_path = PathBuf::from(env::var_os("APPDATA").expect("Unable to read %APPDATA%."));
	db_path.push("Stonenet");
	let _ = fs::create_dir(&db_path);
	db_path.push("db.sqlite");
	let db = Database::load(db_path)
		.await
		.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
	Ok(db)
}

#[cfg(not(target_family = "windows"))]
fn load_install_dir() -> io::Result<PathBuf> {
	Ok(PathBuf::new())
}

#[cfg(target_family = "windows")]
fn load_install_dir() -> io::Result<PathBuf> {
	let mut install_dir = env::current_exe().unwrap();
	install_dir.pop();

	env::set_current_dir(&install_dir).unwrap();

	Ok(install_dir)
}

async fn load_trusted_node_config(db: &Database, config: &Config) -> db::Result<()> {
	// I know this code bad but its temporary anyway
	let trusted_node_list = config.trusted_nodes.clone().unwrap_or(Vec::new());
	let mut trusted_node_ids = Vec::with_capacity(trusted_node_list.len());
	for string in trusted_node_list {
		match Address::from_str(&string) {
			Err(e) => error!(
				"A node address in the `trusted_nodes` list is invalid: {}",
				e
			),
			Ok(address) => match address {
				Address::Node(node_address) => {
					let id = db.ensure_trusted_node(&node_address, 255).await?;
					trusted_node_ids.push(id);
				}
				_ => {
					error!("An address in the `trusted_nodes` list is not actually a node address.")
				}
			},
		}
	}

	db.clear_trusted_nodes_except(trusted_node_ids).await
}

fn parse_versions(string: &str) -> (&str, Option<&str>) {
	if let Some(i) = string.find('\n') {
		let latest_version = &string[..i];
		let required_version = if let Some(j) = string[(i + 1)..].find('\n') {
			&string[(i + 1)..(i + 1 + j)]
		} else {
			&string[(i + 1)..]
		};
		(latest_version, Some(required_version))
	} else {
		(string, None)
	}
}

#[cfg(package_manager = "apt")]
#[allow(dead_code)]
fn version_message(_version_str: &str) -> String {
	"Update stonenet with: <code>apt update && update upgrade</code>".to_owned()
}

#[cfg(package_manager = "homebrew")]
#[allow(dead_code)]
fn version_message(_version_str: &str) -> String {
	"Update stonenet with: <code>brew update</code>".to_owned()
}

#[cfg(package_manager = "windows-installer")]
#[allow(dead_code)]
fn version_message(version_str: &str) -> String {
	format!(
		"<a target=\"_blank\" href=\"https://get.stonenet.org/windows/stonenet-installer-{}.exe\">download the update \
		 here</a>",
		version_str
	)
}

#[cfg(not(package_manager))]
#[allow(dead_code)]
fn version_message(_version_str: &str) -> String {
	"use your package manager to update the stonenet client".to_owned()
}

#[tokio::main]
async fn main() {
	initialize_logging();

	let install_dir = match load_install_dir() {
		Ok(p) => p,
		Err(e) => {
			error!("Unable to load install directory: {}", e);
			return;
		}
	};

	// Load config
	let config_path = config_path(install_dir.clone());
	if let Some(config) = load_config(&config_path) {
		if let Err(_) = CONFIG.set(config.clone()) {
			panic!("Unable to set config global.")
		}

		// Catch signals
		let stop_flag = Arc::new(AtomicBool::new(false));
		flag::register(signal_hook::consts::SIGINT, stop_flag.clone()).unwrap();
		flag::register(signal_hook::consts::SIGTERM, stop_flag.clone()).unwrap();
		let stop_flag2 = stop_flag.clone();
		ctrlc::set_handler(move || {
			stop_flag2.store(true, Ordering::Relaxed);
		})
		.expect("Error setting Ctrl-C handler");

		// Load database
		let db = match load_database(&config, install_dir).await {
			Ok(db) => db,
			Err(e) => {
				error!("Unable to load database: {}", e);
				return;
			}
		};

		// Run migrations (does nothing if there is nothing to migrate)
		{
			let migrations = Migrations::load();
			migrations.run(&db).await.expect("migration issue");
		}

		// Load configured trusted nodes into database
		if let Err(e) = load_trusted_node_config(&db, &config).await {
			error!("Unable to load trusted node list: {}", e);
			return;
		}

		// Load node
		let node = if let Some(n) = load_node(stop_flag.clone(), db.clone(), &config).await {
			n
		} else {
			info!("Node not loaded, exiting...");
			return;
		};
		info!(
			"Loaded node with address {}",
			Address::Node(node.node_id().clone())
		);

		// Test openness
		let api = Api { node, db };
		let new_bootstrap_nodes = test_bootstrap_nodes(&api, &config).await;
		test_openness(&api, &config, !new_bootstrap_nodes).await;

		// Check for updates (only in release mode)
		#[cfg(not(debug_assertions))]
		let update_message = {
			let new_version_opt = check_version().await;
			if let Some((new_version, required)) = new_version_opt {
				Some((version_message(&new_version), required))
			} else {
				None
			}
		};
		#[cfg(debug_assertions)]
		let update_message = None;

		// Spawn web servers
		if config.load_web_interface.unwrap_or(false) {
			let server_info = web::server::ServerInfo {
				is_exposed: true,
				federation_domain: config
					.federation_domain
					.clone()
					.unwrap_or("localhost".to_string()),
				url_base: config.web_url_base.clone().unwrap_or(String::new()),
				update_message: None,
			};
			let stop_flag2 = stop_flag.clone();
			let api2 = api.clone();
			let config2 = config.clone();
			spawn(async move {
				web::server::serve(
					stop_flag2,
					config.web_interface_port.unwrap_or(80),
					None,
					api2,
					server_info,
					config2,
				)
				.await
				.unwrap();
			});
		}
		if config.load_user_interface.unwrap_or(false) {
			let port = config.user_interface_port.unwrap_or(37338);
			let server_info = web::server::ServerInfo {
				is_exposed: false,
				federation_domain: config
					.federation_domain
					.clone()
					.unwrap_or("localhost".to_string()),
				url_base: config
					.web_url_base
					.clone()
					.unwrap_or(format!("http://localhost:{}", port)),
				update_message,
			};
			let stop_flag2 = stop_flag.clone();
			let api2 = api.clone();
			let config2 = config.clone();
			spawn(async move {
				web::server::serve(stop_flag2, port, None, api2, server_info, config2)
					.await
					.unwrap();
			});
		}

		// Run the main loop, until it exits because of a signal
		node_main(stop_flag, &api, &config).await;

		// Shutdown rocket servers
		info!("Exiting stonenetd...");

		api.close().await;
		info!("Done.");
	}
}

async fn load_node(
	stop_flag: Arc<AtomicBool>, db: Database, config: &Config,
) -> Option<Arc<OverlayNode>> {
	let (address, private_key) = match db.load_node_identity().await {
		Ok(r) => r,
		Err(e) => {
			error!("Unable to load node identity from database: {}", e);
			return None;
		}
	};

	match net::overlay::OverlayNode::start(stop_flag, config, address, private_key, db).await {
		Err(e) => {
			error!("Unable to bind socket: {}", e);
			process::exit(1)
		}
		Ok(s) => Some(s),
	}
}

async fn node_main(stop_flag: Arc<AtomicBool>, g: &Api, config: &Config) {
	info!("Network node started.");

	// Join the network
	if config.bootstrap_nodes.len() > 0 {
		let flag2 = stop_flag.clone();
		let node = g.node.clone();
		tokio::spawn(async move {
			if !node.join_network(flag2).await {
				error!("Attempt at joining the network failed.");
			} else {
				info!("Joined network.");
			}
		});
	}

	while !stop_flag.load(Ordering::Relaxed) {
		sleep(Duration::from_secs(1)).await;
	}
}

/// Populates our bootstrap_id table with the node ID's of our bootstrap nodes
async fn test_bootstrap_nodes(g: &Api, config: &Config) -> bool {
	let bootstrap_nodes = resolve_bootstrap_addresses(&config.bootstrap_nodes, true, true);

	let mut updated = 0;
	for bootstrap_node in &bootstrap_nodes {
		if let Some(bootstrap_id) = g.node.obtain_id(&bootstrap_node).await {
			g.db.ensure_bootstrap_node_id(bootstrap_node, &bootstrap_id)
				.await
				.unwrap();
			// FIXME: Properly handle database error
			updated += 1;
		}
	}
	updated > 0
}

async fn test_openness(g: &Api, config: &Config, should_test: bool) {
	// TODO: Clean up this code:
	if config.ipv4_address.is_some() {
		let mut bootstrap_nodes: Option<Vec<SocketAddr>> = None;

		// Use the openness as found in the config file, or, if not set, test it
		let udp4_openness = if let Some(string) = &config.ipv4_udp_openness {
			if let Ok(o) = Openness::from_str(string) {
				info!("Using UDPv4 openness: {}", o);
				Some(o)
			} else {
				info!("Using UDPv4 openness: unidirectional");
				Some(Openness::Unidirectional)
			}
		} else if should_test {
			info!("Testing UDPv4 openness...");
			bootstrap_nodes = Some(resolve_bootstrap_addresses(
				&config.bootstrap_nodes,
				true,
				false,
			));
			if bootstrap_nodes.as_ref().unwrap().len() < 2 {
				warn!("Not enough bootstrap nodes available");
				None
			} else if let Some(nodes) = &bootstrap_nodes {
				if let Some(o) = g.node.test_openness_udpv4(&nodes).await {
					info!("Tested UDPv4 openness to be: {}", o);
					Some(o)
				} else {
					warn!("No UDPv4 connectivity detected.");
					None
				}
			} else {
				None
			}
		} else {
			None
		};

		if let Some(openness) = udp4_openness {
			let mut ci = g.node.contact_info();
			if let Some(entry) = &mut ci.ipv4 {
				if let Some(entry) = &mut entry.availability.udp {
					entry.openness = openness;
				}
			}
			g.node.set_contact_info(ci);
		}

		let tcpv4_openness = if let Some(string) = &config.ipv4_tcp_openness {
			if let Ok(o) = Openness::from_str(string) {
				info!("Using TCPv4 openness: {}", o);
				Some(o)
			} else {
				info!("Using TCPv4 openness: unidirectional");
				Some(Openness::Unidirectional)
			}
		} else if should_test {
			info!("Testing TCPv4 openness...");
			if bootstrap_nodes.is_none() {
				bootstrap_nodes = Some(resolve_bootstrap_addresses(
					&config.bootstrap_nodes,
					true,
					false,
				));
			}
			if bootstrap_nodes.as_ref().unwrap().len() < 2 {
				warn!("Not enough bootstrap nodes available");
				None
			} else if let Some(nodes) = &bootstrap_nodes {
				if let Some(o) = g.node.test_openness_tcpv4(&nodes).await {
					info!("Tested TCPv4 openness to be: {}", o);
					Some(o)
				} else {
					warn!("No TCPv4 connectivity detected.");
					None
				}
			} else {
				None
			}
		} else {
			None
		};

		if let Some(openness) = tcpv4_openness {
			let mut ci = g.node.contact_info();
			if let Some(entry) = &mut ci.ipv4 {
				if let Some(entry) = &mut entry.availability.tcp {
					entry.openness = openness;
				}
			}
			g.node.set_contact_info(ci);
		}
	}

	if config.ipv6_address.is_some() {
		let mut bootstrap_nodes: Option<Vec<SocketAddr>> = None;

		// Use the openness as found in the config file, or, if not set, test it
		let udp6_openness = if let Some(string) = &config.ipv6_udp_openness {
			if let Ok(o) = Openness::from_str(string) {
				info!("Using UDPv6 openness: {}", o);
				Some(o)
			} else {
				info!("Using UDPv6 openness: unidirectional");
				Some(Openness::Unidirectional)
			}
		} else if should_test {
			info!("Testing UDPv6 openness...");
			bootstrap_nodes = Some(resolve_bootstrap_addresses(
				&config.bootstrap_nodes,
				false,
				true,
			));
			if bootstrap_nodes.as_ref().unwrap().len() < 2 {
				warn!("Not enough bootstrap nodes available");
				None
			} else if let Some(nodes) = &bootstrap_nodes {
				if let Some(o) = g.node.test_openness_udpv6(&nodes).await {
					info!("Tested UDPv6 openness to be: {}", o);
					Some(o)
				} else {
					warn!("No UDPv6 connectivity detected.");
					None
				}
			} else {
				None
			}
		} else {
			None
		};

		if let Some(openness) = udp6_openness {
			let mut ci = g.node.contact_info();
			if let Some(entry) = &mut ci.ipv6 {
				if let Some(entry) = &mut entry.availability.udp {
					entry.openness = openness;
				}
			}
			g.node.set_contact_info(ci);
		}

		let tcpv6_openness = if let Some(string) = &config.ipv6_tcp_openness {
			if let Ok(o) = Openness::from_str(string) {
				info!("Using TCPv6 openness: {}", o);
				Some(o)
			} else {
				info!("Using TCPv6 openness: unidirectional");
				Some(Openness::Unidirectional)
			}
		} else if should_test {
			info!("Testing TCPv6 openness...");
			if bootstrap_nodes.is_none() {
				bootstrap_nodes = Some(resolve_bootstrap_addresses(
					&config.bootstrap_nodes,
					false,
					true,
				));
			}
			if bootstrap_nodes.as_ref().unwrap().len() < 2 {
				warn!("Not enough bootstrap nodes available");
				None
			} else if let Some(nodes) = &bootstrap_nodes {
				if let Some(o) = g.node.test_openness_tcpv6(&nodes).await {
					info!("Tested TCPv6 openness to be: {}", o);
					Some(o)
				} else {
					warn!("No TCPv6 connectivity detected.");
					None
				}
			} else {
				None
			}
		} else {
			None
		};

		if let Some(openness) = tcpv6_openness {
			let mut ci = g.node.contact_info();
			if let Some(entry) = &mut ci.ipv6 {
				if let Some(entry) = &mut entry.availability.tcp {
					entry.openness = openness;
				}
			}
			g.node.set_contact_info(ci);
		}
	}
}

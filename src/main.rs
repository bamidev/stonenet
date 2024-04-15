#![windows_subsystem = "windows"]

#[macro_use]
extern crate arrayref;

mod api;
mod common;
mod config;
mod core;
mod db;
mod entity;
mod identity;
mod limited_store;
mod migration;
mod net;
#[cfg(test)]
mod test;
mod trace;
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
use config::{Config, *};
use ctrlc;
use db::Database;
use env_logger;
use log::*;
use net::{overlay::OverlayNode, *};
use semver::Version;
use signal_hook::flag;
use simple_logging;
use tokio::{self};
use toml;

use crate::migration::Migrations;


#[allow(dead_code)]
async fn check_version() -> Option<String> {
	info!("Checking version...");

	let url = "https://get.stonenet.org/windows/latest-version.txt";
	let response = match reqwest::get(url).await {
		Ok(r) => r,
		Err(e) => {
			error!("Unable to complete get request for version file: {}", e);
			return None;
		}
	};

	let latest_version_str = match response.text().await {
		Ok(r) => r,
		Err(e) => {
			error!("Unable to download latest version file: {}", e);
			return None;
		}
	};
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
			error!("Unable to parse latest version string: {}", e);
			return None;
		}
	};

	if latest_version > current_version {
		info!("New version available!");
		Some(latest_version_str.to_owned())
	} else {
		None
	}
}

#[cfg(not(target_family = "windows"))]
fn config_path(_install_dir: PathBuf) -> PathBuf {
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
async fn load_database(
	config: &Config, _install_dir: PathBuf,
) -> io::Result<(Database, sea_orm::DatabaseConnection)> {
	let old_db = Database::load(
		PathBuf::from_str(&config.database_path)
			.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
	)
	.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

	let new_db = sea_orm::Database::connect(format!("sqlite://{}?mode=rwc", &config.database_path))
		.await
		.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

	Ok((old_db, new_db))
}

#[cfg(target_family = "windows")]
async fn load_database(
	_config: &Config, install_dir: PathBuf,
) -> io::Result<(Database, sea_orm::DatabaseConnection)> {
	let mut db_path = PathBuf::from(env::var_os("APPDATA").expect("Unable to read %APPDATA%."));
	db_path.push("Stonenet");
	let _ = fs::create_dir(&db_path);
	db_path.push("db.sqlite");
	let old_db = Database::load(db_path).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

	let new_db = sea_orm::Database::connect(format!("sqlite://{}?mode=rwc", &db_path))
		.await
		.map_err(|e| io::Error::new(io::ErrorKind::Other, e));
	(old_db, new_db)
}

#[cfg(not(target_family = "windows"))]
fn load_install_dir() -> io::Result<PathBuf> { Ok(PathBuf::new()) }

#[cfg(target_family = "windows")]
fn load_install_dir() -> io::Result<PathBuf> {
	let mut install_dir = env::current_exe().unwrap();
	install_dir.pop();

	env::set_current_dir(&install_dir).unwrap();

	Ok(install_dir)
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
		let (db, orm) = match load_database(&config, install_dir).await {
			Ok(dbs) => dbs,
			Err(e) => {
				error!("Unable to load database: {}", e);
				return;
			}
		};

		// Run migrations (does nothing if there is nothing to migrate)
		{
			let migrations = Migrations::load();
			migrations.run(&orm).await.expect("migration issue");
		}

		// Load node
		let node = load_node(stop_flag.clone(), db.clone(), &config).await;

		// Test openness
		let api = Api { node, db, orm };
		let new_bootstrap_nodes = test_bootstrap_nodes(&api, &config).await;
		test_openness(&api, &config, !new_bootstrap_nodes).await;

		// Check for updates (only in release mode)
		#[cfg(not(debug_assertions))]
		let update_message = {
			let new_version_opt = check_version().await;
			if let Some(new_version) = new_version_opt {
				Some(version_message(&new_version))
			} else {
				None
			}
		};
		#[cfg(debug_assertions)]
		let update_message = None;

		// Spawn web servers
		if config.load_web_interface.unwrap_or(false) {
			let server_info = web::ServerInfo {
				is_exposed: true,
				update_message: None,
			};
			web::spawn(
				stop_flag.clone(),
				config.web_interface_port.unwrap_or(80),
				None,
				api.clone(),
				server_info,
			)
			.await
			.unwrap();
		}
		if config.load_user_interface.unwrap_or(false) {
			let server_info = web::ServerInfo {
				is_exposed: false,
				update_message,
			};
			web::spawn(
				stop_flag.clone(),
				config.user_interface_port.unwrap_or(37338),
				None,
				api.clone(),
				server_info,
			)
			.await
			.unwrap();
		}

		// Run the main loop, until it exits because of a signal
		node_main(stop_flag, &api, &config).await;

		// Shutdown rocket servers
		info!("Exiting stonenetd...");

		api.close().await;
		info!("Done.");
	}
}

async fn load_node(stop_flag: Arc<AtomicBool>, db: Database, config: &Config) -> Arc<OverlayNode> {
	let mut c = db.connect_old().expect("Unable to connect to database.");
	let (node_id, keypair) = c
		.fetch_node_identity()
		.expect("Unable to load node identity");
	match net::overlay::OverlayNode::start(stop_flag, config, node_id, keypair, db).await {
		Err(e) => {
			error!("Unable to bind socket: {}", e);
			process::exit(1)
		}
		Ok(s) => s,
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
		tokio::time::sleep(Duration::from_secs(1)).await;
	}
}

/// Populates our bootstrap_id table with the node ID's of our bootstrap nodes
async fn test_bootstrap_nodes(g: &Api, config: &Config) -> bool {
	let bootstrap_nodes = resolve_bootstrap_addresses(&config.bootstrap_nodes, true, true);

	let mut updated = 0;
	for bootstrap_node in &bootstrap_nodes {
		if let Some(bootstrap_id) = g.node.obtain_id(&bootstrap_node).await {
			g.db.perform(|mut c| {
				if c.remember_bootstrap_node_id(&bootstrap_node, &bootstrap_id)? {
					updated += 1;
				}
				Ok(())
			})
			.expect("database error");
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

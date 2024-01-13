#![feature(ip)]

#[macro_use]
extern crate arrayref;

mod api;
mod common;
mod config;
mod db;
mod identity;
mod limited_store;
mod model;
mod net;
#[cfg(test)]
mod test;
mod web;

use std::{
	fs::File,
	io::{self, prelude::*},
	net::{SocketAddr, ToSocketAddrs},
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
use signal_hook::flag;
use tokio;
use toml;


fn initialize_network_interfaces() {
	let mut map = net::NETWORK_INTERFACES.lock().unwrap();
	for interface in pnet::datalink::interfaces() {
		map.insert(interface.name, interface.ips);
	}
}

fn load_config() -> Option<Config> {
	let mut file = match File::open(config::CONFIG_FILE_PATH) {
		Err(e) => match e.kind() {
			io::ErrorKind::NotFound => {
				eprintln!("Config file {} not found!", config::CONFIG_FILE_PATH);
				return None;
			}
			_ => {
				eprintln!(
					"Unable to open config file {}: {}",
					config::CONFIG_FILE_PATH,
					e
				);
				return None;
			}
		},
		Ok(f) => f,
	};

	let mut content = String::new();
	match file.read_to_string(&mut content) {
		Err(e) => {
			error!("Unable to read config file {}: {}", CONFIG_FILE_PATH, e);
			return None;
		}
		Ok(_) => {}
	}

	match toml::from_str(&content) {
		Err(e) => {
			error!("Unable to parse config file {}: {}", CONFIG_FILE_PATH, e);
			None
		}
		Ok(c) => Some(c),
	}
}

#[tokio::main]
async fn main() {
	env_logger::init();

	initialize_network_interfaces();

	// Load config
	if let Some(config) = load_config() {
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
		let db = match Database::load(config.database_path.clone().into()) {
			Err(e) => {
				error!("Unable to load database: {}", e);
				return;
			}
			Ok(d) => d,
		};

		// Load node
		let node = load_node(stop_flag.clone(), db.clone(), &config).await;

		// Test openness
		let globals = Api { node, db };
		test_openness(&globals, &config).await;

		// Spawn threads
		if config.load_web_interface {
			let g2 = globals.clone();
			let (shutdown, join) = web::spawn(g2).await;
			node_main(stop_flag, &globals, &config).await;
			shutdown.notify();

			info!("Exiting stonenetd...");
			//globals.node.remember_nodes().await;
			match join.await {
				Ok(()) => {}
				Err(e) => error!("Rocket error after shutdown: {}", e),
			}
		} else {
			node_main(stop_flag, &globals, &config).await;
		}
		info!("Finished.");
	}
}

async fn load_node(stop_flag: Arc<AtomicBool>, db: Database, config: &Config) -> Arc<OverlayNode> {
	let mut c = db.connect().expect("Unable to connect to database.");
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

async fn test_openness(g: &Api, config: &Config) {
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
		} else {
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
		} else {
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
		} else {
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
		} else {
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

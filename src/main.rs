mod common;
mod config;
mod db;
mod global;
mod identity;
mod limited_store;
mod model;
mod net;
mod ui;


use std::{
	fs::File,
	io::prelude::*,
	process,
	sync::{Arc, atomic::AtomicBool}
};

use db::Database;
use common::*;
use config::Config;
use net::overlay::OverlayNode;

use env_logger;
use global::Global;
use log::*;
use signal_hook::flag;
use tokio;
use toml;


const CONFIG_FILE_PATH: &'static str = "/etc/stonenet.conf";


fn load_config() -> Option<Config> {
	let mut file = match File::open(CONFIG_FILE_PATH) {
		Err(e) => {
			error!("Unable to open config file {}: {}", CONFIG_FILE_PATH, e);
			return None;
		},
		Ok(f) => f
	};

	let mut content = String::new();
	match file.read_to_string(&mut content) {
		Err(e) => {
			error!("Unable to read config file {}: {}", CONFIG_FILE_PATH, e);
			return None;
		},
		Ok(_) => {}
	}

	match toml::from_str(&content) {
		Err(e) => {
			error!("Unable to parse config file {}: {}", CONFIG_FILE_PATH, e);
			None
		},
		Ok(v) => Some(v)
	}
}

#[tokio::main]
async fn main() {
	env_logger::init();
	
	let stop_flag = Arc::new(AtomicBool::new(false));
	flag::register(signal_hook::consts::SIGINT, stop_flag.clone()).unwrap();
	flag::register(signal_hook::consts::SIGTERM, stop_flag.clone()).unwrap();

	// Load config
	let config = match load_config() {
		None => return,
		Some(c) => c
	};

	// Load database
	let db = match Database::load() {
		Err(e) => {
			error!("Unable to load database: {}", e);
			return;
		},
		Ok(c) => Arc::new(c)
	};

	// Load node
	let node = Arc::new(load_node(db.clone(), &config).await);

	// Spawn threads
	let globals = Global { node, db };
	if config.load_web_interface {
		let g2 = globals.clone();
		let ui = tokio::spawn(async {
			ui::main(g2).await;
		});
		node_main(stop_flag, &globals, &config).await;

		info!("Exiting stonenetd...");
		ui.await.expect("Unable to join UI task.");
	}
	else {
		node_main(stop_flag, &globals, &config).await;
	}
	info!("Finished.");
}

async fn load_node(db: Arc<Database>, config: &Config) -> OverlayNode {
	let node_id = IdType::random();
	match net::overlay::OverlayNode::bind(node_id, &config.address, db, config).await {
		Err(e) => {
			error!("Unable to bind to address {}: {}", config.address, e);
			process::exit(1)
		},
		Ok(s) => s
	}
}

async fn node_main(stop_flag: Arc<AtomicBool>, g: &Global, config: &Config) {
	info!("Network node started.");

	// Join the network
	if config.bootstrap_nodes.len() > 0 {
		let flag2 = stop_flag.clone();
		let node = g.node.clone();
		tokio::spawn(async move {
			if !node.join_network(flag2).await {
				error!("Attempt at joining the network failed.");
			}
			else {
				info!("Joined network.");

				// Publish own identities
				node.store_my_identities().await;
			}
		});
	}

	// Process messages
	g.node.clone().serve(stop_flag).await;
	info!("Network node exitted.");
}

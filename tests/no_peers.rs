mod common;


use std::{
	net::{SocketAddr},
	sync::{
		atomic::AtomicBool,
		Arc
	}
};

use stonenet::{
	config::Config,
	db::Database
};

use log::*;
use tokio::{
	self,
	runtime
};


#[test]
fn main() {
	let config = Config {
		address: "0.0.0.0:37337".into(),
		bootstrap_nodes: vec!["0.0.0.0:10000".into()],
		load_web_interface: false,
		udp_max_idle_time: 60,
		bucket_size: 4
	};

	// Load database
	let db = match Database::load() {
		Err(e) => {
			error!("Unable to load database: {}", e);
			return;
		},
		Ok(c) => Arc::new(c)
	};

	let stop_flag = Arc::new(AtomicBool::new(false));
	let rt  = runtime::Builder::new_multi_thread()
		.enable_io()
		.enable_time()
		.build().unwrap();
	rt.block_on(async {
		let node_addr: SocketAddr = "0.0.0.0:10001".parse().unwrap();
		let node = common::launch_node(
			stop_flag.clone(),
			node_addr,
			db.clone(),
			&config
		).await;
		assert!(
			!node.join_network(stop_flag.clone()).await,
			"able to join a non-existent network"
		);
	});
}
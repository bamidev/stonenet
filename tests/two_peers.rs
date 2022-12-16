mod common;


use std::{
	net::{SocketAddr},
	process,
	sync::{
		atomic::AtomicBool,
		Arc
	}
};

use stonenet::{
	common::*,
	config::Config,
	db::Database,
	identity::MyIdentity,
	net::{
		overlay::OverlayNode
	}
};

use env_logger;
use log::*;
use tokio::{
	self,
	runtime
};


#[test]
fn two_peers() {
	env_logger::init();
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
		let keypair = MyIdentity::generate();
		let public_key = keypair.public();
		let test_address = public_key.generate_address();

		let master_addr: SocketAddr = "0.0.0.0:10000".parse().unwrap();
		let master = common::launch_node(
			stop_flag.clone(),
			master_addr,
			db.clone(),
			&config
		).await;

		let slave = common::launch_node(
			stop_flag.clone(),
			"0.0.0.0:10001".to_string(),
			db.clone(),
			&config
		).await;
		assert!(
			slave.join_network(stop_flag.clone()).await,
			"slave unable to join network"
		);

		slave.store_actor(
			&test_address,
			4,
			&public_key,
			true,
			Vec::new()
		).await;

		let _actor = master.find_actor(&test_address, 2, false).await.expect("actor not found");
	});
}
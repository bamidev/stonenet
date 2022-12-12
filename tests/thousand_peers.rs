mod common;


use std::{
	mem::MaybeUninit,
	net::{SocketAddr},
	sync::{
		atomic::AtomicBool,
		Arc
	}
};

use stonenet::{
	config::Config,
	db::Database,
	identity::*,
	net::overlay::OverlayNode
};

use env_logger;
use log::*;
use tokio::{
	self,
	runtime
};


#[test]
fn main() {
	env_logger::init();
	let config = Config {
		address: "0.0.0.0:37337".into(),
		bootstrap_nodes: vec!["0.0.0.0:9999".into()],
		load_web_interface: false,
		udp_max_idle_time: 60
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
		let master_addr: SocketAddr = "0.0.0.0:9999".parse().unwrap();
		let master = common::launch_node(
			stop_flag.clone(),
			master_addr,
			db.clone(),
			&config
		).await;

		let keypair = MyIdentity::generate();
		let public_key = keypair.public();
		let address = public_key.generate_address();

		// TODO: Set to some kind of default value initially.
		let mut first_peer: Arc<OverlayNode> = common::launch_node(
			stop_flag.clone(),
			"0.0.0.0:".to_string() + &(20000u16 + 3456).to_string(),
			db.clone(),
			&config
		).await;
		for i in 0..1000 {
			let peer = common::launch_node(
				stop_flag.clone(),
				"0.0.0.0:".to_string() + &(10000u16 + i).to_string(),
				db.clone(),
				&config
			).await;
			assert!(
				peer.join_network(stop_flag.clone()).await,
				"peer {} unable to join network", i
			);

			if i == 0 {
				first_peer = peer.clone();
			}
			else if i == 999 {
				if !peer.store_actor(&address, &public_key, Vec::new()).await {
					info!("public key got stored by own node");
				}
			}
		}
		// Not working yet:
		//let actor_info = first_peer.find_actor(&address).await
		//	.expect("stored actor not found");
	});
}
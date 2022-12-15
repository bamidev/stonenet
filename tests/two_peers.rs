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
	net::{
		overlay::OverlayNode
	}
};

use env_logger;
use log::*;
use tokio::{
	self,
	net::ToSocketAddrs,
	runtime
};


async fn launch_node<A: ToSocketAddrs>(
	stop_flag: Arc<AtomicBool>,
	addr: A,
	db: Arc<Database>,
	config: &Config
) -> Arc<OverlayNode> {
	let node = match OverlayNode::bind(IdType::random(), addr, db, config).await {
		Err(e) => {
			error!("Unable to bind to port 8337: {}", e);
			process::exit(1)
		},
		Ok(s) => Arc::new(s)
	};
	let node2 = node.clone();
	tokio::task::spawn_local(async move { node2.serve(stop_flag.clone()).await });
	node
}


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
		let local = tokio::task::LocalSet::new();
		local.run_until(async {
			let master_addr: SocketAddr = "0.0.0.0:10000".parse().unwrap();
			let _master = launch_node(
				stop_flag.clone(),
				master_addr,
				db.clone(),
				&config
			).await;

			let slave = launch_node(
				stop_flag.clone(),
				"0.0.0.0:10001".to_string(),
				db.clone(),
				&config
			).await;
			assert!(
				slave.join_network(stop_flag.clone()).await,
				"slave unable to join network"
			);
			//let actor_id = IdType::default();
			//let actor_info = master.find_actor(&actor_id).await.expect("actor not found");
		}).await;
	});
}
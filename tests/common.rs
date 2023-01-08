use std::{
	net::{SocketAddr, ToSocketAddrs},
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


use log::*;
use tokio::{
	self,
};


pub async fn launch_node<A: ToSocketAddrs>(
	stop_flag: Arc<AtomicBool>,
	addr: A,
	db: Database,
	config: &Config
) -> Arc<OverlayNode> {
	let a: SocketAddr = addr.to_socket_addrs().unwrap().next().unwrap();
	let node = match OverlayNode::bind(IdType::random(), &a, db, config).await {
		Err(e) => {
			error!("Unable to bind to port 8337: {}", e);
			process::exit(1)
		},
		Ok(s) => Arc::new(s)
	};
	let node2 = node.clone();
	tokio::task::spawn(async move { node2.serve(stop_flag.clone()).await });
	node
}
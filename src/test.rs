use std::sync::{atomic::AtomicBool, Arc};

use log::*;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use tempfile::NamedTempFile;

use crate::{
	api::Api, config::Config, db::Database, identity::NodePrivateKey, net::overlay::OverlayNode,
};


pub fn initialize_rng() -> ChaCha8Rng {
	let seed = <ChaCha8Rng as SeedableRng>::Seed::default();
	ChaCha8Rng::from_seed(seed)
}

/// Sets up a node usable for testing.
pub async fn load_test_node(
	stop_flag: Arc<AtomicBool>, rng: &mut (impl CryptoRng + RngCore), config: &Config,
	filename: &str,
) -> Api {
	let temp_file = NamedTempFile::with_prefix(filename).unwrap();
	let old_db = Database::load(temp_file.path().to_owned()).expect("unable to load database");
	let orm = sea_orm::Database::connect("sqlite://{}?mode=rwc")
		.await
		.expect("unable to load ORM");
	// Leak it on purpose so that the temp file may live until the end of all tests
	// However, the OS will not clean it up after exit either...
	Box::into_raw(Box::new(temp_file));
	let private_key = NodePrivateKey::generate_with_rng(rng);
	let node_id = private_key.public().generate_address();
	info!(
		"Node {} runs on port {}.",
		node_id,
		config.ipv4_udp_port.expect("no port in config")
	);
	let node = OverlayNode::start(
		stop_flag.clone(),
		&config,
		node_id,
		private_key,
		old_db.clone(),
	)
	.await
	.expect("unable to start node");

	node.join_network(stop_flag).await;

	Api { node, old_db, orm }
}

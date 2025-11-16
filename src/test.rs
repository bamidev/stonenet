use std::sync::{atomic::AtomicBool, Arc};

use log::*;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use tempfile::NamedTempFile;

use crate::{
	api::Api, config::Config, db::Database, identity::NodePrivateKey, migration::Migrations,
	net::overlay::OverlayNode,
};

pub async fn empty_node<R>(db: Database, rng: &mut R) -> Arc<OverlayNode>
where
	R: RngCore + CryptoRng,
{
	let migrations = Migrations::load();
	migrations.run(&db).await.expect("migration issue");
	let private_key = NodePrivateKey::generate_with_rng(rng);
	let node_id = private_key.public().generate_address();
	OverlayNode::start(
		Arc::new(AtomicBool::new(true)),
		&Config::default(),
		node_id,
		private_key,
		db,
	)
	.await
	.unwrap()
}

pub fn initialize_rng() -> ChaCha8Rng {
	let mut seed = [0u8; 32];
	if let Ok(seed_data_string) = std::env::var("STONENET_TEST_RANDOM_SEED") {
		info!("Random seed based on data: {}", &seed_data_string);
		let seed_data = seed_data_string.as_bytes();
		for i in 0..seed_data.len() {
			seed[i % 32] = seed_data[i]
		}
	}
	ChaCha8Rng::from_seed(seed)
}

pub async fn load_database(filename: &str) -> Database {
	let temp_file = NamedTempFile::with_prefix(filename).unwrap();
	let db = Database::load(temp_file.path().to_owned())
		.await
		.expect("unable to load database");
	let migrations = Migrations::load();
	migrations.run(&db).await.expect("migration issue");
	debug!("Loaded database at {}", temp_file.path().display());
	// Leak it on purpose so that the temp file may live until the end of all tests
	// FIXME: However, the OS will not clean it up after exit either...
	Box::into_raw(Box::new(temp_file));
	db
}

/// Sets up a node usable for testing.
pub async fn load_test_node(
	stop_flag: Arc<AtomicBool>, rng: &mut (impl CryptoRng + RngCore), config: &Config,
	filename: &str,
) -> Api {
	let db = load_database(filename).await;

	let private_key = NodePrivateKey::generate_with_rng(rng);
	let node_id = private_key.public().generate_address();
	// If not UDP or TCP port is set, implicitly set it to something
	let mut config2 = config.clone();
	if config.ipv4_udp_port.is_none() && config.ipv4_tcp_port.is_none() {
		config2.ipv4_udp_port = Some(0);
	}
	info!(
		"Node {} runs on port {}.",
		node_id,
		config.ipv4_udp_port.expect("no port in config")
	);
	let node = OverlayNode::start(
		stop_flag.clone(),
		&config2,
		node_id,
		private_key,
		db.clone(),
	)
	.await
	.expect("unable to start node");

	node.join_network(stop_flag).await;

	Api { node, db }
}

use std::{
	fs::remove_file,
	io,
	net::Ipv4Addr,
	path::PathBuf,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
};

use log::*;
use rand::{CryptoRng, RngCore};
use stonenetd::{
	api::Api,
	config::Config,
	db::*,
	identity::PrivateKey,
	model::*,
	net::{overlay::*, ContactInfo, *},
	test::*,
};


async fn load_test_node(
	stop_flag: Arc<AtomicBool>, rng: &mut (impl CryptoRng + RngCore), config: &Config, port: u16,
	openness: Openness, filename: &str,
) -> Api {
	// FIXME: Generate proper random temporary file names.
	let file = PathBuf::from(filename);
	match remove_file(&file) {
		Ok(()) => {}
		Err(e) =>
			if e.kind() != io::ErrorKind::NotFound {
				panic!(
					"unable to remove database file {}: {}",
					file.to_string_lossy(),
					e
				);
			},
	}
	let db = Database::load(file).expect("unable to load database");
	let private_key = PrivateKey::generate_with_rng(rng);
	let node_id = private_key.public().generate_address();
	let contact_info = ContactInfo {
		ipv4: Some(Ipv4ContactInfo {
			addr: Ipv4Addr::new(127, 0, 0, 1),
			availability: IpAvailability {
				udp: Some(TransportAvailabilityEntry { port, openness }),
				tcp: None,
			},
		}),
		ipv6: None,
	};
	let node = OverlayNode::start(
		stop_flag.clone(),
		node_id,
		contact_info,
		private_key,
		db.clone(),
		&config,
	)
	.await
	.expect("unable to start node");

	node.join_network(stop_flag).await;

	Api { node, db }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_data_synchronization() {
	env_logger::init();
	let mut rng = initialize_rng();

	// Set up two nodes
	let stop_flag = Arc::new(AtomicBool::new(false));
	let config1 = Config::default();
	let mut config2 = Config::default();
	config2.bootstrap_nodes = vec!["127.0.0.1:37337".to_string()];
	let bootstrap_node = load_test_node(
		stop_flag.clone(),
		&mut rng,
		&config1,
		37337,
		Openness::Bidirectional,
		"/tmp/bootstrap.sqlite",
	)
	.await;
	let node1 = load_test_node(
		stop_flag.clone(),
		&mut rng,
		&config2,
		37338,
		Openness::Unidirectional,
		"/tmp/node1.sqlite",
	)
	.await;
	node1.node.join_network(stop_flag.clone()).await;
	let node2 = load_test_node(
		stop_flag.clone(),
		&mut rng,
		&config2,
		37339,
		Openness::Punchable,
		"/tmp/node2.sqlite",
	)
	.await;
	node2.node.join_network(stop_flag.clone()).await;

	// Create a profile for node 1
	let profile_description = r#"
Hoi ik ben Kees!
"#;
	let mut avatar_file_data = FileData {
		mime_type: "image/png".to_string(),
		data: vec![0u8; 1000],
	};
	rng.fill_bytes(&mut avatar_file_data.data);
	let mut wallpaper_file_data = FileData {
		mime_type: "image/jpeg".to_string(),
		data: vec![0u8; 10000000],
	};
	rng.fill_bytes(&mut wallpaper_file_data.data);
	let (actor_id, actor_info) = node1
		.create_my_identity(
			"kees",
			"Kees",
			Some(&avatar_file_data),
			Some(&wallpaper_file_data),
			profile_description,
		)
		.expect("unable to create identity");
	let _ = node1
		.node
		.join_actor_network(&actor_id, &actor_info)
		.await
		.expect("unable to join actor network");

	// Create some posts
	let first_message = "First post!!!";
	let second_message = "Second post!!!";
	let third_message = "Third post!!!";
	let (_, keypair) = node1
		.fetch_my_identity(&actor_id)
		.expect("unable to load identity")
		.expect("missing identity");
	let first_post_hash = node1
		.publish_post(
			&actor_id,
			&keypair,
			first_message,
			vec!["first".to_string()],
			&[],
			None,
		)
		.await
		.expect("unable to publish first post");
	let second_post_hash = node1
		.publish_post(
			&actor_id,
			&keypair,
			second_message,
			vec!["second".to_string()],
			&[],
			None,
		)
		.await
		.expect("unable to publish second post");
	let third_post_hash = node1
		.publish_post(
			&actor_id,
			&keypair,
			third_message,
			vec!["third".to_string()],
			&[],
			None,
		)
		.await
		.expect("unable to publish third post");

	// Check if all profile data came through correctly
	let profile = node2
		.fetch_profile_info(&actor_id)
		.await
		.expect("unable to fetch profile object from node")
		.expect("got empty profile object");
	assert_eq!(profile.actor.name, "Kees");
	assert_eq!(profile.description, Some(profile_description.to_string()));
	let actor_node = node2
		.node
		.join_actor_network(&actor_id, &actor_info)
		.await
		.expect("actor node not found");
	let avatar = node2
		.find_file_data(
			&actor_node,
			&profile.actor.avatar_id.expect("missing avatar ID"),
		)
		.await
		.expect("unable to get avatar file")
		.expect("unable to get avatar file");
	let wallpaper = node2
		.find_file_data(
			&actor_node,
			&profile.actor.wallpaper_id.expect("missing wallpaper ID"),
		)
		.await
		.expect("unable to get wallpaper file")
		.expect("unable to get wallpaper file");
	assert_eq!(
		avatar.mime_type, avatar_file_data.mime_type,
		"avatar file mime type got corrupted"
	);
	assert_eq!(
		avatar.data, avatar_file_data.data,
		"avatar file data got corrupted"
	);
	assert_eq!(
		wallpaper.mime_type, wallpaper_file_data.mime_type,
		"avatar file mime type got corrupted"
	);
	assert_eq!(
		wallpaper.data, wallpaper_file_data.data,
		"wallpaper file data got corrupted"
	);

	// Download the posts
	let actor_found = node2
		.follow(&actor_id, false)
		.await
		.expect("unable to follow node 1");
	assert!(actor_found, "actor not found");
	debug!("Synchronizing...");
	actor_node.wait_for_synchronization().await;

	// Publish a fourth post after synchronization already happened
	debug!("Publishing a fourth message.");
	let fourth_message = "Fourth post!!!";
	let fourth_post_hash = node1
		.publish_post(
			&actor_id,
			&keypair,
			fourth_message,
			vec!["fourth".to_string()],
			&[],
			None,
		)
		.await
		.expect("unable to publish fourth post");

	// Load posts
	debug!("Loading home feed.");
	let home_feed = tokio::task::block_in_place(|| {
		let mut c = node2.db.connect().expect("unable to open database");
		c.fetch_home_feed(5, 0).expect("unable to fetch home feed")
	});
	assert_eq!(home_feed.len(), 5);

	// Check if we've received all posts no mather in which order.
	for object in &home_feed {
		match &object.payload {
			ObjectPayloadInfo::Profile(_) => {}
			ObjectPayloadInfo::Post(post) =>
				if object.hash == first_post_hash {
					assert_eq!(
						post.message.clone().expect("message is missing"),
						first_message
					);
				} else if object.hash == second_post_hash {
					assert_eq!(
						post.message.clone().expect("message is missing"),
						second_message
					);
				} else if object.hash == third_post_hash {
					assert_eq!(
						post.message.clone().expect("message is missing"),
						third_message
					);
				} else if object.hash == fourth_post_hash {
					assert_eq!(
						post.message.clone().expect("message is missing"),
						fourth_message
					);
				},
			_ => panic!("unknown object type found in home feed"),
		}
	}

	stop_flag.store(true, Ordering::Relaxed);
	node1.close().await;
	node2.close().await;
	bootstrap_node.close().await;
	remove_file("/tmp/bootstrap.sqlite").unwrap();
	remove_file("/tmp/node1.sqlite").unwrap();
	remove_file("/tmp/node2.sqlite").unwrap();
}

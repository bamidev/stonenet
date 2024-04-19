use std::sync::{
	atomic::{AtomicBool, Ordering},
	Arc,
};

use log::*;
use rand::RngCore;
use stonenetd::{api::Api, config::Config, core::*, db::*, net::*, test::*};


#[ctor::ctor]
fn initialize() { env_logger::init(); }

#[tokio::test(flavor = "multi_thread")]
async fn test_data_synchronizations_assisting() {
	let mut next_port = 20000;
	test_data_synchronization(
		&mut next_port,
		Openness::Unidirectional,
		Openness::Bidirectional,
		true,
	)
	.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_data_synchronizations_relaying() {
	let mut next_port = 30000;
	test_data_synchronization(
		&mut next_port,
		Openness::Unidirectional,
		Openness::Unidirectional,
		true,
	)
	.await;
}

#[cfg(test)]
async fn test_data_synchronization(
	next_port: &mut u16, node1_openness: Openness, node2_openness: Openness,
	test_notifications: bool,
) {
	let mut rng = initialize_rng();

	// Set up four nodes
	let stop_flag = Arc::new(AtomicBool::new(false));
	let mut config1 = Config::default();
	config1.ipv4_address = Some("127.0.0.1".to_string());
	config1.ipv4_udp_port = Some(*next_port);
	config1.ipv4_udp_openness = Some("bidirectional".to_string());
	*next_port += 1;
	let mut config2 = Config::default();
	config2.ipv4_address = Some("127.0.0.1".to_string());
	config2.ipv4_udp_port = Some(*next_port);
	config2.ipv4_udp_openness = Some("bidirectional".to_string());
	config2.relay_node = Some(true);
	config2.bootstrap_nodes = vec![format!("127.0.0.1:{}", config1.ipv4_udp_port.unwrap())];
	*next_port += 1;
	let mut config3 = Config::default();
	config3.ipv4_address = Some("127.0.0.1".to_string());
	config3.ipv4_udp_port = Some(*next_port);
	config3.ipv4_udp_openness = Some(node1_openness.to_string());
	config3.bootstrap_nodes = vec![format!("127.0.0.1:{}", config1.ipv4_udp_port.unwrap())];
	*next_port += 1;
	let mut config4 = Config::default();
	config4.ipv4_address = Some("127.0.0.1".to_string());
	config4.ipv4_udp_port = Some(*next_port);
	config4.ipv4_udp_openness = Some(node2_openness.to_string());
	config4.bootstrap_nodes = vec![format!("127.0.0.1:{}", config1.ipv4_udp_port.unwrap())];
	*next_port += 1;
	let bootstrap_node = load_test_node(stop_flag.clone(), &mut rng, &config1, "bootstrap").await;
	let node1 = load_test_node(stop_flag.clone(), &mut rng, &config3, "node1").await;
	let relay_node: Api = load_test_node(stop_flag.clone(), &mut rng, &config2, "random").await;
	let node2 = load_test_node(stop_flag.clone(), &mut rng, &config4, "node2").await;

	// Make sure node 2 knows about the relay node
	let relay_node_info = node2
		.node
		.find_node(relay_node.node.node_id())
		.await
		.expect("relay node not found");
	node2.node.remember_relay_node(&relay_node_info).await;

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
	let description_file_data = FileData {
		mime_type: "text/markdown".to_string(),
		data: profile_description.as_bytes().to_vec(),
	};
	let (actor_id, actor_info) = node1
		.create_my_identity(
			"kees",
			"Kees",
			Some(&avatar_file_data),
			Some(&wallpaper_file_data),
			Some(&description_file_data),
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
	let (_, private_key) = node1
		.fetch_my_identity(&actor_id)
		.expect("unable to load identity")
		.expect("missing identity");
	let first_post_hash = node1
		.publish_post(
			&actor_id,
			&private_key,
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
			&private_key,
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
			&private_key,
			third_message,
			vec!["third".to_string()],
			&[],
			None,
		)
		.await
		.expect("unable to publish third post");
	let share_object = ShareObject {
		actor_address: actor_id.clone(),
		object_hash: first_post_hash.clone(),
	};
	let _share_hash = node1
		.publish_share(&actor_id, &private_key, &share_object)
		.await
		.expect("unable to publish share object");

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
			&private_key,
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
		let mut c = node2.db.connect_old().expect("unable to open database");
		c.fetch_home_feed(6, 0).expect("unable to fetch home feed")
	});
	assert_eq!(home_feed.len(), 5 + test_notifications as usize);

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
			ObjectPayloadInfo::Share(share) => {
				let original_post = share
					.original_post
					.as_ref()
					.expect("share is missing original post");
				assert_eq!(original_post.actor_address, actor_id.to_string());
				assert_eq!(
					original_post
						.message
						.as_ref()
						.expect("message is missing from share")
						.1,
					first_message
				);
			}
		}
	}

	stop_flag.store(true, Ordering::Relaxed);
	node1.close().await;
	node2.close().await;
	relay_node.close().await;
	bootstrap_node.close().await;
}

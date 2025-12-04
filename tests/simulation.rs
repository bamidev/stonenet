use std::sync::{
	atomic::{AtomicBool, Ordering},
	Arc,
};

use log::*;
use rand::RngCore;
use stonenetd::{
	api::Api, config::Config, core::*, db::PersistenceHandle, net::*, test::*,
	web::info::ObjectPayloadInfo,
};
#[cfg(test)]
#[ctor::ctor]
fn initialize() {
	env_logger::init();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_data_synchronizations_assisting() {
	test_data_synchronization(Openness::Unidirectional, Openness::Bidirectional, true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_data_synchronizations_relaying() {
	test_data_synchronization(Openness::Unidirectional, Openness::Unidirectional, true).await;
}

#[cfg(test)]
async fn test_data_synchronization(
	node1_openness: Openness, node2_openness: Openness, test_notifications: bool,
) {
	let mut rng = initialize_rng();

	// Set up four nodes
	let stop_flag = Arc::new(AtomicBool::new(false));
	let mut config1 = Config::default();
	config1.ipv4_address = Some("127.0.0.1".to_string());
	config1.ipv4_udp_openness = Some("bidirectional".to_string());
	config1.ipv4_udp_port = Some(0);
	let bootstrap_node = load_test_node(stop_flag.clone(), &mut rng, &config1, "bootstrap").await;
	let port1 = bootstrap_node
		.node
		.contact_info()
		.ipv4
		.unwrap()
		.availability
		.udp
		.unwrap()
		.port;
	let mut config2 = Config::default();
	config2.ipv4_address = Some("127.0.0.1".to_string());
	config2.ipv4_udp_openness = Some("bidirectional".to_string());
	config2.ipv4_udp_port = Some(0);
	config2.relay_node = Some(true);
	config2.bootstrap_nodes = vec![format!("127.0.0.1:{}", port1)];
	let mut config3 = Config::default();
	config3.ipv4_address = Some("127.0.0.1".to_string());
	config3.ipv4_udp_openness = Some(node1_openness.to_string());
	config3.ipv4_udp_port = Some(0);
	config3.bootstrap_nodes = vec![format!("127.0.0.1:{}", port1)];
	let mut config4 = Config::default();
	config4.ipv4_address = Some("127.0.0.1".to_string());
	config4.ipv4_udp_openness = Some(node2_openness.to_string());
	config4.ipv4_udp_port = Some(0);
	config4.bootstrap_nodes = vec![format!("127.0.0.1:{}", port1)];
	let relay_node = load_test_node(stop_flag.clone(), &mut rng, &config2, "random").await;
	let node1 = load_test_node(stop_flag.clone(), &mut rng, &config3, "node1").await;
	let node2 = load_test_node(stop_flag.clone(), &mut rng, &config4, "node2").await;

	// Make sure node 1 & 2 know about the relay node, because otherwise they may not be able to
	// reach eachother whenever they just happened to not need to come across this node before and
	// therefore remembered it
	let relay_node_info = node2
		.node
		.find_node(relay_node.node.node_id())
		.await
		.expect("relay node not found");
	node1.node.remember_relay_node(&relay_node_info).await;
	node2.node.remember_relay_node(&relay_node_info).await;

	// Create a profile for node 1
	let profile_description = r#"
Hoi ik ben Kees!
"#;
	let mut avatar_file_data = FileData {
		mime_type: "image/png".into(),
		data: vec![0u8; 1000],
	};
	rng.fill_bytes(&mut avatar_file_data.data);
	let mut wallpaper_file_data = FileData {
		mime_type: "image/jpeg".into(),
		data: vec![0u8; 10000000],
	};
	rng.fill_bytes(&mut wallpaper_file_data.data);
	let description_file_data = FileData {
		mime_type: "text/markdown".into(),
		data: profile_description.as_bytes().to_vec(),
	};
	let (actor_id, actor_info) = node1
		.create_identity(
			"kees",
			"Kees",
			Some(&avatar_file_data),
			Some(&wallpaper_file_data),
			Some(&description_file_data),
		)
		.await
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
			"text/plain",
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
			"text/plain",
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
			"text/plain",
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
	let share_hash = node1
		.publish_share(&actor_id, &private_key, &share_object)
		.await
		.expect("unable to publish share object");

	// Check if all profile data came through correctly
	let profile_info = node2
		.find_profile_info("", &actor_id)
		.await
		.expect("unable to fetch profile object from node")
		.expect("got empty profile object");
	assert_eq!(profile_info.actor.name, "Kees");
	assert_eq!(
		profile_info.description,
		Some(profile_description.to_string())
	);
	let actor_node = node2
		.node
		.join_actor_network(&actor_id, &actor_info)
		.await
		.expect("actor node not found");
	let profile_object = node2
		.db
		.load_profile(&actor_id)
		.await
		.expect("unable to load profile")
		.expect("unable to load profile");
	let avatar = node2
		.find_file_data(
			Some(&actor_node),
			&profile_object.avatar.expect("missing avatar ID"),
		)
		.await
		.expect("unable to get avatar file")
		.expect("unable to get avatar file");
	let wallpaper = node2
		.find_file_data(
			Some(&actor_node),
			&profile_object.wallpaper.expect("missing wallpaper ID"),
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
			"text/plain",
			fourth_message,
			vec!["fourth".to_string()],
			&[],
			None,
		)
		.await
		.expect("unable to publish fourth post");

	// Load posts
	debug!("Loading home feed.");
	let home_feed = node2
		.load_home_feed(6, 0)
		.await
		.expect("unable to load home feed");
	assert_eq!(home_feed.len(), 5 + test_notifications as usize);

	// Check if we've received all posts no mather in which order.
	for object in &home_feed {
		match &object.payload {
			ObjectPayloadInfo::Profile(_) => {}
			ObjectPayloadInfo::Post(post) => {
				if object.id == first_post_hash.to_string() {
					assert_eq!(
						post.message.clone().expect("message is missing").body,
						first_message
					);
				} else if object.id == second_post_hash.to_string() {
					assert_eq!(
						post.message.clone().expect("message is missing").body,
						second_message
					);
				} else if object.id == third_post_hash.to_string() {
					assert_eq!(
						post.message.clone().expect("message is missing").body,
						third_message
					);
				} else if object.id == fourth_post_hash.to_string() {
					assert_eq!(
						post.message.clone().expect("message is missing").body,
						fourth_message
					);
				} else if object.id == share_hash.to_string() {
					// TODO: Check if the shared message matches
				}
			}
		}
	}

	stop_flag.store(true, Ordering::Relaxed);
	node1.close().await;
	node2.close().await;
	relay_node.close().await;
	bootstrap_node.close().await;
}

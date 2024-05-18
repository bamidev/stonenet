use std::str::FromStr;

use lazy_static::lazy_static;
use log::*;
use once_cell::sync::OnceCell;
use serde::*;

use crate::core::*;


/// The file path of the configuration file
#[cfg(target_family = "unix")]
pub const CONFIG_FILE_PATH: &str = "/etc/stonenet/config.toml";


#[derive(Clone, Deserialize)]
pub struct Config {
	pub database_path: String,

	pub ipv4_address: Option<String>,
	pub ipv6_address: Option<String>,
	pub ipv4_udp_port: Option<u16>,
	pub ipv4_tcp_port: Option<u16>,
	pub ipv6_udp_port: Option<u16>,
	pub ipv6_tcp_port: Option<u16>,
	pub ipv4_udp_openness: Option<String>,
	pub ipv4_tcp_openness: Option<String>,
	pub ipv6_udp_openness: Option<String>,
	pub ipv6_tcp_openness: Option<String>,

	pub bootstrap_nodes: Vec<String>,
	pub load_web_interface: Option<bool>,
	pub web_interface_port: Option<u16>,
	pub load_user_interface: Option<bool>,
	pub user_interface_port: Option<u16>,
	pub node_ping_interval: Option<u64>,
	pub bucket_size: Option<usize>,
	pub relay_node: Option<bool>,
	pub leak_first_request: Option<bool>,
	pub web_url_base: Option<String>,
	pub publicize_friends_list: Option<bool>,

	pub track: Option<Vec<String>>,

	pub activity_pub_inbox_server: Option<String>,
	pub activity_pub_inbox_size: Option<u32>,
	pub activity_pub_private_key: Option<String>,
	pub activity_pub_public_key: Option<String>,
	pub activity_pub_send_queue_capacity: Option<u64>,

	pub federation_contact_info: Option<String>,
	pub federation_domain: Option<String>,
	pub federation_organization: Option<String>,
	pub federation_server_account: Option<String>,
	pub federation_server_name: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Settings {
	pub default_space_allocation: u32,
}


impl Config {
	pub fn parse_tracked_actors(&self) -> Vec<ActorAddress> {
		let mut addrs = Vec::new();
		if let Some(tracked) = &self.track {
			for string in tracked {
				match Address::from_str(string) {
					Ok(addr) => match addr {
						Address::Actor(aa) => addrs.push(aa),
						_ => error!(
							"Address in track config parameter is not an actor address: {}",
							string
						),
					},
					Err(_) => error!(
						"Invalid actor address in track config parameter: {}",
						string
					),
				}
			}
		}
		addrs
	}
}

impl Default for Config {
	fn default() -> Self {
		Self {
			activity_pub_inbox_size: None,
			activity_pub_private_key: None,
			activity_pub_public_key: None,
			activity_pub_send_queue_capacity: None,
			activity_pub_inbox_server: None,
			bootstrap_nodes: vec![],
			bucket_size: Some(4),
			database_path: String::default(),
			federation_domain: None,
			federation_contact_info: None,
			federation_organization: None,
			federation_server_account: None,
			federation_server_name: None,
			ipv4_address: None,
			ipv6_address: None,
			ipv4_udp_port: None,
			ipv4_tcp_port: None,
			ipv6_udp_port: None,
			ipv6_tcp_port: None,
			ipv4_udp_openness: None,
			ipv4_tcp_openness: None,
			ipv6_udp_openness: None,
			ipv6_tcp_openness: None,
			leak_first_request: None,
			load_user_interface: None,
			load_web_interface: None,
			node_ping_interval: None,
			publicize_friends_list: None,
			relay_node: None,
			track: None,
			user_interface_port: None,
			web_interface_port: None,
			web_url_base: None,
		}
	}
}


lazy_static! {
	pub static ref CONFIG: OnceCell<Config> = OnceCell::new();
}

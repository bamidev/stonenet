use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use serde::*;


/// The file path of the configuration file
#[cfg(target_family = "unix")]
pub const CONFIG_FILE_PATH: &str = "/etc/stonenet/config.toml";
#[cfg(target_family = "windows")]
pub const CONFIG_FILE_PATH: &str = "C:\\Program Files\\stonenet\\config.toml";

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
	pub udp_max_idle_time: usize,
	pub bucket_size: Option<usize>,
	pub relay_node: Option<bool>,
	pub leak_first_request: Option<bool>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Settings {
	pub default_space_allocation: u32,
}


impl Default for Config {
	fn default() -> Self {
		Self {
			database_path: String::default(),
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
			bootstrap_nodes: vec![],
			load_web_interface: None,
			udp_max_idle_time: 60,
			bucket_size: Some(4),
			relay_node: None,
			leak_first_request: None,
			web_interface_port: None,
			load_user_interface: None,
			user_interface_port: None,
		}
	}
}


lazy_static! {
	pub static ref CONFIG: OnceCell<Config> = OnceCell::new();
}

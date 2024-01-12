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
	pub load_web_interface: bool,
	pub udp_max_idle_time: usize,
	pub bucket_size: usize,
	pub relay_node: bool,
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
			load_web_interface: false,
			udp_max_idle_time: 60,
			bucket_size: 4,
			relay_node: false,
		}
	}
}


lazy_static! {
	pub static ref CONFIG: OnceCell<Config> = OnceCell::new();
}

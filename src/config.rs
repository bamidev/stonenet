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
	pub ipv4_udp_port: u16,
	pub ipv4_tcp_port: u16,
	pub ipv6_udp_port: u16,
	pub ipv6_tcp_port: u16,
	pub ipv4_udp_openness: Option<String>,
	pub ipv4_tcp_openness: Option<String>,
	pub ipv6_udp_openness: Option<String>,
	pub ipv6_tcp_openness: Option<String>,

	pub bootstrap_nodes: Vec<String>,
	pub load_web_interface: bool,
	pub udp_max_idle_time: usize,
	pub bucket_size: usize,
	pub super_node: bool
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct Settings {
	pub default_space_allocation: u32,
}


impl Default for Config {
	fn default() -> Self {
		Self {
			database_path: String::default(),
			ipv4_address: Some("0.0.0.0".to_string()),
			ipv6_address: Some("::".to_string()),
			ipv4_udp_port: 37337,
			ipv4_tcp_port: 37337,
			ipv6_udp_port: 37337,
			ipv6_tcp_port: 37337,
			ipv4_udp_openness: Some("bidirectional".to_string()),
			ipv4_tcp_openness: Some("unidirectional".to_string()),
			ipv6_udp_openness: Some("bidirectional".to_string()),
			ipv6_tcp_openness: Some("unidirectional".to_string()),
			bootstrap_nodes: vec![],
			load_web_interface: true,
			udp_max_idle_time: 60,
			bucket_size: 4,
			super_node: false
		}
	}
}


lazy_static! {
	pub static ref CONFIG: OnceCell<Config> = OnceCell::new();
}

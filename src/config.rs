use std::net::SocketAddr;

use serde::Deserialize;


#[derive(Deserialize)]
pub struct Config {
    pub address: String,
    pub bootstrap_nodes: Vec<String>,
    pub load_web_interface: bool,
    pub udp_max_idle_time: usize
}

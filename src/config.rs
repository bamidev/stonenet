use serde::Deserialize;


#[derive(Clone, Deserialize)]
pub struct Config {
    pub address: String,
    pub bootstrap_nodes: Vec<String>,
    pub load_web_interface: bool,
    pub udp_max_idle_time: usize,
    pub bucket_size: usize
}

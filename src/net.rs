pub mod actor;
mod actor_store;
pub mod bincode;
mod connection_manager;
pub mod message;
mod node;
pub mod overlay;
mod socket;
pub(crate) mod sstp;


use std::{
	fmt,
	net::*,
	sync::{atomic::*, Arc},
	time::{Duration, SystemTime},
};

use log::*;
use num::BigUint;
use serde::{Deserialize, Serialize};
use sstp::Connection;
use tokio::sync::Mutex;

use crate::common::*;

/// Size of the 'k-buckets'. This parameter defines how many active fingers we
/// keep for each leaf in the binary tree.
pub const KADEMLIA_K: u32 = 4;
//pub type KADEMLIA_K_AL = U4;
/// Number of bits in a Kademlia ID. It is specified as 160 bits in the paper,
/// but we use 256.
pub const KADEMLIA_BITS: usize = 256;

// Messages for the overlay network:
pub const NETWORK_MESSAGE_TYPE_PING_REQUEST: u8 = 0;
//pub const NETWORK_MESSAGE_TYPE_PING_RESPONSE: u8 = 1;
pub const NETWORK_MESSAGE_TYPE_FIND_NODE_REQUEST: u8 = 2;
//pub const NETWORK_MESSAGE_TYPE_FIND_NODE_RESPONSE: u8 = 3;
pub const NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST: u8 = 4;
//pub const NETWORK_MESSAGE_TYPE_FIND_NODE_RESPONSE: u8 = 5;
pub const NETWORK_MESSAGE_TYPE_PUNCH_HOLE_REQUEST: u8 = 6;
//pub const NETWORK_MESSAGE_TYPE_RELAY_RESPONSE: u8 = 7;
pub const NETWORK_MESSAGE_TYPE_RELAY_PUNCH_HOLE_REQUEST: u8 = 8;
//pub const NETWORK_MESSAGE_TYPE_RELAY_RESPONSE: u8 = 9;
pub const NETWORK_MESSAGE_TYPE_RELAY_REQUEST: u8 = 10;
//pub const NETWORK_MESSAGE_TYPE_RELAY_RESPONSE: u8 = 11;
pub const NETWORK_MESSAGE_TYPE_KEEP_ALIVE_REQUEST: u8 = 12;
//pub const NETWORK_MESSAGE_TYPE_KEEP_ALIVE_RESPONSE: u8 = 13;


/// All the info that advertises in what way this node is approachable over the
/// current internet. Could both be very well set to `None`, if the node is
/// behind a NAT device that allocates different IP addresses to different
/// connections.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContactInfo {
	/// IPv4 contact info
	pub ipv4: Option<Ipv4ContactInfo>,
	/// IPv6 contact info
	pub ipv6: Option<Ipv6ContactInfo>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ContactAvailability {
	pub ipv4: Option<IpAvailability>,
	pub ipv6: Option<IpAvailability>,
}

/// The contact info on a particular IP version
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContactInfoEntry<A>
where
	A: Clone + fmt::Debug + Eq,
{
	/// IP address
	pub addr: A,
	pub availability: IpAvailability,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContactOption {
	target: SocketAddr,
	use_tcp: bool,
}

/// IPv4 contact info
pub type Ipv4ContactInfo = ContactInfoEntry<Ipv4Addr>;
/// IPv6 contact info
pub type Ipv6ContactInfo = ContactInfoEntry<Ipv6Addr>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IpAvailability {
	/// UDP contact info
	pub udp: Option<TransportAvailabilityEntry>,
	/// TCP contact info
	pub tcp: Option<TransportAvailabilityEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeContactInfo {
	pub node_id: IdType,
	pub contact_info: ContactInfo,
}

/*#[derive(Clone)]
pub struct NodeContactMethod {
	pub node_id: IdType,
	pub method: ContactMethod
}*/

/// The port and 'openness' of a transport protocol such as UDP or TCP.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransportAvailabilityEntry {
	pub port: u16,
	pub openness: Openness,
}

/// The level of 'openness' a node has, that determines the way they (can)
/// interact with the rest of the network.
#[derive(Clone, Debug, Eq, Deserialize, PartialEq, Serialize)]
pub enum Openness {
	/// Allowed to initiate and accept connections.
	/// For nodes that are not behind a symmetric NAT
	/// for example.
	Bidirectional  = 0,
	/// Allowed to initiate connections, but not able to accept any.
	Unidirectional = 1,
}


/// Calculates the distance between two hashes.
fn distance(a: &IdType, b: &IdType) -> BigUint { a.distance(b) }


impl ContactInfo {
	pub fn is_open_to_reversed_connections(&self, other: &ContactInfo) -> bool {
		if let Some(entry_a) = &self.ipv4 {
			if let Some(entry_b) = &other.ipv4 {
				if let Some(a) = &entry_a.availability.udp {
					if entry_b.availability.udp.is_some() && a.openness == Openness::Bidirectional {
						return true;
					}
				}
				if let Some(a) = &entry_a.availability.tcp {
					if entry_b.availability.tcp.is_some() && a.openness == Openness::Bidirectional {
						return true;
					}
				}
			}
		}

		if let Some(entry_a) = &self.ipv6 {
			if let Some(entry_b) = &other.ipv6 {
				if let Some(a) = &entry_a.availability.udp {
					if entry_b.availability.udp.is_some() && a.openness == Openness::Bidirectional {
						return true;
					}
				}
				if let Some(a) = &entry_a.availability.tcp {
					if entry_b.availability.tcp.is_some() && a.openness == Openness::Bidirectional {
						return true;
					}
				}
			}
		}

		false
	}

	pub fn update(&mut self, addr: &SocketAddr, for_tcp: bool) {
		match addr {
			SocketAddr::V4(a) => self.update_v4(a.ip(), a.port(), for_tcp),
			SocketAddr::V6(a) => self.update_v6(a.ip(), a.port(), for_tcp),
		}
	}

	pub fn update_v4(&mut self, ip: &Ipv4Addr, port: u16, for_tcp: bool) {
		match &mut self.ipv4 {
			None => {}
			Some(entry) => {
				entry.addr = ip.clone();
				if for_tcp {
					match &mut entry.availability.tcp {
						None =>
							entry.availability.tcp = Some(TransportAvailabilityEntry {
								port,
								openness: Openness::Unidirectional,
							}),
						Some(entry2) => entry2.port = port,
					}
				} else {
					match &mut entry.availability.udp {
						None =>
							entry.availability.udp = Some(TransportAvailabilityEntry {
								port,
								openness: Openness::Unidirectional,
							}),
						Some(entry2) => entry2.port = port,
					}
				}
			}
		}
	}

	pub fn update_v6(&mut self, ip: &Ipv6Addr, port: u16, for_tcp: bool) {
		match &mut self.ipv6 {
			None => {}
			Some(entry) => {
				entry.addr = ip.clone();
				if for_tcp {
					match &mut entry.availability.tcp {
						None =>
							entry.availability.tcp = Some(TransportAvailabilityEntry {
								port,
								openness: Openness::Unidirectional,
							}),
						Some(entry2) => entry2.port = port,
					}
				} else {
					match &mut entry.availability.udp {
						None =>
							entry.availability.udp = Some(TransportAvailabilityEntry {
								port,
								openness: Openness::Unidirectional,
							}),
						Some(entry2) => entry2.port = port,
					}
				}
			}
		}
	}
}

impl fmt::Display for ContactInfo {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self.ipv4.as_ref() {
			None => {}
			Some(ci) => {
				write!(f, "IPv4={},", &ci.addr)?;
				match &ci.availability.udp {
					None => {}
					Some(entry) => write!(f, "UDPv4={},", entry)?,
				}
				match &ci.availability.tcp {
					None => {}
					Some(entry) => write!(f, "TCPv4={},", entry)?,
				}
			}
		}
		match self.ipv6.as_ref() {
			None => {}
			Some(ci) => {
				write!(f, "IPv6={},", &ci.addr)?;
				match &ci.availability.udp {
					None => {}
					Some(entry) => write!(f, "UDPv6={},", entry)?,
				}
				match &ci.availability.tcp {
					None => {}
					Some(entry) => write!(f, "TCPv6={},", entry)?,
				}
			}
		}
		Ok(())
	}
}

impl From<&SocketAddr> for ContactInfo {
	fn from(addr: &SocketAddr) -> Self {
		let mut this = Self::default();
		match addr {
			SocketAddr::V4(addrv4) => {
				this.ipv4 = Some(Ipv4ContactInfo {
					addr: addrv4.ip().clone(),
					availability: IpAvailability {
						udp: Some(TransportAvailabilityEntry {
							port: addrv4.port(),
							openness: Openness::Bidirectional,
						}),
						tcp: Some(TransportAvailabilityEntry {
							port: addrv4.port(),
							openness: Openness::Bidirectional,
						}),
					},
				});
			}
			SocketAddr::V6(addrv6) => {
				this.ipv6 = Some(Ipv6ContactInfo {
					addr: addrv6.ip().clone(),
					availability: IpAvailability {
						udp: Some(TransportAvailabilityEntry {
							port: addrv6.port(),
							openness: Openness::Bidirectional,
						}),
						tcp: Some(TransportAvailabilityEntry {
							port: addrv6.port(),
							openness: Openness::Bidirectional,
						}),
					},
				});
			}
		}
		this
	}
}

impl ContactOption {
	pub fn new(target: SocketAddr, use_tcp: bool) -> Self { Self { target, use_tcp } }

	pub fn use_udp(target: SocketAddr) -> Self { Self::new(target, false) }
}

impl fmt::Display for ContactOption {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if self.use_tcp {
			write!(f, "TCP-{}", self.target)
		} else {
			write!(f, "UDP-{}", self.target)
		}
	}
}

impl NodeContactInfo {
	pub fn update(&mut self, addr: &SocketAddr, for_tcp: bool) {
		self.contact_info.update(addr, for_tcp);
	}
}

impl fmt::Display for NodeContactInfo {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}: {}", self.node_id, self.contact_info)
	}
}

impl fmt::Display for Openness {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Openness::Bidirectional => write!(f, "bidirectional"),
			Openness::Unidirectional => write!(f, "unidirectional"),
		}
	}
}

impl fmt::Display for TransportAvailabilityEntry {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}-{}", self.port, &self.openness)
	}
}


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_distance() {
		let a = IdType::from_base58("DSLVRnqejmzQXKmoZ4KtfvvGLBSFwKJxKEQxnXJq1A8b").unwrap();
		let b = IdType::from_base58("E7hinjgaQ7WfsNjos1FHYvHNCgHJfC9f29arA5QqtZw1").unwrap();
		assert!(distance(&a, &b) > 0u32.into());
	}
}

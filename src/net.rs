pub mod actor;
mod actor_store;
pub mod binserde;
mod bucket;
mod connection_manager;
pub mod message;
mod node;
pub mod overlay;
mod socket;
pub(crate) mod sstp;

use std::{
	collections::HashMap,
	fmt,
	net::*,
	str::FromStr,
	sync::{atomic::*, Arc, Mutex},
	time::{Duration, SystemTime},
};

use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use log::*;
use num::BigUint;
use serde::{Deserialize, Serialize};
use sstp::Connection;

use crate::{common::*, config::Config, core::NodeAddress};

//pub type KADEMLIA_K_AL = U4;
/// Number of bits in a Kademlia ID. It is specified as 160 bits in the paper,
/// but we use 256.
pub const KADEMLIA_BITS: usize = 256;

lazy_static! {
	pub static ref NETWORK_INTERFACES: Mutex<HashMap<String, Vec<IpNetwork>>> =
		Mutex::new(HashMap::new());
}

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

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct LinkProtocol {
	pub use_ipv6: bool,
	pub use_tcp: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeContactInfo {
	pub address: NodeAddress,
	pub contact_info: ContactInfo,
}

#[allow(dead_code)]
pub enum NetworkLevel {
	Global,
	Local(String),
	Unknown,
}

/// The port and 'openness' of a transport protocol such as UDP or TCP.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransportAvailabilityEntry {
	pub port: u16,
	pub openness: Openness,
}

/// The level of 'openness' a node has, that determines the way they (can)
/// interact with the rest of the network.
#[derive(Clone, Copy, Debug, Eq, Deserialize, PartialEq, Serialize)]
pub enum Openness {
	/// Allowed to initiate and accept connections.
	/// For nodes that are not behind a symmetric NAT
	/// for example.
	Bidirectional = 0,
	/// Allowed to initiate connections, and is able to open a hole to accept
	/// connections.
	Punchable = 1,
	/// Allowed to initiate connections, but not able to accept any.
	Unidirectional = 2,
}

/// Calculates the distance between two hashes.
fn distance(a: &IdType, b: &IdType) -> BigUint {
	a.distance(b)
}

impl ContactInfo {
	/// Parses the contact info ready for initiating a `SstpSocket` from the
	/// config file
	pub fn from_config(config: &Config) -> ContactInfo {
		let mut contact_info = ContactInfo::default();

		fn parse_openness(string: &str) -> Openness {
			match Openness::from_str(string) {
				Ok(o) => o,
				Err(()) => {
					error!(
						"Unable to parse openness \"{}\", defaulting to unidirectional",
						string
					);
					Openness::Unidirectional
				}
			}
		}

		// IPv4
		match &config.ipv4_address {
			None => {}
			Some(address) => {
				contact_info.ipv4 =
					Some(ContactInfoEntry {
						addr: address.parse().expect("invalid IPv4 address configured"),
						availability: IpAvailability {
							udp: config.ipv4_udp_port.as_ref().map(|p| {
								TransportAvailabilityEntry {
									port: *p,
									openness: config
										.ipv4_udp_openness
										.as_ref()
										.map(|s| parse_openness(s))
										.unwrap_or(Openness::Unidirectional),
								}
							}),
							tcp: config.ipv4_tcp_port.as_ref().map(|p| {
								TransportAvailabilityEntry {
									port: *p,
									openness: config
										.ipv4_tcp_openness
										.as_ref()
										.map(|s| parse_openness(s))
										.unwrap_or(Openness::Unidirectional),
								}
							}),
						},
					})
			}
		}

		// IPv6
		match &config.ipv6_address {
			None => {}
			Some(address) => {
				contact_info.ipv6 =
					Some(ContactInfoEntry {
						addr: address.parse().expect("invalid IPv6 address configured"),
						availability: IpAvailability {
							udp: config.ipv6_udp_port.as_ref().map(|p| {
								TransportAvailabilityEntry {
									port: *p,
									openness: config
										.ipv6_udp_openness
										.as_ref()
										.map(|s| parse_openness(s))
										.unwrap_or(Openness::Unidirectional),
								}
							}),
							tcp: config.ipv6_tcp_port.as_ref().map(|p| {
								TransportAvailabilityEntry {
									port: *p,
									openness: config
										.ipv6_tcp_openness
										.as_ref()
										.map(|s| parse_openness(s))
										.unwrap_or(Openness::Unidirectional),
								}
							}),
						},
					})
			}
		}

		contact_info
	}

	pub fn merge(&mut self, other: &Self) {
		if let Some(entry_a) = &other.ipv4 {
			if let Some(entry_b) = self.ipv4.as_mut() {
				entry_b.addr = entry_a.addr;
				if let Some(a) = &entry_a.availability.udp {
					entry_b.availability.udp = Some(a.clone());
				}
				if let Some(a) = &entry_a.availability.tcp {
					entry_b.availability.tcp = Some(a.clone());
				}
			} else {
				self.ipv4 = other.ipv4.clone();
			}
		}

		if let Some(entry_a) = &other.ipv6 {
			if let Some(entry_b) = self.ipv6.as_mut() {
				entry_b.addr = entry_a.addr;
				if let Some(a) = &entry_a.availability.udp {
					entry_b.availability.udp = Some(a.clone());
				}
				if let Some(a) = &entry_a.availability.tcp {
					entry_b.availability.tcp = Some(a.clone());
				}
			} else {
				self.ipv6 = other.ipv6.clone();
			}
		}
	}

	pub fn openness_at_option(&self, option: &ContactOption) -> Option<Openness> {
		match &option.target {
			SocketAddr::V4(_addr) => {
				if let Some(e) = &self.ipv4 {
					if !option.use_tcp {
						e.availability.udp.as_ref().map(|e| e.openness.clone())
					} else {
						e.availability.tcp.as_ref().map(|e| e.openness.clone())
					}
				} else {
					None
				}
			}
			SocketAddr::V6(_addr) => {
				if let Some(e) = &self.ipv6 {
					if !option.use_tcp {
						e.availability.udp.as_ref().map(|e| e.openness.clone())
					} else {
						e.availability.tcp.as_ref().map(|e| e.openness.clone())
					}
				} else {
					None
				}
			}
		}
	}

	/// Picks the best available contact option between this ContactInfo and that of the target.
	pub fn pick_best_option(&self, target: &ContactInfo) -> Option<ContactOption> {
		if let Some(our) = self.ipv6.as_ref() {
			if let Some(their) = target.ipv6.as_ref() {
				if our.availability.udp.is_some() {
					if let Some(udp) = their.availability.udp.as_ref() {
						return Some(ContactOption::new(
							SocketAddrV6::new(their.addr.clone(), udp.port, 0, 0xE).into(),
							false,
						));
					}
				}
			}
		}
		if let Some(our) = self.ipv4.as_ref() {
			if let Some(their) = target.ipv4.as_ref() {
				if our.availability.udp.is_some() {
					if let Some(udp) = their.availability.udp.as_ref() {
						return Some(ContactOption::new(
							SocketAddrV4::new(their.addr.clone(), udp.port).into(),
							false,
						));
					}
				}
			}
		}
		if let Some(our) = self.ipv6.as_ref() {
			if let Some(their) = target.ipv6.as_ref() {
				if our.availability.tcp.is_some() {
					if let Some(udp) = their.availability.tcp.as_ref() {
						return Some(ContactOption::new(
							SocketAddrV6::new(their.addr.clone(), udp.port, 0, 0xE).into(),
							true,
						));
					}
				}
			}
		}
		if let Some(our) = self.ipv4.as_ref() {
			if let Some(their) = target.ipv4.as_ref() {
				if our.availability.tcp.is_some() {
					if let Some(udp) = their.availability.tcp.as_ref() {
						return Some(ContactOption::new(
							SocketAddrV4::new(their.addr.clone(), udp.port).into(),
							true,
						));
					}
				}
			}
		}
		None
	}

	pub fn pick_similar_option(&self, target: &ContactOption) -> Option<ContactOption> {
		let socketaddr = match target.target {
			SocketAddr::V6(_) => {
				if let Some(ipv6) = &self.ipv6 {
					let port = if !target.use_tcp {
						if let Some(udp) = &ipv6.availability.udp {
							udp.port
						} else {
							return None;
						}
					} else {
						if let Some(tcp) = &ipv6.availability.tcp {
							tcp.port
						} else {
							return None;
						}
					};
					SocketAddr::V6(SocketAddrV6::new(ipv6.addr, port, 0, 0xE))
				} else {
					return None;
				}
			}
			SocketAddr::V4(_) => {
				if let Some(ipv4) = &self.ipv4 {
					let port = if !target.use_tcp {
						if let Some(udp) = &ipv4.availability.udp {
							udp.port
						} else {
							return None;
						}
					} else {
						if let Some(tcp) = &ipv4.availability.tcp {
							tcp.port
						} else {
							return None;
						}
					};
					SocketAddr::V4(SocketAddrV4::new(ipv4.addr, port))
				} else {
					return None;
				}
			}
		};
		Some(ContactOption::new(socketaddr, target.use_tcp))
	}

	/// Update contact info with what has been seen by the other side.
	/// This is used whenever contacting another node, because our external port and/or IP address
	/// may change with time.
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
				// For TCP, we don't update the port because the source port (as reported
				// by the other side) is rarely open to receiving connections.
				if !for_tcp {
					match &mut entry.availability.udp {
						None => {
							entry.availability.udp = Some(TransportAvailabilityEntry {
								port,
								openness: Openness::Unidirectional,
							})
						}
						Some(udp) => {
							if udp.openness != Openness::Unidirectional {
								// When unidirectional, it doesn't actually matter what the port is,
								// because it can't be reached anyway.
								udp.port = port;
							}
						}
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
				// For TCP, we don't update the port because the source port (as reported
				// by the other side) is rarely open to receiving connections.
				if !for_tcp {
					match &mut entry.availability.udp {
						None => {
							entry.availability.udp = Some(TransportAvailabilityEntry {
								port,
								openness: Openness::Unidirectional,
							})
						}
						Some(udp) => {
							if udp.openness != Openness::Unidirectional {
								// When unidirectional, it doesn't actually matter what the port is,
								// because it can't be reached anyway.
								udp.port = port;
							}
						}
					}
				}
			}
		}
	}

	fn score(&self) -> u8 {
		let mut score = 0u8;

		// FIXME: Don't give points for a protocol that we don't support ourselves, as
		// we shouldn't care about those.
		if let Some(e) = &self.ipv4 {
			if let Some(_udp) = &e.availability.udp {
				score += 4;
			}
			if let Some(_udp) = &e.availability.tcp {
				score += 1;
			}
		}
		if let Some(e) = &self.ipv6 {
			if let Some(_udp) = &e.availability.udp {
				score += 2;
			}
			if let Some(_udp) = &e.availability.tcp {
				score += 1;
			}
		}
		score
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
	pub fn new(target: SocketAddr, use_tcp: bool) -> Self {
		Self { target, use_tcp }
	}

	#[allow(dead_code)]
	pub fn new_udp(target: SocketAddr) -> Self {
		Self::new(target, false)
	}
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
	#[allow(dead_code)]
	pub fn update(&mut self, addr: &SocketAddr, for_tcp: bool) {
		self.contact_info.update(addr, for_tcp);
	}
}

impl fmt::Display for NodeContactInfo {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}: {}", self.address, self.contact_info)
	}
}

impl fmt::Display for Openness {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Bidirectional => write!(f, "bidirectional"),
			Self::Punchable => write!(f, "punchable"),
			Self::Unidirectional => write!(f, "unidirectional"),
		}
	}
}

impl FromStr for Openness {
	type Err = ();

	fn from_str(string: &str) -> Result<Self, ()> {
		match string.to_lowercase().as_str() {
			"bidirectional" => Ok(Self::Bidirectional),
			"punchable" => Ok(Self::Punchable),
			"unidirectional" => Ok(Self::Unidirectional),
			_ => Err(()),
		}
	}
}

impl PartialOrd for Openness {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		(*self as u8)
			.partial_cmp(&(*other as u8))
			.map(|o| o.reverse())
	}
}

impl fmt::Display for TransportAvailabilityEntry {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}-{}", self.port, &self.openness)
	}
}

pub fn resolve_bootstrap_addresses(
	nodes: &[String], use_ipv4: bool, use_ipv6: bool,
) -> Vec<SocketAddr> {
	// Collect all (unique) IP addresses
	let mut addrs = Vec::with_capacity(nodes.len());
	for string in nodes {
		match string.to_socket_addrs() {
			Err(e) => error!("Unable to parse bootstrap node {}: {}.", string, e),
			Ok(mut iter) => {
				while let Some(addr) = iter.next() {
					if addr.is_ipv4() {
						if use_ipv4 {
							addrs.push(addr);
						}
					} else if addr.is_ipv6() {
						if use_ipv6 {
							addrs.push(addr);
						}
					}

					if !addrs.contains(&addr) {
						addrs.push(addr);
					}
				}
			}
		}
	}
	addrs
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_distance() {
		let a = IdType::from_base58("DSLVRnqejmzQXKmoZ4KtfvvGLBSFwKJxKEQxnXJq1A8b").unwrap();
		let b = IdType::from_base58("E7hinjgaQ7WfsNjos1FHYvHNCgHJfC9f29arA5QqtZw1").unwrap();
		assert!(distance(&a, &b) > 0u32.into());
		assert_eq!(distance(&a, &b), distance(&b, &a));
	}
}

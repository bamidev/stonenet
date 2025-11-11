use std::cmp::Ordering;

use super::{distance, NodeContactInfo};
use crate::{core::NodeAddress, limited_store::LimitedVec};

pub struct Bucket {
	pub(super) connections: LimitedVec<NodeContactInfo>,
	fingers: LimitedVec<BucketEntry>,
	replacement_cache: LimitedVec<BucketReplacementEntry>,
}

#[derive(Clone)]
struct BucketEntry {
	node_info: NodeContactInfo,
	trust_score: u8,
	is_relay: bool,
	values_obtained: u32,
}

#[derive(Clone)]
pub struct BucketReplacementEntry {
	finger: BucketEntry,
	failed_attempts: u8,
}

impl Bucket {
	pub fn add_connection(
		&mut self, connection_node_info: &NodeContactInfo, our_node_id: &NodeAddress,
	) -> bool {
		let new_distance = distance(&our_node_id.as_id(), &connection_node_info.address.as_id());

		if let Some(pos) = self
			.connections
			.iter()
			.position(|n| new_distance < distance(&our_node_id.as_id(), &n.address.as_id()))
		{
			let node_info = connection_node_info.clone();
			self.connections.insert(pos, node_info);
			true
		} else if self.connections.len() < self.connections.limit() {
			let node_info = connection_node_info.clone();
			self.connections.push_back(node_info);
			true
		} else {
			false
		}
	}

	/// The fingers that can given to other nodes
	pub fn public_fingers(&self) -> impl Iterator<Item = &NodeContactInfo> {
		self.connections
			.iter()
			.map(|n| n)
			.chain(self.fingers.iter().map(|e| &e.node_info))
	}

	/// The fingers that can given to other nodes
	pub fn public_fingers_no_connection(&self) -> impl Iterator<Item = &NodeContactInfo> {
		self.fingers.iter().map(|e| &e.node_info)
	}

	pub fn find(&self, address: &NodeAddress) -> Option<&NodeContactInfo> {
		if let Some(index) = self.connections.iter().position(|n| &n.address == address) {
			return Some(&self.connections[index]);
		}
		if let Some(index) = self
			.fingers
			.iter()
			.position(|f| &f.node_info.address == address)
		{
			return Some(&self.fingers[index].node_info);
		}
		None
	}

	/// The fingers that can be tried ourself
	pub fn private_fingers(&self) -> impl Iterator<Item = &NodeContactInfo> {
		self.replacement_cache
			.iter()
			.map(|e| &e.finger.node_info)
			.chain(self.public_fingers())
	}

	pub fn private_fingers2(&self) -> Vec<NodeContactInfo> {
		self.private_fingers().map(|f| f.clone()).collect()
	}

	pub fn mark_obtained_value(&mut self, address: &NodeAddress) {
		if let Some(entry) = self
			.fingers
			.iter_mut()
			.find(|e| &e.node_info.address == address)
		{
			entry.values_obtained += 1;
		}
	}

	pub fn mark_helpful(&mut self, node_info: &NodeContactInfo, trust_score: u8, is_relay: bool) {
		match self
			.fingers
			.iter()
			.position(|f| f.node_info.address == node_info.address)
		{
			// If the finger already exists in this bucket, just update its contact info with the
			// latest contact info
			Some(index) => {
				self.fingers[index]
					.node_info
					.contact_info
					.merge(&node_info.contact_info);
			}
			// If the finger is not in this bucket, check if it is in the replacement cache
			None => {
				match self
					.replacement_cache
					.iter()
					.position(|f| &f.finger.node_info.address == &node_info.address)
				{
					// If not in the replacement cache, just add it to our bucket
					None => {
						self.remember(node_info.clone(), trust_score, is_relay);
					}
					// If it is in our replacement cache, add it back
					Some(index) => {
						let finger = self.replacement_cache.remove(index).unwrap().finger;
						self.remember(finger.node_info, trust_score, is_relay);
					}
				}
			}
		}
	}

	pub fn mark_problematic(&mut self, address: &NodeAddress) -> bool {
		let mut removed = false;
		match self
			.fingers
			.iter()
			.position(|f| &f.node_info.address == address)
		{
			None => {}
			Some(index) => {
				// Move contact to the replacement cache if there is room
				if let Some(finger) = self.fingers.remove(index) {
					if self.replacement_cache.has_space() {
						self.replacement_cache.push_front(BucketReplacementEntry {
							finger,
							failed_attempts: 1,
						});
					}
				}
				// Otherwise, increase the failed attempt counter if it is in the replacement cache
				else if let Some(index) = self
					.replacement_cache
					.iter()
					.position(|e| &e.finger.node_info.address == address)
				{
					let entry = &mut self.replacement_cache[index];
					entry.failed_attempts += 1;
					if entry.failed_attempts == 3 {
						self.replacement_cache.remove(index);
						removed = true;
					}
				}
			}
		}
		removed
	}

	pub fn reject(&mut self, address: &NodeAddress) {
		match self.connections.iter().position(|n| &n.address == address) {
			None => {}
			Some(index) => {
				self.connections.remove(index);
			}
		}

		match self
			.fingers
			.iter()
			.position(|f| &f.node_info.address == address)
		{
			None => {}
			Some(index) => {
				self.fingers.remove(index);
			}
		}

		match self
			.replacement_cache
			.iter()
			.position(|f| &f.finger.node_info.address == address)
		{
			None => {}
			Some(index) => {
				self.replacement_cache.remove(index);
			}
		}
	}

	pub fn new(size: usize) -> Self {
		Self {
			connections: LimitedVec::new(size),
			fingers: LimitedVec::new(size),
			replacement_cache: LimitedVec::new(size),
		}
	}

	pub fn remember(&mut self, node: NodeContactInfo, trust_score: u8, is_relay: bool) -> bool {
		let new_entry = BucketEntry::new(node, trust_score, is_relay);

		// Try to add it above an exististing entry if it has higher priority
		if let Some(pos) = self.fingers.iter().rev().position(|e| &new_entry < e) {
			self.fingers.insert(pos, new_entry);
			return true;
		}

		// Otherwise, add it to the bottom (only if space is available)
		if self.fingers.len() < self.fingers.limit() {
			self.fingers.push_back(new_entry);
			return true;
		}

		false
	}

	pub fn remove_connection(&mut self, address: &NodeAddress) -> bool {
		if let Some(index) = self.connections.iter().position(|n| &n.address == address) {
			self.connections.remove(index);
			true
		} else {
			false
		}
	}
}

impl BucketEntry {
	pub fn new(finger: NodeContactInfo, trust_score: u8, is_relay: bool) -> Self {
		Self {
			node_info: finger,
			trust_score,
			values_obtained: 0,
			is_relay,
		}
	}
}

impl PartialEq for BucketEntry {
	fn eq(&self, other: &Self) -> bool {
		self.trust_score == other.trust_score && self.values_obtained == other.values_obtained
	}
}

impl PartialOrd for BucketEntry {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		// Trusted > untrusted
		if self.trust_score > other.trust_score {
			return Some(Ordering::Greater);
		} else if self.trust_score < other.trust_score {
			return Some(Ordering::Less);
		}

		// Compare connection options
		let result = self
			.node_info
			.contact_info
			.score()
			.partial_cmp(&other.node_info.contact_info.score());
		if result != Some(Ordering::Equal) {
			return result;
		}

		// Prioritize nodes that are a relay
		if self.is_relay {
			if !other.is_relay {
				return Some(Ordering::Greater);
			}
		} else {
			if other.is_relay {
				return Some(Ordering::Less);
			}
		}

		// Compare values obtained
		self.values_obtained.partial_cmp(&other.values_obtained)
	}
}

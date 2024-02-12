use std::{cmp::Ordering, sync::Arc};

use tokio::sync::Mutex;

use super::{distance, sstp::Connection, NodeContactInfo};
use crate::{common::*, limited_store::LimitedVec};


pub struct Bucket {
	pub(super) connections: LimitedVec<(NodeContactInfo, Arc<Mutex<Box<Connection>>>)>,
	fingers: LimitedVec<BucketEntry>,
	replacement_cache: LimitedVec<BucketReplacementEntry>,
}

#[derive(Clone)]
struct BucketEntry {
	node_info: NodeContactInfo,
	trusted: bool,
	is_relay: bool,
	values_obtained: u32,
}

#[derive(Clone)]
pub struct BucketReplacementEntry {
	finger: BucketEntry,
	failed_attempts: u8,
}


impl Bucket {
	pub fn add_connection(&mut self, our_node_id: &IdType, connection: Box<Connection>) -> bool {
		let new_node_info = connection.their_node_info();
		let new_distance = distance(our_node_id, &new_node_info.node_id);

		if let Some(pos) = self
			.connections
			.iter()
			.position(|(n, _)| new_distance < distance(our_node_id, &n.node_id))
		{
			let node_info = new_node_info.clone();
			let mutex = Arc::new(Mutex::new(connection));
			self.connections.insert(pos, (node_info, mutex));
			true
		} else if self.connections.len() < self.connections.limit() {
			let node_info = new_node_info.clone();
			let mutex = Arc::new(Mutex::new(connection));
			self.connections.push_back((node_info, mutex));
			true
		} else {
			false
		}
	}

	pub fn space_for_connection(
		&mut self, our_node_id: &IdType, connection_node_id: &IdType,
	) -> bool {
		if self.connections.len() < self.connections.limit() {
			return true;
		}

		let new_distance = distance(our_node_id, connection_node_id);
		if self
			.connections
			.iter()
			.position(|(n, _)| new_distance < distance(our_node_id, &n.node_id))
			.is_some()
		{
			true
		} else {
			false
		}
	}

	/// The fingers that can given to other nodes
	pub fn public_fingers(&self) -> impl Iterator<Item = &NodeContactInfo> {
		self.connections
			.iter()
			.map(|e| &e.0)
			.chain(self.fingers.iter().map(|e| &e.node_info))
	}

	/// The fingers that can given to other nodes
	pub fn public_fingers2(&self) -> Vec<NodeContactInfo> {
		self.public_fingers().map(|f| f.clone()).collect()
	}

	/// The fingers that can given to other nodes
	pub fn public_fingers_no_connection(&self) -> impl Iterator<Item = &NodeContactInfo> {
		self.fingers.iter().map(|e| &e.node_info)
	}

	pub fn find(&self, id: &IdType) -> Option<&NodeContactInfo> {
		if let Some(index) = self.connections.iter().position(|c| &c.0.node_id == id) {
			return Some(&self.connections[index].0);
		}
		if let Some(index) = self.fingers.iter().position(|f| &f.node_info.node_id == id) {
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

	pub fn mark_obtained_value(&mut self, node_id: &IdType) {
		if let Some(entry) = self
			.fingers
			.iter_mut()
			.find(|e| &e.node_info.node_id == node_id)
		{
			entry.values_obtained += 1;
		}
	}

	pub fn mark_helpful(&mut self, node_info: &NodeContactInfo, trusted: bool, is_relay: bool) {
		match self
			.fingers
			.iter()
			.position(|f| f.node_info.node_id == node_info.node_id)
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
					.position(|f| &f.finger.node_info.node_id == &node_info.node_id)
				{
					// If not in the replacement cache, just add it to our bucket
					None => {
						self.remember(node_info.clone(), trusted, is_relay);
					}
					// If it is in our replacement cache, add it back
					Some(index) => {
						let finger = self.replacement_cache.remove(index).unwrap().finger;
						self.remember(
							finger.node_info,
							finger.trusted || trusted,
							finger.is_relay || is_relay,
						);
					}
				}
			}
		}
	}

	pub fn mark_problematic(&mut self, id: &IdType) -> bool {
		let mut removed = false;
		match self.fingers.iter().position(|f| &f.node_info.node_id == id) {
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
					.position(|e| &e.finger.node_info.node_id == id)
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

	pub fn reject(&mut self, id: &IdType) {
		match self.connections.iter().position(|c| &c.0.node_id == id) {
			None => {}
			Some(index) => {
				self.connections.remove(index);
			}
		}

		match self.fingers.iter().position(|f| &f.node_info.node_id == id) {
			None => {}
			Some(index) => {
				self.fingers.remove(index);
			}
		}

		match self
			.replacement_cache
			.iter()
			.position(|f| &f.finger.node_info.node_id == id)
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

	fn pop_front(&mut self) -> bool {
		if self.fingers.len() == 0 {
			return false;
		}
		self.fingers.pop_front();
		true
	}

	pub fn remember(&mut self, node: NodeContactInfo, trusted: bool, is_relay: bool) -> bool {
		let new_entry = BucketEntry::new(node, trusted, is_relay);

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

	/// Returns a finger that can be tried out to check if
	pub fn test_space(&self) -> Option<&NodeContactInfo> {
		if self.fingers.len() < self.fingers.limit() as usize {
			return None;
		}

		Some(&self.fingers[0].node_info)
	}

	/// Updates the node info currently saved in the bucket.
	/// Returns (already_existing, updated)
	pub fn update(&mut self, node_info: &NodeContactInfo) -> (bool, bool) {
		match self
			.fingers
			.iter_mut()
			.position(|f| f.node_info.node_id == node_info.node_id)
		{
			None => (false, false),
			Some(index) => {
				let old = self.fingers[index].node_info.contact_info.clone();
				let different = old != node_info.contact_info;
				if different {
					self.fingers[index]
						.node_info
						.contact_info
						.merge(&node_info.contact_info);
				}
				(true, different)
			}
		}
	}
}

impl BucketEntry {
	pub fn new(finger: NodeContactInfo, trusted: bool, is_relay: bool) -> Self {
		Self {
			node_info: finger,
			trusted,
			values_obtained: 0,
			is_relay,
		}
	}
}

impl PartialEq for BucketEntry {
	fn eq(&self, other: &Self) -> bool {
		self.trusted == other.trusted && self.values_obtained == other.values_obtained
	}
}

impl PartialOrd for BucketEntry {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		// Trusted > untrusted
		if self.trusted {
			if !other.trusted {
				return Some(Ordering::Greater);
			}
		} else {
			if other.trusted {
				return Some(Ordering::Less);
			}
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

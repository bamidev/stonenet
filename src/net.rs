//! This module covers the funcionality of the collective network. The
//! collective network is basically a 'Kademlia' DHT network with Proof-of-Work
//! requirements to protect against Sybil attacks.
//! 
//! The collective network stores currently available peers for a particular
//! actor network. Most notably, a few of the top ones of the network tree.

mod actor;
mod actor_store;
mod bincode;
pub mod exchange_manager;
mod message;
mod object;
pub mod overlay;


use crate::{
	common::*,
	//identity::*,
	limited_store::LimitedVec,
	net::{
		exchange_manager::ExchangeManager,
		message::*
	}
};

use std::{
	collections::VecDeque,
	io,
	net::SocketAddr,
	sync::Arc,
	time::{Duration, SystemTime}
};

use async_recursion::async_recursion;
use async_trait::async_trait;
//use futures::future::join_all;
use log::*;
use num::BigUint;
use serde::{
	Serialize,
	Deserialize
};
use tokio::sync::Mutex;


/// Size of the 'k-buckets'
pub const KADEMLIA_K: u32 = 4;
/// Is 160 bits on paper, but we expanded it to 256.
pub const KADEMLIA_BITS: usize = 256;

// Messages for the overlay network:
pub const NETWORK_MESSAGE_TYPE_ID_PING_REQUEST: u8 = 0;
pub const NETWORK_MESSAGE_TYPE_ID_PING_RESPONSE: u8 = 1;
pub const NETWORK_MESSAGE_TYPE_ID_FIND_NODE_REQUEST: u8 = 2;
pub const NETWORK_MESSAGE_TYPE_ID_FIND_NODE_RESPONSE: u8 = 3;

// Messages for the feed subnetworks:
/// Asks node to relay a request/response exchage for you. Generally will only
/// be allowed by nodes that trust you directly.
pub const FEED_MESSAGE_TYPE_ID_PROXY_REQUEST: u8 = 4;
pub const FEED_MESSAGE_TYPE_ID_PROXY_RESPONSE: u8 = 5;
/// A message that notifies a node of the existance of a new post.
pub const FEED_MESSAGE_ID_BROADCAST_POST_REQUEST: u8 = 6;
pub const FEED_MESSAGE_ID_BROADCAST_POST_RESPONSE: u8 = 7;
/// Asks a node their last known post id.
pub const FEED_MESSAGE_ID_LATEST_POST_REQUEST: u8 = 8;
pub const FEED_MESSAGE_ID_LATEST_POST_RESPONSE: u8 = 9;
/// To find the hashes of the files of the post
pub const FEED_MESSAGE_ID_FIND_POST_REQUEST: u8 = 10;
pub const FEED_MESSAGE_ID_FIND_POST_RESPONSE: u8 = 11;
/// To find the hashes of the blocks of a file
pub const FEED_MESSAGE_ID_FIND_FILE_REQUEST: u8 = 12;
pub const FEED_MESSAGE_ID_FIND_FILE_RESPONSE: u8 = 13;
/// To download the data for a block
pub const FEED_MESSAGE_ID_FIND_BLOCK_REQUEST: u8 = 14;
pub const FEED_MESSAGE_ID_FIND_BLOCK_RESPONSE: u8 = 15;

const NODE_COMMUNICATION_TTL: u32 = 64;
const NODE_COMMUNICATION_TIMEOUT: u32 = 2;
const MINIMUM_PING_INTERVAL: u32 = 60000;


pub struct AllFingersIter<'a> {
	global_index: usize,
	bucket_index: usize,
	buckets: &'a Vec<Mutex<Bucket>>
}

type SerializedNodeId = [u8; 32];

// TODO: Use k>1, and keep prioritize the nodes with the best ping & uptime.
#[derive(Clone, Default)]
struct Bucket {
	main: VecDeque<BucketEntry>,
	/// Contact information for a node that has stayed with us the longest, as
	/// a stable alternative to fall back to.
	backup: Option<BucketEntry>
}

#[derive(Clone)]
struct BucketEntry {
	contact_info: NodeContactInfo,
	last_ping: SystemTime
}

pub struct Node<I> where I: NodeInterface + Send {
	pub node_id: IdType,
	buckets: Vec<Mutex<Bucket>>,
	interface: I
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeContactInfo {
	address: SocketAddr,
	node_id: IdType
}

#[derive(Default, Serialize, Deserialize)]
struct RequestHeader {
	sender_node_id: IdType
}

#[async_trait]
pub trait NodeInterface {

	async fn respond(&self,
		target: &SocketAddr,
		message_type_id: u8,
		exchange_id: u32,
		message: &[u8]
	) -> io::Result<()>;

	async fn request(&self,
		target: &SocketAddr,
		message_id: u8,
		request: &[u8]
	) -> io::Result<(IdType, Vec<u8>)>;
}


/// Calculates the distance between two hashes.
fn distance(a: &IdType, b: &IdType) -> BigUint {
	// Calculating this is a bit weird, because the first bit (0x01) of the first byte
	// is the most significant. In big-endian encoding, the last bit (0x80) of
	// the first byte would be the most significant.
	let mut c = IdType::default();
	for i in 0..32 {
		let mut ci = &mut c.0[i];
		*ci = a.0[i] ^ b.0[i];
		// Mirror the bits
		*ci =
			( *ci         << 7) |
			((*ci & 0x02) << 5) |
			((*ci & 0x04) << 3) |
			((*ci & 0x08) << 1) |
			((*ci & 0x10) >> 1) |
			((*ci & 0x20) >> 3) |
			((*ci & 0x40) >> 5) |
			( *ci         >> 7) 
	}
	BigUint::from_bytes_be(&c.0)
}


#[async_trait]
impl<'a> AsyncIterator for AllFingersIter<'a> {
	type Item = NodeContactInfo;

	async fn next(&mut self) -> Option<NodeContactInfo> {
		while self.global_index < self.buckets.len() {
			let bucket = self.buckets[self.global_index].lock().await;
			if self.bucket_index < bucket.main.len() {
				let result = Some(bucket.main[self.bucket_index].contact_info.clone());
				self.bucket_index += 1;
				return result;
			}
			else if self.bucket_index == bucket.main.len() {
				self.bucket_index = 0;
				self.global_index += 1;
				match bucket.backup.as_ref() {
					None => {},
					Some(e) => return Some(e.contact_info.clone())
				}
			}
			else { panic!("Unreachable"); }
		}
		None
	}
}

impl Bucket {
	fn new() -> Self {
		Self {
			main: VecDeque::new(),
			backup: None
		}
	}
}

impl From<NodeContactInfo> for BucketEntry {
	fn from(contact_info: NodeContactInfo) -> Self {
		Self {
			contact_info,
			last_ping: SystemTime::now()
		}
	}
}

impl<I> Node<I> where I: NodeInterface + Send + Sync {
	fn differs_at_bit(a: &IdType, b: &IdType) -> Option<u8> {
		for i in 0..32 {
			let x = Self::differs_at_bit_u8(a.0[i] as _, b.0[i] as _) as usize;
			if x < 8 {
				return Some((i*8 + x) as u8);
			}
		}
		None
	}

	/// If the bytes differ, returns the index of the bit (little endian),
	/// otherwise, returns 0xFF indicating no change
	fn differs_at_bit_u8(a: u8, b: u8) -> u8 {
		let x = a ^ b;
		for i in 0..8 {
			if ((x >> i) & 0x1) != 0 {
				return i;
			}
		}
		return 0xFF;
	}

	/// Finds the k nodes nearest to the given id. If it can't find k fingers that
	/// are closer to the id than this node is, it will supplement with nodes
	/// that are farther away.
	async fn find_nearest_fingers(&self, id: &IdType) -> Vec<NodeContactInfo> {
		let bucket_pos = match Self::differs_at_bit(&self.node_id, id) {
			// If ID is the same as ours, don't give any other contacts
			None => return Vec::new(),
			Some(p) => p as usize
		};
		let mut fingers = Vec::with_capacity(KADEMLIA_K as _);

		// Return the fingers of the first non-empty bucket lowest in the
		// binary tree.
		for i in (0..(bucket_pos+1)).rev() {
			let additional_fingers: Vec<NodeContactInfo> = {
				let bucket = self.buckets[i].lock().await;
				bucket.main.iter()
					.map(|e| e.contact_info.clone())
					.collect()
			};

			let remaining = KADEMLIA_K as usize - fingers.len();
			if remaining <= additional_fingers.len() {
				fingers.extend_from_slice(&additional_fingers[0..remaining]);
			}
			else {
				fingers.extend_from_slice(&additional_fingers);
			}

			if fingers.len() >= KADEMLIA_K as usize {
				return fingers;
			}
		}

		fingers
	}

	pub async fn find_node(&self,
		id: &IdType,
		result_limit: usize,
		hop_limit: usize,
		only_narrow_down: bool
	) -> Vec<NodeContactInfo> {
		let fingers = self.find_nearest_fingers(id).await;
		if fingers.len() == 0 { return Vec::new(); }
		self.find_node_from_fingers(
			id,
			&fingers,
			result_limit,
			hop_limit, 
			only_narrow_down
		).await
	}

	/// Gets the k closest nodes it can find to the given id.
	/// `fingers` - The nodes to start searching at.
	/// `hop_limit` - The maximum number of hops to make. It may go over it,
	///     but not more than k times.
	/// `only_narrow_down` - Whether to only look for nodes that are closer to
	///     the target than the previous node. If set to `false`, will only
	///     continue with nodes that are further away if none other can be
	///     found. Keep in mind that setting this to `false` is very
	///     ineffecient.
	/*pub async fn find_node_from_fingers(&self,
		id: &IdType,
		result_limit: usize,
		fingers: &[NodeContactInfo],
		hop_limit: usize,
		only_narrow_down: bool
	) -> Vec<NodeContactInfo> {
		let mut visited = Vec::with_capacity(hop_limit);
		let mut found = LimitedVec::new(result_limit);
		let initial_distance = distance(id, &self.node_id);
		for finger in fingers.iter().rev() {
			if distance(id, &finger.node_id) < initial_distance {
				found.push_front(finger.clone());
			}
		}

		self._find_node_from_fingers(id, fingers, true, &mut visited, hop_limit, &mut found).await;
		found.into()
	}*/

	/*async fn _find_node_from_fingers(&self,
		id: &IdType,
		fingers: &[NodeContactInfo],
		visited: &mut Vec<SocketAddr>,
		visited_limit: usize,
		found: &mut LimitedVec<NodeContactInfo>
	) {
		let current_distance = if found.len() == 0 {
			distance(id, &self.node_id)
		}
		else {
			distance(id, &found[0].node_id)
		};
		for finger in fingers {
			// Don't try nodes that have already been visited
			if visited.contains(&finger.address) {
				continue
			}
			visited.push(finger.address.clone());

			let result = match self.request_find_node(&finger.address, &id).await {
				Err(e) => {},
				Ok(response) => {
					let mut sub_fingers = response.fingers;
					// Don't use the fingers that are further away if narrowing down
					sub_fingers.retain(|f| {
						distance(&f.node_id, &self.node_id) < current_distance &&
						!visited.contains(&f.address)
					});
					if sub_fingers.len() == 0 { continue }
					// Start with the closest one first
					sub_fingers.sort_by(|a, b| {
						distance(&a.node_id, &self.node_id).cmp(
							&distance(&b.node_id, &self.node_id)
						)
					});
					// Add to found list if closer
					for sub_finger in sub_fingers.iter().rev() {
						found.push_front(sub_finger.clone());
					}

					// Only go deeper if we haven't reached our limit yet.
					if (visited.len() + sub_fingers.len()) < visited_limit {
						self._find_node_from_fingers(
							id,
							&sub_fingers,
							narrowing_down,
							visited,
							visited_limit,
							found
						);
					}
				}
			};
		}
	}*/

	// TODO: Add a `impl Fn` argument that validates and deserializes the data.
	/*pub async fn find_value_from_fingers(&self,
		id: &IdType,
		message_type_id: u8,
		fingers: &[NodeContactInfo],
		hop_limit: usize
	) -> Option<Vec<u8>> {
		let mut visited = Vec::with_capacity(hop_limit);
		let initial_distance = distance(id, &self.node_id);
		error!("INITIAL Dist: {}", initial_distance);
		error!("TEST: {} {}", id, &self.node_id);
		self._find_value_from_fingers(
			id,
			message_type_id,
			fingers,
			&mut visited,
			hop_limit,
			&initial_distance
		).await
	}*/

	fn append_candidates(id: &IdType, candidates: &mut VecDeque<(BigUint, NodeContactInfo)>, fingers: &[NodeContactInfo]) {
		for finger in fingers {
			Self::insert_candidate(id, candidates, finger);
		}
	}

	fn insert_candidate(id: &IdType, candidates: &mut VecDeque<(BigUint, NodeContactInfo)>, finger: &NodeContactInfo) {
		let distance = distance(id, &finger.node_id);
		for i in 0..candidates.len() {
			let candidate_distance = &candidates[i].0;
			if &distance < candidate_distance {
				candidates.insert(i, (distance, finger.clone()));
				return;
			}
		}
		candidates.push_back((distance, finger.clone()));
	}

	fn sort_fingers(id: &IdType, fingers: &[NodeContactInfo]) -> VecDeque<(BigUint, NodeContactInfo)> {
		let mut fingers2 = Vec::<(BigUint, NodeContactInfo)>::with_capacity(fingers.len() * 2);
		fingers2 = fingers.into_iter().map(|f| {
			let dist = distance(id, &f.node_id);
			(dist, f.clone())
		}).collect();
		fingers2.sort_by(|a, b| a.0.cmp(&b.0));
		let mut candidates = VecDeque::with_capacity(fingers.len());
		candidates.extend(fingers2);
		candidates
	}

	pub async fn find_node_from_fingers(&self,
		id: &IdType,
		fingers: &[NodeContactInfo],
		result_limit: usize,
		visit_limit: usize,
		narrow_down: bool
	) -> Vec<NodeContactInfo> {
		let mut visited = Vec::<SocketAddr>::new();
		let mut candidates = Self::sort_fingers(id, fingers);
		let mut found = LimitedVec::<NodeContactInfo>::new(result_limit);
		let mut shortest_distance = BigUint::from_slice(&[
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
			0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
		]);
		
		let mut i = 0;
		while candidates.len() > 0 && i < visit_limit {
			let (dist, candidate_contact) = &candidates[0];
			if visited.contains(&candidate_contact.address) {
				candidates.pop_front();
				continue;
			}
			visited.push(candidate_contact.address.clone());
			if dist < &shortest_distance {
				found.push_front(candidate_contact.clone());
				shortest_distance = dist.clone();
			}

			match self.request_find_node(
				&candidate_contact.address,
				&id
			).await {
				Err(e) => warn!("Disregarding finger {} due to error: {}", &candidate_contact.address, e),
				Ok(response) => {
					let mut new_fingers = response.fingers;
					if narrow_down {
						new_fingers.retain(|f| &distance(id, &f.node_id) < &dist);
					}
					Self::append_candidates(id, &mut candidates, &new_fingers);
				}
			}
			i += 1;
		}
		found.into()
	}

	pub async fn find_value_from_fingers(&self,
		id: &IdType,
		message_type_id: u8,
		fingers: &[NodeContactInfo],
		visit_limit: usize,
		narrow_down: bool,
		do_verify: impl Fn(&IdType, &[u8]) -> bool
	) -> Option<Vec<u8>> {
		let mut visited = Vec::<SocketAddr>::with_capacity(visit_limit);
		let mut candidates = Self::sort_fingers(id, fingers);
		
		let mut i = 0;
		while candidates.len() > 0 && i < visit_limit {
			let (dist, candidate_contact) = &candidates[0];
			if visited.contains(&candidate_contact.address) {
				candidates.pop_front();
				continue;
			}
			visited.push(candidate_contact.address.clone());

			match self.request_find_value(
				&candidate_contact.address,
				&id,
				message_type_id
			).await {
				Err(e) => warn!("Disregarding finger {} due to error: {}", &candidate_contact.address, e),
				Ok(response) => {
					match response {
						// If node returned new nodes, append them to the candidate list
						Err(mut new_fingers) => {
							if narrow_down {
								new_fingers.retain(|f| &distance(id, &f.node_id) < dist);
							}
							Self::append_candidates(id, &mut candidates, &new_fingers);
						}
						Ok(value) => {
							if do_verify(id, &value) {
								return Some(value)
							}
							// If data is invalid, skip candidate
							else {
								continue;
							}
						}
					}
				}
			}
			i += 1;
		}
		None
	}
	
	/*#[async_recursion]
	async fn _find_value_from_fingers(&self,
		id: &IdType,
		message_type_id: u8,
		fingers: &[NodeContactInfo],
		visited: &mut Vec<SocketAddr>,
		visited_limit: usize,
		current_distance: &BigUint
	) -> Option<(Vec<u8>, usize)> {
		error!("NEXT Dist: {}", current_distance);
		
		for finger in fingers {
			// Don't try nodes that have already been visited
			if visited.contains(&finger.address) {
				error!("Already visited");
				continue
			}
			visited.push(finger.address.clone());

			let result = match self.request_find_value(
				&finger.address,
				&id,
				message_type_id
			).await {
				Err(e) => error!(
					"Disregarding finger {} due to error: {}",
					&finger.address,
					e
				),
				Ok(response) => {
					let mut sub_fingers = match response {
						Err(f) => f,
						Ok(value) => {
							error!("Found");
							// TODO: Verify data by checking hash/id
							return (Some(value), KADEMLIA_K);
						}
					};
					// Don't use the fingers that are further away
					sub_fingers.retain(|f| {
						distance(&f.node_id, &self.node_id) < *current_distance &&
						!visited.contains(&f.address)
					});
					if sub_fingers.len() == 0 { error!("Finger got nothing"); continue }
					// Start with the closest one first
					sub_fingers.sort_by(|a, b| {
						distance(&a.node_id, &self.node_id).cmp(
							&distance(&b.node_id, &self.node_id)
						)
					});

					// Only go deeper if we haven't reached our limit yet.
					if (visited.len() + sub_fingers.len()) < visited_limit {
						let result = self._find_value_from_fingers(
							id,
							message_type_id,
							&sub_fingers,
							narrowing_down,
							visited,
							visited_limit,
							&distance(&sub_fingers[0].node_id, id)
						).await;
						match result {
							None => {},
							Some((value, mut duplicates)) => {
								// If a value is found, try to duplicate the
								// value at nodes that are slightly less close.
								if duplicates > 0 {
									for sub_finger in sub_fingers {
										if duplicates > 0 {
											tokio::spawn(async {
												self.base.request_store_actor(

												).await:
											});
											duplicates -= 1;
										}
									}
								}
								return (value, duplicates)
							}
						}
					}
				}
			};
		}
		error!("End none");
		None
	}*/

	pub fn iter_all_fingers(&self) -> AllFingersIter<'_> {
		AllFingersIter { global_index: 0, bucket_index: 0, buckets: &self.buckets }
	}

	pub fn new(node_id: IdType, interface: I) -> Self {
		let mut buckets = Vec::with_capacity(KADEMLIA_BITS);
		for _ in 0..KADEMLIA_BITS {
			buckets.push(Mutex::new(Bucket::new()));
		}

		Self {
			node_id,
			buckets,
			interface
		}
	}

	/// Pings a node and returns its latency and node ID .
	pub async fn ping(&self, target: &SocketAddr) -> io::Result<(u32, IdType)> {
		debug!("Pinging {}...", target);
		let start = SystemTime::now();
		let node_id = self.request_ping(target).await?;
		let stop = SystemTime::now();
		let latency = stop.duration_since(start).unwrap().as_millis() as u32;
		Ok((latency, node_id))
	}

	/// Removes the node from our k-buckets. Returns false if the node wasn't in
	/// our k-buckets.
	async fn reject_node(&self, address: &SocketAddr) -> bool {
		debug!("Rejecting node {}.", address);
		for bucket_mutex in self.buckets.iter() {
			let mut bucket = bucket_mutex.lock().await;
			let mut index: usize = usize::MAX;
			for i in 0..bucket.main.len() {
				if bucket.main[i].contact_info.address == *address {
					index = i;
					break;
				}
			}
			if index != usize::MAX {
				bucket.main.remove(index);
				return true;
			}
			else {
				match &bucket.backup {
					None => {},
					Some(b) => {
						if b.contact_info.address == *address {
							bucket.backup = None;
							return true;
						}
					}
				}
			}
		}
		false
	}

	/// Puts the given node somewhere in one of the buckets if there is a spot
	/// available.
	/// This method can block for quite a while, as it exchanges requests.
	/// Normally speaking, you'd want to spawn this off to execute on the side.
	async fn remember_node(self: &Arc<Self>, contact_info: NodeContactInfo) {
		let bucket_pos = match Self::differs_at_bit(&self.node_id, &contact_info.node_id) {
			None => {
				warn!("Found same node ID as us, ignoring...");
				return;
			},
			Some(p) => p as usize
		};

		let mut bucket = self.buckets[bucket_pos].lock().await;

		// If peer is already in our bucket, only update node id
		match bucket.main.iter()
			.position(|e| e.contact_info.address == contact_info.address)
		{
			None => debug!("Remember node {}.", &contact_info.address),
			Some(index) => {
				bucket.main[index].contact_info.node_id = contact_info.node_id;
				debug!("Node ID updated for {}.", &contact_info.address);
				return;
			}
		}

		// If bucket is full, decide what to do after a ping
		if bucket.main.len() < KADEMLIA_K as usize {
			bucket.main.push_back(contact_info.into());
			return;
		}

		let mut front_node_is_alive = 
			SystemTime::now().duration_since(
				bucket.main[0].last_ping
			).unwrap() < Duration::from_millis(MINIMUM_PING_INTERVAL as _);
		if !front_node_is_alive {
			match self.ping(&bucket.main[0].contact_info.address).await {
				Err(e) => {},
				Ok(_) => front_node_is_alive = true
			}
		}
		if !front_node_is_alive {
			bucket.main.pop_front();
			bucket.main.push_back(contact_info.into());
			warn!("Replaced old peer with new peer.");
		}
		else {
			// Check if backup is still before we eject it
			let mut backup_node_is_alive = !bucket.backup.is_none() &&
				SystemTime::now().duration_since(
					bucket.backup.as_ref().unwrap().last_ping
				).unwrap() < Duration::from_millis(MINIMUM_PING_INTERVAL as _);
			if !backup_node_is_alive {
				match self.ping(&bucket.main[0].contact_info.address).await {
					Err(e) => {},
					Ok(_) => backup_node_is_alive = true
				}
			}
			if !backup_node_is_alive {
				bucket.backup = bucket.main.pop_front();
				warn!("Moved old peer to backup.");
			}
			else {
				bucket.main.pop_front();
				warn!("Replaced old peer with new peer.2 {} - {}", self.node_id.to_string(), contact_info.node_id.to_string());
			}
			bucket.main.push_back(contact_info.into());
		}
	}
	
	pub async fn request(&self,
		target: &SocketAddr,
		message_type_id: u8,
		buffer: &[u8]
	) -> io::Result<(IdType, Vec<u8>)> {
		let result = self.interface.request(target, message_type_id, buffer).await;
		
		// Reject the node from our routing table if it has proven
		// unresponsive.
		if !result.is_ok() {
			self.reject_node(target).await;
		}
		result
	}

	pub async fn request_find_x(&self,
		target: &SocketAddr,
		node_id: &IdType,
		message_type_id: u8
	) -> io::Result<Vec<u8>> {
		let request = FindNodeRequest {
			node_id: node_id.clone()
		};
		self.request(
			target,
			message_type_id,
			&bincode::serialize(&request).unwrap()
		).await.map(|r| r.1)
	}

	/// In the paper, this is described as the 'FIND_NODE' RPC.
	pub async fn request_find_node(&self,
		target: &SocketAddr,
		node_id: &IdType
	) -> io::Result<FindNodeResponse> {
		let response = self.request_find_x(target, node_id, NETWORK_MESSAGE_TYPE_ID_FIND_NODE_REQUEST).await?;
		bincode::deserialize(&response).map_err(|e| io::Error::new(
			io::ErrorKind::InvalidData,
			e
		))
	}

	pub async fn request_find_value(&self,
		target: &SocketAddr,
		node_id: &IdType,
		message_type_id: u8
	) -> io::Result<Result<Vec<u8>, Vec<NodeContactInfo>>> {
		let response = self.request_find_x(target, node_id, message_type_id).await?;
		if response[0] == 0 {
			return Ok(Ok(response[1..].to_vec()));
		}
		else if response[0] == 1 {
			return Ok(Err(bincode::deserialize(&response[1..]).map_err(|e| {
				error!("HOI");
				io::Error::new(
					io::ErrorKind::InvalidData,
					e
				)
			})?));
		}
		else {
			return Err(io::Error::from(io::ErrorKind::InvalidData));
		}
	}

	/// Pings a peer and returns whether it succeeded or not. A.k.a. the 'PING'
	/// RPC.
	async fn request_ping(&self,
		target: &SocketAddr
	) -> io::Result<IdType> {
		let message = PingRequest {};
		let result = self.request(
			target,
			NETWORK_MESSAGE_TYPE_ID_PING_REQUEST,
			&bincode::serialize(&message).unwrap()
		).await?;
		
		Ok(result.0)
	}
}

/*#[cfg(test)]
mod tests {
	use super::*;

#[test]
fn test_distance() {
	let a1 = IdType::from_base58("DSLVRnqejmzQXKmoZ4KtfvvGLBSFwKJxKEQxnXJq1A8b").unwrap();
	let a2 = IdType::from_base58("E7hinjgaQ7WfsNjos1FHYvHNCgHJfC9f29arA5QqtZw1").unwrap();
	assert!(distance(&a1, &a2) > 0.into());
}}
*/
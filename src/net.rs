//! This module covers the funcionality of the collective network. The
//! collective network is basically a 'Kademlia' DHT network with Proof-of-Work
//! requirements to protect against Sybil attacks.
//! 
//! The collective network stores currently available peers for a particular
//! actor network. Most notably, a few of the top ones of the network tree.

mod actor;
mod actor_store;
pub mod exchange_manager;
mod message;
mod object;
pub mod overlay;


use crate::{
	common::*,
	//identity::*,
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

use async_trait::async_trait;
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

pub struct Node<I> where I: NodeInterface {
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


// FIXME: Is the double clone really necessary?
fn distance(a: &IdType, b: &IdType) -> BigUint {
	let mut c = IdType::default();
	for i in 0..32 {
		c.0[i] = a.0[i] ^ b.0[i];
	}
	BigUint::from_bytes_be(&c.0)
}


#[async_trait]
impl<'a> AsyncIterator for AllFingersIter<'a> {
	type Item = NodeContactInfo;

	async fn next(&mut self) -> Option<NodeContactInfo> {
		if self.global_index < self.buckets.len() {
			let bucket = self.buckets[self.global_index].lock().await;
			if self.bucket_index < bucket.main.len() {
				let result = Some(bucket.main[self.bucket_index].contact_info.clone());
				self.bucket_index += 1;
				result
			}
			else if self.bucket_index == bucket.main.len() {
				self.bucket_index = 0;
				self.global_index += 1;
				bucket.backup.as_ref().map(|e| e.contact_info.clone())
			}
			else { None }
		}
		else { None }
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

impl<I> Node<I> where I: NodeInterface {
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

	/// Finds the nodes nearest to the given id. Doesn't include its own node_id
	/// in the lookup.
	async fn find_nearest_fingers(&self, id: &IdType) -> Vec<NodeContactInfo> {
		let bucket_pos = match Self::differs_at_bit(&self.node_id, id) {
			// If ID is the same as ours, don't give any other contacts
			None => return Vec::new(),
			Some(p) => p as usize
		};

		// Return the fingers of the first non-empty bucket lowest in the
		// binary tree.
		for i in (0..(bucket_pos+1)).rev() {
			let bucket = self.buckets[i].lock().await;
			if bucket.main.len() > 0 {
				return bucket.main.iter().map(|e| e.contact_info.clone()).collect()
			}
		}

		// When nothing was found, return empty list
		Vec::new()
	}

	/// Keeps making FIND_NODE requests until the node has been found
	pub async fn find_nearest_nodes(&self, id: &IdType) -> Vec<NodeContactInfo> {
		let mut fingers = self.find_nearest_fingers(id).await;
		if fingers.len() == 0 {
			warn!("Couldn't find nearest node because we don't have any fingers anymore.");
			return Vec::new();
		};

		let mut prev_fingers = Vec::new();
		while fingers.len() > 0 {
			if !fingers.iter().map(|f| &f.node_id).find(|id| id == &&self.node_id).is_none() {
				return fingers;
			}
			prev_fingers = fingers;
			fingers = self.find_node_from_fingers(id, &*prev_fingers).await;
		}

		// prev_fingers should contain the nearest nodes we could find.
		prev_fingers
	}

	/// Gets a new list of peers to contact to get closer to the given ID.
	/// Returns None if none of the given fingers responded, returns a
	/// (possibly) empty vector
	pub async fn find_node_from_fingers(&self, id: &IdType, fingers: &[NodeContactInfo]) -> Vec<NodeContactInfo> {
		for finger in fingers {
			let result = match self.request_find_node(&finger.address, &id).await {
				Err(e) => {},
				Ok(response) => return response.fingers
			};
		}

		Vec::new()
	}

	// FIXME: Make it so that this function always returns `max` number of contacts.
	pub async fn find_node_contacts(&self, node_id: &IdType, max: usize) -> Vec<NodeContactInfo> {
		// Keep finding new fingers until we have not been able to get any
		// closer to our own ID.
		let mut current_distance = distance(node_id, &self.node_id);
		let mut prev_fingers = self.find_nearest_fingers(node_id).await;
		let mut fingers = Vec::new();
		let mut i = 0;
		loop {
			fingers = self.find_node_from_fingers(&self.node_id, &*prev_fingers).await;
			// Our own node might be in their k-bucket already, so ignore that.
			// Also, check if all new fingers are actually closer, a malicious
			// node might put us off track.
			fingers.retain(|f| {
				f.node_id != self.node_id //&&
				//distance(&f.node_id, &self.node_id) < current_distance
			});
			if fingers.len() == 0 { break; }
			if i >= 64 {
				warn!("Loop detected!");
				return Vec::new();
			}
			// TODO: Maybe get shortest distance of all fingers? Or maybe not necessary.
			current_distance = distance(&fingers[0].node_id, &self.node_id);

			prev_fingers = fingers;
			i += 1;
		}

		prev_fingers
	}

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
		let start = SystemTime::now();
		let node_id = self.request_ping(target).await?;
		let stop = SystemTime::now();
		let latency = stop.duration_since(start).unwrap().as_millis() as u32;
		Ok((latency, node_id))
	}

	/// Removes the node from our k-buckets. Returns false if the node wasn't in
	/// our k-buckets.
	async fn reject_node(&self, address: &SocketAddr) -> bool {
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

		// If peer is already in our bucket, do nothing
		if !bucket.main.iter()
			.find(|e| e.contact_info.address == contact_info.address)
			.is_none()
		{ return }

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

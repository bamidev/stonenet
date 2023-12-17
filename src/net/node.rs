use std::{
	collections::{HashMap, VecDeque},
	ops::Deref,
	sync::{atomic::*, Arc},
	time::SystemTime,
};

use async_trait::async_trait;
use futures::future::{join_all, BoxFuture};
use log::*;
use num::BigUint;
use serde::de::DeserializeOwned;
use tokio::{
	spawn,
	sync::{oneshot, Mutex},
	time::sleep,
};

use super::{
	message::*,
	overlay::OverlayNode,
	sstp::{self, Connection},
	*,
};
use crate::{common::*, db, limited_store::LimitedVec};


const NODE_FINGER_MINIMUM_PING_DELAY: u64 = 60000;
const NODE_COMMUNICATION_TTL: u32 = 64;
const NODE_COMMUNICATION_TIMEOUT: u32 = 2;


pub struct AllFingersIter<'a> {
	global_index: usize,
	buckets: &'a Vec<Mutex<Bucket>>,
	bucket_iter: <Vec<NodeContactInfo> as IntoIterator>::IntoIter,
}

pub struct Bucket {
	pub(super) connection: Option<(NodeContactInfo, Arc<Mutex<Box<sstp::Connection>>>)>,
	fingers: LimitedVec<NodeContactInfo>,
	replacement_cache: LimitedVec<BucketReplacementEntry>,
}

#[derive(Clone, Debug)]
pub struct ContactStrategy {
	contact: ContactOption,
	method: ContactStrategyMethod,
}

#[derive(Clone)]
pub enum ContactStrategyMethod {
	Direct,
	// Punch a hole through a relay node for which a connection is provided.
	PunchHole,
	// TODO: Generally speaking, a contact strategy is not accessed from multiple threads. It is
	// just that the connection, once chosen, needs to be used across possibly another thread.
	// That's what the mutex is for. Check to see if this design can be made more efficient in
	// some way.
	Relay(Arc<Mutex<Box<Connection>>>),
}

#[derive(Clone)]
pub struct BucketReplacementEntry {
	finger: NodeContactInfo,
	failed_attempts: u8,
}

pub struct FindValueIter<'a, I>
where
	I: NodeInterface + Send + Sync,
{
	node: &'a Node<I>,
	overlay_node: Arc<OverlayNode>,
	expect_fingers_in_response: bool,

	id: IdType,
	value_type_id: u8,
	do_verify:
		Box<dyn Fn(&IdType, &NodeContactInfo, &[u8]) -> Option<AtomicPtr<()>> + Send + Sync + 'a>,
	narrow_down: bool,

	visited: Vec<(IdType, ContactOption)>,
	candidates: VecDeque<(BigUint, NodeContactInfo, ContactStrategy)>,
	connection_for_hole_punching: Option<(IdType, Box<Connection>)>,
	open_for_hole_punching: bool,
}

pub struct Node<I>
where
	I: NodeInterface,
{
	pub(super) stop_flag: Arc<AtomicBool>,
	pub(super) node_id: IdType,
	pub(super) buckets: Vec<Mutex<Bucket>>,
	pub(super) interface: I,
	pub(super) socket: Arc<sstp::Server>,
	pub(super) expected_connections:
		Arc<Mutex<HashMap<IdType, oneshot::Sender<Box<sstp::Connection>>>>>,
	pub(super) bucket_size: usize,
}

#[async_trait]
pub trait NodeInterface {
	async fn exchange(
		&self, connection: &mut Connection, message_type: u8, request: &[u8],
	) -> sstp::Result<Vec<u8>>;

	async fn find_value(&self, value_type: u8, id: &IdType) -> db::Result<Option<Vec<u8>>>;

	async fn send(
		&self, connection: &mut Connection, message_type: u8, request: &[u8],
	) -> sstp::Result<()>;

	async fn respond(
		&self, connection: &mut Connection, message_type: u8, message: &[u8],
	) -> sstp::Result<()>;

	async fn find_near_connection(&self, pos: u8) -> Option<NodeContactInfo>;
}

pub fn differs_at_bit(a: &IdType, b: &IdType) -> Option<u8> { a.differs_at_bit(b) }

impl ContactStrategy {
	/// Tries to construct a plan to contact the given target.
	/// If it is decided that we don't have any contact options, returns None.
	/// The hole punching strategy is only used when a connection is provided.
	fn new(
		connection: Option<&Arc<Mutex<Box<Connection>>>>, contact: ContactOption,
		openness: Openness,
	) -> Option<Self> {
		Some(Self {
			contact,
			method: match openness {
				Openness::Bidirectional => ContactStrategyMethod::Direct,
				Openness::Punchable => ContactStrategyMethod::PunchHole,
				Openness::Unidirectional => match connection {
					Some(c) => ContactStrategyMethod::Relay(c.clone()),
					None => return None,
				},
			},
		})
	}
}

impl fmt::Display for ContactStrategy {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}, {}", self.contact, self.method)
	}
}

impl ContactStrategyMethod {
	pub fn to_byte(&self) -> u8 {
		match self {
			Self::Direct => 0,
			Self::PunchHole => 1,
			Self::Relay(_) => 2,
		}
	}
}

impl PartialEq for ContactStrategyMethod {
	fn eq(&self, other: &Self) -> bool { self.to_byte() == other.to_byte() }
}

impl fmt::Debug for ContactStrategyMethod {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self) }
}

impl fmt::Display for ContactStrategyMethod {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Direct => write!(f, "direct"),
			Self::Relay(_) => write!(f, "relay"),
			Self::PunchHole => write!(f, "punch hole"),
		}
	}
}

impl<'a, I> FindValueIter<'a, I>
where
	I: NodeInterface + Send + Sync,
{
	pub fn visited(&self) -> &[(IdType, ContactOption)] { &self.visited }

	pub async fn close(&mut self) {
		if let Some((_, connection)) = self.connection_for_hole_punching.as_mut() {
			connection.close().await;
			self.connection_for_hole_punching = None;
		}
	}
}

#[cfg(debug_assertions)]
impl<'a, I> Drop for FindValueIter<'a, I>
where
	I: NodeInterface + Send + Sync,
{
	fn drop(&mut self) {
		if self.connection_for_hole_punching.is_some() {
			panic!("FindValueIter not closed before drop");
		}
	}
}

impl<I> Node<I>
where
	I: NodeInterface + Send + Sync,
{
	fn append_candidates(
		id: &IdType, candidates: &mut VecDeque<(BigUint, NodeContactInfo, ContactStrategy)>,
		fingers: &[(NodeContactInfo, ContactStrategy)],
	) {
		for finger in fingers {
			Self::insert_candidate(id, candidates, finger);
		}
	}

	fn bidirectional_contact_option(&self, target: &ContactInfo) -> Option<ContactOption> {
		self.socket.bidirectional_contact_option(target)
	}

	pub async fn connect(
		&self, target: &ContactInfo, node_id: Option<&IdType>,
	) -> Option<Box<Connection>> {
		if let Some((option, _)) = self.pick_contact_option(target) {
			self.connect_at(&option, node_id).await
		} else {
			None
		}
	}

	pub async fn connect_at(
		&self, target: &ContactOption, node_id: Option<&IdType>,
	) -> Option<Box<Connection>> {
		match node_id {
			Some(ni) => {
				let result = self.socket.connect(target, node_id).await;
				self.handle_connection_issue(result, ni, target).await
			}
			None => match self.socket.connect(target, node_id).await {
				Ok(c) => Some(c),
				Err(e) => {
					warn!("Unable to connect to {}: {}", target, e);
					None
				}
			},
		}
	}

	pub async fn connect_node(
		&self, node_id: &IdType, strategy: &ContactStrategy,
		last_open_connection: Option<&mut Connection>,
	) -> Option<Box<Connection>> {
		match &strategy.method {
			ContactStrategyMethod::Direct =>
				self.connect_at(&strategy.contact, Some(node_id)).await,
			ContactStrategyMethod::PunchHole => {
				if let Some(mut relay_connection) = last_open_connection {
					if let Some(target_connection) = self
						.punch_hole(&mut relay_connection, node_id, &strategy.contact)
						.await
					{
						Some(target_connection)
					} else {
						None
					}
				} else {
					None
				}
			}
			ContactStrategyMethod::Relay(_intermediary_connection) => {
				// TODO: Return some sort of wrapper that locks the mutex and provides the
				// connection
				None
			}
		}
	}

	pub async fn contact_info(&self) -> ContactInfo { self.socket.our_contact_info().await.clone() }

	pub fn differs_at_bit(&self, other_id: &IdType) -> Option<u8> {
		differs_at_bit(&self.node_id, other_id)
	}

	pub async fn exchange(
		&self, target: &NodeContactInfo, message_type_id: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		// Use an existing connection if possible
		if let Some(bucket) = self.find_bucket(&target.node_id).await {
			if let Some((connected_node_info, connection_lock)) =
				bucket.lock().await.connection.clone()
			{
				if target.node_id == connected_node_info.node_id {
					if let Ok(mut connection) = connection_lock.try_lock() {
						return self
							.handle_connection_issue2(
								self.interface
									.exchange(&mut connection, message_type_id, buffer)
									.await,
								&target.node_id,
								&target.contact_info,
							)
							.await;
					}
				}
			}
		}

		// If no existing connection already existed, open one
		let mut connection = self
			.connect(&target.contact_info, Some(&target.node_id))
			.await?;
		let result = self
			.interface
			.exchange(&mut connection, message_type_id, buffer)
			.await;
		if let Err(e) = connection.close().await {
			debug!("Unable to close connection: {}", e);
		}
		self.handle_connection_issue(result, &target.node_id, &connection.peer_contact_option())
			.await
	}

	/// Exchanges a request with a response with the given contact.
	pub async fn exchange_at(
		&self, node_id: &IdType, target: &ContactOption, message_type_id: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		// TODO: Use an existing connection if possible.
		let mut connection = self.connect_at(target, Some(node_id)).await?;
		let result = self
			.interface
			.exchange(&mut connection, message_type_id, buffer)
			.await;
		if let Err(e) = connection.close().await {
			debug!("Unable to close connection: {}", e);
		}
		self.handle_connection_issue(result, node_id, target).await
	}

	pub async fn exchange_find_x(
		&self, connection: &mut Connection, node_id: &IdType, message_type_id: u8,
	) -> Option<Vec<u8>> {
		let request = FindNodeRequest {
			node_id: node_id.clone(),
		};
		self.exchange_on_connection(
			connection,
			message_type_id,
			&bincode::serialize(&request).unwrap(),
		)
		.await
	}

	/// In the paper, this is described as the 'FIND_NODE' RPC.
	pub async fn exchange_find_node(
		&self, connection: &mut Connection, node_id: &IdType,
	) -> Option<FindNodeResponse> {
		let raw_response_result = self
			.exchange_find_x(connection, node_id, NETWORK_MESSAGE_TYPE_FIND_NODE_REQUEST)
			.await;
		let raw_response = raw_response_result?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: FindNodeResponse = self
			.handle_connection_issue(
				result,
				connection.their_node_id(),
				&connection.peer_contact_option(),
			)
			.await?;
		Some(response)
	}

	pub async fn exchange_find_value_on_connection(
		&self, connection: &mut Connection, id: IdType, value_type: u8,
		expect_fingers_in_response: bool,
	) -> Option<(Option<Vec<u8>>, Option<FindNodeResponse>)> {
		let request = FindValueRequest { id, value_type };
		let raw_request = bincode::serialize(&request).unwrap();
		let response_result: Option<Vec<u8>> = self
			.exchange_on_connection(
				connection,
				NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST,
				&raw_request,
			)
			.await;
		let their_node_id = connection.their_node_id().clone();
		let contact_option = connection.peer_contact_option().clone();
		let response = response_result?;
		self.process_find_value_response(
			&their_node_id,
			&contact_option,
			&response,
			expect_fingers_in_response,
		)
		.await
	}

	pub async fn exchange_find_value_on_connection_and_parse<V>(
		&self, connection: &mut Connection, value_type: ValueType, id: &IdType,
		expect_fingers_in_response: bool,
	) -> Option<(Option<V>, Option<FindNodeResponse>)>
	where
		V: DeserializeOwned,
	{
		let request = FindValueRequest {
			id: id.clone(),
			value_type: value_type as _,
		};
		let raw_request = bincode::serialize(&request).unwrap();
		let raw_response = self
			.exchange_on_connection(
				connection,
				NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST,
				&raw_request,
			)
			.await?;
		let (value_result, fingers_result) = self
			.process_find_value_response(
				connection.their_node_id(),
				&connection.peer_contact_option(),
				&raw_response,
				expect_fingers_in_response,
			)
			.await?;
		if let Some(value_buffer) = value_result {
			let result: sstp::Result<_> = bincode::deserialize(&value_buffer).map_err(|e| e.into());
			let value: V = self
				.handle_connection_issue(
					result,
					&connection.their_node_id(),
					&connection.peer_contact_option(),
				)
				.await?;
			Some((Some(value), fingers_result))
		} else {
			Some((None, fingers_result))
		}
	}

	/// Pings a peer and returns whether it succeeded or not. A.k.a. the 'PING'
	/// RPC.
	pub async fn exchange_keep_alive_on_connection(
		&self, connection: &mut Connection,
	) -> Option<bool> {
		let raw_response = self
			.exchange_on_connection(connection, NETWORK_MESSAGE_TYPE_KEEP_ALIVE_REQUEST, &[])
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: KeepAliveResponse = self
			.handle_connection_issue(
				result,
				connection.their_node_id(),
				&connection.peer_contact_option(),
			)
			.await?;
		Some(response.ok)
	}

	pub async fn exchange_on_connection(
		&self, connection: &mut Connection, message_type_id: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		let result = self
			.interface
			.exchange(connection, message_type_id, buffer)
			.await;

		self.handle_connection_issue(
			result,
			connection.their_node_id(),
			&connection.peer_contact_option(),
		)
		.await
	}

	/// Pings a peer and returns whether it succeeded or not. A.k.a. the 'PING'
	/// RPC.
	async fn exchange_ping(&self, target: &NodeContactInfo) -> Option<()> {
		let message = PingRequest {};
		self.exchange(
			target,
			NETWORK_MESSAGE_TYPE_PING_REQUEST,
			&bincode::serialize(&message).unwrap(),
		)
		.await?;
		Some(())
	}

	pub async fn exchange_ping_on_connection(&self, connection: &mut Connection) -> Option<()> {
		self.exchange_on_connection(connection, NETWORK_MESSAGE_TYPE_PING_REQUEST, &[])
			.await?;
		Some(())
	}

	async fn exchange_punch_hole_on_connection(
		&self, connection: &mut Connection, source_node_id: IdType, source: ContactOption,
	) -> Option<bool> {
		let request = PunchHoleRequest {
			source_node_id,
			source,
		};
		let raw_response = self
			.exchange_on_connection(
				connection,
				NETWORK_MESSAGE_TYPE_PUNCH_HOLE_REQUEST,
				&bincode::serialize(&request).unwrap(),
			)
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: PunchHoleResponse = self
			.handle_connection_issue(
				result,
				connection.their_node_id(),
				&connection.peer_contact_option(),
			)
			.await?;
		Some(response.ok)
	}

	/// Asks a peer to relay a hole punch request to the destination target for
	/// you.
	async fn exchange_relay_punch_hole_request(
		&self, relay_connection: &mut Connection, target: IdType, contact_option: ContactOption,
	) -> Option<bool> {
		let message = RelayPunchHoleRequest {
			target,
			contact_option,
		};
		let raw_response = self
			.exchange_on_connection(
				relay_connection,
				NETWORK_MESSAGE_TYPE_RELAY_PUNCH_HOLE_REQUEST,
				&bincode::serialize(&message).unwrap(),
			)
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: RelayPunchHoleResponse = self
			.handle_connection_issue(
				result,
				&relay_connection.their_node_id(),
				&relay_connection.peer_contact_option(),
			)
			.await?;
		Some(response.ok)
	}

	/// Extracts a list of fingers to contact, and the corresponding strategy to
	/// contact the node.
	fn extract_fingers_from_response(
		&self, response: &FindNodeResponse, visited: &[(IdType, ContactOption)],
	) -> Vec<(NodeContactInfo, ContactStrategy)> {
		let mut new_fingers =
			Vec::with_capacity(response.fingers.len() + response.connection.is_some() as usize);

		for f in &response.fingers {
			match self.pick_contact_option(&f.contact_info) {
				None => {}
				Some((option, openness)) =>
					if visited.iter().find(|v| v.1 == option).is_none() {
						if let Some(strategy) = ContactStrategy::new(None, option, openness) {
							new_fingers.push((f.clone(), strategy));
						}
					},
			}
		}

		match &response.connection {
			None => {}
			Some(c) => match self.pick_contact_option(&c.contact_info) {
				None => {}
				Some((option, openness)) =>
					if visited.iter().find(|v| v.1 == option).is_none() {
						if let Some(strategy) = ContactStrategy::new(None, option, openness) {
							new_fingers.push((c.clone(), strategy));
						}
					},
			},
		}

		new_fingers
	}

	/// Returns the first node with bidirectional contact options known to us
	async fn find_any_bidirectional_contact_option(&self) -> Option<(IdType, ContactOption)> {
		let mut iter = self.iter_all_fingers().await;
		while let Some(finger) = iter.next().await {
			if let Some(contact_option) = self.bidirectional_contact_option(&finger.contact_info) {
				return Some((finger.node_id, contact_option));
			}
		}
		None
	}

	async fn find_bucket(&self, node_id: &IdType) -> Option<&Mutex<Bucket>> {
		let bucket_index = self.differs_at_bit(node_id)?;
		Some(&self.buckets[bucket_index as usize])
	}

	pub async fn find_finger_or_connection(
		&self, id: &IdType,
	) -> Option<(NodeContactInfo, Option<Arc<Mutex<Box<sstp::Connection>>>>)> {
		let bucket_pos = match self.differs_at_bit(id) {
			// If ID is the same as ours, don't give any other contacts
			None => return None,
			Some(p) => p as usize,
		};
		let bucket = self.buckets[bucket_pos].lock().await;
		// First check if we have an active connection to it
		if bucket.connection.is_some() {
			let connection_data = bucket.connection.as_ref().unwrap();
			if &connection_data.0.node_id == id {
				return Some((connection_data.0.clone(), Some(connection_data.1.clone())));
			}
		}
		// Then see if we have it in our cache.
		bucket.find(id).map(|f| (f.clone(), None))
	}

	pub(super) async fn find_nearest_contacts(
		&self, id: &IdType,
	) -> (Option<NodeContactInfo>, Vec<NodeContactInfo>) {
		let bucket_pos = match self.differs_at_bit(id) {
			// If ID is the same as ours, don't give any other contacts
			None => return (None, Vec::new()),
			Some(p) => p as usize,
		};

		// Return the fingers lower down the binary tree first, as they differ
		// at the same bit as our ID.
		// Then return the fingers otherwise lowest in the binary tree.
		let mut connection: Option<NodeContactInfo> = None;
		let mut fingers = Vec::with_capacity(KADEMLIA_K as _);
		for i in (0..(bucket_pos + 1)).rev() {
			let additional_fingers: Vec<NodeContactInfo> = {
				let bucket = self.buckets[i].lock().await;
				let new_fingers = bucket.all();
				if bucket.connection.is_some() {
					connection = bucket.connection.as_ref().map(|(n, _)| n.clone());
				}
				new_fingers
			};

			let remaining = KADEMLIA_K as usize - fingers.len();
			if remaining <= additional_fingers.len() {
				fingers.extend_from_slice(&additional_fingers[0..remaining]);
			} else {
				fingers.extend_from_slice(&additional_fingers);
			}

			if fingers.len() >= KADEMLIA_K as usize {
				return (connection, fingers);
			}
		}

		(connection, fingers)
	}

	/// Finds the k nodes nearest to the given id. If it can't find k fingers
	/// that are closer to the id than this node is, it will supplement with
	/// nodes that are farther away.
	pub async fn find_nearest_fingers(&self, id: &IdType) -> Vec<NodeContactInfo> {
		let bucket_pos = match self.differs_at_bit(id) {
			// If ID is the same as ours, don't give any other contacts
			None => return Vec::new(),
			Some(p) => p as usize,
		};
		let mut fingers = Vec::with_capacity(KADEMLIA_K as _);

		// Return the fingers lower down the binary tree first, as they differ
		// at the same bit as our ID.
		// Then return the fingers otherwise lowest in the binary tree (so they actually
		// differ at a higher bit)
		for i in ((bucket_pos)..256).chain((0..bucket_pos).rev()) {
			// FIXME: Pretty ineffecient, copying the whole vector.
			let additional_fingers: Vec<NodeContactInfo> = {
				let bucket = self.buckets[i].lock().await;
				bucket.all()
			};

			let remaining = KADEMLIA_K as usize - fingers.len();
			if remaining <= additional_fingers.len() {
				fingers.extend_from_slice(&additional_fingers[0..remaining]);
			} else {
				fingers.extend_from_slice(&additional_fingers);
			}

			if fingers.len() >= KADEMLIA_K as usize {
				return fingers;
			}
		}

		fingers
	}

	pub async fn find_node(
		&self, id: &IdType, result_limit: usize, hop_limit: usize,
	) -> Vec<NodeContactInfo> {
		let fingers = self.find_nearest_fingers(id).await;
		if fingers.len() == 0 {
			return Vec::new();
		}
		self.find_node_from_fingers(id, &fingers, result_limit, hop_limit)
			.await
	}

	async fn find_connection_in_buckets(&self, id: &IdType) -> Option<Arc<Mutex<Box<Connection>>>> {
		for i in (0..256).rev() {
			let bucket_mutex = &self.buckets[i];
			let bucket = bucket_mutex.lock().await;
			if let Some((node_info, connection_mutex)) = &bucket.connection {
				if &node_info.node_id == id {
					return Some(connection_mutex.clone());
				}
			}
		}
		None
	}

	pub async fn find_node_from_fingers(
		&self, id: &IdType, fingers: &[NodeContactInfo], result_limit: usize, visit_limit: usize,
	) -> Vec<NodeContactInfo> {
		let mut visited = Vec::<(IdType, ContactOption)>::new();
		let mut candidates = VecDeque::with_capacity(fingers.len());
		for (d, n) in Self::sort_fingers(id, fingers).into_iter() {
			match self.pick_contact_strategy(&n.contact_info, None) {
				None => {}
				Some(strategy) => candidates.push_back((d, n, strategy)),
			}
		}
		let mut found = candidates.clone();
		while found.len() > result_limit {
			found.pop_back();
		}

		let mut i = 0;
		// FIXME: The first candidate node may not have a bidirectional contact option.
		// If a punchable candidate is encountered and we don't have an open connection
		// yet, open a connection to the first bidirectional candidate.
		while candidates.len() > 0 && i < visit_limit {
			let (dist, candidate_contact, strategy) = candidates[0].clone();
			if visited
				.iter()
				.find(|(id, _)| id == &candidate_contact.node_id)
				.is_some()
			{
				candidates.pop_front();
				continue;
			}
			visited.push((candidate_contact.node_id.clone(), strategy.contact.clone()));

			match self
				.connect_node(&candidate_contact.node_id, &strategy, None)
				.await
			{
				None => warn!(
					"Disregarding finger {}, unable to connect...",
					&candidate_contact.contact_info
				),
				Some(mut connection) => {
					match self.exchange_find_node(&mut connection, &id).await {
						None => {
							warn!("Disregarding finger {}", &candidate_contact.contact_info);
						}
						Some(response) => {
							let mut new_fingers =
								self.extract_fingers_from_response(&response, &visited);
							new_fingers.retain(|f| &distance(id, &f.0.node_id) < &dist);
							Self::append_candidates(id, &mut found, &new_fingers);
							while found.len() > result_limit {
								found.pop_back();
							}
							// If the exact ID has been found, we stop
							if new_fingers.iter().find(|f| &f.0.node_id == id).is_some() {
								connection.close().await;
								break;
							}
							Self::append_candidates(id, &mut candidates, &new_fingers);
							// Prevent using candidates that were found too far back. We
							// don't intend to iterate over the whole network. Only the
							// last few candidates that were close.
							while candidates.len() > KADEMLIA_K as usize {
								candidates.pop_back();
							}
						}
					}
					connection.close().await;
				}
			}

			i += 1;
		}

		found.into_iter().map(|c| c.1).collect()
	}

	pub async fn find_value_from_fingers<'a>(
		&'a self, overlay_node: Arc<OverlayNode>, id: &IdType, value_type_id: u8,
		expect_fingers_in_response: bool, fingers: &[NodeContactInfo], visit_limit: usize,
		narrow_down: bool,
		do_verify: impl Fn(&IdType, &NodeContactInfo, &[u8]) -> Option<AtomicPtr<()>> + Send + Sync + 'a,
	) -> Option<AtomicPtr<()>> {
		self.find_value_from_fingers_iter(
			overlay_node,
			id,
			value_type_id,
			expect_fingers_in_response,
			fingers,
			visit_limit,
			narrow_down,
			do_verify,
		)
		.await
		.next()
		.await
	}

	pub async fn find_value_from_fingers_iter<'a>(
		&'a self, overlay_node: Arc<OverlayNode>, id: &IdType, value_type_id: u8,
		expect_fingers_in_response: bool, fingers: &[NodeContactInfo], visit_limit: usize,
		narrow_down: bool,
		do_verify: impl Fn(&IdType, &NodeContactInfo, &[u8]) -> Option<AtomicPtr<()>> + Send + Sync + 'a,
	) -> FindValueIter<'a, I> {
		// Initialize the candidates by picking a contact strategy for each candidate.
		let mut candidates = VecDeque::with_capacity(fingers.len());
		for (d, n) in Self::sort_fingers(id, fingers).into_iter() {
			match self.pick_contact_strategy(&n.contact_info, None) {
				None => {}
				Some(strategy) => {
					candidates.push_back((d, n, strategy));
				}
			}
		}

		FindValueIter {
			node: self,
			overlay_node,
			expect_fingers_in_response,
			id: id.clone(),
			value_type_id,
			do_verify: Box::new(do_verify),
			narrow_down,
			visited: Vec::with_capacity(visit_limit),
			candidates,
			connection_for_hole_punching: None,
			open_for_hole_punching: self.contact_info().await.is_open_to_hole_punching(),
		}
	}

	pub(super) async fn handle_connection_issue<T>(
		&self, result: sstp::Result<T>, node_id: &IdType, contact: &ContactOption,
	) -> Option<T> {
		match result {
			Err(e) => {
				match e {
					sstp::Error::Timeout => {
						debug!("Problematic node {}: {}", contact, e);
						self.mark_node_problematic(node_id).await;
					}
					_ =>
						if !e.forgivable() {
							warn!("Rejecting node {}: {}", contact, e);
							self.reject_node(node_id).await;
						} else {
							debug!("Connection issue with node {}: {}", contact, e);
						},
				}
				None
			}
			Ok(response) => {
				self.mark_node_helpful(node_id).await;
				Some(response)
			}
		}
	}

	pub(super) async fn handle_connection_issue2<T>(
		&self, result: sstp::Result<T>, node_id: &IdType, contact_info: &ContactInfo,
	) -> Option<T> {
		match result {
			Err(e) => {
				match e {
					sstp::Error::Timeout => {
						debug!("Problematic node {}: {}", contact_info, e);
						self.mark_node_problematic(node_id).await;
					}
					_ =>
						if !e.forgivable() {
							warn!("Rejecting node {}: {}", contact_info, e);
							self.reject_node(node_id).await;
						} else {
							debug!("Connection issue with node {}: {}", contact_info, e);
						},
				}
				None
			}
			Ok(response) => {
				self.mark_node_helpful(node_id).await;
				Some(response)
			}
		}
	}

	pub fn has_stopped(&self) -> bool { self.stop_flag.load(Ordering::Relaxed) }

	fn insert_candidate(
		id: &IdType, candidates: &mut VecDeque<(BigUint, NodeContactInfo, ContactStrategy)>,
		finger: &(NodeContactInfo, ContactStrategy),
	) {
		let distance = distance(id, &finger.0.node_id);
		for i in 0..candidates.len() {
			let candidate_distance = &candidates[i].0;
			if &distance < candidate_distance {
				candidates.insert(i, (distance, finger.0.clone(), finger.1.clone()));
				return;
			}
		}
		candidates.push_back((distance, finger.0.clone(), finger.1.clone()));
	}

	/// Joins the network via a peer. If pinging that peer fails, returns an I/O
	/// error.
	pub async fn join_network_starting_at(&self, node_address: &ContactInfo) -> bool {
		// FIXME: It would save a few packets if we would just take the node_id from
		// the first 'FIND_NODE' request. But that would require some
		// restructuring of the code base.
		let node_id = match self.test_presence(node_address).await {
			None => return false,
			Some(id) => id,
		};
		let first_contact = NodeContactInfo {
			contact_info: node_address.clone(),
			node_id,
		};
		self.remember_node_nondestructive(first_contact.clone())
			.await;

		// Keep finding new fingers until we have not been able to get any
		// closer to our own ID.
		//let current_distance = distance(&first_contact.node_id, &self.base.node_id);
		let fingers = vec![first_contact; 1];
		let neighbours = self
			.find_node_from_fingers(
				&self.node_id,
				&*fingers,
				KADEMLIA_K as _,
				100, // TODO: Make configuration variable
			)
			.await;

		// Add the last encountered fingers (neighbours) to our buckets as well, as they
		// have not been automatically added.
		let futs = neighbours.into_iter().map(|n| async move {
			if self.test_id(&n).await {
				self.remember_node_nondestructive(n).await;
			} else {
				warn!("Connecting to neighbour {} failed", &n.contact_info);
			}
		});
		join_all(futs).await;

		true
	}

	pub async fn iter_all_fingers(&self) -> AllFingersIter<'_> {
		AllFingersIter {
			global_index: 255,
			bucket_iter: self.buckets[255].lock().await.all().into_iter(),
			buckets: &self.buckets,
		}
	}

	/// Use this if a node is giving a timeout.
	async fn mark_node_problematic(&self, node_id: &IdType) {
		if let Some(bucket_index) = self.differs_at_bit(node_id) {
			let mut bucket = self.buckets[bucket_index as usize].lock().await;
			bucket.mark_problematic(node_id);
		}
	}

	async fn mark_node_helpful(&self, node_id: &IdType) {
		if let Some(bucket_index) = self.differs_at_bit(node_id) {
			let mut bucket = self.buckets[bucket_index as usize].lock().await;
			bucket.mark_helpful(node_id);
		}
	}

	pub fn new(
		stop_flag: Arc<AtomicBool>, node_id: IdType, socket: Arc<sstp::Server>, interface: I,
		bucket_size: usize,
	) -> Self {
		let mut buckets = Vec::with_capacity(KADEMLIA_BITS);
		for _ in 0..KADEMLIA_BITS {
			buckets.push(Mutex::new(Bucket::new(bucket_size)));
		}

		Self {
			stop_flag,
			node_id,
			buckets,
			interface,
			socket,
			expected_connections: Arc::new(Mutex::new(HashMap::new())),
			bucket_size,
		}
	}

	pub fn node_id(&self) -> &IdType { &self.node_id }

	fn pick_contact_option(&self, target: &ContactInfo) -> Option<(ContactOption, Openness)> {
		self.socket.pick_contact_option(target)
	}

	fn pick_contact_strategy(
		&self, target: &ContactInfo, connection: Option<&Arc<Mutex<Box<Connection>>>>,
	) -> Option<ContactStrategy> {
		let (option, openness) = self.pick_contact_option(target)?;
		ContactStrategy::new(connection, option, openness)
	}

	async fn process_find_node_request(
		&self, buffer: &[u8], actor_id: Option<&IdType>,
	) -> Option<Vec<u8>> {
		let request: FindNodeRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed find node request: {}", e);
				return None;
			}
			Ok(r) => r,
		};

		// Collect all fingers we have
		let (connection, fingers) = self.find_nearest_contacts(&request.node_id).await;
		let response = FindNodeResponse {
			connection,
			fingers,
		};
		Some(bincode::serialize(&response).unwrap())
	}

	async fn process_find_value_response(
		&self, node_id: &IdType, contact_option: &ContactOption, response: &[u8],
		expect_fingers_in_response: bool,
	) -> Option<(Option<Vec<u8>>, Option<FindNodeResponse>)> {
		// If fingers are expected in the response, parse them
		let (contacts, contacts_len) = if expect_fingers_in_response {
			let result: sstp::Result<FindNodeResponse> =
				bincode::deserialize_with_trailing(&response).map_err(|e| e.into());

			let contacts = self
				.handle_connection_issue(result, node_id, &contact_option)
				.await?;
			let contacts_len = bincode::serialized_size(&contacts).unwrap();
			(Some(contacts), contacts_len)
		} else {
			(None, 0)
		};

		// Depending on whether the fingers were expected or not, parse the value of the
		// response befrom after the fingers or at the beginning
		if expect_fingers_in_response {
			if response.len() == contacts_len {
				return Some((None, contacts));
			} else {
				let value = response[contacts_len..].to_vec();
				return Some((Some(value), contacts));
			}
		} else {
			if response[contacts_len] == 1 {
				return Some((Some(response[(contacts_len + 1)..].to_vec()), contacts));
			} else if response[contacts_len] == 0 {
				return Some((None, contacts));
			} else {
				return self
					.handle_connection_issue(
						Err(sstp::Error::MalformedMessage(None)),
						node_id,
						&contact_option,
					)
					.await;
			}
		}
	}

	async fn process_find_value_request(
		&self, buffer: &[u8], overlay_node: Arc<OverlayNode>, actor_id: Option<&IdType>,
	) -> Option<Vec<u8>> {
		let force_including_fingers = actor_id.is_none();

		let request: FindValueRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed find value request: {}", e);
				return None;
			}
			Ok(r) => r,
		};

		let result = match actor_id {
			None =>
				overlay_node
					.base
					.interface
					.find_value(request.value_type, &request.id)
					.await,
			Some(id) => {
				if let Some(actor_node) =
					overlay_node.base.interface.actor_nodes.lock().await.get(id)
				{
					actor_node
						.base
						.interface
						.find_value(request.value_type, &request.id)
						.await
				} else {
					warn!("Value of unknown actor requested: {}", id);
					return None;
				}
			}
		};

		let value_result = match result {
			Err(e) => {
				panic!(
					"Database error occurred processing find value request for value {} (type \
					 {}): {}",
					&request.id, request.value_type, e
				);
				return None;
			}
			Ok(r) => r,
		};

		// Start response with a FindNodeResponse if not found or expected anyway
		if force_including_fingers {
			// Collect all fingers we have
			let (connection, fingers) = self.find_nearest_contacts(&request.id).await;
			let response = FindNodeResponse {
				connection,
				fingers,
			};

			let mut buffer = bincode::serialize(&response).unwrap();
			let mut value_buffer = value_result.unwrap_or_default();
			buffer.append(&mut value_buffer);
			Some(buffer)
		} else {
			let mut buffer = vec![value_result.is_some() as u8; 1];
			if let Some(value) = value_result {
				buffer.extend(value);
			} else {
				let (connection, fingers) = self.find_nearest_contacts(&request.id).await;
				let response = FindNodeResponse {
					connection,
					fingers,
				};

				buffer.extend(bincode::serialize(&response).unwrap());
			}
			Some(buffer)
		}
	}

	async fn process_keep_alive_request(
		&self, connection: &Arc<Mutex<Box<Connection>>>, buffer: &[u8], node_info: &NodeContactInfo,
	) -> Option<Vec<u8>> {
		// The keep alive request is empty
		if buffer.len() > 0 {
			return None;
		}

		let ok = if let Some(bucket_index) = self.differs_at_bit(&node_info.node_id) {
			let mut bucket = self.buckets[bucket_index as usize].lock().await;

			if bucket.connection.is_none() {
				bucket.connection = Some((node_info.clone(), connection.clone()));
				true
			} else {
				false
			}
		} else {
			false
		};

		Some(bincode::serialize(&KeepAliveResponse { ok }).unwrap())
	}

	async fn process_ping_request(&self, address: &SocketAddr) -> Option<Vec<u8>> {
		debug!("Received ping request from {}", address);
		Some(Vec::new())
	}

	pub(super) async fn process_request(
		self: &Arc<Self>, connection: Arc<Mutex<Box<Connection>>>, overlay_node: Arc<OverlayNode>,
		address: &SocketAddr, node_info: &NodeContactInfo, message_type: u8, buffer: &[u8],
		actor_id: Option<&IdType>,
	) -> Option<Option<Vec<u8>>> {
		let result = match message_type {
			NETWORK_MESSAGE_TYPE_PING_REQUEST => self.process_ping_request(address).await,
			NETWORK_MESSAGE_TYPE_FIND_NODE_REQUEST =>
				self.process_find_node_request(buffer, actor_id).await,
			NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST =>
				self.process_find_value_request(buffer, overlay_node, actor_id)
					.await,
			NETWORK_MESSAGE_TYPE_PUNCH_HOLE_REQUEST =>
				self.process_punch_hole_request(buffer, overlay_node).await,
			NETWORK_MESSAGE_TYPE_RELAY_PUNCH_HOLE_REQUEST =>
				self.process_relay_punch_hole_request(buffer).await,
			NETWORK_MESSAGE_TYPE_KEEP_ALIVE_REQUEST =>
				self.process_keep_alive_request(&connection, buffer, node_info)
					.await,
			_ => return None,
		};
		Some(result)
	}

	async fn process_punch_hole_request(
		self: &Arc<Self>, buffer: &[u8], overlay_node: Arc<OverlayNode>,
	) -> Option<Vec<u8>> {
		#[inline(always)]
		fn handle_connection_recursive(
			overlay_node: Arc<OverlayNode>, connection: Box<Connection>,
		) -> BoxFuture<'static, ()> {
			Box::pin(async move {
				handle_connection(overlay_node, connection).await;
			})
		}

		let request: PunchHoleRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				warn!("Malformed punch hole request: {}", e);
				return None;
			}
			Ok(r) => r,
		};
		let mut response = PunchHoleResponse { ok: true };

		if let Some(connection) = self
			.connect_at(&request.source, Some(&request.source_node_id))
			.await
		{
			spawn(handle_connection_recursive(overlay_node, connection));
		} else {
			response.ok = false;
		}

		Some(bincode::serialize(&response).unwrap())
	}

	async fn punch_hole(
		&self, relay_connection: &mut Connection, target: &IdType, contact_option: &ContactOption,
	) -> Option<Box<Connection>> {
		// FIXME: It would be much faster if we didn't have to wait for a timeout before
		// we continued.
		if let Some(connection) = self.connect_at(contact_option, Some(target)).await {
			return Some(connection);
		}

		let (tx, rx) = oneshot::channel();
		{
			let mut expected_connections = self.expected_connections.lock().await;
			// If a connection from the same target is already expected, we can't touch it.
			// It would leave the other task that's still waiting on the previous connection
			// hanging.
			if expected_connections.contains_key(target) {
				error!("Attempted to punch more than one hole at node {}", target);
				return None;
			}
			expected_connections.insert(target.clone(), tx);
		}

		// Contact the relay node
		let knows_target = self
			.exchange_relay_punch_hole_request(
				relay_connection,
				target.clone(),
				contact_option.clone(),
			)
			.await?;
		if !knows_target {
			return None;
		}

		// TODO: Keep the connection with the relay node open until contact is made,
		// because the relay node may be able to tell us if he could contact the target
		// node.

		// Spawn task to cancel the wait after the timeout interval
		let arc_expected_connections = self.expected_connections.clone();
		let target2 = target.clone();
		spawn(async move {
			sleep(Duration::from_millis(10000)).await;
			let mut expected_connections = arc_expected_connections.lock().await;
			expected_connections.remove(&target2);
		});

		// Wait until a connection is received, and return that.
		let connection = rx.await.unwrap();
		Some(connection)
	}

	/// Pings a node and returns its latency and node ID .
	pub async fn ping(&self, target: &NodeContactInfo) -> Option<u32> {
		let start = SystemTime::now();
		self.exchange_ping(target).await?;
		let stop = SystemTime::now();
		let latency = stop.duration_since(start).unwrap().as_millis() as u32;
		Some(latency)
	}

	async fn process_relay_punch_hole_request(&self, buffer: &[u8]) -> Option<Vec<u8>> {
		let request: RelayPunchHoleRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				warn!("Malformed relay punch hole request: {}", e);
				return None;
			}
			Ok(r) => r,
		};
		let mut response = RelayPunchHoleResponse { ok: true };

		if let Some(connection_mutex) = self.find_connection_in_buckets(&request.target).await {
			let mut connection = connection_mutex.lock().await;
			self.exchange_punch_hole_on_connection(
				&mut connection,
				request.target,
				request.contact_option,
			)
			.await;
		} else {
			response.ok = false;
		}

		Some(bincode::serialize(&response).unwrap())
	}

	/// Removes the node from our buckets.
	async fn reject_node(&self, node_id: &IdType) {
		if let Some(bucket_index) = self.differs_at_bit(node_id) {
			let mut bucket = self.buckets[bucket_index as usize].lock().await;
			bucket.reject(node_id);
		}
	}

	/// Puts the given node somewhere in one of the buckets if there is a spot
	/// available.
	/// This method can block for quite a while, as it exchanges requests.
	/// Normally speaking, you'd want to spawn this off to execute on the side.
	pub async fn remember_node(self: &Arc<Self>, node_info: NodeContactInfo) {
		let bucket_pos = match self.differs_at_bit(&node_info.node_id) {
			None => {
				debug!("Found same node ID as us, ignoring...");
				return;
			}
			Some(p) => p as usize,
		};

		// If peer is already in our bucket, only update contact info
		let mut bucket = self.buckets[bucket_pos].lock().await;
		let (already_known, updated) = bucket.update(&node_info);
		if updated {
			debug!("Contact info updated for node {}.", &node_info.node_id);
		}
		if already_known {
			return;
		}

		// If the bucket is full, test whether the node at the front is still active,
		// and yeet it if not.
		if let Some(n) = bucket.test_space() {
			if !self.test_id(n).await {
				bucket.pop_front();
			}
		}
		debug!("Remembering node {}...", &node_info.contact_info);
		bucket.remember(node_info);
	}

	/// Like `remember_node`, but only remembers the node if it doesn't need to
	/// push other data away.
	pub async fn remember_node_nondestructive(&self, node_info: NodeContactInfo) {
		let bucket_pos = match self.differs_at_bit(&node_info.node_id) {
			None => {
				debug!("Found same node ID as us, ignoring...");
				return;
			}
			Some(p) => p as usize,
		};

		// If peer is already in our bucket, only update contact info
		let mut bucket = self.buckets[bucket_pos].lock().await;
		let (already_known, updated) = bucket.update(&node_info);
		if updated {
			debug!("Contact info updated for node {}.", &node_info.node_id);
		}
		if already_known {
			return;
		}

		if bucket.test_space().is_none() {
			debug!("Remembering node {}.", &node_info.contact_info);
			bucket.remember(node_info);
		}
	}

	fn sort_fingers(
		id: &IdType, fingers: &[NodeContactInfo],
	) -> VecDeque<(BigUint, NodeContactInfo)> {
		let mut fingers2: Vec<_> = fingers
			.into_iter()
			.map(|f| {
				let dist = distance(id, &f.node_id);
				(dist, f.clone())
			})
			.collect();
		fingers2.sort_by(|a, b| a.0.cmp(&b.0));
		let mut candidates = VecDeque::with_capacity(fingers.len());
		candidates.extend(fingers2);
		candidates
	}

	pub async fn test_presence(&self, target: &ContactInfo) -> Option<IdType> {
		// TODO: Instead of opening a connection and immediately closing it, ping the
		// node.
		let mut connection = self.connect(target, None).await?;
		let their_node_id = connection.their_node_id().clone();
		if let Err(e) = connection.close().await {
			debug!("Unable to close connection: {}", e);
		}
		Some(their_node_id)
	}

	/// Tests wether the node is available, and if their node ID is correct.
	pub async fn test_id(&self, contact: &NodeContactInfo) -> bool {
		match self.test_presence(&contact.contact_info).await {
			None => false,
			Some(id) => id == contact.node_id,
		}
	}
}

#[async_trait]
impl<'a> AsyncIterator for AllFingersIter<'a> {
	type Item = NodeContactInfo;

	async fn next(&mut self) -> Option<NodeContactInfo> {
		loop {
			if let Some(contact) = self.bucket_iter.next() {
				return Some(contact);
			} else {
				self.bucket_iter = self.buckets[self.global_index]
					.lock()
					.await
					.all()
					.into_iter();
				if self.global_index > 0 {
					self.global_index -= 1;
				} else {
					break;
				}
			}
		}
		None
	}
}

#[async_trait]
impl<'a, I> AsyncIterator for FindValueIter<'a, I>
where
	I: NodeInterface + Send + Sync,
{
	type Item = AtomicPtr<()>;

	async fn next(&mut self) -> Option<Self::Item> {
		while self.candidates.len() > 0 && self.visited.len() < self.visited.capacity() {
			let (dist, candidate_contact, strategy) = self.candidates.pop_front().unwrap();
			let contact_option = strategy.contact.clone();
			// If we ourselves are listed as a candidate, ignore it.
			if &candidate_contact.node_id == self.node.node_id() {
				continue;
			}

			// If already visited before, ignore it.
			if self
				.visited
				.iter()
				.find(|v| v.1 == contact_option)
				.is_some()
			{
				continue;
			}
			self.visited
				.push((candidate_contact.node_id.clone(), contact_option));

			// Use the already found contact option to exchange the find value request.
			let mut special_connection: Option<Box<Connection>> = None;
			let mut connection_for_hole_punching = if self.open_for_hole_punching
				&& strategy.method != ContactStrategyMethod::Direct
			{
				let mut result =
					if let Some((node_id, connection)) = &mut self.connection_for_hole_punching {
						if node_id == &candidate_contact.node_id {
							Some(connection)
						} else {
							None
						}
					} else {
						None
					};
				if result.is_none() {
					special_connection = self
						.overlay_node
						.find_connection_for_node(&candidate_contact.node_id)
						.await;
					result = special_connection.as_mut();
				}
				result
			} else {
				None
			};
			match self
				.node
				.connect_node(
					&candidate_contact.node_id,
					&strategy,
					connection_for_hole_punching
						.as_deref_mut()
						.map(|c| c.as_mut()),
				)
				.await
			{
				None => {
					if let Some(mut sc) = special_connection.as_mut() {
						sc.close().await;
					}
					warn!("Disregarding finger {}", &candidate_contact.contact_info)
				}
				Some(mut connection) => {
					if let Some(mut sc) = special_connection.as_mut() {
						sc.close().await;
					}

					match self
						.node
						.exchange_find_value_on_connection(
							&mut connection,
							self.id.clone(),
							self.value_type_id,
							self.expect_fingers_in_response,
						)
						.await
					{
						// If node didn't respond right, ignore it
						None => {
							connection.close().await;
						}
						Some((possible_value, possible_contacts)) => {
							// If node returned new fingers, append them to our list
							if let Some(find_node_response) = possible_contacts {
								let mut new_fingers = self.node.extract_fingers_from_response(
									&find_node_response,
									&self.visited,
								);
								if self.narrow_down {
									new_fingers
										.retain(|(f, _)| &distance(&self.id, &f.node_id) < &dist);
								}

								Node::<I>::append_candidates(
									&self.id,
									&mut self.candidates,
									&new_fingers,
								);
								if self.narrow_down {
									while self.candidates.len() > KADEMLIA_K as usize {
										self.candidates.pop_back();
									}
								}

								if let Some(connected_contact) = find_node_response.connection {
									if let Some((_, previous_connection)) =
										self.connection_for_hole_punching.as_mut()
									{
										previous_connection.close().await;
									}
									self.connection_for_hole_punching =
										Some((connected_contact.node_id, connection));
								} else {
									connection.close().await;
								}
							} else {
								connection.close().await;
							}

							// If a value was found, return it, otherwise keep the search loop going
							if let Some(value) = possible_value {
								return (self.do_verify)(&self.id, &candidate_contact, &value);
							}
						}
					}
				}
			}
		}
		None
	}
}

impl Bucket {
	pub fn all(&self) -> Vec<NodeContactInfo> {
		let mut list = Vec::with_capacity(self.fingers.len() + self.connection.is_some() as usize);
		if let Some((node_info, _)) = self.connection.as_ref() {
			list.push(node_info.clone());
		}
		list.extend(self.fingers.clone());
		list
	}

	pub fn find(&self, id: &IdType) -> Option<&NodeContactInfo> {
		if let Some(contact) = self.connection.as_ref() {
			return Some(&contact.0);
		}
		if let Some(index) = self.fingers.iter().position(|f| &f.node_id == id) {
			return Some(&self.fingers[index]);
		}
		None
	}

	// TODO: Make this return an iterator
	fn fingers(&self) -> Vec<NodeContactInfo> {
		let mut fingers = Vec::with_capacity(self.fingers.len() + self.replacement_cache.len());
		fingers.extend(self.fingers.clone());
		let vec2: Vec<NodeContactInfo> = self
			.replacement_cache
			.iter()
			.map(|e| e.finger.clone())
			.collect();
		fingers.extend(vec2);
		fingers
	}

	fn mark_helpful(&mut self, id: &IdType) {
		match self
			.replacement_cache
			.iter()
			.position(|f| &f.finger.node_id == id)
		{
			None => {}
			Some(index) => {
				let finger = self.replacement_cache.remove(index).unwrap().finger;
				self.remember(finger);
			}
		}
	}

	fn mark_problematic(&mut self, id: &IdType) {
		match self.fingers.iter().position(|f| &f.node_id == id) {
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
					.position(|e| &e.finger.node_id == id)
				{
					let entry = &mut self.replacement_cache[index];
					entry.failed_attempts += 1;
					if entry.failed_attempts == 3 {
						self.replacement_cache.remove(index);
					}
				}
			}
		}
	}

	fn reject(&mut self, id: &IdType) {
		// If it refers to a connection, drop the connection.
		if let Some((node_info, connection)) = self.connection.as_ref() {
			if &node_info.node_id == id {
				let c = connection.clone();
				spawn(async move {
					let _ = c.lock().await.close().await;
				});
				self.connection = None;
				//return;
			}
		}

		match self.fingers.iter().position(|f| &f.node_id == id) {
			None => {}
			Some(index) => {
				self.fingers.remove(index);
			}
		}

		match self
			.replacement_cache
			.iter()
			.position(|f| &f.finger.node_id == id)
		{
			None => {}
			Some(index) => {
				self.replacement_cache.remove(index);
			}
		}
	}

	fn new(size: usize) -> Self {
		Self {
			connection: None,
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

	fn remember(&mut self, node: NodeContactInfo) {
		if self.fingers.len() == self.fingers.limit() as usize {
			if self.replacement_cache.has_space() {
				self.replacement_cache.push_back(BucketReplacementEntry {
					finger: self.fingers.pop_front().unwrap(),
					failed_attempts: 1,
				});
			} else {
				self.fingers.pop_front();
			}
		}
		self.fingers.push_back(node);
	}

	fn test_space(&self) -> Option<&NodeContactInfo> {
		if self.fingers.len() < KADEMLIA_K as usize {
			return None;
		}

		Some(&self.fingers[0])
	}

	/// Updates the node info currently saved in the bucket.
	/// Returns (already_existing, updated)
	fn update(&mut self, node_info: &NodeContactInfo) -> (bool, bool) {
		match self
			.fingers
			.iter_mut()
			.position(|f| f.node_id == node_info.node_id)
		{
			None => (false, false),
			Some(index) => {
				let old = self.fingers[index].contact_info.clone();
				let different = old != node_info.contact_info;
				if different {
					self.fingers[index].contact_info = node_info.contact_info.clone();
				}
				(true, different)
			}
		}
	}
}

impl<I> Deref for Node<I>
where
	I: NodeInterface,
{
	type Target = I;

	fn deref(&self) -> &I { &self.interface }
}

/// Runs a loop that continiously accepts requests, processes them (which
/// returns a response). It stops if the connection is closed, or if some sort
/// of network error (like a timeout) occurred. So a node receiving a connection
/// will keep listening on the same connection until the sending node is done
/// with it.
pub(super) async fn handle_connection(overlay_node: Arc<OverlayNode>, c: Box<Connection>) {
	let mutex: Arc<Mutex<Box<Connection>>> = Arc::new(Mutex::new(c));
	let mut is_first_message = true;
	loop {
		let message = {
			let mut connection = mutex.lock().await;
			match connection.receive().await {
				Ok(m) => m,
				Err(e) => {
					match e {
						sstp::Error::Timeout => {
							// Currently there is an issue with close packets being malformed, and
							// so because of it connections my not be properly closed after the
							// first request is received.
							if is_first_message {
								debug!(
									"Node {} timed out before request was received ({})",
									connection.peer_address(),
									connection.their_session_id(),
								);
							}
							return;
						}
						// Opening and immediately closing connections is done to test presence, so
						// ignore these two errors for now:
						sstp::Error::ConnectionClosed => return,
						other => {
							// For the other errors the connection may have not been closed already.
							let _ = connection.close().await;
							error!(
								"Unable to properly receive full request from {}: {}",
								connection.peer_address(),
								other
							);
							return;
						}
					}
				}
			}
		};
		is_first_message = false;

		process_request_message(overlay_node.clone(), mutex.clone(), &message).await;
	}
}


pub(super) async fn keep_alive_connection(overlay_node: Arc<OverlayNode>, c: Box<Connection>) {
	let mutex: Arc<Mutex<Box<Connection>>> = Arc::new(Mutex::new(c));
	loop {
		let message = {
			let mut connection = mutex.lock().await;
			match connection
				.receive_with_timeout(Duration::from_secs(120))
				.await
			{
				Ok(m) => m,
				Err(e) => {
					match e {
						// If the node hasn't send any pings for 120 seconds, we're done.
						sstp::Error::Timeout => return,
						// Opening and immediately closing connections is done to test presence, so
						// ignore these two errors for now:
						sstp::Error::ConnectionClosed => return,
						other => {
							// For the other errors the connection may have not been closed already.
							let _ = connection.close().await;
							error!(
								"Unable to properly receive full request from {}: {}",
								connection.peer_address(),
								other
							);
							return;
						}
					}
				}
			}
		};

		process_request_message(overlay_node.clone(), mutex.clone(), &message).await;
	}
}

async fn process_request_message(
	overlay_node: Arc<OverlayNode>, connection: Arc<Mutex<Box<Connection>>>, buffer: &[u8],
) {
	let mut c = connection.lock().await;

	let mut message_type_id = buffer[0];
	if message_type_id >= 0x80 {
		message_type_id ^= 0x80;
		let actor_id: IdType = bincode::deserialize(&buffer[1..33]).unwrap();
		let actor_nodes = overlay_node.base.interface.actor_nodes.lock().await;
		let actor_node = match actor_nodes.get(&actor_id) {
			None => return, // Don't respond to requests for networks we are not connected to.
			Some(n) => n.clone(),
		};
		drop(actor_nodes);

		let r = match overlay_node
			.base
			.process_request(
				connection.clone(),
				overlay_node.clone(),
				c.peer_address(),
				c.their_node_info(),
				message_type_id,
				&buffer[33..],
				Some(&actor_id),
			)
			.await
		{
			Some(r) => r,
			None =>
				overlay_node
					.process_actor_request(
						&mut c,
						&connection,
						&actor_id,
						message_type_id,
						&buffer[33..],
					)
					.await,
		};

		match r {
			None => {}
			Some(response) => {
				debug_assert!(
					response.len() > 0,
					"actor response must be more than 0 bytes"
				);
				if let Err(e) = actor_node
					.base
					.interface
					.respond(&mut *c, message_type_id + 1, &response)
					.await
				{
					warn!("Unable to respond to actor request: {}", e)
				} else {
					let node_info = c.their_node_info().clone();
					actor_node.base.remember_node(node_info).await;
				}
			}
		}
	} else {
		let r = match overlay_node
			.base
			.process_request(
				connection.clone(),
				overlay_node.clone(),
				&c.peer_address(),
				c.their_node_info(),
				message_type_id,
				&buffer[1..],
				None,
			)
			.await
		{
			Some(r) => r,
			None =>
				overlay_node
					.process_request(&mut *c, message_type_id, &buffer[1..])
					.await,
		};

		match r {
			None => {}
			Some(x) => {
				if let Err(e) = overlay_node
					.base
					.interface
					.respond(&mut *c, message_type_id + 1, &x)
					.await
				{
					warn!("Unable to respond: {}", e)
				} else {
					let node_info = c.their_node_info().clone();
					overlay_node.base.remember_node(node_info).await;
				}
			}
		}
	};
}

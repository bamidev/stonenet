use std::{
	collections::VecDeque,
	ops::Deref,
	sync::{atomic::*, Arc},
	time::SystemTime,
};

use async_trait::async_trait;
use futures::future::join_all;
use log::*;
use num::BigUint;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

use super::{
	bucket::Bucket,
	message::*,
	overlay::OverlayNode,
	sstp::{self, Connection, MessageProcessorResult},
	*,
};
use crate::{
	common::*,
	db,
	trace::{self, Traced},
};


// Messages for the overlay network:
pub const NETWORK_MESSAGE_TYPE_PING_REQUEST: u8 = 0;
pub const NETWORK_MESSAGE_TYPE_PING_RESPONSE: u8 = 1;
pub const NETWORK_MESSAGE_TYPE_FIND_NODE_REQUEST: u8 = 2;
pub const NETWORK_MESSAGE_TYPE_FIND_NODE_RESPONSE: u8 = 3;
pub const NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST: u8 = 4;
pub const NETWORK_MESSAGE_TYPE_FIND_VALUE_RESPONSE: u8 = 5;


pub struct AllFingersIter<'a> {
	global_index: usize,
	buckets: &'a Vec<Mutex<Bucket>>,
	bucket_iter: <Vec<NodeContactInfo> as IntoIterator>::IntoIter,
}

#[derive(Clone, Debug)]
pub struct ContactStrategy {
	pub contact: ContactOption,
	pub method: ContactStrategyMethod,
}

#[derive(Clone)]
pub enum ContactStrategyMethod {
	/// Contact the node directly
	Direct,
	/// Request the other node to contact us
	HolePunch,
	/// Relay the value through another node
	Relay,
}

pub struct FindValueIter<'a, I>
where
	I: NodeInterface + Send + Sync,
{
	pub(super) node: &'a Node<I>,
	pub(super) overlay_node: Arc<OverlayNode>,
	expect_fingers_in_response: bool,

	id: IdType,
	value_type_id: u8,
	do_verify:
		Box<dyn Fn(&IdType, &NodeContactInfo, &[u8]) -> Option<AtomicPtr<()>> + Send + Sync + 'a>,
	narrow_down: bool,
	use_relays: bool,

	visited: Vec<(IdType, ContactOption)>,
	candidates: VecDeque<(BigUint, NodeContactInfo, ContactStrategy)>,
	connection_for_reverse_connection_requests: Option<(IdType, Box<Connection>)>,
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
	pub(super) bucket_size: usize,
	pub(super) leak_first_request: bool,
}

#[async_trait]
pub trait NodeInterface {
	async fn close(&self);

	async fn exchange(
		&self, connection: &mut Connection, message_type: u8, buffer: &[u8],
	) -> sstp::Result<Vec<u8>> {
		let real_buffer = self.prepare(message_type, buffer);
		let request_message_type = real_buffer[0];
		connection.send(real_buffer).await?;

		// Receive response
		let mut response = connection.receive().await?;
		if response[0] != (request_message_type + 1) {
			return Err(sstp::Error::InvalidResponseMessageType((
				response[0],
				request_message_type + 1,
			))
			.into());
		}

		response.remove(0);
		return Ok(response);
	}

	async fn find_value(&self, value_type: u8, id: &IdType) -> db::Result<Option<Vec<u8>>>;

	fn overlay_node(&self) -> Arc<OverlayNode>;

	fn prepare(&self, message_type: u8, request: &[u8]) -> Vec<u8>;

	async fn send(
		&self, connection: &mut Connection, message_type: u8, buffer: &[u8],
	) -> sstp::Result<()> {
		let real_buffer = self.prepare(message_type, buffer);

		// Send request
		connection.send(real_buffer).await
	}
}

pub fn differs_at_bit(a: &IdType, b: &IdType) -> Option<u8> { a.differs_at_bit(b) }

impl ContactStrategy {
	fn new(contact: ContactOption, openness: Openness) -> Option<Self> {
		Some(Self {
			contact,
			method: match openness {
				Openness::Bidirectional => ContactStrategyMethod::Direct,
				Openness::Punchable => ContactStrategyMethod::HolePunch,
				Openness::Unidirectional => ContactStrategyMethod::Relay,
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
			Self::HolePunch => 1,
			Self::Relay => 2,
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
			Self::HolePunch => write!(f, "hole punch"),
			Self::Relay => write!(f, "relay"),
		}
	}
}

impl<'a, I> FindValueIter<'a, I>
where
	I: NodeInterface + Send + Sync,
{
	pub fn visited(&self) -> &[(IdType, ContactOption)] { &self.visited }
}

impl<I> Node<I>
where
	I: NodeInterface + Send + Sync + 'static,
{
	fn append_candidates(
		id: &IdType, candidates: &mut VecDeque<(BigUint, NodeContactInfo, ContactStrategy)>,
		fingers: &[(NodeContactInfo, ContactStrategy)],
	) {
		for finger in fingers {
			Self::insert_candidate(id, candidates, finger);
		}
	}

	pub async fn close(&self) {
		self.stop_flag.store(true, Ordering::Relaxed);
		self.interface.close().await;
	}

	pub async fn select_direct_connection(
		&self, target: &NodeContactInfo, request: Option<&[u8]>,
	) -> Option<(Box<Connection>, Option<Vec<u8>>)> {
		self.select_direct_connection2(&target.contact_info, Some(&target.node_id), request)
			.await
	}

	pub async fn select_direct_connection2(
		&self, target: &ContactInfo, node_id: Option<&IdType>, request: Option<&[u8]>,
	) -> Option<(Box<Connection>, Option<Vec<u8>>)> {
		if let Some((option, _)) = self.pick_contact_option(target) {
			self.connect(&option, node_id, request).await
		} else {
			None
		}
	}

	pub async fn connect(
		&self, target: &ContactOption, node_id: Option<&IdType>, request: Option<&[u8]>,
	) -> Option<(Box<Connection>, Option<Vec<u8>>)> {
		match self.socket.connect(target, node_id, request).await {
			Ok(c) => Some(c),
			Err(e) => {
				warn!("Unable to connect to {}: {}", target, e);
				if let Some(ni) = node_id {
					self.mark_node_problematic(ni).await
				}
				None
			}
		}
	}

	pub async fn connect_by_strategy(
		&self, node_info: &NodeContactInfo, strategy: &ContactStrategy,
		last_open_connection: Option<&mut Connection>, overlay_node: &Arc<OverlayNode>,
		request: Option<&[u8]>,
	) -> Option<(Box<Connection>, Option<Vec<u8>>)> {
		match &strategy.method {
			ContactStrategyMethod::Direct =>
				self.connect(&strategy.contact, Some(&node_info.node_id), request)
					.await,
			ContactStrategyMethod::HolePunch => {
				if let Some(mut relay_connection) = last_open_connection {
					// FIXME: The contact option needs to be carefully picked
					let my_contact_info = self.contact_info();
					let contact_me_option = ContactOption::new(
						SocketAddrV4::new(
							my_contact_info.ipv4.as_ref().unwrap().addr.clone().into(),
							my_contact_info.ipv4.unwrap().availability.udp.unwrap().port,
						)
						.into(),
						false,
					);
					if let Some(target_connection) = overlay_node
						.request_reversed_connection(
							&mut relay_connection,
							&node_info.node_id,
							&strategy.contact,
							&contact_me_option,
							true,
						)
						.await
					{
						Some((target_connection, None))
					} else {
						None
					}
				// If no connection to obtain reversed connection
				// with is provided, try to obtain one from the overlay network
				} else {
					// If we already have a connection with this node, don't use that one because it
					// using it will block any hole punch requests that might come in during usage.
					// Open a new connection to the node, because the existing connection has
					// already 'opened the hole'.
					if let Some(existing_connection) =
						self.find_connection_in_buckets(&node_info.node_id).await
					{
						// FIXME: contact option should be obtainable without having to lock the
						// existing connection.
						let contact_option = {
							let c = existing_connection.lock().await;
							c.contact_option()
						};
						return self
							.connect(&contact_option, Some(&node_info.node_id), request)
							.await;
					}

					if let Some(mut relay_connection) = overlay_node
						.find_connection_for_node(&node_info.node_id)
						.await
					{
						let my_contact_info = self.contact_info();
						let contact_me_option = ContactOption::new(
							SocketAddrV4::new(
								my_contact_info.ipv4.as_ref().unwrap().addr.clone().into(),
								my_contact_info.ipv4.unwrap().availability.udp.unwrap().port,
							)
							.into(),
							false,
						);
						let tc = if let Some(target_connection) = overlay_node
							.request_reversed_connection(
								&mut relay_connection,
								&node_info.node_id,
								&strategy.contact,
								&contact_me_option,
								true,
							)
							.await
						{
							Some((target_connection, None))
						} else {
							None
						};
						tc
					} else {
						None
					}
				}
			}
			ContactStrategyMethod::Relay => self
				.overlay_node()
				.open_relay(node_info)
				.await
				.map(|r| (r, None)),
		}
	}

	pub async fn connect_with_timeout(
		&self, stop_flag: Arc<AtomicBool>, target: &ContactOption, node_id: Option<&IdType>,
		request: Option<&[u8]>, timeout: Duration,
	) -> Option<(Box<Connection>, Option<Vec<u8>>)> {
		match self
			.socket
			.connect_with_timeout(stop_flag, target, node_id, request, timeout)
			.await
		{
			Ok(r) => Some(r),
			Err(e) => {
				warn!("Unable to connect to {}: {}", target, e);
				if let Some(ni) = node_id {
					self.mark_node_problematic(ni).await
				}
				None
			}
		}
	}

	pub fn contact_info(&self) -> ContactInfo { self.socket.our_contact_info() }

	pub fn differs_at_bit(&self, other_id: &IdType) -> Option<u8> {
		differs_at_bit(&self.node_id, other_id)
	}

	pub async fn exchange(
		&self, target: &NodeContactInfo, message_type: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		// If no existing connection already existed, open one
		let first_buffer = self.interface.prepare(message_type, buffer);
		let opt_request = self.first_request(&first_buffer);

		let (connection, opt_response) = self.select_direct_connection(target, opt_request).await?;
		self.handle_exchange_result(
			connection,
			opt_request.is_some(),
			opt_response,
			message_type,
			buffer,
		)
		.await
	}

	/// Exchanges a request with a response with the given contact.
	pub async fn exchange_at(
		&self, node_id: &IdType, target: &ContactOption, message_type: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		// TODO: Use an existing connection if possible.
		let first_buffer = self.interface.prepare(message_type, buffer);
		let opt_request = self.first_request(&first_buffer);
		let (connection, opt_response) = self.connect(target, Some(node_id), opt_request).await?;
		self.handle_exchange_result(
			connection,
			opt_request.is_some(),
			opt_response,
			message_type,
			buffer,
		)
		.await
	}

	pub async fn exchange_find_x_on_connection(
		&self, connection: &mut Connection, node_id: &IdType, message_type_id: u8,
	) -> Option<Vec<u8>> {
		let request = FindNodeRequest {
			node_id: node_id.clone(),
		};
		self.exchange_on_connection(
			connection,
			message_type_id,
			&binserde::serialize(&request).unwrap(),
		)
		.await
	}

	/// In the paper, this is described as the 'FIND_NODE' RPC.
	pub async fn exchange_find_node_on_connection(
		&self, connection: &mut Connection, node_id: &IdType,
	) -> Option<FindNodeResponse> {
		let raw_response_result = self
			.exchange_find_x_on_connection(
				connection,
				node_id,
				NETWORK_MESSAGE_TYPE_FIND_NODE_REQUEST,
			)
			.await;
		let raw_response = raw_response_result?;
		let result: sstp::Result<_> =
			binserde::deserialize(&raw_response).map_err(|e| Traced::new(e.into()));
		let response: FindNodeResponse = self
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		Some(response)
	}

	pub async fn exchange_find_value_on_connection(
		&self, connection: &mut Connection, id: IdType, value_type: u8,
		expect_fingers_in_response: bool,
	) -> Option<(Option<Vec<u8>>, Option<FindNodeResponse>)> {
		let request = FindValueRequest { id, value_type };
		let raw_request = binserde::serialize(&request).unwrap();
		let response_result: Option<Vec<u8>> = self
			.exchange_on_connection(
				connection,
				NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST,
				&raw_request,
			)
			.await;
		let response = response_result?;
		self.process_find_value_response(
			connection.their_node_info(),
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
		let raw_request = binserde::serialize(&request).unwrap();
		let raw_response = self
			.exchange_on_connection(
				connection,
				NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST,
				&raw_request,
			)
			.await?;
		let (value_result, fingers_result) = self
			.process_find_value_response(
				connection.their_node_info(),
				&raw_response,
				expect_fingers_in_response,
			)
			.await?;
		if let Some(value_buffer) = value_result {
			let result: sstp::Result<_> =
				binserde::deserialize(&value_buffer).map_err(|e| Traced::new(e.into()));
			let value: V = self
				.handle_connection_issue(result, &connection.their_node_info())
				.await?;
			Some((Some(value), fingers_result))
		} else {
			Some((None, fingers_result))
		}
	}

	pub async fn exchange_on_connection(
		&self, connection: &mut Connection, message_type_id: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		let result = self
			.interface
			.exchange(connection, message_type_id, buffer)
			.await;
		self.handle_connection_issue(result, connection.their_node_info())
			.await
	}

	/// Pings a peer and returns whether it succeeded or not. A.k.a. the 'PING'
	/// RPC.
	async fn exchange_ping(&self, target: &NodeContactInfo) -> Option<()> {
		let message = PingRequest {};
		self.exchange(
			target,
			NETWORK_MESSAGE_TYPE_PING_REQUEST,
			&binserde::serialize(&message).unwrap(),
		)
		.await?;
		Some(())
	}

	pub async fn exchange_ping_on_connection(&self, connection: &mut Connection) -> Option<()> {
		self.exchange_on_connection(connection, NETWORK_MESSAGE_TYPE_PING_REQUEST, &[])
			.await?;
		Some(())
	}

	/// Extracts a list of fingers to contact, and the corresponding strategy to
	/// contact the node.
	fn extract_fingers_from_response(
		&self, response: &FindNodeResponse, visited: &[(IdType, ContactOption)],
	) -> Vec<(NodeContactInfo, ContactStrategy)> {
		let mut new_fingers =
			Vec::with_capacity(response.fingers.len() + response.connected.is_some() as usize);

		for f in &response.fingers {
			match self.pick_contact_option(&f.contact_info) {
				None => {}
				Some((option, openness)) =>
					if visited.iter().find(|v| v.1 == option).is_none() {
						if let Some(strategy) = ContactStrategy::new(option, openness) {
							new_fingers.push((f.clone(), strategy));
						}
					},
			}
		}

		match &response.connected {
			None => {}
			Some(c) => match self.pick_contact_option(&c.contact_info) {
				None => {}
				Some((option, openness)) =>
					if visited.iter().find(|v| v.1 == option).is_none() {
						if let Some(strategy) = ContactStrategy::new(option, openness) {
							new_fingers.push((c.clone(), strategy));
						}
					},
			},
		}

		new_fingers
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
		let mut fingers = Vec::with_capacity(self.bucket_size);
		for i in (0..(bucket_pos + 1)).rev() {
			let additional_fingers: Vec<NodeContactInfo> = {
				let bucket = self.buckets[i].lock().await;
				if bucket.connection.is_some() {
					connection = bucket.connection.as_ref().map(|(n, _)| n.clone());
				}
				bucket
					.public_fingers_no_connection()
					.map(|n| n.clone())
					.collect()
			};

			let remaining = self.bucket_size - fingers.len();
			if remaining <= additional_fingers.len() {
				fingers.extend_from_slice(&additional_fingers[0..remaining]);
			} else {
				fingers.extend_from_slice(&additional_fingers);
			}

			if fingers.len() >= self.bucket_size {
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
		let mut fingers = Vec::with_capacity(self.bucket_size);

		// Return the fingers lower down the binary tree first, as they differ
		// at the same bit as our ID.
		// Then return the fingers otherwise lowest in the binary tree (so they actually
		// differ at a higher bit)
		for i in ((bucket_pos)..256).chain((0..bucket_pos).rev()) {
			// FIXME: Pretty ineffecient, copying the whole vector.
			let additional_fingers: Vec<NodeContactInfo> = {
				let bucket = self.buckets[i].lock().await;
				bucket.public_fingers().map(|n| n.clone()).collect()
			};
			let remaining = self.bucket_size - fingers.len();
			if remaining <= additional_fingers.len() {
				fingers.extend_from_slice(&additional_fingers[0..remaining]);
			} else {
				fingers.extend_from_slice(&additional_fingers);
			}

			if fingers.len() >= self.bucket_size {
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

	pub async fn find_connection_in_buckets(
		&self, id: &IdType,
	) -> Option<Arc<Mutex<Box<Connection>>>> {
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
			if n.node_id != self.node_id {
				match self.pick_contact_strategy(&n.contact_info) {
					None => {}
					Some(strategy) => candidates.push_back((d, n, strategy)),
				}
			}
		}
		let mut found = candidates.clone();
		while found.len() > result_limit {
			found.pop_back();
		}

		let mut i = 0;
		while candidates.len() > 0 && i < visit_limit {
			let (candidate_dist, candidate_contact, strategy) = candidates[0].clone();
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
				.connect(&strategy.contact, Some(&candidate_contact.node_id), None)
				.await
			{
				None => debug!(
					"Disregarding finger {}, unable to connect...",
					&candidate_contact.node_id
				),
				Some((mut connection, _)) => {
					match self
						.exchange_find_node_on_connection(&mut connection, &id)
						.await
					{
						None => {
							debug!("Disregarding finger {}", &candidate_contact.node_id);
						}
						Some(response) => {
							if response.is_relay_node
								&& strategy.method == ContactStrategyMethod::Direct
							{
								self.overlay_node()
									.remember_relay_node(&candidate_contact)
									.await;
							}
							let mut new_fingers =
								self.extract_fingers_from_response(&response, &visited);
							new_fingers.retain(|(f, strat)| {
								if f.node_id == self.node_id {
									return false;
								}
								if strat.method != ContactStrategyMethod::Direct {
									return false;
								}
								let finger_dist = distance(id, &f.node_id);
								finger_dist < candidate_dist
							});
							Self::append_candidates(id, &mut found, &new_fingers);
							while found.len() > result_limit {
								found.pop_back();
							}
							// If the exact ID has been found, we stop
							if new_fingers.iter().find(|f| &f.0.node_id == id).is_some() {
								break;
							}
							Self::append_candidates(id, &mut candidates, &new_fingers);
							// Prevent using candidates that were found too far back. We
							// don't intend to iterate over the whole network. Only the
							// last few candidates that were close.
							while candidates.len() > self.bucket_size {
								candidates.pop_back();
							}
						}
					}
				}
			}

			i += 1;
		}

		found.into_iter().map(|c| c.1).collect()
	}

	pub async fn find_value_from_fingers<'a>(
		&'a self, overlay_node: Arc<OverlayNode>, id: &IdType, value_type_id: u8,
		expect_fingers_in_response: bool, fingers: &[NodeContactInfo], visit_limit: usize,
		narrow_down: bool, use_relays: bool,
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
			use_relays,
			do_verify,
		)
		.await
		.next()
		.await
	}

	pub async fn find_value_from_fingers_iter<'a>(
		&'a self, overlay_node: Arc<OverlayNode>, id: &IdType, value_type_id: u8,
		expect_fingers_in_response: bool, fingers: &[NodeContactInfo], visit_limit: usize,
		narrow_down: bool, use_relays: bool,
		do_verify: impl Fn(&IdType, &NodeContactInfo, &[u8]) -> Option<AtomicPtr<()>> + Send + Sync + 'a,
	) -> FindValueIter<'a, I> {
		// Initialize the candidates by picking a contact strategy for each candidate.
		let mut candidates = VecDeque::with_capacity(fingers.len());
		for (d, n) in Self::sort_fingers(id, fingers).into_iter() {
			match self.pick_contact_strategy(&n.contact_info) {
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
			use_relays,
			visited: Vec::with_capacity(visit_limit),
			candidates,
			connection_for_reverse_connection_requests: None,
		}
	}

	fn first_request<'a>(&self, buffer: &'a [u8]) -> Option<&'a [u8]> {
		if self.leak_first_request {
			Some(buffer)
		} else {
			None
		}
	}

	pub(super) async fn handle_connection_issue<T>(
		&self, result: sstp::Result<T>, node_info: &NodeContactInfo,
	) -> Option<T> {
		match result {
			Err(e) => {
				match &*e {
					sstp::Error::Timeout(_) => {
						warn!("Problematic node {}: {:?}", node_info, e);
						self.mark_node_problematic(&node_info.node_id).await;
					}
					_ =>
						if !e.forgivable() {
							warn!("Problematic node {}: {:?}", node_info, e);
							self.reject_node(&node_info.node_id).await;
						} else {
							debug!("Connection issue with node {}: {:?}", node_info, e);
						},
				}
				None
			}
			Ok(response) => {
				self.mark_node_helpful(node_info).await;
				Some(response)
			}
		}
	}

	async fn handle_exchange_result(
		&self, mut connection: Box<Connection>, first_request_included: bool,
		opt_response: Option<Vec<u8>>, message_type: u8, request: &[u8],
	) -> Option<Vec<u8>> {
		let result = if opt_response.is_some() {
			return opt_response;
		} else if first_request_included {
			connection.receive().await
		} else {
			self.interface
				.exchange(&mut connection, message_type, request)
				.await
		};
		self.handle_connection_issue(result, connection.their_node_info())
			.await
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
		self.mark_node_helpful(&first_contact).await;

		// Keep finding new fingers until we have not been able to get any
		// closer to our own ID.
		//let current_distance = distance(&first_contact.node_id, &self.base.node_id);
		let fingers = vec![first_contact; 1];
		let neighbours = self
			.find_node_from_fingers(
				&self.node_id,
				&*fingers,
				self.bucket_size,
				100, // TODO: Make configuration variable
			)
			.await;

		// Add the last encountered fingers (neighbours) to our buckets as well, as they
		// have not been automatically added due to interaction.
		let futs = neighbours.into_iter().map(|n| async move {
			if self.test_id(&n).await == true {
				self.mark_node_helpful(&n).await;
			} else {
				warn!("Connecting to neighbour {} failed", &n.node_id);
			}
		});
		join_all(futs).await;

		true
	}

	pub async fn iter_all_fingers(&self) -> AllFingersIter<'_> {
		AllFingersIter {
			global_index: 255,
			bucket_iter: self.buckets[255].lock().await.public_fingers2().into_iter(),
			buckets: &self.buckets,
		}
	}

	/// Use this if a node is giving a timeout.
	async fn mark_node_problematic(&self, node_id: &IdType) {
		if let Some(bucket_index) = self.differs_at_bit(node_id) {
			let removed = {
				let mut bucket = self.buckets[bucket_index as usize].lock().await;
				bucket.mark_problematic(node_id)
			};
			if removed {
				warn!("Node {} has been removed.", node_id);
			}
		}
	}

	async fn mark_node_helpful(&self, node_info: &NodeContactInfo) {
		if let Some(bucket_index) = self.differs_at_bit(&node_info.node_id) {
			let mut bucket = self.buckets[bucket_index as usize].lock().await;
			bucket.mark_helpful(node_info, false);
		}
	}

	async fn mark_obtained_value(&self, node_id: &IdType) {
		if let Some(mutex) = self.find_bucket(node_id).await {
			mutex.lock().await.mark_obtained_value(node_id);
		}
	}

	pub fn new(
		stop_flag: Arc<AtomicBool>, node_id: IdType, socket: Arc<sstp::Server>, interface: I,
		bucket_size: usize, leak_first_request: bool,
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
			bucket_size,
			leak_first_request,
		}
	}

	pub fn node_id(&self) -> &IdType { &self.node_id }

	fn pick_contact_option(&self, target: &ContactInfo) -> Option<(ContactOption, Openness)> {
		self.socket.pick_contact_option(target)
	}

	pub(super) fn pick_contact_strategy(&self, target: &ContactInfo) -> Option<ContactStrategy> {
		let (option, openness) = self.pick_contact_option(target)?;
		let method = match openness {
			Openness::Bidirectional => ContactStrategyMethod::Direct,
			Openness::Punchable => ContactStrategyMethod::HolePunch,
			Openness::Unidirectional => {
				let own_openness = self.contact_info().openness_at_option(&option)?;
				if own_openness != Openness::Unidirectional {
					if self.node_id.to_string() != "gGCoKktsmezqAaYwkZmN4k3pUC8c5m5AWPZZgB9bFB8" {
						//panic!("hole punch?! own={} {}", own_openness,
						// self.contact_info());
					}
					ContactStrategyMethod::HolePunch
				} else {
					ContactStrategyMethod::Relay
				}
			}
		};

		Some(ContactStrategy {
			method,
			contact: option,
		})
	}

	async fn process_find_node_request(&self, buffer: &[u8]) -> MessageProcessorResult {
		let request: FindNodeRequest = match binserde::deserialize(buffer) {
			Err(e) => {
				error!("Malformed find node request: {}", e);
				return None;
			}
			Ok(r) => r,
		};

		// Collect all fingers we have
		let (connected, fingers) = self.find_nearest_contacts(&request.node_id).await;
		let response = FindNodeResponse {
			is_relay_node: self.overlay_node().is_relay_node,
			connected,
			fingers,
		};
		self.simple_result(NETWORK_MESSAGE_TYPE_FIND_NODE_RESPONSE, &response)
	}

	async fn process_find_value_response(
		&self, node_info: &NodeContactInfo, response: &[u8], expect_fingers_in_response: bool,
	) -> Option<(Option<Vec<u8>>, Option<FindNodeResponse>)> {
		// If fingers are expected in the response, parse them
		let (contacts, contacts_len) = if expect_fingers_in_response {
			let result: sstp::Result<FindNodeResponse> =
				binserde::deserialize_with_trailing(&response).map_err(|e| Traced::new(e.into()));

			let contacts = self.handle_connection_issue(result, node_info).await?;
			let contacts_len = binserde::serialized_size(&contacts).unwrap();
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
						trace::err(sstp::Error::MalformedMessage(None)),
						node_info,
					)
					.await;
			}
		}
	}

	async fn process_find_value_request(
		&self, buffer: &[u8], overlay_node: Arc<OverlayNode>, actor_id: Option<&IdType>,
	) -> MessageProcessorResult {
		let force_including_fingers = actor_id.is_none();

		let request: FindValueRequest = match binserde::deserialize(buffer) {
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
				error!(
					"Database error occurred processing find value request for value {} (type \
					 {}): {}",
					&request.id, request.value_type, e
				);
				return None;
			}
			Ok(r) => r,
		};

		// Start response with a FindNodeResponse if not found or expected anyway
		let mut b = if force_including_fingers {
			// Collect all fingers we have
			let (connection, fingers) = self.find_nearest_contacts(&request.id).await;
			let response = FindNodeResponse {
				is_relay_node: self.overlay_node().is_relay_node,
				connected: connection,
				fingers,
			};

			let mut buffer = binserde::serialize(&response).unwrap();
			let mut value_buffer = value_result.unwrap_or_default();
			buffer.append(&mut value_buffer);
			buffer
		} else {
			let mut buffer = vec![value_result.is_some() as u8; 1];
			if let Some(value) = value_result {
				buffer.extend(value);
			} else {
				let (connection, fingers) = self.find_nearest_contacts(&request.id).await;
				let response = FindNodeResponse {
					is_relay_node: self.overlay_node().is_relay_node,
					connected: connection,
					fingers,
				};

				buffer.extend(binserde::serialize(&response).unwrap());
			}
			buffer
		};

		b.insert(0, NETWORK_MESSAGE_TYPE_FIND_VALUE_RESPONSE);
		Some((b, None))
	}

	async fn process_ping_request(&self, addr: &SocketAddr) -> MessageProcessorResult {
		debug!("Received ping request from {}", addr);
		let response = PingResponse {};
		self.simple_result(NETWORK_MESSAGE_TYPE_PING_RESPONSE, &response)
	}

	pub(super) async fn process_request(
		self: &Arc<Self>, overlay_node: Arc<OverlayNode>, message_type: u8, buffer: &[u8],
		addr: &SocketAddr, _node_info: &NodeContactInfo, actor_id: Option<&IdType>,
	) -> (MessageProcessorResult, bool) {
		let result = match message_type {
			NETWORK_MESSAGE_TYPE_PING_REQUEST => self.process_ping_request(addr).await,
			NETWORK_MESSAGE_TYPE_FIND_NODE_REQUEST => self.process_find_node_request(buffer).await,
			NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST =>
				self.process_find_value_request(buffer, overlay_node, actor_id)
					.await,
			_ => return (None, false),
		};
		(result, true)
	}

	/// Pings a node and returns its latency and node ID .
	pub async fn ping(&self, target: &NodeContactInfo) -> Option<u32> {
		let start = SystemTime::now();
		self.exchange_ping(target).await?;
		let stop = SystemTime::now();
		let latency = stop.duration_since(start).unwrap().as_millis() as u32;
		Some(latency)
	}

	/// Removes the node from our buckets.
	async fn reject_node(&self, node_id: &IdType) {
		if let Some(bucket_index) = self.differs_at_bit(node_id) {
			let mut bucket = self.buckets[bucket_index as usize].lock().await;
			bucket.reject(node_id);
		}
	}

	pub(super) fn simple_response<T>(&self, message_type: u8, response: &T) -> Vec<u8>
	where
		T: Serialize,
	{
		let response_len = binserde::serialized_size(response).unwrap();
		let mut buffer = vec![message_type; 1 + response_len];
		binserde::serialize_into(&mut buffer[1..], response).unwrap();
		buffer
	}

	pub(super) fn simple_result<T>(&self, message_type: u8, response: &T) -> MessageProcessorResult
	where
		T: Serialize,
	{
		let buffer = self.simple_response(message_type, response);
		Some((buffer, None))
	}

	pub async fn select_connection(
		&self, node_info: &NodeContactInfo, request: Option<&[u8]>,
	) -> Option<(Box<Connection>, Option<Vec<u8>>)> {
		if let Some(strategy) = self.pick_contact_strategy(&node_info.contact_info) {
			self.connect_by_strategy(&node_info, &strategy, None, &self.overlay_node(), request)
				.await
		} else {
			None
		}
	}

	pub fn set_contact_info(&self, contact_info: ContactInfo) {
		self.socket.set_contact_info(contact_info);
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
		let (mut connection, _) = self.select_direct_connection2(target, None, None).await?;
		let their_node_id = connection.their_node_id().clone();
		let result = self.exchange_ping_on_connection(&mut connection).await;
		result?;
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
				if self.global_index > 0 {
					self.global_index -= 1;
					self.bucket_iter = self.buckets[self.global_index]
						.lock()
						.await
						.public_fingers2()
						.into_iter();
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
	I: NodeInterface + Send + Sync + 'static,
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
			if strategy.method == ContactStrategyMethod::Relay && !self.use_relays {
				continue;
			}
			let mut special_connection: Option<Box<Connection>> = None;
			let mut reversed_connection = if strategy.method == ContactStrategyMethod::HolePunch
				&& self
					.node
					.contact_info()
					.is_open_to_reversed_connections(&candidate_contact.contact_info)
			{
				if let Some((node_id, connection)) =
					&mut self.connection_for_reverse_connection_requests
				{
					if node_id == &candidate_contact.node_id {
						Some(connection)
					} else {
						None
					}
				} else {
					None
				}
			} else {
				None
			};
			match self
				.node
				.connect_by_strategy(
					&candidate_contact,
					&strategy,
					reversed_connection.as_deref_mut().map(|c| c.as_mut()),
					&self.overlay_node,
					None,
				)
				.await
			{
				None => {
					special_connection.take();
					debug!("Disregarding finger {}", &candidate_contact)
				}
				Some((mut connection, _)) => {
					special_connection.take();

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
						None => {}
						Some((possible_value, possible_contacts)) => {
							// If node returned new fingers, append them to our list
							if let Some(find_node_response) = possible_contacts {
								if find_node_response.is_relay_node
									&& strategy.method == ContactStrategyMethod::Direct
								{
									self.node
										.overlay_node()
										.remember_relay_node(&candidate_contact)
										.await;
								}
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
									while self.candidates.len() > self.node.bucket_size {
										self.candidates.pop_back();
									}
								}

								if let Some(connected_contact) = find_node_response.connected {
									if let Some((_, previous_connection)) =
										self.connection_for_reverse_connection_requests.as_mut()
									{
										previous_connection.close().await;
									}
									self.connection_for_reverse_connection_requests =
										Some((connected_contact.node_id, connection));
								}
							}

							// If a value was found, return it, otherwise keep the search loop going
							if let Some(value) = possible_value {
								if let Some(result) =
									(self.do_verify)(&self.id, &candidate_contact, &value)
								{
									self.node
										.mark_obtained_value(&candidate_contact.node_id)
										.await;
									return Some(result);
								}
							}
						}
					}
				}
			}
		}
		None
	}
}

impl<I> Deref for Node<I>
where
	I: NodeInterface,
{
	type Target = I;

	fn deref(&self) -> &I { &self.interface }
}

// Runs a loop that continiously accepts requests, processes them (which
// returns a response). It stops if the connection is closed, or if some sort
// of network error (like a timeout) occurred. So a node receiving a connection
// will keep listening on the same connection until the sending node is done
// with it.
/*pub(super) async fn handle_connection(overlay_node: Arc<OverlayNode>, c: Box<Connection>) {
	// Otherwise, just process the incomming requests
	let mut is_first_message = true;
	let mut connection = Some(c);
	while let Some(mut c) = connection {
		if !overlay_node.base.stop_flag.load(Ordering::Relaxed) {
			return;
		}

		let message = {
			match c.wait_for(Duration::from_secs(30)).await {
				Ok(m) => m,
				Err(e) => {
					match &*e {
						sstp::Error::Timeout(_) => {
							if is_first_message {
								debug!(
									"Node {} timed out before request was received.",
									c.peer_address(),
								);
								print!(
									"Node {} timed out before request was received.",
									c.peer_address(),
								);
							} else {
								debug!(
									"Node {} timeoued out before additional request was received.",
									c.peer_address()
								);
							}
							break;
						}
						// Opening and immediately closing connections is done to test presence, so
						// ignore these two errors for now:
						sstp::Error::ConnectionClosed => {
							break;
						}
						other => {
							// For the other errors the connection may have not been closed already.
							error!(
								"Unable to properly receive full request from {}: {}",
								c.peer_address(),
								other
							);
							break;
						}
					}
				}
			}
		};
		is_first_message = false;
		connection = process_request_message(overlay_node.clone(), c, &message).await;
	}
}*/

/*pub(super) async fn handle_find_value_connection(
	overlay_node: &Arc<OverlayNode>, connection: &mut Connection,
) {
	let mut is_first_message = true;
	while !overlay_node.base.stop_flag.load(Ordering::Relaxed) {
		let message = {
			match connection.receive().await {
				Ok(m) => m,
				Err(e) => {
					match &*e {
						sstp::Error::Timeout(_) => {
							if is_first_message {
								debug!(
									"Node {} timed out before find value request was received",
									connection.peer_address(),
								);
								print!(
									"Node {} timed out before find value request was received",
									connection.peer_address(),
								);
							}
							let _ = connection.close().await;
							break;
						}
						// Opening and immediately closing connections is done to test presence, so
						// ignore these two errors for now:
						sstp::Error::ConnectionClosed => {
							break;
						}
						other => {
							// For the other errors the connection may have not been closed already.
							let _ = connection.close().await;
							error!(
								"Unable to properly receive full request from {}: {}",
								connection.peer_address(),
								other
							);
							break;
						}
					}
				}
			}
		};
		is_first_message = false;

		if (message[0] & 0x7F) != NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST {
			warn!("Something other than a find value request has been received");
			return;
		}
		process_find_value_request_message(overlay_node.clone(), connection, &message).await;
	}
}*/

/*pub(super) async fn keep_alive_connection(overlay_node: Arc<OverlayNode>, mut c2: Box<Connection>) {
	let timeout = Duration::from_secs(120);
	c2.set_keep_alive_timeout(timeout).await;
	let mut c = Some(c2);
	while let Some(mut connection) = c {
		if overlay_node.base.has_stopped() {
			return;
		}

		let message = {
			match connection.wait_for(timeout).await {
				Ok(m) => m,
				Err(e) => {
					match &*e {
						// If the node hasn't send any pings for 120 seconds, we're done
						sstp::Error::Timeout(_) => {
							debug!(
								"Kept alive connection has timed out. [{} -> {}]",
								connection.our_session_id(),
								connection.their_session_id()
							);
							break;
						}
						// The other end closed the connection, so stop
						sstp::Error::ConnectionClosed => {
							break;
						}
						other => {
							// For the other errors the connection may have not been closed already.
							let _ = connection.close().await;
							error!(
								"Unable to properly receive full request from {}: {}",
								connection.peer_address(),
								other
							);
							break;
						}
					}
				}
			}
		};

		c = process_request_message(overlay_node.clone(), connection, &message).await;
	}
}*/

/*async fn process_find_value_request_message(
	overlay_node: Arc<OverlayNode>, connection: &mut Connection, buffer: &[u8],
) {
	let mut message_type_id = buffer[0];
	if message_type_id >= 0x80 {
		message_type_id ^= 0x80;
		if message_type_id != NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST {
			return;
		}

		let actor_id: IdType = binserde::deserialize(&buffer[1..33]).unwrap();
		let actor_nodes = overlay_node.base.interface.actor_nodes.lock().await;
		let actor_node = match actor_nodes.get(&actor_id) {
			None => return, /* Don't respond to requests for networks we are not connected */
			// to.
			Some(n) => n.clone(),
		};
		drop(actor_nodes);

		let r = actor_node
			.base
			.process_find_value_request(&buffer[33..], overlay_node.clone(), Some(&actor_id))
			.await;

		match r {
			None => {}
			Some(response) => {
				debug_assert!(
					response.len() > 0,
					"actor response must be more than 0 bytes ({})",
					message_type_id,
				);
				if let Err(e) = actor_node
					.base
					.interface
					.respond(connection, message_type_id + 1, &response)
					.await
				{
					warn!("Unable to respond to actor request: {}", e);
					actor_node
						.base
						.mark_node_problematic(connection.their_node_id())
						.await;
				} else {
					actor_node
						.base
						.mark_node_helpful(connection.their_node_info())
						.await;
				}
			}
		}
	}
}*/

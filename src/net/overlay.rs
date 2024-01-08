use std::{
	boxed::Box,
	collections::HashMap,
	net::SocketAddr,
	str::FromStr,
	sync::{atomic::*, Arc, Mutex as StdMutex, OnceLock},
};

use async_trait::async_trait;
use futures::{
	channel::oneshot,
	future::{join_all, BoxFuture},
};
use log::*;
use tokio::{self, select, spawn, sync::Mutex, time::sleep};

use super::{actor::*, actor_store::*, bincode, message::*, node::*, sstp};
use crate::{
	common::*,
	config::*,
	db::{self, Database},
	identity::*,
	limited_store::LimitedVec,
	model::*,
	net::*,
};


// Messages for the overlay network:
pub const OVERLAY_MESSAGE_TYPE_FIND_ACTOR_REQUEST: u8 = 64;
//pub const OVERLAY_MESSAGE_TYPE_ID_FIND_ACTOR_RESPONSE: u8 = 65;
pub const OVERLAY_MESSAGE_TYPE_STORE_ACTOR_REQUEST: u8 = 66;
//pub const OVERLAY_MESSAGE_TYPE_ID_STORE_ACTOR_RESPONSE: u8 = 67;
pub const OVERLAY_MESSAGE_TYPE_PUNCH_HOLE_REQUEST: u8 = 68;
//pub const OVERLAY_MESSAGE_TYPE_PUNCH_HOLE_RESPONSE: u8 = 69;
pub const OVERLAY_MESSAGE_TYPE_RELAY_PUNCH_HOLE_REQUEST: u8 = 70;
//pub const OVERLAY_MESSAGE_TYPE_RELAY_PUNCH_HOLE_RESPONSE: u8 = 71;
pub const OVERLAY_MESSAGE_TYPE_OPEN_RELAY_REQUEST: u8 = 72;
pub const OVERLAY_MESSAGE_TYPE_OPEN_RELAY_RESPONSE: u8 = 73;
pub const OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_REQUEST: u8 = 74;
//pub const OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_RESPONSE: u8 = 75;
pub const OVERLAY_MESSAGE_TYPE_START_RELAY_REQUEST: u8 = 76;
//pub const OVERLAY_MESSAGE_TYPE_START_RELAY_RESPONSE: u8 = 77;


pub struct ConnectActorIter<'a> {
	base: FindActorIter<'a>,
	actor_info: Option<ActorInfo>,
	state: u8,
	pi: usize,
	ri: usize,
	punchable_nodes: Vec<(NodeContactInfo, ContactOption)>,
	relayable_nodes: Vec<NodeContactInfo>,
}
pub struct FindActorIter<'a>(FindValueIter<'a, OverlayInterface>);

/*#[derive(Clone, Default)]
struct OverlayBucket {
	pub base: StandardBucket
}*/

pub struct OverlayNode {
	pub(super) base: Arc<Node<OverlayInterface>>,
	bootstrap_nodes: Vec<SocketAddr>,
	pub(super) expected_connections:
		Arc<Mutex<HashMap<ContactOption, oneshot::Sender<Box<sstp::Connection>>>>>,
	pub(super) is_super_node: bool,
	super_nodes: Mutex<LimitedVec<(IdType, ContactOption)>>,
}

pub(super) struct OverlayInterface {
	node: OnceLock<Option<Arc<OverlayNode>>>,
	db: Database,
	pub(super) actor_nodes: Mutex<HashMap<IdType, Arc<ActorNode>>>,
	max_idle_time: usize,
	last_message_time: StdMutex<SystemTime>,
}


#[async_trait]
impl NodeInterface for OverlayInterface {
	async fn close(&self) {
		let mut actor_nodes = self.actor_nodes.lock().await;
		for (_, actor_node) in actor_nodes.drain() {
			actor_node.close().await;
		}
		let _ = self.node.set(None);
	}

	async fn exchange(
		&self, connection: &mut Connection, message_type: u8, buffer: &[u8],
	) -> sstp::Result<Vec<u8>> {
		self.send(connection, message_type, buffer).await?;

		// Receive response
		let mut response = connection.receive().await?;
		if response[0] != (message_type + 1) {
			return Err(
				sstp::Error::InvalidResponseMessageType((response[0], message_type + 1)).into(),
			);
		}
		response.remove(0);
		return Ok(response);
	}

	async fn find_value(&self, value_type: u8, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		if value_type > 0 {
			return Ok(None);
		}

		// Check what we have in memory first.
		let node_actor_store = NODE_ACTOR_STORE.lock().await;
		let value = if let Some(store_entry) = node_actor_store.find(id) {
			let actor_info = store_entry.actor_info.clone();
			let peers: Vec<NodeContactInfo> =
				store_entry.available_nodes.clone().into_iter().collect();
			drop(node_actor_store);

			let actor_nodes = self.actor_nodes.lock().await;
			let i_am_available = actor_nodes.contains_key(id);
			drop(actor_nodes);

			FindActorResult {
				actor_info,
				i_am_available,
				peers,
			}
		}
		// Otherwise, check our database
		else {
			let result = tokio::task::block_in_place(|| {
				let db = self.db.connect()?;
				db.fetch_identity(id)
			})?;
			if result.is_none() {
				return Ok(None);
			}
			let actor_info = result.unwrap();

			FindActorResult {
				actor_info,
				i_am_available: false,
				peers: Vec::new(),
			}
		};

		Ok(Some(bincode::serialize(&value).unwrap()))
	}

	fn overlay_node(&self) -> Arc<OverlayNode> {
		self.node
			.get()
			.expect("missing node in overlay interface")
			.as_ref()
			.expect("overlay interface already closed")
			.clone()
	}

	async fn send(
		&self, connection: &mut Connection, message_type: u8, buffer: &[u8],
	) -> sstp::Result<()> {
		*self.last_message_time.lock().unwrap() = SystemTime::now();

		// Send request
		let mut real_buffer = Vec::with_capacity(1 + buffer.len());
		real_buffer.push(message_type);
		real_buffer.extend(buffer);
		connection.send(&real_buffer).await
	}

	async fn respond(
		&self, connection: &mut Connection, message_type: u8, buffer: &[u8],
	) -> sstp::Result<()> {
		self.send(connection, message_type, buffer).await
	}
}

impl<'a> FindActorIter<'a> {
	pub fn visited(&self) -> &[(IdType, ContactOption)] { self.0.visited() }

	pub fn close(&mut self) { self.0.close(); }
}

#[async_trait]
impl<'a> AsyncIterator for FindActorIter<'a> {
	type Item = Box<(ActorInfo, Vec<NodeContactInfo>)>;

	async fn next(&mut self) -> Option<Self::Item> {
		let result = self.0.next().await;
		result.map(|p| unsafe {
			Box::from_raw(p.into_inner() as *mut (ActorInfo, Vec<NodeContactInfo>))
		})
	}
}

impl<'a> ConnectActorIter<'a> {
	pub fn visited(&self) -> &[(IdType, ContactOption)] { self.base.visited() }

	pub fn close(&mut self) { self.base.close(); }
}

#[async_trait]
impl<'a> AsyncIterator for ConnectActorIter<'a> {
	type Item = (Box<Connection>, ActorInfo);

	async fn next(&mut self) -> Option<Self::Item> {
		// At first, just try bidirectional nodes only
		if self.state == 0 {
			while let Some(result) = self.base.next().await {
				let (ai, actor_nodes) = *result;
				if self.actor_info.is_none() {
					self.actor_info = Some(ai);
				}

				// Try all unidirectional nodes first, just remember the others
				for node in actor_nodes {
					if let Some(strategy) =
						self.base.0.node.pick_contact_strategy(&node.contact_info)
					{
						match strategy.method {
							ContactStrategyMethod::Relay => {
								self.relayable_nodes.push(node);
							}
							ContactStrategyMethod::HolePunch => {
								self.punchable_nodes.push((node.clone(), strategy.contact));
							}
							ContactStrategyMethod::Direct => {
								if let Some(connection) = self
									.base
									.0
									.node
									.connect(&strategy.contact, Some(&node.node_id))
									.await
								{
									return Some((connection, self.actor_info.clone().unwrap()));
								}
							}
						}
					}
				}
			}
			self.state = 1;
		}

		// Then, try all the punchable nodes we've encountered
		if self.state == 1 {
			for i in self.pi..self.punchable_nodes.len() {
				let (node_info, contact_option) = &self.punchable_nodes[i];
				let strategy = ContactStrategy {
					method: ContactStrategyMethod::HolePunch,
					contact: contact_option.clone(),
				};
				// FIXME: There needs to be a "self.base.connect_through_hole_punching"
				// function or something like that...
				if let Some(connection) = self
					.base
					.0
					.node
					.connect_by_strategy(&node_info, &strategy, None, &self.base.0.overlay_node)
					.await
				{
					self.pi = i + 1;
					return Some((connection, self.actor_info.as_ref().unwrap().clone()));
				}
			}
			self.pi = self.punchable_nodes.len();

			for i in self.ri..self.relayable_nodes.len() {
				let node_info = &self.relayable_nodes[i];
				if let Some(connection) = self.base.0.overlay_node.open_relay(node_info).await {
					self.ri = i + 1;
					return Some((connection, self.actor_info.as_ref().unwrap().clone()));
				}
			}
			self.ri = self.relayable_nodes.len();
		}

		None
	}
}

impl OverlayNode {
	pub async fn close(self: Arc<Self>) { self.base.close().await; }

	pub async fn start(
		stop_flag: Arc<AtomicBool>, node_id: IdType, contact_info: ContactInfo,
		private_key: PrivateKey, db: Database, config: &Config,
	) -> sstp::Result<Arc<Self>> {
		let mut bootstrap_nodes = Vec::<SocketAddr>::with_capacity(config.bootstrap_nodes.len());
		for address_string in &config.bootstrap_nodes {
			match SocketAddr::from_str(address_string) {
				Err(e) => error!("Unable to parse bootstrap node {}: {}.", address_string, e),
				Ok(s) => bootstrap_nodes.push(s),
			}
		}

		let socket = sstp::Server::bind(
			stop_flag.clone(),
			node_id.clone(),
			contact_info.clone(),
			private_key,
			sstp::DEFAULT_TIMEOUT,
		)
		.await?;

		let this = Arc::new(Self {
			base: Arc::new(Node::new(
				stop_flag,
				node_id,
				socket.clone(),
				OverlayInterface {
					node: OnceLock::new(),
					db,
					last_message_time: StdMutex::new(SystemTime::now()),
					max_idle_time: config.udp_max_idle_time,
					actor_nodes: Mutex::new(HashMap::new()),
				},
				config.bucket_size,
			)),
			bootstrap_nodes,
			expected_connections: Arc::new(Mutex::new(HashMap::new())),
			is_super_node: config.super_node,
			super_nodes: Mutex::new(LimitedVec::new(100)),
		});
		debug_assert!(this.base.interface.node.set(Some(this.clone())).is_ok());

		let this2 = this.clone();
		socket.listen(move |connection| {
			let this3 = this2.clone();
			tokio::spawn(async move {
				// Check if reversed connection is expected
				{
					let mut expected_connections = this3.expected_connections.lock().await;
					if let Some(tx) = expected_connections.remove(&connection.contact_option()) {
						if tx.is_canceled() {
							warn!("Unable to pass expected connection along: sender is closed.");
						} else {
							if let Err(_) = tx.send(connection) {
								error!("Unable to pass expected connection along.");
							}
						}
						return;
					}
				}

				// If not, just handle it like any other
				handle_connection(this3, connection).await;
			});
		});
		socket.spawn();

		Ok(this)
	}

	//pub fn contact_info(&self) -> &IdType { &self.base.node_info.contact_info }

	pub fn db(&self) -> &db::Database { &self.base.interface.db }

	pub async fn drop_actor_network(&self, actor_id: &IdType) -> bool {
		match self
			.base
			.interface
			.actor_nodes
			.lock()
			.await
			.remove(actor_id)
		{
			None => false,
			Some(_node) => {
				//node

				true
			}
		}
	}

	pub async fn exchange_find_x(
		&self, target: &NodeContactInfo, node_id: &IdType, message_type_id: u8,
	) -> Option<Vec<u8>> {
		let request = FindNodeRequest {
			node_id: node_id.clone(),
		};
		self.base
			.exchange(
				target,
				message_type_id,
				&bincode::serialize(&request).unwrap(),
			)
			.await
	}

	/// In the paper, this is described as the 'FIND_VALUE' RPC.
	pub async fn exchange_find_actor(
		&self, target: &NodeContactInfo, node_id: &IdType,
	) -> Option<FindActorResponse> {
		let raw_response = self
			.exchange_find_x(target, node_id, OVERLAY_MESSAGE_TYPE_FIND_ACTOR_REQUEST)
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: FindActorResponse = self.base.handle_connection_issue(result, target).await?;
		Some(response)
	}

	/// Pings a peer and returns whether it succeeded or not. A.k.a. the 'PING'
	/// RPC.
	pub async fn exchange_keep_alive_on_connection(
		&self, connection: &mut Connection,
	) -> Option<bool> {
		let raw_response = self
			.base
			.exchange_on_connection(connection, OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_REQUEST, &[])
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: KeepAliveResponse = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		Some(response.ok)
	}

	pub async fn exchange_open_relay_on_connection(
		&self, connection: &mut Connection, target: NodeContactInfo,
	) -> Option<bool> {
		let request = OpenRelayRequest { target };
		// FIXME: This should have about 4 times the default timeout because the relay
		// node needs to reach the other node before responding
		let raw_response = self
			.base
			.exchange_on_connection(
				connection,
				OVERLAY_MESSAGE_TYPE_OPEN_RELAY_REQUEST,
				&bincode::serialize(&request).unwrap(),
			)
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: OpenRelayResponse = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		Some(response.ok)
	}

	pub(super) async fn exchange_punch_hole_on_connection(
		&self, connection: &mut Connection, source_node_id: IdType,
		source_contact_option: ContactOption,
	) -> Option<bool> {
		let request = InitiateConnectionRequest {
			source_node_id,
			source_contact_option,
		};
		let raw_response = self
			.base
			.exchange_on_connection(
				connection,
				OVERLAY_MESSAGE_TYPE_PUNCH_HOLE_REQUEST,
				&bincode::serialize(&request).unwrap(),
			)
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: InitiateConnectionResponse = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		Some(response.ok)
	}

	/// Asks a peer to relay an initiate connection request to the destination
	/// target for you.
	async fn exchange_relay_punch_hole_request(
		&self, relay_connection: &mut Connection, target: IdType, contact_option: ContactOption,
	) -> Option<bool> {
		let message = RelayInitiateConnectionRequest {
			target,
			contact_option,
		};
		let raw_response = self
			.base
			.exchange_on_connection(
				relay_connection,
				OVERLAY_MESSAGE_TYPE_RELAY_PUNCH_HOLE_REQUEST,
				&bincode::serialize(&message).unwrap(),
			)
			.await;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response?).map_err(|e| e.into());
		let response: RelayInitiateConnectionResponse = self
			.base
			.handle_connection_issue(result, &relay_connection.their_node_info())
			.await?;
		Some(response.ok)
	}

	async fn exchange_start_relay_on_connection(
		&self, connection: &mut Connection, origin: NodeContactInfo,
	) -> Option<bool> {
		let request = StartRelayRequest { origin };
		let raw_response = self
			.base
			.exchange_on_connection(
				connection,
				OVERLAY_MESSAGE_TYPE_START_RELAY_REQUEST,
				&bincode::serialize(&request).unwrap(),
			)
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: StartRelayResponse = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		Some(response.ok)
	}

	pub async fn exchange_store_actor(
		&self, target: &NodeContactInfo, actor_id: IdType, actor_info: ActorInfo,
	) -> Option<()> {
		let request = StoreActorRequest {
			actor_id,
			actor_info,
		};
		self.base
			.exchange(
				target,
				OVERLAY_MESSAGE_TYPE_STORE_ACTOR_REQUEST,
				&bincode::serialize(&request).unwrap(),
			)
			.await?;
		Some(())
	}

	pub async fn exchange_store_actor_at(
		&self, node_id: &IdType, target: &ContactOption, actor_id: IdType, actor_info: ActorInfo,
	) -> Option<()> {
		let request = StoreActorRequest {
			actor_id,
			actor_info,
		};
		self.base
			.exchange_at(
				node_id,
				target,
				OVERLAY_MESSAGE_TYPE_STORE_ACTOR_REQUEST,
				&bincode::serialize(&request).unwrap(),
			)
			.await?;
		Some(())
	}

	pub async fn exchange_store_actor_on_connection(
		&self, connection: &mut Connection, actor_id: IdType, actor_info: ActorInfo,
	) -> Option<()> {
		let request = StoreActorRequest {
			actor_id,
			actor_info,
		};
		let raw_request = bincode::serialize(&request).unwrap();
		self.base
			.exchange_on_connection(
				connection,
				OVERLAY_MESSAGE_TYPE_STORE_ACTOR_REQUEST,
				&raw_request,
			)
			.await?;
		Some(())
	}

	pub async fn find_connection_from_buckets(
		&self, id: &IdType,
	) -> Option<Arc<Mutex<Box<sstp::Connection>>>> {
		if let Some(bucket_pos) = self.base.differs_at_bit(id) {
			let bucket = self.base.buckets[bucket_pos as usize].lock().await;
			return bucket.connection.as_ref().map(|c| c.1.clone());
		}
		None
	}

	/// Tries to connect to the actor network of the given actor ID, but in
	/// 'lurking' mode. Meaning, the nodes of the network won't consider you as
	/// a part of it.
	pub async fn find_actor_profile_info(self: &Arc<Self>, actor_id: &IdType) -> Option<Object> {
		let mut iter = self.connect_actor_iter(actor_id).await;
		let (node, object) = loop {
			if let Some((mut connection, actor_info)) = iter.next().await {
				let node = Arc::new(ActorNode::new_lurker(
					self.base.stop_flag.clone(),
					self.clone(),
					self.base.socket.clone(),
					actor_id.clone(),
					actor_info.clone(),
					self.db().clone(),
					self.base.bucket_size,
				));

				let (object_id, object) =
					if let Some(r) = node.exchange_profile_on_connection(&mut connection).await {
						r
					} else {
						connection.close_async();
						continue;
					};

				// We need to store the identity in order for the object to be able to be stored
				let result = tokio::task::block_in_place(|| {
					let mut db = self.db().connect()?;
					db.store_identity(actor_id, &actor_info.public_key, &actor_info.first_object)
				});
				if let Err(e) = result {
					error!("Unable to store identity: {}", e);
					connection.close_async();
					iter.close();
					return Some(object);
				}

				// Then we can collect all the values related to this identity
				match node
					.collect_object(&mut connection, &object_id, &object, false)
					.await
				{
					Ok(done) =>
						if done {
							connection.close_async();
							iter.close();
							return Some(object);
						},
					Err(e) => {
						error!("Unable collect object on first connection: {}", e);
						connection.close_async();
						iter.close();
						return Some(object);
					}
				}
				// If we don't have all the files and blocks yet, attempt to synchronize
				// (outside of the loop)
				connection.close_async();
				break (node, object);
			} else {
				iter.close();
				return None;
			}
		};
		iter.close();

		// Try to synchronize the missing files and blocks. Only works if there are some
		// bidirectional nodes available.
		if let Err(e) = node.synchronize_files().await {
			error!("Database error while synchronizing files: {}", e);
			return Some(object);
		}
		if let Err(e) = node.synchronize_blocks().await {
			error!("Database error while synchronizing files: {}", e);
			return Some(object);
		}

		Some(object)
	}

	pub async fn find_actor(
		self: &Arc<Self>, id: &IdType, hop_limit: usize, narrow_down: bool,
	) -> Option<Box<(ActorInfo, Vec<NodeContactInfo>)>> {
		let mut iter = self.find_actor_iter(id, hop_limit, narrow_down).await;
		let result = iter.next().await;
		iter.close();
		result
	}

	/// Tries to find the
	pub async fn find_actor_iter<'a>(
		self: &'a Arc<Self>, id: &IdType, hop_limit: usize, narrow_down: bool,
	) -> FindActorIter<'a> {
		fn verify_pubkey(
			id: &IdType, peer: &NodeContactInfo, data: &[u8],
		) -> Option<AtomicPtr<()>> {
			match bincode::deserialize::<FindActorResult>(&data) {
				Err(e) => {
					warn!("Received invalid actor info from node: {}", e);
					None
				}
				Ok(result) => {
					let actor_info_bytes = bincode::serialize(&result.actor_info).unwrap();
					let actor_info_hash = IdType::hash(&actor_info_bytes);
					if &actor_info_hash != id {
						warn!("Received invalid actor info from node: invalid hash");
						return None;
					}
					let mut peers: Vec<NodeContactInfo> = result.peers;

					if result.i_am_available {
						peers.insert(0, peer.clone());
					}
					let value: Box<(ActorInfo, Vec<NodeContactInfo>)> =
						Box::new((result.actor_info, peers));
					let value_ptr = AtomicPtr::new(Box::into_raw(value) as _);
					Some(value_ptr)
				}
			}
		}

		let fingers = self.base.find_nearest_fingers(id).await;
		let this = self.clone();
		let iter = self
			.base
			.find_value_from_fingers_iter(
				this,
				id,
				0,
				true,
				&fingers,
				hop_limit,
				narrow_down,
				false,
				verify_pubkey,
			)
			.await;
		FindActorIter(iter)
	}

	// Does a simple search on the overlay network to find a node that is connected
	// to the given node_id, and returns the connection to that node.
	pub async fn find_connection_for_node(&self, node_id: &IdType) -> Option<Box<Connection>> {
		let fingers = self.base.find_nearest_fingers(node_id).await;
		if fingers.len() == 0 {
			return None;
		}

		let mut fingers_iter = fingers.into_iter();
		let mut higest_bit_found = 0u8;
		loop {
			let new_fingers = loop {
				if let Some(finger) = fingers_iter.next() {
					match self.base.select_direct_connection(&finger).await {
						None => {}
						Some(mut connection) => {
							if let Some(response) = self
								.base
								.exchange_find_node_on_connection(&mut *connection, &node_id)
								.await
							{
								if let Some(node_info) = response.connection {
									if &node_info.node_id == node_id {
										return Some(connection);
									}
								}

								connection.close_async();
								let mut fingers = response.fingers;
								fingers.retain(|f| {
									if &f.node_id == self.node_id() {
										false
									} else if let Some(bit) = differs_at_bit(node_id, &f.node_id) {
										if bit > higest_bit_found {
											higest_bit_found = bit;
											true
										} else {
											false
										}
									} else {
										true
									}
								});
								if fingers.len() > 0 {
									break fingers;
								}
							} else {
								connection.close_async();
							}
						}
					}
				} else {
					return None;
				}
			};

			fingers_iter = new_fingers.into_iter();
		}
		//None
	}

	pub async fn get_actor_node(&self, actor_id: &IdType) -> Option<Arc<ActorNode>> {
		let nodes = self.base.interface.actor_nodes.lock().await;
		nodes.get(actor_id).map(|n| n.clone())
	}

	async fn connect_actor_iter<'a>(
		self: &'a Arc<Self>, actor_id: &IdType,
	) -> ConnectActorIter<'a> {
		ConnectActorIter {
			base: self.find_actor_iter(actor_id, 100, true).await,
			actor_info: None,
			state: 0,
			pi: 0,
			ri: 0,
			punchable_nodes: Vec::new(),
			relayable_nodes: Vec::new(),
		}
	}

	pub async fn join_actor_network(
		self: &Arc<Self>, actor_id: &IdType, actor_info: &ActorInfo,
	) -> Option<Arc<ActorNode>> {
		// Insert a new - or load the existing node
		let node = {
			let mut actor_nodes = self.base.interface.actor_nodes.lock().await;
			if let Some(node) = actor_nodes.get(&actor_id) {
				node.clone()
			} else {
				// Start up a new node for the actor network
				let node = Arc::new(ActorNode::new(
					self.base.stop_flag.clone(),
					self.clone(),
					self.node_id().clone(),
					self.base.socket.clone(),
					actor_id.clone(),
					actor_info.clone(),
					self.db().clone(),
					self.base.bucket_size,
					false,
				));
				actor_nodes.insert(actor_id.clone(), node.clone());
				node
			}
		};

		// Try to find a node on the actor network first
		let mut iter = self.connect_actor_iter(actor_id).await;
		loop {
			if let Some((connection, _)) = iter.next().await {
				if let Some(_open) = node.join_network_starting_with_connection(connection).await {
					break;
				}
			} else {
				break;
			}
		}
		iter.close();
		let last_two_visited: Vec<_> = iter
			.visited()
			.into_iter()
			.rev()
			.take(2)
			.map(|f| f.clone())
			.collect();
		let stored = self
			.store_actor_at_contacts(actor_id, 4, actor_info, &last_two_visited)
			.await;
		debug!("Stored actor {} at {} nodes.", actor_id, stored);

		Some(node)
	}

	async fn join_actor_networks(self: &Arc<Self>, actors: Vec<(IdType, ActorInfo)>) {
		// Join each network in parallel
		let futs = actors.into_iter().map(|(actor_id, actor_info)| async move {
			if !self
				.base
				.interface
				.actor_nodes
				.lock()
				.await
				.contains_key(&actor_id)
			{
				let actor_id_string = actor_id.to_string();
				if self
					.join_actor_network(&actor_id, &actor_info)
					.await
					.is_some()
				{
					info!("Joined actor network {}.", actor_id_string);
				} else {
					info!(
						"Only one in actor network {} at the moment.",
						actor_id_string
					);
				}
			}
		});
		join_all(futs).await;
	}

	/// Joins the network by trying to connect to old peers. If that doesn't
	/// work, try to connect to bootstrap nodes.
	pub async fn join_network(self: &Arc<Self>, stop_flag: Arc<AtomicBool>) -> bool {
		// TODO: Find remembered nodes from the database and try them out first. This is
		// currently not implemented yet.

		self.maintain_node_connections();

		let mut i = 0;
		// TODO: Contact all bootstrap nodes
		while i < self.bootstrap_nodes.len() && !stop_flag.load(Ordering::Relaxed) {
			let bootstrap_node = &self.bootstrap_nodes[i];
			match self
				.base
				.join_network_starting_at(&bootstrap_node.into())
				.await
			{
				false => warn!("Bootstrap node {} wasn't available", bootstrap_node),
				true => {
					match self.db().connect() {
						Err(e) => {
							panic!("Unable to connect to database to load actor nodes: {}", e);
						}
						Ok(c) => {
							// Load actor nodes for both your own actors and the
							// ones you are following.
							let actor_node_infos = tokio::task::block_in_place(|| {
								let mut list = self.load_following_actor_nodes(&c);
								list.extend(self.load_my_actor_nodes(&c).into_iter().map(
									|(id, first_object, actor_type, private_key)| {
										(
											id,
											ActorInfo {
												public_key: private_key.public(),
												first_object,
												actor_type,
											},
										)
									},
								));
								list
							});

							// Open and maintain a connection to a bidirectional node
							// TODO: Do the same thing for IPv6
							if let Some(ipv4_contact_info) =
								self.base.socket.our_contact_info().ipv4
							{
								if let Some(availability) = ipv4_contact_info.availability.udp {
									if availability.openness == Openness::Unidirectional {
										self.obtain_reverse_connection().await;
									}
								}
							} else {
								panic!("no contact info")
							}

							self.join_actor_networks(actor_node_infos).await;
							self.maintain_synchronization(stop_flag);

							return true;
						}
					}
				}
			}

			i += 1;
		}
		if i == self.bootstrap_nodes.len() {
			if self.bootstrap_nodes.len() > 0 {
				error!(
					"None of the {} bootstrap node(s) were available.",
					self.bootstrap_nodes.len()
				);
			} else {
				debug!("No bootstrap nodes configured. Not connecting to any nodes.");
				return true;
			}
		}

		false
	}

	/*async fn handle_connection_boxed(self: &Arc<Self>, connection: Box<Connection>) -> BoxFuture<'static, ()> {
		async move {
			self.handle_connection(connection).await;
		}.boxed()
	}*/

	async fn keep_hole_open(self: Arc<Self>, stop_flag: Arc<AtomicBool>) {
		while !stop_flag.load(Ordering::Relaxed) {
			sleep(Duration::from_secs(1)).await;

			let is_inactive = {
				let mut last_message_time = self.base.interface.last_message_time.lock().unwrap();
				let is_inactive =
					SystemTime::now()
						.duration_since(*last_message_time)
						.unwrap() > Duration::from_secs(self.base.interface.max_idle_time as _);
				if is_inactive {
					*last_message_time = SystemTime::now();
				}
				is_inactive
			};
			if is_inactive {
				// Ping a peer, one successful ping will be enough
				let mut peer_iter = self.base.iter_all_fingers().await;
				while !stop_flag.load(Ordering::Relaxed) {
					match peer_iter.next().await {
						Some(peer) =>
							if let Some(x) = self.base.ping(&peer).await {
								debug!("Pinged {} for {} ms.", &peer.contact_info, x);
								break;
							},
						// If not a single peer was available, reconnect to the
						// network again.
						None => {
							warn!("Lost connection to all nodes, rejoining the network...");
							if !self.join_network(stop_flag.clone()).await {
								error!("Attempt at rejoining the network failed.")
							} else {
								info!("Rejoined the network");
							}
							break;
						}
					}
				}
			}
		}
	}

	fn load_following_actor_nodes(&self, c: &db::Connection) -> Vec<(IdType, ActorInfo)> {
		match c.fetch_follow_list() {
			Ok(r) => r,
			Err(e) => {
				error!("Unable to fetch following identities: {}", e);
				Vec::new()
			}
		}
	}

	fn load_my_actor_nodes(&self, c: &db::Connection) -> Vec<(IdType, IdType, String, PrivateKey)> {
		let result = match c.fetch_my_identities() {
			Ok(r) => r,
			Err(e) => {
				error!("Unable to fetch my identities: {}", e);
				return Vec::new();
			}
		};

		result
			.into_iter()
			.map(|(_, actor_id, first_object, actor_type, private_key)| {
				(actor_id, first_object, actor_type, private_key)
			})
			.collect()
	}

	fn maintain_reverse_connection(self: &Arc<Self>, connection: Box<Connection>) {
		let this = self.clone();
		spawn(async move {
			node::keep_alive_connection(this.clone(), connection).await;

			// After the connection has closed, try to find a new one.
			if !this.base.stop_flag.load(Ordering::Relaxed) {
				this.start_reverse_connection();
			}
		});
	}

	/// Will send a ping request every minute or so to all connections that are
	/// maintained on the overlay network.
	fn maintain_node_connections(self: &Arc<Self>) {
		let this = self.clone();
		spawn(async move {
			let mut next_ping = SystemTime::now() + Duration::from_secs(60);
			while !this.base.stop_flag.load(Ordering::Relaxed) {
				sleep(
					next_ping
						.duration_since(SystemTime::now())
						.unwrap_or(Duration::default()),
				)
				.await;
				next_ping = SystemTime::now() + Duration::from_secs(60);

				for i in 0..256 {
					let bucket = this.base.buckets[i].lock().await;
					if let Some((_, connection_mutex)) = &bucket.connection {
						let connection_mutex2 = connection_mutex.clone();
						drop(bucket);
						let mut connection = connection_mutex2.lock().await;
						if this
							.base
							.exchange_ping_on_connection(&mut connection)
							.await
							.is_none()
						{
							warn!(
								"Unable to ping on keep alive node connection of node {}",
								connection.their_node_id()
							);
							if let Err(e) = connection.close().await {
								warn!("Unable to close connection that was being kept alive: {}", e);
							}
							let mut bucket = this.base.buckets[i].lock().await;
							bucket.connection = None;
						}
					}
				}
			}
		});
	}

	fn maintain_synchronization(self: &Arc<Self>, stop_flag: Arc<AtomicBool>) {
		let this = self.clone();
		spawn(async move {
			while stop_flag.load(Ordering::Relaxed) {
				let actor_nodes: Vec<Arc<ActorNode>> = this
					.base
					.actor_nodes
					.lock()
					.await
					.values()
					.map(|a| a.clone())
					.collect();
				for actor_node in actor_nodes {
					actor_node.start_synchronization();
				}

				sleep(Duration::from_secs(3600)).await;
			}
		});
	}

	async fn obtain_reverse_connection(self: &Arc<Self>) {
		// Try to find a bidirectional node to open a connection to it
		let mut iter = self.base.iter_all_fingers().await;
		while let Some(finger) = iter.next().await {
			if let Some(ipv4_contact_info) = finger.contact_info.ipv4 {
				if let Some(udpv4_availability) = ipv4_contact_info.availability.udp {
					if udpv4_availability.openness == Openness::Bidirectional {
						let contact_option = ContactOption::new(
							SocketAddr::V4(SocketAddrV4::new(
								ipv4_contact_info.addr,
								udpv4_availability.port,
							)),
							false,
						);

						if let Some(mut c) = self
							.base
							.connect(&contact_option, Some(&finger.node_id))
							.await
						{
							if let Some(success) =
								self.exchange_keep_alive_on_connection(&mut c).await
							{
								if success {
									self.maintain_reverse_connection(c);
									return;
								} else {
									debug!("Keep alive connection was denied.");
									c.close_async();
								}
							} else {
								c.close_async();
							}
						}
					}
				}
			}
		}
		warn!("Unable to obtain keep alive connection.");
	}

	pub async fn open_relay(&self, target: &NodeContactInfo) -> Option<Box<Connection>> {
		loop {
			let mut super_nodes = self.super_nodes.lock().await;
			if let Some((super_node_id, super_node_contact)) = super_nodes.pop_front() {
				drop(super_nodes);
				if let Some(mut connection) = self
					.base
					.connect(&super_node_contact, Some(&super_node_id))
					.await
				{
					connection
						.set_keep_alive_timeout(sstp::DEFAULT_TIMEOUT * 4)
						.await;
					if let Some(ok) = self
						.exchange_open_relay_on_connection(&mut connection, target.clone())
						.await
					{
						if ok {
							connection.update_their_node_info(target.clone());
							let mut super_nodes = self.super_nodes.lock().await;
							super_nodes.push_back((super_node_id, super_node_contact));
							return Some(connection);
						}
					}
					connection.close_async();
				}
			} else {
				return None;
			}
		}
	}

	async fn process_open_relay_request(
		self: &Arc<Self>, connection: &mut Connection, buffer: &[u8],
	) -> Option<Vec<u8>> {
		let request: OpenRelayRequest = match bincode::deserialize(buffer) {
			Ok(r) => r,
			Err(e) => {
				warn!("Malformed relay data request: {}", e);
				return None;
			}
		};
		let result = if self.is_super_node {
			connection
				.set_keep_alive_timeout(sstp::DEFAULT_TIMEOUT * 10)
				.await;
			self.base.select_connection(&request.target).await
		} else {
			None
		};

		if let Some(mut target_connection) = result {
			let opened = if let Some(ok) = self
				.exchange_start_relay_on_connection(
					&mut target_connection,
					connection.their_node_info().clone(),
				)
				.await
			{
				ok
			} else {
				false
			};

			let response = OpenRelayResponse { ok: opened };
			if let Err(e) = self
				.base
				.interface
				.respond(
					connection,
					OVERLAY_MESSAGE_TYPE_OPEN_RELAY_RESPONSE,
					&bincode::serialize(&response).unwrap(),
				)
				.await
			{
				warn!("Unable to respond to relay request: {}", e);
				self.base
					.handle_connection_issue::<()>(Err(e), connection.their_node_info())
					.await;
			}

			if let Err(e) = handle_relay_connection(connection, &mut target_connection).await {
				match e {
					sstp::Error::ConnectionClosed => {}
					other => {
						warn!("Connection issue during relaying: {}", other);
					}
				}
			}
			target_connection.close_async();
			// We've already responded at this point
			return None;
		}

		// If the connection wouldn't open, respond with a failure
		Some(bincode::serialize(&OpenRelayResponse { ok: false }).unwrap())
	}

	pub(super) async fn request_reversed_connection(
		&self, relay_connection: &mut Connection, target: &IdType, their_contact: &ContactOption,
		our_contact: &ContactOption,
	) -> Option<Box<Connection>> {
		// Generally not really needed, but might help in case the target node's
		// connection comes in sooner than the relay node's reply.
		if !self.punch_hole(their_contact).await {
			return None;
		}

		let (tx_in, rx_in) = oneshot::channel();
		{
			let mut expected_connections = self.expected_connections.lock().await;
			// If a connection from the same target is already expected, we can't touch it.
			// It would leave the other task that's still waiting on the previous connection
			// hanging.
			if expected_connections.contains_key(their_contact) {
				error!(
					"Attempted to request reversed connection from same node more than once: {} {}",
					target, their_contact
				);
				return None;
			}
			expected_connections.insert(their_contact.clone(), tx_in);
		}

		// Contact the relay node
		let knows_target = self
			.exchange_relay_punch_hole_request(
				relay_connection,
				target.clone(),
				our_contact.clone(),
			)
			.await?;
		if !knows_target {
			return None;
		}

		// TODO: Keep the connection with the relay node open until contact is made,
		// because the relay node may be able to send us a status message explaining
		// whether things went ok or not.

		// Spawn the connection attempt on another task, because we should only interupt
		// it with the stop flag.
		let stop_flag = Arc::new(AtomicBool::new(false));
		let stop_flag2 = stop_flag.clone();
		let their_contact2 = their_contact.clone();
		let target2 = target.clone();
		let base = self.base.clone();
		let (tx_out, rx_out) = oneshot::channel();
		spawn(async move {
			let result = base
				.connect_with_timeout(
					stop_flag2.clone(),
					&their_contact2,
					Some(&target2),
					sstp::DEFAULT_TIMEOUT * 3,
				)
				.await;
			// If an incomming connection was already received by this point, close the
			// outgoing connection if it was already established.
			if stop_flag2.load(Ordering::Relaxed) {
				if let Some(connection) = result {
					connection.close_async();
				}
			} else {
				if let Err(result2) = tx_out.send(result) {
					error!("Unable to send back incomming connection.");
					if let Some(connection) = result2 {
						connection.close_async();
					}
				}
			}
		});

		// Wait until a connection is received, and return that.
		let result = select! {
			result = rx_in => {
				stop_flag.store(true, Ordering::Relaxed);
				Some(result.expect("sender of expected connection has closed unexpectantly"))
			},
			result = rx_out => {
				result.expect("unable to retrieve result from oneshot")
			},
		};

		let mut expected_connections = self.expected_connections.lock().await;
		let removed = expected_connections.remove(their_contact).is_some();
		debug_assert!(!removed, "expected connection is gone");

		if result.is_none() {
			debug!("Unable to receive reversed connection: timeout elapsed");
		}
		result
	}

	fn start_reverse_connection(self: &Arc<Self>) {
		let this = self.clone();
		spawn(async move {
			this.obtain_reverse_connection().await;
		});
	}

	pub fn node_id(&self) -> &IdType { &self.base.node_id }

	//pub fn node_info(&self) -> &NodeContactInfo {
	// &self.base.interface.socket.our_contact_info }

	async fn process_find_actor_request(&self, buffer: &[u8]) -> Option<Vec<u8>> {
		let request: FindActorRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed find actor request: {}", e);
				return None;
			}
			Ok(r) => r,
		};

		let (connection, fingers) = self.base.find_nearest_contacts(&request.node_id).await;
		let mut response = FindActorResponse {
			contacts: FindNodeResponse {
				is_super_node: self.is_super_node,
				connection,
				fingers,
			},
			result: None,
		};

		// Load the public key and available nodes from our cache
		{
			let store = NODE_ACTOR_STORE.lock().await;
			match store.find(&request.node_id) {
				None => {}
				Some(entry) => {
					response.result = Some(FindActorResult {
						actor_info: entry.actor_info.clone(),
						i_am_available: false,
						peers: entry.available_nodes.clone().into(),
					});
				}
			}
		}

		// If we have the public key in our own database, show that as well.
		let actor_info_result = tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			c.fetch_identity(&request.node_id)
		});
		match actor_info_result {
			Err(e) => error!("Database error while looking for public key: {}", e),
			Ok(actor_info) =>
				if actor_info.is_some() {
					if response.result.is_none() {
						response.result = Some(FindActorResult {
							actor_info: actor_info.unwrap().clone(),
							i_am_available: true,
							peers: Vec::new(),
						});
					} else {
						response.result.as_mut().unwrap().i_am_available = true;
					}
				},
		}

		// Deserialize response
		Some(bincode::serialize(&response).unwrap())
	}

	async fn process_keep_alive_request(
		&self, connection_mutex: &Arc<Mutex<Box<Connection>>>, connection: &mut Connection,
		buffer: &[u8],
	) -> (Option<Vec<u8>>, bool) {
		// The keep alive request is empty
		if buffer.len() > 0 {
			return (None, false);
		}

		let ok = if let Some(bucket_index) = self.base.differs_at_bit(connection.their_node_id()) {
			let mut bucket = self.base.buckets[bucket_index as usize].lock().await;

			if bucket.connection.is_none() {
				connection
					.set_keep_alive_timeout(Duration::from_secs(120))
					.await;
				bucket.connection = Some((
					connection.their_node_info().clone(),
					connection_mutex.clone(),
				));
				debug!(
					"Keeping connection with {} alive.",
					connection.peer_address()
				);
				true
			} else {
				false
			}
		} else {
			false
		};

		(
			Some(bincode::serialize(&KeepAliveResponse { ok }).unwrap()),
			ok,
		)
	}

	async fn process_relay_punch_hole_request(
		self: &Arc<Self>, buffer: &[u8], node_id: &IdType,
	) -> Option<Vec<u8>> {
		let request: RelayInitiateConnectionRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				warn!("Malformed relay initiate connection request: {}", e);
				return None;
			}
			Ok(r) => r,
		};
		let mut response = RelayInitiateConnectionResponse { ok: true };
		if let Some(connection_mutex) = self.base.find_connection_in_buckets(&request.target).await
		{
			let this = self.clone();
			let node_id2 = node_id.clone();
			spawn(async move {
				let mut connection = connection_mutex.lock().await;
				this.exchange_punch_hole_on_connection(
					&mut connection,
					node_id2,
					request.contact_option,
				)
				.await
			});
		} else {
			response.ok = false;
		}

		Some(bincode::serialize(&response).unwrap())
	}

	pub(super) async fn process_request(
		self: &Arc<Self>, connection: &mut sstp::Connection,
		connection_mutex: Arc<Mutex<Box<Connection>>>, message_type: u8, buffer: &[u8],
	) -> (Option<Vec<u8>>, bool) {
		let response = match message_type {
			OVERLAY_MESSAGE_TYPE_FIND_ACTOR_REQUEST =>
				self.process_find_actor_request(buffer).await,
			OVERLAY_MESSAGE_TYPE_STORE_ACTOR_REQUEST =>
				self.process_store_actor_request(connection.their_node_info(), buffer)
					.await,
			OVERLAY_MESSAGE_TYPE_PUNCH_HOLE_REQUEST =>
				self.process_punch_hole_request(buffer).await,
			OVERLAY_MESSAGE_TYPE_RELAY_PUNCH_HOLE_REQUEST =>
				self.process_relay_punch_hole_request(buffer, connection.their_node_id())
					.await,
			OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_REQUEST =>
				return self
					.process_keep_alive_request(&connection_mutex, connection, buffer)
					.await,
			OVERLAY_MESSAGE_TYPE_OPEN_RELAY_REQUEST =>
				self.process_open_relay_request(connection, buffer).await,
			OVERLAY_MESSAGE_TYPE_START_RELAY_REQUEST =>
				self.process_start_relay_request(connection, buffer).await,
			other_id => {
				error!(
					"Unknown overlay message type ID received from {}: {}",
					connection.peer_address(),
					other_id
				);
				None
			}
		};
		(response, false)
	}

	pub(super) async fn process_actor_request(
		self: &Arc<Self>, connection: &mut Connection, mutex: &Arc<Mutex<Box<Connection>>>,
		actor_id: &IdType, message_type: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		let actor_node = {
			let actor_nodes = self.base.interface.actor_nodes.lock().await;
			match actor_nodes.get(actor_id) {
				None => return None,
				Some(n) => n.clone(),
			}
		};

		match actor_node
			.base
			.process_request(
				connection,
				self.clone(),
				message_type,
				&buffer,
				Some(&actor_id),
			)
			.await
		{
			None => {}
			Some(response) => return response,
		}

		actor_node
			.process_request(connection, mutex, message_type, buffer)
			.await
	}

	async fn process_start_relay_request(
		&self, connection: &mut Connection, buffer: &[u8],
	) -> Option<Vec<u8>> {
		let request: StartRelayRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed start relay request: {}", e);
				return None;
			}
			Ok(r) => r,
		};
		connection.update_their_node_info(request.origin);

		// Always accept
		Some(bincode::serialize(&StartRelayResponse { ok: true }).unwrap())
	}

	async fn process_store_actor_request(
		&self, sender_node_info: &NodeContactInfo, buffer: &[u8],
	) -> Option<Vec<u8>> {
		let request: StoreActorRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed store actor request: {}", e);
				return None;
			}
			Ok(r) => r,
		};

		// Check if actor_id is indeed the hash of the public key + first block hash.
		let actor_id_test = IdType::hash(&bincode::serialize(&request.actor_info).unwrap());
		if actor_id_test != request.actor_id {
			warn!("Actor store request invalid: public key doesn't match actor ID.");
			return None;
		}

		// Add actor to store
		let mut node_store = NODE_ACTOR_STORE.lock().await;
		match node_store.find_mut(&request.actor_id) {
			None => {
				node_store.add(
					request.actor_id.clone(),
					ActorStoreEntry::new_with_contact(request.actor_info, sender_node_info.clone()),
				);
			}
			Some(entry) => {
				entry.add_available_node(sender_node_info.clone());
			}
		}

		Some(Vec::new())
	}

	async fn process_punch_hole_request(self: &Arc<Self>, buffer: &[u8]) -> Option<Vec<u8>> {
		#[inline(always)]
		fn handle_connection_recursive(
			overlay_node: Arc<OverlayNode>, connection: Box<Connection>,
		) -> BoxFuture<'static, ()> {
			Box::pin(async move {
				handle_connection(overlay_node, connection).await;
			})
		}

		let request: InitiateConnectionRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				warn!("Malformed initiate connection request: {}", e);
				return None;
			}
			Ok(r) => r,
		};
		let response = InitiateConnectionResponse { ok: true };

		let this = self.clone();
		spawn(async move {
			if let Some(connection) = this
				.base
				.connect(
					&request.source_contact_option,
					Some(&request.source_node_id),
				)
				.await
			{
				handle_connection_recursive(this, connection).await;
			}
		});

		Some(bincode::serialize(&response).unwrap())
	}

	async fn punch_hole(&self, target: &ContactOption) -> bool {
		match self.base.socket.send_punch_hole_packet(target).await {
			Err(e) => {
				error!("Unable to send hole punching packet to {}: {}", &target, e);
				false
			}
			Ok(result) => result,
		}
	}

	pub(super) async fn remember_super_node(
		&self, node_id: &IdType, contact: &ContactOption,
	) -> bool {
		let mut super_nodes = self.super_nodes.lock().await;
		if super_nodes.iter().find(|(n, _)| n == node_id).is_none() {
			super_nodes.push_back((node_id.clone(), contact.clone()));
			true
		} else {
			false
		}
	}

	pub async fn store_actor(
		&self, actor_id: &IdType, duplicates: usize, actor_info: &ActorInfo,
	) -> usize {
		let contacts = self.base.find_node(&actor_id, duplicates * 2, 100).await;
		self.store_actor_at(actor_id, duplicates, actor_info, &contacts)
			.await
	}

	/// Just like `store_actor`, but starts searching from the given fingers.
	pub async fn store_actor_at(
		&self, actor_id: &IdType, duplicates: usize, actor_info: &ActorInfo,
		contacts: &[NodeContactInfo],
	) -> usize {
		let mut store_count = 0;
		for contact in contacts {
			if self
				.exchange_store_actor(&contact, actor_id.clone(), actor_info.clone())
				.await
				.is_some()
			{
				store_count += 1;
				if store_count == duplicates {
					return store_count;
				}
			}
		}
		store_count
	}

	/// Just like `store_actor`, but stores it at the given contacts, and then
	/// continues
	pub async fn store_actor_at_contacts(
		&self, actor_id: &IdType, duplicates: usize, actor_info: &ActorInfo,
		contacts: &[(IdType, ContactOption)],
	) -> usize {
		let mut store_count = 0;
		let mut fingers = Vec::with_capacity(contacts.len());
		for (node_id, contact_option) in contacts {
			if let Some(mut connection) = self.base.connect(contact_option, Some(node_id)).await {
				if self
					.exchange_store_actor_on_connection(
						&mut connection,
						actor_id.clone(),
						actor_info.clone(),
					)
					.await
					.is_some()
				{
					store_count += 1;
					if store_count == duplicates {
						return store_count;
					}
					fingers.push(connection.their_node_info().clone());
				}
				connection.close_async();
			}
		}

		let todo = duplicates - store_count;
		let contacts = self
			.base
			.find_node_from_fingers(&actor_id, &fingers, todo * 2, 1)
			.await;
		store_count += self
			.store_actor_at(actor_id, duplicates - store_count, actor_info, &contacts)
			.await;
		store_count
	}
}


async fn handle_relay_connection(
	client_connection: &mut Connection, server_connection: &mut Connection,
) -> sstp::Result<()> {
	fn verify_request(buffer: &[u8]) -> Option<u8> {
		const MESSAGE_TYPE_WHITELIST: &[u8] = &[
			NETWORK_MESSAGE_TYPE_FIND_NODE_REQUEST,
			NETWORK_MESSAGE_TYPE_FIND_VALUE_REQUEST,
			ACTOR_MESSAGE_TYPE_GET_PROFILE_REQUEST,
			ACTOR_MESSAGE_TYPE_HEAD_REQUEST,
			//ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_REQUEST <-- not supported yet because after
			// response, client may send an additional message, and then direction reverses.
		];

		// Only allow the whitelisted message types
		let message_type = buffer[0];
		if message_type < 0x80 {
			return None;
		}
		if MESSAGE_TYPE_WHITELIST.contains(&(buffer[0] & 0x7F)) {
			return Some(message_type);
		}
		None
	}

	// Keep relaying requests & responses until one connection closes or errors out
	loop {
		let mut message_type = 0u8;
		server_connection
			.pipe(client_connection, |buf| {
				if let Some(mt) = verify_request(buf) {
					message_type = mt;
					true
				} else {
					false
				}
			})
			.await?;
		client_connection
			.pipe(server_connection, |buf| {
				if buf.len() == 0 {
					return false;
				}
				buf[0] == (message_type + 1)
			})
			.await?;
	}
}

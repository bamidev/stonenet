#![allow(deprecated)]

use std::{
	result::Result as StdResult,
	sync::{atomic::*, Mutex as StdMutex, OnceLock},
};

use async_trait::async_trait;
use futures::{
	channel::oneshot,
	future::{join_all, BoxFuture},
};
use log::*;
use rand::{rngs::OsRng, Rng};
use sea_orm::prelude::*;
use tokio::{select, spawn, time::sleep};

use self::connection_manager::ConnectionManager;
use super::{
	actor::*,
	actor_store::*,
	message::*,
	node::*,
	sstp::{server::*, MessageWorkToDo, Result, DEFAULT_TIMEOUT},
};
use crate::{
	common::*,
	config::*,
	core::*,
	db::{self, Database, PersistenceHandle},
	identity::*,
	limited_store::LimitedVec,
	net::*,
	trace::Mutex,
};


const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(120);

const OVERLAY_ATTACHED_NODES_LIMIT_DEFAULT: usize = 1000;
const OVERLAY_ATTACHED_NODES_MINIMUM: usize = 100;

// Messages for the overlay network:
pub const OVERLAY_MESSAGE_TYPE_FIND_ACTOR_REQUEST: u8 = 64;
pub const OVERLAY_MESSAGE_TYPE_FIND_ACTOR_RESPONSE: u8 = 65;
pub const OVERLAY_MESSAGE_TYPE_STORE_ACTOR_REQUEST: u8 = 66;
pub const OVERLAY_MESSAGE_TYPE_STORE_ACTOR_RESPONSE: u8 = 67;
pub const OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_REQUEST: u8 = 68;
pub const OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_RESPONSE: u8 = 69;
pub const OVERLAY_MESSAGE_TYPE_PUNCH_HOLE_REQUEST: u8 = 70;
pub const OVERLAY_MESSAGE_TYPE_PUNCH_HOLE_RESPONSE: u8 = 71;
pub const OVERLAY_MESSAGE_TYPE_RELAY_PUNCH_HOLE_REQUEST: u8 = 72;
pub const OVERLAY_MESSAGE_TYPE_RELAY_PUNCH_HOLE_RESPONSE: u8 = 73;
pub const OVERLAY_MESSAGE_TYPE_REVERSE_CONNECTION_REQUEST: u8 = 74;
pub const OVERLAY_MESSAGE_TYPE_REVERSE_CONNECTION_RESPONSE: u8 = 75;
pub const OVERLAY_MESSAGE_TYPE_OPEN_RELAY_REQUEST: u8 = 76;
pub const OVERLAY_MESSAGE_TYPE_OPEN_RELAY_RESPONSE: u8 = 77;
pub const OVERLAY_MESSAGE_TYPE_PASS_RELAY_REQUEST_REQUEST: u8 = 78;
pub const OVERLAY_MESSAGE_TYPE_PASS_RELAY_REQUEST_RESPONSE: u8 = 79;
pub const OVERLAY_MESSAGE_TYPE_RELAY_REQUEST_REQUEST: u8 = 80;
pub const OVERLAY_MESSAGE_TYPE_RELAY_REQUEST_RESPONSE: u8 = 81;


pub struct ConnectActorIter<'a> {
	base: FindActorIter<'a>,
	actor_info: Option<ActorInfo>,
	has_contacts_to_process: bool,
	open_nodes_iter: <Vec<(NodeContactInfo, ContactOption)> as IntoIterator>::IntoIter,
	punchable_nodes_iter: <Vec<(NodeContactInfo, ContactOption, bool)> as IntoIterator>::IntoIter,
	relayable_nodes_iter: <Vec<NodeContactInfo> as IntoIterator>::IntoIter,
}
pub struct FindActorIter<'a>(FindValueIter<'a, OverlayInterface>);

struct KeepAliveToDo {
	node: Arc<OverlayNode>,
	node_id: IdType,
}

struct OpenRelayToDo {
	node: Arc<OverlayNode>,
	source_addr: SocketAddr,
	target_node_id: IdType,
	assistant_node_info: NodeContactInfo,
	hello_packet: RelayHelloPacket,
	timeout: Duration,
}

pub struct OverlayNode {
	pub(super) base: Arc<Node<OverlayInterface>>,
	bootstrap_nodes: Vec<SocketAddr>,
	pub(super) expected_connections:
		Arc<Mutex<HashMap<IdType, oneshot::Sender<Box<sstp::Connection>>>>>,
	pub(super) is_relay_node: bool,
	pub(crate) tracked_actors: Mutex<HashMap<ActorAddress, Option<ActorInfo>>>,
	relay_nodes: Mutex<LimitedVec<NodeContactInfo>>,
}

pub(super) struct OverlayInterface {
	node: OnceLock<Option<Arc<OverlayNode>>>,
	db: Database,
	pub(super) actor_nodes: Mutex<HashMap<IdType, Arc<ActorNode>>>,
	last_message_time: StdMutex<SystemTime>,
	connection_manager: Arc<ConnectionManager>,
}

struct ReverseConnectionToDo {
	sender: Option<oneshot::Sender<Box<Connection>>>,
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
				let db = self.db.connect_old()?;
				db.fetch_identity_by_id(id)
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

		Ok(Some(binserde::serialize(&value).unwrap()))
	}

	fn overlay_node(&self) -> Arc<OverlayNode> {
		self.node
			.get()
			.expect("missing node in overlay interface")
			.as_ref()
			.expect("overlay interface already closed")
			.clone()
	}

	fn prepare(&self, message_type: u8, buffer: &[u8]) -> Vec<u8> {
		let mut new_buffer = Vec::with_capacity(1 + buffer.len());
		new_buffer.push(message_type);
		new_buffer.extend(buffer);
		new_buffer
	}

	async fn send(
		&self, connection: &mut Connection, message_type: u8, buffer: &[u8],
	) -> sstp::Result<()> {
		*self.last_message_time.lock().unwrap() = SystemTime::now();

		// Send request
		let real_buffer = self.prepare(message_type, buffer);
		connection.send(real_buffer).await
	}
}

impl<'a> FindActorIter<'a> {
	pub fn visited(&self) -> &[(IdType, ContactOption)] { self.0.visited() }
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

	/// Gathers new contacts
	async fn gather_new_contacts(&mut self) -> bool {
		while let Some(result) = self.base.next().await {
			let (ai, actor_nodes) = *result;
			if self.actor_info.is_none() {
				self.actor_info = Some(ai);
			}
			if actor_nodes.len() == 0 {
				continue;
			}

			// Sort all nodes into 3 different collections, to try one collection at the
			// time
			let mut open_nodes: Vec<(NodeContactInfo, ContactOption)> =
				Vec::with_capacity(actor_nodes.len());
			let mut punchable_nodes: Vec<(NodeContactInfo, ContactOption, bool)> =
				Vec::with_capacity(actor_nodes.len());
			let mut relayable_nodes: Vec<NodeContactInfo> = Vec::with_capacity(actor_nodes.len());
			for node in actor_nodes {
				if &node.node_id == self.base.0.node.node_id() {
					continue;
				}

				if let Some(strategy) = self.base.0.node.pick_contact_strategy(&node.contact_info) {
					match strategy.method {
						ContactStrategyMethod::Relay =>
							if relayable_nodes
								.iter()
								.position(|n| &n.node_id == &node.node_id)
								.is_none()
							{
								relayable_nodes.push(node);
							},
						ContactStrategyMethod::PunchHole =>
							if punchable_nodes
								.iter()
								.position(|(n, ..)| &n.node_id == &node.node_id)
								.is_none()
							{
								punchable_nodes.push((node.clone(), strategy.contact, false));
							},
						ContactStrategyMethod::Reversed =>
							if punchable_nodes
								.iter()
								.position(|(n, ..)| &n.node_id == &node.node_id)
								.is_none()
							{
								punchable_nodes.push((node.clone(), strategy.contact, true));
							},
						ContactStrategyMethod::Direct =>
							if open_nodes
								.iter()
								.position(|(n, _)| &n.node_id == &node.node_id)
								.is_none()
							{
								open_nodes.push((node.clone(), strategy.contact));
							},
					}
				}
			}

			self.open_nodes_iter = open_nodes.into_iter();
			self.punchable_nodes_iter = punchable_nodes.into_iter();
			self.relayable_nodes_iter = relayable_nodes.into_iter();
			return true;
		}
		false
	}

	async fn try_contacts(&mut self) -> Option<(Box<Connection>, ActorInfo)> {
		// First try all the open nodes
		while let Some((node_info, contact_option)) = self.open_nodes_iter.next() {
			if let Some((connection, _)) = self
				.base
				.0
				.node
				.connect(&contact_option, Some(&node_info.node_id), None)
				.await
			{
				return Some((connection, self.actor_info.clone().unwrap()));
			}
		}

		// Then try the punchable nodes
		while let Some((node_info, contact_option, reversed)) = self.punchable_nodes_iter.next() {
			let strategy = ContactStrategy {
				method: if reversed {
					ContactStrategyMethod::Reversed
				} else {
					ContactStrategyMethod::PunchHole
				},
				contact: contact_option.clone(),
			};
			// TODO: There needs to be a "self.base.connect_through_hole_punching"
			// function or something like that...
			if let Some((connection, _)) = self
				.base
				.0
				.node
				.connect_by_strategy(&node_info, &strategy, None, None)
				.await
			{
				return Some((connection, self.actor_info.as_ref().unwrap().clone()));
			}
		}

		// Then, try all relayable nodes as a last resort
		while let Some(node_info) = self.relayable_nodes_iter.next() {
			if let Some(connection) = self.base.0.overlay_node.open_relay(&node_info).await {
				return Some((connection, self.actor_info.as_ref().unwrap().clone()));
			}
		}
		None
	}
}

#[async_trait]
impl<'a> AsyncIterator for ConnectActorIter<'a> {
	type Item = (Box<Connection>, ActorInfo);

	async fn next(&mut self) -> Option<Self::Item> {
		// Try new contacts as long as we can gather new ones
		loop {
			// At first, just try bidirectional nodes only
			if !self.has_contacts_to_process {
				if !self.gather_new_contacts().await {
					return None;
				}
				self.has_contacts_to_process = true;
			}

			// Then, consume & try all the nodes we've just received
			if let Some(result) = self.try_contacts().await {
				return Some(result);
			}
			self.has_contacts_to_process = false;
		}
	}
}

#[async_trait]
impl MessageWorkToDo for KeepAliveToDo {
	async fn run(&mut self, mut connection: Box<Connection>) -> Result<Option<Box<Connection>>> {
		let mut response = KeepAliveResponse { ok: false };

		// If the node's ID is not our own, and if there is space for it in the
		// connection manager, keep it alive.
		let node_info = connection.their_node_info().clone();
		if let Some(bucket_index) = self.node.base.differs_at_bit(&self.node_id) {
			let mut bucket = self.node.base.buckets[bucket_index as usize].lock().await;

			if let Some(space) = self
				.node
				.base
				.interface
				.connection_manager
				.find_space(&node_info)
				.await
			{
				connection.set_keep_alive_timeout(KEEP_ALIVE_TIMEOUT).await;

				response.ok = true;
				let raw_response = self
					.node
					.base
					.simple_response(OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_RESPONSE, &response);
				connection.send_async(raw_response)?;

				if let Some(removed_id) = space.put(Arc::new(Mutex::new(connection))) {
					bucket.remove_connection(&removed_id);
				}
				bucket.add_connection(&node_info, &self.node_id);
				info!(
					"[{}] Keeping connection with {} alive.",
					self.node.node_id(),
					node_info
				);
				return Ok(None);
			}
		}

		info!("Rejected keep-alive connection with {}.", node_info);
		let raw_response = self
			.node
			.base
			.simple_response(OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_RESPONSE, &response);
		connection.send(raw_response).await?;
		Ok(Some(connection))
	}
}

impl OverlayNode {
	pub async fn close(self: Arc<Self>) { self.base.close().await; }

	pub fn connection_manager(&self) -> &ConnectionManager {
		&self.base.interface.connection_manager
	}

	pub async fn start(
		stop_flag: Arc<AtomicBool>, config: &Config, node_id: IdType, private_key: NodePrivateKey,
		db: Database,
	) -> StdResult<Arc<Self>, SocketBindError> {
		let attached_node_limit = if let Some(limit) = config.attached_nodes_limit {
			if limit >= OVERLAY_ATTACHED_NODES_MINIMUM {
				limit
			} else {
				OVERLAY_ATTACHED_NODES_MINIMUM
			}
		} else {
			OVERLAY_ATTACHED_NODES_LIMIT_DEFAULT
		};

		let bootstrap_nodes = resolve_bootstrap_addresses(&config.bootstrap_nodes, true, true);

		let socket = sstp::Server::bind(
			stop_flag.clone(),
			config,
			node_id.clone(),
			private_key,
			sstp::DEFAULT_TIMEOUT,
		)
		.await?;
		let mut rng = OsRng {};
		socket.set_next_session_id(rng.gen()).await;

		let node_id2 = node_id.clone();
		let this = Arc::new(Self {
			base: Arc::new(Node::new(
				stop_flag.clone(),
				node_id,
				socket.clone(),
				OverlayInterface {
					node: OnceLock::new(),
					db,
					last_message_time: StdMutex::new(SystemTime::now()),
					actor_nodes: Mutex::new(HashMap::new()),
					connection_manager: Arc::new(ConnectionManager::new(
						node_id2,
						attached_node_limit,
					)),
				},
				config.bucket_size.unwrap_or(4),
				config.leak_first_request.unwrap_or(false),
			)),
			bootstrap_nodes,
			expected_connections: Arc::new(Mutex::new(HashMap::new())),
			is_relay_node: config.relay_node.unwrap_or(false),
			relay_nodes: Mutex::new(LimitedVec::new(100)),
			tracked_actors: Mutex::new(HashMap::from_iter(
				config
					.parse_tracked_actors()
					.into_iter()
					.map(|aa| (aa, None)),
			)),
		});
		let _is_set = this.base.interface.node.set(Some(this.clone())).is_ok();
		debug_assert!(_is_set);

		let this2 = this.clone();
		let this3 = this.clone();
		socket.listen(
			move |message, addr, node_info| {
				let this4 = this2.clone();
				Box::pin(
					async move { process_request_message(this4, message, addr, node_info).await },
				)
			},
			move |result, node_info| {
				let this4 = this3.clone();
				Box::pin(async move {
					this4.base.handle_connection_issue(result, &node_info).await;
				})
			},
		);
		socket.spawn();

		// Keep pinging other nodes
		// TODO: Make sure to send a ping on each available link protocol, because a
		// port needs to remain the same on each on of them.
		let idle_time = config.node_ping_interval.unwrap_or(60);
		let this4 = this.clone();
		let stop_flag2 = stop_flag.clone();
		spawn(async move {
			this4
				.keep_hole_open(stop_flag2, Duration::from_secs(idle_time))
				.await;
		});

		// When nodes attach to us, make sure to ping on those connections to keep them
		// alive.
		this.maintain_node_connections();
		// Synchronize data on each actor network every hour
		this.maintain_synchronization();

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

	pub fn contact_info(&self) -> ContactInfo { self.base.contact_info() }

	/// Pings a peer and returns whether it succeeded or not. A.k.a. the 'PING'
	/// RPC.
	pub async fn exchange_keep_alive_on_connection(
		&self, connection: &mut Connection,
	) -> Option<bool> {
		let raw_response = self
			.base
			.exchange_on_connection(connection, OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_REQUEST, &[])
			.await?;
		let result: sstp::Result<_> = binserde::deserialize_sstp(&raw_response);
		let response: KeepAliveResponse = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		Some(response.ok)
	}

	async fn exchange_pass_relayed_hello_packet(
		&self, target: &NodeContactInfo, request: &PassRelayRequestRequest,
	) -> Option<PassRelayRequestResponse> {
		let raw_request = binserde::serialize(&request).unwrap();
		let (raw_response, _) = self
			.base
			.exchange(
				target,
				OVERLAY_MESSAGE_TYPE_PASS_RELAY_REQUEST_REQUEST,
				&raw_request,
			)
			.await?;
		let result: Result<PassRelayRequestResponse> = binserde::deserialize_sstp(&raw_response);
		self.base.handle_connection_issue(result, target).await
	}

	pub(super) async fn exchange_punch_hole_on_connection(
		&self, connection: &mut Connection, source_node_id: IdType,
		source_contact_option: ContactOption, request_connection: bool,
	) -> Option<bool> {
		let request = PunchHoleRequest {
			source_node_id,
			source_contact_option,
			request_connection,
		};
		let raw_response = self
			.base
			.exchange_on_connection(
				connection,
				OVERLAY_MESSAGE_TYPE_PUNCH_HOLE_REQUEST,
				&binserde::serialize(&request).unwrap(),
			)
			.await?;
		let result: sstp::Result<_> = binserde::deserialize_sstp(&raw_response);
		let response: PunchHoleResponse = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		Some(response.ok)
	}

	/// Asks a peer to relay an initiate connection request to the destination
	/// target for you.
	async fn exchange_relay_punch_hole_request(
		&self, relay_connection: &mut Connection, target: IdType, contact_option: ContactOption,
		request_connection: bool,
	) -> Option<bool> {
		let message = PassPunchHoleRequest {
			target,
			contact_option,
			request_connection,
		};
		let raw_response = self
			.base
			.exchange_on_connection(
				relay_connection,
				OVERLAY_MESSAGE_TYPE_RELAY_PUNCH_HOLE_REQUEST,
				&binserde::serialize(&message).unwrap(),
			)
			.await;
		let result: sstp::Result<_> = binserde::deserialize_sstp(&raw_response?);
		let response: PassPunchHoleResponse = self
			.base
			.handle_connection_issue(result, &relay_connection.their_node_info())
			.await?;
		Some(response.ok)
	}

	async fn exchange_relay_request_on_connection(
		&self, connection: &mut Connection, request: &RelayRequestRequest,
	) -> Option<()> {
		let raw_request = binserde::serialize(request).unwrap();
		let raw_response = self
			.base
			.exchange_on_connection(
				connection,
				OVERLAY_MESSAGE_TYPE_RELAY_REQUEST_REQUEST,
				&raw_request,
			)
			.await?;
		self.base
			.handle_connection_issue(
				binserde::deserialize_sstp(&raw_response),
				connection.their_node_info(),
			)
			.await
	}

	async fn exchange_reverse_connection_on_connection(
		&self, connection: &mut Connection,
	) -> Option<bool> {
		let request = ReverseConnectionRequest {};
		let raw_response = self
			.base
			.exchange_on_connection(
				connection,
				OVERLAY_MESSAGE_TYPE_REVERSE_CONNECTION_REQUEST,
				&binserde::serialize(&request).unwrap(),
			)
			.await;
		let result: sstp::Result<_> = binserde::deserialize_sstp(&raw_response?);
		let response: ReverseConnectionResponse = self
			.base
			.handle_connection_issue(result, &connection.their_node_info())
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
				&binserde::serialize(&request).unwrap(),
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
		let raw_request = binserde::serialize(&request).unwrap();
		self.base
			.exchange_on_connection(
				connection,
				OVERLAY_MESSAGE_TYPE_STORE_ACTOR_REQUEST,
				&raw_request,
			)
			.await?;
		Some(())
	}

	/// Tries to connect to the actor network of the given actor ID, but in
	/// 'lurking' mode. Meaning, the nodes of the network won't consider you as
	/// a part of it.
	pub async fn find_actor_profile_info(
		self: &Arc<Self>, actor_address: &ActorAddress,
	) -> Option<Object> {
		let mut iter = self.connect_actor_iter(actor_address).await;
		let (node, object) = loop {
			if let Some((mut connection, actor_info)) = iter.next().await {
				let actor_id = match self.db().ensure_actor_id(actor_address, &actor_info).await {
					Ok(id) => id,
					Err(e) => {
						error!(
							"Database error while trying to find actor profile info for {}: {:?}",
							actor_address, e
						);
						return None;
					}
				};

				let node = Arc::new(ActorNode::new(
					self.base.stop_flag.clone(),
					self.clone(),
					self.node_id().clone(),
					self.base.packet_server.clone(),
					actor_address.clone(),
					actor_id,
					actor_info.clone(),
					self.db().clone(),
					self.base.bucket_size,
					self.base.leak_first_request,
					true,
				));

				let (object_id, object) =
					if let Some(r) = node.exchange_profile_on_connection(&mut connection).await {
						r
					} else {
						continue;
					};

				// We need to store the identity in order for the object to be able to be stored
				let _actor_id = match self.db().ensure_actor_id(actor_address, &actor_info).await {
					Ok(id) => id,
					Err(e) => {
						error!("Unable to store identity: {:?}", e);
						return Some(object);
					}
				};
				if let Err(e) = self
					.db()
					.perform(|mut c| c.store_object(actor_address, &object_id, &object, false))
				{
					error!(
						"Unable to store profile object for {}: {:?}",
						actor_address, e
					);
				}

				// Then we can collect all the values related to this identity
				match node.complete_object(&mut connection, object.clone()).await {
					Ok(done) =>
						if done {
							return Some(object);
						},
					Err(e) => {
						error!("Unable collect object on first connection: {}", e);
						return Some(object);
					}
				}
				// If we don't have all the files and blocks yet, attempt to synchronize
				// (outside of the loop)
				break (node, object);
			} else {
				return None;
			}
		};

		// Try to synchronize the missing files and blocks. Only works if there are some
		// bidirectional nodes available.
		if let Err(e) = node
			.synchronize_files_and_blocks_of_object(&object.payload)
			.await
		{
			error!(
				"Database error while synchronizing files & blocks for profile info: {:?}",
				e
			);
		}

		Some(object)
	}

	pub async fn find_actor(
		self: &Arc<Self>, id: &ActorAddress, hop_limit: usize, narrow_down: bool,
	) -> Option<Box<(ActorInfo, Vec<NodeContactInfo>)>> {
		let mut iter = self.find_actor_iter(id, hop_limit, narrow_down).await;
		let result = iter.next().await;
		result
	}

	/// Tries to find the
	pub async fn find_actor_iter<'a>(
		self: &'a Arc<Self>, address: &ActorAddress, hop_limit: usize, narrow_down: bool,
	) -> FindActorIter<'a> {
		fn verify_pubkey(
			id: &IdType, peer: &NodeContactInfo, data: &[u8],
		) -> Option<AtomicPtr<()>> {
			match binserde::deserialize::<FindActorResult>(&data) {
				Err(e) => {
					warn!("Received invalid actor info from node: {}", e);
					None
				}
				Ok(result) => {
					match result.actor_info.generate_address() {
						ActorAddress::V1(actor_address) =>
							if &actor_address != id {
								warn!("Received invalid actor info from node: invalid hash");
								return None;
							},
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

		let id = address.as_id();
		let fingers = self.base.find_nearest_private_fingers(&id).await;
		let this = self.clone();
		let iter = self
			.base
			.find_value_from_fingers_iter(
				this,
				&id,
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

	/// Does a simple search on the overlay network to find a node that is
	/// connected to the given node_id, and returns the connection to that node.
	pub async fn find_assistant_connection_for_node(
		&self, node_id: &IdType,
	) -> Option<(Box<Connection>, bool)> {
		// TODO: If the node itself has actually been found, and it has a bidirectional
		// contact option all of the sudden, let the caller know.
		let mut fingers = self.base.find_nearest_private_fingers(node_id).await;
		fingers.retain(|f| &f.node_id != node_id);
		if fingers.len() == 0 {
			return None;
		}

		let mut fingers_iter = fingers.into_iter();
		let mut higest_bit_found = 0u8;
		loop {
			let new_fingers = loop {
				if let Some(finger) = fingers_iter.next() {
					if let Some((response, connection)) =
						self.base.exchange_find_node(&finger, node_id.clone()).await
					{
						for node_info in response.connected {
							if &node_info.node_id == node_id {
								return Some((connection, response.is_relay_node));
							}
						}

						drop(connection);
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
							// If finger's ID is the same as `node_id`, we've
							// found our target but we were looking for the
							// assitant. Don't contact the target node though...
							} else {
								false
							}
						});
						if fingers.len() > 0 {
							break fingers;
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

	#[allow(dead_code)]
	pub async fn find_node(&self, node_id: &IdType) -> Option<NodeContactInfo> {
		let result = self.base.find_node(node_id, 1, 100).await;
		for node_info in result {
			if &node_info.node_id == node_id {
				return Some(node_info);
			}
		}
		None
	}

	pub async fn get_actor_node(&self, actor_id: &IdType) -> Option<Arc<ActorNode>> {
		let nodes = self.base.interface.actor_nodes.lock().await;
		nodes.get(actor_id).map(|n| n.clone())
	}

	pub async fn get_actor_node_or_lurker(
		self: &Arc<Self>, address: &ActorAddress,
	) -> Option<Arc<ActorNode>> {
		if let Some(n) = self.get_actor_node(&address.as_id()).await {
			Some(n)
		} else {
			self.lurk_actor_network(address).await
		}
	}

	async fn connect_actor_iter<'a>(
		self: &'a Arc<Self>, actor_id: &ActorAddress,
	) -> ConnectActorIter<'a> {
		ConnectActorIter {
			base: self.find_actor_iter(actor_id, 100, true).await,
			actor_info: None,
			has_contacts_to_process: false,
			open_nodes_iter: Vec::new().into_iter(),
			punchable_nodes_iter: Vec::new().into_iter(),
			relayable_nodes_iter: Vec::new().into_iter(),
		}
	}

	pub async fn join_actor_network(
		self: &Arc<Self>, actor_address: &ActorAddress, actor_info: &ActorInfo,
	) -> Option<Arc<ActorNode>> {
		debug_assert!(
			&actor_info.generate_address() == actor_address,
			"actor info and actor address don't match ({:?})",
			actor_address
		);

		// Insert a new - or load the existing node
		let node = {
			let mut actor_nodes = self.base.interface.actor_nodes.lock().await;
			if let Some(node) = actor_nodes.get(&actor_address.as_id()) {
				node.clone()
			} else {
				let actor_id = match self.db().ensure_actor_id(actor_address, actor_info).await {
					Ok(id) => id,
					Err(e) => {
						error!(
							"Database error while joining actor network {}: {:?}",
							&actor_address, e
						);
						return None;
					}
				};

				// Start up a new node for the actor network
				let node = Arc::new(ActorNode::new(
					self.base.stop_flag.clone(),
					self.clone(),
					self.node_id().clone(),
					self.base.packet_server.clone(),
					actor_address.clone(),
					actor_id,
					actor_info.clone(),
					self.db().clone(),
					self.base.bucket_size,
					self.base.leak_first_request,
					false,
				));
				actor_nodes.insert(actor_address.as_id().into_owned(), node.clone());
				node
			}
		};

		// Try to find a node on the overlay network first
		let mut iter = self.connect_actor_iter(actor_address).await;
		loop {
			if let Some((connection, _)) = iter.next().await {
				if let Some(_open) = node.join_network_starting_with_connection(connection).await {
					break;
				}
			} else {
				break;
			}
		}

		let last_two_visited: Vec<_> = iter
			.visited()
			.into_iter()
			.rev()
			.take(2)
			.map(|f| f.clone())
			.collect();
		let stored = self
			.store_actor_at_contacts(&actor_address.as_id(), 4, actor_info, &last_two_visited)
			.await;
		debug!("Stored actor {:?} at {} nodes.", actor_address, stored);

		Some(node)
	}

	async fn join_actor_networks(self: &Arc<Self>, actors: Vec<(ActorAddress, ActorInfo)>) {
		// Join each network in parallel
		let futs = actors.into_iter().map(|(actor_id, actor_info)| async move {
			if !self
				.base
				.interface
				.actor_nodes
				.lock()
				.await
				.contains_key(&actor_id.as_id())
			{
				if self
					.join_actor_network(&actor_id, &actor_info)
					.await
					.is_some()
				{
					info!("Joined actor network {:?}.", actor_id);
				} else {
					info!("Only one in actor network {:?} at the moment.", actor_id);
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
					match self.db().connect_old() {
						Err(e) => {
							panic!("Unable to connect to database to load actor nodes: {}", e);
						}
						Ok(c) => {
							// Load actor nodes for both your own actors and the
							// ones you are following.
							self.maintain_tracked_actors().await;
							let actor_node_infos = tokio::task::block_in_place(|| {
								let mut list = self.load_following_actor_nodes(&c);
								list.extend(self.load_my_actor_nodes(&c).into_iter().map(
									|(id, first_object, actor_type, private_key)| {
										(
											id,
											ActorInfo::V1(ActorInfoV1 {
												flags: 0,
												public_key: private_key.public(),
												first_object,
												actor_type,
											}),
										)
									},
								));
								list
							});

							// Open and maintain a connection to a bidirectional node
							// TODO: Do the same thing for IPv6
							if let Some(ipv4_contact_info) =
								self.base.packet_server.our_contact_info().ipv4
							{
								if let Some(availability) = ipv4_contact_info.availability.udp {
									if availability.openness != Openness::Bidirectional {
										self.obtain_keep_alive_connection().await;
									}
								}
							} else {
								panic!("no contact info")
							}

							self.join_actor_networks(actor_node_infos).await;

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
					"None of the {} bootstrap node(s) were available. {:?}",
					self.bootstrap_nodes.len(),
					self.bootstrap_nodes
				);
			} else {
				debug!("No bootstrap nodes configured. Not connecting to any nodes.");
				return true;
			}
		}

		false
	}

	/// Runs a loop that pings one finger every so often.
	async fn keep_hole_open(self: Arc<Self>, stop_flag: Arc<AtomicBool>, sleep_duration: Duration) {
		// FIXME: Wait until the network is actually joined.
		sleep(Duration::from_secs(120)).await;

		while !stop_flag.load(Ordering::Relaxed) {
			let mut iter = self.base.iter_all_fingers_local_first().await;

			let mut tried = 0usize;
			while let Some(peer) = iter.next().await {
				if let Some(p) = self.base.ping(&peer).await {
					debug!("Pinged {}, took {} ms.", &peer.contact_info, p);
				}
				tried += 1;
				sleep(sleep_duration).await;
			}

			if tried == 0 {
				warn!(
					"Lost connection to all nodes, rejoining the network in {:?}...",
					sleep_duration
				);
				sleep(sleep_duration).await;

				if !self.join_network(stop_flag.clone()).await {
					error!("Attempt at rejoining the network failed.")
				} else {
					info!("Rejoined the network");
				}
			}
		}
	}

	fn load_following_actor_nodes(&self, c: &db::Connection) -> Vec<(ActorAddress, ActorInfo)> {
		match c.fetch_follow_list() {
			Ok(r) => r,
			Err(e) => {
				error!("Unable to fetch following identities: {:?}", e);
				Vec::new()
			}
		}
	}

	fn load_my_actor_nodes(
		&self, c: &db::Connection,
	) -> Vec<(ActorAddress, IdType, String, ActorPrivateKeyV1)> {
		let result = match c.fetch_my_identities() {
			Ok(r) => r,
			Err(e) => {
				error!("Unable to fetch my identities: {:?}", e);
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

	pub async fn lurk_actor_network(
		self: &Arc<Self>, address: &ActorAddress,
	) -> Option<Arc<ActorNode>> {
		let mut iter = self.connect_actor_iter(address).await;
		while let Some((connection, actor_info)) = iter.next().await {
			let actor_id = match self.db().ensure_actor_id(address, &actor_info).await {
				Ok(id) => id,
				Err(e) => {
					error!(
						"Database error while going to lurk actor network {}: {:?}",
						address, e
					);
					return None;
				}
			};

			let node = Arc::new(ActorNode::new(
				self.base.stop_flag.clone(),
				self.clone(),
				self.base.node_id.clone(),
				self.base.packet_server.clone(),
				address.clone(),
				actor_id,
				actor_info,
				self.base.interface.db.clone(),
				1, // A lurker node doesn't need to keep fingers in the first place
				self.base.leak_first_request,
				true,
			));
			node.base
				.mark_node_helpful(connection.their_node_info())
				.await;
			return Some(node);
		}
		None
	}

	/// Will send a ping request every minute or so to all connections that are
	/// maintained on the overlay network.
	fn maintain_node_connections(self: &Arc<Self>) {
		let this = self.clone();
		spawn(async move {
			let mut next_ping = SystemTime::now() + Duration::from_secs(60);
			let stop_flag = this.base.stop_flag.clone();
			while !stop_flag.load(Ordering::Relaxed) {
				sleep(
					next_ping
						.duration_since(SystemTime::now())
						.unwrap_or(Duration::default()),
				)
				.await;
				next_ping = SystemTime::now() + Duration::from_secs(60);

				// Sent a ping request to all connections at once
				let connections = this.base.interface.connection_manager.connections().await;
				for connection_mutex in connections {
					let this2 = this.clone();
					spawn(async move {
						let mut connection = connection_mutex.lock().await;
						if this2
							.base
							.exchange_ping_on_connection(&mut connection)
							.await
							.is_none()
						{
							warn!(
								"Unable to ping on keep alive node connection of node {}, \
								 rejecting it...",
								connection.their_node_id()
							);
							if let Some(bucket) =
								this2.base.bucket_for(connection.their_node_id()).await
							{
								bucket.lock().await.reject(connection.their_node_id());
							}
							this2
								.base
								.interface
								.connection_manager
								.remove(connection.their_node_id())
								.await;
						}
					});
				}
			}
		});
	}

	fn maintain_synchronization(self: &Arc<Self>) {
		let this = self.clone();
		spawn(async move {
			while this.base.is_running() {
				let actor_nodes: Vec<Arc<ActorNode>> = this
					.base
					.interface
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

	pub async fn obtain_id(&self, target: &SocketAddr) -> Option<IdType> {
		let contact_info: ContactInfo = target.into();
		self.base.obtain_id(&contact_info).await
	}

	/// Tries to obtain a keep-alive connection from one of the available
	/// fingers.
	async fn obtain_keep_alive_connection(self: &Arc<Self>) {
		async fn use_connection(this: &Arc<OverlayNode>, mut connection: Box<Connection>) -> bool {
			if let Some(success) = this
				.exchange_keep_alive_on_connection(&mut connection)
				.await
			{
				if success {
					connection.set_keep_alive_timeout(KEEP_ALIVE_TIMEOUT).await;
					this.base
						.packet_server
						.spawn_connection(connection, Some(KEEP_ALIVE_TIMEOUT));
					return true;
				} else {
					debug!("Keep alive connection was denied.");
				}
			}
			false
		}

		// Try to find a bidirectional node to keep a connection with
		let mut punchable_nodes = Vec::new();
		let mut iter = self.base.iter_all_fingers_local_first().await;
		while let Some(finger) = iter.next().await {
			if let Some(ipv4_contact_info) = finger.contact_info.ipv4.clone() {
				if let Some(udpv4_availability) = ipv4_contact_info.availability.udp {
					if udpv4_availability.openness == Openness::Punchable {
						punchable_nodes.push(finger);
					} else if udpv4_availability.openness == Openness::Bidirectional {
						let contact_option = ContactOption::new(
							SocketAddr::V4(SocketAddrV4::new(
								ipv4_contact_info.addr,
								udpv4_availability.port,
							)),
							false,
						);

						if let Some((c, _)) = self
							.base
							.connect(&contact_option, Some(&finger.node_id), None)
							.await
						{
							if use_connection(self, c).await {
								return;
							}
						}
					}
				}
			}
		}

		// If not bidirectional nodes were available, try the punchable ones next
		for finger in &punchable_nodes {
			if let Some((c, _)) = self.base.select_connection(finger, None).await {
				if use_connection(self, c).await {
					return;
				}
			}
		}

		warn!(
			"Unable to obtain keep alive connection, will try again in 5 minutes {}",
			self.node_id()
		);
		let this = self.clone();
		spawn(async move {
			sleep(Duration::from_secs(300)).await;
			this.start_obtaining_keep_alive_connection();
		});
	}

	pub async fn open_relay(&self, target: &NodeContactInfo) -> Option<Box<Connection>> {
		debug_assert!(
			&target.node_id != self.node_id(),
			"can't open a relay to yourself"
		);
		// We need to know what assistant node we are going to use
		let (assitant_connection, is_relay) = self
			.find_assistant_connection_for_node(&target.node_id)
			.await?;
		let assistant_node_info = assitant_connection.their_node_info();

		// If the assistant node is a relay itself, just simply relay through the
		// assistant node
		if is_relay {
			if let Some((target_contact_option, _)) = self
				.base
				.packet_server
				.pick_contact_option(&target.contact_info)
			{
				if let Some((relay_contact_option, _)) = self
					.base
					.packet_server
					.pick_contact_option(&assistant_node_info.contact_info)
				{
					match self
						.base
						.packet_server
						.relay(
							&relay_contact_option,
							assistant_node_info.node_id.clone(),
							target_contact_option.target,
							&target.node_id,
						)
						.await
					{
						Err(e) => {
							error!("Unable to relay: {:?}", e);
							return None;
						}
						Ok(c) => return Some(c),
					}
				}
			}
		}

		// Otherwise, loop through all of our relay nodes until one serviced us
		// successfully.
		loop {
			let mut relay_nodes = self.relay_nodes.lock().await;
			if let Some(relay_node_info) = relay_nodes.pop_front() {
				drop(relay_nodes);
				let (contact_option, _) = self
					.base
					.packet_server
					.pick_contact_option(&target.contact_info)?;
				if let Some(relay_contact_option) = relay_node_info
					.contact_info
					.pick_relay_option(&contact_option)
				{
					// Attempt to open a relay connection through the current relay node
					match self
						.open_relay_with_node(
							&relay_node_info.node_id,
							&relay_contact_option,
							assistant_node_info.clone(),
							target.node_id.clone(),
							&contact_option,
						)
						.await
					{
						// On failure with the relay node, keep trying other relay nodes
						None => {}
						// If the relay node tells us the target was not reachable, stop.
						// Or if the connection was obtained, we're done.
						Some(r) => match r {
							OpenRelayStatus::Success(connection) => return Some(connection),
							OpenRelayStatus::AssistantUnaware => {
								warn!(
									"Unable to obtain relay connection because the assistant node \
									 was unaware of the target node."
								);
							}
							OpenRelayStatus::Timeout => {
								warn!(
									"Unable to obtain relay connection because the target node \
									 never contacted the relay node."
								);
							}
						},
					}
				}
			} else {
				break;
			}
		}
		warn!("No relay nodes were available to contact {}.", target);
		None
	}

	pub async fn open_relay_with_node(
		&self, relay_node_id: &IdType, relay_contact_option: &ContactOption,
		assistant_node_info: NodeContactInfo, target_node_id: IdType,
		target_contact_option: &ContactOption,
	) -> Option<OpenRelayStatus<Box<Connection>>> {
		let timeout = DEFAULT_TIMEOUT * 3;

		let protocol = LinkProtocol {
			use_ipv6: target_contact_option.target.is_ipv6(),
			use_tcp: target_contact_option.use_tcp,
		};
		let initiation_info = match self
			.base
			.packet_server
			.setup_outgoing_relay(
				relay_node_id.clone(),
				target_node_id.clone(),
				&target_contact_option.target,
				timeout,
				None,
			)
			.await
		{
			Ok(d) => d,
			Err(e) => {
				error!("Unable to set up outgoing relay: {:?}", e);
				return None;
			}
		};
		let request = OpenRelayRequest {
			target_node_id: target_node_id.clone(),
			protocol,
			assistant_node: assistant_node_info,
			hello_packet: initiation_info.packet.clone(),
		};

		let (status_message, relay_node_connection) = self
			.exchange_open_relay(relay_node_id, relay_contact_option, &request, timeout)
			.await?;
		match status_message.status {
			OpenRelayStatus::Success(hello_ack) => {
				let establish_info = hello_ack.into();
				let relay_connection = match self
					.base
					.packet_server
					.complete_outgoing_relay(
						relay_node_connection.socket_sender(),
						initiation_info,
						establish_info,
						&target_node_id,
						target_contact_option.target.clone(),
						timeout,
					)
					.await
				{
					Ok(c) => c,
					Err(e) => {
						error!("Unable to complete outgoing relay: {:?}", e);
						return None;
					}
				};
				Some(OpenRelayStatus::Success(relay_connection))
			}
			// TODO: Implement From/Into for the OpenRelayStatus error codes.
			OpenRelayStatus::AssistantUnaware => Some(OpenRelayStatus::AssistantUnaware),
			OpenRelayStatus::Timeout => Some(OpenRelayStatus::Timeout),
		}
	}

	async fn exchange_open_relay(
		&self, relay_node_id: &IdType, relay_contact_option: &ContactOption,
		request: &OpenRelayRequest, timeout: Duration,
	) -> Option<(OpenRelayStatusMessage, Box<Connection>)> {
		// Exchange the request and response to start opening the relay
		let buffer = binserde::serialize(request).unwrap();
		let (raw_response, mut connection) = self
			.base
			.exchange_at(
				relay_node_id,
				relay_contact_option,
				OVERLAY_MESSAGE_TYPE_OPEN_RELAY_REQUEST,
				&buffer,
			)
			.await?;
		let result: sstp::Result<_> = binserde::deserialize_sstp(&raw_response);
		let response: OpenRelayResponse = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		if !response.ok {
			return None;
		}

		// Wait for an update to know whether the target is ready to start the relay
		// connection.
		connection.set_keep_alive_timeout(timeout).await;
		let raw_update_result = connection.receive().await;
		let raw_update = self
			.base
			.handle_connection_issue(raw_update_result, connection.their_node_info())
			.await?;
		let result: sstp::Result<_> = binserde::deserialize_sstp(&raw_update);
		let update: OpenRelayStatusMessage = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		Some((update, connection))
	}

	pub(super) async fn initiate_indirect_connection(
		&self, relay_connection: &mut Connection, target: &IdType, their_contact: &ContactOption,
		our_contact: &ContactOption, reversed: bool, first_request: Option<&[u8]>,
	) -> Option<(Box<Connection>, Option<Vec<u8>>)> {
		// TODO: Only send a punch hole packet whenever our node is punchable for the
		// selected contact option.
		if reversed {
			if !self.punch_hole(their_contact).await {
				return None;
			}
		}

		// Contact the relay node
		let knows_target = self
			.exchange_relay_punch_hole_request(
				relay_connection,
				target.clone(),
				our_contact.clone(),
				reversed,
			)
			.await?;
		if !knows_target {
			return None;
		}

		let (tx_in, rx_in) = oneshot::channel();
		let connection_result = if reversed {
			{
				let mut expected_connections = self.expected_connections.lock().await;
				// If a connection from the same target is already expected, we can't touch it.
				// It would leave the other task that's still waiting on the previous connection
				// hanging.
				if expected_connections.contains_key(target) {
					error!(
						"Attempted to request reversed connection from same node more than once: \
						 {} {}",
						target, their_contact
					);
					return None;
				}
				expected_connections.insert(target.clone(), tx_in);
			}

			let result = select! {
				result = rx_in => {
					Some((result.expect("sender of expected connection has closed unexpectantly"), None))
				},
				() = sleep(sstp::DEFAULT_TIMEOUT * 5) => {
					None
				}
			};

			let mut expected_connections = self.expected_connections.lock().await;
			let removed = expected_connections.remove(target).is_some();

			// It could happen that the connection sender has already been taken from the
			// expected_connections map, but the sender hasn't been used yet. It is unlikely
			// but possible. However, the ownership of the connection sender has already
			// been taken, so there is not much else we can do about it, other than logging
			// it...
			if result.is_none() && !removed {
				debug!(
					"Reversed connection seems to have received, but the connection sender has \
					 not been used yet."
				);
			}

			result
		} else {
			let stop_flag = Arc::new(AtomicBool::new(false));
			self.base
				.connect_with_timeout(
					stop_flag,
					&their_contact,
					Some(&target),
					first_request,
					sstp::DEFAULT_TIMEOUT * 5,
				)
				.await
		};

		connection_result
	}

	fn start_obtaining_keep_alive_connection(self: &Arc<Self>) {
		let this = self.clone();
		spawn(async move {
			this.obtain_keep_alive_connection().await;
		});
	}

	pub fn node_id(&self) -> &IdType { &self.base.node_id }

	#[allow(dead_code)]
	pub async fn ping(&self, target: &NodeContactInfo) -> Option<u32> {
		self.base.ping(target).await
	}

	#[allow(dead_code)]
	pub async fn ping_at(&self, target: &ContactOption, node_id: &IdType) -> Option<u32> {
		self.base.ping_at(target, node_id).await
	}

	pub(super) async fn process_actor_request(
		self: &Arc<Self>, actor_node: &Arc<ActorNode>, message_type: u8, buffer: &[u8],
		addr: &SocketAddr, node_info: &NodeContactInfo, is_lurker: bool,
	) -> MessageProcessorResult {
		let (result, processed) = actor_node
			.base
			.process_request(
				self.clone(),
				message_type,
				&buffer,
				addr,
				node_info,
				Some(&actor_node.actor_address().as_id()),
			)
			.await;
		if !processed {
			debug_assert!(result.is_none());
		}

		if !processed {
			actor_node
				.process_request(message_type, buffer, addr, node_info)
				.await
		} else {
			if let Some(mut x) = result {
				if !is_lurker {
					actor_node.base.mark_node_helpful(node_info).await;
				}
				if x.0.len() > 0 {
					x.0[0] |= 0x80;
				}
				Some(x)
			} else {
				actor_node
					.base
					.mark_node_problematic(&node_info.node_id)
					.await;
				None
			}
		}
	}

	async fn process_find_actor_request(&self, buffer: &[u8]) -> MessageProcessorResult {
		let request: FindActorRequest = match binserde::deserialize(buffer) {
			Err(e) => {
				error!("Malformed find actor request: {}", e);
				return None;
			}
			Ok(r) => r,
		};

		let (connected, fingers) = self
			.base
			.find_nearest_public_contacts(&request.node_id)
			.await;
		let mut response = FindActorResponse {
			contacts: FindNodeResponse {
				is_relay_node: self.is_relay_node,
				connected,
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
			let c = self.db().connect_old()?;
			c.fetch_identity_by_id(&request.node_id)
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
		self.base
			.simple_result(OVERLAY_MESSAGE_TYPE_FIND_ACTOR_RESPONSE, &response)
	}

	async fn process_keep_alive_request(
		self: &Arc<Self>, buffer: &[u8], node_info: &NodeContactInfo,
	) -> MessageProcessorResult {
		// The keep alive request should be empty
		if buffer.len() > 0 {
			return None;
		}

		Some((
			Vec::new(),
			Some(Box::new(KeepAliveToDo {
				node: self.clone(),
				node_id: node_info.node_id.clone(),
			})),
		))
	}

	async fn process_open_relay_request(
		self: &Arc<Self>, buffer: &[u8], addr: &SocketAddr,
	) -> MessageProcessorResult {
		let request: OpenRelayRequest = match binserde::deserialize(buffer) {
			Ok(r) => r,
			Err(e) => {
				error!("Malformed open relay request: {}", e);
				return None;
			}
		};

		Some((
			Vec::new(),
			Some(Box::new(OpenRelayToDo {
				node: self.clone(),
				source_addr: addr.clone(),
				target_node_id: request.target_node_id,
				assistant_node_info: request.assistant_node,
				hello_packet: request.hello_packet,
				timeout: DEFAULT_TIMEOUT * 3,
			})),
		))
	}

	async fn process_pass_relay_request_request(
		self: &Arc<Self>, buffer: &[u8],
	) -> MessageProcessorResult {
		let request: PassRelayRequestRequest = match binserde::deserialize(buffer) {
			Ok(r) => r,
			Err(e) => {
				error!("Malformed open relay request: {}", e);
				return None;
			}
		};
		let request2 = Box::new(request);
		let mut response = PassRelayRequestResponse { ok: true };
		let this = self.clone();
		match self
			.connection_manager()
			.find(&request2.target_node_id)
			.await
		{
			None => response.ok = false,
			Some((_, c)) => {
				spawn(async move {
					let mut connection = c.lock().await;

					if this
						.exchange_relay_request_on_connection(&mut connection, &request2.base)
						.await
						.is_none()
					{
						warn!(
							"Unable to pass relay request to node {}.",
							connection.their_node_info()
						);
					}
				});
			}
		}

		self.base
			.simple_result(OVERLAY_MESSAGE_TYPE_PASS_RELAY_REQUEST_RESPONSE, &response)
	}

	async fn process_punch_hole_request(self: &Arc<Self>, buffer: &[u8]) -> MessageProcessorResult {
		let request: PunchHoleRequest = match binserde::deserialize(buffer) {
			Err(e) => {
				warn!("Malformed initiate connection request: {}", e);
				return None;
			}
			Ok(r) => r,
		};

		// If a connection was not requested, simply send a packet to open a hole for a
		// connection to come in
		let success = if !request.request_connection {
			if let Err(e) = self
				.base
				.packet_server
				.send_punch_hole_packet(&request.source_contact_option)
				.await
			{
				error!(
					"Unable to send hole punch packet to {}: {:?}",
					&request.source_contact_option, e
				);
				false
			} else {
				true
			}

		// If a connection was requested, open one and reverse the direction
		// immediately
		} else {
			let this = self.clone();
			spawn(async move {
				if let Some((mut connection, _)) = this
					.base
					.connect(
						&request.source_contact_option,
						Some(&request.source_node_id),
						None,
					)
					.await
				{
					if this
						.exchange_reverse_connection_on_connection(&mut connection)
						.await == Some(true)
					{
						this.base.packet_server.spawn_connection(connection, None);
					}
				}
			});
			true
		};

		let response = PunchHoleResponse { ok: success };
		self.base
			.simple_result(OVERLAY_MESSAGE_TYPE_PUNCH_HOLE_RESPONSE, &response)
	}

	async fn process_relay_punch_hole_request(
		self: &Arc<Self>, buffer: &[u8], node_info: &NodeContactInfo,
	) -> MessageProcessorResult {
		let request: PassPunchHoleRequest = match binserde::deserialize(buffer) {
			Err(e) => {
				warn!("Malformed relay initiate connection request: {}", e);
				return None;
			}
			Ok(r) => r,
		};
		let mut response = PassPunchHoleResponse { ok: true };

		// If the requested target node happens to be one of our known bootstrap nodes,
		// we always allow it
		if self
			.bootstrap_nodes
			.contains(&request.contact_option.target)
		{
			let this = self.clone();
			let node_id2 = node_info.node_id.clone();
			spawn(async move {
				if let Some((mut connection, _)) = this
					.base
					.connect(&request.contact_option, Some(&request.target), None)
					.await
				{
					this.exchange_punch_hole_on_connection(
						&mut connection,
						node_id2,
						request.contact_option,
						request.request_connection,
					)
					.await;
				}
			});
		}
		// Otherwise, we only allow if we have a connection with the node
		else if let Some((_, connection_mutex)) =
			self.connection_manager().find(&request.target).await
		{
			let this = self.clone();
			let node_id2 = node_info.node_id.clone();
			spawn(async move {
				let mut connection = connection_mutex.lock().await;
				this.exchange_punch_hole_on_connection(
					&mut connection,
					node_id2,
					request.contact_option,
					request.request_connection,
				)
				.await
			});
		} else {
			response.ok = false;
		}

		self.base
			.simple_result(OVERLAY_MESSAGE_TYPE_RELAY_PUNCH_HOLE_RESPONSE, &response)
	}

	async fn process_relay_request_request(
		self: &Arc<Self>, buffer: &[u8],
	) -> MessageProcessorResult {
		let request: RelayRequestRequest = match binserde::deserialize(buffer) {
			Ok(r) => r,
			Err(e) => {
				warn!("Malformed open relay request: {}", e);
				return None;
			}
		};
		let request2 = Box::new(request);

		let this = self.clone();
		spawn(async move {
			let sender = match this
				.base
				.packet_server
				.link_connect(&request2.relay_node_contact, DEFAULT_TIMEOUT)
				.await
			{
				Ok(s) => s,
				Err(e) => {
					warn!(
						"Unable to sent relayed hello ack packet to relay node: {:?}",
						e
					);
					return;
				}
			};
			if let Err(e) = this
				.base
				.packet_server
				.process_relayed_hello_packet(
					sender,
					&request2.relay_node_contact,
					request2.relayed_hello_packet,
				)
				.await
			{
				warn!("Unable to process relayed hello ack packet: {:?}", e);
			}
		});

		self.base
			.simple_result(OVERLAY_MESSAGE_TYPE_RELAY_REQUEST_RESPONSE, &())
	}

	pub(super) async fn process_request(
		self: &Arc<Self>, message_type: u8, buffer: &[u8], contact: &ContactOption,
		node_info: &NodeContactInfo,
	) -> MessageProcessorResult {
		match message_type {
			OVERLAY_MESSAGE_TYPE_FIND_ACTOR_REQUEST =>
				self.process_find_actor_request(buffer).await,
			OVERLAY_MESSAGE_TYPE_STORE_ACTOR_REQUEST =>
				self.process_store_actor_request(buffer, node_info).await,
			OVERLAY_MESSAGE_TYPE_KEEP_ALIVE_REQUEST =>
				return self.process_keep_alive_request(buffer, node_info).await,
			OVERLAY_MESSAGE_TYPE_PUNCH_HOLE_REQUEST =>
				self.process_punch_hole_request(buffer).await,
			OVERLAY_MESSAGE_TYPE_RELAY_PUNCH_HOLE_REQUEST =>
				self.process_relay_punch_hole_request(buffer, node_info)
					.await,
			OVERLAY_MESSAGE_TYPE_REVERSE_CONNECTION_REQUEST =>
				self.process_reverse_connection_request(buffer, &node_info.node_id)
					.await,
			OVERLAY_MESSAGE_TYPE_OPEN_RELAY_REQUEST =>
				self.process_open_relay_request(buffer, &contact.target)
					.await,
			OVERLAY_MESSAGE_TYPE_RELAY_REQUEST_REQUEST =>
				self.process_relay_request_request(buffer).await,
			OVERLAY_MESSAGE_TYPE_PASS_RELAY_REQUEST_REQUEST =>
				self.process_pass_relay_request_request(buffer).await,
			other_id => {
				warn!(
					"Unknown overlay message type ID received from {}: {}",
					contact, other_id
				);
				return None;
			}
		}
	}

	async fn process_reverse_connection_request(
		&self, buffer: &[u8], node_id: &IdType,
	) -> MessageProcessorResult {
		if buffer.len() > 0 {
			warn!("Malformed reverse connection request.");
			return None;
		}

		let result = self.expected_connections.lock().await.remove(node_id);
		let response = ReverseConnectionResponse {
			ok: result.is_some(),
		};
		let raw_response = self
			.base
			.simple_response(OVERLAY_MESSAGE_TYPE_REVERSE_CONNECTION_RESPONSE, &response);

		if let Some(tx) = result {
			Some((
				raw_response,
				Some(Box::new(ReverseConnectionToDo { sender: Some(tx) })),
			))
		} else {
			Some((raw_response, None))
		}
	}

	async fn process_store_actor_request(
		&self, buffer: &[u8], node_info: &NodeContactInfo,
	) -> MessageProcessorResult {
		let request: StoreActorRequest = match binserde::deserialize(buffer) {
			Err(e) => {
				error!("Malformed store actor request: {}", e);
				return None;
			}
			Ok(r) => r,
		};

		// Check if actor_id is indeed the hash of the public key + first block hash.
		let actor_id_test = request.actor_info.generate_address();
		if actor_id_test.as_id().as_ref() != &request.actor_id {
			warn!("Actor store request invalid: public key doesn't match actor ID.");
			return None;
		}

		// Add actor to store
		let mut node_store = NODE_ACTOR_STORE.lock().await;
		match node_store.find_mut(&request.actor_id) {
			None => {
				node_store.add(
					request.actor_id.clone(),
					ActorStoreEntry::new_with_contact(request.actor_info, node_info.clone()),
				);
			}
			Some(entry) => {
				entry.add_available_node(node_info.clone());
			}
		}

		let response = StoreActorResponse {};
		self.base
			.simple_result(OVERLAY_MESSAGE_TYPE_STORE_ACTOR_RESPONSE, &response)
	}

	async fn punch_hole(&self, target: &ContactOption) -> bool {
		match self.base.packet_server.send_punch_hole_packet(target).await {
			Ok(_) => true,
			Err(e) => {
				error!("Unable to send hole punching packet to {}: {}", &target, e);
				false
			}
		}
	}

	/// Remembers the given node info as one of our relay nodes, if the room is
	/// available. Returns whether it was added.
	pub async fn remember_relay_node(&self, node_info: &NodeContactInfo) -> bool {
		let mut relay_nodes = self.relay_nodes.lock().await;
		if relay_nodes
			.iter()
			.find(|n| n.node_id == node_info.node_id)
			.is_none()
		{
			relay_nodes.push_back(node_info.clone());
			true
		} else {
			false
		}
	}

	pub fn set_contact_info(&self, contact_info: ContactInfo) {
		self.base.set_contact_info(contact_info);
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
	/// continues to find contacts to store them at too.
	pub async fn store_actor_at_contacts(
		&self, actor_id: &IdType, duplicates: usize, actor_info: &ActorInfo,
		contacts: &[(IdType, ContactOption)],
	) -> usize {
		let mut store_count = 0;
		let mut fingers = Vec::with_capacity(contacts.len());
		for (node_id, contact_option) in contacts {
			if let Some((mut connection, _)) =
				self.base.connect(contact_option, Some(node_id), None).await
			{
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
			}
		}

		if store_count < duplicates {
			let todo = duplicates - store_count;
			let contacts = self
				.base
				.find_node_from_fingers(&actor_id, &fingers, todo * 2, 1)
				.await;
			if contacts.len() > 0 {
				store_count += self
					.store_actor_at(actor_id, todo, actor_info, &contacts)
					.await;
			} else {
				store_count += self.store_actor(actor_id, todo, actor_info).await;
			}
		}
		store_count
	}

	pub async fn test_openness_udpv4(&self, bootstrap_nodes: &[SocketAddr]) -> Option<Openness> {
		self._test_openness(&bootstrap_nodes, true, |ci| {
			let e1 = ci.ipv4.as_ref().expect("IPv4 not set");
			let e2 = e1.availability.udp.as_ref().expect("UDPv4 port not set");
			ContactOption::new(SocketAddr::V4(SocketAddrV4::new(e1.addr, e2.port)), false)
		})
		.await
	}

	pub async fn test_openness_tcpv4(&self, bootstrap_nodes: &[SocketAddr]) -> Option<Openness> {
		self._test_openness(&bootstrap_nodes, false, |ci| {
			let e1 = ci.ipv4.as_ref().expect("IPv4 not set");
			let e2 = e1.availability.udp.as_ref().expect("TCPv4 port not set");
			ContactOption::new(SocketAddr::V4(SocketAddrV4::new(e1.addr, e2.port)), true)
		})
		.await
	}

	pub async fn test_openness_udpv6(&self, bootstrap_nodes: &[SocketAddr]) -> Option<Openness> {
		self._test_openness(&bootstrap_nodes, true, |ci| {
			let e1 = ci.ipv6.as_ref().expect("IPv6 not set");
			let e2 = e1.availability.udp.as_ref().expect("UDPv6 port not set");
			ContactOption::new(
				SocketAddr::V6(SocketAddrV6::new(e1.addr, e2.port, 0, 0)),
				false,
			)
		})
		.await
	}

	pub async fn test_openness_tcpv6(&self, bootstrap_nodes: &[SocketAddr]) -> Option<Openness> {
		self._test_openness(&bootstrap_nodes, false, |ci| {
			let e1 = ci.ipv6.as_ref().expect("IPv6 not set");
			let e2 = e1.availability.udp.as_ref().expect("TCPv6 port not set");
			ContactOption::new(
				SocketAddr::V6(SocketAddrV6::new(e1.addr, e2.port, 0, 0)),
				true,
			)
		})
		.await
	}

	pub async fn _test_openness(
		&self, bootstrap_nodes: &[SocketAddr], use_udp: bool,
		our_contact_fn: impl FnOnce(&ContactInfo) -> ContactOption,
	) -> Option<Openness> {
		// Parse the bootstrap nodes addresses
		let bnode1_addr = bootstrap_nodes[0];
		let bnode2_addr = bootstrap_nodes[1];
		let bnode1_contact = ContactOption::new(bnode1_addr, !use_udp);
		let bnode2_contact = ContactOption::new(bnode2_addr, !use_udp);

		// Test if we can do hole punching
		// We need to open a connection to obtain the node's ID first, because
		// requesting a reversed connection requires it
		// FIXME: In order to test if this node is actually bidirectional, we
		// can request a reverse connection without connecting to it first.
		let mut db = self
			.db()
			.connect_old()
			.expect("unable to connect to database");
		let (mut bnode1_connection, _) = self.base.connect(&bnode1_contact, None, None).await?;
		bnode1_connection
			.set_keep_alive_timeout(sstp::DEFAULT_TIMEOUT * 4)
			.await;
		let our_contact = our_contact_fn(&self.base.packet_server.our_contact_info());
		let bnode2_id = if let Some(bnode2_id) = db
			.fetch_bootstrap_node_id(&bnode2_addr)
			.expect("unable to fetch bootstrap node ID")
		{
			// If we know the bootstrap node's ID, we can test if we are a bidirectional
			// node.
			if let Some(_rc) = self
				.initiate_indirect_connection(
					&mut bnode1_connection,
					&bnode2_id,
					&bnode2_contact,
					&our_contact,
					true,
					None,
				)
				.await
			{
				return Some(Openness::Bidirectional);
			}

			bnode2_id
		} else {
			if let Some((bnode2_connection, _)) =
				self.base.connect(&bnode2_contact, None, None).await
			{
				let bnode2_id = bnode2_connection.their_node_id().clone();
				db.remember_bootstrap_node_id(&bnode2_addr, &bnode2_id)
					.expect("unable to remember bootstrap node ID");
				bnode2_id
			} else {
				return None;
			}
		};

		// If the node is not bidirectional, try to test if it is punchable
		if let Some(_rc) = self
			.initiate_indirect_connection(
				&mut bnode1_connection,
				&bnode2_id,
				&bnode2_contact,
				&our_contact,
				true,
				None,
			)
			.await
		{
			return Some(Openness::Punchable);
		} else {
			return Some(Openness::Unidirectional);
		}
	}

	/// Makes an attempt to update the actor info for a tracked actor. If not
	/// able to, it will try again in an hour.
	fn maintain_tracked_actor(self: Arc<Self>, address: ActorAddress) -> BoxFuture<'static, ()> {
		fn join(this: Arc<OverlayNode>, address: ActorAddress, actor_info: ActorInfo) {
			spawn(async move {
				if let Some(node) = this.join_actor_network(&address, &actor_info).await {
					{
						let mut map = this.tracked_actors.lock().await;
						map.insert(address.clone(), Some(actor_info));
					}
					this.base
						.interface
						.actor_nodes
						.lock()
						.await
						.insert(address.to_id(), node);
				}
			});
		}

		Box::pin(async move {
			// If the data is in our own DB, use it then join the network
			let result = match self.db().find_actor_info(&address).await {
				Ok(r) => r,
				Err(e) => {
					error!("Database issue when trying to find actor: {}", e);
					return;
				}
			};
			if let Some(actor_info) = result {
				join(self.clone(), address.clone(), actor_info);
			}
			// If not, we need fetch it from the network itself.
			else {
				if let Some(result) = self.find_actor(&address, 100, true).await {
					let actor_info = result.0;
					if let Err(e) = self.db().perform(|mut c| {
						c.store_identity(&address, &actor_info.public_key, &actor_info.first_object)
					}) {
						error!("Unable to store identity of tracked actor: {:?}", e);
					}
					join(self.clone(), address.clone(), actor_info);
				}
				// If failed to obtain actor info from anywhere, wait an hour and then try again
				else if self.base.is_running() {
					spawn(async move {
						sleep(Duration::from_secs(3600)).await;
						self.maintain_tracked_actor(address).await;
					});
				}
			}
		})
	}

	/// Will start to update the `tracked_actors` map with some actor info, if
	/// that can be found. Tasks will be spawned to retry after an hour, if the
	/// address has failed to be found.
	async fn maintain_tracked_actors(self: &Arc<Self>) {
		// TODO: Improve effeciency
		let tracked_actors = self.tracked_actors.lock().await;
		for (address, actor_info_opt) in tracked_actors.iter() {
			if actor_info_opt.is_none() {
				let this = self.clone();
				let address2 = address.clone();
				spawn(async move {
					this.maintain_tracked_actor(address2).await;
				});
			}
		}
	}
}

#[async_trait]
impl MessageWorkToDo for OpenRelayToDo {
	// The OpenRelayToDo will sent a request to an assistant node to reach the
	// target node, to ask it to sent a RelayedHelloAckPacket to our server. Then,
	// if it worked out, the packet will be sent back to the source node.
	async fn run(&mut self, mut connection: Box<Connection>) -> Result<Option<Box<Connection>>> {
		let mut response = OpenRelayResponse { ok: true };

		let (_, relayed_hello_packet, mut hello_receiver) = match self
			.node
			.base
			.packet_server
			.process_relay_hello_packet(
				connection.socket_sender(),
				&self.source_addr,
				self.hello_packet.clone(),
				None,
			)
			.await
		{
			Ok(r) => r,
			Err(e) => {
				error!(
					"Unable to process relay hello packet for open relay request: {:?}",
					e
				);
				response.ok = false;
				let raw_response = self
					.node
					.base
					.simple_response(OVERLAY_MESSAGE_TYPE_OPEN_RELAY_RESPONSE, &response);
				connection.send(raw_response).await?;
				return Ok(None);
			}
		};

		// The response wasn't sent yet
		let raw_response = self
			.node
			.base
			.simple_response(OVERLAY_MESSAGE_TYPE_OPEN_RELAY_RESPONSE, &response);
		connection.send(raw_response).await?;
		if !response.ok {
			return Ok(None);
		}

		// Pass the packet to the assistant node.
		match self
			.node
			.base
			.contact_info()
			.pick_relay_option(&connection.contact_option())
		{
			None => return Ok(None),
			Some(relay_node_contact) => {
				let request = PassRelayRequestRequest {
					target_node_id: self.target_node_id.clone(),
					base: RelayRequestRequest {
						relay_node_contact,
						relayed_hello_packet,
					},
				};
				match self
					.node
					.exchange_pass_relayed_hello_packet(&self.assistant_node_info, &request)
					.await
				{
					None => return Ok(None),
					// If assistant node doesn't know the target node, we need to let the source
					// node know
					Some(response) =>
						if !response.ok {
							let message = OpenRelayStatusMessage {
								status: OpenRelayStatus::AssistantUnaware,
							};
							connection
								.send(binserde::serialize(&message).unwrap())
								.await?;
							return Ok(None);
						},
				}
			}
		}

		// Wait for the RelayedHelloAckPacket to arrive.
		let relayed_hello_ack_packet = select! {
			result = hello_receiver.recv() => {
				let packet = match result {
					Some(r) => r,
					None => {
						error!("Unable to received relay hello ack packet from channel.");
						return Ok(None);
					}
				};

				// TODO: Send back
				Some(packet)
			},
			_ = sleep(self.timeout) => {
				warn!("Never received the expected relayed hello ack packet from target node after {:?} seconds.", self.timeout);
				None
			}
		};

		let message = OpenRelayStatusMessage {
			status: match relayed_hello_ack_packet {
				None => OpenRelayStatus::Timeout,
				Some(packet) => OpenRelayStatus::Success(packet),
			},
		};
		connection
			.send(binserde::serialize(&message).unwrap())
			.await?;
		// I guess we can keep the connection open if the client wants to do anything
		// else with it
		Ok(Some(connection))
	}
}

#[async_trait]
impl MessageWorkToDo for ReverseConnectionToDo {
	async fn run(&mut self, connection: Box<Connection>) -> Result<Option<Box<Connection>>> {
		// The ReverseConnectionToDo will only give away the connection to start
		// listening on it.
		if let Err(_) = self.sender.take().unwrap().send(connection) {
			error!("Unable to send expected connection to channel.");
		}
		Ok(None)
	}
}


pub(super) async fn process_request_message(
	overlay_node: Arc<OverlayNode>, buffer: Vec<u8>, contact: ContactOption,
	node_info: NodeContactInfo,
) -> Option<(Vec<u8>, Option<Box<dyn MessageWorkToDo>>)> {
	let mut message_type_id = buffer[0];
	if message_type_id >= 0x80 {
		message_type_id ^= 0x80;
		let actor_id: IdType = binserde::deserialize(&buffer[1..33]).unwrap();
		let is_lurker = buffer[33] & 0x80 > 0;
		let actor_nodes = overlay_node.base.interface.actor_nodes.lock().await;
		let actor_node = match actor_nodes.get(&actor_id) {
			None => {
				warn!("Received actor request for actor network we've not joined.");
				return None; /* Don't respond to requests for networks we are not connected */
			}
			// to.
			Some(n) => n.clone(),
		};
		drop(actor_nodes);

		overlay_node
			.process_actor_request(
				&actor_node,
				message_type_id,
				&buffer[34..],
				&contact.target,
				&node_info,
				is_lurker,
			)
			.await
	} else {
		let (connection2, processed) = overlay_node
			.base
			.process_request(
				overlay_node.clone(),
				message_type_id,
				&buffer[1..],
				&contact.target,
				&node_info,
				None,
			)
			.await;
		if !processed {
			overlay_node
				.process_request(message_type_id, &buffer[1..], &contact, &node_info)
				.await
		} else {
			connection2
		}
	}
}


#[cfg(test)]
mod tests {

	use crate::{net::overlay::*, test};

	#[tokio::test(flavor = "multi_thread")]
	async fn test_direct() {
		test_overlay_connectivity("unidirectional", "bidirectional", false, 11000).await;
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_hole_punching_normal() {
		test_overlay_connectivity("unidirectional", "punchable", false, 12000).await;
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_hole_punching_reversed() {
		test_overlay_connectivity("punchable", "unidirectional", false, 13000).await;
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_relay_direct() {
		test_overlay_connectivity("unidirectional", "unidirectional", true, 14000).await;
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn test_relay_indirect() {
		test_overlay_connectivity("unidirectional", "unidirectional", false, 15000).await;
	}

	async fn test_overlay_connectivity(
		openness_source_node: &str, openness_target_node: &str, assistant_is_relay: bool,
		first_port: u16,
	) {
		// Setup all nodes
		let mut rng = test::initialize_rng();
		let stop_flag = Arc::new(AtomicBool::new(false));
		let mut assistant_config = Config::default();
		assistant_config.ipv4_address = Some("127.0.0.1".to_string());
		assistant_config.ipv4_udp_port = Some(first_port);
		assistant_config.ipv4_udp_openness = Some("bidirectional".to_string());
		assistant_config.relay_node = Some(assistant_is_relay);
		let mut relay_config = Config::default();
		relay_config.bootstrap_nodes = vec![format!(
			"127.0.0.1:{}",
			assistant_config.ipv4_udp_port.unwrap()
		)];
		relay_config.ipv4_address = Some("127.0.0.1".to_string());
		relay_config.ipv4_udp_port = Some(first_port + 1);
		relay_config.ipv4_udp_openness = Some("bidirectional".to_string());
		relay_config.relay_node = Some(true);
		let mut source_config = Config::default();
		source_config.bootstrap_nodes = vec![format!(
			"127.0.0.1:{}",
			assistant_config.ipv4_udp_port.unwrap()
		)];
		source_config.ipv4_address = Some("127.0.0.1".to_string());
		source_config.ipv4_udp_port = Some(first_port + 2);
		source_config.ipv4_udp_openness = Some(openness_source_node.to_string());
		let mut target_config = Config::default();
		target_config.bootstrap_nodes = vec![format!(
			"127.0.0.1:{}",
			assistant_config.ipv4_udp_port.unwrap()
		)];
		target_config.ipv4_address = Some("127.0.0.1".to_string());
		target_config.ipv4_udp_port = Some(first_port + 3);
		target_config.ipv4_udp_openness = Some(openness_target_node.to_string());

		let _assistant_node =
			test::load_test_node(stop_flag.clone(), &mut rng, &assistant_config, "assistant").await;
		let target_node =
			test::load_test_node(stop_flag.clone(), &mut rng, &target_config, "target").await;
		// Load the 'relay' node after the 'target' node, so that the 'target' node
		// always attached itself to the 'assistant' node rather than the 'relay' node.
		let relay_node =
			test::load_test_node(stop_flag.clone(), &mut rng, &relay_config, "random").await;

		// Create data at the target node
		let (actor_address, actor_info) = target_node
			.create_identity("test", "Test", None, None, None)
			.await
			.unwrap();
		let _ = target_node
			.node
			.join_actor_network(&actor_address, &actor_info)
			.await
			.unwrap();

		// Find data as the source node
		let source_node =
			test::load_test_node(stop_flag.clone(), &mut rng, &source_config, "source").await;
		// Make sure that we find the relay node in case the source node needs it
		let relay_node_info = source_node
			.node
			.find_node(relay_node.node.node_id())
			.await
			.expect("relay node not found");
		source_node.node.remember_relay_node(&relay_node_info).await;

		let profile = source_node
			.find_profile_info(&actor_address)
			.await
			.unwrap()
			.expect("no actor profile found");
		stop_flag.store(true, Ordering::Relaxed);

		assert_eq!(profile.actor.name, "Test");
	}
}

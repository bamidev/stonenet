// FIXME: Remove when going stable:
#![allow(dead_code)]

use std::{
	boxed::Box,
	collections::HashMap,
	net::SocketAddr,
	str::FromStr,
	sync::{atomic::*, Arc, Mutex as StdMutex},
};

use async_trait::async_trait;
use futures::future::join_all;
use log::*;
use tokio::{self, time::sleep};

use super::{actor::*, actor_store::*, bincode, message::*, node::*, sstp, KADEMLIA_K};
use crate::{
	common::*,
	config::*,
	db::{self, Database},
	identity::*,
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
pub const OVERLAY_MESSAGE_TYPE_RELAY_REQUEST: u8 = 72;
//pub const OVERLAY_MESSAGE_TYPE_RELAY_RESPONSE: u8 = 73;

pub struct FindActorIter<'a>(FindValueIter<'a, OverlayInterface>);

/*#[derive(Clone, Default)]
struct OverlayBucket {
	pub base: StandardBucket
}*/

pub struct OverlayNode {
	pub(super) base: Arc<Node<OverlayInterface>>,
	bootstrap_nodes: Vec<SocketAddr>,
}

pub(super) struct OverlayInterface {
	db: Database,
	pub(super) actor_nodes: Mutex<HashMap<IdType, Arc<ActorNode>>>,
	max_idle_time: usize,
	last_message_time: StdMutex<SystemTime>,
}


#[async_trait]
impl NodeInterface for OverlayInterface {
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

	/// Goes through all the connection managers of all actor nodes, in order to
	/// find a connection that is close enough. Returns the first one that
	/// is found.
	async fn find_near_connection(&self, bit: u8) -> Option<NodeContactInfo> {
		let actor_nodes = self.actor_nodes.lock().await;
		for actor_node in actor_nodes.values() {
			let result = actor_node.base.interface.find_near_connection(bit).await;
			if result.is_some() {
				return result;
			}
		}
		None
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

impl OverlayNode {
	pub async fn start(
		stop_flag: Arc<AtomicBool>, node_id: IdType, contact_info: ContactInfo, keypair: Keypair,
		db: Database, config: &Config,
	) -> sstp::Result<Arc<Self>> {
		let mut bootstrap_nodes = Vec::<SocketAddr>::with_capacity(config.bootstrap_nodes.len());
		for address_string in &config.bootstrap_nodes {
			match SocketAddr::from_str(address_string) {
				Err(e) => error!("Unable to parse bootstrap node {}: {}.", address_string, e),
				Ok(s) => bootstrap_nodes.push(s),
			}
		}

		let socket =
			sstp::Server::bind(stop_flag.clone(), node_id.clone(), contact_info, keypair).await?;

		let this = Arc::new(Self {
			base: Arc::new(Node::new(
				stop_flag,
				node_id.clone(),
				socket.clone(),
				OverlayInterface {
					db,
					last_message_time: StdMutex::new(SystemTime::now()),
					max_idle_time: config.udp_max_idle_time,
					actor_nodes: Mutex::new(HashMap::new()),
				},
				config.bucket_size,
			)),
			bootstrap_nodes,
		});

		let this2 = this.clone();
		socket.listen(move |connection| {
			let this3 = this2.clone();
			tokio::spawn(async move {
				// Check if connection is expected by a hole punch request
				{
					let mut expected = this3.base.expected_connections.lock().await;
					if let Some(tx) = expected.remove(connection.their_node_id()) {
						if tx.send(connection).is_err() {
							error!("Unable to send connection to hole punch origin node.")
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
		let response: FindActorResponse = self
			.base
			.handle_connection_issue2(result, &target.node_id, &target.contact_info)
			.await?;
		Some(response)
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
	pub async fn lurk_actor_network(&self, actor_id: &IdType) -> Option<ActorNode> {
		let mut iter = self.find_actor_iter(actor_id, 100, true).await;
		while let Some(result) = iter.next().await {
			let (actor_info, nodes) = &*result;
			for contact in nodes {
				let actor_node = ActorNode::new_lurker(
					self.base.stop_flag.clone(),
					self.base.socket.clone(),
					actor_id.clone(),
					actor_info.clone(),
					self.db().clone(),
					self.base.bucket_size,
				);
				if actor_node.base.test_id(&contact).await {
					actor_node
						.base
						.remember_node_nondestructive(contact.clone())
						.await;
					return Some(actor_node);
				}
			}
		}

		None
	}

	pub async fn find_actor(
		&self, id: &IdType, hop_limit: usize, narrow_down: bool,
	) -> Option<Box<(ActorInfo, Vec<NodeContactInfo>)>> {
		self.find_actor_iter(id, hop_limit, narrow_down)
			.await
			.next()
			.await
	}

	/// Tries to find the
	pub async fn find_actor_iter(
		&self, id: &IdType, hop_limit: usize, narrow_down: bool,
	) -> FindActorIter {
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
					let x = AtomicPtr::new(Box::into_raw(value) as _);
					Some(x)
				}
			}
		}

		let fingers = self.base.find_nearest_fingers(id).await;
		let iter = self.base.find_value_from_fingers_iter(
			id,
			0,
			true,
			&fingers,
			hop_limit,
			narrow_down,
			verify_pubkey,
		);
		FindActorIter(iter)
	}

	pub async fn get_actor_node(&self, actor_id: &IdType) -> Option<Arc<ActorNode>> {
		let nodes = self.base.interface.actor_nodes.lock().await;
		nodes.get(actor_id).map(|n| n.clone())
	}

	pub async fn join_actor_network(
		&self, actor_id: IdType, actor_info: ActorInfo,
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
					self.node_id().clone(),
					self.base.socket.clone(),
					actor_id.clone(),
					actor_info,
					self.db().clone(),
					self.base.bucket_size,
				));
				actor_nodes.insert(actor_id.clone(), node.clone());
				node
			}
		};

		// Try to find k nodes for the network first
		let mut contacts = Vec::with_capacity((KADEMLIA_K * 2 - 1) as _);
		let mut actor_iter = self.find_actor_iter(&actor_id, 100, false).await;
		let mut actor_info = None;
		while let Some(result) = actor_iter.next().await {
			let (ai, actor_nodes) = *result;
			if actor_info.is_none() {
				actor_info = Some(ai);
			}

			// Test each found node before using them
			for n in actor_nodes {
				if self.base.test_id(&n).await {
					contacts.push(n);
				}
			}

			if contacts.len() >= KADEMLIA_K as usize {
				break;
			}
			if self.base.has_stopped() {
				return None;
			}
		}

		// If no nodes responded with a result, we don't have the public key.
		if actor_info.is_none() {
			tokio::task::block_in_place(|| {
				match self.db().connect() {
					Err(e) => error!("Unable to connect to database to fetch identity: {}", e),
					Ok(c) => match c.fetch_identity(&actor_id) {
						Err(e) => error!("Unable to fetch identity from db: {}", e),
						Ok(ai) => actor_info = ai,
					},
				};
			});

			// If we don't have it, we can't join the network.
			if actor_info.is_none() {
				return None;
			}
		}

		// If we've found less than k nodes, make sure to store it a few more
		// times in the network.
		if contacts.len() < KADEMLIA_K as usize {
			let store_count = KADEMLIA_K as usize - contacts.len();
			let fingers = if store_count > actor_iter.visited().len() {
				actor_iter.visited()
			} else {
				let l = actor_iter.visited().len();
				&actor_iter.visited()[(l - store_count)..]
			};

			// Try storing from the last visited nodes first
			let mut actually_stored = 0;
			if fingers.len() > 0 {
				// FIXME: Uncomment
				actually_stored = self
					.store_actor_at_contacts(
						&actor_id,
						store_count,
						actor_info.as_ref().unwrap(),
						fingers,
					)
					.await;
			}

			// If still not enough stored at enough nodes, try again from the
			// start.
			if actually_stored < store_count {
				actually_stored += self
					.store_actor(
						&actor_id,
						store_count - actually_stored,
						actor_info.as_ref().unwrap(),
					)
					.await;

				if actually_stored == 0 {
					warn!("Unable to store actor at any nodes.");
					return None;
				}
			}
		}

		//spawn(async move {
		node.initialize(&contacts).await;
		//});
		Some(node)
	}

	async fn join_actor_networks(&self, actors: Vec<(IdType, ActorInfo)>) {
		// Join each network in parallel
		let futs = actors.into_iter().map(|(actor_id, actor_info)| async {
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
					.join_actor_network(actor_id, actor_info)
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
	pub async fn join_network(&self, stop_flag: Arc<AtomicBool>) -> bool {
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
				false => error!("Bootstrap node {} wasn't available", bootstrap_node),
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
									|(id, first_object, actor_type, keypair)| {
										(
											id,
											ActorInfo {
												public_key: keypair.public(),
												first_object,
												actor_type,
											},
										)
									},
								));
								list
							});

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
					"None of the {} bootstrap node(s) were available.",
					self.bootstrap_nodes.len()
				);
			} else {
				debug!("No bootstrap nodes configured. Not connecting to any nodes.");
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

	fn load_my_actor_nodes(&self, c: &db::Connection) -> Vec<(IdType, IdType, String, Keypair)> {
		let result = match c.fetch_my_identities() {
			Ok(r) => r,
			Err(e) => {
				error!("Unable to fetch my identities: {}", e);
				return Vec::new();
			}
		};

		result
			.into_iter()
			.map(|(_, actor_id, first_object, actor_type, keypair)| {
				(actor_id, first_object, actor_type, keypair)
			})
			.collect()
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

		let (connection, fingers) = self
			.base
			.find_nearest_contacts(&request.node_id, None)
			.await;
		let mut response = FindActorResponse {
			contacts: FindNodeResponse {
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

	pub(super) async fn process_request(
		self: &Arc<Self>, connection: &mut sstp::Connection, message_type: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		match message_type {
			OVERLAY_MESSAGE_TYPE_FIND_ACTOR_REQUEST =>
				self.process_find_actor_request(buffer).await,
			OVERLAY_MESSAGE_TYPE_STORE_ACTOR_REQUEST =>
				self.process_store_actor_request(connection.their_node_info(), buffer)
					.await,
			OVERLAY_MESSAGE_TYPE_RELAY_REQUEST =>
				self.process_relay_request(connection, buffer).await,
			other_id => {
				error!(
					"Unknown message type ID received from {}: {}",
					connection.peer_address(),
					other_id
				);
				None
			}
		}
	}

	pub(super) async fn process_actor_request(
		&self, connection: &mut Connection, mutex: &Arc<Mutex<Box<Connection>>>, actor_id: &IdType,
		message_type: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		let actor_node = {
			let actor_nodes = self.base.interface.actor_nodes.lock().await;
			match actor_nodes.get(actor_id) {
				None => return None,
				Some(n) => n.clone(),
			}
		};

		actor_node
			.process_request(connection, mutex, message_type, buffer)
			.await
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

	/// Processes the relay request
	async fn process_relay_request(
		&self, _connection: &mut Connection, buffer: &[u8],
	) -> Option<Vec<u8>> {
		let request: RelayRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				warn!("Malformed relay request: {}", e);
				return None;
			}
			Ok(r) => r,
		};

		if let Some((_contact_info, _connection_opt)) =
			self.base.find_finger_or_connection(&request.target).await
		{
			// TODO: Implement
		}
		None
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

	/// Just like `store_actor`, but starts searching from the given fingers.
	pub async fn store_actor_at_contacts(
		&self, actor_id: &IdType, duplicates: usize, actor_info: &ActorInfo,
		contacts: &[(IdType, ContactOption)],
	) -> usize {
		let mut store_count = 0;
		for (node_id, contact_option) in contacts {
			if self
				.exchange_store_actor_at(
					&node_id,
					&contact_option,
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
			}
		}
		store_count
	}
}

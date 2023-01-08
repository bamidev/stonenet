use super::{
	actor::*,
	actor_store::*,
	bincode,
	KADEMLIA_K,
	message::*,
	socket::UdpSocket,
	sstp::*
};

use crate::{
	common::*,
	config::Config,
	db::Database,
	identity::*,
	net::*
};

use std::{
	collections::HashMap,
	io,
	net::SocketAddr,
	str::FromStr,
	sync::{
		Arc,
		atomic::*,
		Mutex as StdMutex
	}
};

use async_trait::async_trait;
use futures::future::join_all;
use log::*;
use tokio::{
	self,
	time::sleep
};


// Messages for the overlay network:
pub const OVERLAY_MESSAGE_TYPE_ID_FIND_ACTOR_REQUEST: u8 = 4;
pub const OVERLAY_MESSAGE_TYPE_ID_FIND_ACTOR_RESPONSE: u8 = 5;
pub const OVERLAY_MESSAGE_TYPE_ID_STORE_ACTOR_REQUEST: u8 = 6;
pub const OVERLAY_MESSAGE_TYPE_ID_STORE_ACTOR_RESPONSE: u8 = 7;


pub struct FindActorIter<'a> (FindValueIter<'a, OverlayInterface>);

pub struct OverlayNode {
	base: Arc<Node<OverlayInterface>>,
	actor_nodes: HashMap<IdType, Arc<Node<ActorInterface>>>,
	db: Database,
	bootstrap_nodes: Vec<SocketAddr>
}

struct OverlayInterface {
	socket: SstpSocket<UdpSocket>,
	max_idle_time: usize,
	last_message_time: StdMutex<SystemTime>
}


#[async_trait]
impl NodeInterface for OverlayInterface {

	async fn connect(&self,
		target: &SocketAddr,
		node_id: Option<&IdType>
	) -> io::Result<Connection<UdpSocket>> {
		self.socket.connect(target.clone(), node_id).await
	}
	
	async fn exchange(&self,
		connection: &mut Connection<UdpSocket>,
		message_type_id: u8,
		buffer: &[u8]
	) -> io::Result<Vec<u8>> {
		*self.last_message_time.lock().unwrap() = SystemTime::now();
		
		// Send request
		let mut real_buffer = Vec::with_capacity(1 + buffer.len());
		real_buffer.push(message_type_id);
		real_buffer.extend(buffer);
		connection.send(
			&real_buffer
		).await?;

		// Receive response
		let mut response = connection.receive().await?;
		if response[0] != (message_type_id + 1) {
			return Err(sstp::Error::InvalidResponseMessageType((
				response[0],
				message_type_id + 1
			)).into());
		}
		response.remove(0);
		return Ok(response)
	}

	async fn respond(&self,
		message_type_id: u8,
		buffer: &[u8]
	) -> Vec<u8> {
		*self.last_message_time.lock().unwrap() = SystemTime::now();

		let mut real_buffer = Vec::with_capacity(1 + buffer.len());
		real_buffer.push(message_type_id);
		real_buffer.extend(buffer);
		real_buffer
	}
}

#[async_trait]
impl<'a> AsyncIterator for FindActorIter<'a> {
	type Item = Box<(PublicKey, Vec<NodeContactInfo>)>;

	async fn next(&mut self) -> Option<Self::Item> {
		let result = self.0.next().await;
		result.map(|p| unsafe {
			Box::from_raw(p.into_inner() as *mut (PublicKey, Vec<NodeContactInfo>))
		})
	}
}

impl OverlayNode {

	pub async fn bind(
		node_id: IdType,
		addr: &SocketAddr,
		db: Database,
		config: &Config
	) -> io::Result<Self> {
		let mut bootstrap_nodes = Vec::<SocketAddr>::with_capacity(
			config.bootstrap_nodes.len()
		);
		for address_string in &config.bootstrap_nodes {
			match SocketAddr::from_str(address_string) {
				Err(e) => error!("Unable to parse bootstrap node {}: {}.", address_string, e),
				Ok(s) => bootstrap_nodes.push(s)
			}
		}

		let keypair = Keypair::generate();
		let socket = SstpSocket::bind(addr, keypair).await?;
		Ok(Self {
			base: Arc::new(Node::new(node_id.clone(), OverlayInterface {
				socket,
				last_message_time: StdMutex::new(SystemTime::now()),
				max_idle_time: config.udp_max_idle_time
			})),
			actor_nodes: HashMap::new(),
			db,
			bootstrap_nodes
		})
	}

	/// Tries to connect to the actor network of the given actor ID, but in
	/// 'lurking' mode. Meaning, the nodes of the network won't considuer you
	/// as part of it.
	pub async fn lurk_actor_network(&self,
		actor_id: &IdType
	) -> Option<ActorNode> {
		let mut iter = self.find_actor_iter(actor_id, 100, true).await;
		while let Some(result) = iter.next().await {
			//let public_key = result.0;
			for node in result.1 {
				let actor_node = ActorNode::new_lurker(
					self.base.interface.socket.clone(),
					actor_id.clone()
				);
				// Ping node on actor network to see if they are still online
				// and following the actor.
				if let Ok(_) = actor_node.base.request_ping(&node.address).await {
					return Some(actor_node);
				}
			}
		}
		None
	}

	pub async fn find_actor(&self,
		id: &IdType,
		hop_limit: usize,
		narrow_down: bool
	) -> Option<Box<(PublicKey, Vec<NodeContactInfo>)>> {
		self.find_actor_iter(id, hop_limit, narrow_down).await.next().await
	}

	/// Tries to find the 
	pub async fn find_actor_iter(&self,
		id: &IdType,
		hop_limit: usize,
		narrow_down: bool
	) -> FindActorIter {
		fn verify_pubkey(id: &IdType, peer: &NodeContactInfo, data: &[u8]) -> Option<AtomicPtr<()>> {
			match bincode::deserialize::<FindActorResult>(&data) {
				Err(e) => {
					warn!("Received invalid actor public key from node: {}", e);
					None
				},
				Ok(result) => {
					if &result.public_key.generate_address() != id {
						return None;
					}
					let mut peers: Vec<NodeContactInfo> = result.peers;
					
					if result.i_am_available {
						peers.insert(0, peer.clone());
					}
					let value: Box<(PublicKey, Vec<NodeContactInfo>)> = Box::new((result.public_key, peers));
					Some(AtomicPtr::new(Box::into_raw(value) as _))
				}
			}
		}

		let fingers = self.base.find_nearest_fingers(id).await;
		let iter = self.base.find_value_from_fingers_iter(
			id,
			OVERLAY_MESSAGE_TYPE_ID_FIND_ACTOR_REQUEST,
			&fingers,
			hop_limit, 
			narrow_down,
			verify_pubkey
		);
		FindActorIter (iter)
	}

	/// Joins the network by trying to connect to old peers. If that doesn't
	/// work, try to connect to bootstrap nodes.
	pub async fn join_network(&self, stop_flag: Arc<AtomicBool>) -> bool {
		// TODO: Find remembered nodes from the database and try them out

		let mut i = 0;
		// TODO: Contact all bootstrap nodes at the same time
		while i < self.bootstrap_nodes.len() && !stop_flag.load(Ordering::Relaxed) {
			let bootstrap_node = &self.bootstrap_nodes[i];
			match self.join_network_starting_at(bootstrap_node).await {
				Err(e) => error!("Bootstrap node {} didn't work: {}", bootstrap_node, e),
				Ok(()) => return true
			}

			i += 1;
		}
		if i == self.bootstrap_nodes.len() {
			error!("None of the {} bootstrap node(s) were available.", self.bootstrap_nodes.len());
		}

		false
	}

	/// Joins the network via a peer. If pinging that peer fails, returns an
	/// I/O error.
	pub async fn join_network_starting_at(&self, node_address: &SocketAddr) -> io::Result<()> {
		// FIXME: It would save a few packets if we would just take the node_id from
		// the first 'FIND_NODE' request. But that would require some
		// restructuring of the code base.
		let node_id = self.base.test_presence(node_address).await?;
		let first_contact = NodeContactInfo {
			address: node_address.clone(),
			node_id
		};
		
		// Keep finding new fingers until we have not been able to get any
		// closer to our own ID.
		//let current_distance = distance(&first_contact.node_id, &self.base.node_id);
		let fingers = vec![first_contact; 1];
		let neighbours = self.base.find_node_from_fingers(
			&self.base.node_id,
			&*fingers,
			KADEMLIA_K as _,
			100,	// TODO: Make configuration variable
		).await;
		
		// Add our neighbours to our buckets
		let futs = neighbours.iter().map(|n| async move {
			match self.base.connect(&n.address, Some(&n.node_id)).await {
				Err(e) => warn!(
					"Connecting to neighbour {} failed: {}",
					&n.address,
					e
				),
				Ok(_) => {
					self.base.remember_node_silently(n.clone()).await;
				}
			}
		});
		join_all(futs).await;
		Ok(())
	}

	async fn handle_connection(&self,
		connection: &mut Connection<UdpSocket>
	) -> io::Result<()> {
		let message = connection.receive().await?;
		let result = self.process_request_message(
			connection.target(),
			connection.their_node_id(),
			&message
		).await;
		match result {
			None => Ok(()),
			Some(response) => {
				connection.send(&response).await
			}
		}
	}

	async fn keep_hole_open(self: Arc<Self>, stop_flag: Arc<AtomicBool>) {
		while !stop_flag.load(Ordering::Relaxed) {
			sleep(Duration::from_secs(1)).await;

			let is_inactive = {
				let mut last_message_time = self.base.interface.last_message_time.lock().unwrap();
				let is_inactive = SystemTime::now()
				                    .duration_since(*last_message_time).unwrap() >
				                Duration::from_secs(
				                    self.base.interface.max_idle_time as _
				                );
				if is_inactive {
					*last_message_time = SystemTime::now();
				}
				is_inactive
			};
			if is_inactive {
				// Ping a peer, one successful ping will be enough
				let mut peer_iter = self.base.iter_all_fingers();
				while !stop_flag.load(Ordering::Relaxed) {
					match peer_iter.next().await {
						Some(peer) => {
							if self.base.ping(&peer.address).await.is_ok() {
								break
							}
						}
						// If not a single peer was available, reconnect to the
						// network again.
						None => {
							warn!("Lost connection to all nodes.");
							if !self.join_network(stop_flag.clone()).await {
								error!("Attempt at rejoining the network failed.")
							}
							else {
								info!("Rejoined the network");
							}
							break;
						}
					}
				}
			}
			
		}
	}

	pub fn node_id(&self) -> &IdType {
		&self.base.node_id
	}

	async fn process_request_message(&self,
		address: &SocketAddr,
		sender_node_id: &IdType,
		buffer: &[u8]
	) -> Option<Vec<u8>> {
		let mut message_type_id = buffer[0];
		let response = if message_type_id >= 0x80 {
			message_type_id ^= 0x80;
			let actor_id: IdType = bincode::deserialize(&buffer[1..33]).unwrap();
			let actor_node = match self.actor_nodes.get(&actor_id) {
				None => return None, // Don't respond to requests for networks we are not connected to.
				Some(n) => &n.interface,
			};

			let r = self.process_request(
				address,
				sender_node_id,
				message_type_id,
				&buffer[33..]
			).await;
	
			match r {
				None => None,
				Some(x) => Some(actor_node.respond(
					message_type_id + 1,
					&x
				).await)
			}
		}
		else {
			let r = self.process_request(
				address,
				sender_node_id,
				message_type_id,
				&buffer[1..]
			).await;
	
			match r {
				None => None,
				Some(x) => Some(self.base.interface.respond(
					message_type_id + 1,
					&x
				).await)
			}
		};

		// Let us remember the node that send the message, but lets not wait
		// for the whole process to finish before we return the response.
		let address_copy = address.clone();
		let node = self.base.clone();
		let sender_node_id2 = sender_node_id.clone();
		tokio::spawn(async move {
			node.remember_node(NodeContactInfo {
				address: address_copy,
				node_id: sender_node_id2
			}).await;
		});

		response
	}


	async fn process_find_actor_request(&self, buffer: &[u8]) -> Option<Vec<u8>> {
		let request: FindActorRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed find actor request: {}", e);
				return None;
			}
			Ok(r) => r
		};
		let nearest_nodes = self.base.find_nearest_fingers(&request.node_id).await;
		let mut response = FindActorResponse {
			fingers: nearest_nodes.clone(),
			result: None
		};

		// Load the public key and available nodes from our cache
		{
			let store = NODE_ACTOR_STORE.lock().await;
			match store.find(&request.node_id) {
				None => {},
				Some(entry) => {
					response.result = Some(FindActorResult {
						public_key: entry.public_key.clone(),
						i_am_available: false,
						peers: entry.available_nodes.clone().into()
					});
				}
			}
		}

		// Load the public key and available nodes from our own follow list
		{
			let store = FOLLOW_ACTOR_STORE.lock().await;
			if response.result.is_none() {
				response.result = store.get(&request.node_id).map(|public_key| {
					FindActorResult {
						public_key: public_key.clone(),
						i_am_available: true,
						peers: Vec::new()
					}
				});
			}
			else {
				if store.contains_key(&request.node_id) {
					let r = response.result.as_mut().unwrap();
					r.i_am_available = true;
				}
			}
		}
		
		// Deserialize response
		Some(bincode::serialize(&response).unwrap())
	}

	async fn process_find_node_request(&self, buffer: &[u8]) -> Option<Vec<u8>> {
		let request: FindNodeRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed find node request: {}", e);
				return None;
			}
			Ok(r) => r
		};

		// Collect all fingers we have
		let fingers = self.base.find_nearest_fingers(&request.node_id).await;
		let response = FindNodeResponse {
			fingers,
			follows: Vec::new()
		};
		Some(bincode::serialize(&response).unwrap())
	}

	async fn process_ping_request(&self, address: &SocketAddr) -> Option<Vec<u8>> {
		debug!("Received ping request from {}", address); Some(Vec::new())
	}

	async fn process_request(&self,
		address: &SocketAddr,
		sender_node_id: &IdType,
		message_type_id: u8,
		buffer: &[u8]
	) -> Option<Vec<u8>> {
		match message_type_id {
			NETWORK_MESSAGE_TYPE_ID_PING_REQUEST => self.process_ping_request(address).await,
			NETWORK_MESSAGE_TYPE_ID_FIND_NODE_REQUEST => self.process_find_node_request(buffer).await,
			OVERLAY_MESSAGE_TYPE_ID_FIND_ACTOR_REQUEST => self.process_find_actor_request(buffer).await,
			OVERLAY_MESSAGE_TYPE_ID_STORE_ACTOR_REQUEST => self.process_store_actor_request(sender_node_id, address, buffer).await,
			other_id => {
				error!("Unknown message type ID received from {}: {}", address, other_id);
				None
			}
		}
	}

	async fn process_actornet_request(&self,
		_sender_node_id: &IdType,
		_address: &SocketAddr,
		_message_type_id: u8,
		_exchange_id: u32,
		_buffer: &[u8]
	) -> Option<Vec<u8>> {
		// TODO: Implement, 
		None
	}

	async fn process_store_actor_request(&self,
		sender_node_id: &IdType,
		address: &SocketAddr,
		buffer: &[u8]
	) -> Option<Vec<u8>> {
		let request: StoreActorRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed store actor request: {}", e);
				return None;
			}
			Ok(r) => r
		};

		// Check if actor_id is indeed the hash of the public_key.
		if request.public_key.generate_address() != request.actor_id {
			warn!("Actor store request invalid: public key doesn't match actor ID.");
			return None;
		}

		// Add actor to store
		let contact_info = NodeContactInfo {
			address: address.clone(),
			node_id: sender_node_id.clone()
		};
		let mut node_store = NODE_ACTOR_STORE.lock().await;
		match node_store.find_mut(&request.actor_id) {
			None => {
				node_store.add(
					request.actor_id.clone(),
					ActorStoreEntry::new_with_contact(
						request.public_key,
						contact_info
					)
				);
			},
			Some(entry) => {
				entry.add_available_node(contact_info);
			}
		}

		Some(Vec::new())
	}

	/// In the paper, this is described as the 'FIND_VALUE' RPC.
	pub async fn request_find_actor(&self,
		target: &SocketAddr,
		node_id: &IdType
	) -> io::Result<FindActorResponse> {
		debug!("Find actor request to {}", target);
		let response = self.base.request_find_x(
			target,
			node_id,
			OVERLAY_MESSAGE_TYPE_ID_FIND_ACTOR_REQUEST
		).await?;
		println!("request_find_actor {:?}", &response);
		bincode::deserialize(&response).map_err(|e| io::Error::new(
			io::ErrorKind::InvalidData,
			e
		))
	}


	pub async fn request_store_actor(&self,
		target: &SocketAddr,
		actor_id: IdType,
		public_key: PublicKey
	) -> io::Result<()> {
		let request = StoreActorRequest {
			actor_id,
			public_key
		};
		self.base.exchange(
			target,
			OVERLAY_MESSAGE_TYPE_ID_STORE_ACTOR_REQUEST,
			&bincode::serialize(&request).unwrap()
		).await?;
		Ok(())
	}

	/// Runs a continual loop that can be stopped with `stop()`, that processes
	/// al messages received on the UDP socket.
	pub async fn serve(self: Arc<Self>, stop_flag: Arc<AtomicBool>) {
		if self.bootstrap_nodes.len() > 0 {
			tokio::spawn(self.clone().keep_hole_open(stop_flag.clone()));
		}
		let this = self.clone();
		self.base.interface.socket.listen(
			stop_flag,
			move |mut connection| {
				let this2 = this.clone();
				tokio::task::spawn(async move {
					match this2.handle_connection(&mut connection).await {
						Ok(()) => {},
						Err(e) => error!("Node io error: {}", e)
					}
				});
			}
		).serve("").await
	}

	pub async fn store_actor(&self,
		actor_id: &IdType,
		duplicates: usize,
		public_key: &PublicKey
	) -> bool {
		let contacts = self.base.find_node(
			&actor_id,
			duplicates*2,
			100
		).await;
		
		let mut store_count = 0;
		for contact in contacts {
			if self.request_store_actor(
				&contact.address,
				actor_id.clone(),
				public_key.clone()
			).await.is_ok() {
				store_count += 1;
			}
		}
		store_count > 0
	}

	/// Publishes the identities that are stored in the DB
	pub async fn publish_my_identities(&self) {
		let c = match self.db.connect() {
			Ok(c) => c,
			Err(e) => {
				error!("Unable to connect to database: {}", e);
				return;
			}
		};
		let identities = match c.fetch_my_identities() {
			Err(e) => {
				error!("Unable to fetch my identities: {}", e);
				return;
			}
			Ok(i) => i
		};

		for (label, node_id, keypair) in identities {

			let public_key = keypair.public();
			let success = self.store_actor(
				&node_id,
				KADEMLIA_K as _,
				&public_key
			).await;
			if !success {
				warn!("Unable to store identity {} in network.", label);
			}
		}
	}
}

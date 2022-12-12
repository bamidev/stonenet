use super::{
	actor::*,
	actor_store::*,
	distance,
	exchange_manager::ExchangeManager,
	KADEMLIA_K,
	message::*,
};

use crate::{
	common::*,
	config::Config,
	db::*,
	identity::*,
	limited_store::LimitedVec,
	net::*
};

use std::{
	collections::HashMap,
	io,
	net::SocketAddr,
	str::FromStr,
	sync::{
		Arc,
		atomic::{AtomicBool, Ordering},
		Mutex as StdMutex
	}
};

use async_trait::async_trait;
use futures::future::join_all;
use log::*;
use tokio::{
	self,
	net::ToSocketAddrs,
	time::sleep
};


// Messages for the overlay network:

pub const OVERLAY_MESSAGE_TYPE_ID_FIND_ACTOR_REQUEST: u8 = 4;
pub const OVERLAY_MESSAGE_TYPE_ID_FIND_ACTOR_RESPONSE: u8 = 5;
pub const OVERLAY_MESSAGE_TYPE_ID_STORE_ACTOR_REQUEST: u8 = 6;
pub const OVERLAY_MESSAGE_TYPE_ID_STORE_ACTOR_RESPONSE: u8 = 7;


pub struct OverlayNode {
	base: Arc<Node<OverlayInterface>>,
	exch: Arc<ExchangeManager>,
	actor_nodes: HashMap<IdType, Arc<Node<ActorInterface>>>,
	db: Arc<Database>,
	bootstrap_nodes: Vec<SocketAddr>
}

struct OverlayInterface {
	node_id: IdType,
	exch: Arc<ExchangeManager>,
	max_idle_time: usize,
	last_request_time: StdMutex<SystemTime>
}


#[async_trait]
impl NodeInterface for OverlayInterface {
	
	async fn request(&self,
		target: &SocketAddr,
		message_type_id: u8,
		buffer: &[u8]
	) -> io::Result<(IdType, Vec<u8>)> {
		*self.last_request_time.lock().unwrap() = SystemTime::now();
		self.exch.request(
			&self.node_id,
			target,
			message_type_id,
			buffer,
			Some(NODE_COMMUNICATION_TIMEOUT)
		).await
	}

	async fn respond(&self,
		target: &SocketAddr,
		message_type_id: u8,
		exchange_id: u32,
		buffer: &[u8]
	) -> io::Result<()> {
		self.exch.send_message(
			&self.node_id,
			target,
			message_type_id,
			exchange_id,
			buffer
		).await
	}
}

impl OverlayNode {

	pub async fn bind<A: ToSocketAddrs>(
		node_id: IdType,
		addr: A,
		db: Arc<Database>,
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

		let exchange_manager = Arc::new(ExchangeManager::bind(addr).await?);
		Ok(Self {
			base: Arc::new(Node::new(node_id.clone(), OverlayInterface {
				exch: exchange_manager.clone(),
				node_id: node_id,
				last_request_time: StdMutex::new(SystemTime::now()),
				max_idle_time: config.udp_max_idle_time
			})),
			exch: exchange_manager,
			actor_nodes: HashMap::new(),
			db,
			bootstrap_nodes
		})
	}

	/// Returns actor info if it found some
	pub async fn find_actor(&self, id: &IdType) -> Option<FindActorResult> {
		// Keep finding new fingers until we have not been able to get any
		// closer to our own ID.
		let mut fingers = self.base.find_nearest_fingers(id).await;
		let mut current_distance = distance(&self.base.node_id, id);
		let mut i = 0;
		loop {
			fingers = match self.find_actor_from_fingers(&self.base.node_id, &*fingers).await {
				Err(f) => f,
				Ok(result) => return Some(result)
			};
			// Our own node might be in their k-bucket already, so ignore that.
			// Also, check if all new fingers are actually closer, a malicious
			// node might put us off track.
			//fingers.retain(|f| {
			//	f.node_id != self.base.node_id //&&
			//	//distance(&f.node_id, id) < current_distance
			//});
			if fingers.len() == 0 { break; }
			if i >= 64 {
				warn!("Loop detected!");
				return None;
			}
			// TODO: Maybe get shortest distance of all fingers? Or maybe not necessary.
			current_distance = distance(&fingers[0].node_id, id);

			i += 1;
		}

		// If we reached this point, we have not found the actor before we have
		// exhausted our resources.
		None
	}

	pub async fn find_actor_from_fingers(&self,
		id: &IdType,
		fingers: &[NodeContactInfo]
	) -> Result<FindActorResult, Vec<NodeContactInfo>> {
		for finger in fingers {
			let result = match self.request_find_actor(&finger.address, &id).await {
				Err(e) => {},
				Ok(response) => return response.result
			};
		}

		Err(Vec::new())
	}

	/// Joins the network by trying to connect to old peers. If that doesn't
	/// work, try to connect to bootstrap nodes.
	pub async fn join_network(&self, stop_flag: Arc<AtomicBool>) -> bool {
		// TODO: Find remembered nodes from the database and try them out

		let mut i = 0;
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
		let (_, node_id) = self.base.ping(node_address).await?;
		let first_contact = NodeContactInfo {
			address: node_address.clone(),
			node_id
		};
		
		// Keep finding new fingers until we have not been able to get any
		// closer to our own ID.
		let mut current_distance = distance(&first_contact.node_id, &self.base.node_id);
		let mut fingers = vec![first_contact; 1];
		let mut i = 0;
		loop {
			fingers = self.base.find_node_from_fingers(&self.base.node_id, &*fingers).await;
			// Our own node might be in their k-bucket already, so ignore that.
			// Also, check if all new fingers are actually closer, a malicious
			// node might put us off track.
			fingers.retain(|f| {
				f.node_id != self.base.node_id //&&
				//distance(&f.node_id, &self.node_id) < current_distance
			});
			if fingers.len() == 0 { break; }
			if i >= 64 {
				return Err(io::ErrorKind::NotFound.into());
			}
			// TODO: Maybe get shortest distance of all fingers? Or maybe not necessary.
			current_distance = distance(&fingers[0].node_id, &self.base.node_id);

			i += 1;
		}
		// We are now 'connected', because our k-buckets are filled with
		// usefull nodes, and they have us in their own k-buckets.
		Ok(())
	}

	async fn keep_hole_open(self: Arc<Self>, stop_flag: Arc<AtomicBool>) {
		while !stop_flag.load(Ordering::Relaxed) {
			sleep(Duration::from_secs(1)).await;

			let is_inactive = {
				let mut last_request_time = self.base.interface.last_request_time.lock().unwrap();
				let is_inactive = SystemTime::now()
				                    .duration_since(*last_request_time).unwrap() >
				                Duration::from_secs(
				                    self.base.interface.max_idle_time as _
				                );
				if is_inactive {
					*last_request_time = SystemTime::now();
				}
				is_inactive
			};
			if is_inactive {
				// Ping a peer, one successful ping will be enough
				let mut peer_iter = self.base.iter_all_fingers();
				while !stop_flag.load(Ordering::Relaxed) {
					match peer_iter.next().await {
						Some(peer) => {
							match self.base.ping(&peer.address).await {
								Err(e) => {},
								Ok(_) => break
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

	async fn process_message(&self, address: SocketAddr, buffer: Vec<u8>) {
		if buffer.len() < 37 {
			error!(
				"Packet received from {} smaller than header: only {} bytes.",
				address, buffer.len()
			);
			return;
		}
		let mut message_type_id = buffer[0];
		let exchange_id = u32::from_le_bytes(buffer[1..5].try_into().unwrap());
		let sender_node_id: IdType = bincode::deserialize(&buffer[5..37]).unwrap();

		let mut sub_buffer = &buffer[37..];
		let node_interface: &(dyn NodeInterface + Sync) = if message_type_id >= 0x80 {
			message_type_id ^= 0x80;
			let actor_id: IdType = bincode::deserialize(&buffer[37..69]).unwrap();
			let actor_node = match self.actor_nodes.get(&actor_id) {
				None => return, // Don't respond to requests for networks we are not connected to.
				Some(n) => &n.interface,
			};
			sub_buffer = &buffer[69..];
			actor_node
		}
		else {
			&self.base.interface
		};

		if message_type_id % 2 == 0 {
			match self.process_request(
				&sender_node_id,
				&address,
				message_type_id,
				exchange_id,
				&sub_buffer
			).await {
				None => {},
				Some(buffer) => {
					match node_interface.respond(
						&address,
						message_type_id + 1,
						exchange_id,
						&buffer
					).await {
						Err(e) => error!("Unable to respond back to request {}", exchange_id),
						Ok(()) => {}
					}
				}
			}
		}
		else {
			self.process_response(&sender_node_id, message_type_id, exchange_id, &sub_buffer).await;
		}

		// Let us remember the node that send the message, but lets not wait
		// for the whole process to finish before we return the response.
		// Except for ping request, so it won't cause a never ending ping chain.
		if message_type_id > NETWORK_MESSAGE_TYPE_ID_PING_REQUEST + 1 {
			let address_copy = address.clone();
			let node = self.base.clone();
			tokio::task::spawn(async move {
				node.remember_node(NodeContactInfo {
					address: address_copy,
					node_id: sender_node_id
				}).await;
			});
		}
	}


	async fn process_find_actor_request(&self, buffer: &[u8]) -> Option<Vec<u8>> {
		let request: FindActorRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed find node request.");
				return None;
			}
			Ok(r) => r
		};

		// If we follow this actor, reply with us as a peer node, and possibly
		// our other contacts.
		let mut response: Option<FindActorResponse> = FOLLOW_ACTOR_STORE
			.lock().await
			.get(&request.node_id)
			.map(|public_key| {
				// TODO: Add other known peers of the subnetwork to this list:
				let other_peers = Vec::new();
				FindActorResponse {
					result: Ok(FindActorResult {
						public_key: public_key.clone(),
						i_am_available: true,
						peers: other_peers
					})
				}
			});
		
		// If we don't follow this actor, check if we have stored in our node's
		// DHT store.
		if response.is_none() {
			response = NODE_ACTOR_STORE.lock().await
				.find(&request.node_id)
				.map(|entry| {
					FindActorResponse {
						result: Ok(FindActorResult {
							public_key: entry.public_key.clone(),
							i_am_available: false,
							peers: entry.available_nodes.clone().into()
						})
					}
				}
			);
		}

		match response {
			// Otherwise, just respond with the nearest node/finger
			None => {
				let nearest_nodes = self.base.find_nearest_fingers(&request.node_id).await;
				Some(bincode::serialize(&FindActorResponse {
					result: Err(nearest_nodes)
				}).unwrap())
			},
			Some(r) => Some(bincode::serialize(&r).unwrap())
		}
	}

	async fn process_find_node_request(&self, buffer: &[u8]) -> Option<Vec<u8>> {
		let request: FindNodeRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed find node request.");
				return None;
			}
			Ok(r) => r
		};

		// Collect all fingers we have
		let fingers = self.base.find_nearest_fingers(&request.node_id).await;
		let response = FindNodeResponse {
			fingers,
			i_am_stable: false,
			follows: Vec::new()
		};
		Some(bincode::serialize(&response).unwrap())
	}

	async fn process_ping_request(&self, address: &SocketAddr) -> Option<Vec<u8>> {
		debug!("Received ping request from {}", address); Some(Vec::new())
	}

	async fn process_response(&self, sender_node_id: &IdType, message_type_id: u8, exchange_id: u32, buffer: &[u8]) {
		let success = self.exch.trigger_response(sender_node_id, exchange_id, buffer).await;
		if !success {
			error!("Unable to trigger response with exchange ID {}.", exchange_id)
		}
	}

	async fn process_request(&self,
		sender_node_id: &IdType,
		address: &SocketAddr,
		message_type_id: u8,
		exchange_id: u32,
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
		sender_node_id: &IdType,
		address: &SocketAddr,
		message_type_id: u8,
		exchange_id: u32,
		buffer: &[u8]
	) -> Option<Vec<u8>> {
		// TODO: Implement, 
		None
	}

	async fn process_store_actor_request(&self,
		sender_node_id: &IdType,
		address: &SocketAddr,
		buffer:&[u8]
	) -> Option<Vec<u8>> {
		let request: StoreActorRequest = match bincode::deserialize(buffer) {
			Err(e) => {
				error!("Malformed store actor request: {}", e);
				return None;
			}
			Ok(r) => r
		};

		// TODO: Check if actor_id is indeed the hash of the public_key.

		let mut node_store = NODE_ACTOR_STORE.lock().await;
		match node_store.find_mut(&request.actor_id) {
			None => {
				let mut new_list = LimitedVec::new(10); // TODO: Use a constant for array size
				new_list.push_front(NodeContactInfo {
					address: address.clone(),
					node_id: sender_node_id.clone()
				});
				node_store.add(request.actor_id.clone(), ActorStoreEntry {
					public_key: request.public_key.clone(),
					i_am_available: false,
					available_nodes: new_list
				});
			},
			Some(entry) => {
				entry.available_nodes.push_front(NodeContactInfo {
					address: address.clone(),
					node_id: sender_node_id.clone()
				});
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
		bincode::deserialize(&response).map_err(|e| io::Error::new(
			io::ErrorKind::InvalidData,
			e
		))
	}


	pub async fn request_store_actor(&self,
		target: &SocketAddr,
		actor_id: IdType,
		public_key: PublicKey,
		nodes: Vec<NodeContactInfo>
	) -> io::Result<()> {
		let request = StoreActorRequest {
			actor_id,
			public_key,
			nodes
		};
		self.base.request(
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
		self.exch.clone().serve(stop_flag, move |address, buffer| {
			let this = self.clone();
			tokio::task::spawn(async move {
				this.process_message(address, buffer).await;
			});
		}).await;
	}

	pub async fn store_actor(&self,
		actor_id: &IdType,
		public_key: &PublicKey,
		nodes: Vec<NodeContactInfo>
	) -> bool {
		let contacts = self.base.find_node_contacts(&actor_id, KADEMLIA_K as _).await;
		if contacts.len() == 0 {
			let mut store = NODE_ACTOR_STORE.lock().await;
			store.store_personal(actor_id, public_key);
			false
		}
		else {
			let futs = contacts.iter().map(|c| async {
				match self.request_store_actor(
					&c.address,
					actor_id.clone(),
					public_key.clone(),
					nodes.clone()
				).await {
					Err(_) => false,
					Ok(()) => true
				}
			});
			let mut results = join_all(futs).await;
			results.retain(|r| *r);
			if results.len() == 0 {
				let mut store = NODE_ACTOR_STORE.lock().await;
				store.store_personal(actor_id, public_key);
				false
			}
			else { true }
		}
	}

	/// Publishes the identities that are stored in the DB
	pub async fn publish_identities(&self) {
		let identities = match self.db.fetch_my_identities() {
			Err(e) => {
				error!("Unable to fetch my identities: {}", e);
				return;
			}
			Ok(i) => i
		};

		for (label, address, keypair) in identities {
			let public_key = keypair.public();
			if !self.store_actor(&address, &public_key, Vec::new()).await {
				error!("Unable to store personal identity {} = {}.", &label, &address);
			}
		}
	}
}

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use tokio::{spawn, time::sleep};

use super::{connection_manager::*, message::*, node::*, overlay::OverlayNode, sstp, *};
use crate::{
	common::*,
	db::{self, Database},
	identity::*,
	model::*,
};


pub const ACTOR_MESSAGE_TYPE_HEAD_REQUEST: u8 = 64;
//pub const ACTOR_MESSAGE_TYPE_HEAD_RESPONSE: u8 = 65;
pub const ACTOR_MESSAGE_TYPE_GET_PROFILE_REQUEST: u8 = 66;
//pub const ACTOR_MESSAGE_TYPE_GET_PROFILE_RESPONSE: u8 = 67;
pub const ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_REQUEST: u8 = 70;
pub const ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_RESPONSE: u8 = 71;


pub struct ActorNode {
	pub(super) base: Arc<Node<ActorInterface>>,
	downloading_objects: Mutex<Vec<IdType>>,
	is_synchonizing: Arc<AtomicBool>,
}

pub struct ActorInterface {
	db: Database,
	actor_id: IdType,
	actor_info: ActorInfo,
	is_lurker: bool,
	pub(super) connection_manager: Arc<ConnectionManager>,
}

impl ActorInterface {
	async fn find_block(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_block(&self.actor_id, id)
		})?;
		if let Some(data) = result {
			let response = FindBlockResult { data };
			Ok(Some(bincode::serialize(&response).unwrap()))
		} else {
			Ok(None)
		}
	}

	async fn find_file(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_file(id)
		})?;
		Ok(result.map(|file| bincode::serialize(&file).unwrap()))
	}

	async fn find_object(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_object(&self.actor_id, id)
		})?;
		Ok(result.map(|(object, _)| bincode::serialize(&FindObjectResult { object }).unwrap()))
	}

	async fn find_next_object(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let mut c = self.db.connect()?;
			c.fetch_next_object(&self.actor_id, id)
		})?;
		Ok(result.map(|(hash, object, _)| {
			bincode::serialize(&FindNextObjectResult { hash, object }).unwrap()
		}))
	}
}

#[async_trait]
impl NodeInterface for ActorInterface {
	async fn exchange(
		&self, connection: &mut Connection, mut message_type: u8, buffer: &[u8],
	) -> sstp::Result<Vec<u8>> {
		message_type |= 0x80;

		let mut real_buffer = Vec::with_capacity(33 + buffer.len());
		real_buffer.push(message_type);
		real_buffer.extend(self.actor_id.as_bytes());
		real_buffer.extend(buffer);
		connection.send(&real_buffer).await?;

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

	async fn find_near_connection(&self, bit: u8) -> Option<NodeContactInfo> {
		self.connection_manager.find_near(bit).await.map(|r| r.0)
	}

	async fn find_value(&self, value_type: u8, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		const VALUE_TYPE_BLOCK: u8 = ValueType::Block as _;
		const VALUE_TYPE_FILE: u8 = ValueType::File as _;
		const VALUE_TYPE_OBJECT: u8 = ValueType::Object as _;
		const VALUE_TYPE_NEXT_OBJECT: u8 = ValueType::NextObject as _;
		match value_type {
			VALUE_TYPE_BLOCK => self.find_block(id).await,
			VALUE_TYPE_FILE => self.find_file(id).await,
			VALUE_TYPE_OBJECT => self.find_object(id).await,
			VALUE_TYPE_NEXT_OBJECT => self.find_next_object(id).await,
			other => {
				warn!("Invalid block type requested: {} for id {}", other, id);
				return Ok(None);
			}
		}
	}

	async fn send(
		&self, connection: &mut Connection, message_type: u8, buffer: &[u8],
	) -> sstp::Result<()> {
		let mut real_buffer = Vec::with_capacity(1 + buffer.len());
		real_buffer.push(message_type | 0x80);
		real_buffer.extend(buffer);

		// Send request
		connection.send(&real_buffer).await
	}

	async fn respond(
		&self, connection: &mut Connection, message_type: u8, buffer: &[u8],
	) -> sstp::Result<()> {
		self.send(connection, message_type, buffer).await
	}
}

impl ActorNode {
	pub fn actor_id(&self) -> &IdType { &self.base.interface.actor_id }

	/*async fn broadcast_value(
		self: Arc<Self>, responsibility_bit: Option<u8>, id: &IdType, value_type: ValueType,
		data: Arc<Vec<u8>>,
	) {
		let _i = 255;
		let mut iter = self.base.iter_all_fingers().await;
		// FIXME: Could be more effecient if iterating over one bucket at the time.
		loop {
			// Don't broadcast to above the responsibility bit in the binary tree
			let bucket_index = iter.bucket_index();
			if responsibility_bit.is_some() && bucket_index <= responsibility_bit {
				break;
			}

			if let Some(contact) = iter.next().await {
				let this = self.clone();
				let contact2 = contact.clone();
				let id2 = id.clone();
				let value_type2 = value_type.clone();
				let data2 = data.clone();
				tokio::spawn(async move {
					this.store_value_at(&contact2, &id2, value_type2, &*data2)
						.await;
				});
			} else {
				break;
			}
		}
	}*/

	/// Attempts to collect as much blocks of this file on the given connection.
	async fn collect_block(
		&self, connection: &mut Connection, block_id: &IdType,
	) -> db::Result<bool> {
		if let Some(result) = self
			.exchange_find_block_on_connection(connection, block_id)
			.await
		{
			if self.verify_block(block_id, &result.data) {
				self.store_block(block_id, &result.data)?;
			} else {
				return Ok(false);
			}
		}
		Ok(true)
	}

	/// Attempts to collect as much blocks of this file on the given connection.
	async fn collect_file(
		&self, connection: &mut Connection, file_id: &IdType,
	) -> db::Result<bool> {
		if let Some(result) = self
			.exchange_find_file_on_connection(connection, &file_id)
			.await
		{
			if self.verify_file(file_id, &result.file) {
				self.store_file(file_id, &result.file)?;

				for sequence in 0..result.file.blocks.len() {
					let block_id = &result.file.blocks[sequence];
					if !self.collect_block(connection, block_id).await? {
						return Ok(false);
					}
				}
			} else {
				return Ok(false);
			}
		}

		Ok(true)
	}

	/// Attempts to collect as much files and their blocks on the given
	/// connection.
	async fn collect_object(
		&self, connection: &mut Connection, id: &IdType, object: &Object, verified_from_start: bool,
	) -> db::Result<bool> {
		self.store_object(id, object, verified_from_start)?;

		match &object.payload {
			ObjectPayload::Profile(payload) => {
				if let Some(block_id) = payload.description.as_ref() {
					if !self.collect_block(connection, block_id).await? {
						return Ok(false);
					}
				}
				if let Some(hash) = payload.avatar.as_ref() {
					if !self.collect_file(connection, &hash).await? {
						return Ok(false);
					}
				}
				if let Some(hash) = payload.wallpaper.as_ref() {
					if !self.collect_file(connection, &hash).await? {
						return Ok(false);
					}
				}
			}
			ObjectPayload::Post(payload) =>
				for hash in &payload.files {
					if !self.collect_file(connection, &hash).await? {
						return Ok(false);
					}
				},
			_ => {}
		}
		Ok(true)
	}

	fn db(&self) -> &db::Database { &self.base.interface.db }

	/*fn async fn exchange(
		&self, target: &NodeContactInfo, message_type_id: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		self.base.exchange(target, message_type_id | 0x80)
	}*/

	pub async fn exchange_head(&self, target: &NodeContactInfo) -> Option<HeadResponse> {
		let raw_response = self
			.base
			.exchange(target, ACTOR_MESSAGE_TYPE_HEAD_REQUEST, &[])
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: HeadResponse = self
			.base
			.handle_connection_issue2(result, &target.node_id, &target.contact_info)
			.await?;
		Some(response)
	}

	pub async fn exchange_head_on_connection(
		&self, connection: &mut Connection,
	) -> Option<HeadResponse> {
		let raw_response = self
			.base
			.exchange_on_connection(connection, ACTOR_MESSAGE_TYPE_HEAD_REQUEST, &[])
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: HeadResponse = self
			.base
			.handle_connection_issue(
				result,
				&connection.their_node_id(),
				&connection.peer_contact_option(),
			)
			.await?;
		// FIXME: Verify object here
		Some(response)
	}

	pub async fn exchange_find_block_on_connection(
		&self, connection: &mut Connection, id: &IdType,
	) -> Option<FindBlockResult> {
		self.exchange_find_value_on_connection_and_parse(connection, ValueType::Block, id)
			.await
	}

	pub async fn exchange_find_file_on_connection(
		&self, connection: &mut Connection, id: &IdType,
	) -> Option<FindFileResult> {
		self.exchange_find_value_on_connection_and_parse(connection, ValueType::File, id)
			.await
	}

	async fn exchange_find_value_on_connection_and_parse<V>(
		&self, connection: &mut Connection, value_type: ValueType, id: &IdType,
	) -> Option<V>
	where
		V: DeserializeOwned,
	{
		let (value_result, _) = self
			.base
			.exchange_find_value_on_connection_and_parse(connection, value_type, id, false)
			.await?;
		value_result
	}

	/*async fn exchange_store_value(
		&self, c: &mut Connection, id: IdType, value_type: ValueType,
	) -> Option<StoreValueResponse> {
		let request = StoreValueRequest { id, value_type };
		let raw_response = self
			.base
			.exchange_on_connection(
				c,
				ACTOR_MESSAGE_TYPE_STORE_VALUE_REQUEST,
				&bincode::serialize(&request).unwrap(),
			)
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: StoreValueResponse = self
			.base
			.handle_connection_issue(result, c.their_node_id(), &c.peer_contact_option())
			.await?;
		Some(response)
	}*/

	async fn exchange_profile(&self, contact: &NodeContactInfo) -> Option<ProfileObject> {
		let request = GetProfileRequest {};
		let raw_response = self
			.base
			.exchange(
				contact,
				ACTOR_MESSAGE_TYPE_GET_PROFILE_REQUEST,
				&bincode::serialize(&request).unwrap(),
			)
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: GetProfileResponse = self
			.base
			.handle_connection_issue2(result, &contact.node_id, &contact.contact_info)
			.await?;
		response.profile
	}

	/// Publishes an object on a connection.
	async fn exchange_publish_object_on_connection(
		&self, connection: &mut Connection, id: &IdType,
	) -> Option<bool> {
		let request = PublishObjectRequest { id: id.clone() };
		let raw_request = bincode::serialize(&request).unwrap();
		let raw_response = self
			.base
			.exchange_on_connection(
				connection,
				ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_REQUEST,
				&raw_request,
			)
			.await?;
		let result: sstp::Result<_> = bincode::deserialize(&raw_response).map_err(|e| e.into());
		let response: PublishObjectResponse = self
			.base
			.handle_connection_issue(
				result,
				connection.their_node_id(),
				&connection.peer_contact_option(),
			)
			.await?;
		Some(response.needed)
	}

	pub async fn fetch_profile(&self) -> Option<ProfileObject> {
		let mut iter = self.base.iter_all_fingers().await;
		while let Some(contact) = iter.next().await {
			match self.exchange_profile(&contact).await {
				None => debug!("Node {} doesn't have profile data.", &contact.contact_info),
				Some(profile) => return Some(profile),
			}
		}
		None
	}

	pub async fn find_block(&self, id: &IdType) -> Option<FindBlockResult> {
		let result: Box<FindBlockResult> =
			self.find_value(ValueType::Block, id, 100, false).await?;
		Some(*result)
	}

	pub async fn find_file(&self, id: &IdType) -> Option<FindFileResult> {
		let result: Box<FindFileResult> = self.find_value(ValueType::File, id, 100, false).await?;
		Some(*result)
	}

	pub async fn find_next_object(&self, id: &IdType) -> Option<FindNextObjectResult> {
		let result: Box<FindNextObjectResult> = self
			.find_value(ValueType::NextObject, id, 100, false)
			.await?;

		Some(*result)
	}

	pub async fn find_object(&self, id: &IdType) -> Option<FindObjectResult> {
		let result: Box<FindObjectResult> =
			self.find_value(ValueType::Object, id, 100, false).await?;
		Some(*result)
	}

	async fn find_value<V>(
		&self, value_type: ValueType, id: &IdType, hop_limit: usize, only_narrow_down: bool,
	) -> Option<Box<V>>
	where
		V: DeserializeOwned,
	{
		fn parse_value<V>(
			_id: &IdType, _peer: &NodeContactInfo, data: &[u8],
		) -> Option<AtomicPtr<()>>
		where
			V: DeserializeOwned,
		{
			match bincode::deserialize_owned::<V>(&data) {
				Err(e) => {
					warn!("Malformed value received: {}", e);
					None
				}
				Ok(result) => {
					let box_ = Box::new(result);
					Some(AtomicPtr::new(Box::into_raw(box_) as _))
				}
			}
		}

		let fingers = self.base.find_nearest_fingers(id).await;
		if fingers.len() == 0 {
			return None;
		}

		let result = self
			.base
			.find_value_from_fingers(
				id,
				value_type as _,
				false,
				&fingers,
				hop_limit,
				only_narrow_down,
				parse_value::<V>,
			)
			.await;

		result.map(|p| {
			let object_result: Box<V> = unsafe { Box::from_raw(p.into_inner() as *mut V) };
			object_result
		})
	}

	pub async fn fetch_head(&self) -> Option<Object> {
		let mut iter = self.base.iter_all_fingers().await;
		let mut i = 0;
		let mut newest_object: Option<Object> = None;
		while let Some(contact) = iter.next().await {
			if let Some(response) = self.exchange_head(&contact).await {
				if newest_object.is_none()
					|| response.object.sequence > newest_object.as_ref().unwrap().sequence
				{
					newest_object = Some(response.object)
				}
			}

			if i == KADEMLIA_K {
				break;
			}
			i += 1
		}
		newest_object
	}

	fn has_object_by_sequence(&self, sequence: u64) -> bool {
		tokio::task::block_in_place(|| {
			let c = self.db().connect().expect("unable to open database");
			c.has_object_sequence(self.actor_id(), sequence)
				.expect("unable to read object from database")
		})
	}

	/// Does all the work that is expected upon joining the network.
	pub async fn initialize(
		self: &Arc<Self>, overlay_node: &Arc<OverlayNode>, first_nodes: &[NodeContactInfo],
	) {
		// Put yourself in the network
		let mut joined = false;
		for first_node in first_nodes {
			if self
				.base
				.join_network_starting_at(&first_node.contact_info)
				.await
			{
				joined = true;
				break;
			}
		}
		if !joined {
			info!("Alone on actor network {}.", &self.base.interface.actor_id);
			return;
		}

		// Check if we are behind or if the network is behind
		self.synchronize_head(overlay_node)
			.await
			.expect("unable to synchronize head");

		// Do the work of synchronizing all missing data.
		self.start_synchronization();
	}

	/// Returns a list of block hashes that we'd like to have.
	fn investigate_missing_blocks(&self) -> db::Result<Vec<IdType>> {
		tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			c.fetch_missing_file_blocks(self.actor_id())
		})
	}

	/// Returns a list of file hashes that we'd like to have.but our still
	/// missing.
	fn investigate_missing_files(&self) -> db::Result<Vec<IdType>> {
		tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			let (_, head, ..) = if let Some(h) = c.fetch_head(self.actor_id())? {
				h
			} else {
				return Ok(Vec::new());
			};
			let mut results = Vec::new();

			for i in 0..head.sequence {
				if let Some((_, object, ..)) = c.fetch_object_by_sequence(self.actor_id(), i)? {
					match object.payload {
						ObjectPayload::Profile(payload) => {
							if let Some(file_hash) = payload.avatar.as_ref() {
								if !c.has_file(self.actor_id(), file_hash)? {
									results.push(file_hash.clone());
								}
							}
							if let Some(file_hash) = payload.wallpaper.as_ref() {
								if !c.has_file(self.actor_id(), file_hash)? {
									results.push(file_hash.clone());
								}
							}
						}
						ObjectPayload::Post(payload) =>
							for file_hash in payload.files {
								if !c.has_file(self.actor_id(), &file_hash)? {
									results.push(file_hash.clone());
								}
							},
						ObjectPayload::Move(_) => {}
						ObjectPayload::Boost(_) => {}
					}
				}
			}
			Ok(results)
		})
	}

	fn investigate_missing_object_files(&self, object: &Object) -> db::Result<Vec<IdType>> {
		tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			let mut results = Vec::new();
			match &object.payload {
				ObjectPayload::Profile(payload) => {
					if let Some(file_hash) = payload.avatar.as_ref() {
						if !c.has_file(self.actor_id(), file_hash)? {
							results.push(file_hash.clone());
						}
					}
					if let Some(file_hash) = payload.wallpaper.as_ref() {
						if !c.has_file(self.actor_id(), file_hash)? {
							results.push(file_hash.clone());
						}
					}
				}
				ObjectPayload::Post(payload) =>
					for file_hash in &payload.files {
						if !c.has_file(self.actor_id(), &file_hash)? {
							results.push(file_hash.clone());
						}
					},
				ObjectPayload::Move(_) => {}
				ObjectPayload::Boost(_) => {}
			}
			Ok(results)
		})
	}

	fn load_public_key(&self) -> PublicKey {
		let actor_info = tokio::task::block_in_place(|| {
			let c = self.db().connect().expect("unable to connect to database");
			c.fetch_identity(self.actor_id())
				.expect("unable to load identity for actor node")
				.expect("no identity for actor node")
		});
		actor_info.public_key
	}

	pub fn new(
		stop_flag: Arc<AtomicBool>, node_id: IdType, socket: Arc<sstp::Server>, actor_id: IdType,
		actor_info: ActorInfo, db: Database, bucket_size: usize,
	) -> Self {
		let interface = ActorInterface {
			db,
			actor_id,
			actor_info,
			is_lurker: false,
			connection_manager: Arc::new(ConnectionManager::new(node_id.clone(), 1)),
		};
		Self {
			is_synchonizing: Arc::new(AtomicBool::new(false)),
			base: Arc::new(Node::new(
				stop_flag,
				node_id,
				socket,
				interface,
				bucket_size,
			)),
			downloading_objects: Mutex::new(Vec::new()),
		}
	}

	pub(super) fn new_lurker(
		stop_flag: Arc<AtomicBool>, socket: Arc<sstp::Server>, actor_id: IdType,
		actor_info: ActorInfo, db: Database, bucket_size: usize,
	) -> Self {
		let keypair = PrivateKey::generate();
		let public_key = keypair.public();
		let address = public_key.generate_address();

		let interface = ActorInterface {
			db,
			actor_id,
			actor_info,
			is_lurker: true,
			connection_manager: Arc::new(ConnectionManager::new(address.clone(), 0)),
		};
		Self {
			is_synchonizing: Arc::new(AtomicBool::new(false)),
			base: Arc::new(Node::new(
				stop_flag,
				address,
				socket,
				interface,
				bucket_size,
			)),
			downloading_objects: Mutex::new(Vec::new()),
		}
	}

	async fn missing_value_response(&self, id: &IdType) -> Vec<u8> {
		let bit = self.base.node_id.differs_at_bit(id);
		let connection = match bit {
			None => None,
			Some(b) => self
				.base
				.interface
				.connection_manager
				.find_near(b)
				.await
				.map(|r| r.0),
		};
		let fingers = self.base.find_nearest_fingers(id).await;
		let response = FindNodeResponse {
			connection,
			fingers,
		};
		let result: Result<(), FindNodeResponse> = Err(response);
		bincode::serialize(&result).unwrap()
	}

	async fn process_get_profile_request(&self, buffer: &[u8]) -> Option<Vec<u8>> {
		let _request: GetProfileRequest = match bincode::deserialize(buffer) {
			Ok(r) => r,
			Err(e) => {
				error!("Malformed get profile message: {}", e);
				return None;
			}
		};

		let result = tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			c.fetch_profile(&self.base.interface.actor_id)
		});
		let profile = match result {
			Ok(p) => p,
			Err(e) => {
				error!(
					"Unable to fetch profile for actor {}: {}",
					&self.base.interface.actor_id, e
				);
				None
			}
		};

		let response = GetProfileResponse { profile };
		Some(bincode::serialize(&response).unwrap())
	}

	async fn process_keep_alive_request(
		self: &Arc<Self>, node_info: &NodeContactInfo, mutex: &Arc<Mutex<Box<Connection>>>,
	) -> Option<Vec<u8>> {
		let ok = self
			.base
			.interface
			.connection_manager
			.add(node_info, mutex)
			.await;
		Some(bincode::serialize(&KeepAliveResponse { ok }).unwrap())
	}

	/*async fn process_relay_request(
		self: &Arc<Self>, mutex: &Arc<Mutex<Box<Connection>>>, buffer: &[u8],
	) -> Option<Vec<u8>> {
		let request: RelayRequest = match bincode::deserialize(buffer) {
			Ok(id) => id,
			Err(e) => {
				warn!("Malformed relay request: {}", e);
				return None;
			}
		};

		if let Some((target, target_connection_lock)) = self
			.base
			.interface
			.connection_manager
			.find(&request.target)
			.await
		{
			let this = self.clone();
			let mutex2 = mutex.clone();
			spawn(async move {
				if let Ok(mut target_connection) = target_connection_lock.try_lock() {
					let mut response = RelayResponse { ok: true };
					let mut connection = mutex2.lock().await;
					if this
						.base
						.interface
						.send(
							&mut *target_connection,
							request.message_type_id,
							&[],
							//&request.message,
						)
						.await
						.is_ok()
					{
						if let Err(e) = this
							.base
							.interface
							.respond(
								&mut *connection,
								ACTOR_MESSAGE_TYPE_RELAY_RESPONSE,
								&bincode::serialize(&response).unwrap(),
							)
							.await
						{
							warn!("Unable to respond to relay request: {}", e);
						}
						if let Err(e) = target_connection.pipe(connection.as_mut()).await {
							warn!("Unable to pipe relay request: {}", e);
						}
					} else {
						response.ok = false;
						if let Err(e) = this
							.base
							.interface
							.respond(
								&mut *connection,
								ACTOR_MESSAGE_TYPE_RELAY_RESPONSE,
								&bincode::serialize(&response).unwrap(),
							)
							.await
						{
							warn!("Unable to respond to relay request: {}", e);
						}
					}
				}
			});
			return None;
		}

		let response = RelayResponse { ok: false };
		Some(bincode::serialize(&response).unwrap())
	}*/

	pub(super) async fn process_request(
		self: &Arc<Self>, connection: &mut Connection, _mutex: &Arc<Mutex<Box<Connection>>>,
		message_type: u8, buffer: &[u8],
	) -> Option<Vec<u8>> {
		match message_type {
			ACTOR_MESSAGE_TYPE_HEAD_REQUEST => self.process_head_request(buffer).await,
			ACTOR_MESSAGE_TYPE_GET_PROFILE_REQUEST =>
				self.process_get_profile_request(buffer).await,
			ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_REQUEST => {
				self.process_publish_object_request(connection, buffer)
					.await;
				None
			}
			other_id => {
				error!(
					"Unknown actor message type ID received from {}: {}",
					connection.peer_address(),
					other_id
				);
				None
			}
		}
	}

	async fn process_head_request(&self, buffer: &[u8]) -> Option<Vec<u8>> {
		if buffer.len() > 0 {
			warn!("Malformed head request");
			return None;
		}

		let head_result = tokio::task::block_in_place(|| {
			let c = match self.db().connect() {
				Ok(c) => c,
				Err(e) => {
					error!("Unable to connect to database to check block: {}", e);
					return None;
				}
			};
			match c.fetch_head(&self.base.interface.actor_id) {
				Ok(h) => h,
				Err(e) => {
					error!("Unable to fetch head: {}", e);
					None
				}
			}
		});

		let response = match head_result {
			None => {
				error!(
					"No objects found for actor {}",
					&self.base.interface.actor_id
				);
				return None;
			}
			Some((hash, object, ..)) => HeadResponse { hash, object },
		};
		Some(bincode::serialize(&response).unwrap())
	}

	async fn process_publish_object_request_receive_object(
		self: &Arc<Self>, c: &mut Connection, object_id: &IdType, needed: bool,
		public_key: &PublicKey,
	) -> Option<Object> {
		let response = PublishObjectResponse { needed };
		match self
			.base
			.interface
			.respond(
				c,
				ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_RESPONSE,
				&bincode::serialize(&response).unwrap(),
			)
			.await
		{
			Ok(()) => {}
			Err(e) => {
				error!("Unable to respond to publish object request: {}", e);
				return None;
			}
		}

		if needed {
			let buffer = match c.receive().await {
				Ok(v) => Arc::new(v),
				Err(e) => {
					error!("Unable to download object data: {}", e);
					return None;
				}
			};
			let upload: PublishObjectMessage = match bincode::deserialize(&buffer) {
				Ok(r) => r,
				Err(e) => {
					warn!("Object upload message was malformed: {}", e);
					return None;
				}
			};

			if !self.verify_object(&object_id, &upload.object, public_key) {
				warn!("Invalid object received: verification failed.");
				return None;
			}

			// If everything checks out, use the same connection to start synchronizing all
			// the files and blocks on it, then close it ourselves.
			// self.synchronize_object(c, object_id, &upload.object).await;
			//self.process_new_object(c, object_id, &upload.object).await.expect("db
			// error"); c.close().await;

			return Some(upload.object);
		}

		None
	}

	async fn process_publish_object_request(self: &Arc<Self>, c: &mut Connection, buffer: &[u8]) {
		let request: PublishObjectRequest = match bincode::deserialize(buffer) {
			Ok(r) => r,
			Err(e) => {
				warn!(
					"Malformed publish block request from {}: {}",
					c.peer_address(),
					e
				);
				// TODO: Reject node
				return;
			}
		};

		// Respond with whether we need the value or not.
		let needed = {
			let mut downloading_objects = self.downloading_objects.lock().await;
			let mut needed = !downloading_objects.contains(&request.id);
			let actor_id = &self.actor_id();
			if needed {
				needed = self.needs_object(actor_id, &request.id);
				if needed {
					downloading_objects.push(request.id.clone());
				}
			}
			needed
		};

		let public_key = &self.base.interface.actor_info.public_key;
		let object_result = self
			.process_publish_object_request_receive_object(c, &request.id, needed, public_key)
			.await;
		debug!("process_publish_object_request3 {:?}", &object_result);

		// Forget we were downloading this object
		let mut downloading_objects = self.downloading_objects.lock().await;
		if let Some(p) = downloading_objects.iter().position(|i| i == &request.id) {
			downloading_objects.remove(p);
		}

		// Store & rebroadcast object if needed
		if let Some(object) = object_result {
			let this = self.clone();
			debug!("process_publish_object_request4");
			if let Err(e) = this.process_new_object(c, &request.id, &object).await {
				error!("Database error while processing new object: {}", e);
			}
			c.close().await;
		}
	}

	fn needs_object(&self, actor_id: &IdType, id: &IdType) -> bool {
		tokio::task::block_in_place(|| {
			let c = match self.db().connect() {
				Ok(c) => c,
				Err(e) => {
					error!("Unable to connect to database to check object: {}", e);
					return false;
				}
			};
			let has_object = match c.has_object(actor_id, id) {
				Ok(b) => b,
				Err(e) => {
					error!("Unable to check object: {}", e);
					return false;
				}
			};
			!has_object
		})
	}

	fn needs_file(&self, actor_id: &IdType, id: &IdType) -> bool {
		tokio::task::block_in_place(|| {
			let c = match self.db().connect() {
				Ok(c) => c,
				Err(e) => {
					error!("Unable to connect to database to check object: {}", e);
					return false;
				}
			};
			let has_object = match c.has_file(actor_id, id) {
				Ok(b) => b,
				Err(e) => {
					error!("Unable to check object: {}", e);
					return false;
				}
			};
			!has_object
		})
	}

	fn needs_block(&self, actor_id: &IdType, id: &IdType) -> bool {
		tokio::task::block_in_place(|| {
			let c = match self.db().connect() {
				Ok(c) => c,
				Err(e) => {
					error!("Unable to connect to database to check object: {}", e);
					return false;
				}
			};
			let has_object = match c.has_block(actor_id, id) {
				Ok(b) => b,
				Err(e) => {
					error!("Unable to check object: {}", e);
					return false;
				}
			};
			!has_object
		})
	}

	async fn process_upload_block_message(
		&self, actor_id: &IdType, id: &IdType, buffer: &[u8],
	) -> bool {
		if &IdType::hash(buffer) != id {
			warn!("Invalid block data received from for block {}.", id);
			return false;
		}

		tokio::task::block_in_place(|| {
			let mut c = match self.db().connect() {
				Ok(c) => c,
				Err(e) => {
					error!("Unable to connect to database to store block: {}", e);
					return false;
				}
			};

			match c.store_block(actor_id, id, buffer) {
				Ok(()) => true,
				Err(e) => {
					error!("Unable to store block {}: {}", id, e);
					false
				}
			}
		})
	}

	async fn process_upload_file_message(
		&self, actor_id: &IdType, id: &IdType, buffer: &[u8],
	) -> bool {
		let file: File = match bincode::deserialize(buffer) {
			Err(e) => {
				warn!("Malformed upload file message: {}", e);
				return false;
			}
			Ok(o) => o,
		};

		// TODO: Verify file hash

		tokio::task::block_in_place(|| {
			let mut c = match self.db().connect() {
				Ok(c) => c,
				Err(e) => {
					error!("Unable to connect to database to store file: {}", e);
					return false;
				}
			};

			match c.store_file2(actor_id, id, &file.mime_type, &file.blocks) {
				Ok(_) => true,
				Err(e) => {
					error!("Unable to store file {}: {}", id, e);
					false
				}
			}
		})
	}

	fn verify_block(&self, id: &IdType, data: &[u8]) -> bool {
		let hash = IdType::hash(data);
		id == &hash
	}

	fn verify_file(&self, id: &IdType, file: &File) -> bool {
		let buffer = bincode::serialize(file).unwrap();
		let hash = IdType::hash(&buffer);
		id == &hash
	}

	/*fn verify_first_object(&self, id: &IdType, object: &Object, public_key: &PublicKey) -> bool {
		if object.created as u128
			> SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_millis()
		{
			warn!(
				"First object {} is invalid: creation timestamp is from the future: {}",
				&id, object.created
			);
			return false;
		}

		let sign_data = FirstObjectSignData {
			sequence: object.sequence,
			created: object.created,
			payload: &object.payload,
		};
		let raw_sign_data = bincode::serialize(&sign_data).unwrap();
		if !public_key.verify(&raw_sign_data, &object.signature) {
			warn!("First object {} is invalid: signature is incorrect.", &id);
			return false;
		}

		let signature_hash = object.signature.hash();
		if &signature_hash != id {
			warn!(
				"First object {} is invalid: id is not a hash of the signature: {} != {}",
				self.actor_id(),
				signature_hash,
				&id
			);
			return false;
		}
		true
	}*/

	fn verify_object(&self, id: &IdType, object: &Object, public_key: &PublicKey) -> bool {
		if object.created as u128
			> SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_millis()
		{
			warn!(
				"Object {} is invalid: creation timestamp is from the future: {}",
				&id, object.created
			);
			return false;
		}

		let sign_data = ObjectSignData {
			previous_hash: object.previous_hash.clone(),
			sequence: object.sequence,
			created: object.created,
			payload: &object.payload,
		};
		let raw_sign_data = bincode::serialize(&sign_data).unwrap();
		if !public_key.verify(&raw_sign_data, &object.signature) {
			warn!("Object {} is invalid: signature is incorrect.", &id);
			return false;
		}

		let signature_hash = object.signature.hash();
		if &signature_hash != id {
			warn!(
				"Object {} is invalid: id is not a hash of the signature: {} != {}",
				self.actor_id(),
				signature_hash,
				&id
			);
			return false;
		}
		true
	}

	pub async fn publish_object(
		self: Arc<Self>, overlay_node: Arc<OverlayNode>, id: &IdType, object: &Object,
	) {
		let mut iter = self.base.iter_all_fingers().await;
		while let Some(finger) = iter.next().await {
			if let Some(connection) = self
				.base
				.connect(&finger.contact_info, Some(&finger.node_id))
				.await
			{
				self.clone()
					.publish_object_on_connection(&overlay_node, connection, id, object)
					.await;
			}
		}
	}

	pub async fn publish_object_on_connection(
		self: Arc<Self>, overlay_node: &Arc<OverlayNode>, mut connection: Box<Connection>,
		id: &IdType, object: &Object,
	) {
		if let Some(wants_it) = self
			.exchange_publish_object_on_connection(&mut connection, id)
			.await
		{
			if wants_it {
				let buffer = bincode::serialize(object).unwrap();
				if let Err(e) = connection.send(&buffer).await {
					error!(
						"Unable to upload object {} to node {}: {}",
						id,
						connection.their_node_id(),
						e
					);
				}
				// Keep the connection open so that the other side can continue to make
				// requests to us, and once (s)he closes, we return our function.
				connection.should_be_closed.store(false, Ordering::Relaxed);
				node::handle_connection(overlay_node.clone(), connection).await;
			} else {
				connection.close().await;
			}
			return;
		}

		connection.close().await;
	}

	/// Processes a new object:
	/// * Stores it in our DB if we don't have it yet.
	/// * Uses the connection to ask for files and blocks as well.
	/// * Starts the synchronization process if we don't have the objects
	///   leading up to this new object.
	async fn process_new_object(
		&self, connection: &mut Connection, id: &IdType, object: &Object,
	) -> db::Result<Option<Object>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			c.fetch_head(self.actor_id())
		})?;

		// If we have at least one object already
		if let Some((_, our_head, verified_from_start)) = result {
			// If we are behind, store the received object in our database
			if object.sequence > our_head.sequence {
				if !self
					.collect_object(
						connection,
						id,
						object,
						verified_from_start && object.sequence == (our_head.sequence + 1),
					)
					.await?
				{
					error!("Invalid data received on connection.")
				}
				return Ok(Some(our_head));
			}
		// If we don't have any objects yet
		} else {
			// If first object, we can immediately 'verify it from start'
			if object.sequence == 0 {
				if id != &self.base.interface.actor_info.first_object {
					error!("Invalid first object received on connection");
					return Ok(None);
				}
			}
			if !self
				.collect_object(connection, id, object, object.sequence == 0)
				.await?
			{
				error!("Invalid data received on connection.")
			}
		}

		Ok(None)
	}

	fn store_block(&self, id: &IdType, data: &[u8]) -> db::Result<()> {
		tokio::task::block_in_place(|| {
			let mut c = self.db().connect()?;
			c.store_block(self.actor_id(), id, data)
		})?;
		Ok(())
	}

	fn store_file(&self, id: &IdType, file: &File) -> db::Result<()> {
		tokio::task::block_in_place(|| {
			let mut c = self.db().connect()?;
			c.store_file(self.actor_id(), id, file)
		})?;
		Ok(())
	}

	fn store_object(
		&self, id: &IdType, object: &Object, verified_from_start: bool,
	) -> db::Result<bool> {
		tokio::task::block_in_place(|| {
			let mut c = self.db().connect()?;
			c.store_object(self.actor_id(), id, object, verified_from_start)
		})
	}

	pub async fn synchronize(&self) -> db::Result<()> {
		self.synchronize_objects().await?;
		self.synchronize_files().await?;
		self.synchronize_blocks().await
	}

	async fn synchronize_blocks(&self) -> db::Result<()> {
		let missing_blocks = self.investigate_missing_blocks()?;
		for hash in missing_blocks {
			if let Some(result) = self.find_block(&hash).await {
				tokio::task::block_in_place(|| {
					let mut c = self.db().connect()?;
					c.store_block(self.actor_id(), &hash, &result.data)
				})?;
			}
		}
		Ok(())
	}

	async fn synchronize_head(self: &Arc<Self>, overlay_node: &Arc<OverlayNode>) -> db::Result<()> {
		let mut finger_iter = self.base.iter_all_fingers().await;
		while let Some(finger) = finger_iter.next().await {
			if let Some(mut connection) = self
				.base
				.connect(&finger.contact_info, Some(&finger.node_id))
				.await
			{
				if let Some(response) = self.exchange_head_on_connection(&mut connection).await {
					match self
						.process_new_object(&mut connection, &response.hash, &response.object)
						.await
					{
						Err(e) => {
							connection.close().await;
							return Err(e);
						}
						Ok(result) => {
							if let Some(our_head) = result {
								// If that node is behind, publish our head to that node
								if response.object.sequence < our_head.sequence {
									self.clone()
										.publish_object_on_connection(
											overlay_node,
											connection,
											&response.hash,
											&response.object,
										)
										.await;
								} else {
									connection.close().await;
								}
							} else {
								connection.close().await;
							}
						}
					}

					// Stop after we've gotten head from one peer
					break;
				} else {
					connection.close().await;
				}
			}
		}
		Ok(())
	}

	async fn synchronize_files(&self) -> db::Result<()> {
		let missing_files = self.investigate_missing_files()?;
		for hash in missing_files {
			if let Some(result) = self.find_file(&hash).await {
				tokio::task::block_in_place(|| {
					let mut c = self.db().connect()?;
					c.store_file(self.actor_id(), &hash, &result.file)
				})?;
			}
		}
		Ok(())
	}

	async fn synchronize_object(
		&self, connection: &mut Connection, object: &Object,
	) -> db::Result<()> {
		let missing_files = self.investigate_missing_object_files(object)?;
		for file_id in &missing_files {
			self.collect_file(connection, file_id).await?;
		}
		Ok(())
	}

	/// Iteratively search the network for object meta data.
	async fn synchronize_objects(&self) -> db::Result<bool> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			c.fetch_last_verified_object(self.actor_id())
		})?;
		let (mut last_known_object_id, mut last_known_object_sequence) = match result {
			Some((hash, object)) => (hash, object.sequence),
			// If we don't have anything, try to find the first object as well
			None => {
				let first_object_hash = &self.base.interface.actor_info.first_object;
				match self.find_object(first_object_hash).await {
					None => return Ok(false),
					Some(object_result) => {
						if self.verify_object(
							&first_object_hash,
							&object_result.object,
							&self.base.interface.actor_info.public_key,
						) {
							self.store_object(
								&self.base.interface.actor_info.first_object,
								&object_result.object,
								true,
							)?;
						} else {
							return Ok(false);
						}
						(first_object_hash.clone(), 0)
					}
				}
			}
		};

		loop {
			match self.find_next_object(&last_known_object_id).await {
				None => return Ok(true),
				Some(FindNextObjectResult { hash, object }) => {
					if object.sequence != (last_known_object_sequence + 1) {
						error!(
							"Object received with invalid sequence number: {} {}",
							object.sequence, last_known_object_sequence
						);
						return Ok(true);
					}

					if self.verify_object(
						&hash,
						&object,
						&self.base.interface.actor_info.public_key,
					) {
						self.store_object(&hash, &object, true)?;
					} else {
						return Ok(false);
					}
					last_known_object_id = hash.clone();
					last_known_object_sequence += 1;

					// Update the objects we may have already stored if we know they have been
					// verified.
					loop {
						let to_break: db::Result<bool> = tokio::task::block_in_place(|| {
							let mut c = self.db().connect()?;
							let result = c.fetch_object_by_sequence(
								self.actor_id(),
								last_known_object_sequence + 1,
							)?;

							if let Some((hash, _, verified_from_start)) = result {
								// If hashes don't compare, we know the object is invalid (even
								// though the signature is correct), and so we should delete it.

								if (object.sequence > 0
									&& object.previous_hash != last_known_object_id)
									|| (object.sequence == 0
										&& object.previous_hash != IdType::default())
								{
									c.delete_object(self.actor_id(), &hash)?;
									Ok(true)
								} else {
									last_known_object_sequence += 1;
									last_known_object_id = hash.clone();
									if !verified_from_start {
										c.update_object_verified(self.actor_id(), &hash)?;
									}

									Ok(false)
								}
							} else {
								Ok(true)
							}
						});
						if to_break? {
							break;
						}
					}
				}
			}
		}
	}

	/// Will run the
	fn start_synchronization(self: &Arc<Self>) -> bool {
		if !self.is_synchonizing.load(Ordering::Acquire) {
			self.is_synchonizing.store(true, Ordering::Release);
			let this = self.clone();
			spawn(async move {
				let result = this.synchronize().await;
				this.is_synchonizing.store(false, Ordering::Release);
				if let Err(e) = result {
					error!(
						"Error occurred during synchronization for actor {}: {}",
						this.actor_id(),
						e
					);
				}
			});
			true
		} else {
			false
		}
	}

	pub async fn wait_for_synchronization(&self) {
		loop {
			if self.is_synchonizing.load(Ordering::Relaxed) {
				sleep(Duration::from_millis(100)).await;
			} else {
				return;
			}
		}
	}
}

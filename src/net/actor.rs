use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures::future::join_all;
use serde::de::DeserializeOwned;
use tokio::{spawn, time::sleep};

use super::{
	connection_manager::*,
	message::*,
	node::*,
	overlay::OverlayNode,
	sstp::{self, MessageProcessorResult, MessageWorkToDo, Result},
	*,
};
use crate::{
	common::*,
	core::*,
	db::{self, Database},
	identity::*,
	trace::Mutex,
};


pub const ACTOR_MESSAGE_TYPE_HEAD_REQUEST: u8 = 64;
pub const ACTOR_MESSAGE_TYPE_HEAD_RESPONSE: u8 = 65 | 0x80;
pub const ACTOR_MESSAGE_TYPE_GET_PROFILE_REQUEST: u8 = 66;
pub const ACTOR_MESSAGE_TYPE_GET_PROFILE_RESPONSE: u8 = 67 | 0x80;
pub const ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_REQUEST: u8 = 70;
pub const ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_RESPONSE: u8 = 71 | 0x80;


pub struct ActorNode {
	pub(super) base: Arc<Node<ActorInterface>>,
	downloading_objects: Mutex<Vec<IdType>>,
	is_synchonizing: Arc<AtomicBool>,
}

pub struct ActorInterface {
	overlay_node: Arc<OverlayNode>,
	db: Database,
	actor_address: ActorAddress,
	actor_info: ActorInfo,
	is_lurker: bool,
	pub(super) connection_manager: Arc<ConnectionManager>,
}

struct PublishObjectToDo {
	node: Arc<ActorNode>,
	hash: IdType,
}

impl ActorInterface {
	async fn find_block(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_block(id)
		})?;
		if let Some(data) = result {
			let response = FindBlockResult { data };
			Ok(Some(binserde::serialize(&response).unwrap()))
		} else {
			Ok(None)
		}
	}

	async fn find_file(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_file(id)
		})?;
		Ok(result.map(|file| binserde::serialize(&file).unwrap()))
	}

	async fn find_object(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_object(id)
		})?;
		Ok(result.map(|(object, _)| binserde::serialize(&FindObjectResult { object }).unwrap()))
	}

	async fn find_next_object(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let mut c = self.db.connect()?;
			c.fetch_next_object(&self.actor_address, id)
		})?;
		Ok(result.map(|(hash, object, _)| {
			binserde::serialize(&FindNextObjectResult { hash, object }).unwrap()
		}))
	}
}

#[async_trait]
impl NodeInterface for ActorInterface {
	async fn close(&self) {}

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

	fn overlay_node(&self) -> Arc<OverlayNode> { self.overlay_node.clone() }

	fn prepare(&self, message_type: u8, buffer: &[u8]) -> Vec<u8> {
		let mut new_buffer = Vec::with_capacity(1 + 32 + buffer.len());
		new_buffer.push(message_type | 0x80);
		new_buffer.extend(self.actor_address.as_id().as_bytes());
		new_buffer.extend(buffer);
		new_buffer
	}
}

impl ActorNode {
	pub fn actor_address(&self) -> &ActorAddress { &self.base.interface.actor_address }

	pub async fn close(self: Arc<Self>) { self.base.close().await; }

	/// Attempts to collect as much blocks of this file on the given connection.
	pub async fn collect_block(
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
	pub async fn collect_file(
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
					if self.needs_block(block_id) {
						if !self.collect_block(connection, block_id).await? {
							return Ok(false);
						}
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
	pub(super) async fn collect_object(
		&self, connection: &mut Connection, id: &IdType, object: &Object, verified_from_start: bool,
	) -> db::Result<bool> {
		self.store_object(id, object, verified_from_start)?;
		match &object.payload {
			ObjectPayload::Profile(payload) => {
				if let Some(file_id) = payload.description.as_ref() {
					if self.needs_file(file_id) {
						if !self.collect_file(connection, file_id).await? {
							return Ok(false);
						}
					}
				}
				if let Some(hash) = payload.avatar.as_ref() {
					if self.needs_file(&hash) {
						if !self.collect_file(connection, &hash).await? {
							return Ok(false);
						}
					}
				}
				if let Some(hash) = payload.wallpaper.as_ref() {
					if self.needs_file(&hash) {
						if !self.collect_file(connection, &hash).await? {
							return Ok(false);
						}
					}
				}
			}
			ObjectPayload::Post(payload) => match &payload.data {
				PostObjectCryptedData::Plain(plain) =>
					for hash in &plain.files {
						if self.needs_file(&hash) {
							if !self.collect_file(connection, &hash).await? {
								return Ok(false);
							}
						}
					},
			},
			_ => {}
		}
		Ok(true)
	}

	fn db(&self) -> &db::Database { &self.base.interface.db }

	pub async fn exchange_head_on_connection(
		&self, connection: &mut Connection,
	) -> Option<HeadResponse> {
		let raw_response = self
			.base
			.exchange_on_connection(connection, ACTOR_MESSAGE_TYPE_HEAD_REQUEST, &[])
			.await?;
		let result: sstp::Result<_> = binserde::deserialize_sstp(&raw_response);
		let response: HeadResponse = self
			.base
			.handle_connection_issue(result, &connection.their_node_info())
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

	pub(super) async fn exchange_profile_on_connection(
		&self, connection: &mut Connection,
	) -> Option<(IdType, Object)> {
		let request = GetProfileRequest {};
		let raw_response = self
			.base
			.exchange_on_connection(
				connection,
				ACTOR_MESSAGE_TYPE_GET_PROFILE_REQUEST,
				&binserde::serialize(&request).unwrap(),
			)
			.await?;
		let result: sstp::Result<_> = binserde::deserialize_sstp(&raw_response);
		let response: GetProfileResponse = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		response.object
	}

	/// Publishes an object on a connection.
	async fn exchange_publish_object_on_connection(
		&self, connection: &mut Connection, id: &IdType,
	) -> Option<bool> {
		let request = PublishObjectRequest { id: id.clone() };
		let raw_request = binserde::serialize(&request).unwrap();
		let raw_response = self
			.base
			.exchange_on_connection(
				connection,
				ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_REQUEST,
				&raw_request,
			)
			.await?;
		let result: sstp::Result<_> = binserde::deserialize_sstp(&raw_response);
		let response: PublishObjectResponse = self
			.base
			.handle_connection_issue(result, connection.their_node_info())
			.await?;
		Some(response.needed)
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
			match binserde::deserialize_owned::<V>(&data) {
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

		let fingers = self.base.find_nearest_private_fingers(id).await;
		if fingers.len() == 0 {
			return None;
		}

		let result = self
			.base
			.find_value_from_fingers(
				self.base.interface.overlay_node.clone(),
				id,
				value_type as _,
				false,
				&fingers,
				hop_limit,
				only_narrow_down,
				true,
				parse_value::<V>,
			)
			.await;

		result.map(|p| {
			let object_result: Box<V> = unsafe { Box::from_raw(p.into_inner() as *mut V) };
			object_result
		})
	}

	fn has_object_by_sequence(&self, sequence: u64) -> bool {
		tokio::task::block_in_place(|| {
			let c = self.db().connect().expect("unable to open database");
			c.has_object_sequence(self.actor_address(), sequence)
				.expect("unable to read object from database")
		})
	}

	/// Does all the work that is expected upon joining the network.
	pub async fn initialize(self: &Arc<Self>, neighbours: &[NodeContactInfo]) {
		debug_assert!(
			neighbours.len() > 0,
			"need fingers to intialize actor node with"
		);
		// Check if we are behind or if the network is behind
		self.synchronize_head(neighbours)
			.await
			.expect("unable to synchronize head");

		// Do the work of synchronizing all missing data.
		self.start_synchronization();
	}

	pub async fn initialize_with_connection(self: &Arc<Self>, mut connection: Box<Connection>) {
		self.synchronize_recent_objects_on_connection(&mut connection)
			.await;
	}

	/// Returns a list of block hashes that we'd like to have.
	fn investigate_missing_blocks(&self) -> db::Result<Vec<IdType>> {
		tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			c.fetch_missing_file_blocks()
		})
	}

	/// Returns a list of file hashes that we'd like to have.but our still
	/// missing.
	fn investigate_missing_files(&self) -> db::Result<Vec<IdType>> {
		tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			let (_, head, ..) = if let Some(h) = c.fetch_head(self.actor_address())? {
				h
			} else {
				return Ok(Vec::new());
			};
			let mut results = Vec::new();

			for i in 0..head.sequence {
				if let Some((_, object, ..)) =
					c.fetch_object_by_sequence(self.actor_address(), i)?
				{
					match object.payload {
						ObjectPayload::Profile(payload) => {
							if let Some(file_hash) = payload.avatar.as_ref() {
								if !c.has_file(file_hash)? {
									results.push(file_hash.clone());
								}
							}
							if let Some(file_hash) = payload.wallpaper.as_ref() {
								if !c.has_file(file_hash)? {
									results.push(file_hash.clone());
								}
							}
						}
						ObjectPayload::Post(payload) => match &payload.data {
							PostObjectCryptedData::Plain(plain) =>
								for file_hash in &plain.files {
									if !c.has_file(file_hash)? {
										results.push(file_hash.clone());
									}
								},
						},
						ObjectPayload::Boost(_) => {}
					}
				}
			}
			Ok(results)
		})
	}

	#[allow(dead_code)]
	fn investigate_missing_object_files(&self, object: &Object) -> db::Result<Vec<IdType>> {
		tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			let mut results = Vec::new();
			match &object.payload {
				ObjectPayload::Profile(payload) => {
					if let Some(file_hash) = payload.avatar.as_ref() {
						if !c.has_file(file_hash)? {
							results.push(file_hash.clone());
						}
					}
					if let Some(file_hash) = payload.wallpaper.as_ref() {
						if !c.has_file(file_hash)? {
							results.push(file_hash.clone());
						}
					}
				}
				ObjectPayload::Post(payload) => match &payload.data {
					PostObjectCryptedData::Plain(plain) =>
						for file_hash in &plain.files {
							if !c.has_file(&file_hash)? {
								results.push(file_hash.clone());
							}
						},
				},
				ObjectPayload::Boost(_) => {}
			}
			Ok(results)
		})
	}

	pub async fn join_network_starting_with_connection(
		self: &Arc<Self>, mut connection: Box<Connection>,
	) -> Option<bool> {
		let response = self
			.base
			.exchange_find_node_on_connection(&mut connection, self.base.node_id())
			.await?;
		let mut fingers = response.fingers.clone();
		fingers.push(connection.their_node_info().clone());

		// If there is one or more fingers that do not require relaying, the node will
		// synchronize by using the whole network. If there are only nodes that require
		// communication via a relay, we savour the open connection and use it to
		// synchronize at least the last 10 objects.
		if !fingers.iter().any(|f| {
			if let Some(strategy) = self.base.pick_contact_strategy(&f.contact_info) {
				&f.node_id != &self.base.node_id && strategy.method != ContactStrategyMethod::Relay
			} else {
				false
			}
		}) {
			self.initialize_with_connection(connection).await;
			return Some(false);
		}

		let neighbours = self
			.base
			.find_node_from_fingers(self.base.node_id(), &fingers, 4, 100)
			.await;
		if neighbours.len() > 0 {
			self.initialize(&neighbours).await;
		} else {
			self.initialize(&fingers).await;
		}
		Some(true)
	}

	#[allow(dead_code)]
	fn load_public_key(&self) -> ActorPublicKeyV1 {
		let actor_info = tokio::task::block_in_place(|| {
			let c = self.db().connect().expect("unable to connect to database");
			c.fetch_identity(self.actor_address())
				.expect("unable to load identity for actor node")
				.expect("no identity for actor node")
		});
		match actor_info {
			ActorInfo::V1(ai) => ai.public_key,
		}
	}

	pub fn new(
		stop_flag: Arc<AtomicBool>, overlay_node: Arc<OverlayNode>, node_id: IdType,
		socket: Arc<sstp::Server>, actor_address: ActorAddress, actor_info: ActorInfo,
		db: Database, bucket_size: usize, leak_first_request: bool, is_lurker: bool,
	) -> Self {
		let interface = ActorInterface {
			overlay_node,
			db,
			actor_address,
			actor_info,
			is_lurker,
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
				leak_first_request,
			)),
			downloading_objects: Mutex::new(Vec::new()),
		}
	}

	async fn process_get_profile_request(&self, buffer: &[u8]) -> MessageProcessorResult {
		let _request: GetProfileRequest = match binserde::deserialize(buffer) {
			Ok(r) => r,
			Err(e) => {
				error!("Malformed get profile message: {}", e);
				return None;
			}
		};

		let result = tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			c.fetch_profile_object(&self.base.interface.actor_address)
		});
		let object = match result {
			Ok(p) => p,
			Err(e) => {
				error!(
					"Unable to fetch profile for actor {:?}: {}",
					&self.base.interface.actor_address, e
				);
				None
			}
		};

		let response = GetProfileResponse { object };
		self.base
			.simple_result(ACTOR_MESSAGE_TYPE_GET_PROFILE_RESPONSE, &response)
	}

	pub(super) async fn process_request(
		self: &Arc<Self>, message_type: u8, buffer: &[u8], addr: &SocketAddr,
		_node_info: &NodeContactInfo,
	) -> MessageProcessorResult {
		match message_type {
			ACTOR_MESSAGE_TYPE_HEAD_REQUEST => self.process_head_request(buffer).await,
			ACTOR_MESSAGE_TYPE_GET_PROFILE_REQUEST =>
				self.process_get_profile_request(buffer).await,
			ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_REQUEST =>
				self.process_publish_object_request(buffer, addr).await,
			other_id => {
				error!(
					"Unknown actor message type ID received from {}: {}",
					addr, other_id
				);
				return None;
			}
		}
	}

	async fn process_head_request(&self, buffer: &[u8]) -> MessageProcessorResult {
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
			match c.fetch_head(&self.base.interface.actor_address) {
				Ok(h) => h,
				Err(e) => {
					error!("Unable to fetch head: {}", e);
					return None;
				}
			}
		});

		let response = match head_result {
			None => {
				error!(
					"No objects found for actor {:?}",
					&self.base.interface.actor_address
				);
				return None;
			}
			Some((hash, object, ..)) => HeadResponse { hash, object },
		};
		self.base
			.simple_result(ACTOR_MESSAGE_TYPE_HEAD_RESPONSE, &response)
	}

	async fn process_publish_object_request(
		self: &Arc<Self>, buffer: &[u8], addr: &SocketAddr,
	) -> MessageProcessorResult {
		let request: PublishObjectRequest = match binserde::deserialize(buffer) {
			Ok(r) => r,
			Err(e) => {
				warn!("Malformed publish block request from {}: {}", addr, e);
				// TODO: Reject node
				return None;
			}
		};

		// Respond with whether we need the value or not.
		let needed = {
			let mut downloading_objects = self.downloading_objects.lock().await;
			let mut needed = !downloading_objects.contains(&request.id);
			let actor_id = &self.actor_address();
			if needed {
				needed = self.needs_object(actor_id, &request.id);
				if needed {
					downloading_objects.push(request.id.clone());
				}
			}
			needed
		};

		// If not needed, immediately respond
		let response = PublishObjectResponse { needed };
		let response_buffer = self
			.base
			.simple_response(ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_RESPONSE, &response);
		if !response.needed {
			return Some((response_buffer, None));
		}

		// Otherwise,
		Some((
			response_buffer,
			Some(Box::new(PublishObjectToDo {
				node: self.clone(),
				hash: request.id.clone(),
			})),
		))
	}

	fn needs_object(&self, actor_address: &ActorAddress, id: &IdType) -> bool {
		tokio::task::block_in_place(|| {
			let c = match self.db().connect() {
				Ok(c) => c,
				Err(e) => {
					error!("Unable to connect to database to check object: {}", e);
					return false;
				}
			};
			let has_object = match c.has_object(actor_address, id) {
				Ok(b) => b,
				Err(e) => {
					error!("Unable to check object: {}", e);
					return false;
				}
			};
			!has_object
		})
	}

	fn needs_file(&self, id: &IdType) -> bool {
		tokio::task::block_in_place(|| {
			let c = match self.db().connect() {
				Ok(c) => c,
				Err(e) => {
					error!("Unable to connect to database to check file: {}", e);
					return false;
				}
			};
			let has_object = match c.has_file(id) {
				Ok(b) => b,
				Err(e) => {
					error!("Unable to check file: {}", e);
					return false;
				}
			};
			!has_object
		})
	}

	fn needs_block(&self, id: &IdType) -> bool {
		tokio::task::block_in_place(|| {
			let c = match self.db().connect() {
				Ok(c) => c,
				Err(e) => {
					error!("Unable to connect to database to check block: {}", e);
					return false;
				}
			};
			let has_object = match c.has_block(id) {
				Ok(b) => b,
				Err(e) => {
					error!("Unable to check block: {}", e);
					return false;
				}
			};
			!has_object
		})
	}

	fn verify_block(&self, id: &IdType, data: &[u8]) -> bool {
		let hash = IdType::hash(data);
		id == &hash
	}

	fn verify_file(&self, id: &IdType, file: &File) -> bool {
		let buffer = binserde::serialize(file).unwrap();
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

	fn verify_object(&self, id: &IdType, object: &Object, public_key: &ActorPublicKeyV1) -> bool {
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
		let raw_sign_data = binserde::serialize(&sign_data).unwrap();
		if !public_key.verify(&raw_sign_data, &object.signature) {
			warn!("Object {} is invalid: signature is incorrect.", &id);
			return false;
		}

		let signature_hash = object.signature.hash();
		if &signature_hash != id {
			warn!(
				"Object {} is invalid: id is not a hash of the signature: {}",
				&id, signature_hash,
			);
			return false;
		}
		true
	}

	pub async fn publish_object(
		self: &Arc<Self>, overlay_node: &Arc<OverlayNode>, id: &IdType, object: &Object,
	) {
		let mut iter = self.base.iter_all_fingers().await;
		let mut futs = Vec::new();
		while let Some(finger) = iter.next().await {
			let this = self.clone();
			let overlay_node2 = overlay_node.clone();
			let id2 = id.clone();
			let object2 = object.clone();
			futs.push(async move {
				if let Some((connection, _)) = this.base.select_connection(&finger, None).await {
					this.publish_object_on_connection(overlay_node2, connection, &id2, &object2)
						.await;
				}
			});
		}
		join_all(futs).await;
	}

	pub async fn publish_object_on_connection(
		self: &Arc<Self>, _overlay_node: Arc<OverlayNode>, mut connection: Box<Connection>,
		id: &IdType, object: &Object,
	) {
		if let Some(wants_it) = self
			.exchange_publish_object_on_connection(&mut connection, id)
			.await
		{
			if wants_it {
				let buffer = binserde::serialize(object).unwrap();
				if let Err(e) = connection.send(buffer).await {
					error!(
						"Unable to upload object {} to node {}: {}",
						id,
						connection.their_node_id(),
						e
					);
				}

				// Keep the connection open so that the other side can continue to make
				// requests to us, like downloading any data
				self.base
					.packet_server
					.handle_connection(connection, None)
					.await;
			}
			return;
		}
	}

	/// Processes a new object:
	/// * Stores it in our DB if we don't have it yet.
	/// * Uses the connection to ask for files and blocks as well.
	/// * Starts the synchronization process if we don't have the objects
	///   leading up to this new object.
	async fn process_new_object(
		&self, connection: &mut Connection, id: &IdType, object: &Object,
	) -> db::Result<bool> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db().connect()?;
			c.fetch_head(self.actor_address())
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
					error!("Invalid data received on connection.");
					return Ok(false);
				}
				Ok(true)
			} else {
				Ok(false)
			}
		// If we don't have any objects yet
		} else {
			// If first object, we can immediately 'verify it from start'
			if object.sequence == 0 {
				if id != &self.base.interface.actor_info.first_object {
					error!("Invalid first object received on connection");
					return Ok(false);
				}
			}
			if !self
				.collect_object(connection, id, object, object.sequence == 0)
				.await?
			{
				error!("Invalid data received on connection.");
				return Ok(false);
			}
			Ok(true)
		}
	}

	fn store_block(&self, id: &IdType, data: &[u8]) -> db::Result<()> {
		self.db().perform(|mut c| c.store_block(id, data))
	}

	fn store_file(&self, id: &IdType, file: &File) -> db::Result<()> {
		self.db().perform(|mut c| c.store_file(id, file))
	}

	fn store_object(
		&self, id: &IdType, object: &Object, verified_from_start: bool,
	) -> db::Result<bool> {
		self.db()
			.perform(|mut c| c.store_object(self.actor_address(), id, object, verified_from_start))
	}

	pub async fn synchronize(&self) -> db::Result<()> {
		self.synchronize_objects().await?;
		self.synchronize_files().await?;
		self.synchronize_blocks().await
	}

	pub async fn synchronize_recent_objects_on_connection(&self, connection: &mut Connection) {
		let result = match self.synchronize_head_on_connection(connection).await {
			Ok(r) => r,
			Err(e) => {
				error!(
					"Database error while synchonizing head on connection: {}",
					e
				);
				return;
			}
		};

		if let Some((head, _)) = result {
			let head_sequence = head.sequence;
			let mut i = head_sequence;
			let mut last_object = head;
			while i > 0 && head_sequence - i < 10 {
				i -= 1;
				if !self.has_object_by_sequence(i) {
					match self
						.exchange_find_value_on_connection_and_parse::<FindObjectResult>(
							connection,
							ValueType::Object,
							&last_object.previous_hash,
						)
						.await
					{
						None => break,
						Some(result) => {
							match self
								.collect_object(
									connection,
									&last_object.previous_hash,
									&result.object,
									false,
								)
								.await
							{
								Ok(_) => {}
								Err(e) => {
									error!(
										"Database issue while trying to synchronize object (seq \
										 {}): {}",
										i, e
									);
									return;
								}
							}
							last_object = result.object;
						}
					}
				}
			}
			// TODO: Actually check if the obtained objects are now verified
			// from start.
		}
	}

	pub(super) async fn synchronize_blocks(&self) -> db::Result<()> {
		let missing_blocks = self.investigate_missing_blocks()?;
		for hash in missing_blocks {
			if let Some(result) = self.find_block(&hash).await {
				tokio::task::block_in_place(|| {
					let mut c = self.db().connect()?;
					c.store_block(&hash, &result.data)
				})?;
			}
		}
		Ok(())
	}

	async fn synchronize_head(self: &Arc<Self>, fingers: &[NodeContactInfo]) -> db::Result<()> {
		for finger in fingers {
			if let Some((mut connection, _)) =
				self.base.select_direct_connection(&finger, None).await
			{
				if let Err(e) = self.synchronize_head_on_connection(&mut connection).await {
					error!("Database issue with synchronizing head: {}", e);
				}
			}
		}
		Ok(())
	}

	async fn synchronize_head_on_connection(
		&self, connection: &mut Connection,
	) -> db::Result<Option<(Object, bool)>> {
		if let Some(response) = self.exchange_head_on_connection(connection).await {
			let result = self
				.process_new_object(connection, &response.hash, &response.object)
				.await?;
			return Ok(Some((response.object, result)));
		}
		Ok(None)
	}

	pub(super) async fn synchronize_files(&self) -> db::Result<()> {
		let missing_files = self.investigate_missing_files()?;
		for hash in missing_files {
			if let Some(result) = self.find_file(&hash).await {
				tokio::task::block_in_place(|| {
					let mut c = self.db().connect()?;
					c.store_file(&hash, &result.file)
				})?;
			}
		}
		Ok(())
	}

	#[allow(dead_code)]
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
			c.fetch_last_verified_object(self.actor_address())
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
								self.actor_address(),
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
									c.delete_object(self.actor_address(), &hash)?;
									Ok(true)
								} else {
									last_known_object_sequence += 1;
									last_known_object_id = hash.clone();
									if !verified_from_start {
										c.update_object_verified(self.actor_address(), &hash)?;
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
	pub fn start_synchronization(self: &Arc<Self>) -> bool {
		if !self.is_synchonizing.swap(true, Ordering::Acquire) {
			let this = self.clone();
			spawn(async move {
				let result = this.synchronize().await;
				this.is_synchonizing.store(false, Ordering::Release);
				if let Err(e) = result {
					error!(
						"Error occurred during synchronization for actor {:?}: {:?}",
						this.actor_address(),
						e
					);
				}
			});
			true
		} else {
			false
		}
	}

	#[allow(dead_code)]
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

impl PublishObjectToDo {
	async fn receive_object(
		&self, c: &mut Connection, object_id: &IdType, public_key: &ActorPublicKeyV1,
	) -> Option<Object> {
		let buffer = match c.receive().await {
			Ok(v) => Arc::new(v),
			Err(e) => {
				error!("Unable to download object data: {}", e);
				return None;
			}
		};
		let upload: PublishObjectMessage = match binserde::deserialize(&buffer) {
			Ok(r) => r,
			Err(e) => {
				warn!("Object upload message was malformed: {}", e);
				return None;
			}
		};

		if !self
			.node
			.verify_object(&object_id, &upload.object, public_key)
		{
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
}

#[async_trait]
impl MessageWorkToDo for PublishObjectToDo {
	async fn run(&mut self, mut connection: Box<Connection>) -> Result<Option<Box<Connection>>> {
		let public_key = &self.node.base.interface.actor_info.public_key;
		let object_result = self
			.receive_object(&mut connection, &self.hash, public_key)
			.await;

		// Forget we were downloading this object
		let mut downloading_objects = self.node.downloading_objects.lock().await;
		if let Some(p) = downloading_objects.iter().position(|i| i == &self.hash) {
			downloading_objects.remove(p);
		}

		// Store & rebroadcast object if needed
		if let Some(object) = object_result {
			let this = self.node.clone();
			if let Err(e) = this
				.process_new_object(&mut connection, &self.hash, &object)
				.await
			{
				error!("Database error while processing new object: {}", e);
				return Ok(None);
			}
		}

		Ok(Some(connection))
	}
}

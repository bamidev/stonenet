use std::{
	net::SocketAddr,
	sync::{
		atomic::{AtomicBool, AtomicPtr, Ordering},
		Arc, Mutex as StdMutex,
	},
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use futures::{
	future::{join_all, BoxFuture},
	FutureExt,
};
use log::{error, warn};
use sea_orm::{prelude::*, ActiveValue::*};
use serde::de::DeserializeOwned;
use tokio::{spawn, time::sleep};

use super::{
	binserde,
	message::{
		FindBlockResult, FindFileResult, FindNextObjectResult, FindObjectResult, GetProfileRequest,
		GetProfileResponse, HeadResponse, PublishObjectMessage, PublishObjectRequest,
		PublishObjectResponse,
	},
	node::{ContactStrategyMethod, Node, NodeInterface},
	overlay::OverlayNode,
	sstp::{self, Connection, MessageProcessorResult, MessageWorkToDo, Result},
};
use crate::{
	common::*,
	core::*,
	db::{self, Database, PersistenceHandle},
	entity::{block, object},
	identity::ActorPublicKeyV1,
	net::{message::BlogchainValueType, NodeContactInfo},
	trace::Mutex,
};

pub const ACTOR_MESSAGE_TYPE_HEAD_REQUEST: u8 = 64;
pub const ACTOR_MESSAGE_TYPE_HEAD_RESPONSE: u8 = 65 | 0x80;
pub const ACTOR_MESSAGE_TYPE_GET_PROFILE_REQUEST: u8 = 66;
pub const ACTOR_MESSAGE_TYPE_GET_PROFILE_RESPONSE: u8 = 67 | 0x80;
pub const ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_REQUEST: u8 = 70;
pub const ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_RESPONSE: u8 = 71 | 0x80;

/// The amount of recent objects to always store for an actor.
pub const ACTOR_LIMIT_RECENT_OBJECTS: u64 = 1_000;
/// The amount of recent objects to always store its files (including its
/// blocks) for. The garbage collector will not clean up the files and blocks
/// for these objects
pub const ACTOR_LIMIT_RECENT_OBJECTS_FILES: u64 = 1_000;
/// The max amount of objects to keep at minimum for an actor.
/// This should equate to about 3-4MB of disk space.
pub const ACTOR_MIN_LIMIT_TOTAL_OBJECTS: u64 = 10_000;
/// The max amount of files to keep at minimum for an actor.
/// This should equate to about 1MB of disk space.
pub const ACTOR_MIN_LIMIT_TOTAL_FILES: u64 = 10_000;
/// The max amount of bytes of blocks (excluding their meta data) to keep at
/// minimum for an actor.
pub const ACTOR_MIN_LIMIT_TOTAL_BLOCK_SPACE: u64 = 100_000_000;

pub struct ActorNode {
	pub(super) base: Arc<Node<ActorInterface>>,
	downloading_objects: Mutex<Vec<IdType>>,
	is_synchonizing: Arc<AtomicBool>,
}

pub struct ActorInterface {
	overlay_node: Arc<OverlayNode>,
	db: Database,
	actor_address: ActorAddress,
	actor_id: i64,
	actor_info: ActorInfo,
	head_sequence: StdMutex<Option<u64>>,
	is_lurker: bool,
}

struct PublishObjectToDo {
	node: Arc<ActorNode>,
	hash: IdType,
}

impl ActorInterface {
	async fn find_block(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = block::Entity::find()
			.filter(block::Column::Hash.eq(id))
			.one(self.db.inner())
			.await?;

		if let Some(record) = result {
			let response = FindBlockResult {
				data: record.data.into(),
			};
			Ok(Some(binserde::serialize(&response).unwrap()))
		} else {
			Ok(None)
		}
	}

	async fn find_file(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect_old()?;
			c.fetch_file(id)
		})?;
		Ok(result.map(|file| binserde::serialize(&file).unwrap()))
	}

	async fn find_object(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect_old()?;
			c.fetch_object(id)
		})?;
		Ok(result.map(|(object, _)| binserde::serialize(&FindObjectResult { object }).unwrap()))
	}

	async fn find_next_object(&self, id: &IdType) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let mut c = self.db.connect_old()?;
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
		const VALUE_TYPE_BLOCK: u8 = BlogchainValueType::Block as _;
		const VALUE_TYPE_FILE: u8 = BlogchainValueType::File as _;
		const VALUE_TYPE_OBJECT: u8 = BlogchainValueType::Object as _;
		const VALUE_TYPE_NEXT_OBJECT: u8 = BlogchainValueType::NextObject as _;
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

	fn overlay_node(&self) -> Arc<OverlayNode> {
		self.overlay_node.clone()
	}

	fn prepare(&self, message_type: u8, buffer: &[u8]) -> Vec<u8> {
		let mut new_buffer = Vec::with_capacity(1 + 32 + buffer.len());
		new_buffer.push(message_type | 0x80);
		new_buffer.extend(self.actor_address.as_id().as_bytes());
		new_buffer.push(self.is_lurker as u8);
		new_buffer.extend(buffer);
		new_buffer
	}
}

impl ActorNode {
	pub fn actor_address(&self) -> &ActorAddress {
		&self.base.interface.actor_address
	}

	pub async fn close(self: Arc<Self>) {
		self.base.close().await;
	}

	/// Attempts to collect as much blocks of this file on the given connection.
	pub async fn collect_block(
		&self, connection: &mut Connection, file_id: i64, block_id: &IdType,
	) -> db::Result<bool> {
		if let Some(result) = self
			.exchange_find_block_on_connection(connection, block_id)
			.await
		{
			if self.verify_block(block_id, &result.data) {
				self.store_block(file_id, block_id, &result.data)?;
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
				let file_id = self.store_file(file_id, &result.file)?;

				for sequence in 0..result.file.blocks.len() {
					let block_id = &result.file.blocks[sequence];
					if self.needs_block(block_id) {
						if !self.collect_block(connection, file_id, block_id).await? {
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

	pub async fn collect_object(
		self: &Arc<Self>, connection: &mut Connection, hash: &IdType,
	) -> db::Result<Option<(BlogchainObject, bool)>> {
		if let Some(result) = self
			.exchange_find_object_on_connection(connection, hash)
			.await
		{
			self.store_object(hash, &result.object, false)?;
			let completed = self
				.complete_object(connection, result.object.clone())
				.await?;
			Ok(Some((result.object, completed)))
		} else {
			Ok(None)
		}
	}

	/// Attempts to collect as much files and their blocks on the given
	/// connection.
	pub(super) fn complete_object<'a, 'b: 'a>(
		self: &'a Arc<Self>, connection: &'b mut Connection, object: BlogchainObject,
	) -> BoxFuture<'a, db::Result<bool>> {
		async move {
			match object.payload {
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
				ObjectPayload::HomeFile(_) => {
					error!("Home file objects are not implemented yet.");
				}
				ObjectPayload::Post(payload) => {
					match &payload.data {
						PostObjectCryptedData::Plain(plain) => {
							for hash in &plain.files {
								if self.needs_file(&hash) {
									if !self.collect_file(connection, &hash).await? {
										return Ok(false);
									}
								}
							}
						}
					}

					// If the post is a reply, also collect the object it replied to.
					if let PostObjectCryptedData::Plain(plain) = &payload.data {
						if let Some((actor_address, object_hash)) = &plain.in_reply_to {
							if actor_address == self.actor_address() {
								self.collect_object(connection, object_hash).await?;
							} else {
								self.spawn_collect_object_from_other_network(
									actor_address.clone(),
									object_hash.clone(),
								);
							};
						}
					}
				}
			}
			Ok(true)
		}
		.boxed()
	}

	fn db(&self) -> &db::Database {
		&self.base.db
	}

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
		self.exchange_find_value_on_connection_and_parse(connection, BlogchainValueType::Block, id)
			.await
	}

	pub async fn exchange_find_file_on_connection(
		&self, connection: &mut Connection, id: &IdType,
	) -> Option<FindFileResult> {
		self.exchange_find_value_on_connection_and_parse(connection, BlogchainValueType::File, id)
			.await
	}

	pub async fn exchange_find_object_on_connection(
		&self, connection: &mut Connection, id: &IdType,
	) -> Option<FindObjectResult> {
		self.exchange_find_value_on_connection_and_parse(connection, BlogchainValueType::Object, id)
			.await
	}

	async fn exchange_find_value_on_connection_and_parse<V>(
		&self, connection: &mut Connection, value_type: BlogchainValueType, id: &IdType,
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
	) -> Option<(IdType, BlogchainObject)> {
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
		let result: Box<FindBlockResult> = self
			.find_value(BlogchainValueType::Block, id, 100, false)
			.await?;
		Some(*result)
	}

	pub async fn find_file(&self, id: &IdType) -> Option<FindFileResult> {
		let result: Box<FindFileResult> = self
			.find_value(BlogchainValueType::File, id, 100, false)
			.await?;
		Some(*result)
	}

	pub async fn find_next_object(&self, id: &IdType) -> Option<FindNextObjectResult> {
		let result: Box<FindNextObjectResult> = self
			.find_value(BlogchainValueType::NextObject, id, 100, false)
			.await?;

		Some(*result)
	}

	pub async fn find_object(&self, id: &IdType) -> Option<FindObjectResult> {
		let result: Box<FindObjectResult> = self
			.find_value(BlogchainValueType::Object, id, 100, false)
			.await?;
		Some(*result)
	}

	async fn find_value<V>(
		&self, value_type: BlogchainValueType, id: &IdType, hop_limit: usize,
		only_narrow_down: bool,
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
			let c = self.db().connect_old().expect("unable to open database");
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

		// Do the work of synchronizing all missing data.
		self.start_synchronization();
	}

	pub async fn initialize_with_connection(self: &Arc<Self>, mut connection: Box<Connection>) {
		if let Err(e) = self.synchronize_head_on_connection(&mut connection).await {
			error!("Unable to initialize with connection: {:?}", e);
		}
	}

	/// Returns a list of block hashes that we'd like to have.
	fn investigate_missing_blocks(&self) -> db::Result<Vec<(i64, IdType)>> {
		tokio::task::block_in_place(|| {
			let c = self.db().connect_old()?;
			c.fetch_missing_file_blocks()
		})
	}

	async fn object_missing_files(&self, object: &ObjectPayload) -> db::Result<Vec<IdType>> {
		let results = match object {
			ObjectPayload::Profile(payload) => {
				let capacity = payload.avatar.is_some() as usize
					+ payload.wallpaper.is_some() as usize
					+ payload.description.is_some() as usize;
				let mut results = Vec::with_capacity(capacity);
				if let Some(file_hash) = payload.avatar.as_ref() {
					if !self.db().has_file(file_hash).await? {
						results.push(file_hash.clone());
					}
				}
				if let Some(file_hash) = payload.wallpaper.as_ref() {
					if !self.db().has_file(file_hash).await? {
						results.push(file_hash.clone());
					}
				}
				results
			}
			ObjectPayload::Post(payload) => match &payload.data {
				PostObjectCryptedData::Plain(plain) => {
					let mut results = Vec::with_capacity(plain.files.len());
					for file_hash in &plain.files {
						if !self.db().has_file(file_hash).await? {
							results.push(file_hash.clone());
						}
					}
					results
				}
			},
			ObjectPayload::HomeFile(payload) => {
				payload.hash.clone().map(|h| vec![h]).unwrap_or(Vec::new())
			}
		};
		Ok(results)
	}

	/// Returns a list of file hashes that we'd like to have based on the
	/// already stored objects.
	async fn investigate_missing_files(
		&self, head: &BlogchainObject, object_limit: u64, file_limit: u64,
	) -> db::Result<Vec<IdType>> {
		let mut results = Vec::new();
		let start = if head.sequence >= object_limit {
			head.sequence - object_limit
		} else {
			0
		};

		for seq in start..head.sequence {
			for object in self
				.db()
				.find_objects_by_sequence2(self.base.interface.actor_id, seq)
				.await?
			{
				// TODO: If the amount of files found exceeds the file_limit, only insert the
				// hashes up to the limit and don't let it go over only to shrink the array
				// later.
				if results.len() < file_limit as usize {
					let payload = self
						.db()
						.load_object_payload(object.id, object.r#type)
						.await?
						.unwrap();
					results.extend(self.object_missing_files(&payload).await?);
				} else {
					results.resize_with(file_limit as _, || IdType::default());
					return Ok(results);
				}
			}
		}
		Ok(results)
	}

	#[allow(dead_code)]
	fn investigate_missing_object_files(
		&self, object: &BlogchainObject,
	) -> db::Result<Vec<IdType>> {
		tokio::task::block_in_place(|| {
			let c = self.db().connect_old()?;
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
					PostObjectCryptedData::Plain(plain) => {
						for file_hash in &plain.files {
							if !c.has_file(&file_hash)? {
								results.push(file_hash.clone());
							}
						}
					}
				},
				ObjectPayload::HomeFile(payload) => {
					if let Some(hash) = &payload.hash {
						results.push(hash.clone());
					}
				}
			}
			Ok(results)
		})
	}

	pub async fn join_network_starting_with_connection(
		self: &Arc<Self>, mut connection: Box<Connection>,
	) -> Option<bool> {
		let response = self
			.base
			.exchange_find_node_on_connection(&mut connection, &self.base.node_id().as_id())
			.await?;
		let mut fingers = response.fingers.clone();
		fingers.push(connection.their_node_info().clone());

		// If there is one or more fingers that do not require relaying, the node will
		// synchronize by using the whole network. If there are only nodes that require
		// communication via a relay, we savor the open connection and use it to
		// synchronize at least the latest 10 objects.
		if !fingers.iter().any(|f| {
			if let Some(strategy) = self.base.pick_contact_strategy(&f.contact_info) {
				&f.address != &self.base.address && strategy.method != ContactStrategyMethod::Relay
			} else {
				false
			}
		}) {
			self.initialize_with_connection(connection).await;
			return Some(false);
		}

		let neighbours = self
			.base
			.find_node_from_fingers(&self.base.node_id().as_id(), &fingers, 4, 100)
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
			let c = self
				.db()
				.connect_old()
				.expect("unable to connect to database");
			c.fetch_identity(self.actor_address())
				.expect("unable to load identity for actor node")
				.expect("no identity for actor node")
		});
		match actor_info {
			ActorInfo::V1(ai) => ai.public_key,
		}
	}

	pub fn new(
		stop_flag: Arc<AtomicBool>, overlay_node: Arc<OverlayNode>, node_id: NodeAddress,
		socket: Arc<sstp::Server>, actor_address: ActorAddress, actor_id: i64,
		actor_info: ActorInfo, db: Database, bucket_size: usize, leak_first_request: bool,
		is_lurker: bool,
	) -> Self {
		let interface = ActorInterface {
			overlay_node,
			db: db.clone(),
			actor_id,
			actor_info,
			// TODO: Load head sequence from parameter in new, and create an async method `load`
			// that does the same as `new` except it also loads the head_sequence from DB
			head_sequence: StdMutex::new(
				db.perform(|c| c.fetch_head(&actor_address))
					.unwrap()
					.map(|o| o.1.sequence),
			),
			actor_address,
			is_lurker,
		};
		Self {
			is_synchonizing: Arc::new(AtomicBool::new(false)),
			base: Arc::new(Node::new(
				stop_flag,
				db,
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
			let c = self.db().connect_old()?;
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

	/// After a new head is received and stored, will try to synchronize any
	/// files & blocks for it, as well as any missing objects.
	async fn process_new_head_on_connection(
		self: &Arc<Self>, connection: &mut Connection, hash: &IdType, head: BlogchainObject,
	) -> db::Result<()> {
		self.collect_object(connection, hash).await?;
		self.synchronize_missed_objects_on_connection(connection, head)
			.await?;
		Ok(())
	}

	pub(super) async fn process_request(
		self: &Arc<Self>, message_type: u8, buffer: &[u8], addr: &SocketAddr,
		_node_info: &NodeContactInfo,
	) -> MessageProcessorResult {
		match message_type {
			ACTOR_MESSAGE_TYPE_HEAD_REQUEST => self.process_head_request(buffer).await,
			ACTOR_MESSAGE_TYPE_GET_PROFILE_REQUEST => {
				self.process_get_profile_request(buffer).await
			}
			ACTOR_MESSAGE_TYPE_PUBLISH_OBJECT_REQUEST => {
				self.process_publish_object_request(buffer, addr).await
			}
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
			let c = match self.db().connect_old() {
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
			let c = match self.db().connect_old() {
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
			let c = match self.db().connect_old() {
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
			let c = match self.db().connect_old() {
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

	fn verify_object(
		&self, id: &IdType, object: &BlogchainObject, public_key: &ActorPublicKeyV1,
	) -> bool {
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

	async fn republish_object(
		self: &Arc<Self>, overlay_node: &Arc<OverlayNode>, id: &IdType, object: &BlogchainObject,
		source_node_id: &IdType,
	) {
		if let Some(bucket_offset) = self.base.differs_at_bit(source_node_id) {
			self.publish_object(overlay_node, id, object, &[], bucket_offset)
				.await;
		} else {
			debug_assert!(false, "Republishing an object received from ourselves.");
		}
	}

	pub async fn publish_object(
		self: &Arc<Self>, overlay_node: &Arc<OverlayNode>, id: &IdType, object: &BlogchainObject,
		skip_node_ids: &[NodeAddress], bucket_offset: u8,
	) {
		// TODO: When republishing, only publish the object to nodes below the sender's
		// bit position on the binary tree.
		let mut iter = self.base.iter_all_fingers_top_down(bucket_offset).await;
		let mut futs = Vec::new();
		while let Some(finger) = iter.next().await {
			if skip_node_ids.contains(&finger.address) {
				continue;
			}

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
		id: &IdType, object: &BlogchainObject,
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

	fn spawn_collect_object_from_other_network(
		self: &Arc<Self>, actor_address: ActorAddress, object_hash: IdType,
	) {
		let this = self.clone();
		spawn(async move {
			if let Some(actor_node) = this
				.base
				.overlay_node()
				.get_actor_node_or_lurker(&actor_address)
				.await
			{
				// Find the object on the network
				if let Some(result) = actor_node.find_object(&object_hash).await {
					let result = async {
						if actor_node.store_object(&object_hash, &result.object, false)? {
							// If found, collect all files & blocks on the network as well.
							actor_node
								.synchronize_files_and_blocks_of_object(&result.object.payload)
								.await?;
						}
						db::Result::Ok(())
					};
					if let Err(e) = result.await {
						error!(
							"Database error while synchronizing object, files & blocks with actor \
							 network {}: {:?}",
							actor_address, e
						);
					}
				} else {
					warn!(
						"Object {} not found on actor network {}.",
						object_hash, actor_address
					);
				}
			}
		});
	}

	fn store_block(&self, file_id: i64, id: &IdType, data: &[u8]) -> db::Result<()> {
		self.db().perform(|mut c| c.store_block(file_id, id, data))
	}

	fn store_file(&self, id: &IdType, file: &File) -> db::Result<i64> {
		self.db().perform(|mut c| c.store_file(id, file))
	}

	fn store_object(
		&self, id: &IdType, object: &BlogchainObject, verified_from_start: bool,
	) -> db::Result<bool> {
		self.db()
			.perform(|mut c| c.store_object(self.actor_address(), id, object, verified_from_start))
	}

	/// Does everything needed to make sure a node is up to date with the rest
	/// of the network. Invoke this periodically.
	pub async fn synchronize(self: &Arc<Self>) -> db::Result<()> {
		// TODO: Use a iterator that goes over all fingers but with the topmost fingers
		// first instead of the local ones, and then stop when we've had 4 responses.
		let head_opt =
			if let Some((head_hash, newest_head, up_to_date_nodes, a_node_was_behind, updated)) =
				self.synchronize_head().await?
			{
				// Synchronize any files & blocks that we've not yet gotten from the node that
				// we got the head of
				self.synchronize_files_and_blocks_of_object(&newest_head.payload)
					.await?;

				// (Re-)publish head among network if one of our neighbours was behind
				if a_node_was_behind {
					let this = self.clone();
					let object = newest_head.clone();
					let head_hash2 = head_hash.clone();
					spawn(async move {
						this.publish_object(
							&this.base.overlay_node(),
							&head_hash2,
							&object,
							&up_to_date_nodes,
							0,
						)
						.await
					});
				}

				// If a new head was found, update the timestamp so that the most recent object
				// actually shows up as the most recent object on your feed
				if updated {
					let mut m = <object::ActiveModel as Default>::default();
					m.found = Set(current_timestamp() as _);
					object::Entity::update_many()
						.set(m)
						.filter(object::Column::Hash.eq(&head_hash))
						.exec(self.db().inner())
						.await?;
				}

				Some(newest_head)
			} else {
				None
			};

		// Try to sychronize objects from the start of the blogchain so that we may be
		// able to set the verify_from_start flag on objects.
		self.synchronize_objects_from_start().await?;
		if let Some(head) = &head_opt {
			self.synchronize_objects_from_head(head, ACTOR_LIMIT_RECENT_OBJECTS)
				.await?;
			// Synchronize any file and block that we need but don't have yet
			self.synchronize_files(
				head,
				ACTOR_LIMIT_RECENT_OBJECTS,
				ACTOR_LIMIT_RECENT_OBJECTS_FILES,
			)
			.await?;
			self.synchronize_blocks().await?;
		}

		Ok(())
	}

	pub async fn synchronize_files_and_blocks_of_object(
		self: &Arc<Self>, payload: &ObjectPayload,
	) -> db::Result<()> {
		let files = self.object_missing_files(payload).await?;
		// TODO: Instead of searching for missing files, just return all files of this
		// object because this function is only used to try to complete an object that
		// just has been received.

		for file_hash in files {
			// TODO: Use collect_file on the same connection that found the file to collect
			// the blocks where they are likely to be.
			let (file_id, file) = if let Some(result) = self.db().find_file(&file_hash).await? {
				result
			} else {
				if let Some(result) = self.find_file(&file_hash).await {
					let file_id = self.store_file(&file_hash, &result.file)?;
					(file_id, result.file)
				} else {
					continue;
				}
			};

			// Find missing blocks
			for block_hash in file.blocks {
				if !self.db().has_block(&block_hash).await? {
					if let Some(result) = self.find_block(&block_hash).await {
						self.store_block(file_id, &block_hash, &result.data)?;
					}
				}
			}
		}
		Ok(())
	}

	/// Given our own head info, this will utilize the connection to collect as
	/// many of our missing objects (including their files and blocks) as
	/// possible.
	pub async fn synchronize_missed_objects_on_connection(
		self: &Arc<Self>, connection: &mut Connection, up_to_object: BlogchainObject,
	) -> db::Result<()> {
		let up_to_sequence = up_to_object.sequence;
		let mut i = up_to_object.sequence as i128;
		let mut last_object = up_to_object;

		while i > 0 && (up_to_sequence - i as u64) < ACTOR_LIMIT_RECENT_OBJECTS {
			i -= 1;
			if !self.has_object_by_sequence(i as u64) {
				match self
					.collect_object(connection, &last_object.previous_hash)
					.await?
				{
					None => break,
					Some((object, _)) => last_object = object,
				}
			// Stop if we closed the gap
			} else {
				break;
			}
		}
		// TODO: Actually check if the obtained objects are now verified
		// from start.
		Ok(())
	}

	pub(super) async fn synchronize_blocks(&self) -> db::Result<()> {
		let missing_blocks = self.investigate_missing_blocks()?;
		for (file_id, hash) in missing_blocks {
			if let Some(result) = self.find_block(&hash).await {
				tokio::task::block_in_place(|| {
					let mut c = self.db().connect_old()?;
					c.store_block(file_id, &hash, &result.data)
				})?;
			}
		}
		Ok(())
	}

	/// Contacts a few nodes and checks what they consider the head of the
	/// blogchain.
	/// Returns the hash and data of the newest head that has been found, even
	/// if it was our own. And it also returns a list of node ids of the nodes
	/// which are already up to date.
	async fn synchronize_head(
		self: &Arc<Self>,
	) -> db::Result<Option<(IdType, BlogchainObject, Vec<NodeAddress>, bool, bool)>> {
		let mut up_to_date_nodes = Vec::with_capacity(4);
		let our_head_info = self.db().perform(|c| c.fetch_head(self.actor_address()))?;
		let our_head_sequence = if let Some((_, o, _)) = &our_head_info {
			*self.base.interface.head_sequence.lock().unwrap() = Some(o.sequence);
			o.sequence as i128
		} else {
			-1i128
		};
		let (mut latest_hash, mut latest_object) = our_head_info
			.as_ref()
			.map(|(h, o, _)| (h.clone(), Some(o.clone())))
			.unwrap_or((IdType::default(), None));
		let mut a_node_is_behind = true;
		let mut updated = false;

		let mut iter = self.base.iter_all_fingers_top_down(0).await;
		let mut checked = 0u8;
		while let Some(finger) = iter.next().await {
			if let Some((mut connection, _)) =
				self.base.select_direct_connection(&finger, None).await
			{
				match self.synchronize_head_on_connection(&mut connection).await {
					Err(e) => error!("Database issue with synchronizing head: {}", e),
					Ok(r) => {
						if let Some((hash, object)) = r {
							checked += 1;
							let mut is_newer = object.sequence as i128 > our_head_sequence;

							// If the object is the same as our head, nothing will need to happen
							if object.sequence as i128 == our_head_sequence {
								// But if the sequence is the same but the hash different, it may
								// have been overwritten
								if let Some((our_head_hash, our_head, _)) = &our_head_info {
									if our_head_hash != &hash {
										if object.created < our_head.created {
											a_node_is_behind = true;
										} else if object.created > our_head.created {
											is_newer = true;
										}
									}
								}
							}

							// If the head object we've gotten is newer, remember it and whoever
							// already has it
							if is_newer {
								if let Some(other_latest) = &latest_object {
									if other_latest.sequence < object.sequence {
										latest_object = Some(object);
										latest_hash = hash;
										up_to_date_nodes = vec![finger.address.clone(); 1];
										updated = true;
									} else if other_latest.sequence == object.sequence {
										up_to_date_nodes.push(finger.address.clone());
									}
								} else {
									latest_object = Some(object);
									latest_hash = hash;
									up_to_date_nodes = vec![finger.address.clone(); 1];
									updated = true;
								}
							}

							// Only check up to 4 nodes
							if checked == 4 {
								break;
							}
						}
					}
				}
			}
		}

		Ok(latest_object.map(|o| (latest_hash, o, up_to_date_nodes, a_node_is_behind, updated)))
	}

	/// Checks the peer for their head object.
	/// If we didn't have it yet, store it and collect all files, blocks &
	/// previous objects.
	async fn synchronize_head_on_connection(
		self: &Arc<Self>, connection: &mut Connection,
	) -> db::Result<Option<(IdType, BlogchainObject)>> {
		if let Some(response) = self.exchange_head_on_connection(connection).await {
			let stored = self.db().perform(|mut c| {
				c.store_object(
					self.actor_address(),
					&response.hash,
					&response.object,
					false,
				)
			})?;

			if stored {
				self.process_new_head_on_connection(
					connection,
					&response.hash,
					response.object.clone(),
				)
				.await?;
				return Ok(Some((response.hash, response.object)));
			}
		}
		Ok(None)
	}

	pub(super) async fn synchronize_files(
		&self, head: &BlogchainObject, object_limit: u64, file_limit: u64,
	) -> db::Result<()> {
		let missing_files = self
			.investigate_missing_files(head, object_limit, file_limit)
			.await?;
		for hash in missing_files {
			if let Some(result) = self.find_file(&hash).await {
				tokio::task::block_in_place(|| {
					let mut c = self.db().connect_old()?;
					c.store_file(&hash, &result.file)
				})?;
			}
		}
		Ok(())
	}

	#[allow(dead_code)]
	async fn synchronize_object(
		&self, connection: &mut Connection, object: &BlogchainObject,
	) -> db::Result<()> {
		let missing_files = self.investigate_missing_object_files(object)?;
		for file_id in &missing_files {
			self.collect_file(connection, file_id).await?;
		}
		Ok(())
	}

	/// Attempts to synchonize the few objects before our known head object
	async fn synchronize_objects_from_head(
		&self, head: &BlogchainObject, count: u64,
	) -> db::Result<bool> {
		let stop_sequence = if head.sequence as u64 >= count {
			head.sequence as u64 - count
		} else {
			0
		};

		let mut current_sequence: u64;
		let mut previous_hash = head.previous_hash.clone();
		loop {
			if let Some((previous_object, _)) =
				self.db().perform(|c| c.fetch_object(&previous_hash))?
			{
				current_sequence = previous_object.sequence;
				previous_hash = previous_object.previous_hash;
			} else {
				if let Some(result) = self.find_object(&previous_hash).await {
					self.store_object(&previous_hash, &result.object, false)?;
					current_sequence = result.object.sequence;
					previous_hash = result.object.previous_hash;
				} else {
					return Ok(false);
				}
			}

			if current_sequence <= stop_sequence {
				debug_assert_eq!(current_sequence, stop_sequence);
				return Ok(true);
			}
		}
	}

	/// Iteratively search the network for object meta data.
	async fn synchronize_objects_from_start(&self) -> db::Result<bool> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db().connect_old()?;
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
							if !self.store_object(
								&self.base.interface.actor_info.first_object,
								&object_result.object,
								true,
							)? {
								return Ok(false);
							}
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
							let mut c = self.db().connect_old()?;
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
				if let Err(e) = result {
					error!(
						"Error occurred during synchronization for actor {:?}: {:?}",
						this.actor_address(),
						e
					);
				}
				this.is_synchonizing.store(false, Ordering::Release);
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
	) -> Option<BlogchainObject> {
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

		// Store object
		let stored = if let Some(object) = &object_result {
			match self.node.db().perform(|mut c| {
				c.store_object(self.node.actor_address(), &self.hash, object, false)
			}) {
				Ok(r) => r,
				Err(e) => {
					error!("Unable to store received object: {:?}", e);
					false
				}
			}
		} else {
			false
		};

		// Forget we were downloading this object after it is stored
		{
			let mut downloading_objects = self.node.downloading_objects.lock().await;
			if let Some(p) = downloading_objects.iter().position(|i| i == &self.hash) {
				downloading_objects.remove(p);
			}
		}

		if stored {
			let object = object_result.unwrap();
			if let Err(e) = self
				.node
				.process_new_head_on_connection(&mut connection, &self.hash, object.clone())
				.await
			{
				error!("Database error while processing new head: {}", e);
				return Ok(None);
			}

			// Republish object if it was newer than our head
			let guard = self.node.base.interface.head_sequence.lock().unwrap();
			if let Some(our_head_sequence) = &*guard {
				if *our_head_sequence < object.sequence {
					drop(guard);

					let hash = self.hash.clone();
					let node = self.node.clone();
					let source_node_id = connection.their_node_id().clone();
					spawn(async move {
						node.republish_object(
							&node.base.overlay_node(),
							&hash,
							&object,
							&source_node_id.as_id(),
						)
						.await;
					});
				}
			}
		}

		Ok(Some(connection))
	}
}

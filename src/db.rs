/// This module contains all functions to get objects, files & blocks from - and into the database.
///
/// Some functions are placed within the `Database` handle, some in the `Transaction` handle, and
/// some in both.
/// Anything that needs to be done with multiple SQL queries needs to be done inside a transaction,
/// because the transaction also locks the database.
mod install;

use std::{cmp::min, fmt, net::SocketAddr, ops::*, path::*, str, time::Duration};

use async_trait::async_trait;
use chacha20::{
	cipher::{KeyIvInit, StreamCipher},
	ChaCha20,
};
use generic_array::{typenum::U12, GenericArray};
use log::*;
use rusqlite::{
	params,
	types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, Value, ValueRef},
	ToSql,
};
use sea_orm::{prelude::*, sea_query::*, *};
use thiserror::Error;
use unsafe_send_sync::UnsafeSendSync;

use crate::{
	common::*,
	compression::{compress, decompress, mime_type_use_compression},
	core::*,
	entity::*,
	identity::*,
	net::binserde,
	serde_limit::LimString,
	trace::{self, *},
	web::info::*,
};

pub(crate) const BLOCK_SIZE: usize = 0x1000000; // 16 MiB

#[derive(Clone)]
pub struct Database {
	path: PathBuf,
	orm: DatabaseConnection,
}

#[deprecated]
pub struct Connection {
	// The documentation of rusqlite mentions that the Connection struct does
	// not need a mutex, that it is already thread-safe. For some reason it was
	// not marked as Send and Sync.
	old: UnsafeSendSync<rusqlite::Connection>,
}

// TODO: Make the sea_orm::DatabaseTransaction inside private
pub struct Transaction(pub(crate) sea_orm::DatabaseTransaction);

#[derive(Debug, Error)]
pub enum Error {
	/// Sqlite error
	DecompressDecodeError(i32),
	OrmError(sea_orm::DbErr),
	SqliteError(rusqlite::Error),

	ActorAddress(FromBytesAddressError),
	InvalidCompressionType(u8),
	InvalidObjectType(u8),
	/// An invalidhash has been found in the database
	InvalidHash(IdFromBase58Error),
	InvalidSignature(NodeSignatureError),
	InvalidPrivateKey(usize),
	InvalidPublicKey,
	/// The data that is stored for a block is corrupt
	BlockDataCorrupt(i64),
	BlockDataInvalidSize(IdType, usize, usize),
	//PostMissingFiles(i64),
	FileMissingBlock(i64, u32),
	FileWithoutBlocks(i64),

	MissingIdentity(ActorAddress),
	/// Something in the database is not how it is expected to be.
	UnexpectedState(String),
}

pub trait DerefConnection: Deref<Target = rusqlite::Connection> {}
impl<T> DerefConnection for T where T: Deref<Target = rusqlite::Connection> {}

pub type Result<T> = trace::Result<T, self::Error>;

#[async_trait]
pub trait PersistenceHandle {
	type Inner: ConnectionTrait;

	fn inner(&self) -> &Self::Inner;

	fn backend(&self) -> DatabaseBackend {
		self.inner().get_database_backend()
	}

	async fn clear_trusted_nodes_except(
		&self, trusted_nodes_ids: impl IntoIterator<Item = i64> + Send + std::fmt::Debug,
	) -> Result<()> {
		trusted_node::Entity::delete_many()
			.filter(
				Expr::col((trusted_node::Entity, trusted_node::Column::Id))
					.is_not_in(trusted_nodes_ids),
			)
			.exec(self.inner())
			.await?;
		Ok(())
	}

	async fn ensure_actor_id(&self, address: &ActorAddress, info: &ActorInfo) -> Result<i64> {
		if let Some(record) = actor::Entity::find()
			.filter(actor::Column::Address.eq(address))
			.one(self.inner())
			.await?
		{
			Ok(record.id)
		} else {
			let model = actor::ActiveModel {
				id: NotSet,
				address: Set(address.clone()),
				public_key: Set(info.public_key.clone().to_bytes().to_vec()),
				first_object: Set(info.first_object.clone()),
				r#type: Set(info.actor_type.clone().into()),
			};
			Ok(actor::Entity::insert(model)
				.exec(self.inner())
				.await?
				.last_insert_id)
		}
	}

	async fn ensure_bootstrap_node_id(
		&self, socket_address: &SocketAddr, node_id: &NodeAddress,
	) -> Result<()> {
		let model = bootstrap_node_id::ActiveModel {
			address: NotSet,
			node_id: Set(node_id.clone()),
		};
		let affected = bootstrap_node_id::Entity::update_many()
			.set(model)
			.filter(bootstrap_node_id::Column::Address.eq(socket_address.to_string()))
			.exec(self.inner())
			.await?
			.rows_affected;

		if affected == 0 {
			let model = bootstrap_node_id::ActiveModel {
				address: Set(socket_address.to_string()),
				node_id: Set(node_id.clone()),
			};
			bootstrap_node_id::Entity::insert(model)
				.exec(self.inner())
				.await?;
		}
		Ok(())
	}

	async fn ensure_trusted_node(&self, address: &NodeAddress, score: u8) -> Result<i64> {
		if let Some(record) = trusted_node::Entity::find()
			.filter(trusted_node::Column::Address.eq(address))
			.one(self.inner())
			.await?
		{
			Ok(record.id)
		} else {
			let model = trusted_node::ActiveModel {
				id: NotSet,
				label: Set(address.to_string()),
				address: Set(address.clone()),
				score: Set(score),
			};
			Ok(trusted_node::Entity::insert(model)
				.exec(self.inner())
				.await?
				.last_insert_id)
		}
	}

	async fn load_identity_system_user(&self, label: &str) -> Result<Option<Option<String>>> {
		// TODO: Only load system_user from query
		let result = identity::Entity::find()
			.filter(identity::Column::Label.eq(label))
			.one(self.inner())
			.await?;
		if let Some(r) = result {
			return Ok(Some(r.system_user));
		}
		Ok(None)
	}

	async fn fetch_identities(
		&self, system_user: Option<&str>, load_all: bool,
	) -> Result<Vec<(String, ActorAddress, IdType, String)>> {
		let mut query = actor::Entity::find().column(identity::Column::Label);
		if !load_all {
			query = query.filter(
				identity::Column::SystemUser
					.eq(system_user)
					.or(identity::Column::SystemUser.is_null()),
			);
		}
		let stat = query
			.join(
				JoinType::RightJoin,
				actor::Entity::belongs_to(identity::Entity)
					.from(actor::Column::Id)
					.to(identity::Column::ActorId)
					.into(),
			)
			.build(self.backend());
		let results = self.inner().query_all(stat).await?;

		// Prepare all fetched identities and load their private key from the disk
		// Identities tied to a system user will load their private key from a local directory.
		let mut identities = Vec::with_capacity(results.len());
		for r in results {
			let label: String = r.try_get_by(identity::Column::Label.as_str())?;
			let address: ActorAddress = r.try_get_by(actor::Column::Address.as_str())?;
			let first_object: IdType = r.try_get_by(actor::Column::FirstObject.as_str())?;
			let actor_type: String = r.try_get_by(actor::Column::Type.as_str())?;
			identities.push((label, address, first_object, actor_type));
		}
		Ok(identities)
	}

	async fn fetch_identities_info(&self) -> Result<Vec<IdentityInfo>> {
		let (query, vals) = Query::select()
			.column(identity::Column::Label)
			.column(actor::Column::Address)
			.column(identity::Column::SystemUser)
			.from(identity::Entity)
			.left_join(
				actor::Entity,
				Expr::col((actor::Entity, actor::Column::Id))
					.equals((identity::Entity, identity::Column::ActorId)),
			)
			.build_any(&*self.backend().get_query_builder());
		let results = self
			.inner()
			.query_all(Statement::from_sql_and_values(self.backend(), query, vals))
			.await?;
		let mut identities = Vec::with_capacity(results.len());
		for result in results {
			let label: String = result.try_get_by_index(0)?;
			let address: ActorAddress = result.try_get_by_index(1)?;
			let system_user: Option<String> = result.try_get_by_index(2)?;
			identities.push(IdentityInfo {
				label,
				address,
				system_user,
			});
		}
		Ok(identities)
	}

	async fn find_block(&self, id: &IdType) -> Result<Option<Vec<u8>>> {
		let result = block::Entity::find()
			.filter(block::Column::Hash.eq(id))
			.one(self.inner())
			.await?;
		Ok(result.map(|r| r.data.into()))
	}

	async fn has_block(&self, hash: &IdType) -> Result<bool> {
		Ok(block::Entity::find()
			.filter(block::Column::Hash.eq(hash))
			.one(self.inner())
			.await?
			.is_some())
	}

	async fn has_file(&self, hash: &IdType) -> Result<bool> {
		Ok(file::Entity::find()
			.filter(file::Column::Hash.eq(hash))
			.one(self.inner())
			.await?
			.is_some())
	}

	async fn has_object(&self, actor_id: i64, hash: &IdType) -> Result<bool> {
		Ok(object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::Hash.eq(hash))
			.one(self.inner())
			.await?
			.is_some())
	}

	async fn has_object_sequence(&self, actor_id: i64, sequence: u64) -> Result<bool> {
		Ok(object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::Sequence.eq(sequence))
			.one(self.inner())
			.await?
			.is_some())
	}

	async fn load_activity_pub_follower_servers(&self, actor_id: i64) -> Result<Vec<String>> {
		let (query, vals) = Query::select()
			.distinct()
			.column(activity_pub_follower::Column::Host)
			.from(activity_pub_follower::Entity)
			.and_where(activity_pub_follower::Column::ActorId.eq(actor_id))
			.build_any(&*self.backend().get_query_builder());

		let results = self
			.inner()
			.query_all(Statement::from_sql_and_values(self.backend(), query, vals))
			.await?;
		let mut servers = Vec::with_capacity(results.len());
		for result in results {
			let server: String = result.try_get_by_index(0)?;
			servers.push(server);
		}
		Ok(servers)
	}

	async fn load_file_blocks(&self, file_id: i64, block_count: u32) -> Result<Vec<IdType>> {
		let results = file_block::Entity::find()
			.filter(file_block::Column::FileId.eq(file_id))
			.order_by_asc(file_block::Column::Sequence)
			.all(self.inner())
			.await?;

		// Verify if all blocks are all there
		for i in 0..results.len() as u32 {
			if results[i as usize].sequence != i {
				Err(Error::FileMissingBlock(file_id, i))?;
			}
		}
		if (results.len() as u32) < block_count {
			Err(Error::FileMissingBlock(file_id, results.len() as u32))?;
		}

		Ok(results.into_iter().map(|r| r.block_hash).collect())
	}

	async fn load_file_data(&self, hash: &IdType) -> Result<Option<FileData>> {
		Ok(
			if let Some(file) = file::Entity::find()
				.filter(file::Column::Hash.eq(hash))
				.limit(1)
				.one(self.inner())
				.await?
			{
				if let Some(compression_type) = CompressionType::from_u8(file.compression_type) {
					let data = self
						.load_file_data2(
							file.id,
							compression_type,
							&file.plain_hash,
							file.block_count,
						)
						.await?;
					Some(FileData {
						mime_type: file.mime_type.into(),
						data,
					})
				} else {
					Err(Error::InvalidCompressionType(file.compression_type))?
				}
			} else {
				None
			},
		)
	}

	async fn load_file_data2(
		&self, file_id: i64, compression_type: CompressionType, plain_hash: &IdType,
		block_count: u32,
	) -> Result<Vec<u8>> {
		let query = Query::select()
			.column(file_block::Column::BlockHash)
			.column(file_block::Column::Sequence)
			.column(block::Column::Size)
			.column(block::Column::Data)
			.from(file_block::Entity)
			.left_join(
				block::Entity,
				Expr::col((file_block::Entity, file_block::Column::BlockHash))
					.equals((block::Entity, block::Column::Hash)),
			)
			.and_where(file_block::Column::FileId.eq(file_id))
			.order_by(file_block::Column::Sequence, Order::Asc)
			.take();
		let stat = self.backend().build(&query);
		let results = self.inner().query_all(stat).await?;
		if results.len() == 0 {
			Err(Error::FileWithoutBlocks(file_id))?;
		}

		// If block count is 1, chances are high that its size is pretty small.
		// If that is the case, preallocation of the buffer isn't really
		// necessary.
		let capacity = if block_count == 1 {
			0
		} else {
			block_count as usize * BLOCK_SIZE
		};
		let mut buffer = Vec::with_capacity(capacity);
		let mut i = 0;
		for row in results {
			let sequence: u32 = row.try_get_by_index(1)?;
			if sequence != i {
				Err(Error::FileMissingBlock(file_id, sequence))?;
			}
			let size2: Option<i64> = row.try_get_by_index(2)?;
			let data2: Option<Vec<u8>> = row.try_get_by_index(3)?;

			if data2.is_none() {
				Err(Error::FileMissingBlock(file_id, sequence))?;
			}
			let size = size2.unwrap() as usize;
			let mut data = data2.unwrap();

			if data.len() != size {
				let hash: IdType = row.try_get_by(file_block::Column::BlockHash.as_str())?;
				Err(Error::BlockDataInvalidSize(hash, size, data.len()))?;
			}
			data.resize(size, 0);

			decrypt_block(i as u64, plain_hash, &mut data);
			buffer.extend(&data);
			i += 1;
		}

		// Decompress the data
		Ok(if compression_type != CompressionType::None {
			decompress(compression_type, &buffer).map_err(|e| Error::from(e))?
		} else {
			buffer
		})
	}

	async fn load_is_following(&self, webfinger_address: &str) -> Result<bool> {
		let is_following = if let Some(actor) = activity_pub_actor::Entity::find()
			.filter(activity_pub_actor::Column::Address.eq(webfinger_address.to_string()))
			.one(self.inner())
			.await?
		{
			activity_pub_following::Entity::find_by_id(actor.id)
				.one(self.inner())
				.await?
				.is_some()
		} else {
			false
		};
		Ok(is_following)
	}

	async fn load_node_identity(&self) -> Result<(NodeAddress, NodePrivateKey)> {
		let result = match node_identity::Entity::find().one(self.inner()).await? {
			Some(m) => {
				let key_len = m.private_key.len();
				match m.private_key.try_into() {
					Ok(buffer) => (m.address, NodePrivateKey::from_bytes(buffer)),
					Err(_) => Err(Error::InvalidPrivateKey(key_len))?,
				}
			}
			None => {
				let private_key = NodePrivateKey::generate();
				let address = NodeAddress::V1(IdType::hash(&private_key.public().to_bytes()));

				let record = node_identity::ActiveModel {
					id: NotSet,
					address: Set(address.clone()),
					private_key: Set(private_key.as_bytes().to_vec()),
				};
				node_identity::Entity::insert(record)
					.exec(self.inner())
					.await?;
				(address, private_key)
			}
		};
		Ok(result)
	}

	async fn load_post_object_payload(&self, object_id: i64) -> Result<Option<PostObject>> {
		let result = post_object::Entity::find_by_id(object_id)
			.one(self.inner())
			.await?;
		if let Some(record) = result {
			let tags = self.load_post_tags(object_id).await?;
			let files = self.load_post_files(object_id).await?;

			let tags2: Vec<LimString<_>> = tags.iter().map(|t| t.into()).collect();
			Ok(Some(PostObject {
				data: PostObjectCryptedData::Plain(PostObjectDataPlain {
					in_reply_to: if record.in_reply_to_actor_address.is_some()
						&& record.in_reply_to_object_hash.is_some()
					{
						Some((
							record.in_reply_to_actor_address.unwrap(),
							record.in_reply_to_object_hash.unwrap(),
						))
					} else {
						None
					},
					tags: tags2.into(),
					files: files.into(),
				}),
			}))
		} else {
			Ok(None)
		}
	}

	async fn load_post_files(&self, object_id: i64) -> Result<Vec<IdType>> {
		Ok(post_file::Entity::find()
			.filter(post_file::Column::ObjectId.eq(object_id))
			.order_by_asc(post_file::Column::Sequence)
			.all(self.inner())
			.await?
			.into_iter()
			.map(|r| r.hash)
			.collect())
	}

	async fn load_post_tags(&self, object_id: i64) -> Result<Vec<String>> {
		Ok(post_tag::Entity::find()
			.filter(post_tag::Column::ObjectId.eq(object_id))
			.all(self.inner())
			.await?
			.into_iter()
			.map(|r| r.tag)
			.collect())
	}

	async fn load_profile(&self, actor_address: &ActorAddress) -> Result<Option<ProfileObject>> {
		if let Some(actor) = actor::Entity::find()
			.filter(actor::Column::Address.eq(actor_address))
			.one(self.inner())
			.await?
		{
			if let Some(result) = object::Entity::find()
				.filter(object::Column::ActorId.eq(actor.id))
				.filter(object::Column::Type.eq(OBJECT_TYPE_PROFILE))
				.one(self.inner())
				.await?
			{
				self.load_profile_object_payload(result.id).await
			} else {
				Ok(None)
			}
		} else {
			Ok(None)
		}
	}

	async fn load_profile_object_payload(&self, object_id: i64) -> Result<Option<ProfileObject>> {
		let result = profile_object::Entity::find_by_id(object_id)
			.one(self.inner())
			.await?;
		Ok(result.map(|r| ProfileObject {
			name: r.name.into(),
			avatar: r.avatar_file_hash,
			wallpaper: r.wallpaper_file_hash,
			description: r.description_file_hash,
		}))
	}

	async fn load_object_payload(
		&self, object_id: i64, object_type: u8,
	) -> Result<Option<ObjectPayload>> {
		Ok(match object_type {
			OBJECT_TYPE_POST => self
				.load_post_object_payload(object_id)
				.await?
				.map(|p| ObjectPayload::Post(p)),
			OBJECT_TYPE_HOME_FILE => panic!("Home file not implemented yet"),
			OBJECT_TYPE_PROFILE => self
				.load_profile_object_payload(object_id)
				.await?
				.map(|p| ObjectPayload::Profile(p)),
			_ => None,
		})
	}

	async fn fetch_follow_list(&self) -> Result<Vec<(ActorAddress, ActorInfo)>> {
		let followers = actor::Entity::find()
			.join(
				JoinType::RightJoin,
				actor::Entity::belongs_to(following::Entity)
					.from(actor::Column::Id)
					.to(following::Column::ActorId)
					.into(),
			)
			.all(self.inner())
			.await?;

		Ok(followers
			.into_iter()
			.map(|r| {
				(
					r.address,
					ActorInfo::V1(ActorInfoV1 {
						flags: 0,
						public_key: ActorPublicKeyV1::from_bytes(r.public_key.try_into().unwrap()), // TODO: Return InvalidPublicKey error
						first_object: r.first_object,
						actor_type: r.r#type.into(),
					}),
				)
			})
			.collect())
	}

	async fn find_file(&self, hash: &IdType) -> Result<Option<(File, i64)>> {
		let result = if let Some(file) = file::Entity::find()
			.filter(file::Column::Hash.eq(hash))
			.one(self.inner())
			.await?
		{
			let blocks = file_block::Entity::find()
				.filter(file_block::Column::FileId.eq(file.id))
				.order_by_asc(file_block::Column::Sequence)
				.all(self.inner())
				.await?
				.into_iter()
				.map(|r| r.block_hash)
				.collect();
			Some((
				File {
					plain_hash: file.plain_hash,
					mime_type: file.mime_type.into(),
					search_index: None,
					compression_type: file.compression_type,
					blocks,
				},
				file.id,
			))
		} else {
			None
		};
		Ok(result)
	}

	async fn find_actor_info(&self, address: &ActorAddress) -> Result<Option<ActorInfo>> {
		let result = actor::Entity::find()
			.filter(actor::Column::Address.eq(address))
			.one(self.inner())
			.await?;

		let actor_info_opt = if let Some(identity) = result {
			if let Ok(public_key) = identity.public_key.try_into() {
				Some(ActorInfo::V1(ActorInfoV1 {
					flags: 0,
					public_key: ActorPublicKeyV1::from_bytes(public_key),
					first_object: identity.first_object,
					actor_type: identity.r#type.into(),
				}))
			} else {
				return Err(Error::InvalidPublicKey.trace());
			}
		} else {
			None
		};
		Ok(actor_info_opt)
	}

	async fn find_next_object_sequence(&self, actor_id: i64) -> Result<u64> {
		let stat = object::Entity::find()
			.select_only()
			.column_as(object::Column::Sequence.max(), "max")
			.filter(object::Column::ActorId.eq(actor_id))
			.build(self.backend());

		if let Some(result) = self.inner().query_one(stat).await? {
			let r = result.try_get_by_index::<Option<i64>>(0)?;
			Ok(r.map(|r| r + 1).unwrap_or(0) as u64)
		} else {
			Ok(0)
		}
	}

	async fn find_objects_by_sequence(
		&self, actor_id: i64, sequence: u64,
	) -> Result<Vec<object::Model>> {
		Ok(object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::Sequence.eq(sequence))
			.order_by_asc(object::Column::Created)
			.all(self.inner())
			.await?)
	}

	async fn find_profile_files(
		&self, actor_id: i64,
	) -> Result<(Option<IdType>, Option<IdType>, Option<IdType>)> {
		// TODO: Merge the following two queries:
		if let Some(object) = object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::Type.eq(OBJECT_TYPE_PROFILE))
			.order_by_desc(object::Column::Sequence)
			.one(self.inner())
			.await?
		{
			if let Some(payload) = profile_object::Entity::find()
				.filter(profile_object::Column::ObjectId.eq(object.id))
				.one(self.inner())
				.await?
			{
				return Ok((
					payload.avatar_file_hash,
					payload.wallpaper_file_hash,
					payload.description_file_hash,
				));
			}
		}
		Ok((None, None, None))
	}

	/// Finds the mime-type and avatar file hash of the latest known profile
	/// object for the given `actor_id`.
	async fn find_profile_limited(
		&self, actor_id: i64,
	) -> Result<(Option<String>, Option<IdType>)> {
		let query = profile_object::Entity::find()
			.join(JoinType::InnerJoin, profile_object::Relation::Object.def())
			.filter(object::Column::ActorId.eq(actor_id))
			.order_by(profile_object::Column::ObjectId, Order::Desc)
			.limit(1)
			.build(self.inner().get_database_backend());

		let result = self.inner().query_one(query).await?;
		let values = if let Some(r) = result {
			let name: String = r.try_get_by(profile_object::Column::Name.as_str())?;
			let avatar_hash: Option<IdType> =
				r.try_get_by(profile_object::Column::AvatarFileHash.as_str())?;
			(Some(name), avatar_hash)
		} else {
			(None, None)
		};
		Ok(values)
	}

	async fn load_trust_score(&self, address: &NodeAddress) -> Result<u8> {
		// Try our own list of trusted nodes first
		let result = trusted_node::Entity::find()
			.filter(trusted_node::Column::Address.eq(address))
			.one(self.inner())
			.await?;
		if let Some(r) = result {
			return Ok(r.score);
		}

		// Otherwise, try to get the highest score available from anywhere
		let stat = trusted_node_trust_item::Entity::find()
			.select_only()
			.column_as(trusted_node_trust_item::Column::OurScore.max(), "max")
			.filter(trusted_node_trust_item::Column::Address.eq(address))
			.order_by_desc(trusted_node_trust_item::Column::Score)
			.build(self.backend());
		if let Some(r) = self.inner().query_one(stat).await? {
			let score_opt: Option<u8> = r.try_get_by_index(0)?;
			Ok(score_opt.unwrap_or(0))
		} else {
			Ok(0)
		}
	}

	async fn next_consolidated_feed_batch(&self) -> Result<u64> {
		let stat = consolidated_object::Entity::find()
			.select_only()
			.column_as(consolidated_object::Column::Batch.max(), "max")
			.build(self.backend());
		if let Some(result) = self.inner().query_one(stat).await? {
			let max: Option<i64> = result.try_get_by_index(0)?;
			let next = if let Some(m) = max { m as u64 + 1 } else { 0 };
			Ok(next)
		} else {
			Ok(0)
		}
	}

	/// Stores an actor
	async fn store_actor(
		&self, address: ActorAddress, public_key: &ActorPublicKeyV1, first_object: IdType,
	) -> Result<i64> {
		let record = actor::ActiveModel {
			id: NotSet,
			address: Set(address),
			public_key: Set(public_key.clone().to_bytes().to_vec()),
			first_object: Set(first_object),
			r#type: Set(ACTOR_TYPE_BLOGCHAIN.to_string()),
		};
		Ok(actor::Entity::insert(record)
			.exec(self.inner())
			.await?
			.last_insert_id)
	}

	/// Stores a data block and returns the record's ID if a block of the given hash did not
	/// already exist.
	async fn store_block(&self, hash: IdType, data: &[u8]) -> Result<i64> {
		let record = block::ActiveModel {
			id: NotSet,
			hash: Set(hash.clone()),
			size: Set(data.len() as _),
			data: Set(data.to_vec()),
		};
		Ok(block::Entity::insert(record)
			.exec(self.inner())
			.await?
			.last_insert_id)
	}

	async fn update_identity_label(&self, old_label: &str, new_label: &str) -> Result<()> {
		let mut model = <identity::ActiveModel as std::default::Default>::default();
		model.label = Set(new_label.to_string());
		identity::Entity::update_many()
			.set(model)
			.filter(identity::Column::Label.eq(old_label))
			.exec(self.inner())
			.await?;
		Ok(())
	}
}

#[allow(dead_code)]
fn query_actor_id(address: &ActorAddress) -> SelectStatement {
	Query::select()
		.column(actor::Column::Id)
		.from(Alias::new(actor::Entity::default().table_name()))
		.and_where(actor::Column::Address.eq(address))
		.take()
}

impl FromSql for ActorAddress {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Blob(blob) => {
				if blob.len() != 33 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 33,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(blob).map_err(|e| FromSqlError::Other(Box::new(e)))?)
				}
			}
			_ => Err(FromSqlError::InvalidType),
		}
	}
}

impl ToSql for ActorAddress {
	fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
		Ok(ToSqlOutput::Owned(Value::Blob(self.to_bytes())))
	}
}

impl ToSql for IdType {
	fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
		Ok(ToSqlOutput::Owned(Value::Text(self.to_string())))
	}
}

impl ToSql for ActorPublicKeyV1 {
	fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
		Ok(ToSqlOutput::Owned(Value::Blob(
			self.clone().to_bytes().to_vec(),
		)))
	}
}

impl FromSql for ActorPublicKeyV1 {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Blob(blob) => {
				if blob.len() != 57 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 57,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(*array_ref![blob, 0, 57]))
				}
			}
			_ => Err(FromSqlError::InvalidType),
		}
	}
}

impl FromSql for ActorPrivateKeyV1 {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Blob(blob) => {
				if blob.len() != 57 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 57,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(*array_ref![blob, 0, 57]))
				}
			}
			_ => Err(FromSqlError::InvalidType),
		}
	}
}

impl FromSql for ActorSignatureV1 {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Blob(blob) => {
				if blob.len() != 114 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 114,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(*array_ref![blob, 0, 114]))
				}
			}
			_ => Err(FromSqlError::InvalidType),
		}
	}
}

impl ToSql for ActorSignatureV1 {
	fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
		Ok(ToSqlOutput::Borrowed(ValueRef::Blob(self.as_bytes())))
	}
}

impl FromSql for NodePublicKey {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Blob(blob) => {
				if blob.len() != 32 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 32,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(*array_ref![blob, 0, 32])
						.map_err(|e| FromSqlError::Other(Box::new(e)))?)
				}
			}
			_ => Err(FromSqlError::InvalidType),
		}
	}
}

impl Database {
	pub fn connect_old(&self) -> self::Result<Connection> {
		Ok(Connection::open_old(&self.path)?)
	}

	pub async fn ensure_block(&self, hash: &IdType, data: &[u8]) -> Result<i64> {
		if let Some(record) = block::Entity::find()
			.filter(block::Column::Hash.eq(hash))
			.one(self.inner())
			.await?
		{
			Ok(record.id)
		} else {
			Ok(self.store_block(hash.clone(), data).await?)
		}
	}

	pub async fn ensure_file(&self, hash: &IdType, file: &File) -> Result<(i64, bool)> {
		if let Some(record) = file::Entity::find()
			.filter(file::Column::Hash.eq(hash))
			.one(self.inner())
			.await?
		{
			Ok((record.id, false))
		} else {
			Ok((self.store_file(hash.clone(), file).await?, true))
		}
	}

	pub async fn ensure_object(
		&self, actor_id: i64, hash: &IdType, object: &BlogchainObject, verified_from_start: bool,
	) -> Result<(i64, bool)> {
		if let Some(record) = object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::Hash.eq(hash))
			.one(self.inner())
			.await?
		{
			Ok((record.id, false))
		} else {
			Ok((
				self.store_object(actor_id, hash, object, verified_from_start)
					.await?,
				true,
			))
		}
	}

	pub async fn find_head_object(
		&self, actor_id: i64,
	) -> Result<Option<(BlogchainObject, i64, IdType)>> {
		let tx = self.transaction().await?;
		let result = tx.find_head_object(actor_id).await?;
		Ok(result)
	}

	pub async fn find_last_profile_object(
		&self, actor_id: i64,
	) -> Result<Option<(IdType, BlogchainObject)>> {
		let tx = self.transaction().await?;
		let result = tx.find_last_profile_object(actor_id).await?;
		Ok(result)
	}

	pub async fn find_last_verified_object(
		&self, actor_id: i64,
	) -> Result<Option<(BlogchainObject, i64, IdType)>> {
		let tx = self.transaction().await?;
		let result = tx.find_last_verified_object(actor_id).await?;
		Ok(result)
	}

	pub async fn find_next_object(
		&self, actor_id: i64, hash: &IdType,
	) -> Result<Option<(BlogchainObject, i64, IdType)>> {
		let tx = self.transaction().await?;
		let result = tx.find_next_object(actor_id, hash).await?;
		Ok(result)
	}

	pub async fn find_object(
		&self, actor_id: i64, hash: &IdType,
	) -> Result<Option<(BlogchainObject, i64)>> {
		let tx = self.transaction().await?;
		let result = tx.find_object(actor_id, hash).await?;
		Ok(result)
	}

	/// Runs the given closure, which pauzes the task that runs it, but doesn't
	/// block the runtime.
	pub fn perform<T>(&self, task: impl FnOnce(Connection) -> Result<T>) -> Result<T> {
		tokio::task::block_in_place(move || {
			let connection = self.connect_old()?;
			task(connection)
		})
	}

	fn install(conn: &Connection) -> Result<()> {
		Ok(conn.execute_batch(install::QUERY)?)
	}

	pub async fn load(path: PathBuf) -> Result<Self> {
		let connection = Connection::open_old(&path).map_err(|e| Error::SqliteError(e))?;

		match connection.prepare("SELECT major, minor FROM version") {
			Ok(mut stat) => {
				let mut rows = stat.query([])?;
				let _row = rows.next()?.expect("missing version data");
			}
			Err(e) => match &e {
				rusqlite::Error::SqliteFailure(_err, msg) => match msg {
					Some(error_message) => {
						if error_message == "no such table: version" {
							Self::install(&connection)?;
						} else {
							Err(e)?;
						}
					}
					None => Err(e)?,
				},
				_ => Err(e)?,
			},
		}

		let mut opts = ConnectOptions::new(format!("sqlite://{}?mode=rwc", path.display()));
		opts.idle_timeout(Duration::from_secs(10));
		opts.acquire_timeout(Duration::from_secs(1));
		opts.sqlx_logging_level(log::LevelFilter::Trace);
		let orm = sea_orm::Database::connect(opts)
			.await
			.map_err(|e| self::Error::OrmError(e))?;

		Ok(Self { path, orm })
	}

	pub async fn store_object(
		&self, actor_id: i64, hash: &IdType, object: &BlogchainObject, verified_from_start: bool,
	) -> Result<i64> {
		let tx = self.transaction().await?;
		let result = tx
			.store_object(actor_id, hash, object, verified_from_start)
			.await?;
		tx.commit().await?;
		Ok(result)
	}

	pub async fn store_file(&self, hash: IdType, file: &File) -> Result<i64> {
		let tx = self.transaction().await?;
		let result = tx.store_file(hash, file).await?;
		tx.commit().await?;
		Ok(result)
	}

	pub async fn transaction(&self) -> Result<Transaction> {
		let tx = self.orm.begin().await?;
		Ok(Transaction(tx))
	}
}

impl Connection {
	/// Returns a list of hashes of blocks we're still missing but also in need
	/// of
	pub fn fetch_missing_file_blocks(&self) -> Result<Vec<(i64, IdType)>> {
		let mut stat = self.prepare(
			r#"
			SELECT fb.file_id, fb.block_hash
			FROM file_block AS fb
			INNER JOIN file AS f ON f.id = fb.file_id
			WHERE fb.block_hash NOT IN (
				SELECT hash FROM block
			)
		"#,
		)?;

		let mut rows = stat.query([])?;
		let mut results = Vec::new();
		while let Some(row) = rows.next()? {
			let file_id: i64 = row.get(0)?;
			let hash: IdType = row.get(1)?;
			results.push((file_id, hash));
		}
		Ok(results)
	}

	pub fn fetch_identity(&self, address: &ActorAddress) -> Result<Option<ActorInfo>> {
		let mut stat = self.prepare(
			r#"
			SELECT public_key, first_object, type FROM actor WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query(params![address])?;
		if let Some(row) = rows.next()? {
			let public_key: ActorPublicKeyV1 = row.get(0)?;
			let first_object: IdType = row.get(1)?;
			let actor_type: String = row.get(2)?;
			Ok(Some(ActorInfo::V1(ActorInfoV1 {
				flags: 0,
				public_key,
				first_object,
				actor_type: actor_type.into(),
			})))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_identity_by_id(&self, id: &IdType) -> Result<Option<ActorInfo>> {
		let mut stat = self.prepare(
			r#"
			SELECT public_key, first_object, type FROM actor WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query([id])?;
		if let Some(row) = rows.next()? {
			let public_key: ActorPublicKeyV1 = row.get(0)?;
			let first_object: IdType = row.get(1)?;
			let actor_type: String = row.get(2)?;
			Ok(Some(ActorInfo::V1(ActorInfoV1 {
				flags: 0,
				public_key,
				first_object,
				actor_type: actor_type.into(),
			})))
		} else {
			Ok(None)
		}
	}

	pub fn follow(&mut self, actor_id: &ActorAddress, actor_info: &ActorInfo) -> Result<()> {
		let tx = self.old.transaction()?;

		let actor_id = {
			let mut stat = tx.prepare(
				r#"
				SELECT id FROM actor WHERE address = ?
			"#,
			)?;
			let mut rows = stat.query(params![actor_id])?;
			let actor_id = if let Some(row) = rows.next()? {
				row.get(0)?
			} else {
				drop(rows);
				let mut stat = tx.prepare(
					r#"
					INSERT INTO actor (address, public_key, first_object, type) VALUES (?,?,?,?,?)
				"#,
				)?;
				stat.insert(params![
					actor_id,
					actor_info.public_key,
					actor_info.first_object,
					ACTOR_TYPE_BLOGCHAIN
				])?
			};
			actor_id
		};

		tx.execute(
			r#"
			INSERT INTO following (actor_id) VALUES (?)
		"#,
			params![actor_id],
		)?;

		tx.commit()?;
		Ok(())
	}

	pub fn is_following(&self, actor_id: &ActorAddress) -> Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT 1
			FROM following AS f
			LEFT JOIN actor AS i ON f.actor_id = i.id
			WHERE i.address = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id])?;
		Ok(rows.next()?.is_some())
	}

	pub fn old(&self) -> &rusqlite::Connection {
		&self.old.0
	}

	pub fn old_mut(&mut self) -> &mut rusqlite::Connection {
		&mut self.old.0
	}

	pub fn open_old(path: &Path) -> rusqlite::Result<Self> {
		let c = rusqlite::Connection::open(&path)?;
		// For some reason foreign key checks are not working properly on windows, so
		// disable it for now.
		#[cfg(target_family = "windows")]
		c.pragma_update(None, "foreign_keys", false)?;
		Ok(Self {
			old: UnsafeSendSync::new(c),
		})
	}

	pub fn unfollow(&mut self, actor_id: &ActorAddress) -> Result<bool> {
		let affected = self.old.execute(
			r#"
			DELETE FROM following WHERE actor_id = (
				SELECT id FROM actor WHERE address = ?
			)
		"#,
			params![actor_id],
		)?;
		Ok(affected > 0)
	}
}

impl PersistenceHandle for Database {
	type Inner = sea_orm::DatabaseConnection;

	fn inner(&self) -> &Self::Inner {
		&self.orm
	}
}

impl PersistenceHandle for Transaction {
	type Inner = sea_orm::DatabaseTransaction;

	fn inner(&self) -> &Self::Inner {
		&self.0
	}
}

impl Deref for Connection {
	type Target = rusqlite::Connection;

	fn deref(&self) -> &Self::Target {
		self.old()
	}
}

impl DerefMut for Connection {
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.old_mut()
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::DecompressDecodeError(code) => {
				write!(f, "decode error during decompression: {}", code)
			}
			Self::SqliteError(e) => write!(f, "{}", e),
			Self::OrmError(e) => write!(f, "{}", e),
			Self::ActorAddress(e) => write!(f, "invalid actor address format: {}", e),
			Self::InvalidCompressionType(code) => write!(f, "invalid compression type: {}", code),
			Self::InvalidHash(e) => {
				write!(f, "hash not a valid base58-encoded 32-byte address {}", e)
			}
			Self::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
			Self::InvalidObjectType(code) => {
				write!(f, "invalid object type found in database: {}", code)
			}
			//Self::InvalidPrivateKey(e) => write!(f, "invalid private_key: {}", e),
			Self::BlockDataCorrupt(block_id) => write!(f, "data of block {} is corrupt", block_id),
			Self::BlockDataInvalidSize(block_id, expected_size, actual_size) => {
				write!(
					f,
					"data of block {} has invalid size {} (expected {})",
					block_id, actual_size, expected_size
				)
			}
			Self::FileMissingBlock(file_id, sequence) => {
				write!(f, "file {} missing block sequence {}", file_id, sequence)
			}
			Self::FileWithoutBlocks(file_id) => write!(f, "file {} has no blocks", file_id),
			Self::InvalidPrivateKey(len) => write!(f, "invalid private key (size={})", len),
			Self::InvalidPublicKey => write!(f, "invalid public key"),
			Self::MissingIdentity(hash) => write!(f, "identity {:?} is missing", &hash),
			Self::UnexpectedState(msg) => write!(f, "unexpected database state: {}", msg),
		}
	}
}

impl From<compu::DecodeError> for Error {
	fn from(other: compu::DecodeError) -> Self {
		Self::DecompressDecodeError(other.as_raw())
	}
}

impl From<FromBytesAddressError> for Error {
	fn from(other: FromBytesAddressError) -> Self {
		Self::ActorAddress(other)
	}
}

impl From<FromBytesAddressError> for Traced<Error> {
	fn from(other: FromBytesAddressError) -> Self {
		Error::ActorAddress(other).trace()
	}
}

impl From<rusqlite::Error> for Error {
	fn from(other: rusqlite::Error) -> Self {
		Self::SqliteError(other)
	}
}

impl From<rusqlite::Error> for Traced<Error> {
	fn from(other: rusqlite::Error) -> Self {
		Error::SqliteError(other).trace()
	}
}

impl From<sea_orm::DbErr> for Error {
	fn from(other: sea_orm::DbErr) -> Self {
		Error::OrmError(other)
	}
}

impl From<sea_orm::DbErr> for Traced<Error> {
	fn from(other: sea_orm::DbErr) -> Self {
		Error::OrmError(other).trace()
	}
}

impl From<NodeSignatureError> for Error {
	fn from(other: NodeSignatureError) -> Self {
		Self::InvalidSignature(other)
	}
}

impl From<IdFromBase58Error> for Error {
	fn from(other: IdFromBase58Error) -> Self {
		other.to_db()
	}
}

impl IdFromBase58Error {
	fn to_db(self) -> Error {
		Error::InvalidHash(self)
	}
}

pub fn decrypt_block(index: u64, key: &IdType, data: &mut [u8]) {
	encrypt_block(index, key, data)
}

pub fn encrypt_block(index: u64, key: &IdType, data: &mut [u8]) {
	// Construct nonce out of the block index
	let mut nonce = GenericArray::<u8, U12>::default();
	let bytes = (u64::BITS / 8) as usize;
	debug_assert!(bytes <= 12);
	nonce[..bytes].copy_from_slice(&index.to_le_bytes());

	// Encrypt
	let generic_key = GenericArray::from_slice(key.as_bytes());
	let mut cipher = ChaCha20::new(generic_key, &nonce);
	cipher.apply_keystream(data);
}

impl Transaction {
	/// Commit the transaction.
	pub async fn commit(self) -> Result<()> {
		self.0.commit().await?;
		Ok(())
	}

	/// Creates a file by doing the following:
	/// * Compress the data if the file type isn't known to use compression
	///   already
	/// * Devide the (possibly compressed) data into blocks
	/// * Encrypt & store all blocks
	/// * Store file
	/// Returns the file id, the hash & the list of block hashes
	pub async fn create_file(&self, file_data: &FileData) -> Result<(i64, IdType, Vec<IdType>)> {
		self.create_file2(file_data.mime_type.as_str(), &file_data.data)
			.await
	}

	/// Same as `create_file`.
	pub async fn create_file2(
		&self, mime_type: &str, data: &[u8],
	) -> Result<(i64, IdType, Vec<IdType>)> {
		debug_assert!(data.len() <= u64::MAX as usize, "data too large");
		debug_assert!(data.len() > 0, "data can not be empty");
		let compressed_data;
		let mut compression_type = if mime_type_use_compression(mime_type) {
			CompressionType::Brotli
		} else {
			CompressionType::None
		};

		// Compress the data first, but only if it actually turns out significantly
		// smaller than the original data blob
		let file_data = if compression_type == CompressionType::Brotli {
			compressed_data = compress(compression_type, data);
			if compressed_data.len() <= (data.len() as f32 * 0.95) as usize {
				&compressed_data
			} else {
				compression_type = CompressionType::None;
				data
			}
		} else {
			data
		};

		// Use an appropriate block size that is not too small to overload the network with blocks.
		let mut block_count =
			file_data.len() / BLOCK_SIZE + ((file_data.len() % BLOCK_SIZE) > 0) as usize;
		let block_size = if block_count <= 100 {
			BLOCK_SIZE
		} else {
			let bs = file_data.len() / 100 + (file_data.len() % 100 > 0) as usize;
			block_count = file_data.len() / bs + ((file_data.len() % bs) > 0) as usize;
			bs
		};
		let mut block_hashes = Vec::with_capacity(block_count);

		// Devide data into blocks, and store them if they don't yet exist
		let plain_hash = IdType::hash(data);
		let mut i = 0;
		let mut block_index = 0;
		loop {
			let slice = &file_data[i..];
			let actual_block_size = min(block_size, slice.len());
			let mut block_data = slice[..actual_block_size].to_vec();
			encrypt_block(block_index, &plain_hash, &mut block_data);
			let block_hash = IdType::hash(&block_data);
			block_hashes.push(block_hash.clone());

			// Store block with an invalid file_id
			// When PostgreSQL & MySQL are available, use a unique temporary file_id because
			// there may be multiple files stored at once. For SQLite it should not be an
			// issue.
			if block::Entity::find()
				.filter(block::Column::Hash.eq(&block_hash))
				.one(self.inner())
				.await?
				.is_none()
			{
				self.store_block(block_hash, &block_data).await?;
			}

			block_index += 1;
			i += block_size;
			if i >= file_data.len() {
				break;
			}
		}

		// Calculate the file hash
		let file_hash = IdType::hash(
			&binserde::serialize(&File {
				blocks: block_hashes.clone(),
				compression_type: compression_type as u8,
				mime_type: mime_type.into(),
				plain_hash: plain_hash.clone(),
				search_index: None,
			})
			.unwrap(),
		);

		// Create or find the file record
		let file_id = if let Some(record) = file::Entity::find()
			.filter(file::Column::Hash.eq(&file_hash))
			.one(self.inner())
			.await?
		{
			record.id
		} else {
			self.store_file2(
				file_hash.clone(),
				plain_hash,
				mime_type.to_string(),
				compression_type,
				&block_hashes,
			)
			.await?
		};

		Ok((file_id as _, file_hash, block_hashes))
	}

	pub async fn create_identity(
		&self, system_user: Option<String>, label: &str, address: &ActorAddress,
		public_key: &ActorPublicKeyV1, is_private: bool, first_object_hash: &IdType,
	) -> Result<i64> {
		let model = actor::ActiveModel {
			id: NotSet,
			address: Set(address.clone()),
			public_key: Set(public_key.clone().to_bytes().to_vec()),
			first_object: Set(first_object_hash.clone()),
			r#type: Set(ACTOR_TYPE_BLOGCHAIN.to_string()),
		};
		let actor_id = actor::Entity::insert(model)
			.exec(self.inner())
			.await?
			.last_insert_id;
		let model = identity::ActiveModel {
			label: Set(label.to_string()),
			actor_id: Set(actor_id),
			is_private: Set(is_private),
			system_user: Set(system_user),
		};
		identity::Entity::insert(model).exec(self.inner()).await?;
		Ok(actor_id)
	}

	pub async fn find_actor_id(&self, actor_address: &ActorAddress) -> Result<Option<i64>> {
		let actor = actor::Entity::find()
			.filter(actor::Column::Address.eq(actor_address))
			.one(self.inner())
			.await?;
		Ok(actor.map(|a| a.id))
	}

	pub async fn find_head_object(
		&self, actor_id: i64,
	) -> Result<Option<(BlogchainObject, i64, IdType)>> {
		let result = object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.order_by_desc(object::Column::Sequence)
			.limit(1)
			.one(self.inner())
			.await?;
		if let Some(record) = result {
			if let Some((object, id)) = self.load_object(Some(record.clone())).await? {
				return Ok(Some((object, id, record.hash)));
			}
		}
		Ok(None)
	}

	pub async fn find_last_profile_object(
		&self, actor_id: i64,
	) -> Result<Option<(IdType, BlogchainObject)>> {
		let result = profile_object::Entity::find()
			.left_join(object::Entity)
			.filter(object::Column::ActorId.eq(actor_id))
			.order_by_desc(object::Column::Sequence)
			.limit(1)
			.one(self.inner())
			.await?;

		if let Some(record) = result {
			let object_result = object::Entity::find_by_id(record.object_id)
				.one(self.inner())
				.await?;
			if let Some(object_record) = object_result {
				if let Some((object, _)) = self.load_object(Some(object_record.clone())).await? {
					return Ok(Some((object_record.hash, object)));
				}
			}
		}
		Ok(None)
	}

	pub async fn find_last_verified_object(
		&self, actor_id: i64,
	) -> Result<Option<(BlogchainObject, i64, IdType)>> {
		let result = object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::VerifiedFromStart.eq(true))
			.order_by_desc(object::Column::Sequence)
			.limit(1)
			.one(self.inner())
			.await?;
		if let Some(record) = result {
			if let Some((object, id)) = self.load_object(Some(record.clone())).await? {
				return Ok(Some((object, id, record.hash)));
			}
		}
		Ok(None)
	}

	/// Finds the object that comes after the object of the given hash.
	pub async fn find_next_object(
		&self, actor_id: i64, hash: &IdType,
	) -> Result<Option<(BlogchainObject, i64, IdType)>> {
		let result = object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::PreviousHash.eq(hash))
			.limit(1)
			.one(self.inner())
			.await?;
		if let Some(record) = result {
			if let Some((object, id)) = self.load_object(Some(record.clone())).await? {
				return Ok(Some((object, id, record.hash)));
			}
		}
		Ok(None)
	}

	async fn load_object(
		&self, result: Option<object::Model>,
	) -> Result<Option<(BlogchainObject, i64)>> {
		if let Some(record) = result {
			if let Some(payload) = self.load_object_payload(record.id, record.r#type).await? {
				return Ok(Some((
					BlogchainObject {
						created: record.created as _,
						sequence: record.sequence as _,
						payload,
						previous_hash: record.previous_hash,
						signature: record.signature,
					},
					record.id,
				)));
			}
			error!("Payload was missing for object {}.", record.id);
		}
		Ok(None)
	}

	pub async fn find_object(
		&self, actor_id: i64, hash: &IdType,
	) -> Result<Option<(BlogchainObject, i64)>> {
		let result = object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::Hash.eq(hash))
			.one(self.inner())
			.await?;
		self.load_object(result).await
	}

	pub async fn find_object_by_sequence(
		&self, actor_id: i64, sequence: u64,
	) -> Result<Option<(BlogchainObject, i64, IdType, bool)>> {
		let result = object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::Sequence.eq(sequence))
			.order_by_desc(object::Column::VerifiedFromStart)
			.order_by_desc(object::Column::Created)
			.one(self.inner())
			.await?;
		if let Some(record) = result {
			if let Some((object, id)) = self.load_object(Some(record.clone())).await? {
				return Ok(Some((object, id, record.hash, record.verified_from_start)));
			}
		}
		Ok(None)
	}

	pub async fn store_file(&self, hash: IdType, file: &File) -> Result<i64> {
		let compression_type = CompressionType::from_u8(file.compression_type)
			.ok_or(Error::InvalidCompressionType(file.compression_type))?;
		self.store_file2(
			hash.clone(),
			file.plain_hash.clone(),
			file.mime_type.to_string(),
			compression_type,
			&file.blocks,
		)
		.await
	}

	pub async fn store_file2(
		&self, hash: IdType, plain_hash: IdType, mime_type: String,
		compression_type: CompressionType, blocks: &[IdType],
	) -> Result<i64> {
		let record = file::ActiveModel {
			id: NotSet,
			block_count: Set(blocks.len() as _),
			compression_type: Set(compression_type as u8),
			hash: Set(hash.clone()),
			plain_hash: Set(plain_hash.clone()),
			mime_type: Set(mime_type.to_string()),
		};
		let file_id = file::Entity::insert(record)
			.exec(self.inner())
			.await?
			.last_insert_id;

		let mut i = 0;
		for block in blocks {
			let record = file_block::ActiveModel {
				id: NotSet,
				file_id: Set(file_id),
				block_hash: Set(block.clone()),
				sequence: Set(i),
			};
			file_block::Entity::insert(record)
				.exec(self.inner())
				.await?;
			i += 1;
		}
		Ok(file_id)
	}

	pub async fn store_object(
		&self, actor_id: i64, object_hash: &IdType, object: &BlogchainObject,
		verified_from_start: bool,
	) -> Result<i64> {
		let object_id = self
			.store_object_meta(
				actor_id,
				object.created,
				object_hash,
				&object.previous_hash,
				object.payload.type_id(),
				&object.signature,
				verified_from_start,
				false,
			)
			.await?;
		self.store_object_payload(object_id, &object.payload)
			.await?;
		Ok(object_id)
	}

	async fn store_object_payload(&self, object_id: i64, payload: &ObjectPayload) -> Result<()> {
		match payload {
			ObjectPayload::HomeFile(_) => {
				error!("Home file payloads are not implemented yet");
				Ok(())
			}
			ObjectPayload::Post(po) => self.store_post_object_payload(object_id, &po).await,
			ObjectPayload::Profile(po) => self.store_profile_object_payload(object_id, &po).await,
		}
	}

	async fn store_post_files(&self, object_id: i64, files: &[IdType]) -> Result<()> {
		let mut i = 0;
		for file in files {
			let record = post_file::ActiveModel {
				id: NotSet,
				object_id: Set(object_id),
				hash: Set(file.clone()),
				sequence: Set(i),
			};
			post_file::Entity::insert(record).exec(self.inner()).await?;
			i += 1;
		}
		Ok(())
	}

	async fn store_post_object_payload(&self, object_id: i64, payload: &PostObject) -> Result<()> {
		match &payload.data {
			PostObjectCryptedData::Plain(plain) => {
				let record = post_object::ActiveModel {
					object_id: Set(object_id),
					in_reply_to_actor_address: Set(plain.in_reply_to.as_ref().map(|r| r.0.clone())),
					in_reply_to_object_hash: Set(plain.in_reply_to.as_ref().map(|r| r.1.clone())),
					file_count: Set(plain.files.len() as _),
				};
				post_object::Entity::insert(record)
					.exec(self.inner())
					.await?;

				let tags2: Vec<_> = plain.tags.iter().map(|t| t.clone().to_string()).collect();
				self.store_post_tags(object_id, &tags2).await?;
				self.store_post_files(object_id, &plain.files).await?;
				Ok(())
			}
		}
	}

	async fn store_post_tags(&self, object_id: i64, tags: &[String]) -> Result<()> {
		let mut i = 0;
		for tag in tags {
			let record = post_tag::ActiveModel {
				id: NotSet,
				object_id: Set(object_id),
				sequence: Set(i),
				tag: Set(tag.clone()),
			};
			post_tag::Entity::insert(record).exec(self.inner()).await?;
			i += 1;
		}
		Ok(())
	}

	async fn store_object_meta(
		&self, actor_id: i64, created: u64, hash: &IdType, previous_hash: &IdType, object_type: u8,
		signature: &ActorSignatureV1, verified_from_start: bool, published_on_fediverse: bool,
	) -> Result<i64> {
		let next_sequence = self.find_next_object_sequence(actor_id).await?;
		let record = object::ActiveModel {
			id: NotSet,
			actor_id: Set(actor_id),
			hash: Set(hash.clone()),
			sequence: Set(next_sequence as _),
			previous_hash: Set(previous_hash.clone()),
			created: Set(created as _),
			found: Set(created as _),
			r#type: Set(object_type),
			signature: Set(signature.clone()),
			verified_from_start: Set(verified_from_start),
			published_on_fediverse: Set(published_on_fediverse),
		};
		Ok(object::Entity::insert(record)
			.exec(self.inner())
			.await?
			.last_insert_id)
	}

	pub async fn store_post(
		&self, actor_id: i64, created: u64, hash: &IdType, previous_hash: &IdType,
		signature: &ActorSignatureV1, verified_from_start: bool, tags: &[String], files: &[IdType],
		in_reply_to: Option<(ActorAddress, IdType)>, published_on_fediverse: bool,
	) -> Result<()> {
		let object_id = self
			.store_object_meta(
				actor_id,
				created,
				hash,
				previous_hash,
				OBJECT_TYPE_POST,
				signature,
				verified_from_start,
				published_on_fediverse,
			)
			.await?;

		let (a, o) = match in_reply_to {
			None => (None, None),
			Some((actor, object)) => (Some(actor), Some(object)),
		};
		let record = post_object::ActiveModel {
			object_id: Set(object_id),
			file_count: Set(files.len() as _),
			in_reply_to_actor_address: Set(a),
			in_reply_to_object_hash: Set(o),
		};
		post_object::Entity::insert(record)
			.exec(self.inner())
			.await?;

		// Store all tags & files
		self.store_post_tags(object_id, tags).await?;
		self.store_post_files(object_id, files).await?;
		Ok(())
	}

	pub async fn store_profile(
		&self, actor_id: i64, created: u64, hash: &IdType, previous_hash: &IdType,
		signature: &ActorSignatureV1, verified_from_start: bool, name: &str,
		avatar_hash: Option<IdType>, wallpaper_hash: Option<IdType>,
		description_hash: Option<IdType>,
	) -> Result<()> {
		let object_id = self
			.store_object_meta(
				actor_id,
				created,
				hash,
				previous_hash,
				OBJECT_TYPE_PROFILE,
				signature,
				verified_from_start,
				false,
			)
			.await?;

		let record = profile_object::ActiveModel {
			object_id: Set(object_id),
			name: Set(name.to_string()),
			avatar_file_hash: Set(avatar_hash),
			wallpaper_file_hash: Set(wallpaper_hash),
			description_file_hash: Set(description_hash),
		};
		profile_object::Entity::insert(record)
			.exec(self.inner())
			.await?;
		Ok(())
	}

	async fn store_profile_object_payload(
		&self, object_id: i64, payload: &ProfileObject,
	) -> Result<()> {
		let record = profile_object::ActiveModel {
			object_id: Set(object_id),
			name: Set(payload.name.to_string()),
			description_file_hash: Set(payload.description.clone()),
			avatar_file_hash: Set(payload.avatar.clone()),
			wallpaper_file_hash: Set(payload.wallpaper.clone()),
		};
		profile_object::Entity::insert(record)
			.exec(self.inner())
			.await?;
		Ok(())
	}

	pub async fn update_object_as_verified_from_start(&self, object_id: i64) -> Result<()> {
		let model = object::ActiveModel {
			id: Set(object_id),
			verified_from_start: Set(true),
			..Default::default()
		};
		object::Entity::update(model).exec(self.inner()).await?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use rand::RngCore;

	use super::*;
	use crate::test;

	#[tokio::test]
	async fn test_file_data() {
		let (db, db_file) = test::load_database("db").await;

		let mut rng = test::initialize_rng();

		let mut file_data1 = FileData {
			mime_type: "image/png".into(),
			data: vec![0u8; 10000],
		};
		rng.fill_bytes(&mut file_data1.data);

		let file_data2 = FileData {
			mime_type: "text/markdown".into(),
			data: "This is some text.".as_bytes().to_vec(),
		};
		let tx = db.transaction().await.unwrap();
		let (_, hash1, _) = tx.create_file(&file_data1).await.unwrap();
		let (_, hash2, _) = tx.create_file(&file_data2).await.unwrap();
		tx.commit().await.unwrap();

		let fetched_file1 = db.load_file_data(&hash1).await.unwrap().unwrap();
		let fetched_file2 = db.load_file_data(&hash2).await.unwrap().unwrap();
		assert_eq!(
			fetched_file1.mime_type, file_data1.mime_type,
			"corrupted mime type"
		);
		assert_eq!(fetched_file1.data, file_data1.data, "corrupted file data");
		assert_eq!(
			fetched_file2.mime_type, file_data2.mime_type,
			"corrupted mime type"
		);
		assert_eq!(fetched_file2.data, file_data2.data, "corrupted file data");

		drop(db_file);
	}
}

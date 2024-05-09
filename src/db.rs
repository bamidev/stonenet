// FIXME: Remove when going stable:
#![allow(dead_code)]
#![allow(deprecated)]

mod install;

use std::{cmp::min, fmt, net::SocketAddr, ops::*, path::*, str, time::Duration};

use ::serde::Serialize;
use async_trait::async_trait;
use chacha20::{
	cipher::{KeyIvInit, StreamCipher},
	ChaCha20,
};
use chrono::Utc;
use fallible_iterator::FallibleIterator;
use generic_array::{typenum::U12, GenericArray};
use log::*;
use rusqlite::{
	self, params,
	types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, Value, ValueRef},
	Rows, ToSql,
};
use sea_orm::{prelude::*, sea_query::*, *};
use thiserror::Error;
use unsafe_send_sync::UnsafeSendSync;

use crate::{
	common::*,
	core::*,
	entity::{
		activity_pub_follow, block, file, file_blocks, following, identity, my_identity, object,
		post_files, post_object, profile_object,
	},
	identity::*,
	net::binserde,
	trace::{self, Traceable, Traced},
};


const DATABASE_VERSION: (u8, u16, u16) = (0, 0, 0);
pub(crate) const BLOCK_SIZE: usize = 0x100000; // 1 MiB

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
	backend: DatabaseBackend,
}

// TODO: Make the sea_orm::DatabaseTransaction inside private
pub struct Transaction(pub(crate) sea_orm::DatabaseTransaction);

#[derive(Debug, Error)]
pub enum Error {
	/// Sqlite error
	SqliteError(rusqlite::Error),
	OrmError(sea_orm::DbErr),
	ActorAddress(FromBytesAddressError),
	InvalidObjectType(u8),
	/// An invalid hash has been found in the database
	InvalidHash(IdFromBase58Error),
	InvalidSignature(NodeSignatureError),
	//InvalidPrivateKey(PrivateKeyError),
	InvalidPublicKey(Option<NodePublicKeyError>),
	/// The data that is stored for a block is corrupt
	BlockDataCorrupt(i64),
	PostMissingFiles(i64),
	FileMissingBlock(i64, u64),

	MissingIdentity(ActorAddress),
}

#[derive(Debug, Default, Serialize)]
pub struct ShareObjectInfo {
	pub original_post: Option<TargetedPostInfo>,
}

pub trait DerefConnection: Deref<Target = rusqlite::Connection> {}
impl<T> DerefConnection for T where T: Deref<Target = rusqlite::Connection> {}

#[derive(Debug, Serialize)]
pub struct TargetedActorInfo {
	pub address: String,
	pub name: String,
	pub avatar_id: Option<IdType>,
	pub wallpaper_id: Option<IdType>,
}


#[derive(Clone, Debug, Serialize)]
pub enum PossiblyKnownFileHeader {
	Unknown(IdType),
	Known(FileHeader),
}

#[derive(Debug, Serialize)]
pub struct TargetedPostInfo {
	pub actor_address: String,
	pub actor_name: Option<String>,
	pub actor_avatar: Option<IdType>,
	//pub sequence: u64,
	pub message: Option<(String, String)>,
	pub attachments: Vec<PossiblyKnownFileHeader>,
}

#[derive(Debug, Serialize)]
pub struct PostObjectInfo {
	pub in_reply_to: Option<TargetedPostInfo>,
	pub sequence: u64,
	pub message: Option<String>,
	pub mime_type: Option<String>,
	pub attachments: Vec<PossiblyKnownFileHeader>,
}

#[derive(Debug, Serialize)]
pub struct ProfileObjectInfo {
	pub actor: TargetedActorInfo,
	pub description: Option<String>,
}

#[derive(Serialize)]
pub struct ObjectInfo {
	pub hash: IdType,
	pub created: u64,
	pub found: u64,
	pub actor_address: ActorAddress,
	pub actor_name: Option<String>,
	pub actor_avatar: Option<IdType>,
	pub payload: ObjectPayloadInfo,
}

#[derive(Debug, Serialize)]
pub enum ObjectPayloadInfo {
	Post(PostObjectInfo),
	Share(ShareObjectInfo),
	Profile(ProfileObjectInfo),
}

pub type Result<T> = trace::Result<T, self::Error>;


#[async_trait]
pub trait PersistenceHandle {
	type Inner: ConnectionTrait;

	fn inner(&self) -> &Self::Inner;

	fn backend(&self) -> DatabaseBackend { self.inner().get_database_backend() }


	async fn load_activity_pub_follower_servers(&self, actor_id: i64) -> Result<Vec<String>> {
		let (query, vals) = Query::select()
			.distinct()
			.column(activity_pub_follow::Column::Server)
			.from(activity_pub_follow::Entity)
			.and_where(activity_pub_follow::Column::ActorId.eq(actor_id))
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

	async fn load_home_feed(
		&self, limit: u64, offset: u64, track: impl Iterator<Item = &ActorAddress> + Send,
	) -> Result<Vec<ObjectInfo>> {
		// Build up the part of the query that includes the id's to track additionally
		let cap = track.size_hint().1.unwrap_or(track.size_hint().0);
		let mut tuples: Vec<&ActorAddress> = Vec::with_capacity(cap);
		for t in track {
			tuples.push(t);
		}

		// The query
		let query = object::Entity::find()
			.column(identity::Column::Address)
			.join(JoinType::LeftJoin, object::Relation::Identity.def())
			.filter(
				Condition::any()
					.add(
						object::Column::ActorId.in_subquery(
							Query::select()
								.column(identity::Column::Id)
								.from(Alias::new(identity::Entity::default().table_name()))
								.and_where(
									Expr::col((identity::Entity, identity::Column::Address))
										.in_tuples(tuples),
								)
								.take(),
						),
					)
					.add(
						object::Column::ActorId.in_subquery(
							Query::select()
								.column(my_identity::Column::IdentityId)
								.from(Alias::new(my_identity::Entity::default().table_name()))
								.take(),
						),
					)
					.add(
						object::Column::ActorId.in_subquery(
							Query::select()
								.column(following::Column::IdentityId)
								.from(Alias::new(following::Entity::default().table_name()))
								.take(),
						),
					),
			)
			.offset(offset)
			.limit(limit)
			.build(self.backend());

		// Process results
		let results = self.inner().query_all(query).await?;
		let mut objects = Vec::with_capacity(limit as _);
		for result in &results {
			let actor_address_opt: Option<ActorAddress> =
				result.try_get_by(identity::Column::Address.as_str())?;
			if let Some(actor_address) = actor_address_opt {
				if let Some(object) = self
					._load_object_info_from_result(&actor_address, result)
					.await?
				{
					objects.push(object);
				}
			}
		}
		Ok(objects)
	}

	async fn load_actor_feed(
		&self, actor: &ActorAddress, limit: u64, offset: u64,
	) -> Result<Vec<ObjectInfo>> {
		let query = Query::select()
			.column((object::Entity, object::Column::Id))
			.column((object::Entity, object::Column::Type))
			.column(object::Column::ActorId)
			.column(object::Column::Hash)
			.column(object::Column::Created)
			.column(object::Column::Found)
			.from(object::Entity)
			.inner_join(
				identity::Entity,
				Expr::col((object::Entity, object::Column::ActorId))
					.equals((identity::Entity, identity::Column::Id)),
			)
			.and_where(identity::Column::Address.eq(actor))
			.order_by(object::Column::Sequence, Order::Desc)
			.limit(limit)
			.offset(offset)
			.take();
		let stat = self.backend().build(&query);

		let results = self.inner().query_all(stat).await?;
		let mut objects = Vec::with_capacity(limit as _);
		for result in &results {
			if let Some(object) = self._load_object_info_from_result(actor, result).await? {
				objects.push(object);
			}
		}
		Ok(objects)
	}

	async fn find_file_data(
		&self, file_id: i64, plain_hash: &IdType, block_count: u32,
	) -> Result<Option<Vec<u8>>> {
		let query = file_blocks::Entity::find()
			.column(block::Column::Id)
			.column(block::Column::Size)
			.column(block::Column::Data)
			.join(
				JoinType::LeftJoin,
				file_blocks::Entity::belongs_to(block::Entity)
					.from(file_blocks::Column::BlockHash)
					.to(block::Column::Hash)
					.into(),
			)
			.filter(file_blocks::Column::FileId.eq(file_id))
			.order_by(file_blocks::Column::Sequence, Order::Asc)
			.build(self.inner().get_database_backend());

		let results = self.inner().query_all(query).await?;
		if results.len() == 0 {
			return Ok(None);
		}

		let capacity = if block_count == 1 {
			0
		} else {
			block_count as usize * BLOCK_SIZE
		};
		let mut buffer = Vec::with_capacity(capacity);
		let mut i = 0;
		for r in results {
			let sequence: i64 = r.try_get_by(file_blocks::Column::Sequence.as_str())?;
			if sequence != i {
				Err(Error::FileMissingBlock(file_id, sequence as _))?;
			}
			let block_id_opt: Option<i64> = r.try_get_by(block::Column::Id.as_str())?;
			if let Some(block_id) = block_id_opt {
				let size: i64 = r.try_get_by(block::Column::Size.as_str())?;
				let mut data: Vec<u8> = r.try_get_by(block::Column::Data.as_str())?;

				data.resize(size as _, 0);
				if (data.len() as i64) < size {
					Err(Error::BlockDataCorrupt(block_id))?;
				} else if (data.len() as i64) > size {
					warn!(
						"Block {} has more data than its size: {} > {}",
						block_id,
						data.len(),
						size
					);
				}

				decrypt_block(i as _, plain_hash, &mut data);
				buffer.extend(&data);
				i += 1;
			} else {
				Err(Error::FileMissingBlock(file_id, sequence as _))?;
			}
		}

		Ok(Some(buffer))
	}

	async fn find_actor_info(&self, address: &ActorAddress) -> Result<Option<ActorInfo>> {
		let result = identity::Entity::find()
			.filter(identity::Column::Address.eq(address))
			.one(self.inner())
			.await?;

		let actor_info_opt = if let Some(identity) = result {
			Some(ActorInfo::V1(ActorInfoV1 {
				flags: 0,
				public_key: ActorPublicKeyV1::from_bytes(identity.public_key.try_into().unwrap())
					.unwrap(),
				first_object: identity.first_object,
				actor_type: identity.r#type,
			}))
		} else {
			None
		};
		Ok(actor_info_opt)
	}

	async fn find_next_object_sequence(&self, identity_id: i64) -> Result<u64> {
		let stat = object::Entity::find()
			.column_as(object::Column::Sequence.max(), "max")
			.filter(object::Column::ActorId.eq(identity_id))
			.build(DatabaseBackend::Sqlite);

		if let Some(result) = self.inner().query_one(stat).await? {
			Ok(result.try_get_by_index::<i64>(0)? as u64)
		} else {
			Ok(0)
		}
	}

	async fn find_object_info(
		&self, actor_address: &ActorAddress, hash: &IdType,
	) -> Result<Option<ObjectInfo>> {
		let query = Query::select()
			.column((object::Entity, object::Column::Id))
			.column((object::Entity, object::Column::Type))
			.column(object::Column::ActorId)
			.column(object::Column::Hash)
			.column(object::Column::Created)
			.column(object::Column::Found)
			.from(object::Entity)
			.inner_join(
				identity::Entity,
				Expr::col((object::Entity, object::Column::ActorId))
					.equals((identity::Entity, identity::Column::Id)),
			)
			.and_where(identity::Column::Address.eq(actor_address))
			.and_where(object::Column::Hash.eq(hash))
			.take();
		let stat = self.backend().build(&query);

		if let Some(result) = self.inner().query_one(stat).await? {
			let object_opt = self
				._load_object_info_from_result(actor_address, &result)
				.await?;
			Ok(object_opt)
		} else {
			Ok(None)
		}
	}

	async fn find_object_by_sequence(
		&self, actor_address: &ActorAddress, sequence: u64,
	) -> Result<Option<object::Model>> {
		if let Some(actor) = identity::Entity::find()
			.filter(identity::Column::Address.eq(actor_address))
			.one(self.inner())
			.await?
		{
			Ok(object::Entity::find()
				.filter(object::Column::ActorId.eq(actor.id))
				.filter(object::Column::Sequence.eq(sequence))
				.one(self.inner())
				.await?)
		} else {
			Ok(None)
		}
	}

	async fn load_object_payload_info(
		&self, object_id: i64, object_type: u8,
	) -> Result<Option<ObjectPayloadInfo>> {
		Ok(match object_type {
			OBJECT_TYPE_POST => self
				.find_post_object_info(object_id)
				.await?
				.map(|r| ObjectPayloadInfo::Post(r)),
			OBJECT_TYPE_SHARE => self
				.find_share_object_info(object_id)
				.await?
				.map(|r| ObjectPayloadInfo::Share(r)),
			OBJECT_TYPE_PROFILE => self
				.find_profile_object_info(object_id)
				.await?
				.map(|r| ObjectPayloadInfo::Profile(r)),
			other => panic!("unknown object type: {}", other),
		})
	}

	async fn find_profile_object_info(&self, object_id: i64) -> Result<Option<ProfileObjectInfo>> {
		let result = self
			.inner()
			.query_one(Statement::from_sql_and_values(
				self.inner().get_database_backend(),
				r#"
			SELECT i.address, po.name, po.avatar_file_hash, po.wallpaper_file_hash, df.id,
			       df.plain_hash, df.block_count
			FROM profile_object AS po
			LEFT JOIN object AS o ON po.object_id = o.id
			LEFT JOIN identity AS i ON o.actor_id = i.id
			LEFT JOIN file AS df ON po.description_file_hash = df.hash
			WHERE o.id = ?
		"#,
				[object_id.into()],
			))
			.await?;

		if let Some(row) = result {
			let actor_address: ActorAddress = row.try_get_by_index(0)?;
			let actor_name: String = row.try_get_by_index(1)?;
			let avatar_id: Option<IdType> = row.try_get_by_index(2)?;
			let wallpaper_id: Option<IdType> = row.try_get_by_index(3)?;
			let description_id: Option<i64> = row.try_get_by_index(4)?;
			let description_plain_hash: Option<IdType> = row.try_get_by_index(5)?;
			let description_block_count: Option<i64> = row.try_get_by_index(6)?;

			let description = if let Some(file_id) = description_id {
				self.find_file_data(
					file_id,
					&description_plain_hash.unwrap(),
					description_block_count.unwrap() as _,
				)
				.await?
			} else {
				None
			};
			Ok(Some(ProfileObjectInfo {
				actor: TargetedActorInfo {
					address: actor_address.to_string(),
					name: actor_name,
					avatar_id,
					wallpaper_id,
				},
				description: description.map(|b| String::from_utf8_lossy(&b).to_string()),
			}))
		} else {
			Ok(None)
		}
	}

	async fn find_share_object_info(&self, object_id: i64) -> Result<Option<ShareObjectInfo>> {
		let result = self
			.inner()
			.query_one(Statement::from_sql_and_values(
				self.inner().get_database_backend(),
				r#"
			SELECT bo.actor_address, bi.id, to_.id
			FROM object AS o
			LEFT JOIN boost_object AS bo ON bo.object_id = o.id
			LEFT JOIN identity AS i ON o.actor_id = i.id
			LEFT JOIN identity AS bi ON bo.actor_address = bi.address
			LEFT JOIN object AS to_ ON to_.hash = bo.object_hash
			WHERE o.id = ?
		"#,
				[object_id.into()],
			))
			.await?;

		if let Some(row) = result {
			let actor_address: ActorAddress = row.try_get_by_index(0)?;
			let target_actor_id_opt: Option<i64> = row.try_get_by_index(1)?;
			let target_object_id_opt: Option<i64> = row.try_get_by_index(2)?;

			if let Some(target_object_id) = target_object_id_opt {
				let (actor_name, actor_avatar) = if let Some(target_actor_id) = target_actor_id_opt
				{
					self.find_profile_limited(target_actor_id).await?
				} else {
					(None, None)
				};
				let mut share_object = ShareObjectInfo::default();
				if let Some((mime_type, body, attachments)) =
					self.find_post_object_info_files(target_object_id).await?
				{
					share_object.original_post = Some(TargetedPostInfo {
						actor_address: actor_address.to_string(),
						actor_name,
						actor_avatar,
						message: Some((mime_type, body)),
						attachments,
					})
				} else {
					share_object.original_post = Some(TargetedPostInfo {
						actor_address: actor_address.to_string(),
						actor_name,
						actor_avatar,
						message: None,
						attachments: Vec::new(),
					})
				};
				Ok(Some(share_object))
			} else {
				Ok(None)
			}
		} else {
			Ok(None)
		}
	}

	/// Finds the mime-type, text content & attachments for the given post
	/// object respectively.
	async fn find_post_object_info_files(
		&self, object_id: i64,
	) -> Result<Option<(String, String, Vec<PossiblyKnownFileHeader>)>> {
		fn file_query<F>(backend: DatabaseBackend, object_id: i64, condition: F) -> Statement
		where
			F: IntoCondition,
		{
			file::Entity::find()
				.join(
					JoinType::LeftJoin,
					file::Entity::belongs_to(post_files::Entity)
						.from(file::Column::Hash)
						.to(post_files::Column::Hash)
						.into(),
				)
				.filter(post_files::Column::ObjectId.eq(object_id))
				.filter(condition)
				.order_by(post_files::Column::Sequence, Order::Asc)
				.build(backend)
		}

		let query = post_object::Entity::find()
			.filter(post_object::Column::ObjectId.eq(object_id))
			.build(self.inner().get_database_backend());
		let result = self.inner().query_one(query).await?;

		if let Some(r) = result {
			let file_count: i64 = r.try_get_by("file_count")?;

			let query = file_query(
				self.inner().get_database_backend(),
				object_id,
				post_files::Column::Sequence.eq(0),
			);
			if let Some(row) = self.inner().query_one(query).await? {
				//let file_hash: IdType = row.try_get_by(file::Column::Hash.as_str())?;
				let file_id_opt: Option<i64> = row.try_get_by(file::Column::Id.as_str())?;
				if let Some(file_id) = file_id_opt {
					let plain_hash: IdType = row.try_get_by(file::Column::PlainHash.as_str())?;
					let mime_type: String = row.try_get_by(file::Column::MimeType.as_str())?;
					let block_count: u32 = row.try_get_by(file::Column::BlockCount.as_str())?;

					let body_opt =
						match self.find_file_data(file_id, &plain_hash, block_count).await {
							Ok(message_data_opt) =>
								message_data_opt.map(|md| String::from_utf8_lossy(&md).to_string()),
							Err(e) => match &*e {
								// If a block is still missing from the message data file, don't
								// actually raise an error, just leave the message data unset.
								Error::FileMissingBlock(..) => None,
								_ => return Err(e),
							},
						};

					if let Some(body) = body_opt {
						// Collect the files
						let mut attachments = Vec::with_capacity(file_count as _);
						let query = file_query(
							self.inner().get_database_backend(),
							object_id,
							post_files::Column::Sequence.gt(0),
						);
						let results = self.inner().query_all(query).await?;
						for row in results {
							let hash: IdType = row.try_get_by_index(0)?;
							let mime_type_opt: Option<String> = row.try_get_by_index(3)?;
							let attachment = if let Some(mime_type) = mime_type_opt {
								let block_count: u32 = row.try_get_by_index(4)?;

								PossiblyKnownFileHeader::Known(FileHeader {
									hash,
									mime_type,
									block_count,
								})
							} else {
								PossiblyKnownFileHeader::Unknown(hash)
							};
							attachments.push(attachment);
						}

						return Ok(Some((mime_type, body, attachments)));
					}
				}
			}
		}
		Ok(None)
	}

	/// Finds `PostObjectInfo` for the given `object_id`.
	async fn find_post_object_info(&self, object_id: i64) -> Result<Option<PostObjectInfo>> {
		let result = self
			.inner()
			.query_one(Statement::from_sql_and_values(
				self.inner().get_database_backend(),
				r#"
			SELECT o.actor_id, o.sequence, ti.id, ti.address, tpo.object_id
			FROM post_object AS po
			INNER JOIN object AS o ON po.object_id = o.id
			INNER JOIN identity AS i ON o.actor_id = i.id
			LEFT JOIN identity AS ti ON po.in_reply_to_actor_address = ti.address
			LEFT JOIN object AS to_ ON to_.actor_id = ti.id
				AND to_.hash = po.in_reply_to_object_hash
			LEFT JOIN post_object as tpo ON tpo.object_id = to_.id
			WHERE po.object_id = ?
		"#,
				[object_id.into()],
			))
			.await?;

		if let Some(r) = result {
			let object_sequence: i64 = r.try_get_by_index(1)?;
			let irt_actor_rowid: Option<i64> = r.try_get_by_index(2)?;
			let irt_actor_address_opt: Option<ActorAddress> = r.try_get_by_index(3)?;
			let irt_object_id_opt: Option<i64> = r.try_get_by_index(4)?;

			let in_reply_to = match irt_object_id_opt {
				None => None,
				Some(irt_object_id) => {
					let (irt_actor_name, irt_actor_avatar_id) = match irt_actor_rowid {
						None => (None, None),
						Some(id) => self.find_profile_limited(id).await?,
					};
					let irt_message_opt = self.find_post_object_info_files(irt_object_id).await?;
					Some(TargetedPostInfo {
						actor_address: irt_actor_address_opt.unwrap().to_string(),
						actor_name: irt_actor_name,
						actor_avatar: irt_actor_avatar_id,
						message: irt_message_opt.clone().map(|(mt, b, _)| (mt, b)),
						attachments: irt_message_opt.map(|(_, _, a)| a).unwrap_or(Vec::new()),
					})
				}
			};

			let message_opt = self.find_post_object_info_files(object_id).await?;
			Ok(Some(PostObjectInfo {
				in_reply_to,
				sequence: object_sequence as _,
				mime_type: message_opt.as_ref().map(|o| o.0.clone()),
				message: message_opt.as_ref().map(|(_, b, _)| b.clone()),
				attachments: message_opt.map(|(_, _, a)| a).unwrap_or(Vec::new()),
			}))
		} else {
			Ok(None)
		}
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

	async fn _load_object_info_from_result(
		&self, actor_address: &ActorAddress, result: &sea_orm::QueryResult,
	) -> Result<Option<ObjectInfo>> {
		let object_id: i64 = result.try_get_by("id")?;
		let object_type: u8 = result.try_get_by("type")?;
		let actor_id: i64 = result.try_get_by("actor_id")?;
		let payload_result = self
			.load_object_payload_info(object_id, object_type)
			.await?;

		if let Some(payload) = payload_result {
			let (actor_name, actor_avatar) = self.find_profile_limited(actor_id).await?;

			let created: i64 = result.try_get_by("created")?;
			let found: i64 = result.try_get_by("found")?;
			Ok(Some(ObjectInfo {
				hash: result.try_get_by("hash")?,
				created: created as _,
				found: found as _,
				actor_address: actor_address.clone(),
				actor_name,
				actor_avatar,
				payload,
			}))
		} else {
			Ok(None)
		}
	}
}


impl FromSql for ActorAddress {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Blob(blob) =>
				if blob.len() != 33 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 33,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(blob).map_err(|e| FromSqlError::Other(Box::new(e)))?)
				},
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
			ValueRef::Blob(blob) =>
				if blob.len() != 57 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 57,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(*array_ref![blob, 0, 57]).unwrap())
				},
			_ => Err(FromSqlError::InvalidType),
		}
	}
}

impl FromSql for ActorPrivateKeyV1 {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Blob(blob) =>
				if blob.len() != 57 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 57,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(*array_ref![blob, 0, 57]))
				},
			_ => Err(FromSqlError::InvalidType),
		}
	}
}

impl FromSql for ActorSignatureV1 {
	fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
		match value {
			ValueRef::Blob(blob) =>
				if blob.len() != 114 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 114,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(*array_ref![blob, 0, 114]))
				},
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
			ValueRef::Blob(blob) =>
				if blob.len() != 32 {
					Err(FromSqlError::InvalidBlobSize {
						expected_size: 32,
						blob_size: blob.len(),
					})
				} else {
					Ok(Self::from_bytes(*array_ref![blob, 0, 32])
						.map_err(|e| FromSqlError::Other(Box::new(e)))?)
				},
			_ => Err(FromSqlError::InvalidType),
		}
	}
}

impl Database {
	pub fn connect_old(&self) -> self::Result<Connection> { Ok(Connection::open_old(&self.path)?) }

	/// Runs the given closure, which pauzes the task that runs it, but doesn't
	/// block the runtime.
	pub fn perform<T>(&self, task: impl FnOnce(Connection) -> Result<T>) -> Result<T> {
		tokio::task::block_in_place(move || {
			let connection = self.connect_old()?;
			task(connection)
		})
	}

	fn install(conn: &Connection) -> Result<()> { Ok(conn.execute_batch(install::QUERY)?) }

	fn is_outdated(major: u8, minor: u16, patch: u16) -> bool {
		major < DATABASE_VERSION.0 || minor < DATABASE_VERSION.1 || patch < DATABASE_VERSION.2
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
					Some(error_message) =>
						if error_message == "no such table: version" {
							Self::install(&connection)?;
						} else {
							Err(e)?;
						},
					None => Err(e)?,
				},
				_ => Err(e)?,
			},
		}

		let mut opts = ConnectOptions::new(format!("sqlite://{}?mode=rwc", path.display()));
		opts.idle_timeout(Duration::from_secs(10));
		opts.acquire_timeout(Duration::from_secs(1));
		let orm = sea_orm::Database::connect(opts)
			.await
			.map_err(|e| self::Error::OrmError(e))?;

		Ok(Self { path, orm })
	}

	pub async fn transaction(&self) -> Result<Transaction> {
		let tx = self.orm.begin().await?;
		Ok(Transaction(tx))
	}

	fn upgrade(_conn: &rusqlite::Connection) {
		panic!("No database upgrade implemented yet!");
	}
}

impl Connection {
	fn _fetch_actor_info<C>(this: &C, identity_id: i64) -> Result<Option<TargetedActorInfo>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT i.address, p.name, af.hash, wf.hash
			FROM identity AS i
			LEFT JOIN profile AS p ON p.identity_id = i.id
			LEFT JOIN file AS af ON p.avatar_file_id = f.id
			LEFT JOIN file AS wf ON p.wallpaper_file_id = f.id
			WHERE id = ?
		"#,
		)?;
		let mut rows = stat.query([identity_id])?;
		if let Some(row) = rows.next()? {
			let address: ActorAddress = row.get(0)?;
			let name = row.get(1)?;
			let avatar_id: Option<IdType> = row.get(2)?;
			let wallpaper_id: Option<IdType> = row.get(3)?;

			Ok(Some(TargetedActorInfo {
				address: address.to_string(),
				name,
				avatar_id,
				wallpaper_id,
			}))
		} else {
			Ok(None)
		}
	}

	fn _fetch_block_data<C>(this: &C, id: &IdType) -> Result<Option<Vec<u8>>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT id, size, data FROM block WHERE hash = ?
		"#,
		)?;
		let mut rows = stat.query([id.to_string()])?;
		if let Some(row) = rows.next()? {
			let rowid: i64 = row.get(0)?;
			let size: usize = row.get(1)?;
			let data: Vec<u8> = row.get(2)?;

			if data.len() < size {
				Err(Error::BlockDataCorrupt(rowid))?
			} else if data.len() > size {
				warn!(
					"Block {} data blob is is larger than its size: {} > {}",
					id,
					data.len(),
					size
				);
				Ok(Some(data[..size].to_vec()))
			} else {
				Ok(Some(data))
			}
		} else {
			Ok(None)
		}
	}

	fn _fetch_file<C>(this: &C, hash: &IdType) -> Result<Option<(String, Vec<u8>)>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT id, plain_hash, mime_type, block_count FROM file WHERE hash = ?
		"#,
		)?;
		let mut rows = stat.query([hash.to_string()])?;
		if let Some(row) = rows.next()? {
			let rowid = row.get(0)?;
			let plain_hash: IdType = row.get(1)?;
			let mime_type = row.get(2)?;
			let block_count = row.get(3)?;

			let data = Self::_fetch_file_data(this, rowid, &plain_hash, block_count)?;
			Ok(Some((mime_type, data)))
		} else {
			Ok(None)
		}
	}

	pub(super) fn _fetch_file_block_hash(
		this: &impl DerefConnection, file_id: i64, sequence: u64,
	) -> Result<Option<IdType>> {
		let mut stat = this.prepare(
			r#"
			SELECT block_hash FROM file_block WHERE file_id = ? AND sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![file_id, sequence])?;

		if let Some(row) = rows.next()? {
			let hash: IdType = row.get(0)?;
			Ok(Some(hash))
		} else {
			Ok(None)
		}
	}

	fn _fetch_file_data(
		this: &impl DerefConnection, file_id: i64, plain_hash: &IdType, block_count: u64,
	) -> Result<Vec<u8>> {
		let mut stat = this.prepare(
			r#"
			SELECT fb.block_hash, fb.sequence, b.id, b.size, b.data
			FROM file_blocks AS fb
			LEFT JOIN block AS b ON fb.block_hash = b.hash
			WHERE file_id = ?
			ORDER BY fb.sequence ASC
		"#,
		)?;
		let mut rows = stat.query([file_id])?;

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
		while let Some(row) = rows.next()? {
			let sequence: u64 = row.get(1)?;
			if sequence != i {
				Err(Error::FileMissingBlock(file_id, sequence))?;
			}
			let block_id: Option<i64> = row.get(2)?;
			let size2: Option<usize> = row.get(3)?;
			let data2: Option<Vec<u8>> = row.get(4)?;

			if block_id.is_none() {
				Err(Error::FileMissingBlock(file_id, sequence))?;
			}
			let size = size2.unwrap();
			let mut data = data2.unwrap();
			data.resize(size, 0);

			if data.len() < size {
				Err(Error::BlockDataCorrupt(block_id.unwrap()))?;
			} else if data.len() > size {
				warn!(
					"Block {} has more data than its size: {} > {}",
					block_id.unwrap(),
					data.len(),
					size
				);
			}

			decrypt_block(i, plain_hash, &mut data);
			buffer.extend(&data);
			i += 1;
		}

		Ok(buffer)
	}

	fn _fetch_object(
		this: &impl DerefConnection, hash: &IdType,
	) -> Result<Option<(IdType, Object, bool)>> {
		let mut stat = this.prepare(
			r#"
			SELECT o.id, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM object AS o
			WHERE o.hash = ?
		"#,
		)?;
		let mut rows = stat.query(params![hash.to_string()])?;
		Self::_parse_object(this, &mut rows)
	}

	fn _fetch_object_by_sequence_old(
		this: &impl DerefConnection, actor_id: &ActorAddress, sequence: u64,
	) -> Result<Option<(IdType, Object, bool)>> {
		let mut stat = this.prepare(
			r#"
			SELECT o.id, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, sequence])?;
		Self::_parse_object(this, &mut rows)
	}

	pub fn _fetch_object_hash_by_sequence<C>(
		this: &C, actor_address: &ActorAddress, sequence: u64,
	) -> Result<IdType>
	where
		C: DerefConnection,
	{
		let id: IdType = this.query_row(
			r#"
			SELECT o.hash FROM object AS o LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ? AND o.sequence = ?
		"#,
			params![actor_address, sequence],
			|r| r.get(0),
		)?;
		Ok(id)
	}

	fn _fetch_object_id_by_sequence<C>(
		this: &C, actor_id: i64, sequence: u64,
	) -> Result<Option<i64>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT id FROM object WHERE actor_id = ? AND sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, sequence])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => {
				let object_id = row.get(0)?;
				Ok(Some(object_id))
			}
		}
	}

	fn _fetch_head<C>(tx: &C, actor_id: &ActorAddress) -> Result<Option<(IdType, Object, bool)>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT o.id, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ?
			ORDER BY sequence DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query(params![actor_id])?;
		Self::_parse_object(tx, &mut rows)
	}

	fn _fetch_last_verified_object<C>(
		tx: &C, actor_address: &ActorAddress,
	) -> Result<Option<(IdType, Object, bool)>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT o.id, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ? AND o.verified_from_start = TRUE
			ORDER BY sequence DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query(params![actor_address])?;
		Self::_parse_object(tx, &mut rows)
	}

	/*pub fn _fetch_post_files(&self, post_id: i64) -> Result<Vec<FileHeader>> {
		let mut stat = self.old().prepare(
			r#"
			SELECT hash, mime_type, block_count FROM file WHERE post_id = ?
		"#,
		)?;
		let mut rows = stat.query([post_id])?;
		let mut files = Vec::new();
		while let Some(row) = rows.next()? {
			let hash: String = row.get(0)?;
			let hash_id = IdType::from_base58(&hash)?;
			files.push(FileHeader {
				hash: hash_id,
				mime_type: row.get(1)?,
				block_count: row.get(2)?,
			});
		}
		Ok(files)
	}*/

	pub fn _fetch_share_object<C>(this: &C, object_id: i64) -> Result<Option<ShareObject>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT actor_address, object_hash
			FROM boost_object
			WHERE object_id = ?
		"#,
		)?;
		let mut rows = stat.query([object_id])?;
		if let Some(row) = rows.next()? {
			let post_actor_address: ActorAddress = row.get(0)?;
			let object_sequence = row.get(1)?;

			Ok(Some(ShareObject {
				actor_address: post_actor_address,
				object_hash: object_sequence,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _fetch_boost_object_info(
		this: &impl DerefConnection, actor_id: i64, sequence: u64,
	) -> Result<Option<ShareObjectInfo>> {
		let mut stat = this.prepare(
			r#"
			SELECT bo.actor_address, bi.id, to_.id
			FROM object AS o
			LEFT JOIN boost_object AS bo ON bo.object_id = o.id
			LEFT JOIN identity AS i ON o.actor_id = i.id
			LEFT JOIN identity AS bi ON bo.actor_address = bi.address
			LEFT JOIN object AS to_ ON to_.hash = bo.object_hash
			WHERE o.actor_id = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, sequence])?;

		if let Some(row) = rows.next()? {
			let actor_address: ActorAddress = row.get(0)?;
			let target_actor_id_opt: Option<i64> = row.get(1)?;
			let target_object_id_opt: Option<i64> = row.get(2)?;

			let mut boost_object = ShareObjectInfo::default();
			if let Some(target_object_id) = target_object_id_opt {
				let (actor_name, actor_avatar) = if let Some(target_actor_id) = target_actor_id_opt
				{
					Self::_find_profile_limited(this, target_actor_id)?
				} else {
					(None, None)
				};
				let (message, attachments) =
					Self::_fetch_post_object_info_files(this, target_object_id)?;
				boost_object.original_post = Some(TargetedPostInfo {
					actor_address: actor_address.to_string(),
					actor_name,
					actor_avatar,
					message,
					attachments,
				});
			}
			Ok(Some(boost_object))
		} else {
			Ok(None)
		}
	}

	fn _fetch_post_files(this: &impl DerefConnection, object_id: i64) -> Result<Vec<IdType>> {
		// Collect the files
		let mut files = Vec::new();
		let mut stat = this.prepare(
			r#"
			SELECT hash
			FROM post_files
			WHERE object_id = ?
			ORDER BY sequence ASC
		"#,
		)?;
		let mut rows = stat.query([object_id])?;
		while let Some(row) = rows.next()? {
			let hash: IdType = row.get(0)?;

			files.push(hash);
		}

		Ok(files)
	}

	fn _fetch_post_object_info_files<C>(
		this: &C, object_id: i64,
	) -> Result<(Option<(String, String)>, Vec<PossiblyKnownFileHeader>)>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT file_count FROM post_object WHERE object_id = ?
		"#,
		)?;
		let mut rows = stat.query([object_id])?;
		if let Some(row) = rows.next()? {
			let file_count: u64 = row.get(0)?;

			// Collect the message file
			let mut stat = this.prepare(
				r#"
				SELECT f.id, f.plain_hash, f.mime_type, f.block_count
				FROM post_files AS pf
				LEFT JOIN file AS f ON pf.hash = f.hash
				WHERE pf.object_id = ? AND pf.sequence = 0
				ORDER BY pf.sequence ASC
			"#,
			)?;
			let mut rows = stat.query([object_id])?;
			let message_opt: Option<(String, String)> = if let Some(row) = rows.next()? {
				let file_id_opt: Option<i64> = row.get(0)?;
				let plain_hash_opt: Option<IdType> = row.get(1)?;
				let mime_type_opt: Option<String> = row.get(2)?;
				let block_count_opt: Option<u64> = row.get(3)?;
				if let Some(file_id) = file_id_opt {
					let plain_hash = plain_hash_opt.unwrap();
					let mime_type = mime_type_opt.unwrap();
					let block_count = block_count_opt.unwrap();
					match Self::_fetch_file_data(this, file_id, &plain_hash, block_count) {
						Ok(message_data) => Some((
							mime_type,
							String::from_utf8_lossy(&message_data).to_string(),
						)),
						Err(e) => match &*e {
							// If a block is still missing from the message data file, don't
							// actually raise an error, just leave the message data unset.
							Error::FileMissingBlock(..) => None,
							_ => return Err(e),
						},
					}
				} else {
					None
				}
			} else {
				None
			};

			// Collect the files
			let mut attachments = Vec::with_capacity(file_count as _);
			let mut stat = this.prepare(
				r#"
				SELECT pf.hash, f.mime_type, f.block_count
				FROM post_files AS pf
				LEFT JOIN file AS f ON f.hash = pf.hash
				WHERE pf.object_id = ? AND pf.sequence > 0
				ORDER BY pf.sequence ASC
			"#,
			)?;
			let mut rows = stat.query([object_id])?;
			while let Some(row) = rows.next()? {
				let hash: IdType = row.get(0)?;
				let mime_type_opt: Option<String> = row.get(1)?;
				let block_count_opt: Option<u32> = row.get(2)?;
				let attachment = if let Some(mime_type) = mime_type_opt {
					let block_count = block_count_opt.unwrap();
					PossiblyKnownFileHeader::Known(FileHeader {
						hash,
						mime_type,
						block_count,
					})
				} else {
					PossiblyKnownFileHeader::Unknown(hash)
				};
				attachments.push(attachment);
			}

			Ok((message_opt, attachments))
		} else {
			Ok((None, Vec::new()))
		}
	}

	fn _fetch_post_object_info(
		this: &impl DerefConnection, actor_id: i64, sequence: u64,
	) -> Result<Option<PostObjectInfo>> {
		let mut stat = this.prepare(
			r#"
			SELECT o.id, o.sequence, ti.id, ti.address, tpo.object_id, to_.sequence
			FROM post_object AS po
			INNER JOIN object AS o ON po.object_id = o.id
			INNER JOIN identity AS i ON o.actor_id = i.id
			LEFT JOIN identity AS ti ON po.in_reply_to_actor_address = ti.address
			LEFT JOIN object AS to_ ON to_.actor_id = ti.id
			    AND to_.hash = po.in_reply_to_object_hash
			LEFT JOIN post_object as tpo ON tpo.object_id = to_.id
			WHERE o.actor_id = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, sequence])?;
		if let Some(row) = rows.next()? {
			let object_id = row.get(0)?;
			let sequence = row.get(1)?;
			let irt_actor_rowid: Option<i64> = row.get(2)?;
			let irt_actor_address_opt: Option<ActorAddress> = row.get(3)?;
			let irt_object_id_opt: Option<i64> = row.get(4)?;
			//let irt_sequence: Option<u64> = row.get(5)?;

			let in_reply_to = match irt_object_id_opt {
				None => None,
				Some(irt_object_id) => {
					let (irt_actor_name, irt_actor_avatar_id) = match irt_actor_rowid {
						None => (None, None),
						Some(id) => Self::_find_profile_limited(this, id)?,
					};
					let (irt_message_opt, irt_attachments) =
						Self::_fetch_post_object_info_files(this, irt_object_id)?;
					Some(TargetedPostInfo {
						actor_address: irt_actor_address_opt.unwrap().to_string(),
						actor_name: irt_actor_name,
						actor_avatar: irt_actor_avatar_id,
						message: irt_message_opt,
						attachments: irt_attachments,
					})
				}
			};
			let (message_opt, attachments) = Self::_fetch_post_object_info_files(this, object_id)?;
			Ok(Some(PostObjectInfo {
				in_reply_to,
				sequence,
				mime_type: message_opt.as_ref().map(|o| o.0.clone()),
				message: message_opt.map(|o| o.1),
				attachments,
			}))
		} else {
			Ok(None)
		}
	}

	fn _fetch_post_object(
		this: &impl DerefConnection, object_id: i64,
	) -> Result<Option<PostObject>> {
		let mut stat = this.prepare(
			r#"
			SELECT in_reply_to_actor_address, in_reply_to_object_hash
			FROM post_object
			WHERE object_id = ?
		"#,
		)?;
		let mut rows = stat.query([object_id])?;
		if let Some(row) = rows.next()? {
			let irt_actor_address: Option<ActorAddress> = row.get(0)?;
			let irt_object_id: Option<IdType> = row.get(1)?;
			let tags = Self::_fetch_post_tags(this, object_id)?;
			let files = Self::_fetch_post_files(this, object_id)?;

			Ok(Some(PostObject {
				in_reply_to: if irt_actor_address.is_some() && irt_object_id.is_some() {
					Some((irt_actor_address.unwrap(), irt_object_id.unwrap()))
				} else {
					None
				},
				data: PostObjectCryptedData::Plain(PostObjectDataPlain { tags, files }),
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _fetch_profile_object(
		this: &impl DerefConnection, object_id: i64,
	) -> Result<Option<ProfileObject>> where
		//C: DerefConnection
	{
		let mut stat = this.prepare(
			r#"
			SELECT name, avatar_file_hash, wallpaper_file_hash, description_file_hash
			FROM profile_object
			WHERE object_id = ?
		"#,
		)?;
		let mut rows = stat.query([object_id])?;
		if let Some(row) = rows.next()? {
			let name: Option<String> = row.get(0)?;
			if name.is_none() {
				return Ok(None);
			}
			let avatar_id: Option<IdType> = row.get(1)?;
			let wallpaper_id: Option<IdType> = row.get(2)?;
			let description_hash: Option<IdType> = row.get(3)?;
			Ok(Some(ProfileObject {
				name: name.unwrap(),
				avatar: avatar_id,
				wallpaper: wallpaper_id,
				description: description_hash,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _fetch_profile_object_info(
		this: &impl DerefConnection, actor_id: i64, sequence: u64,
	) -> Result<Option<ProfileObjectInfo>> where
		//C: DerefConnection
	{
		let mut stat = this.prepare(
			r#"
			SELECT i.address, po.name, po.avatar_file_hash, po.wallpaper_file_hash, df.id,
			       df.plain_hash, df.block_count
			FROM profile_object AS po
			LEFT JOIN object AS o ON po.object_id = o.id
			LEFT JOIN identity AS i ON o.actor_id = i.id
			LEFT JOIN file AS df ON po.description_file_hash = df.hash
			WHERE o.actor_id = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, sequence])?;
		if let Some(row) = rows.next()? {
			let actor_address: ActorAddress = row.get(0)?;
			let actor_name: String = row.get(1)?;
			let avatar_id: Option<IdType> = row.get(2)?;
			let wallpaper_id: Option<IdType> = row.get(3)?;
			let description_id: Option<i64> = row.get(4)?;
			let description_plain_hash: Option<IdType> = row.get(5)?;
			let description_block_count: Option<i64> = row.get(6)?;

			let description = if let Some(file_id) = description_id {
				Some(Self::_fetch_file_data(
					this,
					file_id,
					&description_plain_hash.unwrap(),
					description_block_count.unwrap() as _,
				)?)
			} else {
				None
			};
			Ok(Some(ProfileObjectInfo {
				actor: TargetedActorInfo {
					address: actor_address.to_string(),
					name: actor_name,
					avatar_id,
					wallpaper_id,
				},
				description: description.map(|b| String::from_utf8_lossy(&b).to_string()),
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _fetch_post_tags(tx: &impl DerefConnection, object_id: i64) -> Result<Vec<String>> {
		let mut stat = tx.prepare(
			r#"
			SELECT tag FROM post_tag WHERE object_id = ?
		"#,
		)?;
		let rows = stat.query([object_id])?;
		rows.map(|r| r.get(0)).collect().map_err(|e| e.into())
	}

	pub(crate) fn _find_identity<C>(tx: &C, address: &ActorAddress) -> rusqlite::Result<Option<i64>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT id FROM identity WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query([address])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(Some(row.get(0)?)),
		}
	}

	/// Finds the name and avatar file hash of an actor.
	/// Tries to return it's known profile name & avatar.
	fn _find_profile_limited(
		tx: &impl DerefConnection, actor_id: i64,
	) -> Result<(Option<String>, Option<IdType>)> {
		let mut stat = tx.prepare(
			r#"
			SELECT po.name, po.avatar_file_hash
			FROM profile_object AS po
			INNER JOIN object AS o ON po.object_id = o.id
			WHERE o.actor_id = ?
			ORDER BY o.id DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query([actor_id])?;
		Ok(if let Some(row) = rows.next()? {
			let name: String = row.get(0)?;
			let avatar_id: Option<IdType> = row.get(1)?;
			(Some(name), avatar_id)
		} else {
			(None, None)
		})
	}

	/// Returns the lastest object sequence for an actor if available.
	async fn _max_object_sequence(
		&self, tx: &impl ConnectionTrait, actor_id: i64,
	) -> self::Result<Option<u64>> {
		let stat = object::Entity::find()
			.column_as(object::Column::Sequence.max(), "max")
			.filter(object::Column::ActorId.eq(actor_id))
			.build(self.backend);

		if let Some(result) = tx.query_one(stat).await? {
			Ok(Some(result.try_get_by_index::<i64>(0)? as u64))
		} else {
			Ok(None)
		}
	}

	/// Returns the lastest object sequence for an actor if available.
	fn _max_object_sequence_old<C>(tx: &C, actor_id: i64) -> rusqlite::Result<Option<u64>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT MAX(sequence) FROM object WHERE actor_id = ?
		"#,
		)?;
		let mut rows = stat.query([actor_id])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(row.get(0)?),
		}
	}

	/// Returns the lastest object sequence for an actor if available.
	fn _max_object_sequence_by_address<C>(
		tx: &C, actor_address: &IdType,
	) -> rusqlite::Result<Option<u64>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT MAX(o.sequence)
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ?
		"#,
		)?;
		let mut rows = stat.query([actor_address.to_string()])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(row.get(0)?),
		}
	}

	/// Returns the sequence that the next object would use.
	pub(crate) async fn _next_object_sequence(
		&self, tx: &impl ConnectionTrait, actor_id: i64,
	) -> Result<u64> {
		match self._max_object_sequence(tx, actor_id).await? {
			None => Ok(0),
			Some(s) => Ok(s + 1),
		}
	}

	/// Returns the sequence that the next object would use.
	pub(crate) fn _next_object_sequence_old<C>(tx: &C, actor_id: i64) -> Result<u64>
	where
		C: DerefConnection,
	{
		match Self::_max_object_sequence_old(tx, actor_id)? {
			None => Ok(0),
			Some(s) => Ok(s + 1),
		}
	}

	/// Returns the sequence that the next object would use.
	fn _next_object_sequence_by_address<C>(tx: &C, actor_address: &IdType) -> Result<u64>
	where
		C: DerefConnection,
	{
		match Self::_max_object_sequence_by_address(tx, actor_address)? {
			None => Ok(0),
			Some(s) => Ok(s + 1),
		}
	}

	fn _parse_object(
		tx: &impl DerefConnection, rows: &mut Rows<'_>,
	) -> Result<Option<(IdType, Object, bool)>> {
		if let Some(row) = rows.next()? {
			let object_id = row.get(0)?;
			let sequence = row.get(1)?;
			let created = row.get(2)?;
			let signature: ActorSignatureV1 = row.get(3)?;
			let hash: IdType = row.get(4)?;
			let object_type = row.get(5)?;
			let previous_hash: Option<IdType> = row.get(6)?;
			let verified_from_start: bool = row.get(7)?;

			let payload = match object_type {
				OBJECT_TYPE_POST => Self::_fetch_post_object(tx, object_id)
					.map(|o| o.map(|p| ObjectPayload::Post(p))),
				OBJECT_TYPE_SHARE => Self::_fetch_share_object(tx, object_id)
					.map(|o| o.map(|b| ObjectPayload::Share(b))),
				OBJECT_TYPE_PROFILE => Self::_fetch_profile_object(tx, object_id)
					.map(|o| o.map(|p| ObjectPayload::Profile(p))),
				other => Err(Error::InvalidObjectType(other))?,
			};
			payload.map(|o| {
				o.map(|p| {
					(
						hash,
						Object {
							sequence,
							previous_hash: previous_hash.unwrap_or_default(),
							created,
							signature,
							payload: p,
						},
						verified_from_start,
					)
				})
			})
		} else {
			Ok(None)
		}
	}

	fn _parse_object_info(
		tx: &impl DerefConnection, rows: &mut Rows<'_>,
	) -> Result<Option<ObjectInfo>> {
		if let Some(row) = rows.next()? {
			let actor_id = row.get(0)?;
			let hash: IdType = row.get(1)?;
			let sequence = row.get(2)?;
			let created = row.get(3)?;
			let found = row.get(4)?;
			let object_type = row.get(5)?;
			let actor_address: ActorAddress = row.get(6)?;

			let (actor_name, actor_avatar_id) = Self::_find_profile_limited(tx, actor_id)?;
			let payload_result = match object_type {
				OBJECT_TYPE_POST => Self::_fetch_post_object_info(tx, actor_id, sequence)
					.map(|o| o.map(|p| ObjectPayloadInfo::Post(p))),
				OBJECT_TYPE_SHARE => Self::_fetch_boost_object_info(tx, actor_id, sequence)
					.map(|o| o.map(|b| ObjectPayloadInfo::Share(b))),
				OBJECT_TYPE_PROFILE => Self::_fetch_profile_object_info(tx, actor_id, sequence)
					.map(|o| o.map(|p| ObjectPayloadInfo::Profile(p))),
				other => Err(Error::InvalidObjectType(other))?,
			};
			let payload = if let Some(p) = payload_result? {
				p
			} else {
				return Ok(None);
			};
			Ok(Some(ObjectInfo {
				hash,
				created,
				found,
				actor_address,
				actor_name,
				actor_avatar: actor_avatar_id,
				payload,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _store_block(tx: &impl DerefConnection, hash: &IdType, data: &[u8]) -> Result<()> {
		let mut stat = tx.prepare(
			r#"
			INSERT INTO block (hash, size, data) VALUES (?,?,?)
		"#,
		)?;
		if let Err(e) = stat.insert(params![hash, data.len(), data]) {
			match e {
				rusqlite::Error::SqliteFailure(error, _) => {
					// If the hash already exists, do nothing, it is fine...
					if error.code != rusqlite::ErrorCode::ConstraintViolation {
						Err(e)?
					}
				}
				_ => Err(e)?,
			}
		}
		Ok(())
	}

	pub(crate) fn _store_file_data(
		tx: &impl DerefConnection, mime_type: &str, data: &[u8],
	) -> Result<(i64, IdType, Vec<IdType>)> {
		debug_assert!(data.len() <= u64::MAX as usize, "data too large");
		debug_assert!(data.len() > 0, "data can not be empty");
		let block_count = data.len() / BLOCK_SIZE + ((data.len() % BLOCK_SIZE) > 0) as usize;
		let mut blocks = Vec::with_capacity(block_count);
		let mut block_hashes = Vec::with_capacity(block_count);

		// Devide data into blocks
		let plain_hash = IdType::hash(data);
		let mut i = 0;
		let mut block_index = 0;
		loop {
			let slice = &data[i..];
			let actual_block_size = min(BLOCK_SIZE, slice.len());
			let mut block = slice[..actual_block_size].to_vec();
			encrypt_block(block_index, &plain_hash, &mut block);
			let block_hash = IdType::hash(&block);
			blocks.push(block);
			block_hashes.push(block_hash);

			block_index += 1;
			i += BLOCK_SIZE;
			if i >= data.len() {
				break;
			}
		}

		// Calculate the file hash
		let file_hash = IdType::hash(
			&binserde::serialize(&File {
				plain_hash: plain_hash.clone(),
				mime_type: mime_type.to_string(),
				blocks: block_hashes.clone(),
			})
			.unwrap(),
		);
		// FIXME: Prevent the unnecessary cloning just to calculate the file hash

		// Create the file record
		let file_id =
			Self::_store_file_record(tx, &file_hash, &plain_hash, mime_type, block_count as _)?;

		// Create block records
		for i in 0..block_count {
			let block_data = &blocks[i];
			let block_hash = &block_hashes[i];

			Self::_store_file_block(tx, file_id, i as _, block_hash, block_data)?;
		}
		Ok((file_id as _, file_hash, block_hashes))
	}

	pub(crate) fn _store_file(
		tx: &impl Deref<Target = rusqlite::Connection>, id: &IdType, plain_hash: &IdType,
		mime_type: &str, blocks: &[IdType],
	) -> Result<i64> {
		debug_assert!(blocks.len() <= u32::MAX as usize, "too many blocks");
		debug_assert!(blocks.len() > 0, "file must have at least one block");

		// Create the file record
		let file_id = Self::_store_file_record(tx, id, plain_hash, mime_type, blocks.len() as _)?;

		// Create block records
		for i in 0..blocks.len() {
			let hash = &blocks[i];
			tx.execute(
				r#"
				INSERT INTO file_blocks (file_id, block_hash, sequence)
				VALUES (?,?,?)
			"#,
				params![file_id, hash.to_string(), i],
			)?;
		}

		Ok(file_id)
	}

	fn _store_file_block(
		tx: &impl DerefConnection, file_id: i64, sequence: u64, hash: &IdType, data: &[u8],
	) -> Result<()> {
		Self::_store_block(tx, hash, data)?;

		tx.execute(
			r#"
			INSERT INTO file_blocks (file_id, block_hash, sequence) VALUES (?,?,?)
		"#,
			params![file_id, hash, sequence],
		)?;
		Ok(())
	}

	fn _store_file_record(
		tx: &impl DerefConnection, hash: &IdType, plain_hash: &IdType, mime_type: &str,
		block_count: u32,
	) -> Result<i64> {
		match tx.query_row(
			r#"
			SELECT id, plain_hash, mime_type, block_count FROM file WHERE hash = ?
		"#,
			[hash],
			|r| {
				let rowid: i64 = r.get(0)?;
				let ph: IdType = r.get(1)?;
				let mt: String = r.get(2)?;
				let bc: u32 = r.get(3)?;
				Ok((rowid, ph, mt, bc))
			},
		) {
			Ok((rowid, plain_hash2, mime_type2, block_count2)) => {
				if plain_hash == &plain_hash2
					&& mime_type == &mime_type2
					&& block_count == block_count2
				{
					return Ok(rowid);
				}
				// TODO: Return an error
			}
			Err(e) =>
				if e != rusqlite::Error::QueryReturnedNoRows {
					return trace::err(e.into());
				},
		}

		tx.execute(
			r#"
			INSERT INTO file (hash, plain_hash, mime_type, block_count)
			VALUES (?,?,?,?)
		"#,
			params![hash, plain_hash, mime_type, block_count],
		)?;
		Ok(tx.last_insert_rowid())
	}

	fn _store_identity(
		tx: &impl DerefConnection, address: &ActorAddress, public_key: &ActorPublicKeyV1,
		first_object: &IdType,
	) -> Result<i64> {
		let mut stat = tx.prepare(
			r#"
			INSERT INTO identity (address, public_key, first_object, type) VALUES (?,?,?,?)
		"#,
		)?;
		let rowid = stat.insert(params![
			address,
			public_key,
			first_object,
			ACTOR_TYPE_BLOGCHAIN
		])?;
		Ok(rowid)
	}

	fn _store_my_identity(
		tx: &impl DerefConnection, label: &str, private_key: &ActorPrivateKeyV1,
		first_object: &IdType, actor_type: String,
	) -> Result<i64> {
		let actor_info = ActorInfoV1 {
			flags: 0,
			public_key: private_key.public(),
			first_object: first_object.clone(),
			actor_type,
		};
		let address = ActorAddress::V1(actor_info.generate_id());
		let identity_id =
			Self::_store_identity(tx, &address, &actor_info.public_key, first_object)?;

		let mut stat = tx.prepare(
			r#"
			INSERT INTO my_identity (label, identity_id, private_key) VALUES (?,?,?)
		"#,
		)?;
		stat.insert(params![label, identity_id, private_key.as_bytes()])?;
		Ok(identity_id)
	}

	pub fn _store_object(
		tx: &impl DerefConnection, actor_address: &ActorAddress, id: &IdType, object: &Object,
		verified_from_start: bool,
	) -> Result<i64> {
		let mut stat = tx.prepare(
			r#"
			SELECT id FROM identity WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_address])?;
		if let Some(row) = rows.next()? {
			let actor_rowid: i64 = row.get(0)?;

			let mut stat = tx.prepare(
				r#"
			INSERT INTO object (
				actor_id, sequence, hash, signature, created, found, type, previous_hash,
				verified_from_start
			) VALUES(?,?,?,?,?,?,?,?,?)
			"#,
			)?;
			let object_id = stat.insert(params![
				actor_rowid,
				object.sequence,
				id.to_string(),
				object.signature,
				object.created,
				Utc::now().timestamp_millis(),
				object.payload.type_id(),
				object.previous_hash.to_string(),
				verified_from_start,
			])?;
			Self::_store_object_payload(tx, actor_rowid, object_id, &object.payload)?;
			Ok(object_id)
		} else {
			Err(Error::MissingIdentity(actor_address.clone()))?
		}
	}

	pub fn _store_post(
		tx: &impl DerefConnection, actor_id: i64, created: u64, previous_hash: &IdType,
		verified_from_start: bool, tags: &[String], files: &[IdType], hash: &IdType,
		signature: &ActorSignatureV1, in_reply_to: Option<(ActorAddress, IdType)>,
	) -> Result<()> {
		// Create post object
		let next_sequence = Self::_next_object_sequence_old(tx, actor_id)?;
		let mut stat = tx.prepare(
			r#"
			INSERT INTO object (
				actor_id, sequence, previous_hash, hash, signature, created, found, type, verified_from_start
			)
			VALUES (?,?,?,?,?,?,?,?,?)
		"#,
		)?;

		let object_id = stat.insert(params![
			actor_id,
			next_sequence,
			previous_hash.to_string(),
			hash.to_string(),
			signature,
			created,
			created,
			OBJECT_TYPE_POST,
			verified_from_start
		])?;
		stat = tx.prepare(
			r#"
			INSERT INTO post_object (object_id, file_count, in_reply_to_actor_address, in_reply_to_object_hash) VALUES (?,?,?,?)
		"#,
		)?;
		let (a, o) = match in_reply_to {
			None => (None, None),
			Some((actor, object)) => (Some(actor.to_bytes()), Some(object)),
		};
		stat.insert(params![object_id, files.len(), a, o])?;

		// Store all tags & files
		Self::_store_post_tags(tx, object_id, tags)?;
		Self::_store_post_files(tx, actor_id, object_id, files)?;
		Ok(())
	}

	fn _store_post_files(
		tx: &impl DerefConnection, _actor_id: i64, object_id: i64, files: &[IdType],
	) -> Result<()> {
		for i in 0..files.len() {
			let file = &files[i];

			tx.execute(
				r#"
				INSERT INTO post_files (object_id, hash, sequence)
				VALUES (?,?,?)
			"#,
				params![object_id, file.to_string(), i],
			)?;
		}
		Ok(())
	}

	fn _store_post_object_payload(
		tx: &impl DerefConnection, actor_id: i64, object_id: i64, payload: &PostObject,
	) -> Result<()> {
		let mut stat = tx.prepare(
			r#"
			INSERT INTO post_object (object_id, file_count, in_reply_to_actor_address, in_reply_to_object_hash)
			VALUES (?,?,?,?)
		"#,
		)?;

		match &payload.data {
			PostObjectCryptedData::Plain(plain) => {
				stat.insert(params![
					object_id,
					plain.files.len(),
					payload.in_reply_to.as_ref().map(|irt| irt.0.to_bytes()),
					payload.in_reply_to.as_ref().map(|irt| irt.1.to_string())
				])?;

				Self::_store_post_tags(tx, object_id, &plain.tags)?;
				Self::_store_post_files(tx, actor_id, object_id, &plain.files)?;
				Ok(())
			}
		}
	}

	fn _store_post_tags(tx: &impl DerefConnection, object_id: i64, tags: &[String]) -> Result<()> {
		for tag in tags {
			tx.execute(
				r#"
				INSERT INTO post_tag (object_id, tag) VALUES (?, ?)
			"#,
				params![object_id, tag],
			)?;
		}
		Ok(())
	}

	fn _store_object_payload(
		tx: &impl DerefConnection, actor_id: i64, object_id: i64, payload: &ObjectPayload,
	) -> Result<()> {
		match payload {
			ObjectPayload::Post(po) =>
				Self::_store_post_object_payload(tx, actor_id, object_id, &po),
			ObjectPayload::Share(po) => Self::_store_boost_object_payload(tx, object_id, &po),
			ObjectPayload::Profile(po) => Self::_store_profile_object_payload(tx, object_id, &po),
		}
	}

	fn _store_profile_object(
		tx: &impl DerefConnection, actor_id: i64, object_id: &IdType, object: &Object, name: &str,
		avatar_file_id: Option<&IdType>, wallpaper_file_id: Option<&IdType>,
		description_hash: Option<&IdType>,
	) -> Result<()> {
		// FIXME: Use _store_object instead of the following redundant code
		let mut stat = tx.prepare(
			r#"
			INSERT INTO object (
				actor_id, sequence, hash, signature, created, found, type, verified_from_start, previous_hash
			)
			VALUES (?,?,?,?,?,?,?,?,?)
		"#,
		)?;
		let object_id = stat.insert(params![
			actor_id,
			object.sequence,
			object_id.to_string(),
			object.signature,
			object.created,
			Utc::now().timestamp_millis(),
			object.payload.type_id(),
			true,
			IdType::default()
		])?;

		tx.execute(
			r#"
			INSERT INTO profile_object (
				object_id, name, avatar_file_hash, wallpaper_file_hash, description_file_hash
			) VALUES (?,?,?,?,?)
		"#,
			params![
				object_id,
				name,
				avatar_file_id.map(|id| id.to_string()),
				wallpaper_file_id.map(|id| id.to_string()),
				description_hash.map(|id| id.to_string())
			],
		)?;
		Ok(())
	}

	fn _store_boost_object_payload(
		tx: &impl DerefConnection, object_id: i64, payload: &ShareObject,
	) -> Result<()> {
		tx.execute(
			r#"
			INSERT INTO boost_object (object_id, actor_address, object_hash)
			VALUES (?,?,?)
		"#,
			params![object_id, &payload.actor_address, &payload.object_hash],
		)?;
		Ok(())
	}

	fn _store_profile_object_payload(
		tx: &impl DerefConnection, object_id: i64, payload: &ProfileObject,
	) -> Result<()> {
		tx.execute(r#"
			INSERT INTO profile_object (object_id, name, avatar_file_hash, wallpaper_file_hash, description_file_hash)
			VALUES (?,?,?,?,?)
		"#, params![
			object_id,
			&payload.name,
			&payload.avatar,
			&payload.wallpaper,
			&payload.description,
		])?;
		Ok(())
	}

	pub fn _create_my_identity(
		tx: &impl DerefConnection, label: &str, private_key: &ActorPrivateKeyV1,
		first_object_hash: &IdType, first_object: &Object, name: &str,
		avatar_hash: Option<&IdType>, wallpaper_hash: Option<&IdType>,
		description_hash: Option<&IdType>,
	) -> Result<()> {
		let identity_id = Self::_store_my_identity(
			tx,
			label,
			private_key,
			&first_object_hash,
			ACTOR_TYPE_BLOGCHAIN.to_string(),
		)?;

		Self::_store_profile_object(
			tx,
			identity_id,
			first_object_hash,
			&first_object,
			name,
			avatar_hash,
			wallpaper_hash,
			description_hash,
		)?;

		Ok(())
	}

	pub fn delete_object(&self, actor_address: &ActorAddress, hash: &IdType) -> Result<bool> {
		let object_id: i64 = self.old.query_row(
			r#"
			SELECT id FROM object WHERE hash = ? AND actor_id = (
				SELECT id FROM identity WHERE address = ?
			)"#,
			params![hash.to_string(), actor_address],
			|r| r.get(0),
		)?;

		// Delete all possible foreign references first
		self.old.execute(
			r#"
			DELETE FROM post_files WHERE object_id = ?
		"#,
			[object_id],
		)?;
		self.old.execute(
			r#"
			DELETE FROM post_tag WHERE object_id = ?
		"#,
			[object_id],
		)?;
		self.old.execute(
			r#"
			DELETE FROM post_object WHERE object_id = ?
		"#,
			[object_id],
		)?;
		self.old.execute(
			r#"
			DELETE FROM boost_object WHERE object_id = ?
		"#,
			[object_id],
		)?;
		self.old.execute(
			r#"
			DELETE FROM profile_object WHERE object_id = ?
		"#,
			[object_id],
		)?;

		let affected = self.old.execute(
			r#"
			DELETE FROM object WHERE id = ?
		"#,
			[object_id],
		)?;
		Ok(affected > 0)
	}

	/*pub fn fetch_latest_posts(&self,
		actor_id: &IdType,
		count: usize,
		offset: usize
	) -> Result<Vec<PostObject>> {
		let mut stat = self.old.prepare(r#"
			SELECT rowid FROM post_object AS po
			LEFT JOIN object AS o ON po.object_id = o.rowid
			WHERE actor_id = (SELECT rowid FROM identity WHERE address = ?)
			ORDER BY o.index DESC
			LIMIT ? OFFSET ?
		"#)?;
		let mut rows = stat.query(rusqlite::params![actor_id.to_string(), count, offset])?;
		let mut posts = Vec::new();
		while let Some(row) = rows.next()? {
			let rowid = row.get(0)?;
			//let hash_blob: Vec<u8> = row.get(1)?;
			posts.push(PostObject {
				//hash: Self::parse_hash(&hash_blob, format!("post {}", rowid))?,
				tags: self.fetch_post_tags(rowid)?,
				files: self.fetch_post_files(rowid)?
			})
		}
		Ok(posts)
	}*/

	/// Returns a list of hashes of blocks we're still missing but also in need
	/// of
	pub fn fetch_missing_file_blocks(&self) -> Result<Vec<IdType>> {
		let mut stat = self.prepare(
			r#"
			SELECT fb.block_hash
			FROM file_blocks AS fb
			INNER JOIN file AS f ON f.id = fb.file_id
			WHERE fb.block_hash NOT IN (
				SELECT hash FROM block
			)
		"#,
		)?;

		let mut rows = stat.query([])?;
		let mut results = Vec::new();
		while let Some(row) = rows.next()? {
			let hash: IdType = row.get(0)?;
			results.push(hash);
		}
		Ok(results)
	}

	pub fn fetch_file_blocks(&self, file_hash: &IdType, size: usize) -> Result<Vec<IdType>> {
		let mut stat = self.prepare(
			r#"
			SELECT block_hash
			FROM file_blocks AS fb
			INNER JOIN file AS f ON fb.file_id = f.id
			WHERE f.hash = ?
			ORDER BY fb.sequence ASC
		"#,
		)?;

		let mut result = Vec::with_capacity(size);
		let mut rows = stat.query([file_hash])?;
		if let Some(row) = rows.next()? {
			let block_hash: IdType = row.get(0)?;
			result.push(block_hash);
		}
		Ok(result)
	}

	pub fn fetch_block(&self, id: &IdType) -> Result<Option<Vec<u8>>> {
		let mut stat = self.prepare(
			r#"
			SELECT b.id, b.size, b.data
			FROM block AS b
			WHERE b.hash = ?
		"#,
		)?;
		let mut rows = stat.query([id.to_string()])?;
		if let Some(row) = rows.next()? {
			let block_id = row.get(0)?;
			let size: usize = row.get(1)?;
			let data: Vec<u8> = row.get(2)?;
			if data.len() != size {
				Err(Error::BlockDataCorrupt(block_id))?;
			}
			Ok(Some(data))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_file_data(&self, id: &IdType) -> Result<Option<FileData>> {
		match Self::_fetch_file(self, id)? {
			None => Ok(None),
			Some((mime_type, data)) => Ok(Some(FileData { mime_type, data })),
		}
	}

	pub fn fetch_file(&self, id: &IdType) -> Result<Option<File>> {
		let mut stat = self.prepare(
			r#"
			SELECT id, plain_hash, mime_type, block_count FROM file WHERE hash = ?
		"#,
		)?;
		let mut rows = stat.query([id.to_string()])?;
		if let Some(row) = rows.next()? {
			let file_id = row.get(0)?;
			let plain_hash: IdType = row.get(1)?;
			let mime_type: String = row.get(2)?;
			let block_count: u32 = row.get(3)?;

			let mut stat = self.prepare(
				r#"
				SELECT sequence, block_hash
				FROM file_blocks
				WHERE file_id = ?
				ORDER BY sequence ASC
			"#,
			)?;
			let mut rows = stat.query([file_id])?;
			let mut i = 0;
			let mut blocks = Vec::with_capacity(block_count as _);
			while let Some(row) = rows.next()? {
				let sequence: u64 = row.get(0)?;
				if sequence != i {
					Err(Error::FileMissingBlock(file_id, i))?;
				}
				let block_hash: IdType = row.get(1)?;

				blocks.push(block_hash);
				if blocks.len() == blocks.capacity() {
					break;
				}
				i += 1;
			}

			Ok(Some(File {
				plain_hash,
				mime_type,
				blocks,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_follow_list(&self) -> Result<Vec<(ActorAddress, ActorInfo)>> {
		let mut stat = self.prepare(
			r#"
			SELECT i.address, i.public_key, i.first_object, i.type
			FROM following AS f
			LEFT JOIN identity AS i ON f.identity_id = i.id
		"#,
		)?;
		let mut rows = stat.query([])?;

		let mut list = Vec::new();
		while let Some(row) = rows.next()? {
			let address: ActorAddress = row.get(0)?;
			let public_key: ActorPublicKeyV1 = row.get(1)?;
			let first_object: IdType = row.get(2)?;
			let actor_type: String = row.get(3)?;
			let actor_info = ActorInfo::V1(ActorInfoV1 {
				flags: 0,
				public_key,
				first_object,
				actor_type,
			});
			list.push((address, actor_info));
		}
		Ok(list)
	}

	pub fn fetch_object_info(
		&mut self, actor_address: &ActorAddress, hash: &IdType,
	) -> Result<Option<ObjectInfo>> {
		let tx = self.old.transaction()?;
		let mut stat = tx.prepare(
			r#"
			SELECT o.actor_id, o.hash, o.sequence, o.created, o.found, o.type, i.address
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ? AND o.hash = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_address, hash])?;
		Self::_parse_object_info(&tx, &mut rows)
	}

	pub fn fetch_home_feed(&mut self, count: u64, offset: u64) -> Result<Vec<ObjectInfo>> {
		let tx = self.old.transaction()?;

		let mut stat = tx.prepare(
			r#"
			SELECT o.actor_id, o.hash, o.sequence, o.created, o.found, o.type, i.address
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE o.actor_id IN (
				SELECT identity_id FROM my_identity
			) OR o.actor_id IN (
				SELECT identity_id FROM following
			)
			ORDER BY o.found DESC LIMIT ? OFFSET ?
		"#,
		)?;
		let mut rows = stat.query([count, offset])?;

		let mut objects = Vec::with_capacity(count as _);
		while let Some(object) = Self::_parse_object_info(&tx, &mut rows)? {
			objects.push(object);
		}
		Ok(objects)
	}

	pub fn fetch_object(&self, object_hash: &IdType) -> Result<Option<(Object, bool)>> {
		if let Some((_, object, verified)) = Self::_fetch_object(self, object_hash)? {
			Ok(Some((object, verified)))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_object_by_sequence(
		&self, actor_id: &ActorAddress, sequence: u64,
	) -> Result<Option<(IdType, Object, bool)>> {
		Self::_fetch_object_by_sequence_old(self, actor_id, sequence)
	}

	pub fn fetch_previous_object(
		&mut self, actor_id: &ActorAddress, hash: &IdType,
	) -> Result<Option<(IdType, Object, bool)>> {
		let tx = self.old.transaction()?;

		let mut stat = tx.prepare(
			r#"
			SELECT o.sequence
			FROM object AS o
			INNER JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ? AND i.actor_version = ? AND o.hash = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, hash.to_string()])?;
		if let Some(row) = rows.next()? {
			let sequence: u64 = row.get(0)?;
			if sequence > 0 {
				Self::_fetch_object_by_sequence_old(&tx, actor_id, sequence - 1)
			} else {
				Ok(None)
			}
		} else {
			Ok(None)
		}
	}

	pub fn fetch_next_object(
		&mut self, actor_address: &ActorAddress, hash: &IdType,
	) -> Result<Option<(IdType, Object, bool)>> {
		let tx = self.old.transaction()?;
		let mut stat = tx.prepare(
			r#"
			SELECT o.sequence
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ? AND o.hash = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_address, hash])?;
		if let Some(row) = rows.next()? {
			let sequence: u64 = row.get(0)?;
			if sequence < u64::MAX {
				if let Some((hash, object, verified_from_start)) =
					Self::_fetch_object_by_sequence_old(&tx, actor_address, sequence + 1)?
				{
					Ok(Some((hash, object, verified_from_start)))
				} else {
					Ok(None)
				}
			} else {
				Ok(None)
			}
		} else {
			Ok(None)
		}
	}

	pub fn fetch_head(&self, actor_id: &ActorAddress) -> Result<Option<(IdType, Object, bool)>> {
		Self::_fetch_head(self, actor_id)
	}

	pub fn fetch_last_verified_object(
		&self, actor_id: &ActorAddress,
	) -> Result<Option<(IdType, Object)>> {
		if let Some((hash, object, _)) = Self::_fetch_last_verified_object(self, actor_id)? {
			Ok(Some((hash, object)))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_identity(&self, address: &ActorAddress) -> Result<Option<ActorInfo>> {
		let mut stat = self.prepare(
			r#"
			SELECT public_key, first_object, type FROM identity WHERE address = ?
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
				actor_type,
			})))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_identity_by_id(&self, id: &IdType) -> Result<Option<ActorInfo>> {
		let mut stat = self.prepare(
			r#"
			SELECT public_key, first_object, type FROM identity WHERE address = ?
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
				actor_type,
			})))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_my_identity(
		&self, address: &ActorAddress,
	) -> Result<Option<(String, ActorPrivateKeyV1)>> {
		let mut stat = self.old.prepare(
			r#"
			SELECT label, private_key FROM my_identity AS mi LEFT JOIN identity AS i
			WHERE i.address = ?
		"#,
		)?;
		let mut rows = stat.query(params![address])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => {
				let label = row.get(0)?;
				let private_key: ActorPrivateKeyV1 = row.get(1)?;
				Ok(Some((label, private_key)))
			}
		}
	}

	pub fn fetch_my_identity_by_label(
		&self, label: &str,
	) -> Result<Option<(ActorAddress, ActorPrivateKeyV1)>> {
		let mut stat = self.old.prepare(
			r#"
			SELECT i.address, mi.private_key
			FROM my_identity AS mi LEFT JOIN identity AS i ON mi.identity_id = i.id
			WHERE label = ?
		"#,
		)?;
		let mut rows = stat.query([label])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => {
				let address: ActorAddress = row.get(0)?;
				let private_key: ActorPrivateKeyV1 = row.get(1)?;
				Ok(Some((address, private_key)))
			}
		}
	}

	pub fn fetch_my_identities(
		&self,
	) -> Result<Vec<(String, ActorAddress, IdType, String, ActorPrivateKeyV1)>> {
		let mut stat = self.old.prepare(
			r#"
			SELECT label, i.address, i.first_object, i.type, mi.private_key
			FROM my_identity AS mi
			LEFT JOIN identity AS i ON mi.identity_id = i.id
		"#,
		)?;
		let mut rows = stat.query([])?;

		let mut ids = Vec::new();
		while let Some(row) = rows.next()? {
			let address: ActorAddress = row.get(1)?;
			let first_object: IdType = row.get(2)?;
			let actor_type: String = row.get(3)?;
			let private_key: ActorPrivateKeyV1 = row.get(4)?;
			ids.push((row.get(0)?, address, first_object, actor_type, private_key));
		}
		Ok(ids)
	}

	pub fn fetch_node_identity(&mut self) -> Result<(IdType, NodePrivateKey)> {
		let tx = self.old.transaction()?;

		let result = {
			let mut stat = tx.prepare(
				r#"
				SELECT address, private_key FROM node_identity LIMIT 1
			"#,
			)?;
			let mut rows = stat.query([])?;

			if let Some(row) = rows.next()? {
				let address: IdType = row.get(0)?;
				let private_key: NodePrivateKey = row.get(1)?;
				(address, private_key)
			} else {
				let private_key = NodePrivateKey::generate();
				let address = IdType::hash(&private_key.public().to_bytes());
				tx.execute(
					r#"
					INSERT INTO node_identity (address, private_key) VALUES (?,?)
				"#,
					params![address, private_key],
				)?;
				(address, private_key)
			}
		};

		tx.commit()?;
		Ok(result)
	}

	pub fn fetch_profile_object(
		&self, actor_id: &ActorAddress,
	) -> Result<Option<(IdType, Object)>> {
		let mut stat = self.prepare(
			r#"
			SELECT o.id, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM profile_object AS po
			INNER JOIN object AS o ON po.object_id = o.id
			INNER JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ?
			ORDER BY o.id DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query(params![actor_id])?;
		if let Some((hash, object, _)) = Self::_parse_object(self, &mut rows)? {
			Ok(Some((hash, object)))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_profile_info(&self, actor_id: &ActorAddress) -> Result<Option<ProfileObjectInfo>> {
		let mut stat = self.prepare(
			r#"
			SELECT i.address, po.name, po.avatar_file_hash, po.wallpaper_file_hash, df.id,
			       df.plain_hash, df.block_count
			FROM profile_object AS po
			INNER JOIN object AS o ON po.object_id = o.id
			INNER JOIN identity AS i ON o.actor_id = i.id
			LEFT JOIN file AS df ON po.description_file_hash = df.hash
			WHERE i.address = ?
			ORDER BY o.sequence DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query(params![actor_id])?;
		if let Some(row) = rows.next()? {
			let address: ActorAddress = row.get(0)?;
			let actor_name: String = row.get(1)?;
			let avatar_id: Option<IdType> = row.get(2)?;
			let wallpaper_id: Option<IdType> = row.get(3)?;
			let description_file_id: Option<i64> = row.get(4)?;
			let description_plain_hash: Option<IdType> = row.get(5)?;
			let description_block_count: Option<u64> = row.get(6)?;

			let description = if let Some(file_id) = description_file_id {
				Some(Self::_fetch_file_data(
					self,
					file_id,
					&description_plain_hash.unwrap(),
					description_block_count.unwrap(),
				)?)
			} else {
				None
			};

			Ok(Some(ProfileObjectInfo {
				actor: TargetedActorInfo {
					address: address.to_string(),
					name: actor_name,
					avatar_id,
					wallpaper_id,
				},
				description: description.map(|b| String::from_utf8_lossy(&b).to_string()),
			}))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_remembered_node(&mut self, address: &SocketAddr) -> Result<(IdType, i32)> {
		let result = self.query_row(
			r#"
			SELECT node_id, success_score FROM remembered_nodes WHERE address = ?
		"#,
			params![address.to_string()],
			|row| {
				let node_id: IdType = row.get(0)?;
				let score: i32 = row.get(1)?;
				Ok((node_id, score))
			},
		)?;
		Ok(result)
	}

	pub fn follow(&mut self, actor_id: &ActorAddress, actor_info: &ActorInfo) -> Result<()> {
		let tx = self.old.transaction()?;

		let identity_id = {
			let mut stat = tx.prepare(
				r#"
				SELECT id FROM identity WHERE address = ?
			"#,
			)?;
			let mut rows = stat.query(params![actor_id])?;
			let identity_id = if let Some(row) = rows.next()? {
				row.get(0)?
			} else {
				drop(rows);
				let mut stat = tx.prepare(
					r#"
					INSERT INTO identity (address, public_key, first_object, type) VALUES (?,?,?,?,?)
				"#,
				)?;
				stat.insert(params![
					actor_id,
					actor_info.public_key,
					actor_info.first_object,
					ACTOR_TYPE_BLOGCHAIN
				])?
			};
			identity_id
		};

		tx.execute(
			r#"
			INSERT INTO following (identity_id) VALUES (?)
		"#,
			params![identity_id],
		)?;

		tx.commit()?;
		Ok(())
	}

	pub fn has_block(&self, hash: &IdType) -> rusqlite::Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT b.id
			FROM block AS b
			WHERE b.hash = ?
		"#,
		)?;
		let mut rows = stat.query([hash.to_string()])?;
		Ok(rows.next()?.is_some())
	}

	pub fn has_file(&self, hash: &IdType) -> rusqlite::Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT f.id
			FROM file AS f
			WHERE f.hash = ?
		"#,
		)?;
		let mut rows = stat.query([hash])?;
		Ok(rows.next()?.is_some())
	}

	pub fn has_object(&self, actor_address: &ActorAddress, id: &IdType) -> rusqlite::Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT o.id
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ? AND o.hash = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_address, id.to_string()])?;
		Ok(rows.next()?.is_some())
	}

	pub fn has_object_sequence(
		&self, actor_id: &ActorAddress, sequence: u64,
	) -> rusqlite::Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT o.id
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.id
			WHERE i.address = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, sequence])?;
		Ok(rows.next()?.is_some())
	}

	pub fn is_identity_available(&self, address: &ActorAddress) -> rusqlite::Result<bool> {
		let mut stat = self.old.prepare(
			r#"
			SELECT address FROM identity AS i
			WHERE address = ? AND id IN (
				SELECT identity_id FROM my_identity
			) OR id IN (
				SELECT identity_id FROM feed_followed
			)
		"#,
		)?;
		let mut rows = stat.query(params![address])?;
		Ok(rows.next()?.is_some())
	}

	pub fn is_following(&self, actor_id: &ActorAddress) -> Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT 1
			FROM following AS f
			LEFT JOIN identity AS i ON f.identity_id = i.id
			WHERE i.address = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id])?;
		Ok(rows.next()?.is_some())
	}

	/// Returns the lastest object sequence for an actor if available.
	pub fn max_object_sequence(&self, actor_id: i64) -> Result<Option<u64>> {
		let mut stat = self.old.prepare(
			r#"
			SELECT MAX(sequence) FROM object WHERE actor_id = ?
		"#,
		)?;
		let mut rows = stat.query([actor_id])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(row.get(0)?),
		}
	}

	/// Returns the sequence that the next object would use.
	pub fn next_object_sequence(&self, actor_id: i64) -> Result<u64> {
		match self.max_object_sequence(actor_id)? {
			None => Ok(0),
			Some(s) => Ok(s + 1),
		}
	}

	pub fn old(&self) -> &rusqlite::Connection { &self.old.0 }

	pub fn old_mut(&mut self) -> &mut rusqlite::Connection { &mut self.old.0 }

	pub async fn open(path: &Path) -> self::Result<Self> {
		let old_connection = rusqlite::Connection::open(&path)?;
		Ok(Self {
			old: UnsafeSendSync::new(old_connection),
			backend: DatabaseBackend::Sqlite,
		})
	}

	pub fn open_old(path: &Path) -> rusqlite::Result<Self> {
		let c = rusqlite::Connection::open(&path)?;
		// For some reason foreign key checks are not working properly on windows, so
		// disable it for now.
		#[cfg(target_family = "windows")]
		c.pragma_update(None, "foreign_keys", false)?;
		Ok(Self {
			old: UnsafeSendSync::new(c),
			backend: DatabaseBackend::Sqlite,
		})
	}

	pub fn store_block(&mut self, hash: &IdType, data: &[u8]) -> Result<()> {
		Self::_store_block(self, hash, data)?;
		Ok(())
	}

	pub fn store_file(&mut self, id: &IdType, file: &File) -> Result<()> {
		self.store_file2(id, &file.plain_hash, &file.mime_type, &file.blocks)
	}

	pub fn store_file_data(&mut self, file_data: &FileData) -> Result<IdType> {
		let (_, file_hash, _) =
			Self::_store_file_data(self, &file_data.mime_type, &file_data.data)?;
		Ok(file_hash)
	}

	pub fn store_file_data2(&mut self, mime_type: &str, data: &[u8]) -> Result<IdType> {
		let (_, file_hash, _) = Self::_store_file_data(self, mime_type, data)?;
		Ok(file_hash)
	}

	pub fn store_file2(
		&mut self, id: &IdType, plain_hash: &IdType, mime_type: &str, blocks: &[IdType],
	) -> Result<()> {
		Self::_store_file(self, id, plain_hash, mime_type, blocks)?;
		Ok(())
	}

	pub fn store_identity(
		&mut self, address: &ActorAddress, public_key: &ActorPublicKeyV1, first_object: &IdType,
	) -> Result<()> {
		let mut stat = self.prepare(
			r#"
			INSERT INTO identity (address, public_key, first_object, type) VALUES(?,?,?,?)
		"#,
		)?;
		stat.insert(params![
			address,
			public_key,
			first_object,
			ACTOR_TYPE_BLOGCHAIN
		])?;
		Ok(())
	}

	pub fn store_my_identity(
		&mut self, label: &str, address: &IdType, private_key: &NodePrivateKey,
		first_object: &IdType,
	) -> rusqlite::Result<()> {
		let tx = self.old.transaction()?;

		let mut stat = tx.prepare(
			r#"
			INSERT INTO identity (address, public_key, first_object) VALUES(?,?,?)
		"#,
		)?;
		let new_id = stat.insert(rusqlite::params![
			address.to_string(),
			private_key.public().as_bytes(),
			first_object.to_string()
		])?;
		stat = tx
			.prepare(
				r#"
			INSERT INTO my_identity (label, identity_id, private_key) VALUES (?,?,?)
		"#,
			)
			.unwrap();
		stat.insert(rusqlite::params![label, new_id, private_key.as_bytes()])?;

		drop(stat);
		tx.commit()?;
		Ok(())
	}

	pub fn store_node_identity(&self, node_id: &IdType, node_key: &NodePrivateKey) -> Result<()> {
		self.execute(
			r#"
			UPDATE node_identity SET address = ?, private_key = ?
		"#,
			params![node_id, node_key],
		)?;
		Ok(())
	}

	pub fn store_object(
		&mut self, actor_id: &ActorAddress, id: &IdType, object: &Object, verified_from_start: bool,
	) -> self::Result<bool> {
		let tx = self.old.transaction()?;
		let _object_id = match Self::_store_object(&tx, actor_id, id, object, verified_from_start) {
			Ok(id) => id,
			// Just return false if the object already existed
			Err(e) => match &*e {
				Error::SqliteError(e2) => match e2 {
					rusqlite::Error::SqliteFailure(e3, _) => {
						if e3.code == libsqlite3_sys::ErrorCode::ConstraintViolation {
							return Ok(false);
						}
						return Err(e);
					}
					_ => return Err(e),
				},
				_ => return Err(e),
			},
		};
		tx.commit()?;
		Ok(true)
	}

	pub fn fetch_bootstrap_node_id(&mut self, address: &SocketAddr) -> Result<Option<IdType>> {
		let mut stat = self.old.prepare(
			r#"
			SELECT node_id FROM bootstrap_id WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query([address.to_string()])?;
		if let Some(row) = rows.next()? {
			let node_id = row.get(0)?;
			Ok(Some(node_id))
		} else {
			Ok(None)
		}
	}

	pub fn remember_bootstrap_node_id(
		&mut self, address: &SocketAddr, node_id: &IdType,
	) -> Result<bool> {
		let tx = self.old.transaction()?;
		let updated = tx.execute(
			"UPDATE bootstrap_id SET node_id = ? WHERE address = ?",
			params![node_id, address.to_string()],
		)?;
		if updated == 0 {
			tx.execute(
				"INSERT INTO bootstrap_id (address, node_id) VALUES (?,?)",
				params![address.to_string(), node_id],
			)?;
		}
		tx.commit()?;
		Ok(updated == 0)
	}

	pub fn remember_node(&mut self, address: &SocketAddr, node_id: &IdType) -> Result<()> {
		let tx = self.old.transaction()?;

		let mut stat = tx.prepare(
			r#"
			SELECT success_score FROM remembered_nodes WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query([address.to_string()])?;
		if let Some(row) = rows.next()? {
			let score: i32 = row.get(0)?;

			let affected = tx.execute(
				r#"UPDATE remembered_nodes SET success_score = ? WHERE address = ?"#,
				params![score + 1, address.to_string()],
			)?;
			debug_assert!(affected > 0);
		} else {
			tx.execute(
				r#"INSERT INTO remembered_nodes (address, node_id, success_score) VALUES (?, ?, ?)"#,
				params![address.to_string(), node_id, 1],
			)?;
		}
		Ok(())
	}

	pub fn transaction_old(&mut self) -> Result<rusqlite::Transaction<'_>> {
		Ok(self.old.transaction()?)
	}

	pub fn unfollow(&mut self, actor_id: &ActorAddress) -> Result<bool> {
		let affected = self.old.execute(
			r#"
			DELETE FROM following WHERE identity_id = (
				SELECT id FROM identity WHERE address = ?
			)
		"#,
			params![actor_id],
		)?;
		Ok(affected > 0)
	}

	pub fn update_object_verified(
		&mut self, actor_address: &ActorAddress, object_id: &IdType,
	) -> Result<()> {
		self.old.execute(
			r#"
			UPDATE object SET verified_from_start = 1
			WHERE hash = ? AND identity_id = (
				SELECT id FROM identity WHERE address = ?
			)
		"#,
			params![object_id.to_string(), actor_address],
		)?;
		Ok(())
	}
}

impl PersistenceHandle for Database {
	type Inner = sea_orm::DatabaseConnection;

	fn inner(&self) -> &Self::Inner { &self.orm }
}

impl PersistenceHandle for Transaction {
	type Inner = sea_orm::DatabaseTransaction;

	fn inner(&self) -> &Self::Inner { &self.0 }
}

impl Deref for Connection {
	type Target = rusqlite::Connection;

	fn deref(&self) -> &Self::Target { self.old() }
}

impl DerefMut for Connection {
	fn deref_mut(&mut self) -> &mut Self::Target { self.old_mut() }
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::SqliteError(e) => write!(f, "{}", e),
			Self::OrmError(e) => write!(f, "{}", e),
			Self::ActorAddress(e) => write!(f, "invalid actor address format: {}", e),
			Self::InvalidHash(e) => {
				write!(f, "hash not a valid base58-encoded 32-byte address {}", e)
			}
			Self::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
			Self::InvalidObjectType(code) => {
				write!(f, "invalid object type found in database: {}", code)
			}
			//Self::InvalidPrivateKey(e) => write!(f, "invalid private_key: {}", e),
			Self::BlockDataCorrupt(block_id) => write!(f, "data of block {} is corrupt", block_id),
			Self::PostMissingFiles(object_id) => write!(f, "object {} has no files", object_id),
			Self::FileMissingBlock(file_id, sequence) => {
				write!(f, "file {} missing block sequence {}", file_id, sequence)
			}
			Self::InvalidPublicKey(oe) => match oe {
				Some(e) => write!(f, "invalid public key: {}", e),
				None => write!(f, "invalid public key size"),
			},
			Self::MissingIdentity(hash) => write!(f, "identity {:?} is missing", &hash),
		}
	}
}

impl From<FromBytesAddressError> for Error {
	fn from(other: FromBytesAddressError) -> Self { Self::ActorAddress(other) }
}

impl From<FromBytesAddressError> for Traced<Error> {
	fn from(other: FromBytesAddressError) -> Self { Error::ActorAddress(other).trace() }
}

impl From<rusqlite::Error> for Error {
	fn from(other: rusqlite::Error) -> Self { Self::SqliteError(other) }
}

impl From<rusqlite::Error> for Traced<Error> {
	fn from(other: rusqlite::Error) -> Self { Error::SqliteError(other).trace() }
}

impl From<sea_orm::DbErr> for Traced<Error> {
	fn from(other: sea_orm::DbErr) -> Self { Error::OrmError(other).trace() }
}

impl From<NodeSignatureError> for Error {
	fn from(other: NodeSignatureError) -> Self { Self::InvalidSignature(other) }
}

impl From<IdFromBase58Error> for Error {
	fn from(other: IdFromBase58Error) -> Self { Self::InvalidHash(other) }
}

impl From<NodePublicKeyError> for Error {
	fn from(other: NodePublicKeyError) -> Self { Self::InvalidPublicKey(Some(other)) }
}

impl IdFromBase58Error {
	fn to_db(self) -> Error { Error::InvalidHash(self) }
}

impl Transaction {
	pub async fn commit(self) -> Result<()> {
		self.0.commit().await?;
		Ok(())
	}
}


pub fn decrypt_block(index: u64, key: &IdType, data: &mut [u8]) { encrypt_block(index, key, data) }

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


#[cfg(test)]
mod tests {
	use rand::RngCore;

	use super::*;
	use crate::test;
	#[tokio::test]
	async fn test_file_data() {
		let db = test::load_database("db").await;

		let mut rng = test::initialize_rng();
		let mut c = db.connect_old().expect("unable to connect to database");

		let mut file_data1 = FileData {
			mime_type: "image/png".to_string(),
			data: vec![0u8; 1000],
		};
		rng.fill_bytes(&mut file_data1.data);

		let file_data2 = FileData {
			mime_type: "text/markdown".to_string(),
			data: "This is some text.".as_bytes().to_vec(),
		};
		let hash1 = c.store_file_data(&file_data1).unwrap();
		let hash2 = c.store_file_data(&file_data2).unwrap();

		let fetched_file1 = c.fetch_file_data(&hash1).unwrap().unwrap();
		let fetched_file2 = c.fetch_file_data(&hash2).unwrap().unwrap();
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
	}
}

impl ObjectPayloadInfo {
	// Returns true if the payload contains enough information to at least show the
	// main content.
	pub fn has_main_content(&self) -> bool {
		match self {
			Self::Post(post) => post.message.is_some() && post.mime_type.is_some(),
			Self::Share(share) =>
				if let Some(op) = &share.original_post {
					op.message.is_some() && op.actor_name.is_some()
				} else {
					false
				},
			Self::Profile(profile) => profile.description.is_some(),
		}
	}
}

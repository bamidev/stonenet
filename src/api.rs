// FIXME: Remove when going stable:
#![allow(dead_code)]

use std::{
	sync::Arc,
	time::{SystemTime, UNIX_EPOCH},
};

use chrono::*;
use log::*;
use rand::rngs::OsRng;
use sea_orm::{
	ActiveValue::NotSet, ColumnTrait, ConnectionTrait, DatabaseBackend, DbErr, EntityTrait,
	QueryFilter, QuerySelect, QueryTrait, Set, TransactionTrait,
};
use tokio::{spawn, sync::mpsc};
use tokio_stream::wrappers::ReceiverStream;

use super::{
	common::*,
	core::*,
	db::{self},
	identity::*,
	net::{actor::ActorNode, binserde, message::*, overlay::OverlayNode},
};
use crate::{
	db::{Database, ObjectInfo, ProfileObjectInfo},
	entity::{boost_object, identity, object},
};

/*#[derive(Debug)]
pub enum Error {
	DatabaseError(db::Error),
	NetworkError(io::Error)
}*/

#[derive(Clone)]
pub struct Api {
	pub node: Arc<OverlayNode>,
	pub old_db: Database,
	pub orm: sea_orm::DatabaseConnection,
}

//pub type Result<T> = std::result::Result<T, self::Error>;

impl Api {
	pub async fn close(self) { self.node.close().await; }

	pub fn create_my_identity(
		&self, label: &str, name: &str, avatar: Option<&FileData>, wallpaper: Option<&FileData>,
		description: Option<&FileData>,
	) -> db::Result<(ActorAddress, ActorInfo)> {
		self.old_db.perform(|c| {
			// Prepare profile object
			let avatar_hash = if let Some(f) = avatar {
				Some(db::Connection::_store_file_data(&c, &f.mime_type, &f.data)?.1)
			} else {
				None
			};
			let wallpaper_hash = if let Some(f) = wallpaper {
				Some(db::Connection::_store_file_data(&c, &f.mime_type, &f.data)?.1)
			} else {
				None
			};
			let description_hash = if let Some(f) = description {
				Some(db::Connection::_store_file_data(&c, &f.mime_type, &f.data)?.1)
			} else {
				None
			};
			let profile = ProfileObject {
				name: name.to_string(),
				avatar: avatar_hash.clone(),
				wallpaper: wallpaper_hash.clone(),
				description: description_hash.clone(),
			};

			// Sign the profile object and construct an object out of it
			let payload = ObjectPayload::Profile(profile);
			let sign_data = ObjectSignData {
				sequence: 0,
				previous_hash: IdType::default(),
				created: SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap()
					.as_millis() as u64,
				payload: &payload,
			};
			let private_key = ActorPrivateKeyV1::generate_with_rng(&mut OsRng);
			let signature = private_key.sign(&binserde::serialize(&sign_data).unwrap());
			let object_hash = signature.hash();
			let object = Object {
				signature,
				previous_hash: IdType::default(),
				sequence: 0,
				created: sign_data.created,
				payload,
			};

			// Generate an actor ID with our new object hash.
			let actor_info = ActorInfo::V1(ActorInfoV1 {
				flags: 0,
				public_key: private_key.public(),
				first_object: object_hash.clone(),
				actor_type: ACTOR_TYPE_BLOGCHAIN.to_string(),
			});
			let actor_address = actor_info.generate_address();

			// Create the identity on disk
			db::Connection::_create_my_identity(
				&c,
				label,
				&private_key,
				&object_hash,
				&object,
				name,
				avatar_hash.as_ref(),
				wallpaper_hash.as_ref(),
				description_hash.as_ref(),
			)?;

			Ok((actor_address, actor_info))
		})
	}

	pub async fn find_block(
		&self, actor_node: &ActorNode, id: &IdType,
	) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.old_db.connect()?;
			c.fetch_block(id)
		})?;

		Ok(match result {
			Some(b) => Some(b),
			None => actor_node.find_block(id).await.map(|r| r.data),
		})
	}

	pub async fn find_file(&self, actor_node: &ActorNode, id: &IdType) -> db::Result<Option<File>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.old_db.connect()?;
			c.fetch_file(id)
		})?;

		Ok(match result {
			Some(r) => Some(r),
			None => actor_node.find_file(id).await.map(|r| r.file),
		})
	}

	pub async fn find_file_data(
		&self, actor_node: &ActorNode, id: &IdType,
	) -> db::Result<Option<FileData>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.old_db.connect()?;
			c.fetch_file_data(id)
		})?;

		let file_result = match result {
			Some(b) => return Ok(Some(b)),
			None => match actor_node.find_file(id).await {
				None => return Ok(None),
				Some(f) => f,
			},
		};

		// Fill a buffer with all the data
		let file = file_result.file;
		let mut buffer = Vec::with_capacity(file.blocks.len() * db::BLOCK_SIZE);
		for block_id in &file.blocks {
			let block_result = self.find_block(&actor_node, block_id).await?;
			match block_result {
				None => return Ok(None),
				Some(block) => buffer.extend(block),
			}
		}
		Ok(Some(FileData {
			mime_type: file.mime_type,
			data: buffer,
		}))
	}

	pub async fn find_object(
		&self, actor_node: &ActorNode, id: &IdType,
	) -> db::Result<Option<FindObjectResult>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.old_db.connect()?;
			c.fetch_object(id)
		})?;

		Ok(match result {
			Some((object, _)) => Some(FindObjectResult { object }),
			None => actor_node.find_object(id).await,
		})
	}

	pub fn fetch_home_feed(&self, count: u64, offset: u64) -> db::Result<Vec<ObjectInfo>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let mut c = this.old_db.connect()?;
			c.fetch_home_feed(count, offset)
		})
	}

	pub fn fetch_my_identity(
		&self, address: &ActorAddress,
	) -> db::Result<Option<(String, ActorPrivateKeyV1)>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let c = this.old_db.connect()?;
			c.fetch_my_identity(address)
		})
	}

	pub fn fetch_my_identity_by_label(
		&self, label: &str,
	) -> db::Result<Option<(ActorAddress, ActorPrivateKeyV1)>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let c = this.old_db.connect()?;
			c.fetch_my_identity_by_label(label)
		})
	}

	pub fn fetch_my_identities(
		&self,
	) -> db::Result<Vec<(String, ActorAddress, IdType, String, ActorPrivateKeyV1)>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let c = this.old_db.connect()?;
			c.fetch_my_identities()
		})
	}

	/*pub async fn fetch_latest_objects_with_preview_data(&self,
		actor_id: &IdType,
		count: usize,
		offset: usize
	) -> db::Result<Vec<Option<(Object)>>> {
		Ok(match self.node.lurk_actor_network(actor_id).await {
			Some(actor_node) => {
				match actor_node.fetch_head().await {
					Some(latest_object_index) => {
						let object_result = self.fetch_objects(
							&actor_node,
							latest_object_index,
							5
						).await?;

						match object_result {
							None => {},
							Some(object) => {
								if object.files.len() > 0 &&
								   object.files[0].mime_type == "text/plain"
								{
									let file_hash = &object.files[0].hash;
									self.fetch_file(file_hash).await?;
								}
							}
						}
					},
					None => Vec::new()
				}
			},
			None => Vec::new()
		})
	}*/

	pub async fn fetch_object_info(
		&self, actor_address: &ActorAddress, hash: &IdType,
	) -> db::Result<Option<ObjectInfo>> {
		tokio::task::block_in_place(|| {
			let mut c = self.old_db.connect()?;
			c.fetch_object_info(actor_address, hash)
		})
	}

	/*pub async fn fetch_objects(
		&self, actor_node: &Arc<ActorNode>, last_post_sequence: u64, count: u64,
	) -> Vec<Option<Object>> {
		debug_assert!(last_post_sequence >= count, "last_post_sequence can not be less than count");
		let objects = Arc::new(Mutex::new(Vec::with_capacity(count as _)));

		let mut futs = Vec::with_capacity(count as _);
		for i in 0..count {
			let post_sequence = last_post_sequence - i;
			let node = actor_node.clone();
			let objects2 = objects.clone();
			futs.append(async move {
				let result = tokio::task::block_in_place(|| {
					let mut c = self.db.connect()?;
					c.fetch_object_by_sequence(node.actor_id(), post_sequence)
				})?;
				let final_result = match result.0 {
					Some(o) => Some(o),
					None => {
						node.find_object(id).await
					}
				};
				objects2.lock().await.push(result);
			});
		}
		join_all!(futs).await;

		Ok(objects.unwrap())
	}*/

	pub async fn fetch_profile_info(
		&self, actor_id: &ActorAddress,
	) -> db::Result<Option<ProfileObjectInfo>> {
		let profile = tokio::task::block_in_place(|| {
			let c = self.old_db.connect()?;
			c.fetch_profile_info(actor_id)
		})?;
		if profile.is_some() {
			return Ok(profile);
		}

		// Try to get the profile from the actor network
		if let Some(_) = self.node.find_actor_profile_info(actor_id).await {
			let profile = tokio::task::block_in_place(|| {
				let c = self.old_db.connect()?;
				c.fetch_profile_info(actor_id)
			})?;
			return Ok(profile);
		}
		Ok(None)
	}

	pub async fn follow(&self, address: &ActorAddress, join_network: bool) -> db::Result<bool> {
		let result = tokio::task::block_in_place(|| {
			let c = self.old_db.connect()?;
			c.fetch_identity(address)
		})?;
		let actor_info = match result {
			Some(pk) => pk,
			None => match self.node.find_actor(&address, 100, false).await {
				Some(r) => r.0.clone(),
				None => return Ok(false),
			},
		};

		let _private_key = tokio::task::block_in_place(|| {
			let mut c = self.old_db.connect()?;
			c.follow(address, &actor_info)
		})?;

		// Join network
		if join_network {
			let node = self.node.clone();
			let actor_id2 = address.clone();
			tokio::spawn(async move {
				node.join_actor_network(&actor_id2, &actor_info).await;
			});
		}

		Ok(true)
	}

	pub async fn unfollow(&self, actor_id: &ActorAddress) -> db::Result<bool> {
		let success = tokio::task::block_in_place(|| {
			let mut c = self.old_db.connect()?;
			c.unfollow(actor_id)
		})?;

		if success {
			self.node.drop_actor_network(&actor_id.as_id()).await;
		}
		Ok(success)
	}

	pub fn is_following(&self, actor_id: &ActorAddress) -> db::Result<bool> {
		tokio::task::block_in_place(|| {
			let c = self.old_db.connect()?;
			c.is_following(actor_id)
		})
	}

	// Like `load_file`, but return an async stream that catches all the blocks that
	// are being loaded in another thread.
	pub async fn stream_file(
		&self, actor_address: ActorAddress, file_hash: IdType,
	) -> db::Result<Option<(String, ReceiverStream<db::Result<Vec<u8>>>)>> {
		let db = self.old_db.clone();
		let r: Option<File> = db.perform(|c| c.fetch_file(&file_hash))?;

		let (tx, rx) = mpsc::channel(1);
		if let Some(file) = r {
			// Asynchronously start loading the blocks one by one, from disk preferably,
			// from the network otherwise
			let node = self.node.clone();
			spawn(async move {
				let mut actor_node: Option<Arc<ActorNode>> = None;
				let mut loaded_actor_node = false;
				for i in 0..file.blocks.len() {
					let block_hash = &file.blocks[i];
					match db.perform(|c| c.fetch_block(block_hash)) {
						Ok(block_result) => match block_result {
							Some(mut block) => {
								db::decrypt_block(i as _, &file.plain_hash, &mut block);
								if let Err(_) = tx.send(Ok(block)).await {
									error!("Unable to send block on stream-file channel.");
								}
							}
							None => {
								if !loaded_actor_node {
									actor_node =
										node.get_actor_node_or_lurker(&actor_address).await;
									loaded_actor_node = true;
								}

								if let Some(n) = &actor_node {
									// Find the block on the network, and store it if we have found
									// it
									if let Some(r) = n.find_block(block_hash).await {
										if let Err(e) =
											db.perform(|mut c| c.store_block(block_hash, &r.data))
										{
											if let Err(_) = tx.send(Err(e)).await {
												error!(
													"Unable to send error on stream-file channel."
												);
											}
										}
										let mut block = r.data;
										db::decrypt_block(i as _, &file.plain_hash, &mut block);
										if let Err(_) = tx.send(Ok(block)).await {
											error!("Unable to send block on stream-file channel.");
										}
										continue;
									}
								}
							}
						},
						Err(e) =>
							if let Err(_) = tx.send(Err(e)).await {
								error!("Unable to send error on stream-file channel.");
							},
					}
				}
			});
			Ok(Some((file.mime_type, ReceiverStream::new(rx))))
		} else {
			Ok(None)
		}
	}

	pub async fn publish_post(
		&self, identity: &ActorAddress, private_key: &ActorPrivateKeyV1, message: &str,
		tags: Vec<String>, attachments: &[FileData], in_reply_to: Option<(ActorAddress, IdType)>,
	) -> db::Result<IdType> {
		let (hash, object) = self.old_db.perform(|mut c| {
			let tx = c.transaction()?;
			let identity_id =
				db::Connection::_find_identity(&tx, identity)?.expect("unknown identity");

			// Store all files
			let mut files = Vec::with_capacity(attachments.len() + 1);
			let (_, file_hash, _) =
				db::Connection::_store_file_data(&tx, "text/markdown", message.as_bytes())?;
			files.push(file_hash);
			for FileData { mime_type, data } in attachments {
				let (_, file_hash, _) = db::Connection::_store_file_data(&tx, mime_type, data)?;
				files.push(file_hash);
			}

			// Sign the post
			let next_object_sequence = db::Connection::_next_object_sequence(&tx, identity_id)?;
			let object_payload = ObjectPayload::Post(PostObject {
				in_reply_to: in_reply_to.clone(),
				data: PostObjectCryptedData::Plain(PostObjectDataPlain {
					tags: tags.clone(),
					files: files.clone(),
				}),
			});
			let created = Utc::now().timestamp_millis() as u64;
			let previous_hash = db::Connection::_fetch_object_hash_by_sequence(
				&tx,
				identity,
				next_object_sequence - 1,
			)?;
			let (hash, signature) = Self::sign_object(
				next_object_sequence,
				&previous_hash,
				created,
				&object_payload,
				&private_key,
			);

			db::Connection::_store_post(
				&tx,
				identity_id,
				created,
				&previous_hash,
				true,
				&tags,
				&files,
				&hash,
				&signature,
				in_reply_to,
			)?;
			tx.commit()?;

			Ok((
				hash,
				Object {
					created,
					sequence: next_object_sequence,
					previous_hash,
					signature,
					payload: object_payload,
				},
			))
		})?;

		if let Some(actor_node) = self.node.get_actor_node(&identity.as_id()).await {
			actor_node.publish_object(&self.node, &hash, &object).await;
		} else {
			error!("Actor node not found.");
		}

		Ok(hash)
	}

	async fn find_next_object_sequence(
		c: &impl ConnectionTrait, identity_id: i64,
	) -> Result<u64, DbErr> {
		let stat = object::Entity::find()
			.column_as(object::Column::Sequence.max(), "max")
			.filter(object::Column::ActorId.eq(identity_id))
			.build(DatabaseBackend::Sqlite);

		if let Some(result) = c.query_one(stat).await? {
			Ok(result.try_get_by_index::<i64>(0)? as u64)
		} else {
			Ok(0)
		}
	}

	async fn find_object_by_sequence(
		c: &impl ConnectionTrait, identity_id: i64, sequence: u64,
	) -> Result<Option<object::Model>, DbErr> {
		object::Entity::find()
			.filter(object::Column::ActorId.eq(identity_id))
			.filter(object::Column::Sequence.eq(sequence))
			.one(c)
			.await
	}

	async fn store_share(
		&self, identity: &ActorAddress, private_key: &ActorPrivateKeyV1, share: &ShareObject,
	) -> Result<(i64, IdType, Object), DbErr> {
		let tx = self.orm.begin().await?;

		// Construct fields for the share object
		let identity_record = identity::Entity::find()
			.filter(identity::Column::Address.eq(identity))
			.one(&tx)
			.await?
			.expect("identity doesn't exist");

		let next_object_sequence = Self::find_next_object_sequence(&tx, identity_record.id).await?;
		let object_payload = ObjectPayload::Share(share.clone());
		let created = Utc::now().timestamp_millis();

		let previous_object =
			Self::find_object_by_sequence(&tx, identity_record.id, next_object_sequence - 1)
				.await?;
		let previous_hash = previous_object
			.map(|o| o.hash)
			.unwrap_or(IdType::default());
		let (hash, signature) = Self::sign_object(
			next_object_sequence,
			&previous_hash,
			created as _,
			&object_payload,
			&private_key,
		);

		// Insert the object record
		let result = object::Entity::insert(object::ActiveModel {
			id: NotSet,
			actor_id: Set(identity_record.id),
			hash: Set(hash.clone()),
			signature: Set(signature.clone()),
			sequence: Set(next_object_sequence as _),
			previous_hash: Set(previous_hash.clone()),
			created: Set(created),
			verified_from_start: Set(true),
			found: Set(created),
			r#type: Set(OBJECT_TYPE_SHARE),
		})
		.exec(&tx)
		.await?;
		let object_id = result.last_insert_id;

		// Insert the share object record
		boost_object::Entity::insert(boost_object::ActiveModel {
			object_id: Set(object_id),
			actor_address: Set(share.actor_address.clone()),
			object_hash: Set(share.object_hash.clone()),
		}).exec(&tx).await?;

		tx.commit().await?;

		let object = Object {
			signature,
			sequence: next_object_sequence,
			previous_hash,
			created: created as _,
			payload: ObjectPayload::Share(share.clone()),
		};
		Ok((result.last_insert_id, hash, object))
	}

	pub async fn publish_share(
		&self, identity: &ActorAddress, private_key: &ActorPrivateKeyV1, object: &ShareObject,
	) -> Result<IdType, DbErr> {
		// Store the share object
		let (_, hash, object) = self.store_share(identity, private_key, object).await?;

		// Publish the object into the network
		if let Some(actor_node) = self.node.get_actor_node(&identity.as_id()).await {
			actor_node.publish_object(&self.node, &hash, &object).await;
		} else {
			error!("Actor node not found.");
		}
		Ok(hash)
	}

	/// Calculates the signature of the s
	fn sign_object(
		sequence: u64, previous_hash: &IdType, created: u64, payload: &ObjectPayload,
		private_key: &ActorPrivateKeyV1,
	) -> (IdType, ActorSignatureV1) {
		// Prepare data to be signed
		let sign_data = ObjectSignData {
			previous_hash: previous_hash.clone(),
			sequence,
			created,
			payload,
		};
		let raw_sign_data = binserde::serialize(&sign_data).unwrap();

		// Sign it
		let signature = private_key.sign(&raw_sign_data);
		let hash = signature.hash();

		(hash, signature)
	}
}

/*impl From<db::Error> for Error {
	fn from(other: db::Error) -> Self {
		Self::DatabaseError(other)
	}
}

impl From<io::Error> for Error {
	fn from(other: io::Error) -> Self {
		Self::NetworkError(other)
	}
}*/

// FIXME: Remove when going stable:
#![allow(deprecated)]

use std::{
	collections::HashMap,
	sync::Arc,
	time::{SystemTime, UNIX_EPOCH},
};

use chrono::Utc;
use log::*;
use rand::rngs::OsRng;
use sea_orm::{prelude::*, NotSet, Set};
use serde::Serialize;
use tokio::{spawn, sync::mpsc};
use tokio_stream::wrappers::ReceiverStream;

use super::{
	common::*,
	core::*,
	db::{self, PersistenceHandle},
	identity::*,
	net::{actor::ActorNode, binserde, overlay::OverlayNode},
};
use crate::{
	compression::decompress,
	db::{decrypt_block, Database},
	entity::*,
	serde_limit::LimString,
	web::{
		self,
		consolidated_feed::{
			load_next_unconsolidated_activity_pub_objects, load_next_unconsolidated_objects,
		},
		info::{ObjectInfo, ProfileObjectInfo},
	},
};


#[derive(Clone)]
pub struct Api {
	pub node: Arc<OverlayNode>,
	pub db: Database,
}

#[derive(Debug, Serialize)]
pub struct OtherObjectInfo {
	pub mime_type: String,
	pub content: String,
}

pub enum PossibleFileStream {
	None,
	//Full(FileData),
	Stream((String, CompressionType, ReceiverStream<db::Result<Vec<u8>>>)),
}


impl Api {
	pub async fn close(self) { self.node.close().await; }

	fn compose_profile_object(
		private_key: &ActorPrivateKeyV1, sequence: u64, name: &str, avatar_hash: &Option<IdType>,
		wallpaper_hash: &Option<IdType>, description_hash: &Option<IdType>,
	) -> (IdType, BlogchainObject) {
		let profile = ProfileObject {
			name: name.into(),
			avatar: avatar_hash.clone(),
			wallpaper: wallpaper_hash.clone(),
			description: description_hash.clone(),
		};

		// Sign the profile object and construct an object out of it
		let payload = ObjectPayload::Profile(profile);
		let sign_data = ObjectSignData {
			sequence,
			previous_hash: IdType::default(),
			created: SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_millis() as u64,
			payload: &payload,
		};

		let signature = private_key.sign(&binserde::serialize(&sign_data).unwrap());
		let object_hash = signature.hash();
		let object = BlogchainObject {
			signature,
			previous_hash: IdType::default(),
			sequence: 0,
			created: sign_data.created,
			payload,
		};

		(object_hash, object)
	}

	pub async fn create_identity(
		&self, label: &str, name: &str, avatar: Option<&FileData>, wallpaper: Option<&FileData>,
		description: Option<&FileData>,
	) -> db::Result<(ActorAddress, ActorInfo)> {
		let tx = self.db.transaction().await?;
		// Prepare profile files
		let avatar_hash = if let Some(f) = avatar {
			Some(tx.create_file(f).await?.1)
		} else {
			None
		};
		let wallpaper_hash = if let Some(f) = wallpaper {
			Some(tx.create_file(f).await?.1)
		} else {
			None
		};
		let description_hash = if let Some(f) = description {
			Some(tx.create_file(f).await?.1)
		} else {
			None
		};

		let private_key = ActorPrivateKeyV1::generate_with_rng(&mut OsRng);
		let (object_hash, object) = Self::compose_profile_object(
			&private_key,
			0,
			name,
			&avatar_hash,
			&wallpaper_hash,
			&description_hash,
		);
		/*let profile = ProfileObject {
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
		};*/

		// Generate an actor ID with our new object hash.
		let actor_info = ActorInfo::V1(ActorInfoV1 {
			flags: 0,
			public_key: private_key.public(),
			first_object: object_hash.clone(),
			actor_type: ACTOR_TYPE_BLOGCHAIN.into(),
		});
		let actor_address = actor_info.generate_address();

		// Create the identity on disk
		// TODO: Remove old code and create the identity with the same transaction as
		// used for the files
		let actor_id = tx
			.create_identity(
				label,
				&actor_address,
				&actor_info.public_key,
				&private_key,
				false,
				&object_hash,
			)
			.await?;
		tx.store_profile(
			actor_id,
			object.created,
			&object_hash,
			&IdType::default(),
			&object.signature,
			true,
			name,
			avatar_hash,
			wallpaper_hash,
			description_hash,
		)
		.await?;
		tx.commit().await?;
		Ok((actor_address, actor_info))
	}

	pub async fn create_share(
		&self, identity: &ActorAddress, private_key: &ActorPrivateKeyV1, share: &ShareObject,
	) -> db::Result<(i64, IdType, BlogchainObject)> {
		let tx = self.db.transaction().await?;

		// Construct fields for the share object
		let identity_record = actor::Entity::find()
			.filter(actor::Column::Address.eq(identity))
			.one(tx.inner())
			.await?
			.expect("identity doesn't exist");

		let next_object_sequence = tx.find_next_object_sequence(identity_record.id).await?;
		let object_payload = ObjectPayload::Share(share.clone());
		let created = Utc::now().timestamp_millis();

		// TODO: Create a seperate db function that merely finds the hash of the object,
		// not the whole object.
		let previous_object = tx
			.find_objects_by_sequence(identity, next_object_sequence - 1)
			.await?;
		let previous_hash = previous_object
			.get(0)
			.map(|o| o.hash.clone())
			.unwrap_or(IdType::default());
		let (hash, signature) = Self::sign_object(
			next_object_sequence,
			&previous_hash,
			created as _,
			&object_payload,
			&private_key,
		);

		// Insert the object record
		// TODO: Move this into module `db`:
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
			published_on_fediverse: Set(false),
		})
		.exec(tx.inner())
		.await?;
		let object_id = result.last_insert_id;

		// Insert the share object record
		share_object::Entity::insert(share_object::ActiveModel {
			object_id: Set(object_id),
			actor_address: Set(share.actor_address.clone()),
			object_hash: Set(share.object_hash.clone()),
		})
		.exec(tx.inner())
		.await?;

		tx.commit().await?;

		let object = BlogchainObject {
			signature,
			sequence: next_object_sequence,
			previous_hash,
			created: created as _,
			payload: ObjectPayload::Share(share.clone()),
		};
		Ok((result.last_insert_id, hash, object))
	}

	pub async fn find_block(
		&self, actor_node_opt: Option<&Arc<ActorNode>>, hash: &IdType,
	) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect_old()?;
			c.fetch_block(hash)
		})?;

		Ok(match result {
			Some(b) => Some(b),
			None =>
				if let Some(actor_node) = actor_node_opt {
					actor_node.find_block(hash).await.map(|r| r.data.into())
				} else {
					None
				},
		})
	}

	pub async fn find_file(
		&self, actor_node_opt: Option<&Arc<ActorNode>>, hash: &IdType,
	) -> db::Result<Option<File>> {
		let mut result = if let Some(record) = file::Entity::find()
			.filter(file::Column::Hash.eq(hash))
			.one(self.db.inner())
			.await?
		{
			let blocks = self
				.db
				.load_file_blocks(record.id, record.block_count)
				.await?;
			Some(File {
				plain_hash: record.plain_hash,
				mime_type: record.mime_type.into(),
				compression_type: record.compression_type,
				blocks,
			})
		} else {
			None
		};

		if result.is_none() {
			if let Some(actor_node) = actor_node_opt {
				result = actor_node.find_file(hash).await.map(|r| r.file)
			}
		}

		Ok(result)
	}

	/// Loads the (undecompressed) file data
	#[allow(dead_code)]
	pub async fn find_file_data(
		&self, actor_node_opt: Option<&Arc<ActorNode>>, hash: &IdType,
	) -> db::Result<Option<FileData>> {
		// TODO: Optionally decompress data
		let file = if let Some(f) = self.find_file(actor_node_opt, hash).await? {
			f
		} else {
			return Ok(None);
		};

		// Fill a buffer with all the data
		let mut buffer = Vec::with_capacity(file.blocks.len() * db::BLOCK_SIZE);
		let mut i = 0;
		for block_id in &file.blocks {
			let block_result = self.find_block(actor_node_opt, block_id).await?;
			match block_result {
				None => return Ok(None),
				Some(mut block) => {
					decrypt_block(i, &file.plain_hash, &mut block);
					buffer.extend(block);
					i += 1;
				}
			}
		}

		// TODO: Remove unwrap
		let compression_type = CompressionType::from_u8(file.compression_type).unwrap();

		Ok(Some(FileData {
			mime_type: file.mime_type,
			// TODO: remove unwrap
			data: decompress(compression_type, &buffer).unwrap(),
		}))
	}

	#[allow(unused)]
	pub fn fetch_my_identity(
		&self, address: &ActorAddress,
	) -> db::Result<Option<(String, ActorPrivateKeyV1)>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let c = this.db.connect_old()?;
			c.fetch_my_identity(address)
		})
	}

	pub fn fetch_my_identities(
		&self,
	) -> db::Result<Vec<(String, ActorAddress, IdType, String, ActorPrivateKeyV1)>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let c = this.db.connect_old()?;
			c.fetch_my_identities()
		})
	}

	pub async fn find_profile_info(
		&self, url_base: &str, actor_address: &ActorAddress,
	) -> db::Result<Option<ProfileObjectInfo>> {
		let profile = web::info::find_profile_info(&self.db, url_base, actor_address).await?;
		if profile.is_some() {
			return Ok(profile);
		}

		// Try to get the profile from the actor network
		if let Some(_) = self.node.find_actor_profile_info(actor_address).await {
			// TODO: Contruct the profile info from the object
			let profile = web::info::find_profile_info(&self.db, url_base, actor_address).await?;
			return Ok(profile);
		}
		Ok(None)
	}

	pub async fn follow(&self, address: &ActorAddress, join_network: bool) -> db::Result<bool> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect_old()?;
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
			let mut c = self.db.connect_old()?;
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
			let mut c = self.db.connect_old()?;
			c.unfollow(actor_id)
		})?;

		if success {
			self.node.drop_actor_network(&actor_id.as_id()).await;
		}
		Ok(success)
	}

	pub fn is_following(&self, actor_id: &ActorAddress) -> db::Result<bool> {
		tokio::task::block_in_place(|| {
			let c = self.db.connect_old()?;
			c.is_following(actor_id)
		})
	}

	pub async fn load_home_feed(&self, count: u64, offset: u64) -> db::Result<Vec<ObjectInfo>> {
		// TODO: Manage tracked actors as followers with a CLI tool
		//       Currently, because tracked actors are not stored in the DB, it
		//       is hard to have them show up in the consolidated home feed.
		let tracked_actors: Vec<ActorAddress> = self
			.node
			.tracked_actors
			.lock()
			.await
			.keys()
			.map(|a| a.clone())
			.collect();
		web::info::load_home_feed(&self.db, count, offset, tracked_actors.iter()).await
	}

	// Like `load_file`, but return an async stream that catches all the blocks that
	// are being loaded in another thread.
	pub async fn stream_file(
		&self, actor_address: ActorAddress, file_hash: IdType,
	) -> db::Result<PossibleFileStream> {
		let db = self.db.clone();
		let r: Option<(i64, File)> = db.find_file(&file_hash).await?;

		// TODO: Don't decompress the file, but let the browser do that.
		if let Some((file_id, file)) = r {
			let compression_type = match CompressionType::from_u8(file.compression_type) {
				Some(t) => t,
				None => {
					error!(
						"Unable to stream file with unknown compression type {}",
						file.compression_type
					);
					return Ok(PossibleFileStream::None);
				}
			};

			/*if file.compression_type != CompressionType::None as u8 {
				// TODO: Make sure that the file meta data isn't searched over the network
				// twice.
				let actor_node_opt = self.node.get_actor_node_or_lurker(&actor_address).await;
				if let Some(file_data) = self
					.find_file_data(actor_node_opt.as_ref(), &file_hash)
					.await?
				{
					return Ok(PossibleFileStream::Full(file_data));
				} else {
					return Ok(PossibleFileStream::None);
				}
			}*/

			let (tx, rx) = mpsc::channel(1);
			// Asynchronously start loading the blocks one by one, from disk preferably,
			// from the network otherwise
			let node: Arc<OverlayNode> = self.node.clone();
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
										if let Err(e) = db.perform(|mut c| {
											c.store_block(file_id, block_hash, &r.data)
										}) {
											if let Err(_) = tx.send(Err(e)).await {
												error!(
													"Unable to send error on stream-file channel."
												);
											}
										}
										let mut block = r.data;
										db::decrypt_block(i as _, &file.plain_hash, &mut block);
										if let Err(_) = tx.send(Ok(block.into())).await {
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
			Ok(PossibleFileStream::Stream((
				file.mime_type.to_string(),
				compression_type,
				ReceiverStream::new(rx),
			)))
		} else {
			Ok(PossibleFileStream::None)
		}
	}

	pub async fn publish_post(
		&self, actor_address: &ActorAddress, private_key: &ActorPrivateKeyV1, msg_mime_type: &str,
		message: &str, tags: Vec<String>, attachments: &[FileData],
		in_reply_to: Option<(ActorAddress, IdType)>,
	) -> db::Result<IdType> {
		let tx = self.db.transaction().await?;
		let actor = actor::Entity::find()
			.filter(actor::Column::Address.eq(actor_address))
			.one(tx.inner())
			.await?;
		assert!(actor.is_some(), "actor address not known");
		let actor_id = actor.unwrap().id;

		// Store all files
		let mut files = Vec::with_capacity(attachments.len() + 1);
		let (_, file_hash, _) = tx.create_file2(msg_mime_type, message.as_bytes()).await?;
		files.push(file_hash);
		for FileData { mime_type, data } in attachments {
			let (_, file_hash, _) = tx.create_file2(mime_type.as_str(), data).await?;
			files.push(file_hash);
		}

		// Sign the post
		let next_object_sequence = tx.find_next_object_sequence(actor_id).await?;
		if next_object_sequence == 0 {
			Err(db::Error::UnexpectedState(
				"actor has no objects".to_string(),
			))?;
		}
		let tags2: Vec<LimString<_>> = tags.iter().map(|i| i.into()).collect();
		let object_payload = ObjectPayload::Post(PostObject {
			in_reply_to: in_reply_to.clone(),
			data: PostObjectCryptedData::Plain(PostObjectDataPlain {
				tags: tags2.into(),
				files: files.clone().into(),
			}),
		});
		let created = Utc::now().timestamp_millis() as u64;
		let current_object_sequence = next_object_sequence - 1;
		let previous_hash = if let Some(object) = object::Entity::find()
			.filter(object::Column::ActorId.eq(actor_id))
			.filter(object::Column::Sequence.eq(current_object_sequence))
			.one(tx.inner())
			.await?
		{
			object.hash
		} else {
			return Err(db::Error::UnexpectedState(format!(
				"can't find object sequence {} for actor {}",
				current_object_sequence, actor_id
			)))?;
		};
		let (hash, signature) = Self::sign_object(
			next_object_sequence,
			&previous_hash,
			created,
			&object_payload,
			&private_key,
		);

		tx.store_post(
			actor_id,
			created,
			&hash,
			&previous_hash,
			&signature,
			true,
			&tags,
			&files,
			in_reply_to,
			false,
		)
		.await?;
		tx.commit().await?;

		let object = BlogchainObject {
			created,
			sequence: next_object_sequence,
			previous_hash,
			signature,
			payload: object_payload,
		};

		if let Some(actor_node) = self.node.get_actor_node(&actor_address.as_id()).await {
			actor_node
				.publish_object(&self.node, &hash, &object, &[], 0)
				.await;
		} else {
			error!("Actor node not found.");
		}

		Ok(hash)
	}

	pub async fn publish_share(
		&self, identity: &ActorAddress, private_key: &ActorPrivateKeyV1, object: &ShareObject,
	) -> db::Result<IdType> {
		// Store the share object
		let (_, hash, object) = { self.create_share(identity, private_key, object).await? };

		// Publish the object into the network
		if let Some(actor_node) = self.node.get_actor_node(&identity.as_id()).await {
			actor_node
				.publish_object(&self.node, &hash, &object, &[], 0)
				.await;
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

	pub async fn update_consolidated_feed(&self) -> db::Result<()> {
		fn merge_objects(
			batch: u64, stonenet_objects: HashMap<i64, (i64, i64)>,
			activity_pub_objects: HashMap<i64, (i64, i64)>,
		) -> Vec<consolidated_object::ActiveModel> {
			let mut consolidated_objects: Vec<_> = stonenet_objects
				.into_iter()
				.map(
					|(actor_id, (object_id, timestamp))| consolidated_object::ActiveModel {
						id: NotSet,
						batch: Set(batch as _),
						r#type: Set(0),
						actor_id: Set(actor_id),
						object_id: Set(object_id),
						timestamp: Set(timestamp),
					},
				)
				.collect();
			let ap_objects: Vec<_> = activity_pub_objects
				.into_iter()
				.map(
					|(actor_id, (object_id, timestamp))| consolidated_object::ActiveModel {
						id: NotSet,
						batch: Set(batch as _),
						r#type: Set(1),
						actor_id: Set(actor_id),
						object_id: Set(object_id),
						timestamp: Set(timestamp),
					},
				)
				.collect();
			consolidated_objects.extend(ap_objects);

			consolidated_objects.sort_by(|a, b| {
				b.timestamp
					.as_ref()
					.partial_cmp(a.timestamp.as_ref())
					.unwrap()
			});
			consolidated_objects
		}

		let batch = self.db.next_consolidated_feed_batch().await?;

		// Get new objects from each source, but only one per actor
		loop {
			let stonenet_objects = load_next_unconsolidated_objects(&self.db).await?;
			let activity_pub_objects =
				load_next_unconsolidated_activity_pub_objects(&self.db).await?;
			let consolidated = merge_objects(batch, stonenet_objects, activity_pub_objects);
			if consolidated.len() == 0 {
				return Ok(());
			}

			for object in consolidated {
				consolidated_object::Entity::insert(object)
					.exec(self.db.inner())
					.await?;
			}
		}
	}

	pub async fn update_profile(
		&self, private_key: &ActorPrivateKeyV1, actor_id: i64, old_label: &str, new_label: &str,
		name: &str, avatar: Option<FileData>, wallpaper: Option<FileData>,
		description: Option<FileData>,
	) -> db::Result<()> {
		let tx = self.db.transaction().await?;

		// Prepare profile files
		let (old_avatar_hash, old_wallpaper_hash, old_description_hash) =
			tx.find_profile_files(actor_id).await?;
		let avatar_hash = if let Some(f) = avatar {
			Some(tx.create_file(&f).await?.1)
		} else {
			old_avatar_hash
		};
		let wallpaper_hash = if let Some(f) = wallpaper {
			Some(tx.create_file(&f).await?.1)
		} else {
			old_wallpaper_hash
		};
		let description_hash = if let Some(f) = description {
			Some(tx.create_file(&f).await?.1)
		} else {
			old_description_hash
		};

		// Construct the profle object & store it
		let next_sequence = tx.find_next_object_sequence(actor_id).await?;
		let (object_hash, object) = Self::compose_profile_object(
			private_key,
			next_sequence,
			name,
			&avatar_hash,
			&wallpaper_hash,
			&description_hash,
		);
		tx.store_profile(
			actor_id,
			object.created,
			&object_hash,
			&object.previous_hash,
			&object.signature,
			true,
			name,
			avatar_hash,
			wallpaper_hash,
			description_hash,
		)
		.await?;
		tx.update_identity_label(old_label, new_label).await?;

		tx.commit().await
	}
}


#[cfg(test)]
mod tests {
	use rand::RngCore;

	use super::*;
	use crate::test;

	#[tokio::test]
	async fn test_create_identity() {
		let mut rng = test::initialize_rng();
		let db = test::load_database("api").await;
		let node = test::empty_node(db.clone(), &mut rng).await;
		let api = Api {
			node,
			db: db.clone(),
		};

		let label = "Label";
		let name = "Display name";
		let mut avatar_data = vec![0u8; 1024];
		rng.fill_bytes(&mut avatar_data);
		let avatar = FileData {
			mime_type: "image/png".into(),
			data: avatar_data,
		};
		let mut wallpaper_data = vec![0u8; 10240];
		rng.fill_bytes(&mut wallpaper_data);
		let wallpaper = FileData {
			mime_type: "image/jpeg".into(),
			data: wallpaper_data,
		};
		let description_data = "Actor description";
		let description = FileData {
			mime_type: "text/plain".into(),
			data: description_data.as_bytes().to_vec(),
		};

		// Create the files already so that we know the hashes beforehand
		let tx = db.transaction().await.unwrap();
		let (_, avatar_hash, _) = tx.create_file(&avatar).await.unwrap();
		let (_, wallpaper_hash, _) = tx.create_file(&wallpaper).await.unwrap();
		let (_, description_hash, _) = tx.create_file(&description).await.unwrap();
		tx.commit().await.unwrap();

		let (address, _) = api
			.create_identity(
				label,
				name,
				Some(&avatar),
				Some(&wallpaper),
				Some(&description),
			)
			.await
			.unwrap();

		actor::Entity::find()
			.filter(actor::Column::Address.eq(&address))
			.one(db.inner())
			.await
			.unwrap()
			.expect("actor not found");
		identity::Entity::find()
			.filter(identity::Column::Label.eq(label))
			.one(db.inner())
			.await
			.unwrap()
			.expect("identity not found");
		let object = object::Entity::find()
			.filter(object::Column::Sequence.eq(0))
			.one(db.inner())
			.await
			.unwrap()
			.expect("profile object not found");
		assert_eq!(object.r#type, OBJECT_TYPE_PROFILE);
		let profile = db
			.load_profile_object_payload(object.id)
			.await
			.unwrap()
			.expect("profile object payload not found");
		assert_eq!(profile.name.as_str(), name);
		assert_eq!(profile.avatar, Some(avatar_hash.clone()));
		assert_eq!(profile.wallpaper, Some(wallpaper_hash.clone()));
		assert_eq!(profile.description, Some(description_hash));

		let profile_info = web::info::find_profile_info(&db, "", &address)
			.await
			.unwrap()
			.expect("profile info not found");
		assert_eq!(profile_info.actor.address, address.to_string());
		assert_eq!(profile_info.actor.name, name.to_string());
		assert_eq!(
			profile_info.actor.avatar_url,
			Some(format!("/actor/{}/file/{}", &address, avatar_hash))
		);
		assert_eq!(
			profile_info.actor.wallpaper_url,
			Some(format!("/actor/{}/file/{}", &address, wallpaper_hash))
		);
		assert_eq!(profile_info.description, Some(description_data.to_string()));
	}
}

// FIXME: Remove when going stable:
#![allow(dead_code)]

use std::{
	cmp::min,
	sync::Arc,
	time::{SystemTime, UNIX_EPOCH},
};

use chrono::*;
use log::*;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

use super::{
	common::*,
	db::{self, *},
	identity::*,
	model::*,
	net::{actor::ActorNode, bincode, message::*, overlay::OverlayNode},
};

/*#[derive(Debug)]
pub enum Error {
	DatabaseError(db::Error),
	NetworkError(io::Error)
}*/

#[derive(Clone)]
pub struct Api {
	pub node: Arc<OverlayNode>,
	pub db: Database,
}

//pub type Result<T> = std::result::Result<T, self::Error>;

impl Api {
	pub async fn close(self) { self.node.close().await; }

	pub fn create_my_identity(
		&self, label: &str, name: &str, avatar: Option<&FileData>, wallpaper: Option<&FileData>,
		description: &str,
	) -> db::Result<(IdType, ActorInfo)> {
		let private_key = PrivateKey::generate();
		let this = self.clone();

		// Prepare profile object
		let avatar_data = avatar.map(|f| self.split_file(&f.mime_type, &f.data));
		let wallpaper_data = wallpaper.map(|f| self.split_file(&f.mime_type, &f.data));
		let description_hash_opt = if description.len() > 0 {
			Some(IdType::hash(description.as_bytes()))
		} else {
			None
		};
		let profile = ProfileObject {
			name: name.to_string(),
			avatar: avatar_data.as_ref().map(|(hash, _)| hash.clone()),
			wallpaper: wallpaper_data.as_ref().map(|(hash, _)| hash.clone()),
			description: description_hash_opt.clone(),
		};

		// Sign the profile object and construct an object out of it
		let payload = ObjectPayload::Profile(profile.clone());
		let sign_data = ObjectSignData {
			sequence: 0,
			previous_hash: IdType::default(),
			created: SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_millis() as u64,
			payload: &payload,
		};
		let signature = private_key.sign(&bincode::serialize(&sign_data).unwrap());
		let object_hash = IdType::hash(&signature.to_bytes());
		let object = Object {
			signature,
			previous_hash: IdType::default(),
			sequence: 0,
			created: sign_data.created,
			payload,
		};

		// Generate an actor ID with our new object hash.
		let actor_info = ActorInfo {
			public_key: private_key.public(),
			first_object: object_hash.clone(),
			actor_type: "feed".into(),
		};
		let actor_id = IdType::hash(&bincode::serialize(&actor_info).unwrap());

		// Create the identity on disk
		tokio::task::block_in_place(|| {
			let mut c = this.db.connect()?;
			c.create_my_identity(
				label,
				&private_key,
				&object_hash,
				&object,
				name,
				avatar_data.as_ref().map(|(hash, blocks)| {
					(hash, avatar.unwrap().mime_type.as_str(), blocks.as_slice())
				}),
				wallpaper_data.as_ref().map(|(hash, blocks)| {
					(
						hash,
						wallpaper.unwrap().mime_type.as_str(),
						blocks.as_slice(),
					)
				}),
				description_hash_opt.map(|hash| (hash, description)),
			)
		})?;

		Ok((actor_id, actor_info))
	}

	pub async fn find_block(
		&self, actor_node: &ActorNode, id: &IdType,
	) -> db::Result<Option<Vec<u8>>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_block(actor_node.actor_id(), id)
		})?;

		Ok(match result {
			Some(b) => Some(b),
			None => actor_node.find_block(id).await.map(|r| r.data),
		})
	}

	pub async fn find_file(&self, actor_node: &ActorNode, id: &IdType) -> db::Result<Option<File>> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
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
			let c = self.db.connect()?;
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
			let c = self.db.connect()?;
			c.fetch_object(actor_node.actor_id(), id)
		})?;

		Ok(match result {
			Some((object, _)) => Some(FindObjectResult { object }),
			None => actor_node.find_object(id).await,
		})
	}

	pub fn fetch_home_feed(&self, count: u64, offset: u64) -> db::Result<Vec<ObjectInfo>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let mut c = this.db.connect()?;
			c.fetch_home_feed(count, offset)
		})
	}

	pub fn fetch_my_identity(&self, address: &IdType) -> db::Result<Option<(String, PrivateKey)>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let c = this.db.connect()?;
			c.fetch_my_identity(address)
		})
	}

	pub fn fetch_my_identity_by_label(
		&self, label: &str,
	) -> db::Result<Option<(IdType, PrivateKey)>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let c = this.db.connect()?;
			c.fetch_my_identity_by_label(label)
		})
	}

	pub fn fetch_my_identities(
		&self,
	) -> db::Result<Vec<(String, IdType, IdType, String, PrivateKey)>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let c = this.db.connect()?;
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
		&self, actor_id: &IdType, sequence: u64,
	) -> db::Result<Option<ObjectInfo>> {
		tokio::task::block_in_place(|| {
			let mut c = self.db.connect()?;
			c.fetch_object_info(actor_id, sequence)
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
		&self, actor_id: &IdType,
	) -> db::Result<Option<ProfileObjectInfo>> {
		let profile = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_profile_info(actor_id)
		})?;
		if profile.is_some() {
			return Ok(profile);
		}

		// FIXME: Also load the avatar and wallpaper files and the description block
		let actor_node = match self.node.lurk_actor_network(actor_id).await {
			None => {
				warn!("Couldn't reach actor network for profile.");
				return Ok(None);
			}
			Some(n) => n,
		};

		Ok(match actor_node.fetch_profile().await {
			None => None,
			Some(ProfileObject {
				name,
				avatar,
				wallpaper,
				description,
			}) => {
				let info = ProfileObjectInfo {
					actor: TargetedActorInfo {
						id: actor_id.clone(),
						name,
						avatar_id: avatar,
						wallpaper_id: wallpaper,
					},
					description: match description {
						None => None,
						Some(hash) => {
							let raw = self.find_block(&actor_node, &hash).await?;
							raw.map(|r| String::from_utf8_lossy(&r).into_owned())
						}
					},
				};

				Some(info)
			}
		})
	}

	pub async fn follow(&self, actor_id: &IdType, join_network: bool) -> db::Result<bool> {
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_identity(actor_id)
		})?;
		let actor_info = match result {
			Some(pk) => pk,
			None => match self.node.find_actor(actor_id, 100, false).await {
				Some(r) => r.0.clone(),
				None => return Ok(false),
			},
		};

		let _private_key = tokio::task::block_in_place(|| {
			let mut c = self.db.connect()?;
			c.follow(actor_id, &actor_info)
		})?;

		// Join network
		if join_network {
			let node = self.node.clone();
			let actor_id2 = actor_id.clone();
			tokio::spawn(async move {
				node.join_actor_network(actor_id2, actor_info).await;
			});
		}

		Ok(true)
	}

	pub async fn unfollow(&self, actor_id: &IdType) -> db::Result<bool> {
		let success = tokio::task::block_in_place(|| {
			let mut c = self.db.connect()?;
			c.unfollow(actor_id)
		})?;

		if success {
			self.node.drop_actor_network(actor_id).await;
		}
		Ok(success)
	}

	pub fn is_following(&self, actor_id: &IdType) -> db::Result<bool> {
		tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.is_following(actor_id)
		})
	}

	// Like `load_file`, but return an async stream that catches all the blocks that
	// are being loaded in another thread.
	pub async fn stream_file(
		&self, actor_id: IdType, hash: IdType,
	) -> Result<Option<(String, ReceiverStream<db::Result<Vec<u8>>>)>> {
		let (mt_tx, mt_rx) = oneshot::channel();
		let (tx, mut rx) = mpsc::channel(1);

		let db = self.db.clone();
		tokio::task::spawn_blocking(move || {
			let mut c = match db.connect() {
				Ok(c) => c,
				Err(e) => {
					if let Err(_) = tx.blocking_send(Err(db::Error::SqliteError(e))) {
						error!("Unable to send init error.");
					}
					return;
				}
			};
			let result = match c.load_file(&actor_id, &hash) {
				Ok(c) => c,
				Err(e) => {
					if let Err(_) = tx.blocking_send(Err(e)) {
						error!("Unable to send init error.");
					}
					return;
				}
			};

			if let Some((mime_type, mut loader)) = result {
				if let Err(_) = mt_tx.send(Some(mime_type)) {
					error!("Unable to send none.");
				}
				while let Some(result) = loader.next() {
					match result {
						Ok(block) =>
							if let Err(_) = tx.blocking_send(Ok(block)) {
								error!("Unable to send block.");
							},
						Err(e) => {
							match e {
								db::Error::FileMissingBlock(..) => {
									// TODO: Try to find the block on the
									// network, and send it back instead of the
									// error
								}
								_ => {}
							}
							if let Err(_) = tx.blocking_send(Err(e)) {
								error!("Unable to send block.");
							}
						}
					}
				}
			} else {
				if let Err(_) = mt_tx.send(None) {
					error!("Unable to send none.");
				}
			}
		});

		let mime_type = match mt_rx.await {
			Ok(r) => r,
			Err(_) => {
				if let Some(result) = rx.recv().await {
					if let Err(e) = result {
						return Err(e);
					}
				}
				panic!("Unable to receive mime type from file.");
			}
		};
		Ok(mime_type.map(|mt| (mt, ReceiverStream::new(rx))))
	}

	pub async fn publish_post(
		&self, identity: &IdType, private_key: &PrivateKey, message: &str, tags: Vec<String>,
		attachments: &[FileData], in_reply_to: Option<(IdType, IdType)>,
	) -> db::Result<IdType> {
		let (hash, object) = tokio::task::block_in_place(|| {
			let mut c = self.db.connect()?;
			let tx = c.transaction()?;
			let identity_id =
				db::Connection::_find_identity(&tx, identity)?.expect("unknown identity");

			// Store all files
			let mut files = Vec::with_capacity(attachments.len() + 1);
			let (_, file_hash, _) = db::Connection::_store_file_data(
				&tx,
				identity_id,
				"text/markdown",
				message.as_bytes(),
			)?;
			files.push(file_hash);
			for FileData { mime_type, data } in attachments {
				let (_, file_hash, _) =
					db::Connection::_store_file_data(&tx, identity_id, mime_type, data)?;
				files.push(file_hash);
			}

			// Sign the post
			let next_object_sequence = db::Connection::_next_object_sequence(&tx, identity_id)?;
			let object_payload = ObjectPayload::Post(PostObject {
				in_reply_to: in_reply_to.clone(),
				tags: tags.clone(),
				files: files.clone(),
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
			)?;

			db::Connection::_store_post(
				&tx,
				identity_id,
				created,
				&previous_hash,
				&tags,
				&files,
				&hash,
				&signature,
				in_reply_to,
			)?;
			tx.commit()?;

			Ok::<_, db::Error>((
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

		if let Some(actor_node) = self.node.get_actor_node(identity).await {
			actor_node
				.publish_object(self.node.clone(), &hash, &object)
				.await;
		} else {
			error!("Actor node not found.");
		}

		Ok(hash)
	}

	/// Calculates the signature of the s
	fn sign_object(
		sequence: u64, previous_hash: &IdType, created: u64, payload: &ObjectPayload,
		private_key: &PrivateKey,
	) -> db::Result<(IdType, Signature)> {
		// Prepare data to be signed
		let sign_data = ObjectSignData {
			previous_hash: previous_hash.clone(),
			sequence,
			created,
			payload,
		};
		let raw_sign_data = bincode::serialize(&sign_data).unwrap();

		// Sign it
		let signature = private_key.sign(&raw_sign_data);
		let hash = IdType::hash(&signature.to_bytes());

		Ok((hash, signature))
	}

	pub fn split_file(&self, mime_type: &str, data: &[u8]) -> (IdType, Vec<(IdType, Vec<u8>)>) {
		debug_assert!(data.len() <= u64::MAX as usize, "data too large");
		debug_assert!(data.len() > 0, "data can not be empty");
		let block_count = data.len() / BLOCK_SIZE + ((data.len() % BLOCK_SIZE) > 0) as usize;
		let mut blocks: Vec<&[u8]> = Vec::with_capacity(block_count);
		let mut file = File {
			mime_type: mime_type.to_string(),
			blocks: Vec::with_capacity(block_count),
		};
		let mut result = Vec::with_capacity(block_count);

		// Devide data into blocks
		let mut i = 0;
		loop {
			let slice = &data[i..];
			let actual_block_size = min(BLOCK_SIZE, slice.len());
			blocks.push(&slice[..actual_block_size]);

			i += db::BLOCK_SIZE;
			if i >= data.len() {
				break;
			}
		}

		// Calculate the block hashes
		for i in 0..block_count {
			let block_data = blocks[i];
			let block_hash = IdType::hash(block_data);
			file.blocks.push(block_hash.clone());
			result.push((block_hash, block_data.to_vec()));
		}

		// Calculate the file hash
		let file_buf = bincode::serialize(&file).unwrap();
		let file_hash = IdType::hash(&file_buf);

		(file_hash, result)
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

//! TODO: Rename this module to "Api".

use std::{
	sync::Arc
};

use super::{
	common::*,
	identity::*,
	model::*,
	net::{
		actor::ActorNode,
		overlay::OverlayNode
	},
	db::{self, Database}
};


/*#[derive(Debug)]
pub enum Error {
	DatabaseError(db::Error),
	NetworkError(io::Error)
}*/

#[derive(Clone)]
pub struct Api {
	pub node: Arc<OverlayNode>,
	pub db: Database
}

//pub type Result<T> = std::result::Result<T, self::Error>;


impl Api {

	pub fn create_my_identity(&self,
		label: &str,
		identity: &IdType,
		keypair: &Keypair
	) -> db::Result<()> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let mut c = this.db.connect()?;
			c.store_my_identity(label, identity, keypair).map_err(|e| e.into())
		})
	}

	pub fn fetch_home_feed(&self,
		count: usize,
		offset: usize
	) -> db::Result<Vec<Object>> {
		
	}

	pub async fn fetch_latest_objects(&self,
		actor_id: &IdType,
		count: usize,
		offset: usize
	) -> db::Result<Vec<Option<Object>>> {
		Ok(match self.node.lurk_actor_network(actor_id).await {
			Some(actor_node) => {
				match actor_node.fetch_head().await {
					Some(latest_object_index) => {
						self.fetch_objects(
							&actor_node,
							latest_object_index,
							5
						).await?
					},
					None => Vec::new()
				}
			},
			None => Vec::new()
		})
	}

	pub fn fetch_my_identity(&self,
		address: &IdType
	) -> db::Result<Option<(String, Keypair)>> {
		let this = self.clone();
		tokio::task::block_in_place(|| {
			let c = this.db.connect()?;
			c.fetch_my_identity(address)
		})
	}

	pub fn fetch_my_identities(&self
	) -> db::Result<Vec<(String, IdType, Keypair)>> {
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

	pub async fn fetch_object(&self,
		actor_node: &ActorNode,
		index: u64
	) -> db::Result<Option<Object>> {
		let this = self.clone();
		let result = tokio::task::block_in_place(|| {
			let c = self.db.connect()?;
			c.fetch_object(index)
		});
		match result? {
			Some(object) => Ok(Some(object)),
			None => {
				Ok(actor_node.find_object(index, 100, true).await)
			}
		}
	}

	pub async fn fetch_objects(&self,
		actor_node: &ActorNode,
		last_post_index: u64,
		count: u64
	) -> db::Result<Vec<Option<Object>>> {
		let mut objects = Vec::with_capacity(count as _);
		// TODO: Execute fetch_object in parallel
		for i in 0..count {
			if i > last_post_index {
				return Ok(objects);
			}
			let result = self.fetch_object(
				actor_node,
				last_post_index - i
			).await?;
			objects.push(result);
		}
		Ok(objects)
	}

	pub async fn publish_post(&self,
		identity: &IdType,
		keypair: &Keypair,
		message: &str,
		tags: Vec<String>,
		attachments: &[(&str, &[u8])]
	) -> db::Result<()> {
		let mut c = self.db.connect()?;
		let identity_id = c.find_identity(identity)?.expect("unknown identity");

		// Store all files
		let mut files = Vec::with_capacity(attachments.len() + 1);
		let file_id = c.store_file("text/plain", message.as_bytes())?;
		files.push(FileHeader { hash: file_id, mime_type: "text/plain".into() });
		for (mime_type, data) in attachments {
			let file_id = c.store_file(mime_type, data)?;
			files.push(FileHeader { hash: file_id, mime_type: mime_type.to_string() });
		}

		// Sign the post
		let next_object_sequence = c.next_object_sequence(identity_id)?;
		let object_payload = ObjectPayload::Post(PostObject {
			in_reply_to: None,
			tags: tags.clone(),
			files: files.clone()
		});
		let payload_raw = bincode::serialize(&object_payload).expect("serialization error");
		let signature = keypair.sign(&payload_raw);

		c.store_post(identity_id, &tags, &files, &signature)?;

		let object = Object {
			sequence: next_object_sequence,
			signature,
			payload: object_payload
		};
		//self.node.publish_post()

		Ok(())
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

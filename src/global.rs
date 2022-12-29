use std::{
	sync::Arc
};

use super::{
	common::*,
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
pub struct Global {
	pub node: Arc<OverlayNode>,
	pub db: Arc<Database>
}

//pub type Result<T> = std::result::Result<T, self::Error>;


impl Global {

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

	async fn fetch_object(&self,
		actor_node: &ActorNode,
		index: u64
	) -> db::Result<Option<Object>> {
		match self.db.fetch_object(index)? {
			Some(object) => Ok(Some(object)),
			None => {
				Ok(actor_node.find_object(index, 100, true).await)
			}
		}
	}

	async fn fetch_objects(&self,
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

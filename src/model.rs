use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{common::*, identity::*};


pub const ACTOR_TYPE_FEED: &str = "feed";
pub const ACTOR_TYPE_SITE: &str = "website";


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActorInfo {
	pub public_key: PublicKey,
	pub first_object: IdType,
	pub actor_type: String,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Block {
	pub hash: IdType,
	pub data: Arc<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BoostObject {
	pub post_actor_id: IdType,
	pub object_sequence: u64,
}

#[derive(Default)]
pub struct FileData {
	pub mime_type: String,
	pub data: Vec<u8>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct File {
	pub mime_type: String,
	pub blocks: Vec<IdType>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileHeader {
	pub hash: IdType,
	pub mime_type: String,
	pub block_count: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MoveObject {
	pub new_actor_id: IdType,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PostObject {
	/// If this post is a reply, a tuple of the actor's ID and the post.
	pub in_reply_to: Option<(IdType, IdType)>,
	/// Searchable keywords
	pub tags: Vec<String>,
	/// A list of (mime-type, hash) tuples.
	pub files: Vec<IdType>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PostObjectInfo {
	base: PostObject,
	in_reply_to: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProfileObject {
	pub name: String,
	pub avatar: Option<IdType>,
	pub wallpaper: Option<IdType>,
	pub description: Option<IdType>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Object {
	pub signature: Signature,
	pub sequence: u64,
	pub previous_hash: IdType,
	pub created: u64,
	pub payload: ObjectPayload,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObjectSignData<'a> {
	pub sequence: u64,
	pub previous_hash: IdType,
	pub created: u64,
	pub payload: &'a ObjectPayload,
}

pub const OBJECT_TYPE_POST: u8 = 0;
pub const OBJECT_TYPE_BOOST: u8 = 1;
pub const OBJECT_TYPE_PROFILE: u8 = 2;
pub const OBJECT_TYPE_MOVE: u8 = 3;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ObjectPayload {
	Post(PostObject),
	Boost(BoostObject),
	Profile(ProfileObject),
	Move(MoveObject),
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ObjectHeader {
	pub index: u64,
	pub signature: Signature,
}

impl ObjectPayload {
	pub fn type_id(&self) -> u8 {
		match self {
			Self::Post(_) => 0,
			Self::Boost(_) => 1,
			Self::Profile(_) => 2,
			Self::Move(_) => 3,
		}
	}
}

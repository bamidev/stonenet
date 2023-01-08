use super::{
	common::*,
	identity::*
};

use serde::{Deserialize, Serialize};


#[derive(Clone, Deserialize, Serialize)]
pub struct BoostObject {
	pub post_actor_id: IdType,
	pub post_index: u64
}

#[derive(Clone, Deserialize, Serialize)]
pub struct FileHeader {
	pub hash: IdType,
	pub mime_type: String
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MoveObject {
	pub new_actor_id: IdType
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PostObject {
	/// If this post is a reply, a tuple of the actor's ID and the post.
	pub in_reply_to: Option<(IdType, u64)>,
	/// Searchable keywords
	pub tags: Vec<String>,
	/// A list of (mime-type, hash) tuples.
	pub files: Vec<FileHeader>
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ProfileObject {
	pub avatar: FileHeader,
	pub wallpaper: FileHeader,
	pub description_block_id: IdType
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Object {
	pub sequence: u64,
	pub signature: Signature,
	pub payload: ObjectPayload
}

pub const OBJECT_TYPE_POST: u8 = 0;
pub const OBJECT_TYPE_BOOST: u8 = 1;
pub const OBJECT_TYPE_PROFILE: u8 = 2;
pub const OBJECT_TYPE_MOVE: u8 = 3;

#[derive(Clone, Deserialize, Serialize)]
pub enum ObjectPayload {
	Post(PostObject),
	Boost(BoostObject),
	Profile(ProfileObject),
	Move(MoveObject)
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ObjectHeader {
	pub index: u64,
	pub signature: Signature
}

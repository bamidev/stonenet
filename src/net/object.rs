use crate::{
    common::*,
    identity::*
};

use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct BoostObject {
    actor_id: IdType,
    post_id: IdType
}

/// A post conveys a message and/or data.
/// A lot of times a post is just a simple text message. Such a post would
/// be a single file post with a single block. A text message with attachments
/// would have its atta
#[derive(Serialize, Deserialize)]
pub struct Object {
    pub header: ObjectHeader,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize)]
pub struct ObjectHeader {
    pub index: u64,
    pub type_: ObjectType,
    pub hash: IdType,
    pub timestamp: u64
}

#[derive(Serialize, Deserialize)]
pub enum ObjectType {
    /// A post that describes a message or has some sort of payload
    Post,
    /// Remove an exising post
    Undo,
    /// Reshare another's post on your own timeline.
    Boost,
    /// Changes information on the profile
    UpdateProfile,
    /// A post that provides a new actor address to follow instead of the old one
    Move
}

#[derive(Serialize, Deserialize)]
pub struct PostObject {
    /// List of hashes of each file
    files: Vec<IdType>,
    /// The list of hashes of all the blocks of the first file
    first_file_blocks: Vec<IdType>
}
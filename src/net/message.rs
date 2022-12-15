use super::{
    object::*
};

use crate::{
    common::*,
    identity::*,
    net::NodeContactInfo
};

use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
pub struct DownloadBlockRequest {
    post_number: u64,
    file_id: IdType,
    block_id: IdType
}

#[derive(Serialize, Deserialize)]
pub struct PingRequest {}

#[derive(Serialize, Deserialize)]
pub struct PingResponse {
}

#[derive(Serialize, Deserialize)]
pub struct FindNodeRequest {
    pub node_id: IdType
}

#[derive(Serialize, Deserialize)]
pub struct FindNodeResponse {
    /// A list of contact information to other peers.
    pub fingers: Vec<NodeContactInfo>,
    /// A list of actor networks that this node is connected to.
    pub follows: Vec<IdType>
}

pub type FindActorRequest = FindNodeRequest;

#[derive(Serialize, Deserialize)]
pub struct FindActorResult {
    /// The public key of the actor. The hash of this is the ID of the actor.
    pub public_key: PublicKey,
    /// Whether the responding peer is also on the actor's network
    pub i_am_available: bool,
    /// A list of known nodes that are connected to it.
    pub peers: Vec<NodeContactInfo>
}

#[derive(Serialize, Deserialize)]
pub struct FindActorResponse {
    pub result: Result<FindActorResult, Vec<NodeContactInfo>>
}

#[derive(Serialize, Deserialize)]
pub struct StoreActorRequest {
    pub actor_id: IdType,
    pub public_key: PublicKey,
    pub i_am_available: bool,
    pub nodes: Vec<NodeContactInfo>
}

#[derive(Serialize, Deserialize)]
pub struct StoreActorResponse {}

pub struct FindSubNodeRequest {
    pub node_id: IdType,
    pub actor_id: IdType
}

pub struct FindSubNodeResponse {
    pub base: FindNodeResponse,
    pub last_object_index: u64
}

#[derive(Serialize, Deserialize)]
pub struct BroadcastPostRequest {
    /// The result of XOR-ing all the file hashes of this post. Also serves as
    /// an indicator of who should store it.
    pub hash: IdType,
    pub index: u64,
    /// A signature of all the data above
    pub signature: Signature,
    /// List of hashes of each file
    pub files: Vec<IdType>
}

#[derive(Serialize, Deserialize)]
pub struct BroadcastPostResponse {}

#[derive(Serialize, Deserialize)]
pub struct FindObjectRequest {
    pub index: u64
}

#[derive(Serialize, Deserialize)]
pub struct FindObjectResponse {
    pub result: Result<FindObjectResult, Vec<NodeContactInfo>>
}

#[derive(Serialize, Deserialize)]
pub struct FindObjectResult {
    pub header: ObjectHeader
}

pub enum FindObjectResponsePayload {
    Post(PostObject),
    Boost(BoostObject),
    Move(IdType)
}

#[derive(Serialize, Deserialize)]
pub struct FindFileRequest {
    pub hash: IdType,
}

#[derive(Serialize, Deserialize)]
pub struct FindFileResponse {
    pub result: Result<FindFileResult, Vec<NodeContactInfo>>
}

#[derive(Serialize, Deserialize)]
pub struct FindFileResult {
    pub mime_type: String,
    pub blocks: Vec<IdType>
}

#[derive(Serialize, Deserialize)]
pub struct FindBlockRequest {
    pub hash: IdType,
    /// If one or more parts are requested, the responding node will reply
    /// only with those parts. If left empty, the node will reply with all
    /// available parts.
    pub parts: Vec<u16>
}

#[derive(Serialize, Deserialize)]
pub struct FindBlockResponse {
    pub result: Result<FindBlockResult, Vec<NodeContactInfo>>
}

#[derive(Serialize, Deserialize)]
pub struct FindBlockResult {
    pub size: u64
}
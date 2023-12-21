use serde::{Deserialize, Serialize};

use crate::{common::*, model::*, net::*};


#[derive(Debug, Deserialize, Serialize)]
pub struct BroadcastNewObject {
	pub hash: IdType,
	pub object: Object,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeepAliveRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeepAliveResponse {
	pub ok: bool,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct PingRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct PingResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelFindValueRequest {
	pub target_node_info: NodeContactInfo,
	pub source_contact_info: ContactInfo,
	//pub proof_of_work: ProofOfWork
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelFindValueResponse<T> {
	pub result: Result<T, Vec<NodeContactInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindNodeRequest {
	pub node_id: IdType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindNodeResponse {
	pub connection: Option<NodeContactInfo>,
	/// A list of other nodes this node knows about. Are less likely to be still
	/// available.
	pub fingers: Vec<NodeContactInfo>,
	// A list of other nodes which this node knows about, but are either
	// unavailable through the normal internet protocols, or just 'private' and
	// don't wan't their IP address to be known. They are only accessible
	// through tunneling.
	//pub private: Vec<IdType>,
}

pub type FindActorRequest = FindNodeRequest;

#[derive(Debug, Deserialize, Serialize)]
pub struct FindActorResult {
	/// The public key of the actor. The hash of this is the ID of the actor.
	pub actor_info: ActorInfo,
	/// Whether the responding peer is also on the actor's network
	pub i_am_available: bool,
	/// A list of known nodes that are connected to it.
	pub peers: Vec<NodeContactInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindActorResponse {
	pub contacts: FindNodeResponse,
	pub result: Option<FindActorResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeadRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeadResponse {
	pub hash: IdType,
	pub object: Object,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreActorRequest {
	pub actor_id: IdType,
	pub actor_info: ActorInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreActorResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindObjectRequest {
	pub sequence: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindObjectResult {
	pub object: Object,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindNextObjectResult {
	pub hash: IdType,
	pub object: Object,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindNextObjectResponse {
	pub result: Result<FindNextObjectResult, Vec<NodeContactInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindObjectResponse {
	pub result: Result<FindObjectResult, Vec<NodeContactInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindFileResponse {
	pub result: Result<FindFileResult, Vec<NodeContactInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindFileResult {
	pub file: File,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindBlockResponse {
	pub result: Result<FindBlockResult, Vec<NodeContactInfo>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindBlockResult {
	pub data: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindValueRequest {
	pub id: IdType,
	pub value_type: u8,
}

/// A message that is sent to indicate that the sender has their object meta
/// store up to date up to this object.
#[derive(Debug, Serialize, Deserialize)]
pub struct ObjectStoreRequest {
	pub object: Object,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishObjectRequest {
	pub id: IdType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishObjectResponse {
	pub needed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileUploadMessage {
	pub mime_type: String,
	pub blocks: Vec<IdType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishObjectMessage {
	pub object: Object,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetProfileRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetProfileResponse {
	pub profile: Option<ProfileObject>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitiateConnectionMessage {}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitiateConnectionRequest {
	pub source_node_id: IdType,
	pub source_contact_option: ContactOption,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitiateConnectionResponse {
	pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayInitiateConnectionRequest {
	pub target: IdType,
	pub contact_option: ContactOption,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct RelayInitiateConnectionResponse {
	pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayRequest {
	pub target: IdType,
	pub message_type_id: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayResponse {
	pub ok: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ValueType {
	Block      = 0,
	File       = 1,
	Object     = 2,
	NextObject = 3,
}

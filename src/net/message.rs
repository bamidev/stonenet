use serde::{Deserialize, Serialize};

use self::sstp::server::RelayedHelloPacket;
use crate::{
	common::*,
	core::*,
	net::{
		sstp::server::{RelayHelloAckPacket, RelayHelloPacket},
		*,
	},
};


#[derive(Debug, Deserialize, Serialize)]
pub struct GetAssistantNodeResponse {
	pub node_info: Option<NodeContactInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BroadcastNewObject {
	pub hash: IdType,
	pub object: BlogchainObject,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeepAliveRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeepAliveResponse {
	pub ok: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListActorsRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListActorsResponse {
	address: NodeAddress,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListFriendsRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListFriendsResponse {
	address: NodeAddress,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PingRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct PingResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReverseConnectionRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReverseConnectionResponse {
	pub ok: bool,
}

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
	pub is_relay_node: bool,
	pub connected: Vec<NodeContactInfo>,
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
	pub object: BlogchainObject,
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
	pub object: BlogchainObject,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindNextObjectResult {
	pub hash: IdType,
	pub object: BlogchainObject,
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
	pub object: BlogchainObject,
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
	pub object: BlogchainObject,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetProfileRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetProfileResponse {
	pub object: Option<(IdType, BlogchainObject)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitiateConnectionMessage {}

#[derive(Debug, Serialize, Deserialize)]
pub struct PunchHoleRequest {
	pub source_node_id: IdType,
	pub source_contact_option: ContactOption,
	pub request_connection: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PunchHoleResponse {
	pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PassPunchHoleRequest {
	pub target: IdType,
	pub contact_option: ContactOption,
	pub request_connection: bool,
}


#[derive(Serialize, Deserialize)]
pub struct PassPunchHoleResponse {
	pub ok: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RelayRequestRequest {
	pub relay_node_contact: ContactOption,
	pub relayed_hello_packet: RelayedHelloPacket,
}

#[derive(Serialize, Deserialize)]
pub struct PassRelayRequestRequest {
	pub target_node_id: IdType,
	pub base: RelayRequestRequest,
}

#[derive(Serialize, Deserialize)]
pub struct PassRelayRequestResponse {
	pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenRelayRequest {
	pub target_node_id: IdType,
	pub protocol: LinkProtocol,
	pub assistant_node: NodeContactInfo,
	pub hello_packet: RelayHelloPacket,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenRelayResponse {
	pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenRelayStatusMessage {
	pub status: OpenRelayStatus<RelayHelloAckPacket>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OpenRelayStatus<T> {
	Success(T),
	/// The assistant node is unaware of the target node
	AssistantUnaware,
	/// The target node never contacted the relay node
	Timeout,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StartRelayRequest {
	pub origin: NodeContactInfo,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StartRelayResponse {
	pub ok: bool,
}


#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ValueType {
	Block      = 0,
	File       = 1,
	Object     = 2,
	NextObject = 3,
}

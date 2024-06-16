use serde::{Deserialize, Serialize};

use self::sstp::server::RelayedHelloPacket;
use crate::{
	common::*,
	core::*,
	net::{
		sstp::server::{RelayHelloAckPacket, RelayHelloPacket},
		*,
	},
	serde_limit::*,
};


pub type FindActorRequest = FindNodeRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct FindActorResponse {
	pub contacts: FindNodeResponse,
	pub result: Option<FindActorResult>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindActorResult {
	/// The public key of the actor. The hash of this is the ID of the actor.
	pub actor_info: ActorInfo,
	/// Whether the responding peer is also on the actor's network
	pub i_am_available: bool,
	/// A list of known nodes that are connected to it.
	pub peers: LimVec<NodeContactInfo, Limit4>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindBlockResult {
	pub data: LimVec<u8, Limit10M>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindFileResult {
	pub file: File,
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
pub struct FindNodeRequest {
	pub node_id: IdType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindNodeResponse {
	pub is_relay_node: bool,
	pub connected: LimVec<NodeContactInfo, Limit10K>,
	/// A list of other nodes this node knows about. Are less likely to be still
	/// available.
	pub fingers: LimVec<NodeContactInfo, Limit256>,
	// A list of other nodes which this node knows about, but are either
	// unavailable through the normal internet protocols, or just 'private' and
	// don't wan't their IP address to be known. They are only accessible
	// through tunneling.
	//pub private: Vec<IdType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileUploadMessage {
	pub mime_type: LimString<LimitMimeType>,
	pub blocks: LimVec<IdType, Limit10K>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindValueRequest {
	pub id: IdType,
	pub value_type: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetProfileRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetProfileResponse {
	pub object: Option<(IdType, BlogchainObject)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeadRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct HeadResponse {
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
pub struct ListTrustedNodesRequest {
	pub recursion_level: u8,
	pub checksum: Option<IdType>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListTrustedNodesResponse {
	pub result: ListTrustedNodesResult,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ListTrustedNodesResult {
	None,
	ValidChecksum,
	List(LimVec<(NodeAddress, u8), Limit1M>),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenRelayRequest {
	pub target_node_id: NodeAddress,
	pub protocol: LinkProtocol,
	pub assistant_node: NodeContactInfo,
	pub hello_packet: RelayHelloPacket,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenRelayResponse {
	pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OpenRelayStatus<T> {
	Success(T),
	/// The assistant node is unaware of the target node
	AssistantUnaware,
	/// The target node never contacted the relay node
	Timeout,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenRelayStatusMessage {
	pub status: OpenRelayStatus<RelayHelloAckPacket>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PassPunchHoleRequest {
	pub target: NodeAddress,
	pub contact_option: ContactOption,
	pub request_connection: bool,
}

#[derive(Serialize, Deserialize)]
pub struct PassPunchHoleResponse {
	pub ok: bool,
}

#[derive(Serialize, Deserialize)]
pub struct PassRelayRequestRequest {
	pub target_node_id: NodeAddress,
	pub base: RelayRequestRequest,
}

#[derive(Serialize, Deserialize)]
pub struct PassRelayRequestResponse {
	pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PingRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct PingResponse {}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishObjectRequest {
	pub id: IdType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishObjectResponse {
	pub needed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishObjectMessage {
	pub object: BlogchainObject,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PunchHoleRequest {
	pub source_node_id: NodeAddress,
	pub source_contact_option: ContactOption,
	pub request_connection: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PunchHoleResponse {
	pub ok: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RelayRequestRequest {
	pub relay_node_contact: ContactOption,
	pub relayed_hello_packet: RelayedHelloPacket,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReverseConnectionRequest {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReverseConnectionResponse {
	pub ok: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StartRelayRequest {
	pub origin: NodeContactInfo,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StartRelayResponse {
	pub ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreActorRequest {
	pub actor_id: IdType,
	pub actor_info: ActorInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreActorResponse {}


#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum BlogchainValueType {
	Block      = 0,
	File       = 1,
	Object     = 2,
	NextObject = 3,
}

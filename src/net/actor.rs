use super::{
	*,
	message::*,
	socket::*,
	sstp::*,
};

use crate::{
	common::*,
	identity::*,
	model::*
};

use std::{
	io,
	net::SocketAddr
};

use async_trait::async_trait;


pub const ACTOR_MESSAGE_TYPE_ID_BROADCAST_OBJECT_REQUEST: u8 = 4;
pub const ACTOR_MESSAGE_TYPE_ID_BROADCAST_OBJECT_RESPONSE: u8 = 5;
pub const ACTOR_MESSAGE_TYPE_ID_HEAD_REQUEST: u8 = 6;
pub const ACTOR_MESSAGE_TYPE_ID_HEAD_RESPONSE: u8 = 7;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_OBJECT_REQUEST: u8 = 8;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_OBJECT_RESPONSE: u8 = 9;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_FILE_REQUEST: u8 = 10;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_FILE_RESPONSE: u8 = 11;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_BLOCK_REQUEST: u8 = 12;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_BLOCK_RESPONSE: u8 = 13;


pub struct ActorNode {
	pub(super) base: Node<ActorInterface>
}

pub struct ActorInterface {
	socket: SstpSocket<UdpSocket>,
	node_id: IdType,
	keypair: Keypair,
	actor_id: IdType,
	is_lurker: bool
}


#[async_trait]
impl NodeInterface for ActorInterface {

	async fn connect(&self,
		target: &SocketAddr,
		node_id: Option<&IdType>
	) -> io::Result<Connection<UdpSocket>> {
		self.socket.connect(target.clone(), node_id).await
	}

	async fn exchange(&self,
		connection: &mut Connection<UdpSocket>,
		mut message_type_id: u8,
		buffer: &[u8]
	) -> io::Result<Vec<u8>> {
		message_type_id &= 0x80;
		
		// Send request
		let mut real_buffer = Vec::with_capacity(33 + buffer.len());
		real_buffer[0] = message_type_id;
		real_buffer[1..33].copy_from_slice(self.actor_id.as_bytes());
		real_buffer[33..].copy_from_slice(self.actor_id.as_bytes());
		real_buffer.extend(buffer);
		connection.send(
			&real_buffer
		).await?;

		// Receive response
		let mut response = connection.receive().await?;
		if response[0] != (message_type_id + 1) {
			return Err(Error::InvalidResponseMessageType((
				response[0],
				message_type_id + 1
			)).into());
		}
		response.remove(0);
		return Ok(response)
	}

	async fn respond(&self,
		message_type_id: u8,
		buffer: &[u8]
	) -> Vec<u8> {
		let mut real_buffer = Vec::with_capacity(1 + buffer.len());
		real_buffer[0] = message_type_id & 0x80;
		real_buffer.extend(buffer);
		real_buffer
	}
}

impl ActorNode {

	/*pub async fn find_block(&self,
		id: &IdType,
		hop_limit: usize,
		only_narrow_down: bool
	) -> Option<FindActorResult> {
		let fingers = self.base.find_nearest_fingers(id).await;
		if fingers.len() == 0 { return None; }
		
		let result = self.base.find_value_from_fingers(
			id,
			ACTOR_MESSAGE_TYPE_ID_FIND_BLOCK_REQUEST,
			&fingers,
			hop_limit, 
			only_narrow_down,
			|_, _, _| true
		).await;
		
		match result {
			None => None,
			Some(buffer) => Some(
				bincode::deserialize(&buffer).expect("error not properly handled")
			)
		}
	}

	pub async fn find_file(&self,
		id: &IdType,
		hop_limit: usize,
		only_narrow_down: bool
	) -> Option<FindActorResult> {
		let fingers = self.base.find_nearest_fingers(id).await;
		if fingers.len() == 0 { return None; }
		
		let result = self.base.find_value_from_fingers(
			id,
			ACTOR_MESSAGE_TYPE_ID_FIND_FILE_REQUEST,
			&fingers,
			hop_limit, 
			only_narrow_down,
			|_, _, _| true
		).await;
		
		match result {
			None => None,
			Some(buffer) => Some(
				bincode::deserialize(&buffer).expect("error not properly handled")
			)
		}
	}*/

	pub async fn find_object(&self,
		index: u64,
		hop_limit: usize,
		only_narrow_down: bool
	) -> Option<Object> {
		fn parse_object(_id: &IdType, _peer: &NodeContactInfo, data: &[u8]) -> Option<AtomicPtr<()>> {
			match bincode::deserialize::<FindObjectResult>(&data) {
				Err(_) => None,
				Ok(result) => {
					let box_ = Box::new(result);
					Some(AtomicPtr::new(Box::into_raw(box_) as _))
				}
			}
		}

		let pseudo_id = IdType::new_pseudo(index);
		let fingers = self.base.find_nearest_fingers(&pseudo_id).await;
		if fingers.len() == 0 { return None; }
		
		// TODO: Make it so that the requests are being sent with an 8 byte id,
		// instead of 32 bytes.
		let result = self.base.find_value_from_fingers(
			&pseudo_id,
			ACTOR_MESSAGE_TYPE_ID_FIND_OBJECT_REQUEST,
			&fingers,
			hop_limit, 
			only_narrow_down,
			parse_object
		).await;
		
		result.map(|p| {
			let object_result: Box<FindObjectResult> = unsafe { Box::from_raw(p.into_inner() as *mut FindObjectResult) };
			object_result.object
		})
	}

	pub async fn fetch_head(&self) -> Option<u64> {
		let mut iter = self.base.iter_all_fingers();
		while let Some(contact) = iter.next().await {
			match self.request_head(&contact.address).await {
				Err(_) => {},
				Ok(index) => return Some(index)
			}
		}
		None
	}

	pub(super) fn new_lurker(
		socket: SstpSocket<UdpSocket>,
		actor_id: IdType
	) -> Self {
		let keypair = Keypair::generate();
		let public_key = keypair.public();
		let address = public_key.generate_address();
		
		let interface = ActorInterface {
			socket,
			node_id: address.clone(),
			keypair,
			actor_id,
			is_lurker: true
		};
		Self {
			base: Node::new(address, interface)
		}
	}

	pub async fn request_head(&self, target: &SocketAddr) -> io::Result<u64> {
		let (_, response) = self.base.exchange(
			target,
			ACTOR_MESSAGE_TYPE_ID_HEAD_REQUEST,
			&[]
		).await?;
		bincode::deserialize(&response).map_err(|e| io::Error::new(
			io::ErrorKind::InvalidData,
			e
		))
	}
}

use super::{
    *,
};

use crate::common::*;

use std::{
    io,
    net::SocketAddr
};

use async_trait::async_trait;


pub const ACTOR_MESSAGE_TYPE_ID_BROADCAST_POST_REQUEST: u8 = 4;
pub const ACTOR_MESSAGE_TYPE_ID_BROADCAST_POST_RESPONSE: u8 = 5;
pub const ACTOR_MESSAGE_TYPE_ID_LATEST_OBJECT_REQUEST: u8 = 6;
pub const ACTOR_MESSAGE_TYPE_ID_LATEST_OBJECT_RESPONSE: u8 = 7;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_OBJECT_REQUEST: u8 = 8;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_OBJECT_RESPONSE: u8 = 9;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_FILE_REQUEST: u8 = 10;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_FILE_RESPONSE: u8 = 11;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_BLOCK_REQUEST: u8 = 12;
pub const ACTOR_MESSAGE_TYPE_ID_FIND_BLOCK_RESPONSE: u8 = 13;


pub struct ActorNode {
    base: Arc<Node<ActorInterface>>
}

pub struct ActorInterface {
    exch: Arc<ExchangeManager>,
    node_id: IdType,
    pub actor_id: IdType
}


#[async_trait]
impl NodeInterface for ActorInterface {

    async fn request(&self,
        target: &SocketAddr,
        message_type_id: u8,
        buffer: &[u8]
    ) -> io::Result<(IdType, Vec<u8>)> {
        let mut actual_buffer = vec![0u8; 32 + buffer.len()];
        actual_buffer[..32].clone_from_slice(&bincode::serialize(&self.actor_id).unwrap());
        actual_buffer[32..].clone_from_slice(buffer);
        self.exch.request(
            &self.node_id,
            target,
            message_type_id + 0x80,
            &actual_buffer,
            Some(NODE_COMMUNICATION_TIMEOUT)
        ).await
    }

    async fn respond(&self,
        target: &SocketAddr,
        message_type_id: u8,
        exchange_id: u32,
        buffer: &[u8]
    ) -> io::Result<()> {
        let mut actual_buffer = vec![0u8; 32 + buffer.len()];
        actual_buffer[..32].clone_from_slice(&bincode::serialize(&self.actor_id).unwrap());
        actual_buffer[32..].clone_from_slice(buffer);
        self.exch.send_message(
            &self.node_id,
            target,
            message_type_id + 0x80,
            exchange_id,
            &actual_buffer
        ).await
    }
}

impl ActorNode {

	pub async fn find_block(&self,
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
			|_, _| true
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
			|_, _| true
		).await;
		
		match result {
			None => None,
			Some(buffer) => Some(
				bincode::deserialize(&buffer).expect("error not properly handled")
			)
		}
	}

	pub async fn find_object(&self,
		id: &IdType,
		hop_limit: usize,
		only_narrow_down: bool
	) -> Option<FindObjectResult> {
		let fingers = self.base.find_nearest_fingers(id).await;
		if fingers.len() == 0 { return None; }
		
		let result = self.base.find_value_from_fingers(
			id,
			ACTOR_MESSAGE_TYPE_ID_FIND_OBJECT_REQUEST,
			&fingers,
			hop_limit, 
			only_narrow_down,
			|_, _| true
		).await;
		
		match result {
			None => None,
			Some(buffer) => Some(
				bincode::deserialize(&buffer).expect("error not properly handled")
			)
		}
	}
}

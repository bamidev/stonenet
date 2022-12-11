use super::{
    *,
};

use crate::common::*;

use std::{
    io,
    net::SocketAddr
};

use async_trait::async_trait;


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
use super::{
	NodeContactInfo
};

use crate::{
	common::*,
	identity::*,
	limited_store::*
};

use std::{
	collections::HashMap
};

use lazy_static::lazy_static;
use tokio::sync::Mutex;


pub type ActorStore = LimitedMap<IdType, ActorStoreEntry>;

pub struct ActorStoreEntry {
	pub public_key: PublicKey,
	pub available_nodes: LimitedVec<NodeContactInfo>
}


const ACTOR_STORE_CAPACITY: usize = 1000;
const ACTOR_STORE_AVAILABLE_NODES_CAPACITY: usize = 10;


lazy_static! {
	pub static ref NODE_ACTOR_STORE: Mutex<ActorStore> = Mutex::new(ActorStore::new(ACTOR_STORE_CAPACITY));
	pub static ref FOLLOW_ACTOR_STORE: Mutex<HashMap<IdType, Identity>> = Mutex::new(HashMap::new());
}


impl ActorStoreEntry {
	pub fn add_available_node(&mut self, contact: NodeContactInfo) {
		self.available_nodes.push_back(contact);
	}

	pub fn new_with_contact(
		public_key: PublicKey,
		contact: NodeContactInfo
	) -> Self {
		let mut this = Self {
			public_key,
			available_nodes: LimitedVec::new(
				ACTOR_STORE_AVAILABLE_NODES_CAPACITY
			)
		};
		this.add_available_node(contact);
		this
	}
}

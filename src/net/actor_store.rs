use lazy_static::lazy_static;
use tokio::sync::Mutex;

use super::NodeContactInfo;
use crate::{common::*, core::*, limited_store::*};

pub type ActorStore = LimitedMap<IdType, ActorStoreEntry>;

pub struct ActorStoreEntry {
	pub actor_info: ActorInfo,
	pub available_nodes: LimitedVec<NodeContactInfo>,
}

const ACTOR_STORE_CAPACITY: usize = 1000;
const ACTOR_STORE_AVAILABLE_NODES_CAPACITY: usize = 10;

lazy_static! {
	// TODO: Put this variable inside the overlay node
	pub static ref NODE_ACTOR_STORE: Mutex<ActorStore> =
		Mutex::new(ActorStore::new(ACTOR_STORE_CAPACITY));
}

impl ActorStoreEntry {
	pub fn add_available_node(&mut self, contact: NodeContactInfo) {
		if self
			.available_nodes
			.iter()
			.find(|c| &contact.address == &c.address)
			.is_none()
		{
			self.available_nodes.push_back(contact);
		}
	}

	pub fn new_with_contact(actor_info: ActorInfo, contact: NodeContactInfo) -> Self {
		let mut this = Self {
			actor_info,
			available_nodes: LimitedVec::new(ACTOR_STORE_AVAILABLE_NODES_CAPACITY),
		};
		this.add_available_node(contact);
		this
	}
}

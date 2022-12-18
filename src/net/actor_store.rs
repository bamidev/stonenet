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
	pub i_am_available: bool,
	pub available_nodes: LimitedVec<NodeContactInfo>
}


lazy_static! {
	pub static ref NODE_ACTOR_STORE: Mutex<ActorStore> = Mutex::new(ActorStore::new(10));
	pub static ref FOLLOW_ACTOR_STORE: Mutex<HashMap<IdType, Identity>> = Mutex::new(HashMap::new());
}


impl ActorStore {
	pub fn store_personal(&mut self, actor_id: &IdType, public_key: &PublicKey) {
		match self.find_mut(actor_id) {
			None => self.insert(actor_id.clone(), ActorStoreEntry {
				public_key: public_key.clone(),
				i_am_available: true,
				available_nodes: LimitedVec::new(10)
			}),
			Some(mut entry) => {
				entry.i_am_available = true;
			}
		}
	}
}
use super::{
    NodeContactInfo
};

use crate::{
    common::*,
    identity::*,
    limited_store::*
};

use std::{
    collections::HashMap,
    sync::Mutex
};

use lazy_static::lazy_static;


pub type ActorStore = LimitedMap<IdType, ActorStoreEntry>;

pub struct ActorStoreEntry {
    pub public_key: PublicKey,
    pub available_nodes: LimitedVec<NodeContactInfo>
}


lazy_static! {
    pub static ref NODE_ACTOR_STORE: Mutex<ActorStore> = Mutex::new(ActorStore::new(0));
    pub static ref FOLLOW_ACTOR_STORE: Mutex<HashMap<IdType, Identity>> = Mutex::new(HashMap::new());
}
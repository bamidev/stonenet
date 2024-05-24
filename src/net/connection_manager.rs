use std::{collections::HashMap, sync::Arc};

use super::{sstp::Connection, NodeContactInfo};
use crate::{
	common::*,
	trace::{Mutex, MutexGuard},
};


/// The ConnectionManager keeps alive a number of connections.
/// When you add a new connection, it will only be added if there is room, or if
/// there was a previous connection with a node ID that is 'further away' than
/// the new connection's node ID.
pub struct ConnectionManager {
	center: IdType,
	map: Mutex<HashMap<IdType, ConnectionManagerEntry>>,
	limit: usize,
}

/// Holds a lock on the internal map of the `ConnectionManager`, and allows you
/// to insert a connection into it.
pub struct ConnectionSpace<'a> {
	node_info: NodeContactInfo,
	guard: MutexGuard<'a, HashMap<IdType, ConnectionManagerEntry>>,
	to_remove: Option<IdType>,
}

pub type ConnectionManagerEntry = (NodeContactInfo, Arc<Mutex<Box<Connection>>>);


impl ConnectionManager {
	pub async fn connections(&self) -> Vec<Arc<Mutex<Box<Connection>>>> {
		self.map
			.lock()
			.await
			.values()
			.map(|(_, c)| c.clone())
			.collect()
	}

	/// Checks whether there is space for a new connection in the manager,
	pub async fn find_space<'a>(
		&'a self, node_info: &NodeContactInfo,
	) -> Option<ConnectionSpace<'a>> {
		let map = self.map.lock().await;
		if map.len() < self.limit {
			Some(ConnectionSpace {
				node_info: node_info.clone(),
				guard: map,
				to_remove: None,
			})
		} else {
			// Remove a connection if it is further away.
			let mut highest_distance = node_info.node_id.distance(&self.center);
			let mut remove_node_id = None;
			for id in map.keys() {
				let this_distance = id.distance(&self.center);
				if this_distance > highest_distance {
					highest_distance = this_distance;
					remove_node_id = Some(id.clone());
				}
			}
			if let Some(id) = remove_node_id {
				Some(ConnectionSpace {
					node_info: node_info.clone(),
					guard: map,
					to_remove: Some(id),
				})
			} else {
				None
			}
		}
	}

	pub async fn find(&self, target: &IdType) -> Option<ConnectionManagerEntry> {
		match self.center.differs_at_bit(target) {
			None => None,
			Some(bit) => self.find_near(bit).await,
		}
	}

	pub async fn find_near(&self, bit: u8) -> Option<ConnectionManagerEntry> {
		let map = self.map.lock().await;
		for (node_id, (node_info, c)) in map.iter() {
			let is_near = match self.center.differs_at_bit(node_id) {
				None => true,
				Some(b) => b >= bit,
			};
			if is_near {
				return Some((node_info.clone(), c.clone()));
			}
		}
		None
	}

	pub fn new(center: IdType, limit: usize) -> Self {
		Self {
			center,
			map: Mutex::new(HashMap::new()),
			limit,
		}
	}

	pub async fn remove(&self, node_id: &IdType) -> bool {
		self.map.lock().await.remove(node_id).is_some()
	}
}

impl<'a> ConnectionSpace<'a> {
	/// Puts the given connection in place, and returns the node ID of the
	/// connection that has been removed.
	pub fn put(mut self, connection: Arc<Mutex<Box<Connection>>>) -> Option<IdType> {
		if let Some(to_remove) = &self.to_remove {
			let _removed = self.guard.remove(to_remove);
			debug_assert!(_removed.is_some(), "nothing was removed");
		}

		let Self {
			mut guard,
			node_info,
			to_remove,
		} = self;
		guard.insert(node_info.node_id.clone(), (node_info, connection));
		to_remove
	}
}

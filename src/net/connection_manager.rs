use std::{collections::HashMap, sync::Arc};

use super::{sstp::Connection, NodeContactInfo};
use crate::{
	common::*,
	core::NodeAddress,
	trace::{Mutex, MutexGuard},
};

/// The ConnectionManager keeps alive a number of connections.
/// When you add a new connection, it will only be added if there is room, or if
/// there was a previous connection with a node ID that is 'further away' than
/// the new connection's node ID.
pub struct ConnectionManager {
	center: IdType,
	map: Mutex<HashMap<NodeAddress, ConnectionManagerEntry>>,
	limit: usize,
}

/// Holds a lock on the internal map of the `ConnectionManager`, and allows you
/// to insert a connection into it.
pub struct ConnectionSpace<'a> {
	node_info: NodeContactInfo,
	guard: MutexGuard<'a, HashMap<NodeAddress, ConnectionManagerEntry>>,
	to_remove: Option<NodeAddress>,
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
			let mut highest_distance = node_info.address.as_id().as_ref().distance(&self.center);
			let mut remove_node_id = None;
			for id in map.keys() {
				let this_distance = id.as_id().as_ref().distance(&self.center);
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

	pub async fn find(&self, target: &NodeAddress) -> Option<ConnectionManagerEntry> {
		let map = self.map.lock().await;
		map.get(target).map(|x| x.clone())
	}

	pub fn new(center: IdType, limit: usize) -> Self {
		Self {
			center,
			map: Mutex::new(HashMap::new()),
			limit,
		}
	}

	pub async fn remove(&self, node_id: &NodeAddress) -> bool {
		self.map.lock().await.remove(node_id).is_some()
	}
}

impl<'a> ConnectionSpace<'a> {
	/// Puts the given connection in place, and returns the node ID of the
	/// connection that has been removed.
	pub fn put(mut self, connection: Arc<Mutex<Box<Connection>>>) -> Option<NodeAddress> {
		if let Some(to_remove) = &self.to_remove {
			let _removed = self.guard.remove(to_remove);
			debug_assert!(_removed.is_some(), "nothing was removed");
		}

		let Self {
			mut guard,
			node_info,
			to_remove,
		} = self;
		guard.insert(node_info.address.clone(), (node_info, connection));
		to_remove
	}
}

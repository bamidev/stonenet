use std::{collections::HashMap, sync::Arc};

use tokio::{spawn, sync::Mutex};

use super::sstp;
use crate::{common::*, net::*};


/// The ConnectionManager keeps alive a number of connections.
/// When you add a new connection, it will only be added if there is room, or if
/// there was a previous connection with a node ID that is 'further away' than
/// the new connection's node ID.
pub struct ConnectionManager {
	center: IdType,
	map: Mutex<HashMap<IdType, ConnectionManagerEntry>>,
	limit: usize,
}

pub type ConnectionManagerEntry = (NodeContactInfo, Arc<Mutex<Box<sstp::Connection>>>);


impl ConnectionManager {
	/// Tries to add a connection to the ConnectionManager.
	/// Returns true if it succeeded in doing that.
	pub async fn add(
		self: &Arc<Self>, node_info: &NodeContactInfo, connection: &Arc<Mutex<Box<Connection>>>,
	) -> bool {
		let mut map = self.map.lock().await;
		if map.len() < self.limit {
			map.insert(
				node_info.node_id.clone(),
				(node_info.clone(), connection.clone()),
			);
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
				map.remove(&id);
				map.insert(
					node_info.node_id.clone(),
					(node_info.clone(), connection.clone()),
				);
			} else {
				return false;
			}
		}

		// Turn the connection into a keep-alive connection, as soon as the lock on it
		// releases.
		let this = self.clone();
		let node_id2 = node_info.node_id.clone();
		let connection2 = connection.clone();
		/*spawn(async move {
			Connection::keep_alive(&connection2, move |_| {
				spawn(async move {
					this.map.lock().await.remove(&node_id2);
				});
			})
			.await;
		});*/
		true
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
}

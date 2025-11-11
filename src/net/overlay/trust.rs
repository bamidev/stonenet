use std::{sync::Arc, time::Duration};

use log::error;
use sea_orm::{prelude::*, ActiveValue::*, QueryOrder};
use tokio::{spawn, time::sleep};

use super::{
	current_timestamp, message::ListTrustedNodesResult, IdType, NodeAddress, NodeContactInfo,
	OverlayNode,
};
use crate::{
	db::{self, Database, PersistenceHandle},
	entity::*,
	net::binserde,
};

const WAIT_TIME: u64 = 23 * 60 * 60 * 1000;
pub const MAX_RECURSION_LEVEL: u8 = 10;

fn generate_hash(list: &[(NodeAddress, u8)]) -> IdType {
	let data = binserde::serialize(list).unwrap();
	IdType::hash(&data)
}

pub fn maintain_trust_web(node: Arc<OverlayNode>) {
	spawn(keep_updating_trust_web(node));
}

async fn keep_updating_trust_web(node: Arc<OverlayNode>) {
	while node.base.is_running() {
		if let Err(e) = update_node_trust_web(&node).await {
			error!("Database error while updating trust web: {}", e);
		}

		// FIXME: Sleep for a minute at the time
		sleep(Duration::from_millis(WAIT_TIME)).await;
	}
}

async fn recalculate_checksum(db: &Database, recursion_level: u8) -> db::Result<IdType> {
	let results = trusted_node_trust_item::Entity::find()
		.filter(trusted_node_trust_item::Column::RecursionLevel.eq(recursion_level))
		.order_by_asc(trusted_node_trust_item::Column::Id)
		.all(db.inner())
		.await?;
	let items: Vec<(NodeAddress, u8)> = results
		.into_iter()
		.map(|r| (r.address, r.recursion_level))
		.collect();
	let checksum_input = binserde::serialize(&items).unwrap();
	Ok(IdType::hash(&checksum_input))
}

async fn remember_trust_list_update(
	db: &Database, trusted_node_id: i64, recursion_level: u8, last_update_hash_opt: Option<IdType>,
	result: &[(NodeAddress, u8)],
) -> db::Result<()> {
	let new_hash = generate_hash(result);
	if let Some(last_update_hash) = &last_update_hash_opt {
		let mut updates = <trusted_node_update::ActiveModel as Default>::default();
		updates.timestamp = Set(current_timestamp() as i64);
		updates.checksum = Set(new_hash);
		trusted_node_update::Entity::update_many()
			.set(updates)
			.filter(trusted_node_update::Column::Checksum.eq(last_update_hash))
			.exec(db.inner())
			.await?;
	} else {
		let record = trusted_node_update::ActiveModel {
			id: NotSet,
			trusted_node_id: Set(trusted_node_id),
			recursion_level: Set(recursion_level),
			timestamp: Set(current_timestamp() as _),
			checksum: Set(new_hash),
		};
		trusted_node_update::Entity::insert(record)
			.exec(db.inner())
			.await?;
	}
	Ok(())
}

/// Checks with all trusted nodes if we have their trust list, or if their trust
/// lists were updated in the meantime
async fn update_node_trust_web(node: &Arc<OverlayNode>) -> db::Result<()> {
	let trusted_nodes = trusted_node::Entity::find().all(node.db().inner()).await?;
	for trusted_node in trusted_nodes {
		if let Some(contact_info) = node.find_node(&trusted_node.address).await {
			for recursion_level in 0..MAX_RECURSION_LEVEL {
				if !update_trusted_node_trust_list(
					&node,
					&trusted_node,
					&contact_info,
					recursion_level,
				)
				.await?
				{
					break;
				}
			}
		}
	}
	Ok(())
}

/// Replaces the whole trust list for a particular trusted node
async fn update_trust_list(
	node: &Arc<OverlayNode>, trusted_node_id: i64, recursion_level: u8,
	trust_list: &[(NodeAddress, u8)], trust_modifier: f32,
) -> db::Result<()> {
	debug_assert!(trust_modifier <= 1.0 && trust_modifier >= 0.0);

	// Clear the previous list
	trusted_node_trust_item::Entity::delete_many()
		.filter(trusted_node_trust_item::Column::TrustedNodeId.eq(trusted_node_id))
		.filter(trusted_node_trust_item::Column::RecursionLevel.eq(recursion_level))
		.exec(node.db().inner())
		.await?;

	// Insert new trust list
	for (address, score) in trust_list {
		let our_score = (*score as f32 * trust_modifier).round() as u8;
		let record = trusted_node_trust_item::ActiveModel {
			id: NotSet,
			trusted_node_id: Set(trusted_node_id),
			recursion_level: Set(recursion_level),
			address: Set(address.clone()),
			score: Set(*score),
			our_score: Set(our_score),
		};
		trusted_node_trust_item::Entity::insert(record)
			.exec(node.db().inner())
			.await?;
	}
	Ok(())
}

async fn update_trusted_node_trust_list(
	node: &Arc<OverlayNode>, trusted_node: &trusted_node::Model, contact_info: &NodeContactInfo,
	recursion_level: u8,
) -> db::Result<bool> {
	let last_update_hash_opt = if let Some(update) = trusted_node_update::Entity::find()
		.filter(trusted_node_update::Column::TrustedNodeId.eq(trusted_node.id))
		.filter(trusted_node_update::Column::RecursionLevel.eq(recursion_level))
		.one(node.db().inner())
		.await?
	{
		if (current_timestamp() - update.timestamp as u64)
			< (recursion_level as u64 + 1) * WAIT_TIME
		{
			return Ok(true);
		}
		Some(update.checksum)
	} else {
		None
	};

	if let Some(response) = node
		.exchange_trust_list(contact_info, recursion_level, last_update_hash_opt.clone())
		.await
	{
		let list = match response.result {
			ListTrustedNodesResult::None => return Ok(false),
			ListTrustedNodesResult::ValidChecksum => return Ok(true),
			ListTrustedNodesResult::List(l) => l,
		};

		// Only update trust list when we're actually behind
		let our_recursion_level = recursion_level + 1;
		let trust_modifier = trusted_node.score as f32 / 255f32;
		update_trust_list(
			node,
			trusted_node.id,
			our_recursion_level,
			&list,
			trust_modifier,
		)
		.await?;
		remember_trust_list_update(
			node.db(),
			trusted_node.id,
			our_recursion_level,
			last_update_hash_opt,
			&list,
		)
		.await?;
		recalculate_checksum(node.db(), our_recursion_level).await?;
	}
	Ok(true)
}

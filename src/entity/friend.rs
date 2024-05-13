//! A 'friend' is a node that the user has added to their 'friends list', which

use sea_orm::entity::prelude::*;

use crate::core::NodeAddress;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "friend")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	/// If the node is an 'indirect friend', this field is set.
	pub parent_id: Option<i64>,
	#[sea_orm(unique)]
	pub address: NodeAddress,
	#[sea_orm(unique)]
	pub label: String,
	pub last_seen_socket_address: String,
	/// Timestamp of the last moment that this node's actor list has been
	/// checked.
	pub last_actor_list_update: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

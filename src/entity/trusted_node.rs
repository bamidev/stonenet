//! A 'friend' is a node that the user has added to their 'friends list', which

use sea_orm::entity::prelude::*;

use crate::core::NodeAddress;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trusted_node")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	/// If the node is trusted indirectly, this field is set.
	pub parent_id: Option<i64>,
	#[sea_orm(unique)]
	pub address: NodeAddress,
	pub score: u8,
	pub last_seen_socket_address: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
	#[sea_orm(
		belongs_to = "super::trusted_node::Entity",
		from = "Column::ParentId",
		to = "super::trusted_node::Column::Id",
		on_update = "Cascade",
		on_delete = "Cascade"
	)]
	TrustedNode,
}

impl ActiveModelBehavior for ActiveModel {}

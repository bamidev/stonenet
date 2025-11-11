use sea_orm::entity::prelude::*;

use crate::common::IdType;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trusted_node_update")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	pub trusted_node_id: i64,
	pub recursion_level: u8,
	pub timestamp: i64,
	pub checksum: IdType,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
	#[sea_orm(
		belongs_to = "super::trusted_node::Entity",
		from = "Column::TrustedNodeId",
		to = "super::trusted_node::Column::Id",
		on_update = "Cascade",
		on_delete = "Cascade"
	)]
	TrustedNode,
}

impl ActiveModelBehavior for ActiveModel {}

use sea_orm::entity::prelude::*;

use crate::core::NodeAddress;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trusted_node_trust_item")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	pub trusted_node_id: i64,
	pub recursion_level: u8,
	pub address: NodeAddress,
	pub score: u8,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

use sea_orm::entity::prelude::*;

use crate::core::NodeAddress;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trusted_node")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	#[sea_orm(unique)]
	pub label: String,
	#[sea_orm(unique)]
	pub address: NodeAddress,
	pub score: u8,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

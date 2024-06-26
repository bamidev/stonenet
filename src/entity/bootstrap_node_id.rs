//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.15

use sea_orm::entity::prelude::*;

use crate::core::NodeAddress;


#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "bootstrap_node_id")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = false)]
	pub address: String,
	#[sea_orm(unique)]
	pub node_id: NodeAddress,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

use sea_orm::entity::prelude::*;

use crate::common::IdType;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "trust_list_checksum")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = false)]
	pub recursion_level: u8,
	pub checksum: IdType,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

//! A `file_block` describes a part of a file's meta data. Each entry in this
//! table is a hash of the list of blocks in a file.

use sea_orm::entity::prelude::*;

use crate::common::IdType;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "file_block")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	pub file_id: i64,
	pub block_hash: IdType,
	pub sequence: u32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
	#[sea_orm(
		belongs_to = "super::file::Entity",
		from = "Column::FileId",
		to = "super::file::Column::Id",
		on_update = "NoAction",
		on_delete = "NoAction"
	)]
	File,
}

impl Related<super::file::Entity> for Entity {
	fn to() -> RelationDef {
		Relation::File.def()
	}
}

impl ActiveModelBehavior for ActiveModel {}

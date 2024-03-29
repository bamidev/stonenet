//! `SeaORM` Entity. Generated by sea-orm-codegen 0.12.15

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "block")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	#[sea_orm(column_type = "Binary(BlobSize::Blob(None))", nullable, unique)]
	pub hash: Option<Vec<u8>>,
	pub size: i32,
	#[sea_orm(column_type = "Binary(BlobSize::Blob(None))")]
	pub data: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

//! A consolidated object can refer to any of the following objects:
//! * An object of a Stonenet blogchain
//! *

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "consolidated_object")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	pub batch: i64,
	pub r#type: u8,
	/// Refers to a record of one of the actor tables, depending on the type
	pub actor_id: i64,
	/// Refers to a record of one of the object tables, depending on the type
	pub object_id: i64,
	pub timestamp: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

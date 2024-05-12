use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "activity_pub_actor_inbox")]
pub struct Model {
	#[sea_orm(primary_key)]
	pub id: i64,
	pub host: String,
	pub path: String,
	pub inbox: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

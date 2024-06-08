use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "activity_pub_inbox_object")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	pub actor_id: i64,
	#[sea_orm(unique)]
	pub object_id: String,
	pub data: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
	#[sea_orm(
		belongs_to = "super::actor::Entity",
		from = "Column::ActorId",
		to = "super::actor::Column::Id"
	)]
	Actor,
}

impl ActiveModelBehavior for ActiveModel {}

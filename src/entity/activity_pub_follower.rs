use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "activity_pub_follower")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = true)]
	pub id: i64,
	pub actor_id: i64,
	pub host: String,
	pub path: String,
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

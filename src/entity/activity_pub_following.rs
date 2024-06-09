use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "activity_pub_following")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = false)]
	pub actor_id: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
	#[sea_orm(
		belongs_to = "super::activity_pub_actor::Entity",
		from = "Column::ActorId",
		to = "super::activity_pub_actor::Column::Id"
	)]
	Actor,
}

impl ActiveModelBehavior for ActiveModel {}

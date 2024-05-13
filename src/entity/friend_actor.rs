//! Each node publicizes a list of actors that they own. This model represents
//! that list.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "friend_actor")]
pub struct Model {
	#[sea_orm(primary_key, auto_increment = false)]
	pub actor_id: i64,
	pub friend_id: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
	#[sea_orm(
		belongs_to = "super::identity::Entity",
		from = "Column::ActorId",
		to = "super::identity::Column::Id",
		on_update = "NoAction",
		on_delete = "NoAction"
	)]
	Identity,
	#[sea_orm(
		belongs_to = "super::friend::Entity",
		from = "Column::FriendId",
		to = "super::friend::Column::Id",
		on_update = "NoAction",
		on_delete = "NoAction"
	)]
	Friend,
}

impl ActiveModelBehavior for ActiveModel {}

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "activity_pub_actor")]
pub struct Model {
	#[sea_orm(primary_key)]
	pub id: i64,
	pub host: String,
	pub path: String,
	pub address: Option<String>,
	pub name: Option<String>,
	pub inbox: Option<String>,
	pub outbox: Option<String>,
	pub icon_url: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

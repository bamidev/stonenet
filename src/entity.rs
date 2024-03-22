use sea_orm::entity::prelude::*;


#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "object2")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub hash: String,
    pub actor_id: i64,
    pub sequence: u64,
    pub previous_hash: Option<String>,
    pub created: u64,
    pub found: u64,
    pub type_: u8,
    pub signature: Vec<u8>,
    pub verified_from_start: bool
}
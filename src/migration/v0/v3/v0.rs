use async_trait::async_trait;
use sea_orm::{sea_query::*, *};

use crate::{
	db::{self, PersistenceHandle},
	migration::MigrationTrait,
};

mod entity;


pub struct Migration;


#[async_trait]
impl MigrationTrait for Migration {
	async fn run(&self, tx: &db::Transaction) -> db::Result<()> {
		let schema = Schema::new(tx.backend());

		// TODO: Add column published_on_fediverse on table object
        // TODO: Make column verified_from_start have the default value false
        // TODO: Create tables activity_pub_follow, activity_pub_object & activity_pub_send_queue.
		Ok(())
	}
}

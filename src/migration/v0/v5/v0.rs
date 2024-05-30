use async_trait::async_trait;
use sea_orm::*;

use crate::{
	db::{self, PersistenceHandle},
	migration::MigrationTrait,
};


pub struct Migration;


#[async_trait]
impl MigrationTrait for Migration {
	async fn run(&self, tx: &db::Transaction) -> db::Result<()> {
		tx.inner()
			.execute_unprepared(
				r#"
				CREATE TABLE "trusted_node" (
					"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
					"parent_id" integer,
					"address" blob NOT NULL UNIQUE,
					"score" integer NOT NULL,
					"last_seen_socket_address" text,
					FOREIGN KEY ("parent_id") REFERENCES "trusted_node" ("id") ON DELETE CASCADE ON UPDATE CASCADE
				)
		"#,
			)
			.await?;
		Ok(())
	}
}

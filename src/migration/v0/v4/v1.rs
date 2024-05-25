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
			ALTER TABLE block RENAME TO block_old;
			CREATE TABLE "block" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"hash" text(45) NOT NULL UNIQUE,
				"size" integer NOT NULL,
				"data" blob NOT NULL
			);
			INSERT INTO block (id, hash, size, data) SELECT id, hash, size, data FROM block_old;
			DROP TABLE "block_old";
		"#,
			)
			.await?;
		Ok(())
	}
}

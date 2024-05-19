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
		// Because files have changed, their hash has also changed, so all objects have
		// become invalid. For that reason, all data is now invalid.
		tx.inner()
			.execute_unprepared(
				r#"
			DROP TABLE block;
			CREATE TABLE "block" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"file_id" bigint NOT NULL,
				"hash" text(45) NOT NULL,
				"size" integer NOT NULL,
				"data" blob NOT NULL,
				UNIQUE(file_id, hash)
			);
				
			DELETE FROM file_blocks;
			
			DROP TABLE file;
			CREATE TABLE "file" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"hash" text(45) NOT NULL UNIQUE,
				"compression_type" integer NOT NULL,
				"mime_type" text NOT NULL,
				"block_count" integer NOT NULL,
				"plain_hash" text(45) NOT NULL
			);

			DELETE FROM object;
		"#,
			)
			.await?;
		Ok(())
	}
}

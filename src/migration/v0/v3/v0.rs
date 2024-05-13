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
			CREATE TABLE "activity_pub_actor_inbox" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"host" text NOT NULL,
				"path" text NOT NULL,
				"inbox" text NOT NULL,
				UNIQUE(host, path)
			);
			CREATE TABLE "activity_pub_follow" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"actor_id" bigint NOT NULL,
				"host" text NOT NULL,
				"path" text NOT NULL,
				UNIQUE(actor_id, host, path)
			);
			CREATE TABLE "activity_pub_object" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"actor_id" bigint NOT NULL,
				"data" text NOT NULL
			);
			CREATE TABLE "activity_pub_send_queue" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"actor_id" bigint NOT NULL,
				"recipient_server" text NOT NULL,
				"recipient_path" text,
				"object" text NOT NULL,
				"last_fail" bigint,
				"failures" integer NOT NULL
			);
			CREATE TABLE "activity_pub_shared_inbox" (
				"host" text NOT NULL PRIMARY KEY,
				"shared_inbox" text
			);

			-- Recreate the block table because the hash column had an invalid type
			ALTER TABLE "block" RENAME TO "block_old";
			CREATE TABLE "block" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"hash" text(45) NOT NULL UNIQUE,
				"size" integer NOT NULL,
				"data" blob NOT NULL
			);
			INSERT INTO "block" (hash, size, data)
			SELECT hash, size, data FROM "block";
			DROP TABLE "block_old";
			
			-- Recreate file_blocks, as the unique constraint on block_hash isn't needed
			ALTER TABLE "file_blocks" RENAME TO "file_blocks_old";
			CREATE TABLE "file_blocks" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"file_id" bigint NOT NULL,
				"block_hash" text NOT NULL,
				"sequence" integer NOT NULL,
				FOREIGN KEY ("file_id") REFERENCES "file" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
			INSERT INTO file_blocks (file_id, block_hash, sequence)
			SELECT file_id, block_hash, sequence FROM file_blocks_old;
			DROP TABLE file_blocks_old;

			-- Recreate post_files, as object_id can't be unique
			ALTER TABLE post_files RENAME TO post_files_old;
			CREATE TABLE "post_files" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"object_id" bigint NOT NULL,
				"hash" text NOT NULL,
				"sequence" integer NOT NULL,
				FOREIGN KEY ("object_id") REFERENCES "object" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
			INSERT INTO post_files (object_id, hash, sequence)
			SELECT object_id, hash, sequence FROM post_files;
			DROP TABLE post_files_old;

			-- Recreate post_tag, as object_id can't be unique
			ALTER TABLE post_tag RENAME TO post_tag_old;
			CREATE TABLE "post_tag" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"object_id" bigint NOT NULL,
				"tag" text NOT NULL,
				FOREIGN KEY ("object_id") REFERENCES "post_object" ("object_id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
			INSERT INTO post_tag (object_id, tag)
			SELECT object_id, tag FROM post_tag;
			DROP TABLE post_tag_old;

			-- Delete all duplicates in table "object"
			DELETE FROM object WHERE id NOT IN (
				SELECT MIN(id) FROM object GROUP BY actor_id, hash
			);
			ALTER TABLE object ADD COLUMN "published_on_fediverse" boolean NOT NULL DEFAULT FALSE;

			-- Create missing unique constraint/index
			CREATE UNIQUE INDEX uniq_object_hash ON object(actor_id, hash);
			CREATE UNIQUE INDEX uniq_post_files_sequence ON post_files(object_id, sequence);
			CREATE UNIQUE INDEX uniq_post_tag ON post_tag(object_id, tag);
		"#,
			)
			.await?;
		Ok(())
	}
}

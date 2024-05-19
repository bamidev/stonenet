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
		// become invalid. So event actor addresses are invalid now since they are based
		// on the actor info, which is based on the first object. For that reason, all
		// data is now invalid. That being said, I took the chance to rename and fix a
		// bunch of tables anyway.
		tx.inner()
			.execute_unprepared(
				r#"
			DROP TABLE block;
			DROP TABLE boost_object;
			DROP TABLE file_blocks;
			DROP TABLE file;
			DROP TABLE following;
			DROP TABLE identity;
			DROP TABLE object;
			DROP TABLE my_identity;
			DROP TABLE post_files;
			DROP TABLE post_object;
			DROP TABLE post_tag;
			DROP TABLE profile_object;

			CREATE TABLE "actor" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"address" blob NOT NULL UNIQUE,
				"public_key" blob NOT NULL,
				"first_object" text(45) NOT NULL,
				"type" text NOT NULL
			);
			CREATE TABLE "block" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"file_id" bigint NOT NULL,
				"hash" text(45) NOT NULL,
				"size" integer NOT NULL,
				"data" blob NOT NULL,
				UNIQUE(file_id, hash)
			);
			CREATE TABLE "file" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"hash" text(45) NOT NULL UNIQUE,
				"compression_type" integer NOT NULL,
				"mime_type" text NOT NULL,
				"block_count" integer NOT NULL,
				"plain_hash" text(45) NOT NULL
			);
			CREATE TABLE "file_blocks" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"file_id" bigint NOT NULL,
				"block_hash" text(45) NOT NULL,
				"sequence" integer NOT NULL,
				FOREIGN KEY ("file_id") REFERENCES "file" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
			CREATE TABLE "following" (
				"actor_id" bigint NOT NULL PRIMARY KEY,
				FOREIGN KEY ("actor_id") REFERENCES "actor" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
			CREATE TABLE "identity" (
				"label" text NOT NULL PRIMARY KEY,
				"actor_id" bigint NOT NULL UNIQUE,
				"private_key" blob NOT NULL,
				"is_private" boolean NOT NULL,
				FOREIGN KEY ("actor_id") REFERENCES "actor" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
			CREATE TABLE "object" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"actor_id" bigint NOT NULL,
				"hash" text(45) NOT NULL,
				"sequence" bigint NOT NULL,
				"previous_hash" text(45) NOT NULL,
				"created" bigint NOT NULL,
				"found" bigint NOT NULL,
				"type" integer NOT NULL,
				"signature" text(45) NOT NULL,
				"verified_from_start" boolean NOT NULL,
				"published_on_fediverse" boolean NOT NULL DEFAULT FALSE,
				FOREIGN KEY ("actor_id") REFERENCES "actor" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
			CREATE TABLE "post_file" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"object_id" bigint NOT NULL,
				"hash" text(45) NOT NULL,
				"sequence" integer NOT NULL,
				FOREIGN KEY ("object_id") REFERENCES "object" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION,
				UNIQUE(object_id, sequence)
			);
			CREATE TABLE "post_object" (
				"object_id" bigint NOT NULL PRIMARY KEY,
				"in_reply_to_actor_address" blob,
				"in_reply_to_object_hash" text(45),
				"file_count" integer NOT NULL,
				FOREIGN KEY ("object_id") REFERENCES "object" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
			CREATE TABLE "post_tag" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"object_id" bigint NOT NULL,
				"tag" text NOT NULL,
				FOREIGN KEY ("object_id") REFERENCES "post_object" ("object_id") ON DELETE NO ACTION ON UPDATE NO ACTION,
				UNIQUE(object_id, tag)
			);
			CREATE TABLE "profile_object" (
				"object_id" bigint NOT NULL PRIMARY KEY,
				"name" text NOT NULL,
				"avatar_file_hash" text(45),
				"wallpaper_file_hash" text(45),
				"description_file_hash" text(45),
				FOREIGN KEY ("object_id") REFERENCES "object" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
			CREATE TABLE "share_object" (
				"object_id" bigint NOT NULL PRIMARY KEY,
				"actor_address" blob NOT NULL,
				"object_hash" text(45) NOT NULL,
				FOREIGN KEY ("object_id") REFERENCES "object" ("id") ON DELETE NO ACTION ON UPDATE NO ACTION
			);
		"#,
			)
			.await?;
		Ok(())
	}
}

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
				CREATE TABLE "trust_list_checksum" (
					"recursion_level" integer NOT NULL PRIMARY KEY,
					"checksum" text(45) NOT NULL
				);
				CREATE TABLE "trusted_node" (
					"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
					"label" text NOT NULL UNIQUE,
					"address" blob NOT NULL UNIQUE,
					"score" integer NOT NULL
				);
				CREATE TABLE "trusted_node_trust_item" (
					"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
					"trusted_node_id" bigint NOT NULL,
					"recursion_level" integer NOT NULL,
					"address" blob NOT NULL,
					"score" integer NOT NULL,
					"our_score" integer NOT NULL,
					UNIQUE(trusted_node_id, address)
				);
				CREATE TABLE "trusted_node_update" (
					"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
					"trusted_node_id" bigint NOT NULL,
					"recursion_level" integer NOT NULL,
					"timestamp" bigint NOT NULL,
					"checksum" text(45) NOT NULL,
					FOREIGN KEY ("trusted_node_id") REFERENCES "trusted_node" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
					UNIQUE(trusted_node_id, recursion_level)
				);

				DROP TABLE "bootstrap_id";
				CREATE TABLE "bootstrap_node_id" (
					"address" text NOT NULL PRIMARY KEY,
					"node_id" blob NOT NULL UNIQUE
				);

				DROP TABLE "node_identity";
				CREATE TABLE "node_identity" (
					"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
					"address" blob NOT NULL,
					"private_key" blob NOT NULL
				);
		"#,
			)
			.await?;
		Ok(())
	}
}

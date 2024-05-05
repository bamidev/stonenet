use async_trait::async_trait;
use sea_orm::{sea_query::*, *};

use crate::{
	db::{self, PersistenceHandle},
	migration::MigrationTrait,
};


pub struct Migration;


#[async_trait]
impl MigrationTrait for Migration {
	async fn run(&self, tx: &db::Transaction) -> db::Result<()> {
		let schema = Schema::new(tx.backend());

		tx.inner()
			.execute_unprepared(
				r#"
			CREATE TABLE "activity_pub_actor_inbox" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"server" text NOT NULL,
				"path" text NOT NULL,
				"inbox" text NOT NULL
			);
			CREATE TABLE "activity_pub_follow" (
				"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
				"actor_id" bigint NOT NULL,
				"path" text NOT NULL,
				"server" text NOT NULL
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
				"server" text NOT NULL PRIMARY KEY,
				"shared_inbox" text
			);
			ALTER TABLE object ADD COLUMN "published_on_fediverse" boolean NOT NULL DEFAULT FALSE;
		"#,
			)
			.await?;
		Ok(())
	}
}

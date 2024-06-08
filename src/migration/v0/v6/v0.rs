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
				DROP TABLE "activity_pub_object";
				
				CREATE TABLE "activity_pub_actor" (
					"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
					"host" text NOT NULL,
					"path" text NOT NULL,
					"address" text,
					"inbox" text,
					"outbox" text
				);
				CREATE TABLE "activity_pub_follower" (
					"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
					"actor_id" bigint NOT NULL,
					"host" text NOT NULL,
					"path" text NOT NULL,
					FOREIGN KEY ("actor_id") REFERENCES "actor" ("id")
				);
				CREATE TABLE "activity_pub_following" (
					"actor_id" integer NOT NULL PRIMARY KEY,
					FOREIGN KEY ("actor_id") REFERENCES "activity_pub_actor" ("id")
				);
				CREATE TABLE "activity_pub_object" (
					"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
					"actor_id" bigint NOT NULL,
					"object_id" text NOT NULL UNIQUE,
					"data" text NOT NULL,
					FOREIGN KEY ("actor_id") REFERENCES "activity_pub_actor" ("id")
				);
				CREATE TABLE "activity_pub_inbox_object" (
					"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
					"actor_id" bigint NOT NULL,
					"object_id" text NOT NULL UNIQUE,
					"data" text NOT NULL,
					FOREIGN KEY ("actor_id") REFERENCES "actor" ("id")
				);

				INSERT INTO activity_pub_actor (id, host, path, inbox) SELECT id, host, path, inbox FROM activity_pub_actor_inbox;

				DROP TABLE activity_pub_follow;
				DROP TABLE activity_pub_actor_inbox;
		"#,
			)
			.await?;
		Ok(())
	}
}

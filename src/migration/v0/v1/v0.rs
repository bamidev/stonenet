mod entity;


use async_trait::async_trait;
use sea_orm::{prelude::*, Schema};

use crate::{
	db::{self, PersistenceHandle},
	migration::{util::*, MigrationTrait},
};


pub struct Migration;


#[async_trait]
impl MigrationTrait for Migration {
	async fn run(&self, tx: &db::Transaction) -> db::Result<()> {
		// TODO: If any of the following entities change, store the old entity somewhere
		// else
		let schema = Schema::new(tx.backend());

		// Drop unused tables
		tx.inner()
			.execute_unprepared("DROP TABLE move_object")
			.await?;
		tx.inner()
			.execute_unprepared("DROP TABLE remembered_actor_nodes")
			.await?;

		// Point the post_id columns to the object id now
		tx.inner()
			.execute_unprepared(
				"UPDATE post_files SET post_id = (SELECT object_id FROM post_object WHERE rowid = \
				 post_files.post_id)",
			)
			.await?;
		tx.inner()
			.execute_unprepared(
				"UPDATE post_tag SET post_id = (SELECT object_id FROM post_object WHERE rowid = \
				 post_tag.post_id)",
			)
			.await?;

		// Add a new id column to some entities
		let block = self::entity::block::Entity;
		add_id_column(tx, &schema, block, "block", &["hash", "size", "data"]).await?;
		let file = self::entity::file::Entity;
		add_id_column(
			tx,
			&schema,
			file,
			"file",
			&["hash", "mime_type", "block_count", "plain_hash"],
		)
		.await?;
		let identity = self::entity::identity::Entity;
		add_id_column(
			tx,
			&schema,
			identity,
			"identity",
			&["address", "public_key", "first_object, type"],
		)
		.await?;
		let object = self::entity::object::Entity;
		add_id_column(
			tx,
			&schema,
			object,
			"object",
			&[
				"hash",
				"actor_id",
				"sequence, previous_hash",
				"created",
				"found",
				"type",
				"signature",
				"verified_from_start",
			],
		)
		.await?;

		let post_files = self::entity::post_files::Entity;
		add_id_column(
			tx,
			&schema,
			post_files,
			"post_files",
			&["post_id", "hash", "sequence"],
		)
		.await?;

		let entity = self::entity::post_object::Entity;
		reset_table(tx, &schema, entity, "post_object").await?;

		let post_tag = self::entity::post_tag::Entity;
		add_id_column(tx, &schema, post_tag, "post_tag", &["post_id", "tag"]).await?;

		// Reset foreign keys on some tables
		let entity = self::entity::boost_object::Entity;
		reset_table(tx, &schema, entity, "boost_object").await?;
		let entity = self::entity::file_blocks::Entity;
		reset_table(tx, &schema, entity, "file_blocks").await?;
		Ok(())
	}
}

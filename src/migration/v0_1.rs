use async_trait::async_trait;
use sea_orm::{prelude::*, sea_query::*, DatabaseBackend, DatabaseTransaction, Schema, Statement};

use super::MigrationTrait;
use crate::trace;


pub struct Migration;


/// Recreates the table that needs to have a new `id` field as the primary key,
/// instead of using its ROWID.
async fn add_id_column<'c, E>(
	tx: &DatabaseTransaction, schema: &Schema, entity: E, table_name: &str, columns: &[&str],
) -> trace::Result<(), DbErr>
where
	E: EntityTrait,
{
	// First, rename the table
	let old_table_name = "old_".to_string() + table_name;
	let stat = Table::rename()
		.table(Alias::new(table_name), Alias::new(&old_table_name))
		.to_owned();
	tx.execute_unprepared(&stat.build(SqliteQueryBuilder))
		.await?;

	// Then, create the new table of for the entity
	let stat = schema.create_table_from_entity(entity);
	tx.execute_unprepared(&stat.build(SqliteQueryBuilder))
		.await?;

	// Copy over all data from old table to new
	let columns_joined = columns.join(", ");
	let query = format!(
		"INSERT INTO {} (id, {}) SELECT rowid, {} FROM {}",
		table_name, &columns_joined, columns_joined, &old_table_name
	);
	let stat = Statement::from_sql_and_values(DatabaseBackend::Sqlite, query, []);
	tx.execute(stat).await?;

	// Delete old table
	let stat = Table::drop().table(Alias::new(old_table_name)).to_owned();
	tx.execute_unprepared(&stat.build(SqliteQueryBuilder))
		.await?;

	Ok(())
}


#[async_trait]
impl MigrationTrait for Migration {
	async fn run(&self, tx: &DatabaseTransaction) -> trace::Result<(), DbErr> {
		// TODO: If any of the following entities change, store the old entity somewhere
		// else
		let schema = Schema::new(DatabaseBackend::Sqlite);

		// Drop version patch column
		tx.execute_unprepared("ALTER TABLE version DROP COLUMN patch")
			.await?;

		// Drop unused tables
		tx.execute_unprepared("DROP TABLE move_object").await?;
		tx.execute_unprepared("DROP TABLE remembered_actor_nodes")
			.await?;

		// Point the post_id columns to the object id now
		tx.execute_unprepared(
			"UPDATE post_files SET post_id = (SELECT object_id FROM post_object WHERE rowid = \
			 post_files.post_id)",
		)
		.await?;
		tx.execute_unprepared(
			"UPDATE post_tag SET post_id = (SELECT object_id FROM post_object WHERE rowid = \
			 post_tag.post_id)",
		)
		.await?;

		// Add a new id column to some entities
		let block = crate::entity::prelude::Block;
		add_id_column(tx, &schema, block, "block", &["hash", "size", "data"]).await?;
		let file = crate::entity::prelude::File;
		add_id_column(
			tx,
			&schema,
			file,
			"file",
			&["hash", "mime_type", "block_count", "plain_hash"],
		)
		.await?;
		let identity = crate::entity::prelude::Identity;
		add_id_column(
			tx,
			&schema,
			identity,
			"identity",
			&["address", "public_key", "first_object, type"],
		)
		.await?;
		let object = crate::entity::prelude::Object;
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
		let post_files = crate::entity::prelude::PostFiles;
		add_id_column(
			tx,
			&schema,
			post_files,
			"post_files",
			&["post_id", "hash", "sequence"],
		)
		.await?;
		let post_tag = crate::entity::prelude::PostTag;
		add_id_column(tx, &schema, post_tag, "post_tag", &["post_id", "tag"]).await?;
		Ok(())
	}
}

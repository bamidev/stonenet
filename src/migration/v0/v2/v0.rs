use async_trait::async_trait;
use sea_orm::{sea_query::*, *};

use crate::{db::{self, PersistenceHandle}, migration::MigrationTrait};

mod entity;


pub struct Migration;


async fn drop_id_and_rename_post_id_column<E>(tx: &db::Transaction, schema: &Schema, entity: E, table_name: &str, other_columns: &[&str]) -> db::Result<()> where E: EntityTrait {
    // First, rename the table
	let old_table_name = "migrate_".to_string() + table_name;
	let stat = Table::rename()
		.table(Alias::new(table_name), Alias::new(&old_table_name))
		.to_owned();
	tx.handle()
		.execute(tx.backend().build(&stat))
		.await?;

	// Then, create the new table of for the entity
	let stat = schema.create_table_from_entity(entity);
	tx.handle()
		.execute(tx.backend().build(&stat))
		.await?;

	// Copy over all data from old table to new
	let columns_joined = other_columns.join(", ");
	let query = format!(
		"INSERT INTO {} (object_id, {}) SELECT post_id, {} FROM {}",
		table_name, &columns_joined, columns_joined, &old_table_name
	);
	let stat = Statement::from_sql_and_values(tx.backend(), query, []);
	tx.handle().execute(stat).await?;

	// Delete old table
	let stat = Table::drop().table(Alias::new(old_table_name)).to_owned();
	tx.handle()
		.execute(tx.backend().build(&stat))
		.await?;

	Ok(())
}


#[async_trait]
impl MigrationTrait for Migration {
	async fn run(&self, tx: &db::Transaction) -> db::Result<()> {
        let schema = Schema::new(tx.backend());

        let post_files = self::entity::post_files::Entity;
        drop_id_and_rename_post_id_column(tx, &schema, post_files, "post_files", &["hash", "sequence"]).await?;
        let post_tag = self::entity::post_tag::Entity;
        drop_id_and_rename_post_id_column(tx, &schema, post_tag, "post_tag", &["tag"]).await?;
        Ok(())
    }
}
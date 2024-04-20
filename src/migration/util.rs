use sea_orm::{sea_query::*, *};

use crate::db::{self, PersistenceHandle};



/// Recreates the table that needs to have a new `id` field as the primary key,
/// instead of using its ROWID.
pub async fn add_id_column<E>(
	tx: &db::Transaction, schema: &Schema, entity: E, table_name: &str, columns: &[&str],
) -> db::Result<()>
where
	E: EntityTrait,
{
	// First, rename the table
	let old_table_name = "old_".to_string() + table_name;
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
	let columns_joined = columns.join(", ");
	let query = format!(
		"INSERT INTO {} (id, {}) SELECT rowid, {} FROM {}",
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


/// Recreates the table so that all foreign keys are pointing to the correct
/// table again.
pub async fn reset_table<'c, E>(
	tx: &db::Transaction, schema: &Schema, entity: E, table_name: &str,
) -> db::Result<()>
where
	E: EntityTrait,
{
	// First, rename the table
	let old_table_name = "old_".to_string() + table_name;
	let stat = Table::rename()
		.table(Alias::new(table_name), Alias::new(&old_table_name))
		.to_owned();
	tx.handle()
		.execute_unprepared(&stat.build(SqliteQueryBuilder))
		.await?;

	// Then, create the new table of for the entity
	let stat = schema.create_table_from_entity(entity);
	tx.handle()
		.execute_unprepared(&stat.build(SqliteQueryBuilder))
		.await?;

	// Then, copy everything over to the new table
	let query = format!(
		"INSERT INTO {} SELECT * FROM {}",
		table_name, &old_table_name
	);
	let stat = Statement::from_sql_and_values(tx.backend(), query, []);
	tx.handle().execute(stat).await?;

	// Delete old table
	let stat = Table::drop().table(Alias::new(old_table_name)).to_owned();
	tx.handle()
		.execute_unprepared(&stat.build(SqliteQueryBuilder))
		.await?;
	Ok(())
}
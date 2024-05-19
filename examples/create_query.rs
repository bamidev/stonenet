use sea_orm::*;

fn main() {
	// Change this entity to anything you want to see the CREATE TABLE query from:
	let entity = stonenetd::entity::share_object::Entity;

	let backend = DatabaseBackend::Sqlite;
	let schema = Schema::new(backend);
	let statement = backend.build(&schema.create_table_from_entity(entity));

	println!("{}", statement.to_string());
}

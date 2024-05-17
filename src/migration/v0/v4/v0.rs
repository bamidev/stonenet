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
			DELETE FROM block;
			DELETE FROM file_blocks;
			DELETE FROM file;
			ALTER TABLE file ADD COLUMN compression_type INTEGER NOT NULL;
		"#,
			)
			.await?;
		Ok(())
	}
}

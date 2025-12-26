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
		// Delete the whole blogchain history, because the block size changed.
		tx.inner()
			.execute_unprepared(
				r#"
            DELETE FROM post_object;
            DELETE FROM post_file;
            DELETE FROM post_tag;
            DELETE FROM profile_object;
            DELETE FROM object;

            ALTER TABLE post_tag ADD COLUMN sequence INTEGER;
        "#,
			)
			.await?;
		Ok(())
	}
}

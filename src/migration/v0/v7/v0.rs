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
		// Delete the whole blogchain history, because the format has been changed.
		tx.inner()
			.execute_unprepared(
				r#"
            DELETE FROM post_object;
            DELETE FROM post_file;
            DELETE FROM post_tag;
            DELETE FROM profile_object;
            DROP TABLE share_object;
            DELETE FROM object;

            DELETE FROM identity;
            ALTER TABLE identity DROP COLUMN private_key;
            ALTER TABLE identity ADD COLUMN system_user TEXT;
        "#,
			)
			.await?;
		Ok(())
	}
}

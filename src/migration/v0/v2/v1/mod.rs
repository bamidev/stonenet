use async_trait::async_trait;
use sea_orm::prelude::*;

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
                DELETE FROM identity WHERE
                id NOT IN (SELECT DISTINCT(actor_id) FROM object) AND
                id NOT IN (SELECT identity_id FROM my_identity) AND
                id NOT IN (SELECT identity_id FROM following)
            "#,
			)
			.await?;

		tx.inner()
			.execute_unprepared("CREATE UNIQUE INDEX uniq_identity_address ON identity(address)")
			.await;
		Ok(())
	}
}

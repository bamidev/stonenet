//! The module for migrating the database.
mod util;
mod v0;

use std::fmt::Display;

use async_trait::async_trait;
use log::info;
use sea_orm::{prelude::*, sea_query::*, DatabaseBackend, Statement};

use crate::db::{self, PersistenceHandle};


/// The latest database version.
pub const LATEST_VERSION: Version = Version {
	major: 0,
	minor: 5,
	patch: 0,
};


#[derive(Clone, Debug)]
pub struct Version {
	major: u32,
	minor: u32,
	patch: u32,
}

pub struct Migrations {
	/// A list of available migrations, ordered at version
	list: Vec<(Version, Box<dyn MigrationTrait>)>,
}

#[async_trait]
trait MigrationTrait {
	async fn run(&self, tx: &db::Transaction) -> db::Result<()>;
}


impl Migrations {
	pub fn load() -> Self {
		Self {
			list: vec![
				(Version::new(0, 1, 0), Box::new(v0::v1::v0::Migration)),
				(Version::new(0, 2, 0), Box::new(v0::v2::v0::Migration)),
				(Version::new(0, 2, 1), Box::new(v0::v2::v1::Migration)),
				(Version::new(0, 3, 0), Box::new(v0::v3::v0::Migration)),
				(Version::new(0, 4, 0), Box::new(v0::v4::v0::Migration)),
				(Version::new(0, 4, 1), Box::new(v0::v4::v1::Migration)),
				(Version::new(0, 5, 0), Box::new(v0::v5::v0::Migration)),
			],
		}
	}

	async fn load_version(&self, connection: &db::Database) -> db::Result<Version> {
		let q = Query::select()
			.from(Alias::new("version"))
			.column(Alias::new("major"))
			.column(Alias::new("minor"))
			.column(Alias::new("patch"))
			.to_owned();
		let (sql, values) = q.build(SqliteQueryBuilder);
		let r = connection
			.inner()
			.query_one(Statement::from_sql_and_values(
				DatabaseBackend::Sqlite,
				sql,
				values,
			))
			.await?;
		let result = r.expect("no version in the database");
		let major: u32 = result.try_get_by_index(0)?;
		let minor: u32 = result.try_get_by_index(1)?;
		let patch: u32 = result.try_get_by_index(2)?;
		Ok(Version::new(major, minor, patch))
	}

	async fn store_version(
		&self, tx: &impl PersistenceHandle, version: &Version,
	) -> db::Result<()> {
		let q = Query::update()
			.table(Alias::new("version"))
			.values([
				(Alias::new("major"), version.major.into()),
				(Alias::new("minor"), version.minor.into()),
				(Alias::new("patch"), version.patch.into()),
			])
			.to_owned();
		let (sql, values) = q.build(SqliteQueryBuilder);
		let _ = tx
			.inner()
			.execute(Statement::from_sql_and_values(
				DatabaseBackend::Sqlite,
				sql,
				values,
			))
			.await?;
		Ok(())
	}

	pub async fn run(&self, connection: &db::Database) -> db::Result<()> {
		// Stop foreign key errors
		connection
			.inner()
			.execute_unprepared("PRAGMA foreign_keys=off")
			.await?;

		let mut current_version = self.load_version(connection).await?;

		for (new_version, migration) in &self.list {
			if new_version > &current_version {
				let tx = connection.transaction().await?;
				info!(
					"Running database migration from {} to {}...",
					current_version, new_version
				);
				migration.run(&tx).await?;
				self.store_version(&tx, new_version).await?;
				tx.commit().await?;
				info!("Migrated database to {}.", new_version);
				current_version = new_version.clone();
			}
		}

		assert_eq!(
			current_version, LATEST_VERSION,
			"not migrated to latest version"
		);
		connection
			.inner()
			.execute_unprepared("PRAGMA foreign_keys=on")
			.await?;
		Ok(())
	}
}

impl Version {
	pub fn new(major: u32, minor: u32, patch: u32) -> Self {
		Self {
			major,
			minor,
			patch,
		}
	}
}

impl Display for Version {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
	}
}

impl PartialEq for Version {
	fn eq(&self, other: &Self) -> bool {
		self.major == other.major && self.minor == other.minor && self.patch == other.patch
	}
}

impl PartialOrd for Version {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		match self.major.partial_cmp(&other.major) {
			Some(core::cmp::Ordering::Equal) => {}
			ord => return ord,
		}
		match self.minor.partial_cmp(&other.minor) {
			Some(core::cmp::Ordering::Equal) => {}
			ord => return ord,
		}
		self.patch.partial_cmp(&other.patch)
	}
}

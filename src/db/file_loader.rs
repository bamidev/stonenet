use std::{mem, pin::Pin};

use log::*;
use rusqlite::*;

use super::{Database, IdType};


pub struct FileLoader {
	// Needs to be destructed before `stat`, so this field always needs to be above `stat.
	db: db::Database,
	file_hash: IdType,
	blocks: Vec::<IdType>::Iterator
}

impl FileLoader {
	pub fn new(db: Database, file_hash: &IdType) -> super::Result<Self> {
		let blocks = db.perform(|c| {
			db::Connection::fetch_file_blocks(&c, file_hash)
		})?;
		Ok(Self { db, file_hash: file_hash.clone(), blocks: blocks.into_iter() })
	}
}

impl Iterator for FileLoader< {
	type Item = super::Result<Vec<u8>>;

	fn next(&mut self) -> Option<Self::Item> {
		if let Some(block_hash) = self.blocks.next() {
			Some(self.db.perform(|c| c.fetch_block(&block_hash)))
		} else {
			None
		}
	}
}

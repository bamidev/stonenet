use std::{mem, pin::Pin};

use log::*;
use rusqlite::*;


pub struct FileLoader<'a> {
	// Needs to be destructed before `stat`, so this field always needs to be above `stat.
	rows: Rows<'a>,
	stat: Pin<Box<Statement<'a>>>,
	file_id: i64,
	block_count: u64,
	next_sequence: u64,
}

impl<'a> FileLoader<'a> {
	pub fn new(
		mut stat: Pin<Box<Statement<'a>>>, file_id: i64, block_count: u64,
	) -> super::Result<Self> {
		let rows = stat.query([file_id])?;
		let rows2: Rows<'a> = unsafe { mem::transmute(rows) };
		// Unsafe clarification:
		// rusqlite defines their query method like so:
		// `fn query<P: Params>(&mut self, params: P) -> Result<Rows<'_>>`
		// And in Rows<'_> internally, it defines a field like so:
		// `stmt: Option<&'stmt Statement<'stmt>>`
		// So it holds a reference to a statement, with the lifetime of that
		// reference of the statement variable itself, however, the statements'
		// own lifetime should reference the connection, not itself, so it
		// should actually be more like so:
		// stmt: Option<&'stmt Statement<'a>>
		// But somewhere in rusqlite the statements internal lifetime seems to
		// get downgraded.
		// So, the Rows<'_> type is restricted
		// to the lifetime of the statement variable, which is smaller than 'a,
		// while it needs lifetime 'a to live inside this struct `FileLoader`.
		// The problem is that Rows<'_> references Statement<'stmt>, which
		// lives shorter than Statement<'a>, which is unnecessary.
		// I think that the `rusqlite` crate has a design flaw, but I assume
		// that a Statement can live as long as its Connection, and the Rows
		// struct as long as its Statement. Therefore, I forcefully cast the
		// lifetime of the rows back to the same lifetime as our Statement.
		// Also, because they both live in the same struct, it is essentially as
		// if 'stmt equals 'a .
		Ok(Self {
			stat,
			file_id,
			rows: rows2,
			block_count,
			next_sequence: 0,
		})
	}
}

impl<'a> Iterator for FileLoader<'a> {
	type Item = super::Result<Vec<u8>>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.next_sequence >= self.block_count {
			return None;
		}

		let next_sequence = self.next_sequence;
		self.next_sequence += 1;
		let mut n = || -> super::Result<_> {
			if let Some(row) = self.rows.next()? {
				let sequence: u64 = row.get(0)?;
				if sequence != next_sequence {
					return Err(super::Error::FileMissingBlock(self.file_id, next_sequence));
				}

				let block_size = row.get(1)?;
				let mut data: Vec<u8> = row.get(2)?;

				if data.len() < block_size {
					error!("Block sequence {} is missing data.", sequence);
					// FIXME: Turn this into a block corrupt error...
					return Err(super::Error::FileMissingBlock(self.file_id, next_sequence));
				} else if data.len() > block_size {
					data.resize(block_size, 0);
				}

				Ok(data)
			} else {
				Err(super::Error::FileMissingBlock(self.file_id, next_sequence))
			}
		};

		Some(n())
	}
}

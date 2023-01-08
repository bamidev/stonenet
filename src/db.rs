mod install;


use std::{
	cmp::min,
	fmt,
	fs,
	ops::*,
	path::*
};

use crate::{
	common::*,
	model::*,
	identity::*
};

use dirs;
use fallible_iterator::FallibleIterator;
use log::*;
use rusqlite::{self, params, Transaction};
use unsafe_send_sync::*;


const DATABASE_PATH: &'static str = ".stonenet/db.sqlite";
const DATABASE_VERSION: (u8, u16, u16) = (0, 0, 0);
const BLOCK_SIZE: usize = 0x100000;	// 1 MiB


#[derive(Copy, Clone)]
pub struct Database;

pub struct Connection (
	// The documentation of rusqlite mentions that the Connection struct does
	// not need a mutex, that it is already thread-safe. For some reason it was
	// not marked as Send and Sync.
	UnsafeSendSync<rusqlite::Connection>
);

#[derive(Debug)]
pub enum Error {
	/// Sqlite error
	SqliteError(rusqlite::Error),
	InvalidObjectType(u8),
	/// An invalid hash has been found in the database
	InvalidHash(IdFromBase58Error),
	InvalidSignature(SignatureError),
	InvalidKeypair(KeypairError)
}

pub type Result<T> = std::result::Result<T, self::Error>;


impl Database {
	pub fn connect(&self) -> rusqlite::Result<Connection> {
		Ok(Connection::open()?)
	}

	fn install(conn: &Connection) -> rusqlite::Result<()> {
		conn.execute_batch(install::QUERY)
	}

	fn is_outdated(major: u8, minor: u16, patch: u16) -> bool {
		major < DATABASE_VERSION.0 || minor < DATABASE_VERSION.1 || patch < DATABASE_VERSION.2
	}

	pub fn load() -> rusqlite::Result<Self> {
		let connection = Connection::open()?;

		match connection.prepare("SELECT major, minor, patch FROM version") {
			Ok(mut stat) => {
				let mut rows = stat.query([])?;
				let row = rows.next()?.expect("missing version data");
				let major = row.get(0)?;
				let minor = row.get(1)?;
				let patch = row.get(2)?;

				if Self::is_outdated(major, minor, patch) {
					Self::upgrade(&connection);
				}
			},
			Err(e) => {
				match &e {
					rusqlite::Error::SqliteFailure(_err, msg) => {
						match msg {
							Some(error_message) => {
								if error_message == "no such table: version" {
									Self::install(&connection)?;
								}
								else {
									return Err(e);
								}
							},
							None => return Err(e)
						}
					},
					_ => return Err(e)
				}
			}
		}

		Ok(Self)
	}

	fn upgrade(_conn: &rusqlite::Connection) {
		panic!("No database upgrade implemented yet!");
	}
}

impl Connection {
	pub fn fetch_home_feed(&self,
		count: usize,
		offset: usize
	) -> db::Result<Vec<Object>> {
		let mut stat = self.prepare(r#"
			SELECT sequence, type, signature FROM object WHERE actor_id IN (
				SELECT identity_id FROM my_identity
			) OR actor_id IN (
				SELECT identity_id FROM following
			)
			ORDER BY found_timestamp DESC LIMIT ? OFFSET ?
		"#)?;
		let mut rows = stat.query([count, offset])?;

		let mut result = Vec::with_capacity(count);
		while let Some(row) = rows.next()? {
			let sequence = row.get(0)?;
			let object_type = row.get(1)?;
			let signature_blob: Vec<u8> = row.get(2)?;
			let signature = Signature::from_bytes(signature_blob.try_into().unwrap());

			let payload = match object_type {
				0 => self.fetch_post_object(sequence).map(|o| o.map(|p|
					ObjectPayload::Post(p)
				)),
				1 => self.fetch_boost_object(sequence).map(|o| o.map(|b|
					ObjectPayload::Boost(b)
				)),
				2 => self.fetch_profile_object(sequence).map(|o| o.map(|p|
					ObjectPayload::Profile(p)
				)),
				3 => self.fetch_move_object(sequence).map(|o| o.map(|m|
					ObjectPayload::Move(m)
				)),
				other => return Err(Error::InvalidObjectType(other))
			};
			payload.map(|o| o.map(|p| Object {
				sequence,
				signature,
				payload: p
			}))
		}
	}

	pub fn fetch_object(&self,
		sequence: u64
	) -> Result<Option<Object>> {
		let mut stat = self.prepare(r#"
			SELECT type, signature FROM object WHERE sequence = ?
		"#)?;
		let mut rows = stat.query([sequence])?;
		if let Some(row) = rows.next()? {
			let object_type = row.get(0)?;
			let signature_blob: Vec<u8> = row.get(1)?;
			let signature = Signature::from_bytes(signature_blob.try_into().unwrap());

			let payload = match object_type {
				0 => self.fetch_post_object(sequence).map(|o| o.map(|p|
					ObjectPayload::Post(p)
				)),
				1 => self.fetch_boost_object(sequence).map(|o| o.map(|b|
					ObjectPayload::Boost(b)
				)),
				2 => self.fetch_profile_object(sequence).map(|o| o.map(|p|
					ObjectPayload::Profile(p)
				)),
				3 => self.fetch_move_object(sequence).map(|o| o.map(|m|
					ObjectPayload::Move(m)
				)),
				other => return Err(Error::InvalidObjectType(other))
			};
			payload.map(|o| o.map(|p| Object {
				sequence,
				signature,
				payload: p
			}))
		}
		else { Ok(None) }
	}

	pub fn fetch_post_files(&self, post_id: u64) -> Result<Vec<FileHeader>> {
		let mut stat = self.0.prepare(r#"
			SELECT hash, mime_type FROM file WHERE post_id = ?
		"#)?;
		let mut rows = stat.query([post_id])?;
		let mut files = Vec::new();
		while let Some(row) = rows.next()? {
			let hash: String = row.get(0)?;
			let hash_id = IdType::from_base58(&hash)?;
			files.push(FileHeader {
				hash: hash_id,
				mime_type: row.get(2)?
			});
		}
		Ok(files)
	}

	pub fn fetch_boost_object(&self, index: u64) -> Result<Option<BoostObject>> {
		let mut stat = self.0.prepare(r#"
			SELECT post_actor_address, post_index FROM boost_object
			WHERE object_id = (SELECT index FROM object WHERE id = ?)
		"#)?;
		let mut rows = stat.query([index])?;
		if let Some(row) = rows.next()? {
			let actor_address: String = row.get(0)?;
			let post_index: u64 = row.get(1)?;
			let post_actor_id = IdType::from_base58(&actor_address)?;
			Ok(Some(BoostObject {
				post_actor_id,
				post_index
			}))
		}
		else { Ok(None) }
	}

	pub fn fetch_move_object(&self, index: u64) -> Result<Option<MoveObject>> {
		let mut stat = self.0.prepare(r#"
			SELECT new_actor_address FROM move_object
			WHERE object_id = (SELECT index FROM object WHERE id = ?)
		"#)?;
		let mut rows = stat.query([index])?;
		if let Some(row) = rows.next()? {
			let new_actor_address: String = row.get(0)?;
			let new_actor_id = IdType::from_base58(&new_actor_address)?;
			Ok(Some(MoveObject {
				new_actor_id
			}))
		}
		else { Ok(None) }
	}

	pub fn fetch_post_object(&self, index: u64) -> Result<Option<PostObject>> {
		let mut stat = self.0.prepare(r#"
			SELECT po.rowid, i.address, o.post_index
			FROM post_object AS po
			LEFT JOIN post_object AS rpo ON po.in_reply_to_id == rpo.rowid
			LEFT JOIN object AS o ON rpo.object_index == o.index
			LEFT JOIN identity AS i ON o.actor_id == i.rowid
			WHERE object_id = (SELECT index FROM object WHERE id = ?)
		"#)?;
		let mut rows = stat.query([index])?;
		if let Some(row) = rows.next()? {
			let rowid = row.get(0)?;
			let in_reply_to_actor_address: Option<String> = row.get(1)?;
			let in_reply_to_object_index: Option<i64> = row.get(2)?;
			let in_reply_to = match in_reply_to_actor_address {
				None => None,
				Some(address) => {
					let id = IdType::from_base58(&address)?;
					Some((id, in_reply_to_object_index.unwrap() as u64))
				}
			};
			Ok(Some(PostObject {
				in_reply_to,
				tags: self.fetch_post_tags(rowid)?,
				files: self.fetch_post_files(rowid)?
			}))
		}
		else {
			Ok(None)
		}
	}

	pub fn fetch_profile_object(&self, index: u64) -> Result<Option<ProfileObject>> {
		let mut stat = self.0.prepare(r#"
			SELECT af.hash, af.mime_type, wf.hash, wf.mime_type, b.hash
			FROM profile_object AS po
			LEFT JOIN file AS af ON po.avatar_file_id == af.rowid
			LEFT JOIN file AS wf ON po.wallpaper_file_id == wf.rowid
			LEFT JOIN block AS b ON po.description_block_id == b.rowid
			WHERE object_id = (SELECT index FROM object WHERE id = ?)
		"#)?;
		let mut rows = stat.query([index])?;
		if let Some(row) = rows.next()? {
			let avatar_hash: String = row.get(0)?;
			let avatar_id = IdType::from_base58(&avatar_hash)?;
			let avatar_mime_type: String = row.get(1)?;
			let wallpaper_hash: String = row.get(2)?;
			let wallpaper_id = IdType::from_base58(&wallpaper_hash)?;
			let wallpaper_mime_type: String = row.get(3)?;
			let block_hash: String = row.get(4)?;
			let description_block_id = IdType::from_base58(&block_hash)?;
			Ok(Some(ProfileObject {
				avatar: FileHeader {
					hash: avatar_id,
					mime_type: avatar_mime_type
				},
				wallpaper: FileHeader {
					hash: wallpaper_id,
					mime_type: wallpaper_mime_type
				},
				description_block_id
			}))
		}
		else { Ok(None) }
	}

	pub fn fetch_post_tags(&self, post_id: u64) -> Result<Vec<String>> {
		let mut stat = self.0.prepare(r#"
			SELECT tag FROM post_tag WHERE post_id = ?
		"#)?;
		let rows = stat.query([post_id])?;
		rows.map(|r| r.get(0)).collect().map_err(|e| e.into())
	}

	/*pub fn fetch_latest_posts(&self,
		actor_id: &IdType,
		count: usize,
		offset: usize
	) -> Result<Vec<PostObject>> {
		let mut stat = self.0.prepare(r#"
			SELECT rowid FROM post_object AS po
			LEFT JOIN object AS o ON po.object_id = o.rowid
			WHERE actor_id = (SELECT rowid FROM identity WHERE address = ?)
			ORDER BY o.index DESC
			LIMIT ? OFFSET ?
		"#)?;
		let mut rows = stat.query(rusqlite::params![actor_id.to_string(), count, offset])?;
		let mut posts = Vec::new();
		while let Some(row) = rows.next()? {
			let rowid = row.get(0)?;
			//let hash_blob: Vec<u8> = row.get(1)?;
			posts.push(PostObject {
				//hash: Self::parse_hash(&hash_blob, format!("post {}", rowid))?,
				tags: self.fetch_post_tags(rowid)?,
				files: self.fetch_post_files(rowid)?
			})
		}
		Ok(posts)
	}*/

	pub fn fetch_my_identity(&self,
		address: &IdType
	) -> Result<Option<(String, Keypair)>> {
		let mut stat = self.0.prepare(r#"
			SELECT label, keypair FROM my_identity AS mi LEFT JOIN identity AS i
			WHERE i.address = ?
		"#)?;
		let mut rows = stat.query([address.to_string()])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => {
				let label = row.get(0)?;
				let bytes: Vec<u8> = row.get(1)?;
				let keypair = Keypair::from_bytes(&bytes)?;
				Ok(Some((label, keypair)))
			}
		}
	}

	pub fn fetch_my_identities(&self) -> 
		Result<Vec<(String, IdType, Keypair)>>
	{
		let mut stat = self.0.prepare(r#"
			SELECT label, i.address, mi.keypair FROM my_identity AS mi
			LEFT JOIN identity AS i ON mi.identity_id = i.rowid
		"#)?;
		let mut rows = stat.query([])?;

		let mut ids = Vec::new();
		while let Some(row) = rows.next()? {
			let address_string: String = row.get(1)?;
			let address = match IdType::from_base58(&address_string) {
				Err(e) => {
					error!("Unable to load address from DB: {}", e);
					continue;
				}
				Ok(a) => a
			};
			let blob: Vec<u8> = row.get(2)?;
			let id = match Keypair::from_bytes(&blob) {
				Err(e) => {
					error!("Unable to load identity from DB: {}", e);
					continue;
				}
				Ok(i) => i
			};
			ids.push((
				row.get(0)?,
				address,
				id
			));
		}
		Ok(ids)
	}

	pub fn find_identity(&self,
		address: &IdType
	) -> rusqlite::Result<Option<u64>> {
		let mut stat = self.0.prepare(r#"
			SELECT rowid FROM identity WHERE address = ?
		"#)?;
		let mut rows = stat.query([address.to_string()])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(Some(row.get(0)?))
		}
	}

	pub fn is_identity_available(&self, address: &IdType) -> rusqlite::Result<bool> {
		let mut stat = self.0.prepare(r#"
			SELECT address FROM identity AS i
			WHERE address = ? AND rowid IN (
				SELECT identity_id FROM my_identity
			) OR rowid IN (
				SELECT identity_id FROM feed_followed
			)
		"#)?;
		let mut rows = stat.query([address.to_string()])?;
		Ok(rows.next()?.is_some())
	}

	/// Returns the lastest object sequence for an actor if available.
	fn _max_object_sequence(tx: &Transaction,
		actor_id: u64
	) -> rusqlite::Result<Option<u64>> {
		let mut stat = tx.prepare(r#"
			SELECT MAX(sequence) FROM object WHERE actor_id = ?
		"#)?;
		let mut rows = stat.query([actor_id])?;
		println!("XXX");
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(row.get(0)?)
		}
	}

	/// Returns the lastest object sequence for an actor if available.
	pub fn max_object_sequence(&self, actor_id: u64) -> rusqlite::Result<Option<u64>> {
		let mut stat = self.0.prepare(r#"
			SELECT MAX(sequence) FROM object WHERE actor_id = ?
		"#)?;
		let mut rows = stat.query([actor_id])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(row.get(0)?)
		}
	}

	/// Returns the sequence that the next object would use.
	fn _next_object_sequence(tx: &Transaction,
		actor_id: u64
	) -> rusqlite::Result<u64> {
		match Self::_max_object_sequence(tx, actor_id)? {
			None => Ok(0),
			Some(s) => Ok(s + 1)
		}
	}

	/// Returns the sequence that the next object would use.
	pub fn next_object_sequence(&self, actor_id: u64) -> rusqlite::Result<u64> {
		match self.max_object_sequence(actor_id)? {
			None => Ok(0),
			Some(s) => Ok(s + 1)
		}
	}

	pub fn open() -> rusqlite::Result<Self> {
		let mut db_path: PathBuf = dirs::home_dir().expect("no home dir found");
		db_path.push(DATABASE_PATH);
		let db_dir = db_path.parent().unwrap();
		if !db_dir.exists() {
			fs::create_dir_all(db_dir).expect("Unable to create stonenet dir");
		}

		Ok(Self (
			UnsafeSendSync::new(rusqlite::Connection::open(&db_path)?)
		))
	}

	fn _store_block(tx: &Transaction,
		file_id: u64,
		sequence: u64,
		hash: &IdType,
		data: &[u8]
	) -> rusqlite::Result<()> {
		let mut stat = tx.prepare(r#"
			INSERT OR REPLACE INTO block (file_id, hash, sequence, size, data)
			VALUES (?, ?, ?, ?, ?)
		"#)?;
		let block_id = stat.insert(rusqlite::params![
			file_id,
			hash.to_string(),
			sequence,
			data.len(),
			data
		])? as u64;

		tx.execute(r#"
			INSERT INTO file_blocks (file_id, block_id) VALUES (?, ?)
		"#, [file_id, block_id])?;
		Ok(())
	}

	fn _store_file(tx: &Transaction,
		mime_type: &str,
		data: &[u8]
	) -> rusqlite::Result<(u64, IdType, Vec<IdType>)> {
		debug_assert!(data.len() <= u64::MAX as usize, "data too large");
		debug_assert!(data.len() > 0, "data can not be empty");
		let block_count = data.len() / BLOCK_SIZE +
			((data.len() % BLOCK_SIZE) > 0) as usize;
		let mut blocks: Vec<&[u8]> = Vec::with_capacity(block_count);
		let mut block_hashes = Vec::with_capacity(block_count);

		// Devide data into blocks
		let mut i = 0;
		loop {
			let slice = &data[i..];
			let actual_block_size = min(BLOCK_SIZE, slice.len());
			blocks.push(&slice[..actual_block_size]);

			i += BLOCK_SIZE;
			if i >= data.len() { break }
		}

		// Calculate the block hashes and the file hash at the same time
		let mut file_hash = IdType::default();
		for i in 0..block_count {
			let block_data = blocks[i];
			let block_hash = IdType::hash(block_data);
			file_hash = file_hash ^ &block_hash;
			block_hashes.push(block_hash);
		}
		
		// Create the file record
		let mut stat = tx.prepare(r#"
			INSERT OR REPLACE INTO file (hash, mime_type, block_count)
			VALUES (?, ?, ?)
		"#)?;
		let file_id = stat.insert(params![
			file_hash.to_string(),
			mime_type,
			block_count
		])?;

		// Create block records
		for i in 0..block_count {
			let block_data = blocks[i];
			let block_hash = &block_hashes[i];

			Self::_store_block(tx, file_id as _, i as _, block_hash, block_data)?;
		}
		Ok((file_id as _, file_hash, block_hashes))
	}

	fn _store_tags(tx: &Transaction,
		post_id: u64,
		tags: &[String]
	) -> rusqlite::Result<()> {
		for tag in tags {
			tx.execute(r#"
				INSERT INTO post_tag (post_id, tag) VALUES (?, ?)
			"#, params![post_id, tag])?;
		}
		Ok(())
	}

	pub fn store_file(&mut self,
		mime_type: &str,
		data: &[u8]
	) -> rusqlite::Result<IdType> {
		let tx = self.0.transaction()?;
		let (_, hash, _) = Self::_store_file(&tx, mime_type, data)?;
		tx.commit()?;
		Ok(hash)
	}

	pub fn store_my_identity(&mut self,
		label: &str,
		address: &IdType,
		keypair: &Keypair
	) -> rusqlite::Result<()> {
		let tx = self.0.transaction()?;

		let mut stat = tx.prepare(r#"
			INSERT INTO identity (address, public_key) VALUES(?,?)
		"#)?;
		let new_id = stat.insert(rusqlite::params![
			address.to_string(),
			keypair.public().as_bytes()
		])?;
		stat = tx.prepare(r#"
			INSERT INTO my_identity (label, identity_id, keypair) VALUES (?,?,?)
		"#).unwrap();
		stat.insert(rusqlite::params![
			label,
			new_id,
			keypair.as_bytes()
		])?;

		drop(stat);
		tx.commit()?;
		Ok(())
	}

	pub fn store_post(&mut self,
		actor_id: u64,
		tags: &[String],
		files: &[FileHeader],
		signature: &Signature
	) -> rusqlite::Result<()> {
		let tx = self.0.transaction()?;

		// Create post object
		let next_sequence = Self::_next_object_sequence(&tx, actor_id)?;
		let mut stat = tx.prepare(r#"
			INSERT INTO object (actor_id, sequence, signature, type)
			VALUES (?,?,?,?)
		"#)?;
		let object_id = stat.insert(params![
			actor_id,
			next_sequence,
			signature.as_bytes(),
			OBJECT_TYPE_POST,
		])?;
		stat = tx.prepare(r#"
			INSERT INTO post_object (object_id, in_reply_to_id) VALUES (?, NULL)
		"#)?;
		let post_object_id = stat.insert([object_id])?;

		// Link all files
		for header in files {
			tx.execute(r#"
				INSERT INTO post_files (post_object_id, file_id)
				SELECT ?, rowid FROM file WHERE hash = ?
			"#, params![post_object_id, header.hash.to_string()])?;
		}

		// Store all tags
		Self::_store_tags(&tx, object_id as _, tags)?;

		drop(stat);
		tx.commit()
	}
}

impl Deref for Connection {
	type Target = rusqlite::Connection;

	fn deref(&self) -> &Self::Target {
		&*self.0
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::SqliteError(e) => write!(f, "{}", e),
			Self::InvalidHash(e) => 
				write!(f, "hash not a valid base58-encoded 32-byte address {}", e),
			Self::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
			Self::InvalidObjectType(code) => write!(f, "invalid object type found in database: {}", code),
			Self::InvalidKeypair(e) => write!(f, "invalid keypair: {}", e),
		}
	}
}

impl From<rusqlite::Error> for Error {
	fn from(other: rusqlite::Error) -> Self {
		Self::SqliteError(other)
	}
}

impl From<SignatureError> for Error {
	fn from(other: SignatureError) -> Self {
		Self::InvalidSignature(other)
	}
}

impl From<IdFromBase58Error> for Error {
	fn from(other: IdFromBase58Error) -> Self {
		Self::InvalidHash(other)
	}
}

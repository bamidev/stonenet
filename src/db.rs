mod install;


use std::{
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
use ed25519::{signature};
use fallible_iterator::FallibleIterator;
use log::*;
use rusqlite::{self, Connection};
use unsafe_send_sync::*;


const DATABASE_PATH: &'static str = ".stonenet/db.sqlite";
const DATABASE_VERSION: (u8, u16, u16) = (0, 0, 0);


pub struct Database (
	// The documentation of rusqlite mentions that the Connection struct does
	// not need a mutex, that it is already thread-safe. For some reason it was
	// not marked as Sync.
	UnsafeSendSync<Connection>
);

#[derive(Debug)]
pub enum Error {
	/// Sqlite error
	SqliteError(rusqlite::Error),
	InvalidObjectType(u8),
	/// An invalid hash has been found in the database
	InvalidHash(IdFromBase58Error),
	InvalidSignature(signature::Error)
}

pub type Result<T> = std::result::Result<T, self::Error>;


impl Database {
	pub fn fetch_object(&self,
		index: u64
	) -> Result<Option<Object>> {
		let mut stat = self.prepare(r#"
			SELECT type, signature FROM object WHERE index = ?
		"#)?;
		let mut rows = stat.query([index])?;
		if let Some(row) = rows.next()? {
			let object_type = row.get(0)?;
			let signature_blob: Vec<u8> = row.get(1)?;
			let signature = Signature::from_bytes(signature_blob.try_into().unwrap());

			let payload = match object_type {
				0 => self.fetch_post_object(index).map(|o| o.map(|p|
					ObjectPayload::Post(p)
				)),
				1 => self.fetch_boost_object(index).map(|o| o.map(|b|
					ObjectPayload::Boost(b)
				)),
				2 => self.fetch_profile_object(index).map(|o| o.map(|p|
					ObjectPayload::Profile(p)
				)),
				3 => self.fetch_move_object(index).map(|o| o.map(|m|
					ObjectPayload::Move(m)
				)),
				other => return Err(Error::InvalidObjectType(other))
			};
			payload.map(|o| o.map(|p| Object {
				index,
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

	pub fn fetch_my_identities(&self) -> 
		Result<Vec<(String, IdType, Keypair)>>
	{
		let mut stat = self.0.prepare(r#"
			SELECT label, i.address, i.keypair FROM my_identity AS mi
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

	pub fn load() -> rusqlite::Result<Self> {
		let mut db_path: PathBuf = dirs::home_dir().expect("no home dir found");
		db_path.push(DATABASE_PATH);
		let db_dir = db_path.parent().unwrap();
		if !db_dir.exists() {
			fs::create_dir_all(db_dir).expect("Unable to create stonenet dir");
		}
		let connection = Connection::open(db_path)?;

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

		Ok(Self (UnsafeSendSync::new(connection)) )
	}

	fn install(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
		conn.execute_batch(install::QUERY)
	}

	fn is_outdated(major: u8, minor: u16, patch: u16) -> bool {
		major < DATABASE_VERSION.0 || minor < DATABASE_VERSION.1 || patch < DATABASE_VERSION.2
	}

	fn upgrade(_conn: &rusqlite::Connection) {
		panic!("No database upgrade implemented yet!");
	}
}

impl Deref for Database {
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
			Self::InvalidObjectType(code) => write!(f, "invalid object type found in database: {}", code)
		}
	}
}

impl From<rusqlite::Error> for Error {
	fn from(other: rusqlite::Error) -> Self {
		Self::SqliteError(other)
	}
}

impl From<signature::Error> for Error {
	fn from(other: signature::Error) -> Self {
		Self::InvalidSignature(other)
	}
}

impl From<IdFromBase58Error> for Error {
	fn from(other: IdFromBase58Error) -> Self {
		Self::InvalidHash(other)
	}
}

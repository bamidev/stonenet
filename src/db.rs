// FIXME: Remove when going stable:
#![allow(dead_code)]

pub mod file_loader;
mod install;

use std::{cmp::min, fmt, net::SocketAddr, ops::*, path::*};

use chrono::*;
use fallible_iterator::FallibleIterator;
use log::*;
use rusqlite::{self, params, Rows, Transaction};
use serde::Serialize;

pub use self::file_loader::FileLoader;
use crate::{common::*, identity::*, model::*, net::binserde};

const DATABASE_VERSION: (u8, u16, u16) = (0, 0, 0);
pub(crate) const BLOCK_SIZE: usize = 0x100000; // 1 MiB

#[derive(Clone)]
pub struct Database {
	path: PathBuf,
}

pub struct Connection(
	// The documentation of rusqlite mentions that the Connection struct does
	// not need a mutex, that it is already thread-safe. For some reason it was
	// not marked as Send and Sync.
	rusqlite::Connection,
);

#[derive(Debug)]
pub enum Error {
	/// Sqlite error
	SqliteError(rusqlite::Error),
	InvalidObjectType(u8),
	/// An invalid hash has been found in the database
	InvalidHash(IdFromBase58Error),
	InvalidSignature(SignatureError),
	//InvalidPrivateKey(PrivateKeyError),
	InvalidPublicKey(Option<PublicKeyError>),
	/// The data that is stored for a block is corrupt
	BlockDataCorrupt(i64),
	PostMissingFiles(i64),
	FileMissingBlock(i64, u64),

	MissingIdentity(IdType),
}

#[derive(Serialize)]
pub struct BoostObjectInfo {
	pub original_post: TargetedPostInfo,
}

pub trait DerefConnection: Deref<Target = rusqlite::Connection> {}
impl<T> DerefConnection for T where T: Deref<Target = rusqlite::Connection> {}

#[derive(Serialize)]
pub struct TargetedActorInfo {
	pub id: IdType,
	pub name: String,
	pub avatar_id: Option<IdType>,
	pub wallpaper_id: Option<IdType>,
}


#[derive(Debug, Serialize)]
pub enum PossiblyKnownFileHeader {
	Unknown(IdType),
	Known(FileHeader),
}

#[derive(Debug, Serialize)]
pub struct TargetedPostInfo {
	pub actor_id: IdType,
	pub actor_name: Option<String>,
	pub actor_avatar: Option<IdType>,
	pub sequence: u64,
	pub message: Option<(String, String)>,
	pub attachments: Vec<PossiblyKnownFileHeader>,
}

#[derive(Debug, Serialize)]
pub struct PostObjectInfo {
	pub in_reply_to: Option<TargetedPostInfo>,
	pub sequence: u64,
	pub message: Option<String>,
	pub mime_type: Option<String>,
	pub attachments: Vec<PossiblyKnownFileHeader>,
}

#[derive(Serialize)]
pub struct ProfileObjectInfo {
	pub actor: TargetedActorInfo,
	pub description: Option<String>,
}

#[derive(Serialize)]
pub struct MoveObjectInfo {
	pub new_actor: TargetedActorInfo,
}

#[derive(Serialize)]
pub struct ObjectInfo {
	pub hash: IdType,
	pub created: u64,
	pub found: u64,
	pub actor_id: IdType,
	pub actor_name: Option<String>,
	pub actor_avatar: Option<IdType>,
	pub payload: ObjectPayloadInfo,
}

#[derive(Serialize)]
pub enum ObjectPayloadInfo {
	Post(PostObjectInfo),
	Boost(BoostObjectInfo),
	Profile(ProfileObjectInfo),
	Move(MoveObjectInfo),
}

pub type Result<T> = std::result::Result<T, self::Error>;

impl Database {
	pub fn connect(&self) -> rusqlite::Result<Connection> { Ok(Connection::open(&self.path)?) }

	fn install(conn: &Connection) -> rusqlite::Result<()> { conn.execute_batch(install::QUERY) }

	fn is_outdated(major: u8, minor: u16, patch: u16) -> bool {
		major < DATABASE_VERSION.0 || minor < DATABASE_VERSION.1 || patch < DATABASE_VERSION.2
	}

	pub fn load(path: PathBuf) -> rusqlite::Result<Self> {
		let connection = Connection::open(&path)?;

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
			}
			Err(e) => match &e {
				rusqlite::Error::SqliteFailure(_err, msg) => match msg {
					Some(error_message) =>
						if error_message == "no such table: version" {
							Self::install(&connection)?;
						} else {
							return Err(e);
						},
					None => return Err(e),
				},
				_ => return Err(e),
			},
		}

		Ok(Self { path })
	}

	fn upgrade(_conn: &rusqlite::Connection) {
		panic!("No database upgrade implemented yet!");
	}
}

impl Connection {
	fn _fetch_actor_info<C>(this: &C, identity_id: i64) -> Result<Option<TargetedActorInfo>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT i.address, p.name, af.hash, wf.hash
			FROM identity AS i
			LEFT JOIN profile AS p ON p.identity_id = i.rowid
			LEFT JOIN file AS af ON p.avatar_file_id = f.rowid
			LEFT JOIN file AS wf ON p.wallpaper_file_id = f.rowid
			WHERE rowid = ?
		"#,
		)?;
		let mut rows = stat.query([identity_id])?;
		if let Some(row) = rows.next()? {
			let id_hash: String = row.get(0)?;
			let id = IdType::from_base58(&id_hash)?;
			let name = row.get(1)?;
			let avatar_hash: Option<String> = row.get(2)?;
			let avatar_id = match avatar_hash.as_ref() {
				None => None,
				Some(hash) => Some(IdType::from_base58(hash)?),
			};
			let wallpaper_hash: Option<String> = row.get(3)?;
			let wallpaper_id = match wallpaper_hash.as_ref() {
				None => None,
				Some(hash) => Some(IdType::from_base58(hash)?),
			};

			Ok(Some(TargetedActorInfo {
				id,
				name,
				avatar_id,
				wallpaper_id,
			}))
		} else {
			Ok(None)
		}
	}

	fn _fetch_block_data<C>(this: &C, id: &IdType) -> Result<Option<Vec<u8>>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT rowid, size, data FROM block WHERE hash = ?
		"#,
		)?;
		let mut rows = stat.query([id.to_string()])?;
		if let Some(row) = rows.next()? {
			let rowid: i64 = row.get(0)?;
			let size: usize = row.get(1)?;
			let data: Vec<u8> = row.get(2)?;

			if data.len() < size {
				Err(Error::BlockDataCorrupt(rowid))
			} else if data.len() > size {
				warn!(
					"Block {} data blob is is larger than its size: {} > {}",
					id,
					data.len(),
					size
				);
				Ok(Some(data[..size].to_vec()))
			} else {
				Ok(Some(data))
			}
		} else {
			Ok(None)
		}
	}

	fn _fetch_file<C>(this: &C, hash: &IdType) -> Result<Option<(String, Vec<u8>)>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT rowid, mime_type, block_count FROM file WHERE hash = ?
		"#,
		)?;
		let mut rows = stat.query([hash.to_string()])?;
		if let Some(row) = rows.next()? {
			let rowid = row.get(0)?;
			let mime_type = row.get(1)?;
			let block_count = row.get(2)?;

			let data = Self::_fetch_file_data(this, rowid, block_count)?;
			Ok(Some((mime_type, data)))
		} else {
			Ok(None)
		}
	}

	fn _fetch_file_data<C>(this: &C, file_id: i64, block_count: u64) -> Result<Vec<u8>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT fb.block_hash, fb.sequence, b.rowid, b.size, b.data
			FROM file_blocks AS fb
			LEFT JOIN block AS b ON fb.block_hash = b.hash
			WHERE file_id = ?
			ORDER BY fb.sequence ASC
		"#,
		)?;
		let mut rows = stat.query([file_id])?;

		// If block count is 1, chances are high that its size is pretty small.
		// If that is the case, preallocation of the buffer isn't really
		// necessary.
		let capacity = if block_count == 1 {
			0
		} else {
			block_count as usize * BLOCK_SIZE
		};
		let mut buffer = Vec::with_capacity(capacity);
		let mut i = 0;
		while let Some(row) = rows.next()? {
			let _block_hash: String = row.get(0)?;
			let sequence: u64 = row.get(1)?;
			if sequence != i {
				return Err(Error::FileMissingBlock(file_id, sequence));
			}
			let block_id: Option<i64> = row.get(2)?;
			let size2: Option<usize> = row.get(3)?;
			let data2: Option<Vec<u8>> = row.get(4)?;

			if block_id.is_none() {
				return Err(Error::FileMissingBlock(file_id, sequence));
			}
			let size = size2.unwrap();
			let data = data2.unwrap();

			if data.len() < size {
				return Err(Error::BlockDataCorrupt(block_id.unwrap()));
			} else if data.len() > size {
				warn!(
					"Block {} has more data than its size: {} > {}",
					block_id.unwrap(),
					data.len(),
					size
				);
			}

			buffer.extend(&data[..size]);
			i += 1;
		}

		Ok(buffer)
	}

	fn _fetch_object<C>(
		this: &C, actor_id: &IdType, hash: &IdType,
	) -> Result<Option<(IdType, Object, bool)>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT o.rowid, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM object AS o
			INNER JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ? AND o.hash = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id.to_string(), hash.to_string()])?;
		Self::_parse_object(this, &mut rows)
	}

	fn _fetch_object_by_sequence<C>(
		this: &C, actor_id: &IdType, sequence: u64,
	) -> Result<Option<(IdType, Object, bool)>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT o.rowid, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM object AS o
			INNER JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id.to_string(), sequence])?;
		Self::_parse_object(this, &mut rows)
	}

	pub fn _fetch_object_hash_by_sequence<C>(
		this: &C, _actor: &IdType, sequence: u64,
	) -> Result<IdType>
	where
		C: DerefConnection,
	{
		let string: String = this.query_row(
			r#"
			SELECT hash FROM object WHERE sequence = ?
		"#,
			[sequence],
			|r| r.get(0),
		)?;
		let id = IdType::from_base58(&string)?;
		Ok(id)
	}

	fn _fetch_object_id_by_sequence<C>(
		this: &C, actor_id: i64, sequence: u64,
	) -> Result<Option<i64>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT rowid FROM object WHERE actor_id = ? AND sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, sequence])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => {
				let object_id = row.get(0)?;
				Ok(Some(object_id))
			}
		}
	}

	fn _fetch_head<C>(tx: &C, actor_id: &IdType) -> Result<Option<(IdType, Object, bool)>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT o.rowid, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ?
			ORDER BY sequence DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query([actor_id.to_string()])?;
		Self::_parse_object(tx, &mut rows)
	}

	fn _fetch_last_verified_object<C>(
		tx: &C, actor_id: &IdType,
	) -> Result<Option<(IdType, Object, bool)>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT o.rowid, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ? AND o.verified_from_start = TRUE
			ORDER BY sequence DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query([actor_id.to_string()])?;
		Self::_parse_object(tx, &mut rows)
	}

	/*pub fn _fetch_post_files(&self, post_id: i64) -> Result<Vec<FileHeader>> {
		let mut stat = self.0.prepare(
			r#"
			SELECT hash, mime_type, block_count FROM file WHERE post_id = ?
		"#,
		)?;
		let mut rows = stat.query([post_id])?;
		let mut files = Vec::new();
		while let Some(row) = rows.next()? {
			let hash: String = row.get(0)?;
			let hash_id = IdType::from_base58(&hash)?;
			files.push(FileHeader {
				hash: hash_id,
				mime_type: row.get(1)?,
				block_count: row.get(2)?,
			});
		}
		Ok(files)
	}*/

	pub fn _fetch_boost_object<C>(this: &C, object_id: i64) -> Result<Option<BoostObject>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT post_actor_address, object_sequence
			FROM boost_object
			WHERE object_id = ?
		"#,
		)?;
		let mut rows = stat.query([object_id])?;
		if let Some(row) = rows.next()? {
			let post_actor_address: String = row.get(0)?;
			let object_sequence = row.get(1)?;
			let post_actor_id = IdType::from_base58(&post_actor_address)?;

			Ok(Some(BoostObject {
				post_actor_id,
				object_sequence,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _fetch_boost_object_info<C>(
		this: &C, _actor_id: i64, sequence: u64,
	) -> Result<Option<BoostObjectInfo>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT o.rowid, o.sequence, bo.actor_hash, p.name, f.hash
			FROM boost_object AS bo
			LEFT JOIN object AS o ON bo.object_id = o.rowid
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			LEFT JOIN profile AS p ON bo.actor_hash = identity.address
			LEFT JOIN file AS f ON profile.avatar_file_id = af.rowid
			WHERE o.actor_id ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query([sequence])?;
		if let Some(row) = rows.next()? {
			let object_id = row.get(0)?;
			let sequence = row.get(1)?;
			let actor_address: String = row.get(2)?;
			let post_actor_id = IdType::from_base58(&actor_address)?;
			let post_actor_name: Option<String> = row.get(3)?;
			let post_actor_avatar_hash: Option<String> = row.get(4)?;
			let post_actor_avatar_id = match post_actor_avatar_hash.as_ref() {
				None => None,
				Some(hash) => Some(IdType::from_base58(hash)?),
			};

			let (message, attachments) = Self::_fetch_post_object_info_files(this, object_id)?;
			Ok(Some(BoostObjectInfo {
				original_post: TargetedPostInfo {
					actor_id: post_actor_id,
					actor_name: post_actor_name,
					actor_avatar: post_actor_avatar_id,
					sequence,
					message,
					attachments,
				},
			}))
		} else {
			Ok(None)
		}
	}

	fn _fetch_move_object<C>(this: &C, object_id: i64) -> Result<Option<MoveObject>>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT i.address
			FROM move_object AS mo
			LEFT JOIN identity AS i ON mo.new_actor_id = i.rowid
			WHERE mo.object_id = ?
		"#,
		)?;
		let mut rows = stat.query([object_id])?;
		if let Some(row) = rows.next()? {
			let actor_address: String = row.get(0)?;
			let actor_id = IdType::from_base58(&actor_address)?;

			Ok(Some(MoveObject {
				new_actor_id: actor_id,
			}))
		} else {
			Ok(None)
		}
	}

	fn _fetch_move_object_info<C>(
		this: &C, actor_id: i64, sequence: u64,
	) -> Result<Option<MoveObjectInfo>>
	where
		C: DerefConnection,
	{
		let result = Self::_fetch_object_id_by_sequence(this, actor_id, sequence)?;
		if let Some(object_id) = result {
			let actor_info = Self::_fetch_actor_info(this, object_id)?;
			Ok(actor_info.map(|a| MoveObjectInfo { new_actor: a }))
		} else {
			Ok(None)
		}
	}

	fn _fetch_post_files(this: &impl DerefConnection, post_id: i64) -> Result<Vec<IdType>> {
		// Collect the files
		let mut files = Vec::new();
		let mut stat = this.prepare(
			r#"
			SELECT hash
			FROM post_files
			WHERE post_id = ?
			ORDER BY sequence ASC
		"#,
		)?;
		let mut rows = stat.query([post_id])?;
		while let Some(row) = rows.next()? {
			let hash: String = row.get(0)?;

			files.push(IdType::from_base58(&hash)?);
		}

		Ok(files)
	}

	fn _fetch_post_object_info_files<C>(
		this: &C, post_id: i64,
	) -> Result<(Option<(String, String)>, Vec<PossiblyKnownFileHeader>)>
	where
		C: DerefConnection,
	{
		let mut stat = this.prepare(
			r#"
			SELECT file_count FROM post_object WHERE rowid = ?
		"#,
		)?;
		let mut rows = stat.query([post_id])?;
		if let Some(row) = rows.next()? {
			let file_count: u64 = row.get(0)?;

			// Collect the message file
			let mut stat = this.prepare(
				r#"
				SELECT f.rowid, f.mime_type, f.block_count
				FROM post_files AS pf
				LEFT JOIN file AS f ON pf.hash = f.hash
				WHERE pf.post_id = ? AND pf.sequence = 0
				ORDER BY pf.sequence ASC
			"#,
			)?;
			let mut rows = stat.query([post_id])?;
			let message_opt: Option<(String, String)> = if let Some(row) = rows.next()? {
				let file_id_opt: Option<i64> = row.get(0)?;
				let mime_type_opt: Option<String> = row.get(1)?;
				let block_count_opt: Option<u64> = row.get(2)?;
				if let Some(file_id) = file_id_opt {
					let mime_type = mime_type_opt.unwrap();
					let block_count = block_count_opt.unwrap();
					match Self::_fetch_file_data(this, file_id, block_count) {
						Ok(message_data) => Some((
							String::from_utf8_lossy(&message_data).to_string(),
							mime_type,
						)),
						Err(e) => match e {
							// If a block is still missing from the message data file, don't
							// actually raise an error, just leave the message data unset.
							Error::FileMissingBlock(..) => None,
							other => return Err(other),
						},
					}
				} else {
					None
				}
			} else {
				None
			};

			// Collect the files
			let mut attachments = Vec::with_capacity(file_count as _);
			let mut stat = this.prepare(
				r#"
				SELECT pf.hash, f.mime_type, f.block_count
				FROM post_files AS pf
				LEFT JOIN file AS f ON f.hash = pf.hash
				WHERE pf.post_id = ? AND pf.sequence > 0
				ORDER BY pf.sequence ASC
			"#,
			)?;
			let mut rows = stat.query([post_id])?;
			while let Some(row) = rows.next()? {
				let hash_str: String = row.get(0)?;
				let hash = IdType::from_base58(&hash_str)?;
				let mime_type_opt: Option<String> = row.get(1)?;
				let block_count_opt: Option<u32> = row.get(2)?;
				let attachment = if let Some(mime_type) = mime_type_opt {
					let block_count = block_count_opt.unwrap();
					PossiblyKnownFileHeader::Known(FileHeader {
						hash,
						mime_type,
						block_count,
					})
				} else {
					PossiblyKnownFileHeader::Unknown(hash)
				};
				attachments.push(attachment);
			}

			Ok((message_opt, attachments))
		} else {
			Ok((None, Vec::new()))
		}
	}

	fn _fetch_post_object_info(
		this: &impl DerefConnection, actor_id: i64, sequence: u64,
	) -> Result<Option<PostObjectInfo>> {
		let mut stat = this.prepare(
			r#"
			SELECT po.rowid, o.sequence, ti.rowid, ti.address, to_.rowid, to_.sequence
			FROM post_object AS po
			INNER JOIN object AS o ON po.object_id = o.rowid
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			LEFT JOIN identity AS ti ON po.in_reply_to_actor_hash = ti.address
			LEFT JOIN object AS to_ ON to_.actor_id = ti.rowid
			                       AND to_.hash = po.in_reply_to_object_hash
			WHERE o.actor_id = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, sequence])?;
		if let Some(row) = rows.next()? {
			let post_id = row.get(0)?;
			let sequence = row.get(1)?;
			let irt_actor_id: Option<i64> = row.get(2)?;
			let irt_actor_address: Option<String> = row.get(3)?;
			let irt_object_id: Option<i64> = row.get(4)?;
			let irt_sequence: Option<u64> = row.get(5)?;

			let in_reply_to = match irt_object_id {
				None => None,
				Some(irt_post_id) => {
					let (irt_actor_name, irt_actor_avatar_id) = match irt_actor_id {
						None => (None, None),
						Some(id) => Self::_find_profile_limited(this, id)?,
					};
					let irt_actor_id = IdType::from_base58(&irt_actor_address.unwrap())?;
					let (irt_message_opt, irt_attachments) =
						Self::_fetch_post_object_info_files(this, irt_post_id)?;
					Some(TargetedPostInfo {
						actor_id: irt_actor_id,
						actor_name: irt_actor_name,
						actor_avatar: irt_actor_avatar_id,
						sequence: irt_sequence.unwrap(),
						message: irt_message_opt,
						attachments: irt_attachments,
					})
				}
			};
			let (message_opt, attachments) = Self::_fetch_post_object_info_files(this, post_id)?;
			Ok(Some(PostObjectInfo {
				in_reply_to,
				sequence,
				message: message_opt.as_ref().map(|o| o.0.clone()),
				mime_type: message_opt.map(|o| o.1),
				attachments,
			}))
		} else {
			Ok(None)
		}
	}

	fn _fetch_post_object(
		this: &impl DerefConnection, object_id: i64,
	) -> Result<Option<PostObject>> {
		let mut stat = this.prepare(
			r#"
			SELECT rowid, in_reply_to_actor_hash, in_reply_to_object_hash
			FROM post_object
			WHERE object_id = ?
		"#,
		)?;
		let mut rows = stat.query([object_id])?;
		if let Some(row) = rows.next()? {
			let post_id: i64 = row.get(0)?;
			let irt_actor_address: Option<String> = row.get(1)?;
			let irt_object_hash: Option<String> = row.get(2)?;
			let irt_actor_id = match irt_actor_address {
				None => None,
				Some(string) => Some(IdType::from_base58(&string)?),
			};
			let irt_object_id = match irt_object_hash {
				None => None,
				Some(string) => Some(IdType::from_base58(&string)?),
			};
			let tags = Self::_fetch_post_tags(this, post_id)?;
			let files = Self::_fetch_post_files(this, post_id)?;

			Ok(Some(PostObject {
				in_reply_to: if irt_actor_id.is_some() && irt_object_id.is_some() {
					Some((irt_actor_id.unwrap(), irt_object_id.unwrap()))
				} else {
					None
				},
				tags,
				files,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _fetch_profile_object(
		this: &impl DerefConnection, object_id: i64,
	) -> Result<Option<ProfileObject>> where
		//C: DerefConnection
	{
		let mut stat = this.prepare(
			r#"
			SELECT name, avatar_file_hash, wallpaper_file_hash, description_block_hash
			FROM profile_object
			WHERE object_id = ?
		"#,
		)?;
		let mut rows = stat.query([object_id])?;
		if let Some(row) = rows.next()? {
			let name: Option<String> = row.get(0)?;
			if name.is_none() {
				return Ok(None);
			}
			let avatar_hash: Option<String> = row.get(1)?;
			let avatar_id = match avatar_hash.as_ref() {
				None => None,
				Some(hash) => Some(IdType::from_base58(hash)?),
			};
			let wallpaper_hash: Option<String> = row.get(2)?;
			let wallpaper_id = match wallpaper_hash.as_ref() {
				None => None,
				Some(hash) => Some(IdType::from_base58(hash)?),
			};
			let description_block_hash: Option<String> = row.get(3)?;
			let description_block_id = match description_block_hash.as_ref() {
				None => None,
				Some(hash) => Some(IdType::from_base58(hash)?),
			};
			Ok(Some(ProfileObject {
				name: name.unwrap(),
				avatar: avatar_id,
				wallpaper: wallpaper_id,
				description: description_block_id,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _fetch_profile_object_info(
		this: &impl DerefConnection, actor_id: i64, sequence: u64,
	) -> Result<Option<ProfileObjectInfo>> where
		//C: DerefConnection
	{
		let mut stat = this.prepare(
			r#"
			SELECT i.address, po.name, po.avatar_file_hash, po.wallpaper_file_hash, db.data
			FROM profile_object AS po
			LEFT JOIN object AS o ON po.object_id = o.rowid
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			LEFT JOIN block AS db ON po.description_block_hash = db.hash
			WHERE o.actor_id = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id, sequence])?;
		if let Some(row) = rows.next()? {
			let actor_hash: String = row.get(0)?;
			let actor_id = IdType::from_base58(&actor_hash)?;
			let actor_name: String = row.get(1)?;
			let avatar_hash: Option<String> = row.get(2)?;
			let avatar_id = match avatar_hash {
				None => None,
				Some(hash) => Some(IdType::from_base58(&hash)?),
			};
			let wallpaper_hash: Option<String> = row.get(3)?;
			let wallpaper_id = match wallpaper_hash {
				None => None,
				Some(hash) => Some(IdType::from_base58(&hash)?),
			};
			let description_data: Option<Vec<u8>> = row.get(4)?;
			let description = match description_data {
				None => None,
				Some(data) => Some(String::from_utf8_lossy(&data).to_string()),
			};

			Ok(Some(ProfileObjectInfo {
				actor: TargetedActorInfo {
					id: actor_id,
					name: actor_name,
					avatar_id,
					wallpaper_id,
				},
				description,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _fetch_post_tags(tx: &impl DerefConnection, post_id: i64) -> Result<Vec<String>> {
		let mut stat = tx.prepare(
			r#"
			SELECT tag FROM post_tag WHERE post_id = ?
		"#,
		)?;
		let rows = stat.query([post_id])?;
		rows.map(|r| r.get(0)).collect().map_err(|e| e.into())
	}

	/// Finds the profile info of an actor.
	/*fn _find_profile(
		tx: &impl DerefConnection, actor_id: i64,
	) -> Result<Option<ProfileObject>> {
		let mut stat = tx.prepare(
			r#"
			SELECT po.name, po.avatar_file_hash, po.wallpaper_file_hash, po.description_block_hash
			FROM profile_object AS po
			INNER JOIN object AS o ON po.object_id = o.rowid
			WHERE o.actor_id = ?
			ORDER BY po.rowid DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query([actor_id])?;
		Ok(if let Some(row) = rows.next()? {
			let name: String = row.get(0)?;
			let avatar_hash: Option<String> = row.get(1)?;
			let avatar_id = match avatar_hash {
				None => None,
				Some(h) => Some(IdType::from_base58(&h)?),
			};

			(Some(name), avatar_id)
		} else {
			(None, None)
		})
	}*/

	pub(crate) fn _find_identity<C>(tx: &C, address: &IdType) -> rusqlite::Result<Option<i64>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT rowid FROM identity WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query([address.to_string()])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(Some(row.get(0)?)),
		}
	}

	/// Finds the name and avatar file hash of an actor.
	fn _find_profile_limited(
		tx: &impl DerefConnection, actor_id: i64,
	) -> Result<(Option<String>, Option<IdType>)> {
		let mut stat = tx.prepare(
			r#"
			SELECT po.name, po.avatar_file_hash
			FROM profile_object AS po
			INNER JOIN object AS o ON po.object_id = o.rowid
			WHERE o.actor_id = ?
			ORDER BY po.rowid DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query([actor_id])?;
		Ok(if let Some(row) = rows.next()? {
			let name: String = row.get(0)?;
			let avatar_hash: Option<String> = row.get(1)?;
			let avatar_id = match avatar_hash {
				None => None,
				Some(h) => Some(IdType::from_base58(&h)?),
			};

			(Some(name), avatar_id)
		} else {
			(None, None)
		})
	}

	/// Returns the lastest object sequence for an actor if available.
	fn _max_object_sequence<C>(tx: &C, actor_id: i64) -> rusqlite::Result<Option<u64>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT MAX(sequence) FROM object WHERE actor_id = ?
		"#,
		)?;
		let mut rows = stat.query([actor_id])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(row.get(0)?),
		}
	}

	/// Returns the lastest object sequence for an actor if available.
	fn _max_object_sequence_by_address<C>(
		tx: &C, actor_address: &IdType,
	) -> rusqlite::Result<Option<u64>>
	where
		C: DerefConnection,
	{
		let mut stat = tx.prepare(
			r#"
			SELECT MAX(o.sequence)
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ?
		"#,
		)?;
		let mut rows = stat.query([actor_address.to_string()])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(row.get(0)?),
		}
	}

	/// Returns the sequence that the next object would use.
	pub(crate) fn _next_object_sequence<C>(tx: &C, actor_id: i64) -> Result<u64>
	where
		C: DerefConnection,
	{
		match Self::_max_object_sequence(tx, actor_id)? {
			None => Ok(0),
			Some(s) => Ok(s + 1),
		}
	}

	/// Returns the sequence that the next object would use.
	fn _next_object_sequence_by_address<C>(tx: &C, actor_address: &IdType) -> Result<u64>
	where
		C: DerefConnection,
	{
		match Self::_max_object_sequence_by_address(tx, actor_address)? {
			None => Ok(0),
			Some(s) => Ok(s + 1),
		}
	}

	fn _parse_object(
		tx: &impl DerefConnection, rows: &mut Rows<'_>,
	) -> Result<Option<(IdType, Object, bool)>> {
		if let Some(row) = rows.next()? {
			let object_id = row.get(0)?;
			let sequence = row.get(1)?;
			let created = row.get(2)?;
			let raw_signature: Vec<u8> = row.get(3)?;
			let hash_string: String = row.get(4)?;
			let object_type = row.get(5)?;
			let previous_hash_string: Option<String> = row.get(6)?;
			let verified_from_start: bool = row.get(7)?;
			let signature = Signature::from_bytes(raw_signature.as_slice().try_into().unwrap());
			let hash = IdType::from_base58(&hash_string)?;
			let previous_hash = match previous_hash_string {
				None => IdType::default(),
				Some(string) => IdType::from_base58(&string)?,
			};

			let payload = match object_type {
				0 => Self::_fetch_post_object(tx, object_id)
					.map(|o| o.map(|p| ObjectPayload::Post(p))),
				1 => Self::_fetch_boost_object(tx, object_id)
					.map(|o| o.map(|b| ObjectPayload::Boost(b))),
				2 => Self::_fetch_profile_object(tx, object_id)
					.map(|o| o.map(|p| ObjectPayload::Profile(p))),
				other => return Err(Error::InvalidObjectType(other)),
			};
			payload.map(|o| {
				o.map(|p| {
					(
						hash,
						Object {
							sequence,
							previous_hash,
							created,
							signature,
							payload: p,
						},
						verified_from_start,
					)
				})
			})
		} else {
			Ok(None)
		}
	}

	fn _parse_object_info(
		tx: &impl DerefConnection, rows: &mut Rows<'_>,
	) -> Result<Option<ObjectInfo>> {
		if let Some(row) = rows.next()? {
			let actor_id = row.get(0)?;
			let hash_string: String = row.get(1)?;
			let hash = IdType::from_base58(&hash_string)?;
			let sequence = row.get(2)?;
			let created = row.get(3)?;
			let found = row.get(4)?;
			let object_type = row.get(5)?;
			let actor_address_hash: String = row.get(6)?;
			let actor_address = IdType::from_base58(&actor_address_hash)?;

			let (actor_name, actor_avatar_id) = Self::_find_profile_limited(tx, actor_id)?;
			let payload_result = match object_type {
				0 => Self::_fetch_post_object_info(tx, actor_id, sequence)
					.map(|o| o.map(|p| ObjectPayloadInfo::Post(p))),
				1 => Self::_fetch_boost_object_info(tx, actor_id, sequence)
					.map(|o| o.map(|b| ObjectPayloadInfo::Boost(b))),
				2 => Self::_fetch_profile_object_info(tx, actor_id, sequence)
					.map(|o| o.map(|p| ObjectPayloadInfo::Profile(p))),
				3 => Self::_fetch_move_object_info(tx, actor_id, sequence)
					.map(|o| o.map(|m| ObjectPayloadInfo::Move(m))),
				other => return Err(Error::InvalidObjectType(other)),
			};
			let payload = if let Some(p) = payload_result? {
				p
			} else {
				return Ok(None);
			};
			Ok(Some(ObjectInfo {
				hash,
				created,
				found,
				actor_id: actor_address,
				actor_name,
				actor_avatar: actor_avatar_id,
				payload,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn _store_block(
		tx: &impl DerefConnection, actor_id: i64, hash: &IdType, data: &[u8],
	) -> rusqlite::Result<i64> {
		let mut stat = tx.prepare(
			r#"
			INSERT INTO block (hash, actor_id, size, data) VALUES (?,?,?,?)
		"#,
		)?;
		stat.insert(params![hash.to_string(), actor_id, data.len(), data])
	}

	pub(crate) fn _store_file_data(
		tx: &Transaction, actor_id: i64, mime_type: &str, data: &[u8],
	) -> rusqlite::Result<(i64, IdType, Vec<IdType>)> {
		debug_assert!(data.len() <= u64::MAX as usize, "data too large");
		debug_assert!(data.len() > 0, "data can not be empty");
		let block_count = data.len() / BLOCK_SIZE + ((data.len() % BLOCK_SIZE) > 0) as usize;
		let mut blocks: Vec<&[u8]> = Vec::with_capacity(block_count);
		let mut block_hashes = Vec::with_capacity(block_count);

		// Devide data into blocks
		let mut i = 0;
		loop {
			let slice = &data[i..];
			let actual_block_size = min(BLOCK_SIZE, slice.len());
			blocks.push(&slice[..actual_block_size]);

			i += BLOCK_SIZE;
			if i >= data.len() {
				break;
			}
		}

		// Calculate the block hashes
		for i in 0..block_count {
			let block_data = blocks[i];
			let block_hash = IdType::hash(block_data);
			block_hashes.push(block_hash);
		}

		// Calculate the file hash
		let file_hash = IdType::hash(
			&binserde::serialize(&File {
				mime_type: mime_type.to_string(),
				blocks: block_hashes.clone(),
			})
			.unwrap(),
		);
		// FIXME: Prevent the unnecessary cloning just to calculate the file hash

		// Create the file record
		let mut stat = tx.prepare(
			r#"
			INSERT INTO file (actor_id, hash, mime_type, block_count)
			VALUES (?,?,?,?)
		"#,
		)?;
		let file_id = stat.insert(params![
			actor_id,
			file_hash.to_string(),
			mime_type,
			block_count
		])?;

		// Create block records
		for i in 0..block_count {
			let block_data = blocks[i];
			let block_hash = &block_hashes[i];

			Self::_store_file_block(tx, actor_id, file_id, i as _, block_hash, block_data)?;
		}
		Ok((file_id as _, file_hash, block_hashes))
	}

	/*fn _store_file_record(tx: &impl DerefConnection, actor_id: i64, hash: &IdType, mime_type: &str, block_count: u32) -> rusqlite::Result<i64> {
		tx.execute(r#"
			INSERT INTO file (actor_id, hash, mime_type, block_count)
			VALUES (?,?,?,?)
		"#, params![actor_id, hash.to_string(), mime_type, block_count])?;
		Ok(())
	}*/

	pub(crate) fn _store_file(
		tx: &impl DerefConnection, actor_id: i64, id: &IdType, mime_type: &str, blocks: &[IdType],
	) -> rusqlite::Result<i64> {
		debug_assert!(blocks.len() <= u32::MAX as usize, "too many blocks");
		debug_assert!(blocks.len() > 0, "file must have at least one block");

		// Create the file record
		let mut stat = tx.prepare(
			r#"
			INSERT INTO file (actor_id, hash, mime_type, block_count)
			VALUES (?,?,?,?)
		"#,
		)?;
		let file_id = stat.insert(params![actor_id, id.to_string(), mime_type, blocks.len()])?;

		// Create block records
		for i in 0..blocks.len() {
			let hash = &blocks[i];
			tx.execute(
				r#"
				INSERT INTO file_blocks (file_id, block_hash, sequence)
				VALUES (?,?,?)
			"#,
				params![file_id, hash.to_string(), i],
			)?;
		}

		Ok(file_id)
	}

	fn _store_file_block(
		tx: &Transaction, actor_id: i64, file_id: i64, sequence: u64, hash: &IdType, data: &[u8],
	) -> rusqlite::Result<()> {
		let mut stat = tx.prepare(
			r#"
			INSERT INTO block (actor_id, hash, size, data)
			VALUES (?,?,?,?)
		"#,
		)?;
		let _block_id = stat.insert(rusqlite::params![
			actor_id,
			hash.to_string(),
			data.len(),
			data
		])?;

		tx.execute(
			r#"
			INSERT INTO file_blocks (file_id, block_hash, sequence) VALUES (?,?,?)
		"#,
			params![file_id, hash.to_string(), sequence],
		)?;
		Ok(())
	}

	fn _store_identity(
		tx: &impl DerefConnection, address: &IdType, public_key: &PublicKey, first_object: &IdType,
	) -> rusqlite::Result<i64> {
		let mut stat = tx.prepare(
			r#"
			INSERT INTO identity (address, public_key, first_object, type) VALUES (?,?,?, 'feed')
		"#,
		)?;
		stat.insert(params![
			address.to_string(),
			public_key.as_bytes(),
			first_object.to_string()
		])
	}

	fn _store_my_identity(
		tx: &impl DerefConnection, label: &str, private_key: &PrivateKey, first_object: &IdType,
		actor_type: String,
	) -> rusqlite::Result<i64> {
		let actor_info = ActorInfo {
			public_key: private_key.public(),
			first_object: first_object.clone(),
			actor_type,
		};
		let address = actor_info.generate_id();
		let identity_id =
			Self::_store_identity(tx, &address, &actor_info.public_key, first_object)?;

		let mut stat = tx.prepare(
			r#"
			INSERT INTO my_identity (label, identity_id, private_key) VALUES (?,?,?)
		"#,
		)?;
		stat.insert(params![label, identity_id, private_key.as_bytes()])?;
		Ok(identity_id)
	}

	pub fn _store_object(
		tx: &impl DerefConnection, actor_hash: &IdType, id: &IdType, object: &Object,
		verified_from_start: bool,
	) -> Result<i64> {
		let mut stat = tx.prepare(
			r#"
			SELECT rowid FROM identity WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query([actor_hash.to_string()])?;
		if let Some(row) = rows.next()? {
			let actor_rowid: i64 = row.get(0)?;

			let mut stat = tx.prepare(
				r#"
			INSERT INTO object (
				actor_id, sequence, hash, signature, created, found, type, previous_hash,
				verified_from_start
			) VALUES(?,?,?,?,?,?,?,?,?)
			"#,
			)?;
			let object_id = stat.insert(params![
				actor_rowid,
				object.sequence,
				id.to_string(),
				object.signature.to_bytes(),
				object.created,
				Utc::now().timestamp_millis(),
				object.payload.type_id(),
				object.previous_hash.to_string(),
				verified_from_start,
			])?;
			Self::_store_object_payload(tx, actor_rowid, object_id, &object.payload)?;
			Ok(object_id)
		} else {
			Err(Error::MissingIdentity(actor_hash.clone()))
		}
	}

	pub fn _store_post(
		tx: &impl DerefConnection, actor_id: i64, created: u64, previous_hash: &IdType,
		tags: &[String], files: &[IdType], hash: &IdType, signature: &Signature,
		in_reply_to: Option<(IdType, IdType)>,
	) -> Result<()> {
		// Create post object
		let next_sequence = Self::_next_object_sequence(tx, actor_id)?;
		let mut stat = tx.prepare(
			r#"
			INSERT INTO object (
				actor_id, sequence, previous_hash, hash, signature, created, found, type
			)
			VALUES (?,?,?,?,?,?,?,?)
		"#,
		)?;

		let object_id = stat.insert(params![
			actor_id,
			next_sequence,
			previous_hash.to_string(),
			hash.to_string(),
			signature.to_bytes(),
			created,
			created,
			OBJECT_TYPE_POST,
		])?;
		stat = tx.prepare(
			r#"
			INSERT INTO post_object (object_id, file_count, in_reply_to_actor_hash, in_reply_to_object_hash) VALUES (?,?,?,?)
		"#,
		)?;
		let (a, o) = match in_reply_to {
			None => (None, None),
			Some((actor, object)) => (Some(actor.to_string()), Some(object.to_string())),
		};
		let post_id = stat.insert(params![object_id, files.len(), a, o])?;

		// Store all tags & files
		Self::_store_post_tags(tx, post_id as _, tags)?;
		Self::_store_post_files(tx, actor_id, post_id, files)?;
		Ok(())
	}

	fn _store_post_files(
		tx: &impl DerefConnection, _actor_id: i64, post_id: i64, files: &[IdType],
	) -> rusqlite::Result<()> {
		for i in 0..files.len() {
			let file = &files[i];

			tx.execute(
				r#"
				INSERT INTO post_files (post_id, hash, sequence)
				VALUES (?,?,?)
			"#,
				params![post_id, file.to_string(), i],
			)?;
		}
		Ok(())
	}

	fn _store_post_object_payload(
		tx: &impl DerefConnection, actor_id: i64, object_id: i64, payload: &PostObject,
	) -> rusqlite::Result<()> {
		let mut stat = tx.prepare(
			r#"
			INSERT INTO post_object (object_id, file_count, in_reply_to_actor_hash, in_reply_to_object_hash)
			VALUES (?,?,?,?)
		"#,
		)?;
		let post_id = stat.insert(params![
			object_id,
			payload.files.len(),
			payload.in_reply_to.as_ref().map(|irt| irt.0.to_string()),
			payload.in_reply_to.as_ref().map(|irt| irt.1.to_string())
		])?;

		Self::_store_post_tags(tx, post_id, &payload.tags)?;
		Self::_store_post_files(tx, actor_id, post_id, &payload.files)
	}

	fn _store_post_tags(
		tx: &impl DerefConnection, post_id: i64, tags: &[String],
	) -> rusqlite::Result<()> {
		for tag in tags {
			tx.execute(
				r#"
				INSERT INTO post_tag (post_id, tag) VALUES (?, ?)
			"#,
				params![post_id, tag],
			)?;
		}
		Ok(())
	}

	fn _store_object_payload(
		tx: &impl DerefConnection, actor_id: i64, object_id: i64, payload: &ObjectPayload,
	) -> rusqlite::Result<()> {
		match payload {
			ObjectPayload::Post(po) =>
				Self::_store_post_object_payload(tx, actor_id, object_id, &po),
			ObjectPayload::Profile(po) => Self::_store_profile_object_payload(tx, object_id, &po),
			_ => panic!("payload type not implemented yet"),
		}
	}

	fn _store_profile_object(
		tx: &Transaction, actor_id: i64, object_id: &IdType, object: &Object, name: &str,
		avatar_file_id: Option<&IdType>, wallpaper_file_id: Option<&IdType>,
		description_block_id: Option<&IdType>,
	) -> rusqlite::Result<()> {
		// FIXME: Use _store_object instead of the following redundant code
		let mut stat = tx.prepare(
			r#"
			INSERT INTO object (
				actor_id, sequence, hash, signature, created, found, type
			)
			VALUES (?,?,?,?,?,?,?)
		"#,
		)?;
		let object_id = stat.insert(params![
			actor_id,
			object.sequence,
			object_id.to_string(),
			object.signature.to_bytes(),
			object.created,
			Utc::now().timestamp_millis(),
			object.payload.type_id(),
		])?;

		tx.execute(
			r#"
			INSERT INTO profile_object (
				object_id, name, avatar_file_hash, wallpaper_file_hash, description_block_hash
			) VALUES (?,?,?,?,?)
		"#,
			params![
				object_id,
				name,
				avatar_file_id.map(|id| id.to_string()),
				wallpaper_file_id.map(|id| id.to_string()),
				description_block_id.map(|id| id.to_string())
			],
		)?;
		Ok(())
	}

	fn _store_profile_object_payload(
		tx: &impl DerefConnection, object_id: i64, payload: &ProfileObject,
	) -> rusqlite::Result<()> {
		tx.execute(r#"
			INSERT INTO profile_object (object_id, name, avatar_file_hash, wallpaper_file_hash, description_block_hash)
			VALUES (?,?,?,?,?)
		"#, params![
			object_id,
			&payload.name,
			payload.avatar.as_ref().map(|f| f.to_string()),
			payload.wallpaper.as_ref().map(|f| f.to_string()),
			payload.description.as_ref().map(|h| h.to_string()),
		])?;
		Ok(())
	}

	pub fn create_my_identity(
		&mut self, label: &str, private_key: &PrivateKey, first_object_hash: &IdType,
		first_object: &Object, name: &str, avatar: Option<(&IdType, &str, &[(IdType, Vec<u8>)])>,
		wallpaper: Option<(&IdType, &str, &[(IdType, Vec<u8>)])>,
		description: Option<(IdType, &str)>,
	) -> Result<()> {
		fn store_file<'a>(
			tx: &impl DerefConnection, identity_id: i64,
			file_data: Option<(&'a IdType, &str, &[(IdType, Vec<u8>)])>,
		) -> Result<Option<&'a IdType>> {
			if let Some((hash, mime_type, blocks)) = file_data {
				let block_ids: Vec<IdType> = blocks.iter().map(|(hash, _)| hash.clone()).collect();
				Connection::_store_file(tx, identity_id, &hash, &mime_type, &block_ids)?;
				for (block_id, block_data) in blocks {
					Connection::_store_block(tx, identity_id, block_id, block_data)?;
				}
				Ok(Some(hash))
			} else {
				Ok(None)
			}
		}

		let tx = self.0.transaction()?;

		let identity_id = Self::_store_my_identity(
			&tx,
			label,
			private_key,
			&first_object_hash,
			ACTOR_TYPE_BLOGCHAIN.to_string(),
		)?;
		let avatar_file_id = store_file(&tx, identity_id, avatar)?;
		let wallpaper_file_id = store_file(&tx, identity_id, wallpaper)?;
		let description_block_id = if let Some((hash, description_str)) = &description {
			Self::_store_block(&tx, identity_id, hash, description_str.as_bytes())?;
			Some(hash)
		} else {
			None
		};

		Self::_store_profile_object(
			&tx,
			identity_id,
			first_object_hash,
			&first_object,
			name,
			avatar_file_id,
			wallpaper_file_id,
			description_block_id,
		)?;

		tx.commit()?;
		Ok(())
	}

	pub fn delete_object(&self, actor_id: &IdType, hash: &IdType) -> Result<bool> {
		let affected = self.0.execute(
			r#"
			DELETE FROM object WHERE hash = ? AND actor_id = (
				SELECT rowid FROM identity WHERE address = ?
			)
		"#,
			[hash.to_string(), actor_id.to_string()],
		)?;
		Ok(affected > 0)
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

	/// Returns a list of hashes of blocks we're still missing but also in need
	/// of
	pub fn fetch_missing_file_blocks(&self, actor_id: &IdType) -> Result<Vec<IdType>> {
		let mut stat = self.prepare(
			r#"
			SELECT fb.block_hash
			FROM file AS f
			LEFT JOIN identity AS i ON f.actor_id = i.rowid
			LEFT JOIN file_blocks AS fb ON fb.file_id = f.rowid
			WHERE i.address = ? AND fb.block_hash NOT IN (
				SELECT hash FROM block WHERE actor_id = i.rowid
			)
		"#,
		)?;

		let mut rows = stat.query([actor_id.to_string()])?;
		let mut results = Vec::new();
		while let Some(row) = rows.next()? {
			let hash: String = row.get(0)?;
			let id = IdType::from_base58(&hash)?;
			results.push(id);
		}
		Ok(results)
	}

	pub fn fetch_block(&self, actor_id: &IdType, id: &IdType) -> Result<Option<Vec<u8>>> {
		let mut stat = self.prepare(
			r#"
			SELECT b.rowid, b.size, b.data
			FROM block AS b 
			LEFT JOIN identity AS i ON b.actor_id = i.rowid
			WHERE i.address = ? AND b.hash = ?
		"#,
		)?;
		let mut rows = stat.query([actor_id.to_string(), id.to_string()])?;
		if let Some(row) = rows.next()? {
			let block_id = row.get(0)?;
			let size: usize = row.get(1)?;
			let data: Vec<u8> = row.get(2)?;
			if data.len() != size {
				return Err(Error::BlockDataCorrupt(block_id));
			}
			Ok(Some(data))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_file_data(&self, id: &IdType) -> Result<Option<FileData>> {
		match Self::_fetch_file(self, id)? {
			None => Ok(None),
			Some((mime_type, data)) => Ok(Some(FileData { mime_type, data })),
		}
	}

	pub fn fetch_file(&self, id: &IdType) -> Result<Option<File>> {
		let mut stat = self.prepare(
			r#"
			SELECT rowid, mime_type, block_count FROM file WHERE hash = ?
		"#,
		)?;
		let mut rows = stat.query([id.to_string()])?;
		if let Some(row) = rows.next()? {
			let file_id = row.get(0)?;
			let mime_type: String = row.get(1)?;
			let block_count: u32 = row.get(2)?;

			let mut stat = self.prepare(
				r#"
				SELECT sequence, block_hash
				FROM file_blocks
				WHERE file_id = ?
				ORDER BY sequence ASC
			"#,
			)?;
			let mut rows = stat.query([file_id])?;
			let mut i = 0;
			let mut blocks = Vec::with_capacity(block_count as _);
			while let Some(row) = rows.next()? {
				let sequence: u64 = row.get(0)?;
				if sequence != i {
					return Err(Error::FileMissingBlock(file_id, i));
				}
				let block_hash: String = row.get(1)?;
				let block_id = IdType::from_base58(&block_hash)?;

				blocks.push(block_id);
				if blocks.len() == blocks.capacity() {
					break;
				}
				i += 1;
			}

			Ok(Some(File { mime_type, blocks }))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_follow_list(&self) -> Result<Vec<(IdType, ActorInfo)>> {
		let mut stat = self.prepare(
			r#"
			SELECT i.address, i.public_key, i.first_object, i.type
			FROM following AS f
			LEFT JOIN identity AS i ON f.identity_id = i.rowid
		"#,
		)?;
		let mut rows = stat.query([])?;

		let mut list = Vec::new();
		while let Some(row) = rows.next()? {
			let address_string: String = row.get(0)?;
			let raw_public_key: Vec<u8> = row.get(1)?;
			let first_object_string: String = row.get(2)?;
			let actor_type: String = row.get(3)?;
			let address = IdType::from_base58(&address_string)?;
			let public_key = PublicKey::from_bytes(
				raw_public_key
					.try_into()
					.map_err(|_| Error::InvalidPublicKey(None))?,
			)?;
			let first_object = IdType::from_base58(&first_object_string)?;
			let actor_info = ActorInfo {
				public_key,
				first_object,
				actor_type,
			};
			list.push((address, actor_info));
		}
		Ok(list)
	}

	pub fn fetch_object_info(
		&mut self, actor_id: &IdType, sequence: u64,
	) -> Result<Option<ObjectInfo>> {
		let tx = self.0.transaction()?;
		let mut stat = tx.prepare(
			r#"
			SELECT o.actor_id, o.hash, o.sequence, o.created, o.found, o.type, i.address
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id.to_string(), sequence])?;
		Self::_parse_object_info(&tx, &mut rows)
	}

	pub fn fetch_home_feed(&mut self, count: u64, offset: u64) -> Result<Vec<ObjectInfo>> {
		let tx = self.0.transaction()?;

		let mut stat = tx.prepare(
			r#"
			SELECT o.actor_id, o.hash, o.sequence, o.created, o.found, o.type, i.address
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			WHERE o.actor_id IN (
				SELECT identity_id FROM my_identity
			) OR o.actor_id IN (
				SELECT identity_id FROM following
			)
			ORDER BY o.found DESC LIMIT ? OFFSET ?
		"#,
		)?;
		let mut rows = stat.query([count, offset])?;

		let mut objects = Vec::with_capacity(count as _);
		while let Some(object) = Self::_parse_object_info(&tx, &mut rows)? {
			objects.push(object);
		}
		Ok(objects)
	}

	pub fn fetch_object(
		&self, actor_id: &IdType, object_hash: &IdType,
	) -> Result<Option<(Object, bool)>> {
		if let Some((_, object, verified)) = Self::_fetch_object(self, actor_id, object_hash)? {
			Ok(Some((object, verified)))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_object_by_sequence(
		&self, actor_id: &IdType, sequence: u64,
	) -> Result<Option<(IdType, Object, bool)>> {
		Self::_fetch_object_by_sequence(self, actor_id, sequence)
	}

	pub fn fetch_previous_object(
		&mut self, actor_id: &IdType, hash: &IdType,
	) -> Result<Option<(IdType, Object, bool)>> {
		let tx = self.0.transaction()?;

		let mut stat = tx.prepare(
			r#"
			SELECT o.sequence
			FROM object AS o
			INNER JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ? AND o.hash = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id.to_string(), hash.to_string()])?;
		if let Some(row) = rows.next()? {
			let sequence: u64 = row.get(0)?;
			if sequence > 0 {
				Self::_fetch_object_by_sequence(&tx, actor_id, sequence - 1)
			} else {
				Ok(None)
			}
		} else {
			Ok(None)
		}
	}

	pub fn fetch_next_object(
		&mut self, actor_id: &IdType, hash: &IdType,
	) -> Result<Option<(IdType, Object, bool)>> {
		let tx = self.0.transaction()?;

		let mut stat = tx.prepare(
			r#"
			SELECT o.sequence
			FROM object AS o
			INNER JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ? AND o.hash = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id.to_string(), hash.to_string()])?;
		if let Some(row) = rows.next()? {
			let sequence: u64 = row.get(0)?;
			if sequence < u64::MAX {
				if let Some((hash, object, verified_from_start)) =
					Self::_fetch_object_by_sequence(&tx, actor_id, sequence + 1)?
				{
					Ok(Some((hash, object, verified_from_start)))
				} else {
					Ok(None)
				}
			} else {
				Ok(None)
			}
		} else {
			Ok(None)
		}
	}

	pub fn fetch_head(&self, actor_id: &IdType) -> Result<Option<(IdType, Object, bool)>> {
		Self::_fetch_head(self, actor_id)
	}

	pub fn fetch_last_verified_object(
		&self, actor_id: &IdType,
	) -> Result<Option<(IdType, Object)>> {
		if let Some((hash, object, _)) = Self::_fetch_last_verified_object(self, actor_id)? {
			Ok(Some((hash, object)))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_identity(&self, address: &IdType) -> Result<Option<ActorInfo>> {
		let mut stat = self.prepare(
			r#"
			SELECT public_key, first_object, type FROM identity WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query([address.to_string()])?;
		if let Some(row) = rows.next()? {
			let bytes: Vec<u8> = row.get(0)?;
			let hash: String = row.get(1)?;
			let actor_type: String = row.get(2)?;
			if bytes.len() != 32 {
				return Err(Error::InvalidPublicKey(None));
			}
			let public_key = PublicKey::from_bytes(bytes.try_into().unwrap())?;
			let first_object = IdType::from_base58(&hash)?;
			Ok(Some(ActorInfo {
				public_key,
				first_object,
				actor_type,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_my_identity(&self, address: &IdType) -> Result<Option<(String, PrivateKey)>> {
		let mut stat = self.0.prepare(
			r#"
			SELECT label, private_key FROM my_identity AS mi LEFT JOIN identity AS i
			WHERE i.address = ?
		"#,
		)?;
		let mut rows = stat.query([address.to_string()])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => {
				let label = row.get(0)?;
				let private_key: PrivateKey = row.get(1)?;
				Ok(Some((label, private_key)))
			}
		}
	}

	pub fn fetch_my_identity_by_label(&self, label: &str) -> Result<Option<(IdType, PrivateKey)>> {
		let mut stat = self.0.prepare(
			r#"
			SELECT i.address, mi.private_key
			FROM my_identity AS mi LEFT JOIN identity AS i ON mi.identity_id = i.rowid
			WHERE label = ?
		"#,
		)?;
		let mut rows = stat.query([label])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => {
				let address_str: String = row.get(0)?;
				let address = IdType::from_base58(&address_str)?;
				let private_key: PrivateKey = row.get(1)?;
				Ok(Some((address, private_key)))
			}
		}
	}

	pub fn fetch_my_identities(&self) -> Result<Vec<(String, IdType, IdType, String, PrivateKey)>> {
		let mut stat = self.0.prepare(
			r#"
			SELECT label, i.address, i.first_object, i.type, mi.private_key
			FROM my_identity AS mi
			LEFT JOIN identity AS i ON mi.identity_id = i.rowid
		"#,
		)?;
		let mut rows = stat.query([])?;

		let mut ids = Vec::new();
		while let Some(row) = rows.next()? {
			let address_string: String = row.get(1)?;
			let fo_string: String = row.get(2)?;
			let address = IdType::from_base58(&address_string)?;
			let first_object = IdType::from_base58(&fo_string)?;
			let actor_type: String = row.get(3)?;
			let private_key: PrivateKey = row.get(4)?;
			ids.push((row.get(0)?, address, first_object, actor_type, private_key));
		}
		Ok(ids)
	}

	pub fn fetch_node_identity(&mut self) -> Result<(IdType, PrivateKey)> {
		let tx = self.0.transaction()?;

		let result = {
			let mut stat = tx.prepare(
				r#"
				SELECT address, private_key FROM node_identity LIMIT 1
			"#,
			)?;
			let mut rows = stat.query([])?;

			if let Some(row) = rows.next()? {
				let address: IdType = row.get(0)?;
				let private_key: PrivateKey = row.get(1)?;
				(address, private_key)
			} else {
				let private_key = PrivateKey::generate();
				let address = IdType::hash(&private_key.public().to_bytes());
				tx.execute(
					r#"
					INSERT INTO node_identity (address, private_key) VALUES (?,?)
				"#,
					params![address, private_key],
				)?;
				(address, private_key)
			}
		};

		tx.commit()?;
		Ok(result)
	}

	pub fn fetch_profile_object(&self, actor_id: &IdType) -> Result<Option<(IdType, Object)>> {
		let mut stat = self.prepare(
			r#"
			SELECT o.rowid, o.sequence, o.created, o.signature, o.hash, o.type, o.previous_hash, o.verified_from_start
			FROM profile_object AS po
			INNER JOIN object AS o ON po.object_id = o.rowid
			INNER JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ?
			ORDER BY o.rowid DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query(params![actor_id.to_string()])?;
		if let Some((hash, object, _)) = Self::_parse_object(self, &mut rows)? {
			Ok(Some((hash, object)))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_profile_info(&self, actor_id: &IdType) -> Result<Option<ProfileObjectInfo>> {
		let mut stat = self.prepare(
			r#"
			SELECT i.address, po.name, po.avatar_file_hash, po.wallpaper_file_hash, db.data
			FROM profile_object AS po
			INNER JOIN object AS o ON po.object_id = o.rowid
			INNER JOIN identity AS i ON o.actor_id = i.rowid
			LEFT JOIN block AS db ON po.description_block_hash = db.hash
			WHERE i.address = ?
			ORDER BY o.sequence DESC LIMIT 1
		"#,
		)?;
		let mut rows = stat.query([actor_id.to_string()])?;
		if let Some(row) = rows.next()? {
			let actor_hash: String = row.get(0)?;
			let actor_id = IdType::from_base58(&actor_hash)?;
			let actor_name: String = row.get(1)?;
			let avatar_hash: Option<String> = row.get(2)?;
			let avatar_id = match avatar_hash {
				None => None,
				Some(hash) => Some(IdType::from_base58(&hash)?),
			};
			let wallpaper_hash: Option<String> = row.get(3)?;
			let wallpaper_id = match wallpaper_hash {
				None => None,
				Some(hash) => Some(IdType::from_base58(&hash)?),
			};
			let description_data: Option<Vec<u8>> = row.get(4)?;
			let description = match description_data {
				None => None,
				Some(data) => Some(String::from_utf8_lossy(&data).to_string()),
			};

			Ok(Some(ProfileObjectInfo {
				actor: TargetedActorInfo {
					id: actor_id,
					name: actor_name,
					avatar_id,
					wallpaper_id,
				},
				description,
			}))
		} else {
			Ok(None)
		}
	}

	pub fn fetch_remembered_node(&mut self, address: &SocketAddr) -> Result<(IdType, i32)> {
		let result = self.query_row(
			r#"
			SELECT node_id, success_score FROM remembered_nodes WHERE address = ?
		"#,
			params![address.to_string()],
			|row| {
				let node_id: IdType = row.get(0)?;
				let score: i32 = row.get(1)?;
				Ok((node_id, score))
			},
		)?;
		Ok(result)
	}

	pub fn follow(&mut self, actor_id: &IdType, actor_info: &ActorInfo) -> Result<()> {
		let tx = self.0.transaction()?;

		let identity_id = {
			let mut stat = tx.prepare(
				r#"
				SELECT rowid FROM identity WHERE address = ?
			"#,
			)?;
			let mut rows = stat.query([actor_id.to_string()])?;
			let identity_id = if let Some(row) = rows.next()? {
				row.get(0)?
			} else {
				drop(rows);
				let mut stat = tx.prepare(
					r#"
					INSERT INTO identity (address, public_key, first_object, type) VALUES (?,?,?,?)
				"#,
				)?;
				stat.insert(params![
					actor_id.to_string(),
					actor_info.public_key.to_bytes(),
					actor_info.first_object.as_bytes(),
					ACTOR_TYPE_BLOGCHAIN
				])?
			};
			identity_id
		};

		tx.execute(
			r#"
			INSERT INTO following (identity_id) VALUES (?)
		"#,
			params![identity_id],
		)?;

		tx.commit()?;
		Ok(())
	}

	pub fn has_block(&self, actor_id: &IdType, hash: &IdType) -> rusqlite::Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT b.rowid
			FROM block AS b
			LEFT JOIN identity AS i ON b.actor_id = i.rowid
			WHERE i.address = ? AND b.hash = ?
		"#,
		)?;
		let mut rows = stat.query([actor_id.to_string(), hash.to_string()])?;
		Ok(rows.next()?.is_some())
	}

	pub fn has_file(&self, actor_id: &IdType, hash: &IdType) -> rusqlite::Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT f.rowid
			FROM file AS f
			LEFT JOIN identity AS i ON f.actor_id = i.rowid
			WHERE i.address = ? AND f.hash = ?
		"#,
		)?;
		let mut rows = stat.query([actor_id.to_string(), hash.to_string()])?;
		Ok(rows.next()?.is_some())
	}

	pub fn has_object(&self, actor_id: &IdType, id: &IdType) -> rusqlite::Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT o.rowid
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ? AND o.hash = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id.to_string(), id.to_string()])?;
		Ok(rows.next()?.is_some())
	}

	pub fn has_object_sequence(&self, actor_id: &IdType, sequence: u64) -> rusqlite::Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT o.rowid
			FROM object AS o
			LEFT JOIN identity AS i ON o.actor_id = i.rowid
			WHERE i.address = ? AND o.sequence = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id.to_string(), sequence])?;
		Ok(rows.next()?.is_some())
	}

	pub fn is_identity_available(&self, address: &IdType) -> rusqlite::Result<bool> {
		let mut stat = self.0.prepare(
			r#"
			SELECT address FROM identity AS i
			WHERE address = ? AND rowid IN (
				SELECT identity_id FROM my_identity
			) OR rowid IN (
				SELECT identity_id FROM feed_followed
			)
		"#,
		)?;
		let mut rows = stat.query([address.to_string()])?;
		Ok(rows.next()?.is_some())
	}

	pub fn is_following(&self, actor_id: &IdType) -> Result<bool> {
		let mut stat = self.prepare(
			r#"
			SELECT 1
			FROM following AS f
			LEFT JOIN identity AS i ON f.identity_id = i.rowid
			WHERE i.address = ?
		"#,
		)?;
		let mut rows = stat.query(params![actor_id.to_string()])?;
		Ok(rows.next()?.is_some())
	}

	pub fn load_file<'a>(
		&'a mut self, actor_id: &IdType, hash: &IdType,
	) -> Result<Option<(String, FileLoader<'a>)>> {
		let mut stat = self.prepare(
			r#"
			SELECT f.rowid, f.mime_type, f.block_count
			FROM file AS f
			LEFT JOIN identity AS i ON f.actor_id = i.rowid
			WHERE i.address = ? AND f.hash = ?
		"#,
		)?;
		let mut rows = stat.query([actor_id.to_string(), hash.to_string()])?;
		if let Some(row) = rows.next()? {
			let file_id: i64 = row.get(0)?;
			let mime_type = row.get(1)?;
			let block_count = row.get(2)?;

			let stat = Box::pin(self.prepare(
				r#"
				SELECT fb.sequence, b.size, b.data
				FROM file AS f
				LEFT JOIN file_blocks AS fb ON fb.file_id = f.rowid
				LEFT JOIN block AS b ON fb.block_hash = b.hash
				WHERE f.rowid = ?
			"#,
			)?);
			let fl = FileLoader::new(stat, file_id, block_count)?;

			Ok(Some((mime_type, fl)))
		} else {
			Ok(None)
		}
	}

	/// Returns the lastest object sequence for an actor if available.
	pub fn max_object_sequence(&self, actor_id: i64) -> Result<Option<u64>> {
		let mut stat = self.0.prepare(
			r#"
			SELECT MAX(sequence) FROM object WHERE actor_id = ?
		"#,
		)?;
		let mut rows = stat.query([actor_id])?;
		match rows.next()? {
			None => Ok(None),
			Some(row) => Ok(row.get(0)?),
		}
	}

	/// Returns the sequence that the next object would use.
	pub fn next_object_sequence(&self, actor_id: i64) -> Result<u64> {
		match self.max_object_sequence(actor_id)? {
			None => Ok(0),
			Some(s) => Ok(s + 1),
		}
	}

	pub fn open(path: &Path) -> rusqlite::Result<Self> {
		Ok(Self(rusqlite::Connection::open(&path)?))
	}

	pub fn store_block(
		&mut self, actor: &IdType, hash: &IdType, data: &[u8],
	) -> rusqlite::Result<()> {
		let tx = self.0.transaction()?;
		if let Some(actor_id) = Self::_find_identity(&tx, actor)? {
			Self::_store_block(&tx, actor_id, hash, data)?;
			tx.commit()?;
		}
		// FIXME: return an error when identity didn't exist...
		Ok(())
	}

	pub fn store_file(
		&mut self, actor_id: &IdType, id: &IdType, file: &File,
	) -> rusqlite::Result<bool> {
		self.store_file2(actor_id, id, &file.mime_type, &file.blocks)
	}

	pub fn store_file2(
		&mut self, actor_id: &IdType, id: &IdType, mime_type: &str, blocks: &[IdType],
	) -> rusqlite::Result<bool> {
		let tx = self.0.transaction()?;
		if let Some(actor_row_id) = Self::_find_identity(&tx, actor_id)? {
			Self::_store_file(&tx, actor_row_id, id, mime_type, blocks)?;
			tx.commit()?;
			Ok(true)
		} else {
			Ok(false)
		}
	}

	pub fn store_identity(
		&mut self, address: &IdType, public_key: &PublicKey, first_object: &IdType,
	) -> Result<()> {
		let mut stat = self.prepare(
			r#"
			INSERT INTO identity (address, public_key, first_object, type) VALUES(?,?,?,'blogchain')
		"#,
		)?;
		stat.insert(rusqlite::params![
			address,
			public_key.as_bytes(),
			first_object
		])?;
		Ok(())
	}

	pub fn store_my_identity(
		&mut self, label: &str, address: &IdType, private_key: &PrivateKey, first_object: &IdType,
	) -> rusqlite::Result<()> {
		let tx = self.0.transaction()?;

		let mut stat = tx.prepare(
			r#"
			INSERT INTO identity (address, public_key, first_object) VALUES(?,?,?)
		"#,
		)?;
		let new_id = stat.insert(rusqlite::params![
			address.to_string(),
			private_key.public().as_bytes(),
			first_object.to_string()
		])?;
		stat = tx
			.prepare(
				r#"
			INSERT INTO my_identity (label, identity_id, private_key) VALUES (?,?,?)
		"#,
			)
			.unwrap();
		stat.insert(rusqlite::params![label, new_id, private_key.as_bytes()])?;

		drop(stat);
		tx.commit()?;
		Ok(())
	}

	pub fn store_node_identity(&self, node_id: &IdType, node_key: &PrivateKey) -> Result<()> {
		self.execute(
			r#"
			UPDATE node_identity SET address = ?, private_key = ?
		"#,
			params![node_id, node_key],
		)?;
		Ok(())
	}

	pub fn store_object(
		&mut self, actor_id: &IdType, id: &IdType, object: &Object, verified_from_start: bool,
	) -> self::Result<bool> {
		let tx = self.0.transaction()?;
		let _object_id = match Self::_store_object(&tx, actor_id, id, object, verified_from_start) {
			Ok(id) => id,
			// Just return false if the object already existed
			Err(e) => match &e {
				Error::SqliteError(e2) => match e2 {
					rusqlite::Error::SqliteFailure(e3, _) => {
						if e3.code == libsqlite3_sys::ErrorCode::ConstraintViolation {
							return Ok(false);
						}
						return Err(e);
					}
					_ => return Err(e),
				},
				_ => return Err(e),
			},
		};
		tx.commit()?;
		Ok(true)
	}

	pub fn fetch_bootstrap_node_id(&mut self, address: &SocketAddr) -> Result<Option<IdType>> {
		let mut stat = self.0.prepare(
			r#"
			SELECT node_id FROM bootstrap_id WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query([address.to_string()])?;
		if let Some(row) = rows.next()? {
			let node_id = row.get(0)?;
			Ok(Some(node_id))
		} else {
			Ok(None)
		}
	}

	pub fn remember_bootstrap_node_id(
		&mut self, address: &SocketAddr, node_id: &IdType,
	) -> Result<()> {
		let tx = self.0.transaction()?;
		let updated = tx.execute(
			"UPDATE bootstrap_id SET node_id = ? WHERE address = ?",
			params![node_id, address.to_string()],
		)?;
		if updated == 0 {
			tx.execute(
				"INSERT INTO bootstrap_id (address, node_id) VALUES (?,?)",
				params![address.to_string(), node_id],
			)?;
		}
		tx.commit()?;
		Ok(())
	}

	pub fn remember_node(&mut self, address: &SocketAddr, node_id: &IdType) -> Result<()> {
		let tx = self.0.transaction()?;

		let mut stat = tx.prepare(
			r#"
			SELECT success_score FROM remembered_nodes WHERE address = ?
		"#,
		)?;
		let mut rows = stat.query([address.to_string()])?;
		if let Some(row) = rows.next()? {
			let score: i32 = row.get(0)?;

			let affected = tx.execute(
				r#"UPDATE remembered_nodes SET success_score = ? WHERE address = ?"#,
				params![score + 1, address.to_string()],
			)?;
			debug_assert!(affected > 0);
		} else {
			tx.execute(
				r#"INSERT INTO remembered_nodes (address, node_id, success_score) VALUES (?, ?, ?)"#,
				params![address.to_string(), node_id, 1],
			)?;
		}
		Ok(())
	}

	pub fn unfollow(&mut self, actor_id: &IdType) -> Result<bool> {
		let affected = self.0.execute(
			r#"
			DELETE FROM following WHERE identity_id = (
				SELECT rowid FROM identity WHERE address = ?
			)
		"#,
			[actor_id.to_string()],
		)?;
		Ok(affected > 0)
	}

	pub fn update_object_verified(&mut self, actor_id: &IdType, object_id: &IdType) -> Result<()> {
		self.0.execute(
			r#"
			UPDATE object SET verified_from_start = 1
			WHERE hash = ? AND identity_id = (
				SELECT rowid FROM identity WHERE address = ?
			)
		"#,
			[object_id.to_string(), actor_id.to_string()],
		)?;
		Ok(())
	}
}

impl Deref for Connection {
	type Target = rusqlite::Connection;

	fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for Connection {
	fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::SqliteError(e) => write!(f, "{}", e),
			Self::InvalidHash(e) => {
				write!(f, "hash not a valid base58-encoded 32-byte address {}", e)
			}
			Self::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
			Self::InvalidObjectType(code) => {
				write!(f, "invalid object type found in database: {}", code)
			}
			//Self::InvalidPrivateKey(e) => write!(f, "invalid private_key: {}", e),
			Self::BlockDataCorrupt(block_id) => write!(f, "data of block {} is corrupt", block_id),
			Self::PostMissingFiles(object_id) => write!(f, "object {} has no files", object_id),
			Self::FileMissingBlock(file_id, sequence) => {
				write!(f, "file {} missing block sequence {}", file_id, sequence)
			}
			Self::InvalidPublicKey(oe) => match oe {
				Some(e) => write!(f, "invalid public key: {}", e),
				None => write!(f, "invalid public key size"),
			},
			Self::MissingIdentity(hash) => write!(f, "identity {} is missing", &hash),
		}
	}
}

impl From<rusqlite::Error> for Error {
	fn from(other: rusqlite::Error) -> Self { Self::SqliteError(other) }
}

impl From<SignatureError> for Error {
	fn from(other: SignatureError) -> Self { Self::InvalidSignature(other) }
}

impl From<IdFromBase58Error> for Error {
	fn from(other: IdFromBase58Error) -> Self { Self::InvalidHash(other) }
}

impl From<PublicKeyError> for Error {
	fn from(other: PublicKeyError) -> Self { Self::InvalidPublicKey(Some(other)) }
}

impl IdFromBase58Error {
	fn to_db(self) -> Error { Error::InvalidHash(self) }
}


#[cfg(test)]
mod tests {
	use std::sync::Mutex;

	use rand::RngCore;

	use super::*;
	use crate::test;

	static DB: Mutex<Option<Database>> = Mutex::new(None);

	#[ctor::ctor]
	fn initialize() {
		let path: PathBuf = "/tmp/db777.sqlite".into();
		let _ = std::fs::remove_file(&path);
		*DB.lock().unwrap() = Some(Database::load(path).expect("unable to load database"));
	}

	#[test]
	fn test_identity() {
		let mut c = DB
			.lock()
			.unwrap()
			.as_ref()
			.unwrap()
			.connect()
			.expect("unable to connect to database");

		let mut rng = test::initialize_rng();
		let private_key = PrivateKey::generate_with_rng(&mut rng);
		let mut buf = [0u8; 32];
		rng.fill_bytes(&mut buf);
		let payload = ObjectPayload::Profile(ProfileObject {
			name: "Test".to_string(),
			avatar: None,
			wallpaper: None,
			description: None,
		});
		let sign_data = ObjectSignData {
			sequence: 0,
			previous_hash: IdType::default(),
			created: 1234567890,
			payload: &payload,
		};
		let signature = private_key.sign(&binserde::serialize(&sign_data).unwrap());
		let first_object_id = IdType::hash(&signature.to_bytes());
		let first_object = Object {
			signature,
			sequence: 0,
			previous_hash: IdType::default(),
			created: 1234567890,
			payload,
		};
		c.create_my_identity(
			"test",
			&private_key,
			&first_object_id,
			&first_object,
			"Test",
			None,
			None,
			None,
		)
		.expect("unable to create personal identity");

		let actor_info = ActorInfo {
			public_key: private_key.public(),
			first_object: first_object_id,
			actor_type: ACTOR_TYPE_BLOGCHAIN.to_string(),
		};
		let actor_id = actor_info.generate_id();

		let (fetched_address, fetched_private_key) = c
			.fetch_my_identity_by_label("test")
			.expect("unable to load personal identities")
			.expect("personal identity not found");
		assert_eq!(fetched_address, actor_id);
		assert_eq!(fetched_private_key.as_bytes(), private_key.as_bytes());
	}
}

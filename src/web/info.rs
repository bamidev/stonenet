use ::serde::Serialize;
use chrono::TimeDelta;
use sea_orm::{
	prelude::*,
	sea_query::{Alias, IntoCondition, Query},
	Condition, DatabaseBackend, JoinType, Order, QueryOrder, QuerySelect, QueryTrait, Statement,
};

use super::consolidated_feed::ConsolidatedObjectType;
use crate::{
	common::{current_timestamp, IdType},
	compression::decompress,
	core::{
		ActorAddress, CompressionType, FileHeader, OBJECT_TYPE_HOME_FILE, OBJECT_TYPE_POST,
		OBJECT_TYPE_PROFILE,
	},
	db::{Database, Error, PersistenceHandle, Result},
	entity::*,
};

#[derive(Clone, Debug, Serialize)]
pub struct FileInfo {
	pub url: String,
	pub mime_type: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct IdentityInfo {
	pub label: String,
	pub address: ActorAddress,
	pub system_user: Option<String>,
}

#[derive(Serialize)]
pub struct ObjectInfo {
	pub url: String,
	pub id: String,
	pub consolidated_type: ConsolidatedObjectType,
	pub actor_address: Option<String>,
	pub actor_url: String,
	pub actor_name: String,
	pub actor_avatar_url: Option<String>,
	pub created: u64,
	pub found: u64,
	pub found_ago: String,
	pub payload: ObjectPayloadInfo,
}

#[derive(Debug, Serialize)]
pub enum ObjectPayloadInfo {
	Profile(ProfileObjectInfo),
	Post(PostObjectInfo),
}

#[derive(Clone, Debug, Serialize)]
pub enum PossiblyKnownFileHeader {
	Unknown(IdType),
	Known(FileHeader),
}

#[derive(Debug, Serialize)]
pub struct PostObjectInfo {
	pub in_reply_to: Option<TargetedPostInfo>,
	pub sequence: u64,
	pub message: Option<PostMessageInfo>,
	pub attachments: Vec<FileInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PostMessageInfo {
	pub mime_type: String,
	pub body: String,
}

#[derive(Debug, Serialize)]
pub struct ProfileObjectInfo {
	pub actor: TargetedActorInfo,
	pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TargetedActorInfo {
	pub address: String,
	pub url: String,
	pub name: String,
	pub avatar_url: Option<String>,
	pub wallpaper_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TargetedPostInfo {
	pub id: String,
	pub actor_address: String,
	pub actor_name: Option<String>,
	pub actor_avatar_url: Option<String>,
	pub message: Option<PostMessageInfo>,
	pub attachments: Vec<FileInfo>,
}

impl ObjectInfo {
	pub fn type_title(&self) -> String {
		match &self.payload {
			ObjectPayloadInfo::Profile(_) => "Profile update".to_string(),
			ObjectPayloadInfo::Post(post) => {
				if let Some(irt) = &post.in_reply_to {
					if let Some(to_name) = &irt.actor_name {
						format!("Reply from {} to {}", &self.actor_name, to_name)
					} else {
						format!("Reply from {}", &self.actor_name)
					}
				} else {
					format!("Post by {}", &self.actor_name)
				}
			}
		}
	}
}

impl ObjectPayloadInfo {
	// Returns true if the payload contains enough information to at least show the
	// main content.
	pub fn has_main_content(&self) -> bool {
		match self {
			Self::Post(post) => post.message.is_some(),
			Self::Profile(profile) => profile.description.is_some(),
		}
	}

	pub fn to_text(&self) -> String {
		match self {
			// TODO: Based on the mime type, attempt to remove any code from the text
			Self::Post(post) => post
				.message
				.as_ref()
				.map(|m| m.body.clone())
				.unwrap_or("".to_string()),
			Self::Profile(_) => "[Profile updated]".to_string(),
		}
	}
}

impl PossiblyKnownFileHeader {
	#[allow(unused)]
	pub fn hash(&self) -> &IdType {
		match self {
			Self::Known(header) => &header.url,
			Self::Unknown(hash) => hash,
		}
	}
}

/*impl PostMessageInfo {
	pub fn new_html(html: String) -> Self {
		Self {
			mime_type: "text/html".to_string(),
			body: html
		}
	}
}*/

pub fn actor_url(url_base: &str, actor_address: &ActorAddress) -> String {
	format!("{}/actor/{}", url_base, actor_address)
}

pub fn file_url(url_base: &str, actor_address: &ActorAddress, hash: &IdType) -> String {
	format!("{}/actor/{}/file/{}", url_base, actor_address, hash)
}

pub async fn find_object_info(
	db: &Database, url_base: &str, actor_address: &ActorAddress, hash: &IdType,
) -> Result<Option<ObjectInfo>> {
	let query = Query::select()
		.column((object::Entity, object::Column::Id))
		.column((object::Entity, object::Column::Type))
		.column(object::Column::ActorId)
		.column(object::Column::Hash)
		.column(object::Column::Created)
		.column(object::Column::Found)
		.from(object::Entity)
		.inner_join(
			actor::Entity,
			Expr::col((object::Entity, object::Column::ActorId))
				.equals((actor::Entity, actor::Column::Id)),
		)
		.and_where(actor::Column::Address.eq(actor_address))
		.and_where(object::Column::Hash.eq(hash))
		.take();
	let stat = db.backend().build(&query);

	if let Some(result) = db.inner().query_one(stat).await? {
		let object_opt =
			_load_object_info_from_result(db, url_base, actor_address, &result).await?;
		Ok(object_opt)
	} else {
		Ok(None)
	}
}

pub async fn find_profile_info(
	db: &Database, url_base: &str, actor_address: &ActorAddress,
) -> Result<Option<ProfileObjectInfo>> {
	let result = db
		.inner()
		.query_one(Statement::from_sql_and_values(
			db.inner().get_database_backend(),
			r#"
		SELECT i.address, po.name, po.avatar_file_hash, po.wallpaper_file_hash, df.id,
			df.compression_type, df.plain_hash, df.block_count
		FROM profile_object AS po
		LEFT JOIN object AS o ON po.object_id = o.id
		LEFT JOIN actor AS i ON o.actor_id = i.id
		LEFT JOIN file AS df ON po.description_file_hash = df.hash
		WHERE i.address = ?
		ORDER BY sequence DESC
		
	"#,
			[actor_address.to_bytes().into()],
		))
		.await?;
	Ok(if let Some(r) = result {
		_parse_profile_info(db, url_base, r).await?
	} else {
		None
	})
}

pub async fn find_profile_info2(
	db: &Database, url_base: &str, actor_id: i64,
) -> Result<Option<ProfileObjectInfo>> {
	let result = db
		.inner()
		.query_one(Statement::from_sql_and_values(
			db.inner().get_database_backend(),
			r#"
		SELECT i.address, po.name, po.avatar_file_hash, po.wallpaper_file_hash, df.id,
			df.compression_type, df.plain_hash, df.block_count
		FROM profile_object AS po
		LEFT JOIN object AS o ON po.object_id = o.id
		LEFT JOIN actor AS i ON o.actor_id = i.id
		LEFT JOIN file AS df ON po.description_file_hash = df.hash
		WHERE i.id = ?
		ORDER BY sequence DESC
	"#,
			[actor_id.into()],
		))
		.await?;
	Ok(if let Some(r) = result {
		_parse_profile_info(db, url_base, r).await?
	} else {
		None
	})
}

async fn find_profile_object_info(
	db: &Database, url_base: &str, object_id: i64,
) -> Result<Option<ProfileObjectInfo>> {
	let result = db
		.inner()
		.query_one(Statement::from_sql_and_values(
			db.inner().get_database_backend(),
			r#"
		SELECT i.address, po.name, po.avatar_file_hash, po.wallpaper_file_hash, df.id,
			   df.compression_type, df.plain_hash, df.block_count
		FROM profile_object AS po
		LEFT JOIN object AS o ON po.object_id = o.id
		LEFT JOIN actor AS i ON o.actor_id = i.id
		LEFT JOIN file AS df ON po.description_file_hash = df.hash
		WHERE o.id = ?
	"#,
			[object_id.into()],
		))
		.await?;
	Ok(if let Some(r) = result {
		_parse_profile_info(db, url_base, r).await?
	} else {
		None
	})
}

/// Finds the mime-type, text content & attachments for the given post
/// object respectively.
async fn find_post_object_info_files(
	db: &Database, url_base: &str, actor_address: &ActorAddress, object_id: i64,
) -> Result<Option<(String, String, Vec<FileInfo>)>> {
	fn file_query<F>(backend: DatabaseBackend, object_id: i64, condition: F) -> Statement
	where
		F: IntoCondition,
	{
		file::Entity::find()
			.join(
				JoinType::LeftJoin,
				file::Entity::belongs_to(post_file::Entity)
					.from(file::Column::Hash)
					.to(post_file::Column::Hash)
					.into(),
			)
			.filter(post_file::Column::ObjectId.eq(object_id))
			.filter(condition)
			.order_by(post_file::Column::Sequence, Order::Asc)
			.build(backend)
	}

	let query = post_object::Entity::find()
		.filter(post_object::Column::ObjectId.eq(object_id))
		.build(db.inner().get_database_backend());
	let result = db.inner().query_one(query).await?;

	if let Some(r) = result {
		let file_count: i64 = r.try_get_by("file_count")?;

		let query = file_query(
			db.inner().get_database_backend(),
			object_id,
			post_file::Column::Sequence.eq(0),
		);
		if let Some(row) = db.inner().query_one(query).await? {
			//let file_hash: IdType = row.try_get_by(file::Column::Hash.as_str())?;
			let file_id_opt: Option<i64> = row.try_get_by(file::Column::Id.as_str())?;
			if let Some(file_id) = file_id_opt {
				let plain_hash: IdType = row.try_get_by(file::Column::PlainHash.as_str())?;
				let mime_type: String = row.try_get_by(file::Column::MimeType.as_str())?;
				let block_count: u32 = row.try_get_by(file::Column::BlockCount.as_str())?;
				let compression_type_code: u8 =
					row.try_get_by(file::Column::CompressionType.as_str())?;
				// TODO: Remove unwrap
				let compression_type = CompressionType::from_u8(compression_type_code).unwrap();

				let body_opt = match db.find_file_data(file_id, &plain_hash, block_count).await {
					Ok(r) => r,
					Err(e) => match &*e {
						// If a block is still missing from the message data file, don't
						// actually raise an error, just leave the message data unset.
						Error::FileMissingBlock(..) => None,
						_ => return Err(e),
					},
				};

				if let Some(buffer) = body_opt {
					// Collect the files
					let mut attachments = Vec::with_capacity(file_count as _);
					let query = file_query(
						db.inner().get_database_backend(),
						object_id,
						post_file::Column::Sequence.gt(0),
					);
					let results = db.inner().query_all(query).await?;
					for row in results {
						let hash: IdType = row.try_get_by("hash")?;
						let mime_type_opt: Option<String> = row.try_get_by("mime_type")?;
						attachments.push(FileInfo {
							url: format!("{}/actor/{}/file/{}", url_base, actor_address, hash),
							mime_type: mime_type_opt,
						});
					}

					// TODO: remove unwrap
					let decompressed = decompress(compression_type, &buffer).unwrap();
					let body_string = String::from_utf8_lossy(&decompressed).to_string();
					return Ok(Some((mime_type, body_string, attachments)));
				}
			}
		}
	}
	Ok(None)
}

/// Finds `PostObjectInfo` for the given `object_id`.
async fn find_post_object_info(
	db: &Database, url_base: &str, object_id: i64,
) -> Result<Option<PostObjectInfo>> {
	let result = db
		.inner()
		.query_one(Statement::from_sql_and_values(
			db.inner().get_database_backend(),
			r#"
		SELECT o.hash, o.sequence, i.address, ti.id, ti.address, tpo.object_id
		FROM post_object AS po
		INNER JOIN object AS o ON po.object_id = o.id
		INNER JOIN actor AS i ON o.actor_id = i.id
		LEFT JOIN actor AS ti ON po.in_reply_to_actor_address = ti.address
		LEFT JOIN object AS to_ ON to_.actor_id = ti.id
			AND to_.hash = po.in_reply_to_object_hash
		LEFT JOIN post_object as tpo ON tpo.object_id = to_.id
		WHERE po.object_id = ?
	"#,
			[object_id.into()],
		))
		.await?;

	if let Some(r) = result {
		let object_hash: IdType = r.try_get_by_index(0)?;
		let object_sequence: i64 = r.try_get_by_index(1)?;
		let actor_address_opt: Option<ActorAddress> = r.try_get_by_index(2)?;
		let irt_actor_rowid: Option<i64> = r.try_get_by_index(3)?;
		let irt_actor_address_opt: Option<ActorAddress> = r.try_get_by_index(4)?;
		let irt_object_id_opt: Option<i64> = r.try_get_by_index(5)?;

		let in_reply_to = match irt_object_id_opt {
			None => None,
			Some(irt_object_id) => {
				let (irt_actor_name, irt_actor_avatar_id) = match irt_actor_rowid {
					None => (None, None),
					Some(id) => db.find_profile_limited(id).await?,
				};
				let irt_actor_address = irt_actor_address_opt.unwrap();
				let irt_message_opt =
					find_post_object_info_files(db, url_base, &irt_actor_address, irt_object_id)
						.await?;
				Some(TargetedPostInfo {
					id: object_hash.to_string(),
					actor_address: irt_actor_address.to_string(),
					actor_name: irt_actor_name,
					actor_avatar_url: irt_actor_avatar_id
						.map(|hash| file_url(url_base, &irt_actor_address, &hash)),
					message: irt_message_opt.clone().map(|(mt, b, _)| PostMessageInfo {
						mime_type: mt,
						body: b,
					}),
					attachments: irt_message_opt.map(|(_, _, a)| a).unwrap_or(Vec::new()),
				})
			}
		};

		let actor_address = actor_address_opt.unwrap();
		let message_opt =
			find_post_object_info_files(db, url_base, &actor_address, object_id).await?;
		Ok(Some(PostObjectInfo {
			in_reply_to,
			sequence: object_sequence as _,
			message: message_opt.as_ref().map(|(mt, b, _)| PostMessageInfo {
				mime_type: mt.clone(),
				body: b.clone(),
			}),
			attachments: message_opt.map(|(_, _, a)| a).unwrap_or(Vec::new()),
		}))
	} else {
		Ok(None)
	}
}

pub fn human_readable_duration(duration: &TimeDelta) -> String {
	if duration.num_weeks() > 0 {
		let weeks = duration.num_weeks();
		if weeks > 1 {
			weeks.to_string() + " weeks"
		} else {
			weeks.to_string() + " week"
		}
	} else if duration.num_days() > 0 {
		let days = duration.num_days();
		if days > 1 {
			days.to_string() + " days"
		} else {
			days.to_string() + " day"
		}
	} else if duration.num_hours() > 0 {
		let hours = duration.num_hours();
		if hours > 1 {
			hours.to_string() + " hours"
		} else {
			hours.to_string() + " hour"
		}
	} else if duration.num_minutes() > 0 {
		let minutes = duration.num_minutes();
		if minutes > 1 {
			minutes.to_string() + " minutes"
		} else {
			minutes.to_string() + " minute"
		}
	} else {
		let seconds = duration.num_seconds();
		if seconds == 1 {
			seconds.to_string() + " second"
		} else {
			seconds.to_string() + " seconds"
		}
	}
}

fn human_readable_duration_from_timestamp(timestamp: u64) -> String {
	let now = current_timestamp();
	let duration = TimeDelta::try_milliseconds((now - timestamp) as _).unwrap();
	human_readable_duration(&duration)
}

pub async fn load_actor_feed(
	db: &Database, url_base: &str, actor: &ActorAddress, limit: u64, offset: u64,
) -> Result<Vec<ObjectInfo>> {
	let query = Query::select()
		.column((object::Entity, object::Column::Id))
		.column((object::Entity, object::Column::Type))
		.column(object::Column::ActorId)
		.column(object::Column::Hash)
		.column(object::Column::Created)
		.column(object::Column::Found)
		.from(object::Entity)
		.inner_join(
			actor::Entity,
			Expr::col((object::Entity, object::Column::ActorId))
				.equals((actor::Entity, actor::Column::Id)),
		)
		.and_where(actor::Column::Address.eq(actor))
		.order_by(object::Column::Sequence, Order::Desc)
		.limit(limit)
		.offset(offset)
		.take();
	let stat = db.backend().build(&query);

	let results = db.inner().query_all(stat).await?;
	let mut objects = Vec::with_capacity(limit as _);
	for result in &results {
		if let Some(object) = _load_object_info_from_result(db, url_base, actor, result).await? {
			objects.push(object);
		}
	}
	Ok(objects)
}

pub async fn load_home_feed(
	db: &Database, limit: u64, offset: u64, track: impl Iterator<Item = &ActorAddress> + Send,
) -> Result<Vec<ObjectInfo>> {
	// Build up the part of the query that includes the id's to track additionally
	let cap = track.size_hint().1.unwrap_or(track.size_hint().0);
	let mut tuples: Vec<&ActorAddress> = Vec::with_capacity(cap);
	for t in track {
		tuples.push(t);
	}

	// The query
	let query = object::Entity::find()
		.column(actor::Column::Address)
		.join(JoinType::LeftJoin, object::Relation::Actor.def())
		.filter(
			Condition::any()
				.add(
					object::Column::ActorId.in_subquery(
						Query::select()
							.column(actor::Column::Id)
							.from(Alias::new(actor::Entity::default().table_name()))
							.and_where(
								Expr::col((actor::Entity, actor::Column::Address))
									.in_tuples(tuples),
							)
							.take(),
					),
				)
				.add(
					object::Column::ActorId.in_subquery(
						Query::select()
							.column(identity::Column::ActorId)
							.from(Alias::new(identity::Entity::default().table_name()))
							.take(),
					),
				)
				.add(
					object::Column::ActorId.in_subquery(
						Query::select()
							.column(following::Column::ActorId)
							.from(Alias::new(following::Entity::default().table_name()))
							.take(),
					),
				),
		)
		.order_by_desc(object::Column::Found)
		.offset(offset)
		.limit(limit)
		.build(db.backend());

	// Process results
	let results = db.inner().query_all(query).await?;
	let mut objects = Vec::with_capacity(limit as _);
	for result in &results {
		let actor_address_opt: Option<ActorAddress> =
			result.try_get_by(actor::Column::Address.as_str())?;
		if let Some(actor_address) = actor_address_opt {
			if let Some(object) =
				_load_object_info_from_result(db, "", &actor_address, result).await?
			{
				objects.push(object);
			}
		}
	}
	Ok(objects)
}

pub async fn load_object_info(
	db: &Database, url_base: &str, hash: &IdType,
) -> Result<Option<ObjectInfo>> {
	let result = object::Entity::find()
		.filter(object::Column::Hash.eq(hash))
		.one(db.inner())
		.await?;
	_load_object_info(db, url_base, result).await
}

pub async fn load_object_info2(
	db: &Database, url_base: &str, id: i64,
) -> Result<Option<ObjectInfo>> {
	let result = object::Entity::find_by_id(id).one(db.inner()).await?;
	_load_object_info(db, url_base, result).await
}

pub async fn load_object_payload_info(
	db: &Database, url_base: &str, object_id: i64, object_type: u8,
) -> Result<Option<ObjectPayloadInfo>> {
	Ok(match object_type {
		OBJECT_TYPE_POST => find_post_object_info(db, url_base, object_id)
			.await?
			.map(|r| ObjectPayloadInfo::Post(r)),
		OBJECT_TYPE_HOME_FILE => panic!("Home files not implemented yet."),
		OBJECT_TYPE_PROFILE => find_profile_object_info(db, url_base, object_id)
			.await?
			.map(|r| ObjectPayloadInfo::Profile(r)),
		other => panic!("unknown object type: {}", other),
	})
}

fn object_url(url_base: &str, actor_address: &ActorAddress, hash: &IdType) -> String {
	format!("{}/actor/{}/object/{}", url_base, actor_address, hash)
}

async fn _load_object_info(
	db: &Database, url_base: &str, record: Option<object::Model>,
) -> Result<Option<ObjectInfo>> {
	let info = if let Some(object) = record {
		let actor_address = if let Some(record) = actor::Entity::find_by_id(object.actor_id)
			.one(db.inner())
			.await?
		{
			record.address
		} else {
			return Ok(None);
		};
		let (actor_name, actor_avatar) = db.find_profile_limited(object.actor_id).await?;

		if let Some(payload) =
			load_object_payload_info(db, url_base, object.id, object.r#type).await?
		{
			Some(ObjectInfo {
				consolidated_type: ConsolidatedObjectType::Stonenet,
				created: object.created as _,
				found: object.found as _,
				found_ago: human_readable_duration_from_timestamp(object.found as _),
				actor_address: Some(actor_address.to_string()),
				actor_name: actor_name.unwrap_or(actor_address.to_string()),
				payload,
				url: object_url(url_base, &actor_address, &object.hash),
				id: object.hash.to_string(),
				actor_url: actor_url(url_base, &actor_address),
				actor_avatar_url: actor_avatar
					.map(|hash| file_url(url_base, &actor_address, &hash)),
			})
		} else {
			None
		}
	} else {
		None
	};
	Ok(info)
}

async fn _load_object_info_from_result(
	db: &Database, url_base: &str, actor_address: &ActorAddress, result: &sea_orm::QueryResult,
) -> Result<Option<ObjectInfo>> {
	let object_id: i64 = result.try_get_by("id")?;
	let hash: IdType = result.try_get_by("hash")?;
	let object_type: u8 = result.try_get_by("type")?;
	let actor_id: i64 = result.try_get_by("actor_id")?;
	let payload_result = load_object_payload_info(db, url_base, object_id, object_type).await?;

	if let Some(payload) = payload_result {
		let (actor_name, actor_avatar) = db.find_profile_limited(actor_id).await?;

		let created: i64 = result.try_get_by("created")?;
		let found: i64 = result.try_get_by("found")?;
		Ok(Some(ObjectInfo {
			consolidated_type: ConsolidatedObjectType::Stonenet,
			created: created as _,
			found: found as _,
			found_ago: human_readable_duration_from_timestamp(found as _),
			actor_address: Some(actor_address.to_string()),
			actor_name: actor_name.unwrap_or(actor_address.to_string()),
			payload,
			url: object_url(url_base, actor_address, &hash),
			id: hash.to_string(),
			actor_url: actor_url(url_base, actor_address),
			actor_avatar_url: actor_avatar.map(|hash| file_url(url_base, actor_address, &hash)),
		}))
	} else {
		Ok(None)
	}
}

async fn _parse_profile_info(
	db: &Database, url_base: &str, result: QueryResult,
) -> Result<Option<ProfileObjectInfo>> {
	let actor_address: ActorAddress = result.try_get_by_index(0)?;
	let actor_name: String = result.try_get_by_index(1)?;
	let avatar_id: Option<IdType> = result.try_get_by_index(2)?;
	let wallpaper_id: Option<IdType> = result.try_get_by_index(3)?;
	let description_id: Option<i64> = result.try_get_by_index(4)?;
	let description_compression_type: Option<u8> = result.try_get_by_index(5)?;
	let description_plain_hash: Option<IdType> = result.try_get_by_index(6)?;
	let description_block_count: Option<i64> = result.try_get_by_index(7)?;

	let description = if let Some(file_id) = description_id {
		let data = db
			.find_file_data(
				file_id,
				&description_plain_hash.unwrap(),
				description_block_count.unwrap() as _,
			)
			.await?;

		data.map(
			|d| match CompressionType::from_u8(description_compression_type.unwrap()) {
				Some(t) => decompress(t, &d).expect("decompression error"),
				None => panic!("unsupported compression type"),
			},
		)
	} else {
		None
	};
	Ok(Some(ProfileObjectInfo {
		actor: TargetedActorInfo {
			address: actor_address.to_string(),
			url: actor_url(url_base, &actor_address),
			name: actor_name,
			avatar_url: avatar_id.map(|id| file_url(url_base, &actor_address, &id)),
			wallpaper_url: wallpaper_id.map(|id| file_url(url_base, &actor_address, &id)),
		},
		description: description.map(|b| String::from_utf8_lossy(&b).to_string()),
	}))
}

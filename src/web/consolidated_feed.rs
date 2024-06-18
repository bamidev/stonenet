use std::collections::HashMap;

use log::warn;
use sea_orm::{prelude::*, QueryOrder, QuerySelect, QueryTrait};
use serde::Serialize;

use super::Error;
use crate::{
	db::{self, Database, PersistenceHandle},
	entity::*,
	web::{self, info::ObjectInfo, Result},
};


#[derive(Debug, PartialEq, Serialize)]
pub enum ConsolidatedObjectType {
	Stonenet,
	ActivityPub,
}


pub async fn load_consolidated_feed(
	db: &Database, url_base: &str, count: u64, offset: u64,
) -> Result<Vec<ObjectInfo>> {
	let consolidated = consolidated_object::Entity::find()
		.order_by_desc(consolidated_object::Column::Batch)
		.order_by_asc(consolidated_object::Column::Id)
		.limit(count)
		.offset(offset)
		.all(db.inner())
		.await
		.map_err(|e| db::Error::from(e).to_web())?;

	let mut objects = Vec::with_capacity(consolidated.len());
	for consolidated_object in consolidated {
		let object_opt = if consolidated_object.r#type == 0 {
			web::info::load_object_info2(db, url_base, consolidated_object.object_id)
				.await
				.map_err(|e| e.to_web())?
		} else if consolidated_object.r#type == 1 {
			match web::activity_pub::load_object_info(db, consolidated_object.object_id).await {
				Ok(r) => r,
				Err(e) => match &*e {
					Error::UnexpectedBehavior(what, when) => {
						warn!("Unable to parse ActivityPub object when {}: {}", when, what);
						continue;
					}
					_ => Err(e)?,
				},
			}
		} else {
			None
		};

		if let Some(o) = object_opt {
			objects.push(o);
		}
	}
	Ok(objects)
}

pub async fn load_next_unconsolidated_activity_pub_objects(
	db: &Database,
) -> db::Result<HashMap<i64, (i64, i64)>> {
	let stat = activity_pub_object::Entity::find()
		.select_only()
		.column(activity_pub_object::Column::Id)
		.column(activity_pub_object::Column::ActorId)
		.column(activity_pub_object::Column::Published)
		.filter(
			activity_pub_object::Column::Id.not_in_subquery(
				consolidated_object::Entity::find()
					.select_only()
					.column(consolidated_object::Column::ObjectId)
					.filter(consolidated_object::Column::Type.eq(1))
					.into_query(),
			),
		)
		.order_by_asc(activity_pub_object::Column::ActorId)
		.order_by_desc(activity_pub_object::Column::Published)
		.build(db.backend());
	let results = db.inner().query_all(stat).await?;

	// Take one object per actor, the earliest one to be specific
	let mut map = HashMap::new();
	for result in results {
		let object_id: i64 = result.try_get_by_index(0)?;
		let actor_id: i64 = result.try_get_by_index(1)?;
		let timestamp: i64 = result.try_get_by_index(2)?;

		if !map.contains_key(&actor_id) {
			map.insert(actor_id, (object_id, timestamp));
		}
	}
	Ok(map)
}

pub async fn load_next_unconsolidated_objects(
	db: &Database,
) -> db::Result<HashMap<i64, (i64, i64)>> {
	let stat = object::Entity::find()
		.select_only()
		.column(object::Column::Id)
		.column(object::Column::ActorId)
		.column(object::Column::Found)
		.filter(
			object::Column::Id.not_in_subquery(
				consolidated_object::Entity::find()
					.select_only()
					.column(consolidated_object::Column::ObjectId)
					.filter(consolidated_object::Column::Type.eq(0))
					.into_query(),
			),
		)
		.order_by_asc(object::Column::ActorId)
		.order_by_desc(object::Column::Found)
		.build(db.backend());
	let results = db.inner().query_all(stat).await?;

	// Take one object per actor, the earliest one to be specific
	let mut map = HashMap::new();
	for result in results {
		let object_id: i64 = result.try_get_by_index(0)?;
		let actor_id: i64 = result.try_get_by_index(1)?;
		let timestamp: i64 = result.try_get_by_index(2)?;

		if !map.contains_key(&actor_id) {
			map.insert(actor_id, (object_id, timestamp));
		}
	}
	Ok(map)
}
